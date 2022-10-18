//! Link-Layer connection management and LLCP implementation.

use crate::link::data::{self, Header, Llid, Pdu};
use crate::link::llcp::{ConnectionUpdateData, ControlPdu};
use crate::link::queue::{Consume, Consumer, Producer};
use crate::link::{
    advertising::ConnectRequestData, channel_map::ChannelMap, Cmd, CompanyId, FeatureSet,
    NextUpdate, RadioCmd, SeqNum, Transmitter,
};
use crate::time::{Duration, Instant, Timer};
use crate::utils::{Hex, HexSlice};
use crate::{bytes::*, config::*, phy::DataChannel, Error, BLUETOOTH_VERSION};
use core::{marker::PhantomData, num::Wrapping};

/// Connection state and parameters.
pub struct Connection<C: Config> {
    access_address: u32,
    crc_init: u32,
    channel_map: ChannelMap,

    /// Number of (unmapped) channels to hop between each connection event.
    hop: u8,

    /// Connection event interval (duration between the start of 2 subsequent connection events).
    conn_interval: Duration,

    /// Connection event counter (`connEventCount(er)` in the spec).
    conn_event_count: Wrapping<u16>,

    /// Unmapped data channel on which the next connection event will take place.
    ///
    /// Also known as `lastUnmappedChannel` or `previous_event_channel` (yes, the spec uses both).
    unmapped_channel: DataChannel,

    /// Actual data channel on which the next data packets will be exchanged.
    channel: DataChannel,

    // Acknowledgement / Flow Control state
    /// `SN` bit to be used
    transmit_seq_num: SeqNum,
    next_expected_seq_num: SeqNum,

    /// Header of the last transmitted packet, used for retransmission.
    last_header: data::Header,

    /// Whether we have ever received a data packet in this connection.
    received_packet: bool,

    tx: ConfConsumer<C>,
    rx: ConfProducer<C>,

    /// LLCP connection update data received in a previous LL Control PDU.
    ///
    /// Contains the *instant* at which it should be applied to the Link Layer state.
    update_data: Option<LlcpUpdate>,

    _p: PhantomData<C>,
}

impl<C: Config> Connection<C> {
    /// Initializes a connection state according to the `LLData` contained in the `CONNECT_REQ`
    /// advertising PDU.
    ///
    /// Returns the connection state and a `Cmd` to apply to the radio/timer.
    ///
    /// # Parameters
    ///
    /// * **`lldata`**: Data contained in the `CONNECT_REQ` advertising PDU.
    /// * **`rx_end`**: Instant at which the `CONNECT_REQ` PDU was fully received.
    /// * **`tx`**: Channel for packets to transmit.
    /// * **`rx`**: Channel for received packets.
    pub(crate) fn create(
        lldata: &ConnectRequestData,
        rx_end: Instant,
        tx: ConfConsumer<C>,
        rx: ConfProducer<C>,
    ) -> (Self, Cmd) {
        let mut this = Self {
            access_address: lldata.access_address(),
            crc_init: lldata.crc_init(),
            channel_map: *lldata.channel_map(),
            hop: lldata.hop(),
            conn_interval: lldata.interval(),
            conn_event_count: Wrapping(0),

            unmapped_channel: DataChannel::new(0),
            channel: DataChannel::new(0),

            transmit_seq_num: SeqNum::ZERO,
            next_expected_seq_num: SeqNum::ZERO,
            last_header: Header::new(Llid::DataCont),
            received_packet: false,

            tx,
            rx,
            update_data: None,

            _p: PhantomData,
        };

        // Calculate the first channel to use
        this.hop_channel();

        let cmd = Cmd {
            next_update: NextUpdate::At(
                rx_end + lldata.end_of_tx_window() + Duration::from_micros(500),
            ),
            radio: RadioCmd::ListenData {
                channel: this.channel,
                access_address: this.access_address,
                crc_init: this.crc_init,
                timeout: false,
            },
            queued_work: false,
        };

        (this, cmd)
    }

    /// Called by the `LinkLayer` when a data channel packet is received.
    ///
    /// Returns `Err(())` when the connection is ended (not necessarily due to an error condition).
    pub(crate) fn process_data_packet(
        &mut self,
        rx_end: Instant,
        tx: &mut C::Transmitter,
        header: data::Header,
        payload: &[u8],
        crc_ok: bool,
    ) -> Result<Cmd, ()> {
        // If the sequence number of the packet is the same as our next expected sequence number,
        // the packet contains new data that we should try to process. However, if the CRC is bad,
        // we'll never try to process the data and instead request a retransmission.
        let is_new = header.sn() == self.next_expected_seq_num && crc_ok;

        // If the packet's "NESN" is equal to our last sent sequence number + 1, the other side has
        // acknowledged our last packet (and is now expecting one with an incremented seq. num.).
        // However, if the CRC is bad, the bit might be flipped, so we cannot assume that the packet
        // was acknowledged and thus always retransmit.
        let acknowledged = header.nesn() == self.transmit_seq_num + SeqNum::ONE && crc_ok;

        let is_empty = header.llid() == Llid::DataCont && payload.is_empty();

        if acknowledged {
            self.received_packet = true;
            self.transmit_seq_num += SeqNum::ONE;
        }

        // Whether we've already sent a response packet.
        let mut responded = false;
        // Whether we've pushed more work into the RX queue.
        let mut queued_work = false;

        if is_new {
            if is_empty {
                // Always acknowledge empty packets, no need to process them
                self.next_expected_seq_num += SeqNum::ONE;
            } else if header.llid() == Llid::Control {
                // LLCP message, try to process it immediately. Certain LLCPDUs might be put in the
                // channel instead and answered by the non-real-time part.

                if let Ok(pdu) = ControlPdu::from_bytes(&mut ByteReader::new(payload)) {
                    // Some LLCPDUs don't need a response, those can always be processed and
                    // ACKed. For those that do, the other device must have ACKed the last
                    // packet we sent, because we'll directly use the radio's TX buffer to send
                    // back the LLCP response.

                    match self.process_control_pdu(pdu, acknowledged) {
                        Ok(Some(response)) => {
                            self.next_expected_seq_num += SeqNum::ONE;

                            let rsp = Pdu::from(&response);
                            let mut payload_writer = ByteWriter::new(tx.tx_payload_buf());
                            let left = payload_writer.space_left();
                            rsp.to_bytes(&mut payload_writer).unwrap();

                            let mut header = Header::new(Llid::Control);
                            let pl_len = (left - payload_writer.space_left()) as u8;
                            header.set_payload_length(pl_len);
                            self.send(header, tx);
                            responded = true;

                            info!("LLCP<- {:?}", pdu);
                            info!("LLCP-> {:?}", response);
                        }
                        Ok(None) => {
                            self.next_expected_seq_num += SeqNum::ONE;

                            info!("LLCP<- {:?}", pdu);
                            info!("LLCP-> (no response)");
                        }
                        Err(LlcpError::ConnectionLost) => {
                            return Err(());
                        }
                        Err(LlcpError::NoSpace) => {
                            // Do not acknowledge the PDU
                        }
                    }
                } else {
                    // Couldn't parse control PDU. CRC might be invalid. NACK
                }
            } else {
                // Try to buffer the packet. If it fails, we don't acknowledge it, so it will be
                // resent until we have space.

                let result: Result<(), Error> =
                    self.rx.produce_with(header.payload_length(), |writer| {
                        writer.write_slice(payload)?;
                        Ok(header.llid())
                    });

                if result.is_ok() {
                    // Acknowledge the packet
                    self.next_expected_seq_num += SeqNum::ONE;
                    queued_work = true;
                } else {
                    trace!("NACK (no space in rx buffer)");
                }
            }
        }

        if acknowledged {
            if !responded {
                // Send a new data packet.

                // Try to acquire PDU from the tx queue, fall back to an empty PDU.
                let mut payload_writer = ByteWriter::new(tx.tx_payload_buf());
                let header = match self.tx.consume_raw_with(|header, pl| {
                    payload_writer.write_slice(pl).expect("TX buf out of space");
                    Consume::always(Ok(header))
                }) {
                    Ok(h) => h,
                    Err(_) => Header::new(Llid::DataCont),
                };

                self.send(header, tx);
            }
        } else {
            // Last packet not acknowledged, resend.
            // If CRC is bad, this bit could be flipped, so we always retransmit in that case.
            if self.received_packet {
                self.last_header.set_nesn(self.next_expected_seq_num);
                tx.transmit_data(
                    self.access_address,
                    self.crc_init,
                    self.last_header,
                    self.channel,
                );
                trace!("<<RESENT>>");
            } else {
                // We've never received (and thus sent) a data packet before, so we can't
                // *re*transmit anything. Send empty PDU instead.
                // (this should not really happen, though!)
                self.received_packet = true;

                let pdu = Pdu::empty();
                let mut payload_writer = ByteWriter::new(tx.tx_payload_buf());
                pdu.to_bytes(&mut payload_writer).unwrap();
                self.send(Header::new(pdu.llid()), tx);
            }
        }

        let last_channel = self.channel;

        // FIXME: Don't hop if one of the MD bits is set to true (also don't log then)
        {
            // Connection event closes
            self.conn_event_count += Wrapping(1);

            if let Some(update) = self.update_data.take() {
                if update.instant() == self.conn_event_count.0 {
                    // Next conn event will the the first one with these parameters.
                    let result = self.apply_llcp_update(update, rx_end);
                    info!("LLCP patch applied: {:?} -> {:?}", update, result);
                    if let Some(mut cmd) = result {
                        cmd.queued_work = queued_work;
                        return Ok(cmd);
                    }
                } else {
                    // Put it back
                    self.update_data = Some(update);
                }
            }

            // Hop channels after applying LLCP update because it might change the channel map used
            // by the next event
            self.hop_channel();
        }

        trace!(
            "#{} DATA({}->{})<- {}{:?}, {:?}",
            self.conn_event_count,
            last_channel.index(),
            self.channel.index(),
            if crc_ok { "" } else { "BADCRC, " },
            header,
            HexSlice(payload)
        );

        Ok(Cmd {
            next_update: NextUpdate::At(rx_end + self.conn_event_timeout()),
            radio: RadioCmd::ListenData {
                channel: self.channel,
                access_address: self.access_address,
                crc_init: self.crc_init,
                timeout: false,
            },
            queued_work,
        })
    }

    /// Called by the `LinkLayer` when the configured timer expires (according to a `Cmd` returned
    /// earlier).
    ///
    /// Returns `Err(())` when the connection is closed or lost. In that case, the Link-Layer will
    /// return to standby state.
    pub(crate) fn timer_update(&mut self, timer: &mut C::Timer) -> Result<Cmd, ()> {
        if self.received_packet {
            // No packet from master, skip this connection event and listen on the next channel

            let last_channel = self.channel;
            self.hop_channel();
            self.conn_event_count += Wrapping(1);
            trace!(
                "DATA({}->{}): missed conn event #{}",
                last_channel.index(),
                self.channel.index(),
                self.conn_event_count.0,
            );

            Ok(Cmd {
                next_update: NextUpdate::At(timer.now() + self.conn_event_timeout()),
                radio: RadioCmd::ListenData {
                    channel: self.channel,
                    access_address: self.access_address,
                    crc_init: self.crc_init,
                    timeout: true,
                },
                queued_work: false,
            })
        } else {
            // Master did not transmit the first packet during this transmit window.

            // TODO: Move the transmit window forward by the `connInterval`.
            // (do we also need to hop channels here?)

            self.conn_event_count += Wrapping(1);
            trace!("missed transmit window");
            Err(())
        }
    }

    fn conn_event_timeout(&self) -> Duration {
        // Time out ~500µs after the anchor point of the next conn event.
        self.conn_interval + Duration::from_micros(500)
    }

    /// Whether we want to send more data during this connection event.
    ///
    /// Note that this *has to* change to `false` eventually, even if there's more data to be sent,
    /// because the connection event must close at least `T_IFS` before the next one occurs.
    fn has_more_data(&self) -> bool {
        false
    }

    /// Advances the `unmapped_channel` and `channel` fields to the next data channel on which a
    /// connection event will take place.
    ///
    /// According to: `4.5.8.2 Channel Selection`.
    fn hop_channel(&mut self) {
        let unmapped_channel = DataChannel::new((self.unmapped_channel.index() + self.hop) % 37);

        self.unmapped_channel = unmapped_channel;
        self.channel = if self.channel_map.is_used(unmapped_channel) {
            unmapped_channel
        } else {
            // This channel isn't used, remap channel according to map
            let remapping_index = unmapped_channel.index() % self.channel_map.num_used_channels();
            self.channel_map.by_index(remapping_index)
        };
    }

    /// Sends a new PDU to the connected device (ie. a non-retransmitted PDU).
    fn send(&mut self, mut header: Header, tx: &mut C::Transmitter) {
        header.set_md(self.has_more_data());
        header.set_nesn(self.next_expected_seq_num);
        header.set_sn(self.transmit_seq_num);
        self.last_header = header;

        tx.transmit_data(self.access_address, self.crc_init, header, self.channel);

        let pl = &tx.tx_payload_buf()[..usize::from(header.payload_length())];
        trace!("DATA->{:?}, {:?}", header, HexSlice(pl));
    }

    /// Tries to process and acknowledge an LL Control PDU.
    ///
    /// Returns `Err(())` when the connection is closed or lost.
    ///
    /// Note this this function is on a time-critical path and thus can not use logging since that's
    /// currently way too slow. Critical errors can still be logged, since they abort the connection
    /// anyways.
    ///
    /// # Parameters
    ///
    /// * **`pdu`**: The LL Control PDU (LLCPDU) to process.
    /// * **`can_respond`**: Whether the radio's TX buffer may be overwritten to send a response. If
    ///   this is `false`, this method may choose not to acknowledge the PDU and wait for a
    ///   retransmission instead.
    fn process_control_pdu(
        &mut self,
        pdu: ControlPdu<'_>,
        can_respond: bool,
    ) -> Result<Option<ControlPdu<'static>>, LlcpError> {
        let response = match pdu {
            ControlPdu::ConnectionUpdateReq(data) => {
                self.prepare_llcp_update(LlcpUpdate::ConnUpdate(*data))?;
                return Ok(None);
            }
            ControlPdu::ChannelMapReq(req) => {
                self.prepare_llcp_update(LlcpUpdate::ChannelMap {
                    map: req.map.value(),
                    instant: req.instant,
                })?;
                return Ok(None);
            }
            ControlPdu::TerminateInd { error_code } => {
                info!(
                    "closing connection due to termination request: code {:?}",
                    error_code
                );
                return Err(LlcpError::ConnectionLost);
            }
            ControlPdu::FeatureReq { features_master } => ControlPdu::FeatureRsp {
                features_used: features_master & FeatureSet::supported(),
            },
            ControlPdu::VersionInd { .. } => {
                // FIXME this should be something real, and defined somewhere else
                let comp_id = 0xFFFF;
                // FIXME this should correlate with the Cargo package version
                let sub_vers_nr = 0x0000;

                ControlPdu::VersionInd {
                    vers_nr: BLUETOOTH_VERSION,
                    comp_id: CompanyId::from_raw(comp_id),
                    sub_vers_nr: Hex(sub_vers_nr),
                }
            }
            _ => ControlPdu::UnknownRsp {
                unknown_type: pdu.opcode(),
            },
        };

        // If we land here, we have a PDU we want to send
        if can_respond {
            Ok(Some(response))
        } else {
            Err(LlcpError::NoSpace)
        }
    }

    /// Stores `update` in the link layer state so that it will be applied once its *instant* is
    /// reached.
    fn prepare_llcp_update(&mut self, update: LlcpUpdate) -> Result<(), LlcpError> {
        // TODO: check that instant is <32767 in the future
        if let Some(data) = self.update_data {
            error!(
                "got update data {:?} while update {:?} is already queued",
                update, data
            );
            Err(LlcpError::ConnectionLost)
        } else {
            self.update_data = Some(update);
            Ok(())
        }
    }

    /// Patches the link layer state to incorporate `update`.
    ///
    /// Returns a `Cmd` when the usual Link Layer `Cmd` should be overridden. In that case, this
    /// method must also perform channel hopping.
    fn apply_llcp_update(&mut self, update: LlcpUpdate, rx_end: Instant) -> Option<Cmd> {
        match update {
            LlcpUpdate::ConnUpdate(data) => {
                let old_conn_interval = self.conn_interval;
                self.conn_interval = data.interval();

                self.hop_channel();

                Some(Cmd {
                    // Next update after the tx window ends (= missed it)
                    next_update: NextUpdate::At(
                        rx_end + old_conn_interval + data.win_offset() + data.win_size(),
                    ),
                    // Listen for the transmit window
                    radio: RadioCmd::ListenData {
                        channel: self.channel,
                        access_address: self.access_address,
                        crc_init: self.crc_init,
                        timeout: false,
                    },
                    // This function never queues work, but the caller might change this to `true`
                    queued_work: false,
                })
            }
            LlcpUpdate::ChannelMap { map, .. } => {
                self.channel_map = map;
                None
            }
        }
    }
}

// Public API
impl<C: Config> Connection<C> {
    /// Returns the configured interval between connection events.
    ///
    /// The connection event interval is arbitrated by the device in the Central role and heavily
    /// influences the data transmission latency of the connection, which is important for some
    /// applications.
    ///
    /// The Peripheral can request the Central to change the interval by sending an L2CAP signaling
    /// message, or by using the Link Layer control procedure for requesting new connection
    /// parameters.
    pub fn connection_interval(&self) -> Duration {
        self.conn_interval
    }
}

#[derive(Debug, Copy, Clone)]
enum LlcpError {
    /// No space in TX buffer, NACK the incoming PDU and retry later.
    NoSpace,

    /// Consider the connection lost due to a critical error or timeout.
    ConnectionLost,
}

/// A Link-Layer state update that may be applied with a delay.
#[derive(Debug, Copy, Clone)]
enum LlcpUpdate {
    /// Update connection parameters and await the configured transmit window.
    ///
    /// This effectively reset the connection to the state just after the connection request was
    /// received.
    ConnUpdate(ConnectionUpdateData),

    /// Start using a different `ChannelMap`.
    ChannelMap {
        /// The new `ChannelMap` to switch to.
        map: ChannelMap,

        /// The connection event at which to switch.
        instant: u16,
    },
}

impl LlcpUpdate {
    /// Returns the connection event number at which this update should be applied.
    fn instant(&self) -> u16 {
        match self {
            LlcpUpdate::ConnUpdate(data) => data.instant(),
            LlcpUpdate::ChannelMap { instant, .. } => *instant,
        }
    }
}

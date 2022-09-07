//! Link-Layer.
//!
//! Note that a hardware BLE radio will already implement a few aspects of the link layer (such as
//! CRC calculation, preamble generation, etc.). Consider this module to be a construction kit for
//! BLE Link-Layers: Take whatever your hardware can do, supplement it with a few condiments from
//! this module, and you get a (hopefully) working Link-Layer.
//!
//! Refer to the official *Link Layer Specification* for details and more graphics and tables.
//!
//! # Packet Format
//!
//! All following graphics are based on the Bluetooth specification. If a field is marked with `-`,
//! it should be set to 0 when sending such a packet, and ignored when receiving it (the spec calls
//! these "RFU" = Reserved for Future Use).
//!
//! All values are transmitted in little-endian bit order unless otherwise noted. All fields in
//! graphics are ordered starting with the field transmitted first (LSB).
//!
//! The following graphic illustrates the raw in-air packet format. The packet transfers a PDU whose
//! format depends on whether it is sent on an *advertising channel* or a *data channel*.
//!
//! ```notrust
//! LSB                                                     MSB
//! +-----------+----------------+---------------+------------+
//! | Preamble  | Access Address |     PDU       |  CRC       |
//! | (1 octet) | (4 octets)     | (2-39 octets) | (3 octets) |
//! +-----------+----------------+---------------+------------+
//!                              \---------------/      ^
//!                                      |              |
//!                                      +--------------+
//!                                     CRC is calculated
//!                                       over the PDU
//!
//!                              \----------------------------/
//!                                    Data Whitening is
//!                                 applied to PDU and CRC
//! ```
//!
//! The 24-bit CRC value is transmitted MSb first. Length of the PDU depends on the kind of PDU
//! (advertising or data channel).
//!
//! ## Advertising Channel PDU
//!
//! Each advertising channel PDU consists of a 16-bit header and a variably-sized payload, the
//! length of which is stored in a header field.
//!
//! ```notrust
//! LSB                                           MSB
//! +-------------+---------------------------------+
//! |  Header     |             Payload             |
//! |  (16 bits)  |    (length stored in header)    |
//! +-------------+---------------------------------+
//! ```
//!
//! The header looks like this:
//!
//! ```notrust
//! LSB                                                                     MSB
//! +------------+------------+---------+---------+--------------+------------+
//! |  PDU Type  |     -      |  TxAdd  |  RxAdd  |    Length    |     -      |
//! |  (4 bits)  |  (2 bits)  | (1 bit) | (1 bit) |   (6 bits)   |  (2 bits)  |
//! +------------+------------+---------+---------+--------------+------------+
//! ```
//!
//! The `TxAdd` and `RxAdd` field are only used for some payloads, for all others, they should be
//! set to 0.
//!
//! Length may be in range 6 to 36 (inclusive).
//!
//! The data in `Payload` depends on the PDU Type. Refer to the spec or [`advertising::PduType`] for
//! details.
//!
//! [`advertising::PduType`]: advertising/enum.PduType.html
//!
//! ## Data Channel PDU
//!
//! A data channel PDU also contains a 16-bit header (but with a different layout) and a
//! variably-sized payload.
//!
//! If the connection is encrypted and the payload contains at least 1 octet, a Message Integrity
//! Check (MIC) is appended at the end.
//!
//! ```notrust
//! LSB                                          MSB
//! +-----------+----------------------+ - - - - - +
//! |  Header   |        Payload       |    MIC    |
//! | (16 bits) |    (0..=27 octets)   | (32 bits) |
//! +-----------+----------------------+ - - - - - +
//! ```
//!
//! Layout (in Bluetooth 4.2):
//!
//! ```notrust
//! LSB                                                                MSB
//! +----------+---------+---------+---------+------------+--------------+
//! |   LLID   |  NESN   |   SN    |   MD    |     -      |    Length    |
//! | (2 bits) | (1 bit) | (1 bit) | (1 bit) |  (3 bits)  |   (8 bits)   |
//! +----------+---------+---------+---------+------------+--------------+
//! ```
//!
//! Payload format depends on the value of the 2-bit `LLID` field:
//!
//! * `0b00`: Reserved value.
//! * `0b01`: LL Data PDU Continuation fragment or empty PDU.
//! * `0b10`: LL Data PDU Start of L2CAP message (or complete message if no fragmentation
//!   necessary).
//! * `0b11`: LL Control PDU.
//!
//! The `NESN` field specifies the **N**ext **E**xpected **S**equence **N**umber. The `SN` field
//! specifies the **S**equence **N**umber of this PDU.
//!
//! The `MD` field specifies that the device sending the packet has more data to send during this
//! *connection event*. When both slave and master send a packet with the `MD` bit set to 0, the
//! connection event ends.
//!
//! The `Length` field specifies the length of payload **and `MIC`**. For Bluetooth versions <4.2,
//! its maximum value is 31, resulting in a 27 octet Payload (the maximum) and a 32-bit `MIC`. 4.2
//! added the possibility of larger packets.

pub mod ad_structure;
pub mod advertising;
mod channel_map;
mod comp_id;
mod connection;
pub mod data;
mod device_address;
mod features;
pub mod filter;
pub mod llcp;
pub mod queue;
mod responder;
mod seq_num;

pub use self::comp_id::*;
pub use self::connection::Connection;
pub use self::device_address::*;
pub use self::features::*;
pub use self::responder::*;

use self::advertising::{Pdu, PduBuf};
use self::{ad_structure::AdStructure, seq_num::SeqNum};
use crate::phy::{AdvertisingChannel, DataChannel};
use crate::time::{Duration, Instant, Timer};
use crate::{bytes::ByteReader, config::*, utils::HexSlice, Error};

/// The CRC polynomial to use for CRC24 generation.
///
/// If your radio has hardware support for CRC generation, you may use (parts of) this value to
/// configure it (if necessary). The CRC should be computed only over the PDU. Also note that the
/// CRC, unlike every other field, is transmitted MSb first.
///
/// Counting from the least-significant bit (bit 0), bit `k` in this value is set if the term `x^k`
/// occurs in the CRC polynomial. This includes bit 24, which is usually not explicitly specified.
///
/// Written out, the polynomial is:
///
/// `x^24 + x^10 + x^9 + x^6 + x^4 + x^3 + x + 1`
pub const CRC_POLY: u32 = 0b00000001_00000000_00000110_01011011;

/// Min. size a data PDU payload buffer must have (assuming only the bare minimum PDU size is
/// supported).
///
/// Data channel PDUs are smaller than advertising channel PDUs, so this value is less than
/// `MIN_PAYLOAD_BUF`.
pub const MIN_DATA_PAYLOAD_BUF: usize = 27;

/// Min. size a data PDU buffer must have.
///
/// This is `MIN_DATA_PAYLOAD_BUF` plus the size of the data PDU header (2 Bytes).
pub const MIN_DATA_PDU_BUF: usize = MIN_DATA_PAYLOAD_BUF + 2;

/// Min. size a PDU payload buffer must have (to cover both advertising and data channels).
///
/// The Advertising PDU header has a length field that is limited to 37 octets, while data channel
/// PDUs in Bluetooth 4.0 and 4.1 only have a 5-bit length field, limiting the user payload to 27
/// octets (after subtracting the optional 4-Byte MIC). Bluetooth 4.2 added the optional Packet
/// Length Extension, which allows data channel PDUs containing up to 251 user payload bytes,
/// however Rubble doesn't support that yet.
pub const MIN_PAYLOAD_BUF: usize = 37;

/// Min. size a Link-Layer PDU buffer must have (to cover both advertising and data channels).
///
/// Bluetooth 4.2 also allows exchanging larger PDUs using the Packet Length Extension, but Rubble
/// does not currently support that.
pub const MIN_PDU_BUF: usize = MIN_PAYLOAD_BUF + 2 /* 16-bit header */;

/// Min. size a buffer for Link-Layer packets must have to comply with the spec.
///
/// The packet contains everything that ends up being transmitted over the air: Preamble, Access
/// Address, the actual PDU, and the CRC checksum.
///
/// Bluetooth 4.2 also allows exchanging larger packets than this using the Packet Length Extension.
pub const MIN_PACKET_BUF: usize =
    1 /* preamble */ +
    4 /* access addr */ +
    MIN_PDU_BUF +
    3 /* crc */;

/// Link-Layer state machine, according to the Bluetooth spec.
enum State<C: Config> {
    /// Radio silence: Not listening, not transmitting anything.
    Standby,

    /// Device is advertising and wants to establish a connection.
    Advertising {
        /// Advertising interval.
        // TODO: check spec for allowed/recommended values and check for them
        next_adv: Instant,
        interval: Duration,

        /// Precomputed PDU payload to copy into the transmitter's buffer.
        pdu: advertising::PduBuf,

        /// Next advertising channel to use for a message.
        // FIXME: spec check; no idea what order or change delay
        channel: AdvertisingChannel,

        data_queues: Option<(ConfConsumer<C>, ConfProducer<C>)>,
    },

    /// Connected with another device.
    Connection(Connection<C>),
}

/// Implementation of the real-time BLE Link-Layer logic.
///
/// Users of this struct must provide an interface to the platform's hardware by implementing
/// [`Config`].
pub struct LinkLayer<C: Config> {
    dev_addr: DeviceAddress,
    state: State<C>,
    timer: C::Timer,
}

impl<C: Config> LinkLayer<C> {
    /// Creates a new Link-Layer.
    ///
    /// # Parameters
    ///
    /// * **`dev_addr`**: The device address to broadcast as.
    /// * **`timer`**: A `Timer` implementation.
    /// * **`tx`**: Input queue of packets to transmit when connected.
    /// * **`rx`**: Output queue of received packets when connected.
    pub fn new(dev_addr: DeviceAddress, timer: C::Timer) -> Self {
        trace!("new LinkLayer, dev={:?}", dev_addr);
        Self {
            dev_addr,
            state: State::Standby,
            timer,
        }
    }

    /// Returns a reference to the timer instance used by the Link-Layer.
    pub fn timer(&mut self) -> &mut C::Timer {
        &mut self.timer
    }

    /// Send advertisement
    pub fn advertise(
        &mut self,
        interval: Duration,
        data: &[AdStructure<'_>],
        transmitter: &mut C::Transmitter,
        tx: ConfConsumer<C>,
        rx: ConfProducer<C>,
    ) -> Result<NextUpdate, Error> {
        // TODO tear down existing connection?

        let pdu = PduBuf::discoverable(self.dev_addr, data)?;
        debug!("start_advertise: adv_data = {:?}", data);
        debug!("start_advertise: PDU = {:?}", pdu);
        self.state = State::Advertising {
            next_adv: self.timer().now(),
            interval,
            pdu,
            channel: AdvertisingChannel::first(),
            data_queues: Some((tx, rx)),
        };
        Ok(self.update_timer(transmitter).next_update)
    }

    /// Process an incoming packet from an advertising channel.
    ///
    /// The access address of the packet must be `ADVERTISING_ADDRESS`.
    ///
    /// # Parameters
    ///
    /// * **`rx_end`**: A timestamp indicating when the packet was fully received.
    /// * **`tx`**: A packet transmitter.
    /// * **`header`**: The header of the received packet.
    /// * **`payload`**: The packet payload following the header.
    /// * **`crc_ok`**: Whether the packet's CRC is correct.
    pub fn process_adv_packet(
        &mut self,
        rx_end: Instant,
        tx: &mut C::Transmitter,
        header: advertising::Header,
        payload: &[u8],
        crc_ok: bool,
    ) -> Cmd {
        let pdu = advertising::Pdu::from_header_and_payload(header, &mut ByteReader::new(payload));

        if let Ok(pdu) = pdu {
            if let State::Advertising {
                channel,
                data_queues,
                ..
            } = &mut self.state
            {
                if crc_ok && pdu.receiver() == Some(&self.dev_addr) {
                    // Got a packet addressed at us, can be a scan or connect request
                    match pdu {
                        Pdu::ScanRequest { .. } => {
                            let scan_data = &[]; // TODO make this configurable
                            let response = PduBuf::scan_response(self.dev_addr, scan_data).unwrap();
                            tx.transmit_advertising(response.header(), *channel);

                            // Log after responding to meet timing
                            debug!("-> SCAN RESP: {:?}", response);
                        }
                        Pdu::ConnectRequest { lldata, .. } => {
                            trace!("ADV<- CONN! {:?}", pdu);

                            let (tx, rx) = data_queues.take().unwrap();
                            let (conn, cmd) = Connection::create(&lldata, rx_end, tx, rx);
                            self.state = State::Connection(conn);
                            return cmd;
                        }
                        _ => {}
                    }
                }
            }
        }

        trace!(
            "ADV<- {}{:?}, {:?}\n{:?}\n",
            if crc_ok { "" } else { "BADCRC " },
            header,
            HexSlice(payload),
            pdu,
        );

        match self.state {
            State::Standby => unreachable!("standby, can't receive packets"),
            State::Connection { .. } => unreachable!("process_adv_packet called while connected"),
            State::Advertising { channel, .. } => {
                Cmd {
                    radio: RadioCmd::ListenAdvertising { channel },
                    // no change
                    next_update: NextUpdate::Keep,
                    queued_work: false,
                }
            }
        }
    }

    /// Process an incoming data channel packet.
    pub fn process_data_packet(
        &mut self,
        rx_end: Instant,
        tx: &mut C::Transmitter,
        header: data::Header,
        payload: &[u8],
        crc_ok: bool,
    ) -> Cmd {
        if let State::Connection(conn) = &mut self.state {
            match conn.process_data_packet(rx_end, tx, header, payload, crc_ok) {
                Ok(cmd) => cmd,
                Err(()) => {
                    debug!("connection ended, standby");
                    self.state = State::Standby;
                    Cmd {
                        next_update: NextUpdate::Disable,
                        radio: RadioCmd::Off,
                        // FIXME(#70) this might need to be changed to `true`
                        queued_work: false,
                    }
                }
            }
        } else {
            unreachable!("received data channel PDU while not in connected state");
        }
    }

    /// Update the Link-Layer state after the timer expires.
    ///
    /// This should be called whenever the timer set by the last returned `Cmd` has expired.
    ///
    /// # Parameters
    ///
    /// * `tx`: A `Transmitter` for sending packets.
    pub fn update_timer(&mut self, tx: &mut C::Transmitter) -> Cmd {
        match &mut self.state {
            State::Advertising {
                next_adv,
                interval,
                pdu,
                channel,
                ..
            } => {
                *channel = channel.cycle();
                let payload = pdu.payload();
                let buf = tx.tx_payload_buf();
                buf[..payload.len()].copy_from_slice(payload);

                // FIXME According to the spec, this has to broadcast on all advertising channels

                tx.transmit_advertising(pdu.header(), *channel);

                *next_adv += *interval;

                Cmd {
                    radio: RadioCmd::ListenAdvertising { channel: *channel },
                    next_update: NextUpdate::At(*next_adv),
                    queued_work: false,
                }
            }
            State::Connection(conn) => match conn.timer_update(&mut self.timer) {
                Ok(cmd) => cmd,
                Err(()) => {
                    debug!("connection ended (timer), standby");
                    self.state = State::Standby;
                    Cmd {
                        next_update: NextUpdate::Disable,
                        radio: RadioCmd::Off,
                        // FIXME(#70) this might need to be changed to `true`
                        queued_work: false,
                    }
                }
            },
            State::Standby => unreachable!("LL in standby received timer event"),
        }
    }

    /// Returns a reference to the connection state.
    ///
    /// If the Link Layer is not currently in a connection, returns `None`.
    pub fn connection(&self) -> Option<&Connection<C>> {
        if let State::Connection(conn) = &self.state {
            Some(conn)
        } else {
            None
        }
    }

    /// Returns whether the Link-Layer is currently broadcasting advertisement packets.
    pub fn is_advertising(&self) -> bool {
        matches!(self.state, State::Advertising { .. })
    }

    /// Returns whether the Link-Layer is currently connected.
    pub fn is_connected(&self) -> bool {
        matches!(self.state, State::Connection { .. })
    }
}

/// Command returned by the Link-Layer to the user.
///
/// Specifies how the radio should be configured and when/if to call `LinkLayer::update` again.
#[must_use]
#[derive(Debug, Clone)]
pub struct Cmd {
    /// Radio configuration request.
    pub radio: RadioCmd,

    /// Time until `LinkLayer::update` should be called.
    ///
    /// If this is `None`, `update` doesn't need to be called because the Link-Layer is in Standby
    /// state.
    pub next_update: NextUpdate,

    /// Whether the Link-Layer code has enqueued more work into the packet queue.
    ///
    /// If this is `true`, the caller needs to ensure that the queue is drained and processed by
    /// calling the `Responder`. The apps idle loop might unconditionally do that, in which case
    /// checking this flag is not necessary.
    pub queued_work: bool,
}

/// Specifies when the Link Layer's `update` method should be called the next time.
#[derive(Debug, Clone)]
pub enum NextUpdate {
    /// Disable timer and do not call `update`.
    Disable,

    /// Keep the previously configured time.
    Keep,

    /// Call `update` at the given `Instant`.
    ///
    /// If `Instant` is in the past, this is a bug and the implementation may panic.
    At(Instant),
}

/// Specifies if and how the radio should listen for transmissions.
///
/// Returned by the Link-Layer update and processing methods to reconfigure the radio as needed.
#[derive(Debug, Clone)]
pub enum RadioCmd {
    /// Turn the radio off and don't call `LinkLayer::process_*` methods.
    ///
    /// `LinkLayer::update` must still be called according to `Cmd`'s `next_update` field.
    Off,

    /// Listen on an advertising channel. If a packet is received, pass it to
    /// `LinkLayer::process_adv_packet`.
    ListenAdvertising {
        /// The advertising channel to listen on.
        channel: AdvertisingChannel,
    },

    /// Listen on a data channel. If a matching packet is received, pass it to
    /// `LinkLayer::process_data_packet`.
    ListenData {
        /// The data channel to listen on.
        channel: DataChannel,

        /// The Access Address to listen for.
        ///
        /// Packets with a different Access Address must not be passed to the Link-Layer. You may be
        /// able to use your Radio's hardware address matching for this.
        access_address: u32,

        /// Initialization value of the CRC-24 calculation.
        ///
        /// Only the least significant 24 bits are relevant.
        crc_init: u32,

        /// Flag to indicate if the last connection event timed out.
        timeout: bool,
    },
}

/// Trait for Link Layer packet transmission.
///
/// The specifics of sending a Link-Layer packet depend on the underlying hardware. The `link`
/// module provides building blocks that enable implementations without any BLE hardware support,
/// just a compatible radio is needed.
pub trait Transmitter {
    /// Get a reference to the Transmitter's PDU payload buffer.
    ///
    /// The buffer must hold at least 37 Bytes, as that is the maximum length of advertising channel
    /// payloads. While data channel payloads can be up to 251 Bytes in length (resulting in a
    /// "length" field of 255 with the MIC), devices are allowed to use smaller buffers and report
    /// the supported payload length.
    ///
    /// Both advertising and data channel packets also use an additional 2-Byte header preceding
    /// this payload.
    ///
    /// This buffer must not be changed. The BLE stack relies on the buffer to retain its old
    /// contents after transmitting a packet. A separate buffer must be used for received packets.
    fn tx_payload_buf(&mut self) -> &mut [u8];

    /// Transmit an Advertising Channel PDU.
    ///
    /// For Advertising Channel PDUs, the CRC initialization value is always `CRC_PRESET`, and the
    /// Access Address is always `ADVERTISING_ADDRESS`.
    ///
    /// The implementor is expected to send the preamble and access address, and assemble the rest
    /// of the packet, and must apply data whitening and do the CRC calculation. The inter-frame
    /// spacing also has to be upheld by the implementor (`T_IFS`).
    ///
    /// # Parameters
    ///
    /// * `header`: Advertising Channel PDU Header to prepend to the Payload in `payload_buf()`.
    /// * `channel`: Advertising Channel Index to transmit on.
    fn transmit_advertising(&mut self, header: advertising::Header, channel: AdvertisingChannel);

    /// Transmit a Data Channel PDU.
    ///
    /// The implementor is expected to send the preamble and assemble the rest of the packet, and
    /// must apply data whitening and do the CRC calculation.
    ///
    /// # Parameters
    ///
    /// * `access_address`: The Access Address of the Link-Layer packet.
    /// * `crc_iv`: CRC calculation initial value (`CRC_PRESET` for advertising channel).
    /// * `header`: Data Channel PDU Header to be prepended to the Payload in `payload_buf()`.
    /// * `channel`: Data Channel Index to transmit on.
    fn transmit_data(
        &mut self,
        access_address: u32,
        crc_iv: u32,
        header: data::Header,
        channel: DataChannel,
    );
}

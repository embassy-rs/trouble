use crate::l2cap::{L2CAPState, L2CAPStateTx};
use crate::link::data::{Llid, Pdu};
use crate::link::llcp::ControlPdu;
use crate::link::queue::{Consume, Consumer, Producer};
use crate::{bytes::ToBytes, config::*, utils::HexSlice, Error};

/// Data channel packet processor.
///
/// This hooks up to the Real-Time part of the LE Link Layer via a packet queue. This part can run
/// at a lower priority (eg. being driven in the apps idle loop) and receives and transmits packets
/// using the packet queue.
///
/// Some *LL Control PDUs* sent as part of the Link Layer Control Protocol (LLCP) are answered by
/// the responder directly, and all L2CAP data is forwarded to an `L2CAPState<M>`. Note that most
/// LLCPDUs are handled directly by the real-time code.
pub struct Responder<C: Config> {
    tx: ConfProducer<C>,
    rx: Option<ConfConsumer<C>>,
    l2cap: L2CAPState<C::ChannelMapper>,
}

impl<C: Config> Responder<C> {
    /// Creates a new packet processor hooked up to data channel packet queues.
    pub fn new(
        tx: ConfProducer<C>,
        rx: ConfConsumer<C>,
        l2cap: L2CAPState<C::ChannelMapper>,
    ) -> Self {
        Self {
            tx,
            rx: Some(rx),
            l2cap,
        }
    }

    /// Returns `true` when this responder has work to do.
    ///
    /// If this returns `true`, `process` may be called to process incoming packets and send
    /// outgoing ones.
    pub fn has_work(&mut self) -> bool {
        self.with_rx(|rx, _| rx.has_data())
    }

    /// Processes a single incoming packet in the packet queue.
    ///
    /// Returns `Error::Eof` if there are no incoming packets in the RX queue.
    pub fn process_one(&mut self) -> Result<(), Error> {
        self.with_rx(|rx, this| {
            rx.consume_pdu_with(|_, pdu| match pdu {
                Pdu::Control { data } => {
                    // Also see:
                    // https://github.com/jonas-schievink/rubble/issues/26

                    let pdu = data.read();
                    info!("<- LL Control PDU: {:?}", pdu);
                    let response = match pdu {
                        // These PDUs are handled by the real-time code:
                        ControlPdu::FeatureReq { .. } | ControlPdu::VersionInd { .. } => {
                            unreachable!("LLCPDU not handled by LL");
                        }
                        _ => ControlPdu::UnknownRsp {
                            unknown_type: pdu.opcode(),
                        },
                    };
                    info!("-> Response: {:?}", response);

                    // Consume the LL Control PDU iff we can fit the response in the TX buffer:
                    Consume::on_success(this.tx.produce_with(response.encoded_size(), |writer| {
                        response.to_bytes(writer)?;
                        Ok(Llid::Control)
                    }))
                }
                Pdu::DataStart { message } => {
                    info!("L2start: {:?}", HexSlice(message));
                    this.l2cap().process_start(message)
                }
                Pdu::DataCont { message } => {
                    info!("L2cont {:?}", HexSlice(message));
                    this.l2cap().process_cont(message)
                }
            })
        })
    }

    /// Obtains access to the L2CAP instance.
    pub fn l2cap(&mut self) -> L2CAPStateTx<'_, C::ChannelMapper, ConfProducer<C>> {
        self.l2cap.tx(&mut self.tx)
    }

    /// A helper method that splits `self` into the `rx` and the remaining `Self`.
    ///
    /// This can possibly be removed after *RFC 2229 (Closures Capture Disjoint Fields)* is
    /// implemented in stable Rust.
    fn with_rx<R>(&mut self, f: impl FnOnce(&mut ConfConsumer<C>, &mut Self) -> R) -> R {
        let mut rx = self.rx.take().unwrap();
        let result = f(&mut rx, self);
        self.rx = Some(rx);
        result
    }
}

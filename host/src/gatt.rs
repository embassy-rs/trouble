use crate::adapter::Adapter;
use crate::att::Att;
use crate::attribute::Attribute;
use crate::attribute_server::AttributeServer;
use crate::connection::Connection;
use crate::l2cap::L2capPacket;
use crate::pdu::Pdu;
use bt_hci::param::ConnHandle;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::channel::{DynamicReceiver, DynamicSender};

pub struct GattServer<'a, 'b, 'd> {
    server: AttributeServer<'a, 'b>,
    rx: DynamicReceiver<'d, (ConnHandle, Pdu<'d>)>,
    tx: DynamicSender<'d, (ConnHandle, Pdu<'d>)>,
}

impl<'a, 'b, 'd> GattServer<'a, 'b, 'd> {
    pub fn new<M: RawMutex, const CHANNELS: usize, const L2CAP_TXQ: usize, const L2CAP_RXQ: usize>(
        adapter: &'d Adapter<'d, M, CHANNELS, L2CAP_TXQ, L2CAP_RXQ>,
        attributes: &'a mut [Attribute<'b>],
    ) -> Self {
        Self {
            server: AttributeServer::new(attributes),
            rx: adapter.att_channel.receiver().into(),
            tx: adapter.outbound.sender().into(),
        }
    }

    // TODO: Actually return events
    pub async fn next(&mut self) -> GattEvent<'d> {
        loop {
            let (handle, pdu) = self.rx.receive().await;
            match Att::decode(pdu.as_ref()) {
                Ok(att) => match self.server.process(att) {
                    Ok(Some(payload)) => {
                        let mut data = pdu.packet;
                        let packet = L2capPacket { channel: 4, payload };
                        let len = packet.encode(data.as_mut()).unwrap();
                        self.tx.send((handle, Pdu::new(data, len))).await;
                    }
                    Ok(None) => {
                        debug!("No response sent");
                    }
                    Err(e) => {
                        warn!("Error processing attribute: {:?}", e);
                    }
                },
                Err(e) => {
                    warn!("Error decoding attribute request: {:?}", e);
                }
            }
        }
    }
}

#[derive(Clone)]
pub enum GattEvent<'a> {
    Write(Connection<'a>, &'a Attribute<'a>),
}

use crate::adapter::Connection;
use crate::adapter::Pdu;
use crate::att::Att;
use crate::attribute::Attribute;
use crate::attribute_server::AttributeServer;
use crate::l2cap::L2capPacket;
use bt_hci::param::ConnHandle;
use embassy_sync::channel::{DynamicReceiver, DynamicSender};

pub struct GattServer<'a, 'b, 'd> {
    pub(crate) server: AttributeServer<'a, 'd>,
    pub(crate) rx: DynamicReceiver<'b, (ConnHandle, Pdu<'b>)>,
    pub(crate) tx: DynamicSender<'b, (ConnHandle, Pdu<'b>)>,
}

impl<'a, 'b, 'd> GattServer<'a, 'b, 'd> {
    // TODO: Actually return events
    pub async fn next(&mut self) -> GattEvent<'b> {
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

use crate::adapter::Adapter;
use crate::adapter::Connection;
use crate::att::Att;
use crate::attribute::Attribute;
use crate::attribute_server::AttributeServer;
use crate::l2cap::L2capPacket;
use crate::ATT_MTU;
use crate::L2CAP_MTU;
use bt_hci::param::ConnHandle;
use bt_hci::Controller;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::channel::{DynamicReceiver, DynamicSender};
use heapless::Vec;

pub struct GattServer<'a, 'd> {
    server: AttributeServer<'a, 'd>,
    rx: DynamicReceiver<'d, (ConnHandle, Vec<u8, ATT_MTU>)>,
    tx: DynamicSender<'d, (ConnHandle, Vec<u8, L2CAP_MTU>)>,
}

impl<'a, 'd> GattServer<'a, 'd> {
    pub fn new<M: RawMutex, T: Controller>(
        adapter: &'d Adapter<'d, M, T>,
        attributes: &'a mut [Attribute<'d>],
    ) -> Self {
        Self {
            server: AttributeServer::new(attributes),
            rx: adapter.att_receiver().into(),
            tx: adapter.outbound_sender().into(),
        }
    }

    pub async fn next(&mut self) -> GattEvent<'d> {
        loop {
            let (handle, pdu) = self.rx.receive().await;
            match Att::decode(&pdu[..]) {
                Ok(att) => match self.server.process(att) {
                    Ok(Some(payload)) => {
                        let mut pdu = [0u8; L2CAP_MTU];
                        let packet = L2capPacket { channel: 4, payload };
                        let len = packet.encode(&mut pdu);
                        self.tx.send((handle, Vec::from_slice(&pdu[..len]).unwrap())).await;
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

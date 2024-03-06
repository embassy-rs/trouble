use bt_hci::{
    cmd::link_control::DisconnectParams,
    param::{ConnHandle, DisconnectReason},
};
use embassy_sync::{blocking_mutex::raw::RawMutex, channel::DynamicSender};

use crate::{
    adapter::{AdapterResources, ControlCommand},
    pdu::Pdu,
};

#[derive(Clone)]
pub struct Connection<'d> {
    handle: ConnHandle,
    tx: DynamicSender<'d, (ConnHandle, Pdu<'d>)>,
    control: DynamicSender<'d, ControlCommand>,
}

impl<'d> Connection<'d> {
    pub async fn accept<M: RawMutex, const CHANNELS: usize, const L2CAP_TXQ: usize, const L2CAP_RXQ: usize>(
        resources: &'d AdapterResources<'d, M, CHANNELS, L2CAP_TXQ, L2CAP_RXQ>,
    ) -> Self {
        let handle = resources.acceptor.receive().await;
        Connection {
            handle,
            tx: resources.outbound.sender().into(),
            control: resources.control.sender().into(),
        }
    }

    pub async fn disconnect(&mut self) {
        self.control
            .send(ControlCommand::Disconnect(DisconnectParams {
                handle: self.handle,
                reason: DisconnectReason::RemoteUserTerminatedConn,
            }))
            .await;
    }
}

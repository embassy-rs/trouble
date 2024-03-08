use bt_hci::{
    cmd::link_control::DisconnectParams,
    param::{ConnHandle, DisconnectReason},
};
use embassy_sync::{blocking_mutex::raw::RawMutex, channel::DynamicSender};

use crate::adapter::{Adapter, ControlCommand};

#[derive(Clone)]
pub struct Connection<'d> {
    handle: ConnHandle,
    control: DynamicSender<'d, ControlCommand>,
}

impl<'d> Connection<'d> {
    pub fn handle(&self) -> ConnHandle {
        self.handle
    }

    pub async fn accept<
        M: RawMutex,
        const CONNS: usize,
        const CHANNELS: usize,
        const L2CAP_TXQ: usize,
        const L2CAP_RXQ: usize,
    >(
        adapter: &'d Adapter<'d, M, CONNS, CHANNELS, L2CAP_TXQ, L2CAP_RXQ>,
    ) -> Self {
        let handle = adapter.connections.accept().await;
        Connection {
            handle,
            control: adapter.control.sender().into(),
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

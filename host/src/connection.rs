use bt_hci::{
    cmd::{le::LeCreateConnParams, link_control::DisconnectParams},
    param::{AddrKind, BdAddr, ConnHandle, DisconnectReason, Duration},
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
        let handle = adapter.connections.accept(None).await;
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

    pub async fn connect<
        M: RawMutex,
        const CONNS: usize,
        const CHANNELS: usize,
        const L2CAP_TXQ: usize,
        const L2CAP_RXQ: usize,
    >(
        adapter: &'d Adapter<'d, M, CONNS, CHANNELS, L2CAP_TXQ, L2CAP_RXQ>,
        peer_addr: BdAddr,
    ) -> Self {
        // TODO: Make this configurable
        let params = LeCreateConnParams {
            le_scan_interval: Duration::from_micros(1707500),
            le_scan_window: Duration::from_micros(312500),
            use_filter_accept_list: false,
            peer_addr_kind: AddrKind::PUBLIC,
            peer_addr,
            own_addr_kind: AddrKind::PUBLIC,
            conn_interval_min: Duration::from_millis(25),
            conn_interval_max: Duration::from_millis(50),
            max_latency: 0,
            supervision_timeout: Duration::from_millis(250),
            min_ce_length: Duration::from_millis(0),
            max_ce_length: Duration::from_millis(0),
        };
        adapter.control.send(ControlCommand::Connect(params)).await;
        let handle = adapter.connections.accept(Some(params.peer_addr)).await;
        Connection {
            handle,
            control: adapter.control.sender().into(),
        }
    }
}

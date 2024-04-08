use bt_hci::{
    cmd::{
        le::{
            LeAddDeviceToFilterAcceptList, LeClearFilterAcceptList, LeCreateConn, LeExtCreateConn, LeSetExtScanEnable,
            LeSetExtScanParams, LeSetScanEnable, LeSetScanParams,
        },
        link_control::DisconnectParams,
    },
    controller::{ControllerCmdAsync, ControllerCmdSync},
    param::{BdAddr, ConnHandle, DisconnectReason, LeConnRole},
};
use embassy_sync::{blocking_mutex::raw::RawMutex, channel::DynamicSender};

use crate::adapter::{Adapter, ControlCommand};
use crate::scan::ScanConfig;
use crate::AdapterError;
use embassy_time::Duration;

pub use crate::connection_manager::ConnectionInfo;

#[derive(Clone)]
pub struct Connection<'d> {
    pub(crate) info: ConnectionInfo,
    pub(crate) control: DynamicSender<'d, ControlCommand>,
}

pub struct ConnectConfig<'d> {
    pub scan_config: ScanConfig<'d>,
    pub connect_params: ConnectParams,
}

pub struct ConnectParams {
    pub min_connection_interval: Duration,
    pub max_connection_interval: Duration,
    pub max_latency: u16,
    pub supervision_timeout: Duration,
}

impl Default for ConnectParams {
    fn default() -> Self {
        Self {
            min_connection_interval: Duration::from_millis(80),
            max_connection_interval: Duration::from_millis(80),
            max_latency: 0,
            supervision_timeout: Duration::from_secs(8),
        }
    }
}

impl<'d> Connection<'d> {
    pub fn handle(&self) -> ConnHandle {
        self.info.handle
    }

    pub async fn accept<
        M: RawMutex,
        T,
        const CONNS: usize,
        const CHANNELS: usize,
        const L2CAP_TXQ: usize,
        const L2CAP_RXQ: usize,
    >(
        adapter: &'d Adapter<'_, M, T, CONNS, CHANNELS, L2CAP_TXQ, L2CAP_RXQ>,
    ) -> Self {
        let info = adapter.connections.accept(None).await;
        Connection {
            info,
            control: adapter.control.sender().into(),
        }
    }

    pub async fn disconnect(&mut self) {
        self.control
            .send(ControlCommand::Disconnect(DisconnectParams {
                handle: self.info.handle,
                reason: DisconnectReason::RemoteUserTerminatedConn,
            }))
            .await;
    }

    pub fn role(&self) -> LeConnRole {
        self.info.role
    }

    pub fn peer_address(&self) -> BdAddr {
        self.info.peer_address
    }

    pub async fn connect<
        M: RawMutex,
        T,
        const CONNS: usize,
        const CHANNELS: usize,
        const L2CAP_TXQ: usize,
        const L2CAP_RXQ: usize,
    >(
        adapter: &'d Adapter<'_, M, T, CONNS, CHANNELS, L2CAP_TXQ, L2CAP_RXQ>,
        config: &ConnectConfig<'_>,
    ) -> Result<Self, AdapterError<T::Error>>
    where
        T: ControllerCmdSync<LeClearFilterAcceptList>
            + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
            + ControllerCmdAsync<LeCreateConn>
            + ControllerCmdAsync<LeExtCreateConn>
            + ControllerCmdSync<LeSetExtScanEnable>
            + ControllerCmdSync<LeSetExtScanParams>
            + ControllerCmdSync<LeSetScanParams>
            + ControllerCmdSync<LeSetScanEnable>,
    {
        adapter.connect(config).await
    }
}

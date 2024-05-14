//! BLE connection.
use bt_hci::cmd::le::LeConnUpdate;
use bt_hci::cmd::link_control::Disconnect;
use bt_hci::cmd::status::ReadRssi;
use bt_hci::controller::{Controller, ControllerCmdAsync, ControllerCmdSync};
use bt_hci::param::{BdAddr, ConnHandle, DisconnectReason, LeConnRole};
use embassy_time::Duration;

use crate::host::BleHost;
use crate::scan::ScanConfig;
use crate::BleHostError;

#[derive(Clone)]
pub struct Connection {
    handle: ConnHandle,
}

pub struct ConnectConfig<'d> {
    pub scan_config: ScanConfig<'d>,
    pub connect_params: ConnectParams,
}

pub struct ConnectParams {
    pub min_connection_interval: Duration,
    pub max_connection_interval: Duration,
    pub max_latency: u16,
    pub event_length: Duration,
    pub supervision_timeout: Duration,
}

impl Default for ConnectParams {
    fn default() -> Self {
        Self {
            min_connection_interval: Duration::from_millis(80),
            max_connection_interval: Duration::from_millis(80),
            max_latency: 0,
            event_length: Duration::from_secs(0),
            supervision_timeout: Duration::from_secs(8),
        }
    }
}

impl Connection {
    pub(crate) fn new(handle: ConnHandle) -> Self {
        Self { handle }
    }

    /// Connection handle of this connection.
    pub fn handle(&self) -> ConnHandle {
        self.handle
    }

    /// Request disconnection of this connection handle.
    pub fn disconnect<T: Controller + ControllerCmdSync<Disconnect>>(
        &mut self,
        ble: &BleHost<'_, T>,
    ) -> Result<(), BleHostError<T::Error>> {
        ble.connections
            .request_disconnect(self.handle, DisconnectReason::RemoteUserTerminatedConn)?;
        Ok(())
    }

    /// The connection role for this connection.
    pub fn role<T: Controller>(&self, ble: &BleHost<'_, T>) -> Result<LeConnRole, BleHostError<T::Error>> {
        let role = ble.connections.role(self.handle)?;
        Ok(role)
    }

    /// The peer address for this connection.
    pub fn peer_address<T: Controller>(&self, ble: &BleHost<'_, T>) -> Result<BdAddr, BleHostError<T::Error>> {
        let addr = ble.connections.peer_address(self.handle)?;
        Ok(addr)
    }

    /// The RSSI value for this connection.
    pub async fn rssi<T>(&self, ble: &BleHost<'_, T>) -> Result<i8, BleHostError<T::Error>>
    where
        T: ControllerCmdSync<ReadRssi>,
    {
        let ret = ble.command(ReadRssi::new(self.handle)).await?;
        Ok(ret.rssi)
    }

    /// Update connection parameters for this connection.
    pub async fn set_connection_params<T>(
        &self,
        ble: &BleHost<'_, T>,
        params: ConnectParams,
    ) -> Result<(), BleHostError<T::Error>>
    where
        T: ControllerCmdAsync<LeConnUpdate>,
    {
        ble.async_command(LeConnUpdate::new(
            self.handle,
            params.min_connection_interval.into(),
            params.max_connection_interval.into(),
            params.max_latency,
            params.supervision_timeout.into(),
            bt_hci::param::Duration::from_secs(0),
            bt_hci::param::Duration::from_secs(0),
        ))
        .await?;
        Ok(())
    }
}

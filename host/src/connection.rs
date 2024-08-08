//! BLE connection.
use bt_hci::cmd::le::LeConnUpdate;
use bt_hci::cmd::status::ReadRssi;
use bt_hci::controller::{ControllerCmdAsync, ControllerCmdSync};
use bt_hci::param::{BdAddr, ConnHandle, DisconnectReason, LeConnRole};
use embassy_time::Duration;

use crate::connection_manager::DynamicConnectionManager;
use crate::host::BleHost;
use crate::scan::ScanConfig;
use crate::BleHostError;

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

pub struct Connection<'d> {
    index: u8,
    manager: &'d dyn DynamicConnectionManager,
}

impl<'d> Clone for Connection<'d> {
    fn clone(&self) -> Self {
        self.manager.inc_ref(self.index);
        Connection::new(self.index, self.manager)
    }
}

impl<'d> Drop for Connection<'d> {
    fn drop(&mut self) {
        self.manager.dec_ref(self.index);
    }
}

impl<'d> Connection<'d> {
    pub(crate) fn new(index: u8, manager: &'d dyn DynamicConnectionManager) -> Self {
        Self { index, manager }
    }

    pub(crate) fn set_att_mtu(&self, mtu: u16) {
        self.manager.set_att_mtu(self.index, mtu);
    }

    /// Check if still connected
    pub fn is_connected(&self) -> bool {
        self.manager.is_connected(self.index)
    }

    /// Connection handle of this connection.
    pub fn handle(&self) -> ConnHandle {
        self.manager.handle(self.index)
    }

    /// The connection role for this connection.
    pub fn role(&self) -> LeConnRole {
        self.manager.role(self.index)
    }

    /// The peer address for this connection.
    pub fn peer_address(&self) -> BdAddr {
        self.manager.peer_address(self.index)
    }

    pub fn disconnect(&self) {
        self.manager
            .disconnect(self.index, DisconnectReason::RemoteUserTerminatedConn);
    }

    /// The RSSI value for this connection.
    pub async fn rssi<T>(&self, ble: &BleHost<'_, T>) -> Result<i8, BleHostError<T::Error>>
    where
        T: ControllerCmdSync<ReadRssi>,
    {
        let handle = self.handle();
        let ret = ble.command(ReadRssi::new(handle)).await?;
        Ok(ret.rssi)
    }

    /// Update connection parameters for this connection.
    pub async fn update_connection_params<T>(
        &self,
        ble: &BleHost<'_, T>,
        params: ConnectParams,
    ) -> Result<(), BleHostError<T::Error>>
    where
        T: ControllerCmdAsync<LeConnUpdate>,
    {
        let handle = self.handle();
        trace!("[host] updating connection params for {:?}", handle);
        match ble
            .async_command(LeConnUpdate::new(
                handle,
                params.min_connection_interval.into(),
                params.max_connection_interval.into(),
                params.max_latency,
                params.supervision_timeout.into(),
                params.event_length.into(),
                params.event_length.into(),
            ))
            .await
        {
            Ok(_) => Ok(()),
            Err(BleHostError::BleHost(crate::Error::HciEncode(bt_hci::param::Error::UNKNOWN_CONN_IDENTIFIER))) => {
                Err(crate::Error::Disconnected.into())
            }
            Err(e) => Err(e),
        }
    }
}

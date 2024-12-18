//! BLE connection.
use crate::pdu::Pdu;
use bt_hci::cmd::le::LeConnUpdate;
use bt_hci::cmd::status::ReadRssi;
use bt_hci::controller::{ControllerCmdAsync, ControllerCmdSync};
use bt_hci::param::{BdAddr, ConnHandle, DisconnectReason, LeConnRole, Status};
use embassy_time::Duration;

use crate::connection_manager::ConnectionManager;
use crate::scan::ScanConfig;
use crate::{BleHostError, Error, Stack};

/// Connection configuration.
pub struct ConnectConfig<'d> {
    /// Scan configuration to use while connecting.
    pub scan_config: ScanConfig<'d>,
    /// Parameters to use for the connection.
    pub connect_params: ConnectParams,
}

/// Connection parameters.
pub struct ConnectParams {
    /// Minimum connection interval.
    pub min_connection_interval: Duration,
    /// Maximum connection interval.
    pub max_connection_interval: Duration,
    /// Maximum slave latency.
    pub max_latency: u16,
    /// Event length.
    pub event_length: Duration,
    /// Supervision timeout.
    pub supervision_timeout: Duration,
}

/// An event
pub enum ConnectionEvent<'d> {
    /// Connection disconnected.
    Disconnected {
        /// The reason (status code) for the disconnect.
        reason: Status,
    },
    /// GATT event.
    Gatt {
        /// The event that was returned
        #[cfg(feature = "gatt")]
        data: crate::gatt::GattData<'d>,
        #[cfg(not(feature = "gatt"))]
        /// Connection handle for the event
        connection: Connection<'d>,
    },
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

/// Handle to a BLE connection.
///
/// When the last reference to a connection is dropped, the connection is automatically disconnected.
pub struct Connection<'d> {
    index: u8,
    manager: &'d ConnectionManager<'d>,
}

impl Clone for Connection<'_> {
    fn clone(&self) -> Self {
        self.manager.inc_ref(self.index);
        Connection::new(self.index, self.manager)
    }
}

impl Drop for Connection<'_> {
    fn drop(&mut self) {
        self.manager.dec_ref(self.index);
    }
}

impl<'d> Connection<'d> {
    pub(crate) fn new(index: u8, manager: &'d ConnectionManager<'d>) -> Self {
        Self { index, manager }
    }

    pub(crate) fn set_att_mtu(&self, mtu: u16) {
        self.manager.set_att_mtu(self.index, mtu);
    }

    pub(crate) fn get_att_mtu(&self) -> u16 {
        self.manager.get_att_mtu(self.index)
    }

    pub(crate) async fn send(&self, pdu: Pdu<'d>) {
        self.manager.send(self.index, pdu).await
    }

    pub(crate) fn try_send(&self, pdu: Pdu<'d>) -> Result<(), Error> {
        self.manager.try_send(self.index, pdu)
    }

    pub(crate) async fn post_event(&self, event: ConnectionEvent<'d>) {
        self.manager.post_event(self.index, event).await
    }

    #[cfg(feature = "gatt")]
    pub(crate) fn alloc_tx(&self) -> Result<crate::packet_pool::Packet<'d>, Error> {
        self.manager.alloc_tx()
    }

    /// Wait for next connection event.
    pub async fn next(&self) -> ConnectionEvent<'d> {
        self.manager.next(self.index).await
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

    /// Request connection to be disconnected.
    pub fn disconnect(&self) {
        self.manager
            .request_disconnect(self.index, DisconnectReason::RemoteUserTerminatedConn);
    }

    /// The RSSI value for this connection.
    pub async fn rssi<T>(&self, stack: Stack<'_, T>) -> Result<i8, BleHostError<T::Error>>
    where
        T: ControllerCmdSync<ReadRssi>,
    {
        let handle = self.handle();
        let ret = stack.host.command(ReadRssi::new(handle)).await?;
        Ok(ret.rssi)
    }

    /// Update connection parameters for this connection.
    pub async fn update_connection_params<T>(
        &self,
        stack: Stack<'_, T>,
        params: ConnectParams,
    ) -> Result<(), BleHostError<T::Error>>
    where
        T: ControllerCmdAsync<LeConnUpdate>,
    {
        let handle = self.handle();
        match stack
            .host
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
            Err(BleHostError::BleHost(crate::Error::Hci(bt_hci::param::Error::UNKNOWN_CONN_IDENTIFIER))) => {
                Err(crate::Error::Disconnected.into())
            }
            Err(e) => Err(e),
        }
    }
}

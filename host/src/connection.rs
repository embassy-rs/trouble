//! BLE connection.

use bt_hci::cmd::le::{LeConnUpdate, LeReadPhy, LeSetPhy};
use bt_hci::cmd::status::ReadRssi;
use bt_hci::controller::{ControllerCmdAsync, ControllerCmdSync};
use bt_hci::param::{
    AddrKind, AllPhys, BdAddr, ConnHandle, DisconnectReason, LeConnRole, PhyKind, PhyMask, PhyOptions, Status,
};
#[cfg(feature = "gatt")]
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_time::Duration;

use crate::connection_manager::ConnectionManager;
#[cfg(feature = "connection-metrics")]
pub use crate::connection_manager::Metrics as ConnectionMetrics;
use crate::pdu::Pdu;
#[cfg(feature = "gatt")]
use crate::prelude::{AttributeServer, GattConnection};
#[cfg(feature = "security")]
use crate::security_manager::BondInformation;
use crate::{BleHostError, Error, PacketPool, Stack};

/// Connection configuration.
pub struct ConnectConfig<'d> {
    /// Scan configuration to use while connecting.
    pub scan_config: ScanConfig<'d>,
    /// Parameters to use for the connection.
    pub connect_params: ConnectParams,
}

/// Scan/connect configuration.
pub struct ScanConfig<'d> {
    /// Active scanning.
    pub active: bool,
    /// List of addresses to accept.
    pub filter_accept_list: &'d [(AddrKind, &'d BdAddr)],
    /// PHYs to scan on.
    pub phys: PhySet,
    /// Scan interval.
    pub interval: Duration,
    /// Scan window.
    pub window: Duration,
    /// Scan timeout.
    pub timeout: Duration,
}

impl Default for ScanConfig<'_> {
    fn default() -> Self {
        Self {
            active: true,
            filter_accept_list: &[],
            phys: PhySet::M1,
            interval: Duration::from_secs(1),
            window: Duration::from_secs(1),
            timeout: Duration::from_secs(0),
        }
    }
}

/// PHYs to scan on.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Eq, PartialEq, Copy, Clone)]
#[repr(u8)]
pub enum PhySet {
    /// 1Mbps phy
    M1 = 1,
    /// 2Mbps phy
    M2 = 2,
    /// 1Mbps + 2Mbps phys
    M1M2 = 3,
    /// Coded phy (125kbps, S=8)
    Coded = 4,
    /// 1Mbps and Coded phys
    M1Coded = 5,
    /// 2Mbps and Coded phys
    M2Coded = 6,
    /// 1Mbps, 2Mbps and Coded phys
    M1M2Coded = 7,
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

/// A connection event.
#[derive(Debug)]
pub enum ConnectionEvent {
    /// Connection disconnected.
    Disconnected {
        /// The reason (status code) for the disconnect.
        reason: Status,
    },
    /// The phy settings was updated for this connection.
    PhyUpdated {
        /// The TX phy.
        tx_phy: PhyKind,
        /// The RX phy.
        rx_phy: PhyKind,
    },
    /// The phy settings was updated for this connection.
    ConnectionParamsUpdated {
        /// Connection interval.
        conn_interval: Duration,
        /// Peripheral latency.
        peripheral_latency: u16,
        /// Supervision timeout.
        supervision_timeout: Duration,
    },
    #[cfg(feature = "security")]
    /// Bonded event.
    Bonded {
        /// Bond info for this connection
        bond_info: BondInformation,
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
pub struct Connection<'stack, P: PacketPool> {
    index: u8,
    manager: &'stack ConnectionManager<'stack, P>,
}

impl<P: PacketPool> Clone for Connection<'_, P> {
    fn clone(&self) -> Self {
        self.manager.inc_ref(self.index);
        Connection::new(self.index, self.manager)
    }
}

impl<P: PacketPool> Drop for Connection<'_, P> {
    fn drop(&mut self) {
        self.manager.dec_ref(self.index);
    }
}

impl<'stack, P: PacketPool> Connection<'stack, P> {
    pub(crate) fn new(index: u8, manager: &'stack ConnectionManager<'stack, P>) -> Self {
        Self { index, manager }
    }

    pub(crate) fn set_att_mtu(&self, mtu: u16) {
        self.manager.set_att_mtu(self.index, mtu);
    }

    pub(crate) fn get_att_mtu(&self) -> u16 {
        self.manager.get_att_mtu(self.index)
    }

    pub(crate) async fn send(&self, pdu: Pdu<P::Packet>) {
        self.manager.send(self.index, pdu).await
    }

    pub(crate) fn try_send(&self, pdu: Pdu<P::Packet>) -> Result<(), Error> {
        self.manager.try_send(self.index, pdu)
    }

    pub(crate) async fn post_event(&self, event: ConnectionEvent) {
        self.manager.post_event(self.index, event).await
    }

    /// Wait for next connection event.
    pub async fn next(&self) -> ConnectionEvent {
        self.manager.next(self.index).await
    }

    #[cfg(feature = "gatt")]
    pub(crate) async fn next_gatt(&self) -> Pdu<P::Packet> {
        self.manager.next_gatt(self.index).await
    }

    /// Check if still connected
    pub fn is_connected(&self) -> bool {
        self.manager.is_connected(self.index)
    }

    /// Connection handle of this connection.
    pub fn handle(&self) -> ConnHandle {
        self.manager.handle(self.index)
    }

    /// Expose the att_mtu.
    pub fn att_mtu(&self) -> u16 {
        self.get_att_mtu()
    }

    /// The connection role for this connection.
    pub fn role(&self) -> LeConnRole {
        self.manager.role(self.index)
    }

    /// The peer address for this connection.
    pub fn peer_address(&self) -> BdAddr {
        self.manager.peer_address(self.index)
    }

    /// Get the encrypted state of the connection
    pub fn encrypted(&self) -> bool {
        self.manager.get_encrypted(self.index)
    }

    /// Request connection to be disconnected.
    pub fn disconnect(&self) {
        self.manager
            .request_disconnect(self.index, DisconnectReason::RemoteUserTerminatedConn);
    }

    /// Read metrics for this connection
    #[cfg(feature = "connection-metrics")]
    pub fn metrics<F: FnOnce(&ConnectionMetrics) -> R, R>(&self, f: F) -> R {
        self.manager.metrics(self.index, f)
    }

    /// The RSSI value for this connection.
    pub async fn rssi<T>(&self, stack: &Stack<'_, T, P>) -> Result<i8, BleHostError<T::Error>>
    where
        T: ControllerCmdSync<ReadRssi>,
    {
        let handle = self.handle();
        let ret = stack.host.command(ReadRssi::new(handle)).await?;
        Ok(ret.rssi)
    }

    /// Update phy for this connection.
    ///
    /// This updates both TX and RX phy of the connection. For more fine grained control,
    /// use the LeSetPhy HCI command directly.
    pub async fn set_phy<T>(&self, stack: &Stack<'_, T, P>, phy: PhyKind) -> Result<(), BleHostError<T::Error>>
    where
        T: ControllerCmdAsync<LeSetPhy>,
    {
        let all_phys = AllPhys::new()
            .set_has_no_rx_phy_preference(false)
            .set_has_no_tx_phy_preference(false);
        let mut mask = PhyMask::new()
            .set_le_coded_preferred(false)
            .set_le_1m_preferred(false)
            .set_le_2m_preferred(false);
        let mut options = PhyOptions::default();
        match phy {
            PhyKind::Le2M => {
                mask = mask.set_le_2m_preferred(true);
            }
            PhyKind::Le1M => {
                mask = mask.set_le_1m_preferred(true);
            }
            PhyKind::LeCoded => {
                mask = mask.set_le_coded_preferred(true);
                options = PhyOptions::S8CodingPreferred;
            }
            PhyKind::LeCodedS2 => {
                mask = mask.set_le_coded_preferred(true);
                options = PhyOptions::S2CodingPreferred;
            }
        }
        stack
            .host
            .async_command(LeSetPhy::new(self.handle(), all_phys, mask, mask, options))
            .await?;
        Ok(())
    }

    /// Read the current phy used for the connection.
    pub async fn read_phy<T>(&self, stack: &Stack<'_, T, P>) -> Result<(PhyKind, PhyKind), BleHostError<T::Error>>
    where
        T: ControllerCmdSync<LeReadPhy>,
    {
        let res = stack.host.command(LeReadPhy::new(self.handle())).await?;
        Ok((res.tx_phy, res.rx_phy))
    }

    /// Update connection parameters for this connection.
    pub async fn update_connection_params<T>(
        &self,
        stack: &Stack<'_, T, P>,
        params: &ConnectParams,
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

    /// Transform BLE connection into a `GattConnection`
    #[cfg(feature = "gatt")]
    pub fn with_attribute_server<
        'values,
        'server,
        M: RawMutex,
        const ATT_MAX: usize,
        const CCCD_MAX: usize,
        const CONN_MAX: usize,
    >(
        self,
        server: &'server AttributeServer<'values, M, P, ATT_MAX, CCCD_MAX, CONN_MAX>,
    ) -> Result<GattConnection<'stack, 'server, P>, Error> {
        GattConnection::try_new(self, server)
    }
}

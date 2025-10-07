//! BLE connection.

use bt_hci::cmd::le::{LeConnUpdate, LeReadLocalSupportedFeatures, LeReadPhy, LeSetDataLength, LeSetPhy};
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
use crate::security_manager::{BondInformation, PassKey};
use crate::types::l2cap::{ConnParamUpdateReq, ConnParamUpdateRes};
use crate::{bt_hci_duration, BleHostError, Error, Identity, PacketPool, Stack};

/// Security level of a connection
///
/// This describes the various security levels that are supported.
///
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SecurityLevel {
    /// No encryption and no authentication. All connections start on this security level.
    NoEncryption,
    /// Encrypted but not authenticated communication. Does not provide MITM protection.
    Encrypted,
    /// Encrypted and authenticated security level. MITM protected.
    EncryptedAuthenticated,
}

impl SecurityLevel {
    /// Check if the security level is encrypted.
    pub fn encrypted(&self) -> bool {
        !matches!(self, SecurityLevel::NoEncryption)
    }

    /// Check if the security level is authenticated.
    pub fn authenticated(&self) -> bool {
        matches!(self, SecurityLevel::EncryptedAuthenticated)
    }
}

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
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConnectParams {
    /// Minimum connection interval.
    pub min_connection_interval: Duration,
    /// Maximum connection interval.
    pub max_connection_interval: Duration,
    /// Maximum slave latency.
    pub max_latency: u16,
    /// Event length.
    pub min_event_length: Duration,
    /// Event length.
    pub max_event_length: Duration,
    /// Supervision timeout.
    pub supervision_timeout: Duration,
}

/// A connection event.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
    /// The data length was changed for this connection.
    DataLengthUpdated {
        /// Max TX octets.
        max_tx_octets: u16,
        /// Max TX time.
        max_tx_time: u16,
        /// Max RX octets.
        max_rx_octets: u16,
        /// Max RX time.
        max_rx_time: u16,
    },
    /// A request to change the connection parameters.
    RequestConnectionParams {
        /// Minimum connection interval.
        min_connection_interval: Duration,
        /// Maximum connection interval.
        max_connection_interval: Duration,
        /// Maximum slave latency.
        max_latency: u16,
        /// Supervision timeout.
        supervision_timeout: Duration,
    },
    #[cfg(feature = "security")]
    /// Request to display a pass key
    PassKeyDisplay(PassKey),
    #[cfg(feature = "security")]
    /// Request to display and confirm a pass key
    PassKeyConfirm(PassKey),
    #[cfg(feature = "security")]
    /// Request to make the user input the pass key
    PassKeyInput,
    #[cfg(feature = "security")]
    /// Pairing completed
    PairingComplete {
        /// Security level of this pairing
        security_level: SecurityLevel,
        /// Bond information if the devices create a bond with this pairing.
        bond: Option<BondInformation>,
    },
    #[cfg(feature = "security")]
    /// Pairing completed
    PairingFailed(Error),
}

impl Default for ConnectParams {
    fn default() -> Self {
        Self {
            min_connection_interval: Duration::from_millis(80),
            max_connection_interval: Duration::from_millis(80),
            max_latency: 0,
            min_event_length: Duration::from_secs(0),
            max_event_length: Duration::from_secs(0),
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

    /// The peer identity key for this connection.
    pub fn peer_identity(&self) -> Identity {
        self.manager.peer_identity(self.index)
    }
    /// Request a certain security level
    ///
    /// For a peripheral this may cause the peripheral to send a security request. For a central
    /// this may cause the central to send a pairing request.
    ///
    /// If the link is already encrypted then this will always generate an error.
    ///
    pub fn request_security(&self) -> Result<(), Error> {
        self.manager.request_security(self.index)
    }

    /// Get the encrypted state of the connection
    pub fn security_level(&self) -> Result<SecurityLevel, Error> {
        self.manager.get_security_level(self.index)
    }

    /// Get whether the connection is set as bondable or not.
    ///
    /// This is only relevant before pairing has started.
    pub fn bondable(&self) -> Result<bool, Error> {
        self.manager.get_bondable(self.index)
    }

    /// Set whether the connection is bondable or not.
    ///
    /// By default a connection is **not** bondable.
    ///
    /// This must be set before pairing is initiated. Once the pairing procedure has started
    /// this field is ignored.
    ///
    /// If both peripheral and central are bondable then the [`ConnectionEvent::PairingComplete`]
    /// event contains the bond information for the pairing. This bond information should be stored
    /// in non-volatile memory and restored on reboot using [`Stack::add_bond_information()`].
    ///
    /// If any party in a pairing is not bondable the [`ConnectionEvent::PairingComplete`] contains
    /// a `None` entry for the `bond` member.
    ///
    pub fn set_bondable(&self, bondable: bool) -> Result<(), Error> {
        self.manager.set_bondable(self.index, bondable)
    }

    /// Confirm that the displayed pass key matches the one displayed on the other party
    pub fn pass_key_confirm(&self) -> Result<(), Error> {
        self.manager.pass_key_confirm(self.index, true)
    }

    /// The displayed pass key does not match the one displayed on the other party
    pub fn pass_key_cancel(&self) -> Result<(), Error> {
        self.manager.pass_key_confirm(self.index, false)
    }

    /// Input the pairing pass key
    pub fn pass_key_input(&self, pass_key: u32) -> Result<(), Error> {
        self.manager.pass_key_input(self.index, pass_key)
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

    /// Update data length for this connection.
    pub async fn update_data_length<T>(
        &self,
        stack: &Stack<'_, T, P>,
        length: u16,
        time_us: u16,
    ) -> Result<(), BleHostError<T::Error>>
    where
        T: ControllerCmdSync<LeSetDataLength> + ControllerCmdSync<LeReadLocalSupportedFeatures>,
    {
        let handle = self.handle();
        // First, check the local supported features to ensure that the connection update is supported.
        let features = stack.host.command(LeReadLocalSupportedFeatures::new()).await?;
        if length <= 27 || features.supports_le_data_packet_length_extension() {
            match stack.host.command(LeSetDataLength::new(handle, length, time_us)).await {
                Ok(_) => Ok(()),
                Err(BleHostError::BleHost(crate::Error::Hci(bt_hci::param::Error::UNKNOWN_CONN_IDENTIFIER))) => {
                    Err(crate::Error::Disconnected.into())
                }
                Err(e) => Err(e),
            }
        } else {
            Err(BleHostError::BleHost(Error::InvalidValue))
        }
    }

    /// Update connection parameters for this connection.
    pub async fn update_connection_params<T>(
        &self,
        stack: &Stack<'_, T, P>,
        params: &ConnectParams,
    ) -> Result<(), BleHostError<T::Error>>
    where
        T: ControllerCmdAsync<LeConnUpdate> + ControllerCmdSync<LeReadLocalSupportedFeatures>,
    {
        let handle = self.handle();
        // First, check the local supported features to ensure that the connection update is supported.
        let features = stack.host.command(LeReadLocalSupportedFeatures::new()).await?;
        if features.supports_conn_parameters_request_procedure() || self.role() == LeConnRole::Central {
            match stack.host.async_command(into_le_conn_update(handle, params)).await {
                Ok(_) => return Ok(()),
                Err(BleHostError::BleHost(crate::Error::Hci(bt_hci::param::Error::UNKNOWN_CONN_IDENTIFIER))) => {
                    return Err(crate::Error::Disconnected.into());
                }
                Err(BleHostError::BleHost(crate::Error::Hci(bt_hci::param::Error::UNSUPPORTED_REMOTE_FEATURE))) => {
                    // We tried to send the request as a peripheral but the remote central does not support procedure.
                    // Use the L2CAP signaling method below instead.
                    // This code path should never be reached when acting as a central. If a bugged controller implementation
                    // returns this error code we transmit an invalid L2CAP signal which then is rejected by the remote.
                }
                Err(e) => return Err(e),
            }
        }

        // Use L2CAP signaling to update connection parameters
        info!(
            "Connection parameters request procedure not supported, use l2cap connection parameter update req instead"
        );
        let interval_min: bt_hci::param::Duration<1_250> = bt_hci_duration(params.min_connection_interval);
        let interva_max: bt_hci::param::Duration<1_250> = bt_hci_duration(params.max_connection_interval);
        let timeout: bt_hci::param::Duration<10_000> = bt_hci_duration(params.supervision_timeout);
        let param = ConnParamUpdateReq {
            interval_min: interval_min.as_u16(),
            interval_max: interva_max.as_u16(),
            latency: params.max_latency,
            timeout: timeout.as_u16(),
        };
        stack.host.send_conn_param_update_req(handle, &param).await
    }

    /// Respond to updated parameters.
    pub async fn accept_connection_params<T>(
        &self,
        stack: &Stack<'_, T, P>,
        params: &ConnectParams,
    ) -> Result<(), BleHostError<T::Error>>
    where
        T: ControllerCmdAsync<LeConnUpdate>,
    {
        let handle = self.handle();
        if self.role() == LeConnRole::Central {
            match stack.host.async_command(into_le_conn_update(handle, params)).await {
                Ok(_) => {
                    // Use L2CAP signaling to update connection parameters
                    info!(
                        "Connection parameters request procedure not supported, use l2cap connection parameter update res instead"
                    );
                    let param = ConnParamUpdateRes { result: 0 };
                    stack.host.send_conn_param_update_res(handle, &param).await?;
                    Ok(())
                }
                Err(BleHostError::BleHost(crate::Error::Hci(bt_hci::param::Error::UNKNOWN_CONN_IDENTIFIER))) => {
                    Err(crate::Error::Disconnected.into())
                }
                Err(e) => {
                    info!("Connection parameters request procedure failed");
                    let param = ConnParamUpdateRes { result: 1 };
                    stack.host.send_conn_param_update_res(handle, &param).await?;
                    Err(e)
                }
            }
        } else {
            Err(crate::Error::NotSupported.into())
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

fn into_le_conn_update(handle: ConnHandle, params: &ConnectParams) -> LeConnUpdate {
    LeConnUpdate::new(
        handle,
        bt_hci_duration(params.min_connection_interval),
        bt_hci_duration(params.max_connection_interval),
        params.max_latency,
        bt_hci_duration(params.supervision_timeout),
        bt_hci_duration(params.min_event_length),
        bt_hci_duration(params.max_event_length),
    )
}

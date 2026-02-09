//! GAP service (ID 1) protocol definitions.

use alloc::boxed::Box;
use alloc::vec::Vec;

use embassy_time::Duration;
use embedded_io_async::Write;
use trouble_host::IoCapabilities;
use trouble_host::prelude::RequestedConnParams;

use super::Cursor;
use super::header::BtpHeader;
use crate::btp::error::Error;
use crate::btp::types::{AddrKind, Address, BdAddr, ServiceId};
use crate::peripheral::AdvertisementParams;

/// GAP service opcodes.
pub mod opcodes {
    use crate::btp::types::Opcode;

    // Commands
    pub const READ_SUPPORTED_COMMANDS: Opcode = Opcode(0x01);
    pub const READ_CONTROLLER_INDEX_LIST: Opcode = Opcode(0x02);
    pub const READ_CONTROLLER_INFO: Opcode = Opcode(0x03);
    pub const SET_CONNECTABLE: Opcode = Opcode(0x06);
    pub const SET_DISCOVERABLE: Opcode = Opcode(0x08);
    pub const SET_BONDABLE: Opcode = Opcode(0x09);
    pub const START_ADVERTISING: Opcode = Opcode(0x0a);
    pub const STOP_ADVERTISING: Opcode = Opcode(0x0b);
    pub const START_DISCOVERY: Opcode = Opcode(0x0c);
    pub const STOP_DISCOVERY: Opcode = Opcode(0x0d);
    pub const CONNECT: Opcode = Opcode(0x0e);
    pub const DISCONNECT: Opcode = Opcode(0x0f);
    pub const SET_IO_CAPABILITY: Opcode = Opcode(0x10);
    pub const PAIR: Opcode = Opcode(0x11);
    pub const UNPAIR: Opcode = Opcode(0x12);
    pub const PASSKEY_ENTRY: Opcode = Opcode(0x13);
    pub const PASSKEY_CONFIRM: Opcode = Opcode(0x14);
    pub const START_DIRECTED_ADVERTISING: Opcode = Opcode(0x15);
    pub const CONN_PARAM_UPDATE: Opcode = Opcode(0x16);
    pub const SET_FILTER_ACCEPT_LIST: Opcode = Opcode(0x1c);

    // Events
    pub const EVENT_NEW_SETTINGS: Opcode = Opcode(0x80);
    pub const EVENT_DEVICE_FOUND: Opcode = Opcode(0x81);
    pub const EVENT_DEVICE_CONNECTED: Opcode = Opcode(0x82);
    pub const EVENT_DEVICE_DISCONNECTED: Opcode = Opcode(0x83);
    pub const EVENT_PASSKEY_DISPLAY: Opcode = Opcode(0x84);
    pub const EVENT_PASSKEY_ENTRY_REQUEST: Opcode = Opcode(0x85);
    pub const EVENT_PASSKEY_CONFIRM_REQUEST: Opcode = Opcode(0x86);
    pub const EVENT_CONN_PARAM_UPDATE: Opcode = Opcode(0x88);
    pub const EVENT_SEC_LEVEL_CHANGED: Opcode = Opcode(0x89);
    pub const EVENT_PAIRING_FAILED: Opcode = Opcode(0x8c);
}

/// Supported commands bitmask for GAP service.
pub const SUPPORTED_COMMANDS: [u8; 4] = super::supported_commands_bitmask(&[
    opcodes::READ_SUPPORTED_COMMANDS,
    opcodes::READ_CONTROLLER_INDEX_LIST,
    opcodes::READ_CONTROLLER_INFO,
    opcodes::SET_CONNECTABLE,
    opcodes::SET_DISCOVERABLE,
    opcodes::SET_BONDABLE,
    opcodes::START_ADVERTISING,
    opcodes::STOP_ADVERTISING,
    opcodes::START_DISCOVERY,
    opcodes::STOP_DISCOVERY,
    opcodes::CONNECT,
    opcodes::DISCONNECT,
    opcodes::SET_IO_CAPABILITY,
    opcodes::PAIR,
    opcodes::UNPAIR,
    opcodes::PASSKEY_ENTRY,
    opcodes::PASSKEY_CONFIRM,
    opcodes::START_DIRECTED_ADVERTISING,
    opcodes::CONN_PARAM_UPDATE,
    opcodes::SET_FILTER_ACCEPT_LIST,
]);

/// GAP settings flags (bitfield). Bits 0-18 are defined by the BTP spec.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GapSettings(u32);

bitflags::bitflags! {
    impl GapSettings: u32 {
        const POWERED = 1 << 0;
        const CONNECTABLE = 1 << 1;
        const FAST_CONNECTABLE = 1 << 2;
        const DISCOVERABLE = 1 << 3;
        const BONDABLE = 1 << 4;
        const LINK_LEVEL_SECURITY = 1 << 5;
        const SSP = 1 << 6;
        const BR_EDR = 1 << 7;
        const HIGH_SPEED = 1 << 8;
        const LE = 1 << 9;
        const ADVERTISING = 1 << 10;
        const SECURE_CONNECTIONS = 1 << 11;
        const DEBUG_KEYS = 1 << 12;
        const PRIVACY = 1 << 13;
        const CONTROLLER_CONFIG = 1 << 14;
        const STATIC_ADDRESS = 1 << 15;
        const SC_ONLY = 1 << 16;
        const EXTENDED_ADVERTISING = 1 << 17;
        const PERIODIC_ADVERTISING = 1 << 18;
    }
}

impl GapSettings {
    /// The set of settings this IUT advertises as supported.
    pub const SUPPORTED: Self = Self::POWERED
        .union(Self::CONNECTABLE)
        .union(Self::DISCOVERABLE)
        .union(Self::BONDABLE)
        .union(Self::LE)
        .union(Self::ADVERTISING)
        .union(Self::SECURE_CONNECTIONS);
}

/// Synthetic flag stored in bit 31 (outside the valid BTP settings range of bits 0-18)
/// to track limited discoverable mode internally. Stripped before sending on the wire.
pub(crate) const LIMITED_DISCOVERABLE: GapSettings = GapSettings::from_bits_retain(1 << 31);

/// AD Flags byte constants (Bluetooth Core Spec, CSS Part A §1.3).
const AD_TYPE_FLAGS: u8 = 0x01;
const FLAG_LE_LIMITED_DISCOVERABLE: u8 = 0x01;
const FLAG_LE_GENERAL_DISCOVERABLE: u8 = 0x02;
const FLAG_BR_EDR_NOT_SUPPORTED: u8 = 0x04;

/// Ensure connectable advertising data has a Flags AD structure with the
/// BR/EDR Not Supported flag and the appropriate discoverability flags.
///
/// If the data already starts with a Flags AD structure, the required bits are
/// OR'd into the existing flags byte. Otherwise a new 3-byte Flags structure is
/// prepended.
fn prepend_flags(adv_data: &[u8], settings: GapSettings) -> Box<[u8]> {
    if !settings.contains(GapSettings::CONNECTABLE) {
        return Box::from(adv_data);
    }

    let mut flags = FLAG_BR_EDR_NOT_SUPPORTED;
    if settings.contains(GapSettings::DISCOVERABLE) {
        if settings.contains(LIMITED_DISCOVERABLE) {
            flags |= FLAG_LE_LIMITED_DISCOVERABLE;
        } else {
            flags |= FLAG_LE_GENERAL_DISCOVERABLE;
        }
    }

    // Check if adv_data already starts with a Flags AD structure (length=2, type=0x01)
    if adv_data.len() >= 3 && adv_data[0] == 2 && adv_data[1] == AD_TYPE_FLAGS {
        let mut result = Vec::from(adv_data);
        result[2] |= flags;
        return result.into_boxed_slice();
    }

    let mut result = Vec::with_capacity(3 + adv_data.len());
    result.push(2);
    result.push(AD_TYPE_FLAGS);
    result.push(flags);
    result.extend_from_slice(adv_data);
    result.into_boxed_slice()
}

/// Discoverable mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum DiscoverableMode {
    #[default]
    Off = 0x00,
    General = 0x01,
    Limited = 0x02,
}

impl TryFrom<u8> for DiscoverableMode {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Off),
            0x01 => Ok(Self::General),
            0x02 => Ok(Self::Limited),
            _ => Err(Error::InvalidPacket),
        }
    }
}

/// Discovery flags.
#[derive(Debug, Clone, Copy, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DiscoveryFlags(u8);

bitflags::bitflags! {
    impl DiscoveryFlags: u8 {
        const LE_SCAN = 1 << 0;
        const BR_EDR_SCAN = 1 << 1;
        const LIMITED = 1 << 2;
        const ACTIVE = 1 << 3;
        const OBSERVATION = 1 << 4;
        const OWN_ID_ADDR = 1 << 5;
        const FILTER_ACCEPT_LIST = 1 << 6;
    }
}

/// Device found event flags.
#[derive(Debug, Clone, Copy, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DeviceFoundFlags(u8);

bitflags::bitflags! {
    impl DeviceFoundFlags: u8 {
        const RSSI_VALID = 1 << 0;
        const ADV_DATA = 1 << 1;
        const SCAN_RSP = 1 << 2;
    }
}

/// Directed advertising options.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DirectedAdvertisingOptions(u16);

bitflags::bitflags! {
    impl DirectedAdvertisingOptions: u16 {
        const HIGH_DUTY = 1 << 0;
        const OWN_ID_ADDRESS = 1 << 1;
        const PEER_RPA_ADDRESS = 1 << 2;
    }
}

/// Entry in the filter accept list.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct FilterListEntry {
    pub address: Address,
}

/// Iterator over filter list entries from raw wire bytes.
pub struct FilterListEntryIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Iterator for FilterListEntryIter<'_> {
    type Item = FilterListEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos + 7 > self.data.len() {
            return None;
        }
        let s = &self.data[self.pos..self.pos + 7];
        self.pos += 7;
        Some(FilterListEntry {
            address: Address {
                kind: AddrKind::new(s[0]),
                addr: BdAddr::new([s[1], s[2], s[3], s[4], s[5], s[6]]),
            },
        })
    }
}

/// Maximum device name length.
pub const MAX_NAME_LEN: usize = 249;
/// Maximum short name length.
pub const MAX_SHORT_NAME_LEN: usize = 11;

/// Start advertising command data.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct StartAdvertisingCommand<'a> {
    pub adv_data: &'a [u8],
    pub scan_data: &'a [u8],
    #[allow(unused)]
    pub duration: u32,
    #[allow(unused)]
    pub own_addr_type: AddrKind,
}

/// Start directed advertising command data.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct StartDirectedAdvertisingCommand {
    pub address: Address,
    pub options: DirectedAdvertisingOptions,
}

/// Connect command data.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConnectCommand {
    pub address: Address,
    #[allow(unused)]
    pub own_addr_type: AddrKind,
}

/// Passkey entry command data.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PasskeyEntryCommand {
    pub address: Address,
    pub passkey: u32,
}

/// Passkey confirm command data.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PasskeyConfirmCommand {
    pub address: Address,
    pub confirmed: bool,
}

/// Connection parameter update command data.
#[derive(Debug, Clone)]
pub struct ConnParamUpdateCommand<'a> {
    pub address: Address,
    params: &'a [u8], // 8 raw wire bytes
}

impl ConnParamUpdateCommand<'_> {
    /// Parse the raw wire bytes into a `RequestedConnParams`.
    pub fn params(&self) -> RequestedConnParams {
        let interval_min = u16::from_le_bytes([self.params[0], self.params[1]]);
        let interval_max = u16::from_le_bytes([self.params[2], self.params[3]]);
        let latency = u16::from_le_bytes([self.params[4], self.params[5]]);
        let timeout = u16::from_le_bytes([self.params[6], self.params[7]]);
        RequestedConnParams {
            min_connection_interval: Duration::from_micros(interval_min as u64 * 1250),
            max_connection_interval: Duration::from_micros(interval_max as u64 * 1250),
            max_latency: latency,
            min_event_length: Duration::from_millis(0),
            max_event_length: Duration::from_millis(0),
            supervision_timeout: Duration::from_millis(timeout as u64 * 10),
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for ConnParamUpdateCommand<'_> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(
            f,
            "ConnParamUpdateCommand {{ address: {}, params: {:?} }}",
            self.address,
            self.params()
        )
    }
}

/// Set filter accept list command data.
#[derive(Clone)]
pub struct SetFilterAcceptListCommand<'a> {
    addresses: &'a [u8], // raw wire bytes (count * 7)
}

impl<'a> SetFilterAcceptListCommand<'a> {
    /// Iterate over the filter list entries.
    pub fn iter(&self) -> FilterListEntryIter<'a> {
        FilterListEntryIter {
            data: self.addresses,
            pos: 0,
        }
    }

    /// Number of entries.
    pub fn count(&self) -> usize {
        self.addresses.len() / 7
    }
}

impl core::fmt::Debug for SetFilterAcceptListCommand<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SetFilterAcceptListCommand")
            .field("count", &self.count())
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for SetFilterAcceptListCommand<'_> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "SetFilterAcceptListCommand {{ count: {} }}", self.count())
    }
}

/// Parsed GAP command.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum GapCommand<'a> {
    /// Read supported commands (0x01).
    ReadSupportedCommands,

    /// Read controller index list (0x02).
    ReadControllerIndexList,

    /// Read controller information (0x03).
    ReadControllerInfo,

    /// Set connectable state (0x06).
    SetConnectable(bool),

    /// Set discoverable mode (0x08).
    SetDiscoverable(DiscoverableMode),

    /// Set bondable state (0x09).
    SetBondable(bool),

    /// Start advertising (0x0a).
    StartAdvertising(StartAdvertisingCommand<'a>),

    /// Start directed advertising (0x15)
    StartDirectedAdvertising(StartDirectedAdvertisingCommand),

    /// Stop advertising (0x0b).
    StopAdvertising,

    /// Start discovery (0x0c).
    StartDiscovery(DiscoveryFlags),

    /// Stop discovery (0x0d).
    StopDiscovery,

    /// Connect to device (0x0e).
    Connect(ConnectCommand),

    /// Disconnect from device (0x0f).
    Disconnect(Address),

    /// Set IO capability (0x10).
    SetIoCapability(IoCapabilities),

    /// Pair with device (0x11).
    Pair(Address),

    /// Unpair device (0x12).
    Unpair(Address),

    /// Passkey entry response (0x13).
    PasskeyEntry(PasskeyEntryCommand),

    /// Passkey confirmation response (0x14).
    PasskeyConfirm(PasskeyConfirmCommand),

    /// Connection parameter update (0x16).
    ConnParamUpdate(ConnParamUpdateCommand<'a>),

    /// Set filter accept list (0x1c).
    SetFilterAcceptList(SetFilterAcceptListCommand<'a>),
}

impl<'a> GapCommand<'a> {
    /// Parse a GAP command from header and cursor.
    pub fn parse(header: &BtpHeader, cursor: &mut Cursor<'a>) -> Result<Self, Error> {
        // Commands that don't require controller index
        match header.opcode {
            opcodes::READ_SUPPORTED_COMMANDS => return Ok(GapCommand::ReadSupportedCommands),
            opcodes::READ_CONTROLLER_INDEX_LIST => return Ok(GapCommand::ReadControllerIndexList),
            _ => {}
        }

        // All other commands require controller index 0
        match header.controller_index {
            Some(0) => {}
            Some(_) => return Err(Error::InvalidIndex),
            None => return Err(Error::InvalidIndex),
        }

        match header.opcode {
            opcodes::READ_CONTROLLER_INFO => Ok(GapCommand::ReadControllerInfo),
            opcodes::SET_CONNECTABLE => {
                let val = cursor.read_u8()?;
                Ok(GapCommand::SetConnectable(val != 0))
            }
            opcodes::SET_DISCOVERABLE => {
                let val = cursor.read_u8()?;
                Ok(GapCommand::SetDiscoverable(DiscoverableMode::try_from(val)?))
            }
            opcodes::SET_BONDABLE => {
                let val = cursor.read_u8()?;
                Ok(GapCommand::SetBondable(val != 0))
            }
            opcodes::START_ADVERTISING => Self::parse_start_advertising(cursor),
            opcodes::STOP_ADVERTISING => Ok(GapCommand::StopAdvertising),
            opcodes::START_DISCOVERY => {
                let val = cursor.read_u8()?;
                Ok(GapCommand::StartDiscovery(DiscoveryFlags::from_bits_truncate(val)))
            }
            opcodes::STOP_DISCOVERY => Ok(GapCommand::StopDiscovery),
            opcodes::CONNECT => {
                let address = cursor.read_address()?;
                let own_addr_type = AddrKind::new(cursor.read_u8()?);
                Ok(GapCommand::Connect(ConnectCommand { address, own_addr_type }))
            }
            opcodes::DISCONNECT => {
                let address = cursor.read_address()?;
                Ok(GapCommand::Disconnect(address))
            }
            opcodes::SET_IO_CAPABILITY => {
                let val = cursor.read_u8()?;
                Ok(GapCommand::SetIoCapability(
                    IoCapabilities::try_from(val).or(Err(Error::InvalidPacket))?,
                ))
            }
            opcodes::PAIR => {
                let address = cursor.read_address()?;
                Ok(GapCommand::Pair(address))
            }
            opcodes::UNPAIR => {
                let address = cursor.read_address()?;
                Ok(GapCommand::Unpair(address))
            }
            opcodes::PASSKEY_ENTRY => {
                let address = cursor.read_address()?;
                let passkey = cursor.read_u32_le()?;
                Ok(GapCommand::PasskeyEntry(PasskeyEntryCommand { address, passkey }))
            }
            opcodes::PASSKEY_CONFIRM => {
                let address = cursor.read_address()?;
                let confirmed = cursor.read_u8()? != 0;
                Ok(GapCommand::PasskeyConfirm(PasskeyConfirmCommand { address, confirmed }))
            }
            opcodes::START_DIRECTED_ADVERTISING => {
                let address = cursor.read_address()?;
                let options = DirectedAdvertisingOptions::from_bits_truncate(cursor.read_u16_le()?);
                Ok(GapCommand::StartDirectedAdvertising(StartDirectedAdvertisingCommand {
                    address,
                    options,
                }))
            }
            opcodes::CONN_PARAM_UPDATE => {
                let address = cursor.read_address()?;
                let params = cursor.read_exact(8)?;
                Ok(GapCommand::ConnParamUpdate(ConnParamUpdateCommand { address, params }))
            }
            opcodes::SET_FILTER_ACCEPT_LIST => {
                let count = cursor.read_u8()? as usize;
                let addresses = cursor.read_exact(count * 7)?;
                Ok(GapCommand::SetFilterAcceptList(SetFilterAcceptListCommand {
                    addresses,
                }))
            }
            _ => Err(Error::UnknownCommand {
                service: ServiceId::GAP,
                opcode: header.opcode,
            }),
        }
    }

    fn parse_start_advertising(cursor: &mut Cursor<'a>) -> Result<Self, Error> {
        let adv_data_len = cursor.read_u8()? as usize;
        let scan_data_len = cursor.read_u8()? as usize;
        let adv_data = cursor.read_exact(adv_data_len)?;
        let scan_data = cursor.read_exact(scan_data_len)?;
        let duration = cursor.read_u32_le()?;
        let own_addr_type = AddrKind::new(cursor.read_u8()?);

        Ok(GapCommand::StartAdvertising(StartAdvertisingCommand {
            adv_data,
            scan_data,
            duration,
            own_addr_type,
        }))
    }

    /// Return the expected controller index for this command (`Some(0)` for most, `None` for non-controller commands).
    pub fn expected_controller_index(&self) -> Option<u8> {
        (!matches!(
            self,
            GapCommand::ReadSupportedCommands | GapCommand::ReadControllerIndexList
        ))
        .then_some(0)
    }

    /// Build [`AdvertisementParams`] from this command's data and the current GAP settings.
    ///
    /// Returns `None` if the settings/command combination is invalid (e.g. directed
    /// non-connectable advertising).
    pub fn ad(&self, settings: GapSettings) -> Option<AdvertisementParams> {
        match self {
            GapCommand::StartAdvertising(StartAdvertisingCommand {
                adv_data, scan_data, ..
            }) => {
                let adv_data: Box<[u8]> = prepend_flags(adv_data, settings);
                let scan_data: Box<[u8]> = Box::from(*scan_data);

                Some(if settings.contains(GapSettings::EXTENDED_ADVERTISING) {
                    if settings.contains(GapSettings::CONNECTABLE) {
                        AdvertisementParams::ExtConnectableNonscannableUndirected {
                            adv_data,
                            bondable: settings.contains(GapSettings::BONDABLE),
                        }
                    } else if scan_data.is_empty() {
                        AdvertisementParams::ExtNonconnectableNonscannableUndirected { adv_data }
                    } else {
                        AdvertisementParams::ExtNonconnectableScannableUndirected { scan_data }
                    }
                } else if settings.contains(GapSettings::CONNECTABLE) {
                    AdvertisementParams::ConnectableScannableUndirected {
                        adv_data,
                        scan_data,
                        bondable: settings.contains(GapSettings::BONDABLE),
                    }
                } else if scan_data.is_empty() {
                    AdvertisementParams::NonconnectableNonscannableUndirected { adv_data }
                } else {
                    AdvertisementParams::NonconnectableScannableUndirected { adv_data, scan_data }
                })
            }
            GapCommand::StartDirectedAdvertising(StartDirectedAdvertisingCommand { address, options }) => {
                if settings.contains(GapSettings::EXTENDED_ADVERTISING) {
                    if settings.contains(GapSettings::CONNECTABLE) {
                        let adv_data = Box::new([]);
                        Some(AdvertisementParams::ExtConnectableNonscannableDirected {
                            peer: *address,
                            adv_data,
                            bondable: settings.contains(GapSettings::BONDABLE),
                        })
                    } else {
                        None
                    }
                } else if settings.contains(GapSettings::CONNECTABLE) {
                    if options.contains(DirectedAdvertisingOptions::HIGH_DUTY) {
                        Some(AdvertisementParams::ConnectableNonscannableDirectedHighDuty {
                            peer: *address,
                            bondable: settings.contains(GapSettings::BONDABLE),
                        })
                    } else {
                        Some(AdvertisementParams::ConnectableNonscannableDirected {
                            peer: *address,
                            bondable: settings.contains(GapSettings::BONDABLE),
                        })
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// Controller index list response data.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ControllerIndexListResponse {
    pub count: u8,
    pub indices: [u8; 1],
}

/// Controller info response data.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ControllerInfoResponse<'a> {
    pub address: BdAddr,
    pub supported_settings: GapSettings,
    pub current_settings: GapSettings,
    pub class_of_device: [u8; 3],
    pub name: &'a str,
    pub short_name: &'a str,
}

/// GAP service response.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum GapResponse<'a> {
    Success,

    /// Supported commands bitmask.
    SupportedCommands([u8; 4]),

    /// Controller index list.
    ControllerIndexList(ControllerIndexListResponse),

    /// Controller information.
    ControllerInfo(ControllerInfoResponse<'a>),

    /// Current settings (used for most setting change responses).
    CurrentSettings(GapSettings),
}

impl GapResponse<'_> {
    /// Controller info response length: 6 + 4 + 4 + 3 + 249 + 11 = 277
    const CONTROLLER_INFO_LEN: u16 = 6 + 4 + 4 + 3 + MAX_NAME_LEN as u16 + MAX_SHORT_NAME_LEN as u16;

    /// Get the data length for this response.
    pub fn data_len(&self) -> u16 {
        match self {
            GapResponse::Success => 0,
            GapResponse::SupportedCommands(bitmask) => bitmask.len() as u16,
            GapResponse::ControllerIndexList(rsp) => 1 + rsp.indices.len() as u16,
            GapResponse::ControllerInfo(..) => Self::CONTROLLER_INFO_LEN,
            GapResponse::CurrentSettings(..) => 4,
        }
    }

    /// Write the response data.
    pub async fn write<W: Write>(&self, mut writer: W) -> Result<(), W::Error> {
        match self {
            GapResponse::Success => Ok(()),
            GapResponse::SupportedCommands(bitmask) => writer.write_all(bitmask).await,
            GapResponse::ControllerIndexList(rsp) => {
                writer.write_all(&[rsp.count]).await?;
                writer.write_all(&rsp.indices).await
            }
            GapResponse::ControllerInfo(rsp) => {
                writer.write_all(rsp.address.raw()).await?;
                writer.write_all(&rsp.supported_settings.bits().to_le_bytes()).await?;
                writer.write_all(&rsp.current_settings.bits().to_le_bytes()).await?;
                writer.write_all(&rsp.class_of_device).await?;

                // Write name padded to MAX_NAME_LEN
                let name_bytes = rsp.name.as_bytes();
                let len = name_bytes.len().min(MAX_NAME_LEN);
                let padding = MAX_NAME_LEN - len;
                writer.write_all(&name_bytes[..len]).await?;
                let name_padding = [0u8; MAX_NAME_LEN];
                writer.write_all(&name_padding[..padding]).await?;

                // Write short_name padded to MAX_SHORT_NAME_LEN
                let short_bytes = rsp.short_name.as_bytes();
                let len = short_bytes.len().min(MAX_SHORT_NAME_LEN);
                let padding = MAX_SHORT_NAME_LEN - len;
                writer.write_all(&short_bytes[..len]).await?;
                let short_padding = [0u8; MAX_SHORT_NAME_LEN];
                writer.write_all(&short_padding[..padding]).await
            }
            GapResponse::CurrentSettings(settings) => writer.write_all(&settings.bits().to_le_bytes()).await,
        }
    }
}

/// Device found event data.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DeviceFoundEvent<'a> {
    pub address: Address,
    pub rssi: i8,
    pub flags: DeviceFoundFlags,
    pub adv_data: &'a [u8],
}

/// Device connected event data.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DeviceConnectedEvent {
    pub address: Address,
    pub interval: u16,
    pub latency: u16,
    pub timeout: u16,
}

/// Passkey display event data.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PasskeyDisplayEvent {
    pub address: Address,
    pub passkey: u32,
}

/// Passkey confirm request event data.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PasskeyConfirmRequestEvent {
    pub address: Address,
    pub passkey: u32,
}

/// Connection parameter update event data.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConnParamUpdateEvent {
    pub address: Address,
    pub interval: u16,
    pub latency: u16,
    pub timeout: u16,
}

/// Security level changed event data.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SecLevelChangedEvent {
    pub address: Address,
    pub sec_level: u8,
}

/// Pairing failed event data.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PairingFailedEvent {
    pub address: Address,
    pub reason: u8,
}

/// GAP service event.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum GapEvent<'a> {
    /// New settings (0x80).
    NewSettings(GapSettings),

    /// Device found (0x81).
    DeviceFound(DeviceFoundEvent<'a>),

    /// Device connected (0x82).
    DeviceConnected(DeviceConnectedEvent),

    /// Device disconnected (0x83).
    DeviceDisconnected(Address),

    /// Passkey display (0x84).
    PasskeyDisplay(PasskeyDisplayEvent),

    /// Passkey entry request (0x85).
    PasskeyEntryRequest(Address),

    /// Passkey confirm request (0x86).
    PasskeyConfirmRequest(PasskeyConfirmRequestEvent),

    /// Connection parameters updated (0x88).
    ConnParamUpdate(ConnParamUpdateEvent),

    /// Security level changed (0x89).
    SecLevelChanged(SecLevelChangedEvent),

    /// Pairing failed (0x8c).
    PairingFailed(PairingFailedEvent),
}

impl GapEvent<'_> {
    /// Get the header for this event.
    pub fn header(&self) -> BtpHeader {
        let (opcode, data_len) = match self {
            GapEvent::NewSettings(..) => (opcodes::EVENT_NEW_SETTINGS, 4),
            GapEvent::DeviceFound(evt) => (opcodes::EVENT_DEVICE_FOUND, 11 + evt.adv_data.len() as u16),
            GapEvent::DeviceConnected(..) => (opcodes::EVENT_DEVICE_CONNECTED, 13),
            GapEvent::DeviceDisconnected(..) => (opcodes::EVENT_DEVICE_DISCONNECTED, 7),
            GapEvent::PasskeyDisplay(..) => (opcodes::EVENT_PASSKEY_DISPLAY, 11),
            GapEvent::PasskeyEntryRequest(..) => (opcodes::EVENT_PASSKEY_ENTRY_REQUEST, 7),
            GapEvent::PasskeyConfirmRequest(..) => (opcodes::EVENT_PASSKEY_CONFIRM_REQUEST, 11),
            GapEvent::ConnParamUpdate(..) => (opcodes::EVENT_CONN_PARAM_UPDATE, 13),
            GapEvent::SecLevelChanged(..) => (opcodes::EVENT_SEC_LEVEL_CHANGED, 8),
            GapEvent::PairingFailed(..) => (opcodes::EVENT_PAIRING_FAILED, 8),
        };
        BtpHeader::event(ServiceId::GAP, opcode, Some(0), data_len)
    }

    /// Write the event data.
    pub async fn write<W: Write>(&self, mut writer: W) -> Result<(), W::Error> {
        match self {
            GapEvent::NewSettings(current_settings) => writer.write_all(&current_settings.bits().to_le_bytes()).await,
            GapEvent::DeviceFound(evt) => {
                writer.write_all(&[evt.address.kind.as_raw()]).await?;
                writer.write_all(evt.address.addr.raw()).await?;
                writer.write_all(&[evt.rssi as u8]).await?;
                writer.write_all(&[evt.flags.bits()]).await?;
                writer.write_all(&(evt.adv_data.len() as u16).to_le_bytes()).await?;
                writer.write_all(evt.adv_data).await
            }
            GapEvent::DeviceConnected(evt) => {
                writer.write_all(&[evt.address.kind.as_raw()]).await?;
                writer.write_all(evt.address.addr.raw()).await?;
                writer.write_all(&evt.interval.to_le_bytes()).await?;
                writer.write_all(&evt.latency.to_le_bytes()).await?;
                writer.write_all(&evt.timeout.to_le_bytes()).await
            }
            GapEvent::DeviceDisconnected(address) => {
                writer.write_all(&[address.kind.as_raw()]).await?;
                writer.write_all(address.addr.raw()).await
            }
            GapEvent::PasskeyDisplay(evt) => {
                writer.write_all(&[evt.address.kind.as_raw()]).await?;
                writer.write_all(evt.address.addr.raw()).await?;
                writer.write_all(&evt.passkey.to_le_bytes()).await
            }
            GapEvent::PasskeyEntryRequest(address) => {
                writer.write_all(&[address.kind.as_raw()]).await?;
                writer.write_all(address.addr.raw()).await
            }
            GapEvent::PasskeyConfirmRequest(evt) => {
                writer.write_all(&[evt.address.kind.as_raw()]).await?;
                writer.write_all(evt.address.addr.raw()).await?;
                writer.write_all(&evt.passkey.to_le_bytes()).await
            }
            GapEvent::ConnParamUpdate(evt) => {
                writer.write_all(&[evt.address.kind.as_raw()]).await?;
                writer.write_all(evt.address.addr.raw()).await?;
                writer.write_all(&evt.interval.to_le_bytes()).await?;
                writer.write_all(&evt.latency.to_le_bytes()).await?;
                writer.write_all(&evt.timeout.to_le_bytes()).await
            }
            GapEvent::SecLevelChanged(evt) => {
                writer.write_all(&[evt.address.kind.as_raw()]).await?;
                writer.write_all(evt.address.addr.raw()).await?;
                writer.write_all(&[evt.sec_level]).await
            }
            GapEvent::PairingFailed(evt) => {
                writer.write_all(&[evt.address.kind.as_raw()]).await?;
                writer.write_all(evt.address.addr.raw()).await?;
                writer.write_all(&[evt.reason]).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use futures_executor::block_on;

    use super::*;
    use crate::btp::types::Opcode;

    fn make_header(opcode: Opcode, controller_index: Option<u8>) -> BtpHeader {
        BtpHeader::new(ServiceId::GAP, opcode, controller_index, 0)
    }

    #[test]
    fn test_read_start_directed_advertising() {
        // addr_type=0x01, addr=[0x11,0x22,0x33,0x44,0x55,0x66], options=0x0001 (HIGH_DUTY)
        let data: &[u8] = &[0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x01, 0x00];
        let header = make_header(opcodes::START_DIRECTED_ADVERTISING, Some(0));
        let mut cursor = Cursor::new(data);
        let cmd = GapCommand::parse(&header, &mut cursor).unwrap();
        if let GapCommand::StartDirectedAdvertising(StartDirectedAdvertisingCommand { address, options }) = cmd {
            assert_eq!(address.kind, AddrKind::RANDOM);
            assert_eq!(address.addr.raw(), &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
            assert!(options.contains(DirectedAdvertisingOptions::HIGH_DUTY));
        } else {
            panic!("Expected StartDirectedAdvertising");
        }
    }

    #[test]
    fn test_read_set_filter_accept_list() {
        // count=2, then 2 entries (addr_type + 6 bytes addr each)
        let data: &[u8] = &[
            0x02, // count
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // entry 1
            0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // entry 2
        ];
        let header = make_header(opcodes::SET_FILTER_ACCEPT_LIST, Some(0));
        let mut cursor = Cursor::new(data);
        let cmd = GapCommand::parse(&header, &mut cursor).unwrap();
        if let GapCommand::SetFilterAcceptList(cmd) = cmd {
            let entries: heapless::Vec<_, 8> = cmd.iter().collect();
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0].address.kind, AddrKind::PUBLIC);
            assert_eq!(entries[0].address.addr.raw(), &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
            assert_eq!(entries[1].address.kind, AddrKind::RANDOM);
            assert_eq!(entries[1].address.addr.raw(), &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        } else {
            panic!("Expected SetFilterAcceptList");
        }
    }

    #[test]
    fn test_read_start_advertising() {
        // adv_data_len=2, scan_rsp_len=0, adv_data=[0x01, 0x02], duration=0, own_addr_type=0
        let data: &[u8] = &[2, 0, 0x01, 0x02, 0, 0, 0, 0, 0];
        let header = make_header(opcodes::START_ADVERTISING, Some(0));
        let mut cursor = Cursor::new(data);
        let cmd = GapCommand::parse(&header, &mut cursor).unwrap();
        if let GapCommand::StartAdvertising(StartAdvertisingCommand {
            adv_data,
            scan_data,
            duration,
            own_addr_type,
        }) = cmd
        {
            assert_eq!(adv_data, &[0x01, 0x02]);
            assert!(scan_data.is_empty());
            assert_eq!(duration, 0);
            assert_eq!(own_addr_type, AddrKind::PUBLIC);
        } else {
            panic!("Expected StartAdvertising");
        }
    }

    #[test]
    fn test_read_connect() {
        let data: &[u8] = &[0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x00];
        let header = make_header(opcodes::CONNECT, Some(0));
        let mut cursor = Cursor::new(data);
        let cmd = GapCommand::parse(&header, &mut cursor).unwrap();
        if let GapCommand::Connect(ConnectCommand { address, own_addr_type }) = cmd {
            assert_eq!(address.kind, AddrKind::RANDOM);
            assert_eq!(address.addr.raw(), &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
            assert_eq!(own_addr_type, AddrKind::PUBLIC);
        } else {
            panic!("Expected Connect");
        }
    }

    #[test]
    fn test_write_current_settings() {
        let resp = GapResponse::CurrentSettings(GapSettings::POWERED | GapSettings::LE);
        let mut buf = [0u8; 16];
        block_on(resp.write(&mut buf.as_mut_slice())).unwrap();
        let settings = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(settings, (GapSettings::POWERED | GapSettings::LE).bits());
    }

    #[test]
    fn test_write_device_connected_event() {
        let evt = GapEvent::DeviceConnected(DeviceConnectedEvent {
            address: Address {
                kind: AddrKind::RANDOM,
                addr: BdAddr::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            },
            interval: 0x0018,
            latency: 0x0000,
            timeout: 0x00C8,
        });
        let mut buf = [0u8; 32];
        block_on(evt.write(&mut buf.as_mut_slice())).unwrap();
        assert_eq!(buf[0], 0x01); // RANDOM
        assert_eq!(&buf[1..7], &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    }

    #[test]
    fn test_gap_settings() {
        let mut settings = GapSettings::default();
        assert!(!settings.contains(GapSettings::POWERED));

        settings.insert(GapSettings::POWERED);
        assert!(settings.contains(GapSettings::POWERED));

        settings.remove(GapSettings::POWERED);
        assert!(!settings.contains(GapSettings::POWERED));
    }

    // --- Parsing tests for previously untested commands ---

    #[test]
    fn test_read_set_discoverable() {
        let data: &[u8] = &[0x02]; // Limited
        let header = make_header(opcodes::SET_DISCOVERABLE, Some(0));
        let mut cursor = Cursor::new(data);
        let cmd = GapCommand::parse(&header, &mut cursor).unwrap();
        assert!(matches!(cmd, GapCommand::SetDiscoverable(DiscoverableMode::Limited)));
    }

    #[test]
    fn test_set_discoverable_invalid_value() {
        let data: &[u8] = &[0x05];
        let header = make_header(opcodes::SET_DISCOVERABLE, Some(0));
        let mut cursor = Cursor::new(data);
        let result = GapCommand::parse(&header, &mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_set_bondable() {
        let data: &[u8] = &[0x01];
        let header = make_header(opcodes::SET_BONDABLE, Some(0));
        let mut cursor = Cursor::new(data);
        let cmd = GapCommand::parse(&header, &mut cursor).unwrap();
        assert!(matches!(cmd, GapCommand::SetBondable(true)));
    }

    #[test]
    fn test_read_set_bondable_false() {
        let data: &[u8] = &[0x00];
        let header = make_header(opcodes::SET_BONDABLE, Some(0));
        let mut cursor = Cursor::new(data);
        let cmd = GapCommand::parse(&header, &mut cursor).unwrap();
        assert!(matches!(cmd, GapCommand::SetBondable(false)));
    }

    #[test]
    fn test_read_disconnect() {
        let data: &[u8] = &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let header = make_header(opcodes::DISCONNECT, Some(0));
        let mut cursor = Cursor::new(data);
        let cmd = GapCommand::parse(&header, &mut cursor).unwrap();
        if let GapCommand::Disconnect(address) = cmd {
            assert_eq!(address.kind, AddrKind::PUBLIC);
            assert_eq!(address.addr.raw(), &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        } else {
            panic!("Expected Disconnect");
        }
    }

    #[test]
    fn test_read_set_io_capability() {
        let data: &[u8] = &[0x01]; // DisplayYesNo
        let header = make_header(opcodes::SET_IO_CAPABILITY, Some(0));
        let mut cursor = Cursor::new(data);
        let cmd = GapCommand::parse(&header, &mut cursor).unwrap();
        assert!(matches!(cmd, GapCommand::SetIoCapability(IoCapabilities::DisplayYesNo)));
    }

    #[test]
    fn test_read_pair() {
        let data: &[u8] = &[0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let header = make_header(opcodes::PAIR, Some(0));
        let mut cursor = Cursor::new(data);
        let cmd = GapCommand::parse(&header, &mut cursor).unwrap();
        if let GapCommand::Pair(address) = cmd {
            assert_eq!(address.kind, AddrKind::RANDOM);
            assert_eq!(address.addr.raw(), &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        } else {
            panic!("Expected Pair");
        }
    }

    #[test]
    fn test_read_unpair() {
        let data: &[u8] = &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let header = make_header(opcodes::UNPAIR, Some(0));
        let mut cursor = Cursor::new(data);
        let cmd = GapCommand::parse(&header, &mut cursor).unwrap();
        if let GapCommand::Unpair(address) = cmd {
            assert_eq!(address.kind, AddrKind::PUBLIC);
        } else {
            panic!("Expected Unpair");
        }
    }

    #[test]
    fn test_read_passkey_entry() {
        // addr_type=0x00, addr=6 bytes, passkey=123456 (0x0001E240)
        let data: &[u8] = &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x40, 0xE2, 0x01, 0x00];
        let header = make_header(opcodes::PASSKEY_ENTRY, Some(0));
        let mut cursor = Cursor::new(data);
        let cmd = GapCommand::parse(&header, &mut cursor).unwrap();
        if let GapCommand::PasskeyEntry(PasskeyEntryCommand { address, passkey }) = cmd {
            assert_eq!(address.kind, AddrKind::PUBLIC);
            assert_eq!(passkey, 123456);
        } else {
            panic!("Expected PasskeyEntry");
        }
    }

    #[test]
    fn test_read_passkey_confirm() {
        let data: &[u8] = &[0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01];
        let header = make_header(opcodes::PASSKEY_CONFIRM, Some(0));
        let mut cursor = Cursor::new(data);
        let cmd = GapCommand::parse(&header, &mut cursor).unwrap();
        if let GapCommand::PasskeyConfirm(PasskeyConfirmCommand { address, confirmed }) = cmd {
            assert_eq!(address.kind, AddrKind::RANDOM);
            assert!(confirmed);
        } else {
            panic!("Expected PasskeyConfirm");
        }
    }

    #[test]
    fn test_read_passkey_confirm_rejected() {
        let data: &[u8] = &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x00];
        let header = make_header(opcodes::PASSKEY_CONFIRM, Some(0));
        let mut cursor = Cursor::new(data);
        let cmd = GapCommand::parse(&header, &mut cursor).unwrap();
        if let GapCommand::PasskeyConfirm(PasskeyConfirmCommand { confirmed, .. }) = cmd {
            assert!(!confirmed);
        } else {
            panic!("Expected PasskeyConfirm");
        }
    }

    #[test]
    fn test_read_conn_param_update() {
        // addr + 8 bytes params: interval_min=6, interval_max=12, latency=0, timeout=100
        let data: &[u8] = &[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // address
            0x06, 0x00, // interval_min
            0x0C, 0x00, // interval_max
            0x00, 0x00, // latency
            0x64, 0x00, // timeout
        ];
        let header = make_header(opcodes::CONN_PARAM_UPDATE, Some(0));
        let mut cursor = Cursor::new(data);
        let cmd = GapCommand::parse(&header, &mut cursor).unwrap();
        if let GapCommand::ConnParamUpdate(cmd) = cmd {
            let params = cmd.params();
            assert_eq!(params.max_latency, 0);
        } else {
            panic!("Expected ConnParamUpdate");
        }
    }

    #[test]
    fn test_read_stop_advertising() {
        let header = make_header(opcodes::STOP_ADVERTISING, Some(0));
        let mut cursor = Cursor::new(&[]);
        let cmd = GapCommand::parse(&header, &mut cursor).unwrap();
        assert!(matches!(cmd, GapCommand::StopAdvertising));
    }

    #[test]
    fn test_read_start_discovery() {
        let data: &[u8] = &[0x09]; // LE_SCAN | ACTIVE
        let header = make_header(opcodes::START_DISCOVERY, Some(0));
        let mut cursor = Cursor::new(data);
        let cmd = GapCommand::parse(&header, &mut cursor).unwrap();
        if let GapCommand::StartDiscovery(flags) = cmd {
            assert!(flags.contains(DiscoveryFlags::LE_SCAN));
            assert!(flags.contains(DiscoveryFlags::ACTIVE));
            assert!(!flags.contains(DiscoveryFlags::LIMITED));
        } else {
            panic!("Expected StartDiscovery");
        }
    }

    #[test]
    fn test_read_stop_discovery() {
        let header = make_header(opcodes::STOP_DISCOVERY, Some(0));
        let mut cursor = Cursor::new(&[]);
        let cmd = GapCommand::parse(&header, &mut cursor).unwrap();
        assert!(matches!(cmd, GapCommand::StopDiscovery));
    }

    // --- Controller index validation ---

    #[test]
    fn test_invalid_controller_index() {
        let data: &[u8] = &[0x01]; // valid data for SetConnectable
        let header = make_header(opcodes::SET_CONNECTABLE, Some(1)); // index 1, not 0
        let mut cursor = Cursor::new(data);
        let result = GapCommand::parse(&header, &mut cursor);
        assert!(matches!(result, Err(crate::btp::error::Error::InvalidIndex)));
    }

    #[test]
    fn test_missing_controller_index() {
        let data: &[u8] = &[0x01];
        let header = make_header(opcodes::SET_CONNECTABLE, None);
        let mut cursor = Cursor::new(data);
        let result = GapCommand::parse(&header, &mut cursor);
        assert!(matches!(result, Err(crate::btp::error::Error::InvalidIndex)));
    }

    #[test]
    fn test_no_controller_index_for_supported_commands() {
        let header = make_header(opcodes::READ_SUPPORTED_COMMANDS, None);
        let mut cursor = Cursor::new(&[]);
        let cmd = GapCommand::parse(&header, &mut cursor).unwrap();
        assert!(matches!(cmd, GapCommand::ReadSupportedCommands));
    }

    #[test]
    fn test_no_controller_index_for_index_list() {
        let header = make_header(opcodes::READ_CONTROLLER_INDEX_LIST, None);
        let mut cursor = Cursor::new(&[]);
        let cmd = GapCommand::parse(&header, &mut cursor).unwrap();
        assert!(matches!(cmd, GapCommand::ReadControllerIndexList));
    }

    // --- Unknown opcode ---

    #[test]
    fn test_gap_unknown_opcode() {
        let header = make_header(Opcode(0x7F), Some(0));
        let mut cursor = Cursor::new(&[]);
        let result = GapCommand::parse(&header, &mut cursor);
        assert!(matches!(result, Err(crate::btp::error::Error::UnknownCommand { .. })));
    }

    // --- ad() method tests ---

    #[test]
    fn test_ad_connectable_undirected() {
        let cmd = GapCommand::StartAdvertising(StartAdvertisingCommand {
            adv_data: &[0x01],
            scan_data: &[0x02],
            duration: 0,
            own_addr_type: AddrKind::PUBLIC,
        });
        let settings = GapSettings::CONNECTABLE;
        let params = cmd.ad(settings).unwrap();
        assert!(matches!(
            params,
            AdvertisementParams::ConnectableScannableUndirected { .. }
        ));
    }

    #[test]
    fn test_ad_nonconnectable_nonscannable() {
        let cmd = GapCommand::StartAdvertising(StartAdvertisingCommand {
            adv_data: &[0x01],
            scan_data: &[],
            duration: 0,
            own_addr_type: AddrKind::PUBLIC,
        });
        let settings = GapSettings::empty();
        let params = cmd.ad(settings).unwrap();
        assert!(matches!(
            params,
            AdvertisementParams::NonconnectableNonscannableUndirected { .. }
        ));
    }

    #[test]
    fn test_ad_nonconnectable_scannable() {
        let cmd = GapCommand::StartAdvertising(StartAdvertisingCommand {
            adv_data: &[0x01],
            scan_data: &[0x02],
            duration: 0,
            own_addr_type: AddrKind::PUBLIC,
        });
        let settings = GapSettings::empty();
        let params = cmd.ad(settings).unwrap();
        assert!(matches!(
            params,
            AdvertisementParams::NonconnectableScannableUndirected { .. }
        ));
    }

    #[test]
    fn test_ad_directed_not_connectable_returns_none() {
        let cmd = GapCommand::StartDirectedAdvertising(StartDirectedAdvertisingCommand {
            address: Address {
                kind: AddrKind::PUBLIC,
                addr: BdAddr::new([0; 6]),
            },
            options: DirectedAdvertisingOptions::empty(),
        });
        let settings = GapSettings::empty(); // not connectable
        assert!(cmd.ad(settings).is_none());
    }

    #[test]
    fn test_ad_directed_high_duty() {
        let cmd = GapCommand::StartDirectedAdvertising(StartDirectedAdvertisingCommand {
            address: Address {
                kind: AddrKind::PUBLIC,
                addr: BdAddr::new([1, 2, 3, 4, 5, 6]),
            },
            options: DirectedAdvertisingOptions::HIGH_DUTY,
        });
        let settings = GapSettings::CONNECTABLE;
        let params = cmd.ad(settings).unwrap();
        assert!(matches!(
            params,
            AdvertisementParams::ConnectableNonscannableDirectedHighDuty { .. }
        ));
    }

    #[test]
    fn test_ad_non_advertising_command_returns_none() {
        let cmd = GapCommand::StopAdvertising;
        assert!(cmd.ad(GapSettings::CONNECTABLE).is_none());
    }

    // --- Event serialization tests ---

    #[test]
    fn test_write_device_disconnected_event() {
        let evt = GapEvent::DeviceDisconnected(Address {
            kind: AddrKind::PUBLIC,
            addr: BdAddr::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
        });
        let header = evt.header();
        assert_eq!(header.opcode, opcodes::EVENT_DEVICE_DISCONNECTED);
        assert_eq!(header.data_len, 7);
        let mut buf = [0u8; 16];
        block_on(evt.write(&mut buf.as_mut_slice())).unwrap();
        assert_eq!(buf[0], 0x00); // PUBLIC
        assert_eq!(&buf[1..7], &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    }

    #[test]
    fn test_write_passkey_display_event() {
        let evt = GapEvent::PasskeyDisplay(PasskeyDisplayEvent {
            address: Address {
                kind: AddrKind::RANDOM,
                addr: BdAddr::new([1, 2, 3, 4, 5, 6]),
            },
            passkey: 123456,
        });
        let header = evt.header();
        assert_eq!(header.opcode, opcodes::EVENT_PASSKEY_DISPLAY);
        assert_eq!(header.data_len, 11);
        let mut buf = [0u8; 16];
        block_on(evt.write(&mut buf.as_mut_slice())).unwrap();
        assert_eq!(buf[0], 0x01); // RANDOM
        let passkey = u32::from_le_bytes([buf[7], buf[8], buf[9], buf[10]]);
        assert_eq!(passkey, 123456);
    }

    #[test]
    fn test_write_passkey_entry_request_event() {
        let evt = GapEvent::PasskeyEntryRequest(Address {
            kind: AddrKind::PUBLIC,
            addr: BdAddr::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
        });
        let header = evt.header();
        assert_eq!(header.opcode, opcodes::EVENT_PASSKEY_ENTRY_REQUEST);
        assert_eq!(header.data_len, 7);
    }

    #[test]
    fn test_write_passkey_confirm_request_event() {
        let evt = GapEvent::PasskeyConfirmRequest(PasskeyConfirmRequestEvent {
            address: Address {
                kind: AddrKind::PUBLIC,
                addr: BdAddr::new([1, 2, 3, 4, 5, 6]),
            },
            passkey: 999999,
        });
        let header = evt.header();
        assert_eq!(header.opcode, opcodes::EVENT_PASSKEY_CONFIRM_REQUEST);
        assert_eq!(header.data_len, 11);
        let mut buf = [0u8; 16];
        block_on(evt.write(&mut buf.as_mut_slice())).unwrap();
        let passkey = u32::from_le_bytes([buf[7], buf[8], buf[9], buf[10]]);
        assert_eq!(passkey, 999999);
    }

    #[test]
    fn test_write_conn_param_update_event() {
        let evt = GapEvent::ConnParamUpdate(ConnParamUpdateEvent {
            address: Address {
                kind: AddrKind::PUBLIC,
                addr: BdAddr::new([1, 2, 3, 4, 5, 6]),
            },
            interval: 0x0018,
            latency: 0x0000,
            timeout: 0x00C8,
        });
        let header = evt.header();
        assert_eq!(header.opcode, opcodes::EVENT_CONN_PARAM_UPDATE);
        assert_eq!(header.data_len, 13);
        let mut buf = [0u8; 16];
        block_on(evt.write(&mut buf.as_mut_slice())).unwrap();
        assert_eq!(u16::from_le_bytes([buf[7], buf[8]]), 0x0018);
        assert_eq!(u16::from_le_bytes([buf[9], buf[10]]), 0x0000);
        assert_eq!(u16::from_le_bytes([buf[11], buf[12]]), 0x00C8);
    }

    #[test]
    fn test_write_sec_level_changed_event() {
        let evt = GapEvent::SecLevelChanged(SecLevelChangedEvent {
            address: Address {
                kind: AddrKind::RANDOM,
                addr: BdAddr::new([1, 2, 3, 4, 5, 6]),
            },
            sec_level: 2,
        });
        let header = evt.header();
        assert_eq!(header.opcode, opcodes::EVENT_SEC_LEVEL_CHANGED);
        assert_eq!(header.data_len, 8);
        let mut buf = [0u8; 16];
        block_on(evt.write(&mut buf.as_mut_slice())).unwrap();
        assert_eq!(buf[7], 2);
    }

    #[test]
    fn test_write_pairing_failed_event() {
        let evt = GapEvent::PairingFailed(PairingFailedEvent {
            address: Address {
                kind: AddrKind::PUBLIC,
                addr: BdAddr::new([1, 2, 3, 4, 5, 6]),
            },
            reason: 0x05,
        });
        let header = evt.header();
        assert_eq!(header.opcode, opcodes::EVENT_PAIRING_FAILED);
        assert_eq!(header.data_len, 8);
        let mut buf = [0u8; 16];
        block_on(evt.write(&mut buf.as_mut_slice())).unwrap();
        assert_eq!(buf[7], 0x05);
    }

    #[test]
    fn test_write_device_found_event() {
        let evt = GapEvent::DeviceFound(DeviceFoundEvent {
            address: Address {
                kind: AddrKind::PUBLIC,
                addr: BdAddr::new([1, 2, 3, 4, 5, 6]),
            },
            rssi: -50,
            flags: DeviceFoundFlags::RSSI_VALID | DeviceFoundFlags::ADV_DATA,
            adv_data: &[0x02, 0x01, 0x06],
        });
        let header = evt.header();
        assert_eq!(header.opcode, opcodes::EVENT_DEVICE_FOUND);
        assert_eq!(header.data_len, 11 + 3);
        let mut buf = [0u8; 32];
        block_on(evt.write(&mut buf.as_mut_slice())).unwrap();
        assert_eq!(buf[7], (-50i8) as u8); // rssi
        assert_eq!(buf[8], 0x03); // flags: RSSI_VALID | ADV_DATA
        let data_len = u16::from_le_bytes([buf[9], buf[10]]);
        assert_eq!(data_len, 3);
        assert_eq!(&buf[11..14], &[0x02, 0x01, 0x06]);
    }

    #[test]
    fn test_write_new_settings_event() {
        let evt = GapEvent::NewSettings(GapSettings::POWERED | GapSettings::LE);
        let header = evt.header();
        assert_eq!(header.opcode, opcodes::EVENT_NEW_SETTINGS);
        assert_eq!(header.data_len, 4);
        let mut buf = [0u8; 8];
        block_on(evt.write(&mut buf.as_mut_slice())).unwrap();
        let settings = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(settings, (GapSettings::POWERED | GapSettings::LE).bits());
    }

    // --- Response write tests ---

    #[test]
    fn test_write_controller_index_list() {
        let resp = GapResponse::ControllerIndexList(ControllerIndexListResponse { count: 1, indices: [0] });
        assert_eq!(resp.data_len(), 2);
        let mut buf = [0u8; 4];
        block_on(resp.write(&mut buf.as_mut_slice())).unwrap();
        assert_eq!(buf[0], 1);
        assert_eq!(buf[1], 0);
    }

    #[test]
    fn test_write_supported_commands() {
        let resp = GapResponse::SupportedCommands(SUPPORTED_COMMANDS);
        assert_eq!(resp.data_len(), 4);
        let mut buf = [0u8; 8];
        block_on(resp.write(&mut buf.as_mut_slice())).unwrap();
        assert_eq!(&buf[..4], &SUPPORTED_COMMANDS);
    }

    #[test]
    fn test_write_success_response() {
        let resp = GapResponse::Success;
        assert_eq!(resp.data_len(), 0);
    }
}

//! GATT service (ID 2) protocol definitions.

use alloc::boxed::Box;

use embedded_io_async::Write;
use trouble_host::prelude::{AttPermissions, PermissionLevel, Uuid};

use super::Cursor;
use super::header::BtpHeader;
use crate::btp::error::Error;
use crate::btp::types::{AddrKind, BdAddr, ServiceId};

/// GATT service opcodes.
pub mod opcodes {
    use crate::btp::types::Opcode;

    // Server Commands (0x02-0x09)
    pub const READ_SUPPORTED_COMMANDS: Opcode = Opcode(0x01);
    pub const ADD_SERVICE: Opcode = Opcode(0x02);
    pub const ADD_CHARACTERISTIC: Opcode = Opcode(0x03);
    pub const ADD_DESCRIPTOR: Opcode = Opcode(0x04);
    pub const ADD_INCLUDED_SERVICE: Opcode = Opcode(0x05);
    pub const SET_VALUE: Opcode = Opcode(0x06);
    pub const START_SERVER: Opcode = Opcode(0x07);
    pub const SET_ENC_KEY_SIZE: Opcode = Opcode(0x09);

    // Client Commands - Discovery (0x0a-0x10)
    pub const EXCHANGE_MTU: Opcode = Opcode(0x0a);
    pub const DISCOVER_ALL_PRIMARY: Opcode = Opcode(0x0b);
    pub const DISCOVER_PRIMARY_UUID: Opcode = Opcode(0x0c);
    pub const FIND_INCLUDED: Opcode = Opcode(0x0d);
    pub const DISCOVER_ALL_CHRC: Opcode = Opcode(0x0e);
    pub const DISCOVER_CHRC_UUID: Opcode = Opcode(0x0f);
    pub const DISCOVER_ALL_DESC: Opcode = Opcode(0x10);

    // Client Commands - Read (0x11-0x14, 0x20)
    pub const READ: Opcode = Opcode(0x11);
    pub const READ_UUID: Opcode = Opcode(0x12);
    pub const READ_LONG: Opcode = Opcode(0x13);
    pub const READ_MULTIPLE: Opcode = Opcode(0x14);
    pub const READ_MULTIPLE_VAR: Opcode = Opcode(0x20);

    // Client Commands - Write (0x15-0x19)
    pub const WRITE_WITHOUT_RSP: Opcode = Opcode(0x15);
    pub const SIGNED_WRITE_WITHOUT_RSP: Opcode = Opcode(0x16);
    pub const WRITE: Opcode = Opcode(0x17);
    pub const WRITE_LONG: Opcode = Opcode(0x18);
    pub const RELIABLE_WRITE: Opcode = Opcode(0x19);

    // Client Commands - Notifications/Indications (0x1a-0x1b)
    pub const CFG_NOTIFY: Opcode = Opcode(0x1a);
    pub const CFG_INDICATE: Opcode = Opcode(0x1b);

    // Server Commands (0x1c-0x1e)
    pub const GET_ATTRS: Opcode = Opcode(0x1c);
    pub const GET_ATTR_VALUE: Opcode = Opcode(0x1d);

    // Events
    pub const EVENT_NOTIFICATION_RECEIVED: Opcode = Opcode(0x80);
    pub const EVENT_ATTR_VALUE_CHANGED: Opcode = Opcode(0x81);
}

/// Supported commands bitmask for GATT service.
pub const SUPPORTED_COMMANDS: [u8; 5] = super::supported_commands_bitmask(&[
    opcodes::READ_SUPPORTED_COMMANDS,
    opcodes::ADD_SERVICE,
    opcodes::ADD_CHARACTERISTIC,
    opcodes::ADD_DESCRIPTOR,
    opcodes::ADD_INCLUDED_SERVICE,
    opcodes::SET_VALUE,
    opcodes::START_SERVER,
    opcodes::SET_ENC_KEY_SIZE,
    opcodes::EXCHANGE_MTU,
    opcodes::DISCOVER_ALL_PRIMARY,
    opcodes::DISCOVER_PRIMARY_UUID,
    opcodes::FIND_INCLUDED,
    opcodes::DISCOVER_ALL_CHRC,
    opcodes::DISCOVER_CHRC_UUID,
    opcodes::DISCOVER_ALL_DESC,
    opcodes::READ,
    opcodes::READ_UUID,
    opcodes::READ_LONG,
    opcodes::READ_MULTIPLE,
    opcodes::WRITE_WITHOUT_RSP,
    opcodes::SIGNED_WRITE_WITHOUT_RSP,
    opcodes::WRITE,
    opcodes::WRITE_LONG,
    opcodes::RELIABLE_WRITE,
    opcodes::CFG_NOTIFY,
    opcodes::CFG_INDICATE,
    opcodes::GET_ATTRS,
    opcodes::GET_ATTR_VALUE,
    opcodes::READ_MULTIPLE_VAR,
]);

/// GATT service type (primary or secondary).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ServiceType {
    #[default]
    Primary,
    Secondary,
}

/// Attribute permissions.
#[derive(Debug, Clone, Copy, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AttPermission(u8);

bitflags::bitflags! {
    impl AttPermission: u8 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const READ_ENC = 1 << 2;
        const WRITE_ENC = 1 << 3;
        const READ_AUTHEN = 1 << 4;
        const WRITE_AUTHEN = 1 << 5;
        const READ_AUTHOR = 1 << 6;
        const WRITE_AUTHOR = 1 << 7;
    }
}

impl From<AttPermission> for trouble_host::attribute::AttPermissions {
    fn from(value: AttPermission) -> Self {
        let read = if value.contains(AttPermission::READ) {
            PermissionLevel::Allowed
        } else if value.contains(AttPermission::READ_ENC) {
            PermissionLevel::EncryptionRequired
        } else if value.contains(AttPermission::READ_AUTHEN) {
            PermissionLevel::AuthenticationRequired
        } else {
            PermissionLevel::NotAllowed
        };

        let write = if value.contains(AttPermission::WRITE) {
            PermissionLevel::Allowed
        } else if value.contains(AttPermission::WRITE_ENC) {
            PermissionLevel::EncryptionRequired
        } else if value.contains(AttPermission::WRITE_AUTHEN) {
            PermissionLevel::AuthenticationRequired
        } else {
            PermissionLevel::NotAllowed
        };

        trouble_host::attribute::AttPermissions { read, write }
    }
}

impl From<trouble_host::attribute::AttPermissions> for AttPermission {
    fn from(value: trouble_host::attribute::AttPermissions) -> Self {
        let mut result = AttPermission::empty();
        match value.read {
            PermissionLevel::Allowed => {
                result |= AttPermission::READ
                    | AttPermission::READ_ENC
                    | AttPermission::READ_AUTHEN
                    | AttPermission::READ_AUTHOR
            }
            PermissionLevel::EncryptionRequired => {
                result |= AttPermission::READ_ENC | AttPermission::READ_AUTHEN | AttPermission::READ_AUTHOR
            }
            PermissionLevel::AuthenticationRequired => {
                result |= AttPermission::READ_AUTHEN | AttPermission::READ_AUTHOR
            }
            PermissionLevel::NotAllowed => (),
        }
        match value.write {
            PermissionLevel::Allowed => {
                result |= AttPermission::WRITE
                    | AttPermission::WRITE_ENC
                    | AttPermission::WRITE_AUTHEN
                    | AttPermission::WRITE_AUTHOR
            }
            PermissionLevel::EncryptionRequired => {
                result |= AttPermission::WRITE_ENC | AttPermission::WRITE_AUTHEN | AttPermission::WRITE_AUTHOR
            }
            PermissionLevel::AuthenticationRequired => {
                result |= AttPermission::WRITE_AUTHEN | AttPermission::WRITE_AUTHOR
            }
            PermissionLevel::NotAllowed => (),
        }
        result
    }
}

/// Notification type for event 0x80.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum NotificationType {
    Notification = 0x01,
    Indication = 0x02,
}

/// Service discovery result.
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub start_handle: u16,
    pub end_handle: u16,
    pub uuid: Uuid,
}

#[cfg(feature = "defmt")]
impl defmt::Format for ServiceInfo {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(
            f,
            "ServiceInfo {{ start: {=u16:#x}, end: {=u16:#x} }}",
            self.start_handle,
            self.end_handle
        )
    }
}

/// Included service discovery result.
#[derive(Debug, Clone)]
pub struct IncludedServiceInfo {
    pub included_handle: u16,
    pub service_type: ServiceType,
    pub start_handle: u16,
    pub end_handle: u16,
    pub uuid: Uuid,
}

#[cfg(feature = "defmt")]
impl defmt::Format for IncludedServiceInfo {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(
            f,
            "IncludedServiceInfo {{ included: {=u16:#x}, type: {}, start: {=u16:#x}, end: {=u16:#x} }}",
            self.included_handle,
            self.service_type,
            self.start_handle,
            self.end_handle
        )
    }
}

/// Characteristic discovery result.
#[derive(Debug, Clone)]
pub struct CharacteristicInfo {
    pub char_handle: u16,
    pub value_handle: u16,
    pub properties: u8,
    pub uuid: Uuid,
}

#[cfg(feature = "defmt")]
impl defmt::Format for CharacteristicInfo {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(
            f,
            "CharacteristicInfo {{ char: {=u16:#x}, value: {=u16:#x}, props: {=u8:#x} }}",
            self.char_handle,
            self.value_handle,
            self.properties
        )
    }
}

/// Descriptor discovery result.
#[derive(Debug, Clone)]
pub struct DescriptorInfo {
    pub handle: u16,
    pub uuid: Uuid,
}

#[cfg(feature = "defmt")]
impl defmt::Format for DescriptorInfo {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "DescriptorInfo {{ handle: {=u16:#x} }}", self.handle)
    }
}

/// Characteristic value from ReadUuid.
#[derive(Debug, Clone)]
pub struct CharacteristicValue {
    pub handle: u16,
    pub data: Box<[u8]>,
}

#[cfg(feature = "defmt")]
impl defmt::Format for CharacteristicValue {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(
            f,
            "CharacteristicValue {{ handle: {=u16:#x}, data_len: {=usize} }}",
            self.handle,
            self.data.len()
        )
    }
}

/// Parse a UUID from a cursor (1-byte length prefix followed by that many UUID bytes).
fn parse_uuid(cursor: &mut Cursor<'_>) -> Result<Uuid, Error> {
    parse_opt_uuid(cursor)?.ok_or(Error::InvalidPacket)
}

/// Parse an optional UUID from a cursor (1-byte length prefix followed by that many UUID bytes).
/// Returns `None` if the length prefix is 0.
fn parse_opt_uuid(cursor: &mut Cursor<'_>) -> Result<Option<Uuid>, Error> {
    let uuid_len = cursor.read_u8()? as usize;
    if uuid_len == 0 {
        return Ok(None);
    }
    if uuid_len > 16 {
        return Err(Error::InvalidPacket);
    }
    let slice = cursor.read_exact(uuid_len)?;
    Uuid::try_from(slice).map(Some).map_err(|_| Error::InvalidPacket)
}

/// Write a UUID as a 1-byte length prefix followed by the UUID bytes.
async fn write_uuid<W: Write>(uuid: &Uuid, mut writer: W) -> Result<(), W::Error> {
    let uuid_len = uuid.as_raw().len() as u8;
    writer.write_all(&[uuid_len]).await?;
    writer.write_all(uuid.as_raw()).await
}

/// Iterator over u16 handles from raw LE byte pairs.
#[allow(unused)]
pub struct HandleIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Iterator for HandleIter<'_> {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos + 2 > self.data.len() {
            return None;
        }
        let handle = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Some(handle)
    }
}

// === GattCommand structs ===

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AddServiceCommand {
    pub service_type: ServiceType,
    pub uuid: Uuid,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AddCharacteristicCommand {
    pub service_id: u16,
    pub properties: u8,
    pub permissions: AttPermissions,
    pub uuid: Uuid,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AddDescriptorCommand {
    pub char_id: u16,
    pub permissions: AttPermissions,
    pub uuid: Uuid,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SetValueCommand<'a> {
    pub attr_id: u16,
    pub value: &'a [u8],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ExchangeMtuCommand {
    pub addr_type: AddrKind,
    pub address: BdAddr,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(unused)]
pub struct DiscoverAllPrimaryCommand {
    pub addr_type: AddrKind,
    pub address: BdAddr,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DiscoverPrimaryUuidCommand {
    pub addr_type: AddrKind,
    pub address: BdAddr,
    pub uuid: Uuid,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(unused)]
pub struct FindIncludedCommand {
    pub addr_type: AddrKind,
    pub address: BdAddr,
    pub start_handle: u16,
    pub end_handle: u16,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(unused)]
pub struct DiscoverAllChrcCommand {
    pub addr_type: AddrKind,
    pub address: BdAddr,
    pub start_handle: u16,
    pub end_handle: u16,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DiscoverChrcUuidCommand {
    pub addr_type: AddrKind,
    pub address: BdAddr,
    pub start_handle: u16,
    pub end_handle: u16,
    pub uuid: Uuid,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(unused)]
pub struct DiscoverAllDescCommand {
    pub addr_type: AddrKind,
    pub address: BdAddr,
    pub start_handle: u16,
    pub end_handle: u16,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ReadCommand {
    pub addr_type: AddrKind,
    pub address: BdAddr,
    pub handle: u16,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ReadUuidCommand {
    pub addr_type: AddrKind,
    pub address: BdAddr,
    pub start_handle: u16,
    pub end_handle: u16,
    pub uuid: Uuid,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ReadLongCommand {
    pub addr_type: AddrKind,
    pub address: BdAddr,
    pub handle: u16,
    pub offset: u16,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(unused)]
pub struct ReadMultipleCommand<'a> {
    pub addr_type: AddrKind,
    pub address: BdAddr,
    handles: &'a [u8],
}

#[allow(unused)]
impl<'a> ReadMultipleCommand<'a> {
    /// Iterate over the u16 handles.
    pub fn handles(&self) -> HandleIter<'a> {
        HandleIter {
            data: self.handles,
            pos: 0,
        }
    }

    /// Number of handles.
    pub fn handle_count(&self) -> usize {
        self.handles.len() / 2
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(unused)]
pub struct ReadMultipleVarCommand<'a> {
    pub addr_type: AddrKind,
    pub address: BdAddr,
    handles: &'a [u8],
}

#[allow(unused)]
impl<'a> ReadMultipleVarCommand<'a> {
    /// Iterate over the u16 handles.
    pub fn handles(&self) -> HandleIter<'a> {
        HandleIter {
            data: self.handles,
            pos: 0,
        }
    }

    /// Number of handles.
    pub fn handle_count(&self) -> usize {
        self.handles.len() / 2
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct WriteWithoutRspCommand<'a> {
    pub addr_type: AddrKind,
    pub address: BdAddr,
    pub handle: u16,
    pub data: &'a [u8],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(unused)]
pub struct SignedWriteWithoutRspCommand<'a> {
    pub addr_type: AddrKind,
    pub address: BdAddr,
    pub handle: u16,
    pub data: &'a [u8],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct WriteCommand<'a> {
    pub addr_type: AddrKind,
    pub address: BdAddr,
    pub handle: u16,
    pub data: &'a [u8],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(unused)]
pub struct WriteLongCommand<'a> {
    pub addr_type: AddrKind,
    pub address: BdAddr,
    pub handle: u16,
    pub offset: u16,
    pub data: &'a [u8],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(unused)]
pub struct ReliableWriteCommand<'a> {
    pub addr_type: AddrKind,
    pub address: BdAddr,
    pub handle: u16,
    pub offset: u16,
    pub data: &'a [u8],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CfgNotifyCommand {
    pub addr_type: AddrKind,
    pub address: BdAddr,
    pub enable: bool,
    pub ccc_handle: u16,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CfgIndicateCommand {
    pub addr_type: AddrKind,
    pub address: BdAddr,
    pub enable: bool,
    pub ccc_handle: u16,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GetAttrsCommand {
    pub start_handle: u16,
    pub end_handle: u16,
    pub type_uuid: Option<Uuid>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(unused)]
pub struct GetAttrValueCommand {
    pub addr_type: AddrKind,
    pub address: BdAddr,
    pub handle: u16,
}

/// Parsed GATT command.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum GattCommand<'a> {
    // === Server Commands (0x01-0x09) ===
    /// Read supported commands (0x01).
    ReadSupportedCommands,

    /// Add service (0x02).
    AddService(AddServiceCommand),

    /// Add characteristic (0x03).
    AddCharacteristic(AddCharacteristicCommand),

    /// Add descriptor (0x04).
    AddDescriptor(AddDescriptorCommand),

    /// Add included service (0x05).
    AddIncludedService(u16),

    /// Set attribute value (0x06).
    SetValue(SetValueCommand<'a>),

    /// Start server (0x07).
    StartServer,

    /// Set required encryption key size (0x09).
    SetEncKeySize {
        #[allow(unused)]
        attr_id: u16,
        #[allow(unused)]
        key_size: u8,
    },

    // === Client Commands - Discovery (0x0a-0x10) ===
    /// Exchange MTU (0x0a).
    ExchangeMtu(ExchangeMtuCommand),

    /// Discover all primary services (0x0b).
    DiscoverAllPrimary(#[allow(unused)] DiscoverAllPrimaryCommand),

    /// Discover primary service by UUID (0x0c).
    DiscoverPrimaryUuid(DiscoverPrimaryUuidCommand),

    /// Find included services (0x0d).
    FindIncluded(#[allow(unused)] FindIncludedCommand),

    /// Discover all characteristics of a service (0x0e).
    DiscoverAllChrc(#[allow(unused)] DiscoverAllChrcCommand),

    /// Discover characteristics by UUID (0x0f).
    DiscoverChrcUuid(DiscoverChrcUuidCommand),

    /// Discover all characteristic descriptors (0x10).
    DiscoverAllDesc(#[allow(unused)] DiscoverAllDescCommand),

    // === Client Commands - Read (0x11-0x14, 0x20) ===
    /// Read characteristic value/descriptor (0x11).
    Read(ReadCommand),

    /// Read using characteristic UUID (0x12).
    ReadUuid(ReadUuidCommand),

    /// Read long characteristic value/descriptor (0x13).
    ReadLong(ReadLongCommand),

    /// Read multiple characteristic values (0x14).
    ReadMultiple(#[allow(unused)] ReadMultipleCommand<'a>),

    /// Read multiple variable length characteristic values (0x20).
    ReadMultipleVar(#[allow(unused)] ReadMultipleVarCommand<'a>),

    // === Client Commands - Write (0x15-0x19) ===
    /// Write without response (0x15).
    WriteWithoutRsp(WriteWithoutRspCommand<'a>),

    /// Signed write without response (0x16).
    SignedWriteWithoutRsp(#[allow(unused)] SignedWriteWithoutRspCommand<'a>),

    /// Write characteristic value/descriptor (0x17).
    Write(WriteCommand<'a>),

    /// Write long characteristic value/descriptor (0x18).
    WriteLong(#[allow(unused)] WriteLongCommand<'a>),

    /// Reliable write (0x19).
    ReliableWrite(#[allow(unused)] ReliableWriteCommand<'a>),

    // === Client Commands - Notifications/Indications (0x1a-0x1b) ===
    /// Configure notifications (0x1a).
    CfgNotify(CfgNotifyCommand),

    /// Configure indications (0x1b).
    CfgIndicate(CfgIndicateCommand),

    // === Server Commands (0x1c-0x1e) ===
    /// Get attributes (0x1c).
    GetAttrs(GetAttrsCommand),

    /// Get attribute value (0x1d).
    GetAttrValue(GetAttrValueCommand),
}

impl<'a> GattCommand<'a> {
    /// Parse a GATT command from header and cursor.
    pub fn parse(header: &BtpHeader, cursor: &mut Cursor<'a>) -> Result<Self, Error> {
        // ReadSupportedCommands doesn't require controller index
        if header.opcode == opcodes::READ_SUPPORTED_COMMANDS {
            return Ok(GattCommand::ReadSupportedCommands);
        }

        // All other commands require controller index 0
        match header.controller_index {
            Some(0) => {}
            Some(_) => return Err(Error::InvalidIndex),
            None => return Err(Error::InvalidIndex),
        }

        match header.opcode {
            // Server Commands (0x02-0x09)
            opcodes::ADD_SERVICE => Self::parse_add_service(cursor),
            opcodes::ADD_CHARACTERISTIC => Self::parse_add_characteristic(cursor),
            opcodes::ADD_DESCRIPTOR => Self::parse_add_descriptor(cursor),
            opcodes::ADD_INCLUDED_SERVICE => {
                let service_id = cursor.read_u16_le()?;
                Ok(GattCommand::AddIncludedService(service_id))
            }
            opcodes::SET_VALUE => Self::parse_set_value(cursor),
            opcodes::START_SERVER => Ok(GattCommand::StartServer),
            opcodes::SET_ENC_KEY_SIZE => {
                let attr_id = cursor.read_u16_le()?;
                let key_size = cursor.read_u8()?;
                Ok(GattCommand::SetEncKeySize { attr_id, key_size })
            }

            // Client Commands - Discovery (0x0a-0x10)
            opcodes::EXCHANGE_MTU => {
                let (addr_type, address) = Self::parse_addr_only(cursor)?;
                Ok(GattCommand::ExchangeMtu(ExchangeMtuCommand { addr_type, address }))
            }
            opcodes::DISCOVER_ALL_PRIMARY => {
                let (addr_type, address) = Self::parse_addr_only(cursor)?;
                Ok(GattCommand::DiscoverAllPrimary(DiscoverAllPrimaryCommand {
                    addr_type,
                    address,
                }))
            }
            opcodes::DISCOVER_PRIMARY_UUID => {
                let (addr_type, address) = Self::parse_addr_only(cursor)?;
                let uuid = parse_uuid(cursor)?;
                Ok(GattCommand::DiscoverPrimaryUuid(DiscoverPrimaryUuidCommand {
                    addr_type,
                    address,
                    uuid,
                }))
            }
            opcodes::FIND_INCLUDED => {
                let (addr_type, address, start_handle, end_handle) = Self::parse_addr_with_handles(cursor)?;
                Ok(GattCommand::FindIncluded(FindIncludedCommand {
                    addr_type,
                    address,
                    start_handle,
                    end_handle,
                }))
            }
            opcodes::DISCOVER_ALL_CHRC => {
                let (addr_type, address, start_handle, end_handle) = Self::parse_addr_with_handles(cursor)?;
                Ok(GattCommand::DiscoverAllChrc(DiscoverAllChrcCommand {
                    addr_type,
                    address,
                    start_handle,
                    end_handle,
                }))
            }
            opcodes::DISCOVER_CHRC_UUID => {
                let (addr_type, address, start_handle, end_handle) = Self::parse_addr_with_handles(cursor)?;
                let uuid = parse_uuid(cursor)?;
                Ok(GattCommand::DiscoverChrcUuid(DiscoverChrcUuidCommand {
                    addr_type,
                    address,
                    start_handle,
                    end_handle,
                    uuid,
                }))
            }
            opcodes::DISCOVER_ALL_DESC => {
                let (addr_type, address, start_handle, end_handle) = Self::parse_addr_with_handles(cursor)?;
                Ok(GattCommand::DiscoverAllDesc(DiscoverAllDescCommand {
                    addr_type,
                    address,
                    start_handle,
                    end_handle,
                }))
            }

            // Client Commands - Read (0x11-0x14, 0x20)
            opcodes::READ => {
                let (addr_type, address) = Self::parse_addr_only(cursor)?;
                let handle = cursor.read_u16_le()?;
                Ok(GattCommand::Read(ReadCommand {
                    addr_type,
                    address,
                    handle,
                }))
            }
            opcodes::READ_UUID => {
                let (addr_type, address, start_handle, end_handle) = Self::parse_addr_with_handles(cursor)?;
                let uuid = parse_uuid(cursor)?;
                Ok(GattCommand::ReadUuid(ReadUuidCommand {
                    addr_type,
                    address,
                    start_handle,
                    end_handle,
                    uuid,
                }))
            }
            opcodes::READ_LONG => {
                let (addr_type, address) = Self::parse_addr_only(cursor)?;
                let handle = cursor.read_u16_le()?;
                let offset = cursor.read_u16_le()?;
                Ok(GattCommand::ReadLong(ReadLongCommand {
                    addr_type,
                    address,
                    handle,
                    offset,
                }))
            }
            opcodes::READ_MULTIPLE => {
                let (addr_type, address, handles) = Self::parse_read_multiple(cursor)?;
                Ok(GattCommand::ReadMultiple(ReadMultipleCommand {
                    addr_type,
                    address,
                    handles,
                }))
            }
            opcodes::READ_MULTIPLE_VAR => {
                let (addr_type, address, handles) = Self::parse_read_multiple(cursor)?;
                Ok(GattCommand::ReadMultipleVar(ReadMultipleVarCommand {
                    addr_type,
                    address,
                    handles,
                }))
            }

            // Client Commands - Write (0x15-0x19)
            opcodes::WRITE_WITHOUT_RSP => {
                let (addr_type, address, handle, data) = Self::parse_write_cmd(cursor)?;
                Ok(GattCommand::WriteWithoutRsp(WriteWithoutRspCommand {
                    addr_type,
                    address,
                    handle,
                    data,
                }))
            }
            opcodes::SIGNED_WRITE_WITHOUT_RSP => {
                let (addr_type, address, handle, data) = Self::parse_write_cmd(cursor)?;
                Ok(GattCommand::SignedWriteWithoutRsp(SignedWriteWithoutRspCommand {
                    addr_type,
                    address,
                    handle,
                    data,
                }))
            }
            opcodes::WRITE => {
                let (addr_type, address, handle, data) = Self::parse_write_cmd(cursor)?;
                Ok(GattCommand::Write(WriteCommand {
                    addr_type,
                    address,
                    handle,
                    data,
                }))
            }
            opcodes::WRITE_LONG => {
                let (addr_type, address, handle, offset, data) = Self::parse_write_long(cursor)?;
                Ok(GattCommand::WriteLong(WriteLongCommand {
                    addr_type,
                    address,
                    handle,
                    offset,
                    data,
                }))
            }
            opcodes::RELIABLE_WRITE => {
                let (addr_type, address, handle, offset, data) = Self::parse_write_long(cursor)?;
                Ok(GattCommand::ReliableWrite(ReliableWriteCommand {
                    addr_type,
                    address,
                    handle,
                    offset,
                    data,
                }))
            }

            // Client Commands - Notifications/Indications (0x1a-0x1b)
            opcodes::CFG_NOTIFY => {
                let (addr_type, address, enable, ccc_handle) = Self::parse_cfg_notify_indicate(cursor)?;
                Ok(GattCommand::CfgNotify(CfgNotifyCommand {
                    addr_type,
                    address,
                    enable,
                    ccc_handle,
                }))
            }
            opcodes::CFG_INDICATE => {
                let (addr_type, address, enable, ccc_handle) = Self::parse_cfg_notify_indicate(cursor)?;
                Ok(GattCommand::CfgIndicate(CfgIndicateCommand {
                    addr_type,
                    address,
                    enable,
                    ccc_handle,
                }))
            }

            // Server Commands (0x1c-0x1e)
            opcodes::GET_ATTRS => Self::parse_get_attrs(cursor),
            opcodes::GET_ATTR_VALUE => {
                let (addr_type, address) = Self::parse_addr_only(cursor)?;
                let handle = cursor.read_u16_le()?;
                Ok(GattCommand::GetAttrValue(GetAttrValueCommand {
                    addr_type,
                    address,
                    handle,
                }))
            }

            _ => Err(Error::UnknownCommand {
                service: ServiceId::GATT,
                opcode: header.opcode,
            }),
        }
    }

    // === Helper parse methods ===

    /// Parse just address type and address (7 bytes).
    fn parse_addr_only(cursor: &mut Cursor<'_>) -> Result<(AddrKind, BdAddr), Error> {
        let buf = cursor.read_exact(7)?;
        let addr_type = AddrKind::new(buf[0]);
        let address = BdAddr::new([buf[1], buf[2], buf[3], buf[4], buf[5], buf[6]]);
        Ok((addr_type, address))
    }

    /// Parse address + start/end handles (11 bytes).
    fn parse_addr_with_handles(cursor: &mut Cursor<'_>) -> Result<(AddrKind, BdAddr, u16, u16), Error> {
        let buf = cursor.read_exact(11)?;
        let addr_type = AddrKind::new(buf[0]);
        let address = BdAddr::new([buf[1], buf[2], buf[3], buf[4], buf[5], buf[6]]);
        let start_handle = u16::from_le_bytes([buf[7], buf[8]]);
        let end_handle = u16::from_le_bytes([buf[9], buf[10]]);
        Ok((addr_type, address, start_handle, end_handle))
    }

    fn parse_add_service(cursor: &mut Cursor<'_>) -> Result<Self, Error> {
        let service_type_byte = cursor.read_u8()?;
        let service_type = match service_type_byte {
            0x00 => ServiceType::Primary,
            0x01 => ServiceType::Secondary,
            _ => return Err(Error::InvalidPacket),
        };
        let uuid = parse_uuid(cursor)?;
        Ok(GattCommand::AddService(AddServiceCommand { service_type, uuid }))
    }

    fn parse_add_characteristic(cursor: &mut Cursor<'_>) -> Result<Self, Error> {
        let service_id = cursor.read_u16_le()?;
        let properties = cursor.read_u8()?;
        let permissions = AttPermission::from_bits_truncate(cursor.read_u8()?).into();
        let uuid = parse_uuid(cursor)?;
        Ok(GattCommand::AddCharacteristic(AddCharacteristicCommand {
            service_id,
            properties,
            permissions,
            uuid,
        }))
    }

    fn parse_add_descriptor(cursor: &mut Cursor<'_>) -> Result<Self, Error> {
        let char_id = cursor.read_u16_le()?;
        let permissions = AttPermission::from_bits_truncate(cursor.read_u8()?).into();
        let uuid = parse_uuid(cursor)?;
        Ok(GattCommand::AddDescriptor(AddDescriptorCommand {
            char_id,
            permissions,
            uuid,
        }))
    }

    fn parse_set_value(cursor: &mut Cursor<'a>) -> Result<Self, Error> {
        let attr_id = cursor.read_u16_le()?;
        let value_len = cursor.read_u16_le()? as usize;
        let value = cursor.read_exact(value_len)?;
        Ok(GattCommand::SetValue(SetValueCommand { attr_id, value }))
    }

    fn parse_read_multiple(cursor: &mut Cursor<'a>) -> Result<(AddrKind, BdAddr, &'a [u8]), Error> {
        let (addr_type, address) = Self::parse_addr_only(cursor)?;
        let handles_count = cursor.read_u8()? as usize;
        let handles = cursor.read_exact(handles_count * 2)?;
        Ok((addr_type, address, handles))
    }

    fn parse_write_cmd(cursor: &mut Cursor<'a>) -> Result<(AddrKind, BdAddr, u16, &'a [u8]), Error> {
        let (addr_type, address) = Self::parse_addr_only(cursor)?;
        let handle = cursor.read_u16_le()?;
        let data_len = cursor.read_u16_le()? as usize;
        let data = cursor.read_exact(data_len)?;
        Ok((addr_type, address, handle, data))
    }

    fn parse_write_long(cursor: &mut Cursor<'a>) -> Result<(AddrKind, BdAddr, u16, u16, &'a [u8]), Error> {
        let (addr_type, address) = Self::parse_addr_only(cursor)?;
        let handle = cursor.read_u16_le()?;
        let offset = cursor.read_u16_le()?;
        let data_len = cursor.read_u16_le()? as usize;
        let data = cursor.read_exact(data_len)?;
        Ok((addr_type, address, handle, offset, data))
    }

    fn parse_cfg_notify_indicate(cursor: &mut Cursor<'_>) -> Result<(AddrKind, BdAddr, bool, u16), Error> {
        let (addr_type, address) = Self::parse_addr_only(cursor)?;
        let enable = cursor.read_u8()? != 0;
        let ccc_handle = cursor.read_u16_le()?;
        Ok((addr_type, address, enable, ccc_handle))
    }

    fn parse_get_attrs(cursor: &mut Cursor<'_>) -> Result<Self, Error> {
        let start_handle = cursor.read_u16_le()?;
        let end_handle = cursor.read_u16_le()?;
        let type_uuid = parse_opt_uuid(cursor)?;
        Ok(GattCommand::GetAttrs(GetAttrsCommand {
            start_handle,
            end_handle,
            type_uuid,
        }))
    }
}

// === GattResponse structs ===

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ServerStartedResponse {
    pub db_attr_offset: u16,
    pub db_attr_count: u8,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ReadDataResponse {
    pub att_response: u8,
    pub data: Box<[u8]>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ReadUuidDataResponse {
    pub att_response: u8,
    pub values: Box<[CharacteristicValue]>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AttrValueResponse {
    pub att_response: u8,
    pub value: Box<[u8]>,
}

/// GATT service response.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum GattResponse {
    /// Supported commands bitmask (response to 0x01).
    /// Bitmask needs 5 bytes to cover opcodes up to 0x23 (35 bits).
    SupportedCommands([u8; 5]),

    /// Service added (response to 0x02).
    ServiceAdded(u16),

    /// Characteristic added (response to 0x03).
    CharacteristicAdded(u16),

    /// Descriptor added (response to 0x04).
    DescriptorAdded(u16),

    /// Included service added (response to 0x05).
    IncludedServiceAdded(u16),

    /// Value set (response to 0x06).
    ValueSet,

    /// Server started (response to 0x07).
    ServerStarted(ServerStartedResponse),

    /// Encryption key size set (response to 0x09).
    EncKeySizeSet,

    /// MTU exchanged (response to 0x0a).
    MtuExchanged,

    /// Services discovered (response to 0x0b, 0x0c).
    Services(Box<[ServiceInfo]>),

    /// Included services found (response to 0x0d).
    #[allow(unused)]
    IncludedServices(Box<[IncludedServiceInfo]>),

    /// Characteristics discovered (response to 0x0e, 0x0f).
    Characteristics(Box<[CharacteristicInfo]>),

    /// Descriptors discovered (response to 0x10).
    #[allow(unused)]
    Descriptors(Box<[DescriptorInfo]>),

    /// Read data (response to 0x11, 0x13, 0x14, 0x20).
    ReadData(ReadDataResponse),

    /// Read UUID data (response to 0x12).
    ReadUuidData(ReadUuidDataResponse),

    /// Write result (response to 0x17, 0x18, 0x19).
    WriteResult(u8),

    /// Write without response completed (response to 0x15, 0x16).
    WriteWithoutRspDone,

    /// Notification/indication configured (response to 0x1a, 0x1b).
    CfgDone,

    /// Attributes list (response to 0x1c).
    Attrs(Box<[AttributeInfo]>),

    /// Attribute value (response to 0x1d).
    AttrValue(AttrValueResponse),
}

/// Information about a single attribute.
#[derive(Debug, Clone)]
pub struct AttributeInfo {
    pub handle: u16,
    pub permission: AttPermission,
    pub type_uuid: Uuid,
}

#[cfg(feature = "defmt")]
impl defmt::Format for AttributeInfo {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(
            f,
            "AttributeInfo {{ handle: {=u16:#x}, perm: {=u8:#x} }}",
            self.handle,
            self.permission.bits()
        )
    }
}

impl GattResponse {
    /// Get the data length for this response.
    pub fn data_len(&self) -> u16 {
        match self {
            GattResponse::SupportedCommands(bitmask) => bitmask.len() as u16,
            GattResponse::ServiceAdded(..) => 2,
            GattResponse::CharacteristicAdded(..) => 2,
            GattResponse::DescriptorAdded(..) => 2,
            GattResponse::IncludedServiceAdded(..) => 2,
            GattResponse::ValueSet => 0,
            GattResponse::ServerStarted(..) => 3, // 2 + 1
            GattResponse::EncKeySizeSet => 0,
            GattResponse::MtuExchanged => 0,
            GattResponse::Services(services) => {
                1 + services.iter().map(|s| 5 + s.uuid.as_raw().len() as u16).sum::<u16>()
            }
            GattResponse::IncludedServices(services) => {
                1 + services.iter().map(|s| 8 + s.uuid.as_raw().len() as u16).sum::<u16>()
            }
            GattResponse::Characteristics(characteristics) => {
                1 + characteristics
                    .iter()
                    .map(|c| 6 + c.uuid.as_raw().len() as u16)
                    .sum::<u16>()
            }
            GattResponse::Descriptors(descriptors) => {
                1 + descriptors
                    .iter()
                    .map(|d| 3 + d.uuid.as_raw().len() as u16)
                    .sum::<u16>()
            }
            GattResponse::ReadData(rsp) => 1 + 2 + rsp.data.len() as u16,
            GattResponse::ReadUuidData(rsp) => 1 + 1 + rsp.values.iter().map(|v| 3 + v.data.len() as u16).sum::<u16>(),
            GattResponse::WriteResult(..) => 1,
            GattResponse::WriteWithoutRspDone => 0,
            GattResponse::CfgDone => 0,
            GattResponse::Attrs(attrs) => 1 + attrs.iter().map(|a| 4 + a.type_uuid.as_raw().len() as u16).sum::<u16>(),
            GattResponse::AttrValue(rsp) => 1 + 2 + rsp.value.len() as u16,
        }
    }

    /// Write the response data.
    pub async fn write<W: Write>(&self, mut writer: W) -> Result<(), W::Error> {
        match self {
            GattResponse::SupportedCommands(bitmask) => writer.write_all(bitmask).await,
            GattResponse::ServiceAdded(service_id) => writer.write_all(&service_id.to_le_bytes()).await,
            GattResponse::CharacteristicAdded(char_id) => writer.write_all(&char_id.to_le_bytes()).await,
            GattResponse::DescriptorAdded(desc_id) => writer.write_all(&desc_id.to_le_bytes()).await,
            GattResponse::IncludedServiceAdded(included_service_id) => {
                writer.write_all(&included_service_id.to_le_bytes()).await
            }
            GattResponse::ValueSet => Ok(()),
            GattResponse::EncKeySizeSet => Ok(()),
            GattResponse::ServerStarted(rsp) => {
                writer.write_all(&rsp.db_attr_offset.to_le_bytes()).await?;
                writer.write_all(&[rsp.db_attr_count]).await
            }
            GattResponse::MtuExchanged => Ok(()),
            GattResponse::Services(services) => {
                writer.write_all(&[services.len() as u8]).await?;
                for service in services {
                    writer.write_all(&service.start_handle.to_le_bytes()).await?;
                    writer.write_all(&service.end_handle.to_le_bytes()).await?;
                    write_uuid(&service.uuid, &mut writer).await?;
                }
                Ok(())
            }
            GattResponse::IncludedServices(services) => {
                writer.write_all(&[services.len() as u8]).await?;
                for service in services {
                    writer.write_all(&service.included_handle.to_le_bytes()).await?;
                    let svc_type = match service.service_type {
                        ServiceType::Primary => 0x00,
                        ServiceType::Secondary => 0x01,
                    };
                    writer.write_all(&[svc_type]).await?;
                    writer.write_all(&service.start_handle.to_le_bytes()).await?;
                    writer.write_all(&service.end_handle.to_le_bytes()).await?;
                    write_uuid(&service.uuid, &mut writer).await?;
                }
                Ok(())
            }
            GattResponse::Characteristics(characteristics) => {
                writer.write_all(&[characteristics.len() as u8]).await?;
                for chrc in characteristics {
                    writer.write_all(&chrc.char_handle.to_le_bytes()).await?;
                    writer.write_all(&chrc.value_handle.to_le_bytes()).await?;
                    writer.write_all(&[chrc.properties]).await?;
                    write_uuid(&chrc.uuid, &mut writer).await?;
                }
                Ok(())
            }
            GattResponse::Descriptors(descriptors) => {
                writer.write_all(&[descriptors.len() as u8]).await?;
                for desc in descriptors {
                    writer.write_all(&desc.handle.to_le_bytes()).await?;
                    write_uuid(&desc.uuid, &mut writer).await?;
                }
                Ok(())
            }
            GattResponse::ReadData(rsp) => {
                writer.write_all(&[rsp.att_response]).await?;
                writer.write_all(&(rsp.data.len() as u16).to_le_bytes()).await?;
                writer.write_all(&rsp.data).await
            }
            GattResponse::ReadUuidData(rsp) => {
                writer.write_all(&[rsp.att_response]).await?;
                writer.write_all(&[rsp.values.len() as u8]).await?;
                for val in &rsp.values {
                    writer.write_all(&val.handle.to_le_bytes()).await?;
                    writer.write_all(&[val.data.len() as u8]).await?;
                    writer.write_all(&val.data).await?;
                }
                Ok(())
            }
            GattResponse::WriteResult(att_response) => writer.write_all(&[*att_response]).await,
            GattResponse::WriteWithoutRspDone => Ok(()),
            GattResponse::CfgDone => Ok(()),
            GattResponse::Attrs(attrs) => {
                writer.write_all(&[attrs.len() as u8]).await?;
                for attr in attrs {
                    writer.write_all(&attr.handle.to_le_bytes()).await?;
                    writer.write_all(&[attr.permission.bits()]).await?;
                    write_uuid(&attr.type_uuid, &mut writer).await?;
                }
                Ok(())
            }
            GattResponse::AttrValue(rsp) => {
                writer.write_all(&[rsp.att_response]).await?;
                writer.write_all(&(rsp.value.len() as u16).to_le_bytes()).await?;
                writer.write_all(&rsp.value).await
            }
        }
    }
}

// === GattEvent structs ===

#[derive(Debug, Clone)]
pub struct NotificationReceivedEvent<'a> {
    pub addr_type: AddrKind,
    pub address: BdAddr,
    pub notification_type: NotificationType,
    pub handle: u16,
    pub data: &'a [u8],
}

#[cfg(feature = "defmt")]
impl defmt::Format for NotificationReceivedEvent<'_> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(
            f,
            "NotificationReceivedEvent {{ addr_type: {}, handle: {=u16:#x}, data_len: {=usize} }}",
            self.addr_type,
            self.handle,
            self.data.len()
        )
    }
}

#[derive(Debug, Clone)]
pub struct AttrValueChangedEvent<'a> {
    pub attr_id: u16,
    pub data: &'a [u8],
}

#[cfg(feature = "defmt")]
impl defmt::Format for AttrValueChangedEvent<'_> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(
            f,
            "AttrValueChangedEvent {{ attr_id: {=u16:#x}, data_len: {=usize} }}",
            self.attr_id,
            self.data.len()
        )
    }
}

/// GATT service event.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum GattEvent<'a> {
    /// Notification/Indication received (0x80).
    NotificationReceived(NotificationReceivedEvent<'a>),

    /// Attribute value changed (0x81).
    AttrValueChanged(AttrValueChangedEvent<'a>),
}

impl GattEvent<'_> {
    /// Get the header for this event.
    pub fn header(&self) -> BtpHeader {
        match self {
            GattEvent::NotificationReceived(evt) => {
                // 1 addr_type + 6 address + 1 type + 2 handle + 2 data_len + data
                let data_len = 1 + 6 + 1 + 2 + 2 + evt.data.len() as u16;
                BtpHeader::event(ServiceId::GATT, opcodes::EVENT_NOTIFICATION_RECEIVED, Some(0), data_len)
            }
            GattEvent::AttrValueChanged(evt) => {
                // 2 attr_id + 2 data_len + data
                let data_len = 2 + 2 + evt.data.len() as u16;
                BtpHeader::event(ServiceId::GATT, opcodes::EVENT_ATTR_VALUE_CHANGED, Some(0), data_len)
            }
        }
    }

    /// Write the event data.
    pub async fn write<W: Write>(&self, mut writer: W) -> Result<(), W::Error> {
        match self {
            GattEvent::NotificationReceived(evt) => {
                writer.write_all(&[evt.addr_type.as_raw()]).await?;
                writer.write_all(evt.address.raw()).await?;
                writer.write_all(&[evt.notification_type as u8]).await?;
                writer.write_all(&evt.handle.to_le_bytes()).await?;
                writer.write_all(&(evt.data.len() as u16).to_le_bytes()).await?;
                writer.write_all(evt.data).await
            }
            GattEvent::AttrValueChanged(evt) => {
                writer.write_all(&evt.attr_id.to_le_bytes()).await?;
                writer.write_all(&(evt.data.len() as u16).to_le_bytes()).await?;
                writer.write_all(evt.data).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btp::types::Opcode;

    fn make_header(opcode: Opcode, controller_index: Option<u8>, data_len: u16) -> BtpHeader {
        BtpHeader::new(ServiceId::GATT, opcode, controller_index, data_len)
    }

    #[test]
    fn test_read_uuid16() {
        let data: &[u8] = &[2, 0x0F, 0x18]; // 0x180F = Battery Service
        let mut cursor = Cursor::new(data);
        let uuid = parse_uuid(&mut cursor).unwrap();
        if let Uuid::Uuid16(val) = uuid {
            assert_eq!(u16::from_le_bytes(val), 0x180F);
        } else {
            panic!("Expected Uuid16");
        }
    }

    #[test]
    fn test_read_set_value() {
        // attr_id=0x0010, value_len=3, value=[1,2,3]
        let data: &[u8] = &[0x10, 0x00, 0x03, 0x00, 0x01, 0x02, 0x03];
        let header = make_header(opcodes::SET_VALUE, Some(0), 7);
        let mut cursor = Cursor::new(data);
        let cmd = GattCommand::parse(&header, &mut cursor).unwrap();
        if let GattCommand::SetValue(cmd) = cmd {
            assert_eq!(cmd.attr_id, 0x0010);
            assert_eq!(cmd.value, &[0x01, 0x02, 0x03]);
        } else {
            panic!("Expected SetValue");
        }
    }

    #[test]
    fn test_att_permission() {
        let perm = AttPermission::READ | AttPermission::WRITE;
        assert!(perm.contains(AttPermission::READ));
        assert!(perm.contains(AttPermission::WRITE));
        assert!(!perm.contains(AttPermission::READ_ENC));
    }

    #[test]
    fn test_write_supported_commands() {
        use futures_executor::block_on;
        let resp = GattResponse::SupportedCommands([0x7E, 0x00, 0x00, 0x00, 0x00]);
        let mut buf = [0u8; 16];
        block_on(resp.write(&mut buf.as_mut_slice())).unwrap();
        assert_eq!(&buf[..5], &[0x7E, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_read_add_included_service() {
        let data: &[u8] = &[0x01, 0x00]; // service_id = 1
        let header = make_header(opcodes::ADD_INCLUDED_SERVICE, Some(0), 2);
        let mut cursor = Cursor::new(data);
        let cmd = GattCommand::parse(&header, &mut cursor).unwrap();
        if let GattCommand::AddIncludedService(service_id) = cmd {
            assert_eq!(service_id, 1);
        } else {
            panic!("Expected AddIncludedService");
        }
    }

    #[test]
    fn test_read_exchange_mtu() {
        // addr_type=0, address=[1,2,3,4,5,6]
        let data: &[u8] = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let header = make_header(opcodes::EXCHANGE_MTU, Some(0), 7);
        let mut cursor = Cursor::new(data);
        let cmd = GattCommand::parse(&header, &mut cursor).unwrap();
        if let GattCommand::ExchangeMtu(cmd) = cmd {
            assert_eq!(cmd.addr_type, AddrKind::PUBLIC);
            assert_eq!(cmd.address.raw(), &[1, 2, 3, 4, 5, 6]);
        } else {
            panic!("Expected ExchangeMtu");
        }
    }

    #[test]
    fn test_read_discover_all_chrc() {
        // addr_type=0, address=[1,2,3,4,5,6], start=0x0001, end=0xFFFF
        let data: &[u8] = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x00, 0xFF, 0xFF];
        let header = make_header(opcodes::DISCOVER_ALL_CHRC, Some(0), 11);
        let mut cursor = Cursor::new(data);
        let cmd = GattCommand::parse(&header, &mut cursor).unwrap();
        if let GattCommand::DiscoverAllChrc(DiscoverAllChrcCommand {
            addr_type,
            address,
            start_handle,
            end_handle,
        }) = cmd
        {
            assert_eq!(addr_type, AddrKind::PUBLIC);
            assert_eq!(address.raw(), &[1, 2, 3, 4, 5, 6]);
            assert_eq!(start_handle, 0x0001);
            assert_eq!(end_handle, 0xFFFF);
        } else {
            panic!("Expected DiscoverAllChrc");
        }
    }

    #[test]
    fn test_read_read_long() {
        // addr_type=0, address=[1,2,3,4,5,6], handle=0x0010, offset=0x0020
        let data: &[u8] = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x10, 0x00, 0x20, 0x00];
        let header = make_header(opcodes::READ_LONG, Some(0), 11);
        let mut cursor = Cursor::new(data);
        let cmd = GattCommand::parse(&header, &mut cursor).unwrap();
        if let GattCommand::ReadLong(ReadLongCommand {
            addr_type,
            address,
            handle,
            offset,
        }) = cmd
        {
            assert_eq!(addr_type, AddrKind::PUBLIC);
            assert_eq!(address.raw(), &[1, 2, 3, 4, 5, 6]);
            assert_eq!(handle, 0x0010);
            assert_eq!(offset, 0x0020);
        } else {
            panic!("Expected ReadLong");
        }
    }

    #[test]
    fn test_read_read_multiple() {
        // addr_type=0, address=[1,2,3,4,5,6], count=2, handles=[0x0010, 0x0020]
        let data: &[u8] = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x02, 0x10, 0x00, 0x20, 0x00];
        let header = make_header(opcodes::READ_MULTIPLE, Some(0), 12);
        let mut cursor = Cursor::new(data);
        let cmd = GattCommand::parse(&header, &mut cursor).unwrap();
        if let GattCommand::ReadMultiple(cmd) = cmd {
            assert_eq!(cmd.addr_type, AddrKind::PUBLIC);
            assert_eq!(cmd.address.raw(), &[1, 2, 3, 4, 5, 6]);
            let handles: heapless::Vec<u16, 32> = cmd.handles().collect();
            assert_eq!(handles.as_slice(), &[0x0010, 0x0020]);
        } else {
            panic!("Expected ReadMultiple");
        }
    }

    #[test]
    fn test_read_write_cmd() {
        // addr_type=0, address=[1,2,3,4,5,6], handle=0x0010, data_len=3, data=[0xAA,0xBB,0xCC]
        let data: &[u8] = &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x10, 0x00, 0x03, 0x00, 0xAA, 0xBB, 0xCC,
        ];
        let header = make_header(opcodes::WRITE, Some(0), 14);
        let mut cursor = Cursor::new(data);
        let cmd = GattCommand::parse(&header, &mut cursor).unwrap();
        if let GattCommand::Write(cmd) = cmd {
            assert_eq!(cmd.addr_type, AddrKind::PUBLIC);
            assert_eq!(cmd.address.raw(), &[1, 2, 3, 4, 5, 6]);
            assert_eq!(cmd.handle, 0x0010);
            assert_eq!(cmd.data, &[0xAA, 0xBB, 0xCC]);
        } else {
            panic!("Expected Write");
        }
    }

    #[test]
    fn test_read_cfg_notify() {
        // addr_type=0, address=[1,2,3,4,5,6], enable=1, ccc_handle=0x0012
        let data: &[u8] = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x12, 0x00];
        let header = make_header(opcodes::CFG_NOTIFY, Some(0), 10);
        let mut cursor = Cursor::new(data);
        let cmd = GattCommand::parse(&header, &mut cursor).unwrap();
        if let GattCommand::CfgNotify(CfgNotifyCommand {
            addr_type,
            address,
            enable,
            ccc_handle,
        }) = cmd
        {
            assert_eq!(addr_type, AddrKind::PUBLIC);
            assert_eq!(address.raw(), &[1, 2, 3, 4, 5, 6]);
            assert!(enable);
            assert_eq!(ccc_handle, 0x0012);
        } else {
            panic!("Expected CfgNotify");
        }
    }

    #[test]
    fn test_write_server_started() {
        use futures_executor::block_on;
        let resp = GattResponse::ServerStarted(ServerStartedResponse {
            db_attr_offset: 0x0010,
            db_attr_count: 5,
        });
        assert_eq!(resp.data_len(), 3);
        let mut buf = [0u8; 16];
        block_on(resp.write(&mut buf.as_mut_slice())).unwrap();
        assert_eq!(&buf[..3], &[0x10, 0x00, 0x05]);
    }

    #[test]
    fn test_write_read_data() {
        use futures_executor::block_on;
        let resp = GattResponse::ReadData(ReadDataResponse {
            att_response: 0x00,
            data: Box::from([0x01u8, 0x02, 0x03].as_slice()),
        });
        assert_eq!(resp.data_len(), 6); // 1 + 2 + 3
        let mut buf = [0u8; 16];
        block_on(resp.write(&mut buf.as_mut_slice())).unwrap();
        assert_eq!(&buf[..6], &[0x00, 0x03, 0x00, 0x01, 0x02, 0x03]);
    }

    // --- UUID parsing tests ---

    #[test]
    fn test_read_uuid128() {
        let uuid_bytes: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ];
        let mut data = alloc::vec![16u8]; // length prefix
        data.extend_from_slice(&uuid_bytes);
        let mut cursor = Cursor::new(&data);
        let uuid = parse_uuid(&mut cursor).unwrap();
        assert_eq!(uuid.as_raw(), &uuid_bytes);
        assert_eq!(cursor.remaining_len(), 0);
    }

    #[test]
    fn test_uuid_invalid_length() {
        let data: &[u8] = &[17]; // length 17 > 16
        let mut cursor = Cursor::new(data);
        let result = parse_uuid(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn test_uuid_truncated_data() {
        let data: &[u8] = &[4, 0x01, 0x02]; // says 4 bytes, only 2 available
        let mut cursor = Cursor::new(data);
        let result = parse_uuid(&mut cursor);
        assert!(result.is_err());
    }

    // --- AddService parsing ---

    #[test]
    fn test_read_add_service_primary() {
        // type=0x00 (Primary), uuid_len=2, uuid=0x180F
        let data: &[u8] = &[0x00, 0x02, 0x0F, 0x18];
        let header = make_header(opcodes::ADD_SERVICE, Some(0), 4);
        let mut cursor = Cursor::new(data);
        let cmd = GattCommand::parse(&header, &mut cursor).unwrap();
        if let GattCommand::AddService(AddServiceCommand { service_type, uuid }) = cmd {
            assert_eq!(service_type, ServiceType::Primary);
            if let Uuid::Uuid16(val) = uuid {
                assert_eq!(u16::from_le_bytes(val), 0x180F);
            } else {
                panic!("Expected Uuid16");
            }
        } else {
            panic!("Expected AddService");
        }
    }

    #[test]
    fn test_read_add_service_secondary() {
        let data: &[u8] = &[0x01, 0x02, 0x0F, 0x18];
        let header = make_header(opcodes::ADD_SERVICE, Some(0), 4);
        let mut cursor = Cursor::new(data);
        let cmd = GattCommand::parse(&header, &mut cursor).unwrap();
        assert!(matches!(
            cmd,
            GattCommand::AddService(AddServiceCommand {
                service_type: ServiceType::Secondary,
                ..
            })
        ));
    }

    #[test]
    fn test_read_add_service_invalid_type() {
        let data: &[u8] = &[0x02, 0x02, 0x0F, 0x18]; // type=0x02 is invalid
        let header = make_header(opcodes::ADD_SERVICE, Some(0), 4);
        let mut cursor = Cursor::new(data);
        let result = GattCommand::parse(&header, &mut cursor);
        assert!(result.is_err());
    }

    // --- AddCharacteristic parsing ---

    #[test]
    fn test_read_add_characteristic() {
        // service_id=0x0001, properties=0x02 (Read), permissions=0x01 (READ), uuid_len=2, uuid=0x2A19
        let data: &[u8] = &[0x01, 0x00, 0x02, 0x01, 0x02, 0x19, 0x2A];
        let header = make_header(opcodes::ADD_CHARACTERISTIC, Some(0), 7);
        let mut cursor = Cursor::new(data);
        let cmd = GattCommand::parse(&header, &mut cursor).unwrap();
        if let GattCommand::AddCharacteristic(AddCharacteristicCommand {
            service_id,
            properties,
            uuid,
            ..
        }) = cmd
        {
            assert_eq!(service_id, 1);
            assert_eq!(properties, 0x02);
            if let Uuid::Uuid16(val) = uuid {
                assert_eq!(u16::from_le_bytes(val), 0x2A19);
            } else {
                panic!("Expected Uuid16");
            }
        } else {
            panic!("Expected AddCharacteristic");
        }
    }

    // --- AddDescriptor parsing ---

    #[test]
    fn test_read_add_descriptor() {
        // char_id=0x0003, permissions=0x01 (READ), uuid_len=2, uuid=0x2902 (CCCD)
        let data: &[u8] = &[0x03, 0x00, 0x01, 0x02, 0x02, 0x29];
        let header = make_header(opcodes::ADD_DESCRIPTOR, Some(0), 6);
        let mut cursor = Cursor::new(data);
        let cmd = GattCommand::parse(&header, &mut cursor).unwrap();
        if let GattCommand::AddDescriptor(AddDescriptorCommand { char_id, uuid, .. }) = cmd {
            assert_eq!(char_id, 3);
            if let Uuid::Uuid16(val) = uuid {
                assert_eq!(u16::from_le_bytes(val), 0x2902);
            } else {
                panic!("Expected Uuid16");
            }
        } else {
            panic!("Expected AddDescriptor");
        }
    }

    // --- DiscoverPrimaryUuid parsing ---

    #[test]
    fn test_read_discover_primary_uuid() {
        // addr_type=0, address=[1..6], uuid_len=2, uuid=0x180F
        let data: &[u8] = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x02, 0x0F, 0x18];
        let header = make_header(opcodes::DISCOVER_PRIMARY_UUID, Some(0), 10);
        let mut cursor = Cursor::new(data);
        let cmd = GattCommand::parse(&header, &mut cursor).unwrap();
        if let GattCommand::DiscoverPrimaryUuid(cmd) = cmd {
            assert_eq!(cmd.addr_type, AddrKind::PUBLIC);
            if let Uuid::Uuid16(val) = cmd.uuid {
                assert_eq!(u16::from_le_bytes(val), 0x180F);
            } else {
                panic!("Expected Uuid16");
            }
        } else {
            panic!("Expected DiscoverPrimaryUuid");
        }
    }

    // --- DiscoverChrcUuid parsing ---

    #[test]
    fn test_read_discover_chrc_uuid() {
        // addr_type=0, address=[1..6], start=0x0001, end=0xFFFF, uuid_len=2, uuid=0x2A19
        let data: &[u8] = &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x00, 0xFF, 0xFF, 0x02, 0x19, 0x2A,
        ];
        let header = make_header(opcodes::DISCOVER_CHRC_UUID, Some(0), 14);
        let mut cursor = Cursor::new(data);
        let cmd = GattCommand::parse(&header, &mut cursor).unwrap();
        if let GattCommand::DiscoverChrcUuid(cmd) = cmd {
            assert_eq!(cmd.start_handle, 0x0001);
            assert_eq!(cmd.end_handle, 0xFFFF);
        } else {
            panic!("Expected DiscoverChrcUuid");
        }
    }

    // --- CfgIndicate parsing ---

    #[test]
    fn test_read_cfg_indicate() {
        let data: &[u8] = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x14, 0x00];
        let header = make_header(opcodes::CFG_INDICATE, Some(0), 10);
        let mut cursor = Cursor::new(data);
        let cmd = GattCommand::parse(&header, &mut cursor).unwrap();
        if let GattCommand::CfgIndicate(CfgIndicateCommand { enable, ccc_handle, .. }) = cmd {
            assert!(enable);
            assert_eq!(ccc_handle, 0x0014);
        } else {
            panic!("Expected CfgIndicate");
        }
    }

    // --- GetAttrs parsing ---

    #[test]
    fn test_read_get_attrs_without_uuid() {
        let data: &[u8] = &[0x01, 0x00, 0xFF, 0xFF, 0x00]; // start=1, end=0xFFFF, type_len=0
        let header = make_header(opcodes::GET_ATTRS, Some(0), 5);
        let mut cursor = Cursor::new(data);
        let cmd = GattCommand::parse(&header, &mut cursor).unwrap();
        if let GattCommand::GetAttrs(GetAttrsCommand {
            start_handle,
            end_handle,
            type_uuid,
        }) = cmd
        {
            assert_eq!(start_handle, 1);
            assert_eq!(end_handle, 0xFFFF);
            assert!(type_uuid.is_none());
        } else {
            panic!("Expected GetAttrs");
        }
    }

    #[test]
    fn test_read_get_attrs_with_uuid() {
        let data: &[u8] = &[0x01, 0x00, 0xFF, 0xFF, 0x02, 0x03, 0x28]; // uuid=0x2803
        let header = make_header(opcodes::GET_ATTRS, Some(0), 7);
        let mut cursor = Cursor::new(data);
        let cmd = GattCommand::parse(&header, &mut cursor).unwrap();
        if let GattCommand::GetAttrs(GetAttrsCommand { type_uuid, .. }) = cmd {
            let uuid = type_uuid.unwrap();
            if let Uuid::Uuid16(val) = uuid {
                assert_eq!(u16::from_le_bytes(val), 0x2803);
            } else {
                panic!("Expected Uuid16");
            }
        } else {
            panic!("Expected GetAttrs");
        }
    }

    // --- Controller index validation ---

    #[test]
    fn test_gatt_invalid_controller_index() {
        let data: &[u8] = &[0x00, 0x02, 0x0F, 0x18];
        let header = make_header(opcodes::ADD_SERVICE, Some(1), 4); // index 1
        let mut cursor = Cursor::new(data);
        let result = GattCommand::parse(&header, &mut cursor);
        assert!(matches!(result, Err(crate::btp::error::Error::InvalidIndex)));
    }

    #[test]
    fn test_gatt_supported_commands_no_index_needed() {
        let header = make_header(opcodes::READ_SUPPORTED_COMMANDS, None, 0);
        let mut cursor = Cursor::new(&[]);
        let cmd = GattCommand::parse(&header, &mut cursor).unwrap();
        assert!(matches!(cmd, GattCommand::ReadSupportedCommands));
    }

    // --- Unknown opcode ---

    #[test]
    fn test_gatt_unknown_opcode() {
        let header = make_header(Opcode(0x7F), Some(0), 0);
        let mut cursor = Cursor::new(&[]);
        let result = GattCommand::parse(&header, &mut cursor);
        assert!(matches!(result, Err(crate::btp::error::Error::UnknownCommand { .. })));
    }

    // --- Malformed input tests ---

    #[test]
    fn test_add_service_truncated() {
        let data: &[u8] = &[0x00]; // service type but no UUID
        let header = make_header(opcodes::ADD_SERVICE, Some(0), 1);
        let mut cursor = Cursor::new(data);
        let result = GattCommand::parse(&header, &mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_value_truncated() {
        let data: &[u8] = &[0x10, 0x00, 0x05, 0x00, 0x01]; // says 5 bytes, only 1
        let header = make_header(opcodes::SET_VALUE, Some(0), 5);
        let mut cursor = Cursor::new(data);
        let result = GattCommand::parse(&header, &mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn test_write_cmd_truncated() {
        // addr + handle + data_len=3 but only 1 byte of data
        let data: &[u8] = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x10, 0x00, 0x03, 0x00, 0xAA];
        let header = make_header(opcodes::WRITE, Some(0), 12);
        let mut cursor = Cursor::new(data);
        let result = GattCommand::parse(&header, &mut cursor);
        assert!(result.is_err());
    }

    // --- Event serialization tests ---

    #[test]
    fn test_write_notification_received_event() {
        use futures_executor::block_on;
        let evt = GattEvent::NotificationReceived(NotificationReceivedEvent {
            addr_type: AddrKind::PUBLIC,
            address: BdAddr::new([1, 2, 3, 4, 5, 6]),
            notification_type: NotificationType::Notification,
            handle: 0x0010,
            data: &[0xAA, 0xBB],
        });
        let header = evt.header();
        assert_eq!(header.service_id, ServiceId::GATT);
        assert_eq!(header.opcode, opcodes::EVENT_NOTIFICATION_RECEIVED);
        assert_eq!(header.data_len, 1 + 6 + 1 + 2 + 2 + 2); // 14
        let mut buf = [0u8; 20];
        block_on(evt.write(&mut buf.as_mut_slice())).unwrap();
        assert_eq!(buf[0], 0x00); // PUBLIC
        assert_eq!(buf[7], NotificationType::Notification as u8);
        assert_eq!(u16::from_le_bytes([buf[8], buf[9]]), 0x0010);
        assert_eq!(u16::from_le_bytes([buf[10], buf[11]]), 2);
        assert_eq!(&buf[12..14], &[0xAA, 0xBB]);
    }

    #[test]
    fn test_write_indication_received_event() {
        use futures_executor::block_on;
        let evt = GattEvent::NotificationReceived(NotificationReceivedEvent {
            addr_type: AddrKind::RANDOM,
            address: BdAddr::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
            notification_type: NotificationType::Indication,
            handle: 0x0020,
            data: &[],
        });
        let header = evt.header();
        assert_eq!(header.data_len, 1 + 6 + 1 + 2 + 2); // 12, no data
        let mut buf = [0u8; 16];
        block_on(evt.write(&mut buf.as_mut_slice())).unwrap();
        assert_eq!(buf[7], NotificationType::Indication as u8);
    }

    #[test]
    fn test_write_attr_value_changed_event() {
        use futures_executor::block_on;
        let evt = GattEvent::AttrValueChanged(AttrValueChangedEvent {
            attr_id: 0x0005,
            data: &[0x01, 0x02, 0x03],
        });
        let header = evt.header();
        assert_eq!(header.service_id, ServiceId::GATT);
        assert_eq!(header.opcode, opcodes::EVENT_ATTR_VALUE_CHANGED);
        assert_eq!(header.data_len, 2 + 2 + 3); // 7
        let mut buf = [0u8; 16];
        block_on(evt.write(&mut buf.as_mut_slice())).unwrap();
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 0x0005);
        assert_eq!(u16::from_le_bytes([buf[2], buf[3]]), 3);
        assert_eq!(&buf[4..7], &[0x01, 0x02, 0x03]);
    }

    // --- Response serialization tests ---

    #[test]
    fn test_write_service_added_response() {
        use futures_executor::block_on;
        let resp = GattResponse::ServiceAdded(0x0001);
        assert_eq!(resp.data_len(), 2);
        let mut buf = [0u8; 4];
        block_on(resp.write(&mut buf.as_mut_slice())).unwrap();
        assert_eq!(&buf[..2], &[0x01, 0x00]);
    }

    #[test]
    fn test_write_characteristic_added_response() {
        use futures_executor::block_on;
        let resp = GattResponse::CharacteristicAdded(0x0003);
        assert_eq!(resp.data_len(), 2);
        let mut buf = [0u8; 4];
        block_on(resp.write(&mut buf.as_mut_slice())).unwrap();
        assert_eq!(&buf[..2], &[0x03, 0x00]);
    }

    #[test]
    fn test_write_descriptor_added_response() {
        use futures_executor::block_on;
        let resp = GattResponse::DescriptorAdded(0x0005);
        assert_eq!(resp.data_len(), 2);
        let mut buf = [0u8; 4];
        block_on(resp.write(&mut buf.as_mut_slice())).unwrap();
        assert_eq!(&buf[..2], &[0x05, 0x00]);
    }

    #[test]
    fn test_write_value_set_response() {
        use futures_executor::block_on;
        let resp = GattResponse::ValueSet;
        assert_eq!(resp.data_len(), 0);
        let mut buf = [0u8; 4];
        block_on(resp.write(&mut buf.as_mut_slice())).unwrap();
    }

    #[test]
    fn test_write_mtu_exchanged_response() {
        use futures_executor::block_on;
        let resp = GattResponse::MtuExchanged;
        assert_eq!(resp.data_len(), 0);
        let mut buf = [0u8; 4];
        block_on(resp.write(&mut buf.as_mut_slice())).unwrap();
    }

    #[test]
    fn test_write_write_result_response() {
        use futures_executor::block_on;
        let resp = GattResponse::WriteResult(0x00);
        assert_eq!(resp.data_len(), 1);
        let mut buf = [0u8; 4];
        block_on(resp.write(&mut buf.as_mut_slice())).unwrap();
        assert_eq!(buf[0], 0x00);
    }

    #[test]
    fn test_write_cfg_done_response() {
        use futures_executor::block_on;
        let resp = GattResponse::CfgDone;
        assert_eq!(resp.data_len(), 0);
        let mut buf = [0u8; 4];
        block_on(resp.write(&mut buf.as_mut_slice())).unwrap();
    }

    #[test]
    fn test_write_services_response() {
        use futures_executor::block_on;
        let services = alloc::vec![ServiceInfo {
            start_handle: 0x0001,
            end_handle: 0x0005,
            uuid: Uuid::Uuid16(0x180Fu16.to_le_bytes()),
        }];
        let resp = GattResponse::Services(services.into_boxed_slice());
        // 1 (count) + 1*(2+2+1+2) = 8
        assert_eq!(resp.data_len(), 8);
        let mut buf = [0u8; 16];
        block_on(resp.write(&mut buf.as_mut_slice())).unwrap();
        assert_eq!(buf[0], 1); // count
        assert_eq!(u16::from_le_bytes([buf[1], buf[2]]), 0x0001);
        assert_eq!(u16::from_le_bytes([buf[3], buf[4]]), 0x0005);
        assert_eq!(buf[5], 2); // uuid len
        assert_eq!(u16::from_le_bytes([buf[6], buf[7]]), 0x180F);
    }

    #[test]
    fn test_write_characteristics_response() {
        use futures_executor::block_on;
        let chrcs = alloc::vec![CharacteristicInfo {
            char_handle: 0x0002,
            value_handle: 0x0003,
            properties: 0x02,
            uuid: Uuid::Uuid16(0x2A19u16.to_le_bytes()),
        }];
        let resp = GattResponse::Characteristics(chrcs.into_boxed_slice());
        // 1 (count) + 1*(2 char_handle + 2 value_handle + 1 properties + 1 uuid_len + 2 uuid16) = 9
        assert_eq!(resp.data_len(), 9);
        let mut buf = [0u8; 16];
        block_on(resp.write(&mut buf.as_mut_slice())).unwrap();
        assert_eq!(buf[0], 1);
        assert_eq!(u16::from_le_bytes([buf[1], buf[2]]), 0x0002);
        assert_eq!(u16::from_le_bytes([buf[3], buf[4]]), 0x0003);
        assert_eq!(buf[5], 0x02); // properties
    }
}

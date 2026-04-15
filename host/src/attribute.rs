//! Attribute protocol implementation.
use core::cell::RefCell;
use core::fmt;
use core::marker::PhantomData;

use bt_hci::uuid::declarations::{CHARACTERISTIC, INCLUDE, PRIMARY_SERVICE, SECONDARY_SERVICE};
use bt_hci::uuid::descriptors::CLIENT_CHARACTERISTIC_CONFIGURATION;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::blocking_mutex::Mutex;
use heapless::Vec;

use crate::att::{AttErrorCode, AttUns};
use crate::attribute_server::AttributeServer;
use crate::cursor::{ReadCursor, WriteCursor};
use crate::prelude::{AsGatt, FixedGattValue, FromGatt, GattConnection, SecurityLevel};
use crate::types::gatt_traits::FromGattError;
pub use crate::types::uuid::Uuid;
use crate::{gatt, Error, PacketPool, MAX_INVALID_DATA_LEN};

/// The maximum size in bytes of an attribute using inline small data storage.
pub const MAX_SMALL_DATA_SIZE: usize = 20;

/// Characteristic properties
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum CharacteristicProp {
    /// Broadcast
    Broadcast = 0x01,
    /// Read
    Read = 0x02,
    /// Write without response
    WriteWithoutResponse = 0x04,
    /// Write
    Write = 0x08,
    /// Notify
    Notify = 0x10,
    /// Indicate
    Indicate = 0x20,
    /// Authenticated writes
    AuthenticatedWrite = 0x40,
    /// Extended properties
    Extended = 0x80,
}

/// Attribute permissions
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PermissionLevel {
    #[default]
    /// Operation is allowed with no encryption or authentication
    Allowed,
    /// Encryption is required
    EncryptionRequired,
    /// Encryption and authentication are required
    AuthenticationRequired,
    /// Operation is not allowed
    NotAllowed,
}

/// Attribute permissions
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AttPermissions {
    /// Security required for read operations
    pub read: PermissionLevel,
    /// Security required for write operations
    pub write: PermissionLevel,
    /// Minimum encryption key length required (0 = no minimum)
    #[cfg(feature = "legacy-pairing")]
    pub min_key_len: u8,
}

impl AttPermissions {
    pub(crate) fn read_only() -> Self {
        Self {
            read: PermissionLevel::Allowed,
            write: PermissionLevel::NotAllowed,
            #[cfg(feature = "legacy-pairing")]
            min_key_len: 0,
        }
    }

    pub(crate) fn can_read(
        &self,
        level: SecurityLevel,
        #[cfg(feature = "legacy-pairing")] encryption_key_len: u8,
    ) -> Result<(), AttErrorCode> {
        match self.read {
            PermissionLevel::NotAllowed => Err(AttErrorCode::READ_NOT_PERMITTED),
            PermissionLevel::EncryptionRequired | PermissionLevel::AuthenticationRequired
                if level < SecurityLevel::Encrypted =>
            {
                Err(AttErrorCode::INSUFFICIENT_AUTHENTICATION)
            }
            PermissionLevel::AuthenticationRequired if level < SecurityLevel::EncryptedAuthenticated => {
                Err(AttErrorCode::INSUFFICIENT_AUTHENTICATION)
            }
            _ => {
                #[cfg(feature = "legacy-pairing")]
                if self.min_key_len > 0 && level.encrypted() && encryption_key_len < self.min_key_len {
                    return Err(AttErrorCode::INSUFFICIENT_ENCRYPTION_KEY_SIZE);
                }
                Ok(())
            }
        }
    }

    pub(crate) fn can_write(
        &self,
        level: SecurityLevel,
        #[cfg(feature = "legacy-pairing")] encryption_key_len: u8,
    ) -> Result<(), AttErrorCode> {
        match self.write {
            PermissionLevel::NotAllowed => Err(AttErrorCode::WRITE_NOT_PERMITTED),
            PermissionLevel::EncryptionRequired | PermissionLevel::AuthenticationRequired
                if level < SecurityLevel::Encrypted =>
            {
                Err(AttErrorCode::INSUFFICIENT_AUTHENTICATION)
            }
            PermissionLevel::AuthenticationRequired if level < SecurityLevel::EncryptedAuthenticated => {
                Err(AttErrorCode::INSUFFICIENT_AUTHENTICATION)
            }
            _ => {
                #[cfg(feature = "legacy-pairing")]
                if self.min_key_len > 0 && level.encrypted() && encryption_key_len < self.min_key_len {
                    return Err(AttErrorCode::INSUFFICIENT_ENCRYPTION_KEY_SIZE);
                }
                Ok(())
            }
        }
    }
}

/// A GATT characteristic declaration value.
pub(crate) struct CharacteristicDeclaration {
    pub props: CharacteristicProps,
    pub value_handle: u16,
    pub uuid: Uuid,
}

impl CharacteristicDeclaration {
    pub(crate) fn new<U: Into<Uuid>, P: Into<CharacteristicProps>>(props: P, value_handle: u16, uuid: U) -> Self {
        Self {
            props: props.into(),
            value_handle,
            uuid: uuid.into(),
        }
    }
}

impl TryFrom<&[u8]> for CharacteristicDeclaration {
    type Error = Error;

    fn try_from(data: &'_ [u8]) -> Result<Self, Self::Error> {
        let mut r = ReadCursor::new(data);
        Ok(CharacteristicDeclaration {
            props: CharacteristicProps(r.read()?),
            value_handle: r.read()?,
            uuid: Uuid::try_from(r.remaining())?,
        })
    }
}

/// Attribute metadata.
pub struct Attribute<'a> {
    pub(crate) uuid: Uuid,
    pub(crate) permissions: AttPermissions,
    pub(crate) data: AttributeData<'a>,
}

impl<'a> Attribute<'a> {
    const EMPTY: Option<Attribute<'a>> = None;

    pub(crate) fn read(&self, offset: usize, data: &mut [u8]) -> Result<usize, AttErrorCode> {
        self.data.read(offset, data)
    }

    pub(crate) fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), AttErrorCode> {
        self.data.write(offset, data)
    }

    pub(crate) fn permissions(&self) -> AttPermissions {
        self.permissions
    }

    pub(crate) fn readable(&self) -> bool {
        self.permissions.read != PermissionLevel::NotAllowed
    }

    pub(crate) fn writable(&self) -> bool {
        self.permissions.write != PermissionLevel::NotAllowed
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AttributeData<'d> {
    ReadOnlyData {
        value: &'d [u8],
    },
    Data {
        variable_len: bool,
        len: u16,
        value: &'d mut [u8],
    },
    SmallData {
        variable_len: bool,
        capacity: u8,
        len: u8,
        value: [u8; MAX_SMALL_DATA_SIZE],
    },
    ClientSpecific(u16),
}

impl From<Uuid> for AttributeData<'_> {
    fn from(uuid: Uuid) -> Self {
        let raw = uuid.as_raw();
        let len = raw.len() as u8;
        let mut value = [0u8; MAX_SMALL_DATA_SIZE];
        value[..raw.len()].copy_from_slice(raw);
        AttributeData::SmallData {
            variable_len: false,
            capacity: len,
            len,
            value,
        }
    }
}

impl From<bt_hci::uuid::BluetoothUuid16> for AttributeData<'_> {
    fn from(uuid: bt_hci::uuid::BluetoothUuid16) -> Self {
        let raw = uuid.to_le_bytes();
        let len = raw.len() as u8;
        let mut value = [0u8; MAX_SMALL_DATA_SIZE];
        value[..raw.len()].copy_from_slice(&raw);
        AttributeData::SmallData {
            variable_len: false,
            capacity: len,
            len,
            value,
        }
    }
}

impl From<bt_hci::uuid::BluetoothUuid128> for AttributeData<'_> {
    fn from(uuid: bt_hci::uuid::BluetoothUuid128) -> Self {
        let raw = uuid.to_le_bytes();
        let len = raw.len() as u8;
        let mut value = [0u8; MAX_SMALL_DATA_SIZE];
        value[..raw.len()].copy_from_slice(&raw);
        AttributeData::SmallData {
            variable_len: false,
            capacity: len,
            len,
            value,
        }
    }
}

impl From<CharacteristicDeclaration> for AttributeData<'_> {
    fn from(decl: CharacteristicDeclaration) -> Self {
        let uuid_raw = decl.uuid.as_raw();
        let total_len = 1 + 2 + uuid_raw.len(); // props + handle + uuid
        debug_assert!(total_len <= MAX_SMALL_DATA_SIZE);
        let mut value = [0u8; MAX_SMALL_DATA_SIZE];
        value[0] = decl.props.0;
        value[1..3].copy_from_slice(&decl.value_handle.to_le_bytes());
        value[3..3 + uuid_raw.len()].copy_from_slice(uuid_raw);
        let len = total_len as u8;
        AttributeData::SmallData {
            variable_len: false,
            capacity: len,
            len,
            value,
        }
    }
}

impl AttributeData<'_> {
    /// Get the byte value of the attribute data.
    pub(crate) fn value(&self) -> Option<&[u8]> {
        match self {
            AttributeData::ReadOnlyData { value } => Some(value),
            AttributeData::Data { len, value, .. } => Some(&value[..*len as usize]),
            AttributeData::SmallData { len, value, .. } => Some(&value[..*len as usize]),
            AttributeData::ClientSpecific(_) => None,
        }
    }

    fn read(&self, mut offset: usize, mut data: &mut [u8]) -> Result<usize, AttErrorCode> {
        fn append(src: &[u8], offset: &mut usize, dest: &mut &mut [u8]) -> usize {
            if *offset >= src.len() {
                *offset -= src.len();
                0
            } else {
                let d = core::mem::take(dest);
                let n = d.len().min(src.len() - *offset);
                d[..n].copy_from_slice(&src[*offset..][..n]);
                *dest = &mut d[n..];
                *offset = 0;
                n
            }
        }

        let written = match self {
            Self::ReadOnlyData { value } => append(value, &mut offset, &mut data),
            Self::Data { len, value, .. } => {
                let value = &value[..*len as usize];
                append(value, &mut offset, &mut data)
            }
            Self::SmallData { len, value, .. } => {
                let value = &value[..*len as usize];
                append(value, &mut offset, &mut data)
            }
            Self::ClientSpecific(_) => return Err(AttErrorCode::UNLIKELY_ERROR),
        };

        if offset > 0 {
            Err(AttErrorCode::INVALID_OFFSET)
        } else {
            Ok(written)
        }
    }

    fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), AttErrorCode> {
        match self {
            Self::Data {
                value,
                variable_len,
                len,
            } => {
                if offset > value.len() {
                    Err(AttErrorCode::INVALID_OFFSET)
                } else if offset + data.len() > value.len() {
                    Err(AttErrorCode::INVALID_ATTRIBUTE_VALUE_LENGTH)
                } else {
                    value[offset..offset + data.len()].copy_from_slice(data);
                    if *variable_len {
                        *len = (offset + data.len()) as u16;
                    }
                    Ok(())
                }
            }
            Self::SmallData {
                variable_len,
                capacity,
                len,
                value,
            } => {
                if offset > usize::from(*capacity) {
                    Err(AttErrorCode::INVALID_OFFSET)
                } else if offset + data.len() > usize::from(*capacity) {
                    Err(AttErrorCode::INVALID_ATTRIBUTE_VALUE_LENGTH)
                } else {
                    value[offset..offset + data.len()].copy_from_slice(data);
                    if *variable_len {
                        *len = (offset + data.len()) as u8;
                    }
                    Ok(())
                }
            }
            _ => Err(AttErrorCode::WRITE_NOT_PERMITTED),
        }
    }
}

impl fmt::Debug for Attribute<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Attribute")
            .field("uuid", &self.uuid)
            .field("readable", &self.readable())
            .field("writable", &self.writable())
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl<'a> defmt::Format for Attribute<'a> {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "{}", defmt::Debug2Format(self))
    }
}

impl<'a> Attribute<'a> {
    pub(crate) fn new<U: Into<Uuid>, T: Into<AttributeData<'a>>>(
        uuid: U,
        permissions: AttPermissions,
        data: T,
    ) -> Attribute<'a> {
        Attribute {
            uuid: uuid.into(),
            permissions,
            data: data.into(),
        }
    }
}

/// A table of attributes.
pub struct AttributeTable<'d, M: RawMutex, const MAX: usize> {
    inner: Mutex<M, RefCell<InnerTable<'d, MAX>>>,
}

pub(crate) struct InnerTable<'d, const MAX: usize> {
    attributes: Vec<Attribute<'d>, MAX>,
}

impl<'d, const MAX: usize> InnerTable<'d, MAX> {
    fn push(&mut self, attribute: Attribute<'d>) -> u16 {
        let handle = self.next_handle();
        self.attributes.push(attribute).unwrap();
        handle
    }

    fn iterate_from(&self, pos: usize) -> AttributeIterator<'_, 'd> {
        AttributeIterator {
            attributes: &self.attributes,
            pos,
        }
    }

    fn service_group_end(&self, service_handle: u16) -> u16 {
        self.iterate_from(usize::from(service_handle)).service_group_end()
    }

    fn next_handle(&self) -> u16 {
        self.attributes.len() as u16 + 1
    }
}

impl<M: RawMutex, const MAX: usize> Default for AttributeTable<'_, M, MAX> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'d, M: RawMutex, const MAX: usize> AttributeTable<'d, M, MAX> {
    /// Create a new GATT table.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(RefCell::new(InnerTable { attributes: Vec::new() })),
        }
    }

    pub(crate) fn with_inner<F: FnOnce(&InnerTable<'d, MAX>) -> R, R>(&self, f: F) -> R {
        self.inner.lock(|inner| {
            let table = inner.borrow();
            f(&table)
        })
    }

    pub(crate) fn with_inner_mut<F: FnOnce(&mut InnerTable<'d, MAX>) -> R, R>(&self, f: F) -> R {
        self.inner.lock(|inner| {
            let mut table = inner.borrow_mut();
            f(&mut table)
        })
    }

    pub(crate) fn iterate<F: FnOnce(AttributeIterator<'_, 'd>) -> R, R>(&self, f: F) -> R {
        self.with_inner(|table| f(table.iterate_from(0)))
    }

    pub(crate) fn with_attribute<F: FnOnce(&Attribute<'d>) -> R, R>(&self, handle: u16, f: F) -> Option<R> {
        if handle == 0 {
            return None;
        }

        self.with_inner(|table| {
            let i = usize::from(handle) - 1;
            table.attributes.get(i).map(f)
        })
    }

    pub(crate) fn with_attribute_mut<F: FnOnce(&mut Attribute<'d>) -> R, R>(&self, handle: u16, f: F) -> Option<R> {
        if handle == 0 {
            return None;
        }

        self.with_inner_mut(|table| {
            let i = usize::from(handle) - 1;
            table.attributes.get_mut(i).map(f)
        })
    }

    pub(crate) fn iterate_from<F: FnOnce(AttributeIterator<'_, 'd>) -> R, R>(&self, start: u16, f: F) -> R {
        let i = usize::from(start).saturating_sub(1);
        self.with_inner(|table| f(table.iterate_from(i)))
    }

    fn push(&mut self, attribute: Attribute<'d>) -> u16 {
        self.with_inner_mut(|table| table.push(attribute))
    }

    /// Add a service to the attribute table (group of characteristics)
    pub fn add_service(&mut self, service: Service) -> ServiceBuilder<'_, 'd, M, MAX> {
        let handle = self.push(Attribute::new(
            PRIMARY_SERVICE,
            AttPermissions::read_only(),
            service.uuid,
        ));
        ServiceBuilder { handle, table: self }
    }

    /// Add a service to the attribute table (group of characteristics)
    pub fn add_secondary_service(&mut self, service: Service) -> ServiceBuilder<'_, 'd, M, MAX> {
        let handle = self.push(Attribute::new(
            SECONDARY_SERVICE,
            AttPermissions::read_only(),
            service.uuid,
        ));
        ServiceBuilder { handle, table: self }
    }

    /// Get the permissions for the attribute
    ///
    /// Returns `None` if the attribute handle is invalid.
    pub fn permissions(&self, attribute: u16) -> Option<AttPermissions> {
        self.with_attribute(attribute, |att| att.permissions())
    }

    /// Get the UUID of the attribute type
    ///
    /// Returns `None` if the attribute handle is invalid.
    pub fn uuid(&self, attribute: u16) -> Option<Uuid> {
        self.with_attribute(attribute, |att| att.uuid)
    }

    pub(crate) fn set_ro(&self, attribute: u16, new_value: &'d [u8]) -> Result<(), Error> {
        self.with_attribute_mut(attribute, |att| match &mut att.data {
            AttributeData::ReadOnlyData { value, .. } => {
                *value = new_value;
                Ok(())
            }
            _ => Err(Error::NotSupported),
        })
        .unwrap_or(Err(Error::NotFound))
    }

    /// Read the raw value of the attribute
    ///
    /// If the attribute value is larger than the data buffer, data will be filled with
    /// as many bytes as fit. Use additional reads with an offset to read the remaining data.
    ///
    /// The value of the attribute is undefined for connection-specific attributes (like CCCD).
    pub fn read(&self, attribute: u16, offset: usize, data: &mut [u8]) -> Result<usize, Error> {
        self.with_attribute(attribute, |att| att.read(offset, data).map_err(Into::into))
            .unwrap_or(Err(Error::NotFound))
    }

    /// Write the raw value of the attribute
    ///
    /// If the attribute is variable length, its length will be set to `offset + data.len()`.
    /// If the attribute is fixed length, the range `offset..(offset + data.len())` will be
    /// overwritten.
    pub fn write(&self, attribute: u16, offset: usize, data: &[u8]) -> Result<(), Error> {
        self.with_attribute_mut(attribute, |att| att.write(offset, data).map_err(Into::into))
            .unwrap_or(Err(Error::NotFound))
    }

    pub(crate) fn set_raw(&self, attribute: u16, input: &[u8]) -> Result<(), Error> {
        self.with_attribute_mut(attribute, |att| match &mut att.data {
            AttributeData::Data {
                value,
                variable_len,
                len,
                ..
            } => {
                let expected_len = value.len();
                let actual_len = input.len();

                if *variable_len && actual_len <= expected_len {
                    value[..input.len()].copy_from_slice(input);
                    *len = input.len() as u16;
                    Ok(())
                } else if expected_len == actual_len {
                    value.copy_from_slice(input);
                    Ok(())
                } else {
                    Err(Error::UnexpectedDataLength {
                        expected: expected_len,
                        actual: actual_len,
                    })
                }
            }
            AttributeData::SmallData {
                variable_len,
                capacity,
                len,
                value,
                ..
            } => {
                let expected_len = usize::from(*capacity);
                let actual_len = input.len();

                if *variable_len && actual_len <= expected_len {
                    value[..input.len()].copy_from_slice(input);
                    *len = input.len() as u8;
                    Ok(())
                } else if expected_len == actual_len {
                    value[..expected_len].copy_from_slice(input);
                    Ok(())
                } else {
                    Err(Error::UnexpectedDataLength {
                        expected: expected_len,
                        actual: actual_len,
                    })
                }
            }
            _ => Err(Error::NotSupported),
        })
        .unwrap_or(Err(Error::NotFound))
    }

    /// Get the number of attributes in the table
    pub fn len(&self) -> usize {
        self.with_inner(|table| table.attributes.len())
    }

    /// Returns true if the table is empty
    pub fn is_empty(&self) -> bool {
        self.with_inner(|table| table.attributes.is_empty())
    }

    /// Set the value of a characteristic
    ///
    /// For fixed-length values, the provided data must exactly match the storage size.
    /// For variable-length values, any length up to the configured capacity is accepted.
    ///
    /// Returns an error if the characteristic cannot be found, if the input length is
    /// incompatible with the characteristic storage, or if the data shape does not
    /// match the characteristic type.
    pub fn set<T: AttributeHandle>(&self, attribute_handle: &T, input: &T::Value) -> Result<(), Error> {
        let gatt_value = input.as_gatt();
        self.set_raw(attribute_handle.handle(), gatt_value)
    }

    /// Read the value of the characteristic and pass the value to the provided closure.
    ///
    /// The return value of the closure is returned in this function and is assumed to be infallible.
    ///
    /// If the characteristic for the handle cannot be found, an error is returned.
    pub fn get<T: AttributeHandle<Value = V>, V: FromGatt>(&self, attribute_handle: &T) -> Result<T::Value, Error> {
        self.with_attribute(attribute_handle.handle(), |att| {
            let value_slice = att.data.value().ok_or(Error::NotSupported)?;
            T::Value::from_gatt(value_slice).map_err(|_| {
                let mut invalid_data = [0u8; MAX_INVALID_DATA_LEN];
                let len_to_copy = value_slice.len().min(MAX_INVALID_DATA_LEN);
                invalid_data[..len_to_copy].copy_from_slice(&value_slice[..len_to_copy]);

                Error::CannotConstructGattValue(invalid_data)
            })
        })
        .unwrap_or(Err(Error::NotFound))
    }

    /// Return the characteristic which corresponds to the supplied value handle
    ///
    /// If no characteristic corresponding to the given value handle was found, returns an error
    pub fn find_characteristic_by_value_handle<T: AsGatt>(&self, handle: u16) -> Result<Characteristic<T>, Error> {
        if handle == 0 {
            return Err(Error::NotFound);
        }

        self.iterate_from(handle - 1, |mut it| {
            if let Some((_, att)) = it.next() {
                if att.uuid == CHARACTERISTIC.into() {
                    let decl = CharacteristicDeclaration::try_from(att.data.value().unwrap())?;
                    let props = decl.props;
                    let uuid = decl.uuid;
                    if it.next().is_some() {
                        let end_handle = it.characteristic_group_end();
                        let cccd_handle = it.next().and_then(|(handle, att)| {
                            (att.uuid == CLIENT_CHARACTERISTIC_CONFIGURATION.into()).then_some(handle)
                        });

                        return Ok(Characteristic {
                            handle,
                            cccd_handle,
                            end_handle,
                            props,
                            uuid,
                            phantom: PhantomData,
                        });
                    }
                }
            }
            Err(Error::NotFound)
        })
    }

    #[cfg(feature = "security")]
    /// Calculate the database hash for the attribute table.
    ///
    /// See Core Specification Vol 3, Part G, Section 7.3.1
    pub fn hash(&self) -> u128 {
        use bt_hci::uuid::*;

        use crate::security_manager::crypto::AesCmac;

        const PRIMARY_SERVICE: Uuid = Uuid::Uuid16(declarations::PRIMARY_SERVICE.to_le_bytes());
        const SECONDARY_SERVICE: Uuid = Uuid::Uuid16(declarations::SECONDARY_SERVICE.to_le_bytes());
        const INCLUDED_SERVICE: Uuid = Uuid::Uuid16(declarations::INCLUDE.to_le_bytes());
        const CHARACTERISTIC: Uuid = Uuid::Uuid16(declarations::CHARACTERISTIC.to_le_bytes());
        const CHARACTERISTIC_EXTENDED_PROPERTIES: Uuid =
            Uuid::Uuid16(descriptors::CHARACTERISTIC_EXTENDED_PROPERTIES.to_le_bytes());

        const CHARACTERISTIC_USER_DESCRIPTION: Uuid =
            Uuid::Uuid16(descriptors::CHARACTERISTIC_USER_DESCRIPTION.to_le_bytes());
        const CLIENT_CHARACTERISTIC_CONFIGURATION: Uuid =
            Uuid::Uuid16(descriptors::CLIENT_CHARACTERISTIC_CONFIGURATION.to_le_bytes());
        const SERVER_CHARACTERISTIC_CONFIGURATION: Uuid =
            Uuid::Uuid16(descriptors::SERVER_CHARACTERISTIC_CONFIGURATION.to_le_bytes());
        const CHARACTERISTIC_PRESENTATION_FORMAT: Uuid =
            Uuid::Uuid16(descriptors::CHARACTERISTIC_PRESENTATION_FORMAT.to_le_bytes());
        const CHARACTERISTIC_AGGREGATE_FORMAT: Uuid =
            Uuid::Uuid16(descriptors::CHARACTERISTIC_AGGREGATE_FORMAT.to_le_bytes());

        let mut mac = AesCmac::db_hash();

        self.iterate(|it| {
            for (handle, att) in it {
                match att.uuid {
                    PRIMARY_SERVICE
                    | SECONDARY_SERVICE
                    | INCLUDED_SERVICE
                    | CHARACTERISTIC
                    | CHARACTERISTIC_EXTENDED_PROPERTIES => {
                        mac.update(handle.to_le_bytes()).update(att.uuid.as_raw());
                        let value = att.data.value().unwrap_or(&[]);
                        mac.update(value);
                    }
                    CHARACTERISTIC_USER_DESCRIPTION
                    | CLIENT_CHARACTERISTIC_CONFIGURATION
                    | SERVER_CHARACTERISTIC_CONFIGURATION
                    | CHARACTERISTIC_PRESENTATION_FORMAT
                    | CHARACTERISTIC_AGGREGATE_FORMAT => {
                        mac.update(handle.to_le_bytes()).update(att.uuid.as_raw());
                    }
                    _ => {}
                }
            }
        });

        mac.finalize()
    }
}

/// A type which holds a handle to an attribute in the attribute table
pub trait AttributeHandle {
    /// The data type which the attribute contains
    type Value: AsGatt;

    /// Returns the attribute's handle
    fn handle(&self) -> u16;
}

impl<T: AsGatt> AttributeHandle for Characteristic<T> {
    type Value = T;

    fn handle(&self) -> u16 {
        self.handle
    }
}

/// Invalid handle value
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct InvalidHandle;

impl core::fmt::Display for InvalidHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        core::fmt::Debug::fmt(self, f)
    }
}

impl core::error::Error for InvalidHandle {}

impl From<InvalidHandle> for Error {
    fn from(value: InvalidHandle) -> Self {
        Error::InvalidValue
    }
}

/// Builder for constructing GATT service definitions.
pub struct ServiceBuilder<'r, 'd, M: RawMutex, const MAX: usize> {
    handle: u16,
    table: &'r mut AttributeTable<'d, M, MAX>,
}

impl<'d, M: RawMutex, const MAX: usize> ServiceBuilder<'_, 'd, M, MAX> {
    fn add_characteristic_internal<T: AsGatt + ?Sized>(
        &mut self,
        uuid: Uuid,
        props: CharacteristicProps,
        permissions: AttPermissions,
        data: AttributeData<'d>,
    ) -> CharacteristicBuilder<'_, 'd, T, M, MAX> {
        let chrc_uuid = uuid;
        // First the characteristic declaration
        let (handle, cccd_handle) = self.table.with_inner_mut(|table| {
            let value_handle = table.next_handle() + 1;
            let declaration = CharacteristicDeclaration::new(props, value_handle, uuid);
            table.push(Attribute::new(CHARACTERISTIC, AttPermissions::read_only(), declaration));

            // Then the value declaration
            let h = table.push(Attribute::new(uuid, permissions, data));
            debug_assert!(h == value_handle);

            // Add optional CCCD handle
            let cccd_handle = if props.has_cccd() {
                let handle = table.push(Attribute::new(
                    CLIENT_CHARACTERISTIC_CONFIGURATION,
                    AttPermissions {
                        read: PermissionLevel::Allowed,
                        write: PermissionLevel::Allowed,
                        #[cfg(feature = "legacy-pairing")]
                        min_key_len: 0,
                    },
                    AttributeData::ClientSpecific(2),
                ));

                Some(handle)
            } else {
                None
            };

            (value_handle, cccd_handle)
        });

        CharacteristicBuilder {
            handle: Characteristic {
                handle,
                cccd_handle,
                // Temporarily set to value handle; updated in build() after descriptors are added
                end_handle: cccd_handle.unwrap_or(handle),
                props,
                uuid: chrc_uuid,
                phantom: PhantomData,
            },
            table: self.table,
        }
    }

    /// Add a characteristic to this service with a refererence to a mutable storage buffer.
    pub fn add_characteristic<T: AsGatt, U: Into<Uuid>, P: Into<CharacteristicProps>>(
        &mut self,
        uuid: U,
        props: P,
        value: T,
        store: &'d mut [u8],
    ) -> CharacteristicBuilder<'_, 'd, T, M, MAX> {
        let props: CharacteristicProps = props.into();
        let permissions = props.default_permissions();
        let bytes = value.as_gatt();
        store[..bytes.len()].copy_from_slice(bytes);
        let variable_len = T::MAX_SIZE != T::MIN_SIZE;
        let len = bytes.len() as u16;
        self.add_characteristic_internal(
            uuid.into(),
            props,
            permissions,
            AttributeData::Data {
                value: store,
                variable_len,
                len,
            },
        )
    }

    /// Add a characteristic to this service using inline storage. The characteristic value must be [`MAX_SMALL_DATA_SIZE`] bytes or less.
    pub fn add_characteristic_small<T: AsGatt, U: Into<Uuid>, P: Into<CharacteristicProps>>(
        &mut self,
        uuid: U,
        props: P,
        value: T,
    ) -> CharacteristicBuilder<'_, 'd, T, M, MAX> {
        assert!(T::MIN_SIZE <= MAX_SMALL_DATA_SIZE);

        let props: CharacteristicProps = props.into();
        let permissions = props.default_permissions();
        let bytes = value.as_gatt();
        assert!(bytes.len() <= MAX_SMALL_DATA_SIZE);
        let mut value = [0; MAX_SMALL_DATA_SIZE];
        value[..bytes.len()].copy_from_slice(bytes);
        let variable_len = T::MAX_SIZE != T::MIN_SIZE;
        let capacity = T::MAX_SIZE.min(MAX_SMALL_DATA_SIZE) as u8;
        let len = bytes.len() as u8;
        self.add_characteristic_internal(
            uuid.into(),
            props,
            permissions,
            AttributeData::SmallData {
                variable_len,
                capacity,
                len,
                value,
            },
        )
    }

    /// Add a characteristic to this service with a refererence to an immutable storage buffer.
    pub fn add_characteristic_ro<T: AsGatt + ?Sized, U: Into<Uuid>>(
        &mut self,
        uuid: U,
        value: &'d T,
    ) -> CharacteristicBuilder<'_, 'd, T, M, MAX> {
        let props: CharacteristicProps = [CharacteristicProp::Read].into();
        let permissions = props.default_permissions();
        self.add_characteristic_internal(
            uuid.into(),
            props,
            permissions,
            AttributeData::ReadOnlyData { value: value.as_gatt() },
        )
    }

    /// Add an included service to this service
    pub fn add_included_service(&mut self, handle: u16) -> Result<u16, InvalidHandle> {
        self.table.with_inner_mut(|table| {
            if handle > 0 && table.attributes.len() >= usize::from(handle) {
                let i = usize::from(handle - 1);
                let att = &table.attributes[i];
                let service_uuid = att.uuid;
                if service_uuid == Uuid::from(PRIMARY_SERVICE) || service_uuid == Uuid::from(SECONDARY_SERVICE) {
                    let last_handle_in_group = table.service_group_end(handle);

                    // Included service values only include 16-bit UUIDs per the Bluetooth spec
                    let uuid = att.data.value().and_then(|val| (val.len() == 2).then_some(val));

                    // Encode: handle_LE(2) + last_handle_in_group_LE(2) + optional_uuid(0 or 2)
                    let mut value = [0u8; MAX_SMALL_DATA_SIZE];
                    let mut w = WriteCursor::new(&mut value);
                    w.write(handle).unwrap();
                    w.write(last_handle_in_group).unwrap();
                    if let Some(uuid) = uuid {
                        w.append(uuid).unwrap();
                    }
                    let len = w.len() as u8;

                    Ok(table.push(Attribute::new(
                        INCLUDE,
                        AttPermissions::read_only(),
                        AttributeData::SmallData {
                            variable_len: false,
                            capacity: len,
                            len,
                            value,
                        },
                    )))
                } else {
                    Err(InvalidHandle)
                }
            } else {
                Err(InvalidHandle)
            }
        })
    }

    /// Finish construction of the service and return a handle.
    pub fn build(self) -> u16 {
        self.handle
    }
}

/// A characteristic in the attribute table.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Characteristic<T: AsGatt + ?Sized> {
    /// Handle value assigned to the Client Characteristic Configuration Descriptor (if any)
    pub cccd_handle: Option<u16>,
    /// Handle value assigned to this characteristic when it is added to the Gatt Attribute Table
    pub handle: u16,
    /// Last attribute handle belonging to this characteristic (value handle + descriptors)
    pub end_handle: u16,
    /// Properties of this characteristic
    pub props: CharacteristicProps,
    /// UUID of this characteristic
    pub uuid: Uuid,
    pub(crate) phantom: PhantomData<T>,
}

impl<T: AsGatt + ?Sized> Characteristic<T> {
    /// Write a value to a characteristic, and notify a connection with the new value of the characteristic.
    ///
    /// If the provided connection has not subscribed for this characteristic, it will not be notified.
    ///
    /// If the characteristic does not support notifications, an error is returned.
    pub async fn notify<P: PacketPool>(&self, connection: &GattConnection<'_, '_, P>, value: &T) -> Result<(), Error> {
        let value = value.as_gatt();
        let server = connection.server;
        server.set(self.handle, value)?;

        let cccd_handle = self.cccd_handle.ok_or(Error::NotFound)?;
        let conn = connection.raw();
        if !server.should_notify(conn, cccd_handle) {
            // No reason to fail?
            return Ok(());
        }

        self.authorize_unsolicited(connection, cccd_handle).await?;

        let uns = AttUns::Notify {
            handle: self.handle,
            data: value,
        };
        let pdu = gatt::assemble(conn, crate::att::AttServer::Unsolicited(uns))?;
        conn.send(pdu).await;
        Ok(())
    }

    /// Write a value to a characteristic, and indicate a connection with the new value of the characteristic.
    ///
    /// If the provided connection has not subscribed for this characteristic, it will not be sent an indication.
    ///
    /// If the characteristic does not support indications, an error is returned.
    ///
    /// This function does not block for the confirmation to the indication message, if the client sends a confirmation
    /// this will be seen on the [GattConnection] as a [crate::att::AttClient::Confirmation] event.
    pub async fn indicate<P: PacketPool>(
        &self,
        connection: &GattConnection<'_, '_, P>,
        value: &T,
    ) -> Result<(), Error> {
        let value = value.as_gatt();
        let server = connection.server;
        server.set(self.handle, value)?;

        let cccd_handle = self.cccd_handle.ok_or(Error::NotFound)?;
        let conn = connection.raw();
        if !server.should_indicate(conn, cccd_handle) {
            // No reason to fail?
            return Ok(());
        }

        self.authorize_unsolicited(connection, cccd_handle).await?;

        let uns = AttUns::Indicate {
            handle: self.handle,
            data: value,
        };
        let pdu = gatt::assemble(conn, crate::att::AttServer::Unsolicited(uns))?;
        conn.send(pdu).await;
        Ok(())
    }

    /// Set the value of the characteristic in the provided attribute server.
    pub fn set<M: RawMutex, P: PacketPool, const AT: usize, const CT: usize, const CN: usize>(
        &self,
        server: &AttributeServer<'_, M, P, AT, CT, CN>,
        value: &T,
    ) -> Result<(), Error> {
        let value = value.as_gatt();
        server.table().set_raw(self.handle, value)?;
        Ok(())
    }

    /// Set the value of the characteristic in the provided attribute server.
    pub fn set_ro<'a, M: RawMutex, P: PacketPool, const AT: usize, const CT: usize, const CN: usize>(
        &self,
        server: &AttributeServer<'a, M, P, AT, CT, CN>,
        value: &'a T,
    ) -> Result<(), Error> {
        let value = value.as_gatt();
        server.table().set_ro(self.handle, value)?;
        Ok(())
    }

    /// Read the value of the characteristic.
    ///
    /// If the characteristic for the handle cannot be found, an error is returned.
    ///
    pub fn get<M: RawMutex, P: PacketPool, const AT: usize, const CT: usize, const CN: usize>(
        &self,
        server: &AttributeServer<'_, M, P, AT, CT, CN>,
    ) -> Result<T, Error>
    where
        T: FromGatt,
    {
        server.table().get(self)
    }

    /// Returns the attribute handle for the characteristic's client characteristic configuration descriptor (if available)
    pub fn cccd_handle(&self) -> Option<CharacteristicPropertiesHandle> {
        self.cccd_handle.map(CharacteristicPropertiesHandle)
    }

    /// Convert this characteristic's type to raw bytes
    pub fn to_raw(self) -> Characteristic<[u8]> {
        Characteristic {
            cccd_handle: self.cccd_handle,
            handle: self.handle,
            end_handle: self.end_handle,
            props: self.props,
            uuid: self.uuid,
            phantom: PhantomData,
        }
    }

    async fn authorize_unsolicited<P: PacketPool>(
        &self,
        connection: &GattConnection<'_, '_, P>,
        cccd_handle: u16,
    ) -> Result<(), Error> {
        let server = connection.server;
        let conn = connection.raw();

        // Ensure encryption before sending notifications that require security
        // (BT Core Spec Vol 3, Part C, Section 10.3.1.1: server "shall" initiate encryption)
        // Write permission on the CCCD defines permission to receive notifications/indications
        match server.can_write(conn, cccd_handle) {
            Ok(()) => Ok(()),
            Err(err) => {
                #[cfg(feature = "security")]
                if conn.is_bonded_peer() && !conn.security_level().is_ok_and(|l| l.encrypted()) {
                    conn.try_enable_encryption().await?;
                    server.can_write(conn, cccd_handle)?;
                    return Ok(());
                }
                Err(err.into())
            }
        }
    }
}

/// Attribute handle for a characteristic's properties
pub struct CharacteristicPropertiesHandle(u16);

impl AttributeHandle for CharacteristicPropertiesHandle {
    type Value = CharacteristicProps;

    fn handle(&self) -> u16 {
        self.0
    }
}

/// Builder for characteristics.
pub struct CharacteristicBuilder<'r, 'd, T: AsGatt + ?Sized, M: RawMutex, const MAX: usize> {
    handle: Characteristic<T>,
    table: &'r mut AttributeTable<'d, M, MAX>,
}

impl<'r, 'd, T: AsGatt + ?Sized, M: RawMutex, const MAX: usize> CharacteristicBuilder<'r, 'd, T, M, MAX> {
    fn add_descriptor_internal<DT: AsGatt + ?Sized>(
        &mut self,
        uuid: Uuid,
        permissions: AttPermissions,
        data: AttributeData<'d>,
    ) -> Descriptor<DT> {
        let handle = self.table.push(Attribute::new(uuid, permissions, data));

        Descriptor {
            handle,
            uuid,
            phantom: PhantomData,
        }
    }

    /// Add a characteristic descriptor for this characteristic.
    pub fn add_descriptor<DT: AsGatt, U: Into<Uuid>>(
        &mut self,
        uuid: U,
        permissions: AttPermissions,
        value: DT,
        store: &'d mut [u8],
    ) -> Descriptor<DT> {
        let bytes = value.as_gatt();
        store[..bytes.len()].copy_from_slice(bytes);
        let variable_len = DT::MAX_SIZE != DT::MIN_SIZE;
        let len = bytes.len() as u16;
        self.add_descriptor_internal(
            uuid.into(),
            permissions,
            AttributeData::Data {
                value: store,
                variable_len,
                len,
            },
        )
    }

    /// Add a characteristic to this service using inline storage. The descriptor value must be [`MAX_SMALL_DATA_SIZE`] bytes or less.
    pub fn add_descriptor_small<DT: AsGatt, U: Into<Uuid>>(
        &mut self,
        uuid: U,
        permissions: AttPermissions,
        value: DT,
    ) -> Descriptor<DT> {
        assert!(DT::MIN_SIZE <= MAX_SMALL_DATA_SIZE);

        let bytes = value.as_gatt();
        assert!(bytes.len() <= MAX_SMALL_DATA_SIZE);
        let mut value = [0; MAX_SMALL_DATA_SIZE];
        value[..bytes.len()].copy_from_slice(bytes);
        let variable_len = DT::MAX_SIZE != DT::MIN_SIZE;
        let capacity = DT::MAX_SIZE.min(MAX_SMALL_DATA_SIZE) as u8;
        let len = bytes.len() as u8;
        self.add_descriptor_internal(
            uuid.into(),
            permissions,
            AttributeData::SmallData {
                variable_len,
                capacity,
                len,
                value,
            },
        )
    }

    /// Add a read only characteristic descriptor for this characteristic.
    pub fn add_descriptor_ro<DT: AsGatt + ?Sized, U: Into<Uuid>>(
        &mut self,
        uuid: U,
        read_permission: PermissionLevel,
        data: &'d DT,
    ) -> Descriptor<DT> {
        let permissions = AttPermissions {
            write: PermissionLevel::NotAllowed,
            read: read_permission,
            #[cfg(feature = "legacy-pairing")]
            min_key_len: 0,
        };
        self.add_descriptor_internal(
            uuid.into(),
            permissions,
            AttributeData::ReadOnlyData { value: data.as_gatt() },
        )
    }

    /// Set the read permission for this characteristic
    pub fn read_permission(self, read: PermissionLevel) -> Self {
        self.table
            .with_attribute_mut(self.handle.handle, |att| att.permissions.read = read);
        self
    }

    /// Set the write permission for this characteristic
    pub fn write_permission(self, write: PermissionLevel) -> Self {
        self.table
            .with_attribute_mut(self.handle.handle, |att| att.permissions.write = write);
        self
    }

    /// Set the write permission for the Client Characteristic Configuration Descriptor for this characteristic
    ///
    /// Panics if this characteristic does not have a Client Characteristic Configuration Descriptor.
    pub fn cccd_permission(self, write: PermissionLevel) -> Self {
        let Some(handle) = self.handle.cccd_handle else {
            panic!("Can't set CCCD permission on characteristics without notify or indicate properties.");
        };

        self.table
            .with_attribute_mut(handle, |att| att.permissions.write = write);
        self
    }

    /// Set the minimum encryption key length required for this characteristic
    #[cfg(feature = "legacy-pairing")]
    pub fn min_key_len(self, len: u8) -> Self {
        self.table
            .with_attribute_mut(self.handle.handle, |att| att.permissions.min_key_len = len);
        self
    }

    /// Convert this characteristic's type to raw bytes
    pub fn to_raw(self) -> CharacteristicBuilder<'r, 'd, [u8], M, MAX> {
        CharacteristicBuilder {
            handle: self.handle.to_raw(),
            table: self.table,
        }
    }
    /// Return the built characteristic.
    pub fn build(mut self) -> Characteristic<T> {
        self.handle.end_handle = self.table.with_inner(|t| t.next_handle() - 1);
        self.handle
    }
}

/// Characteristic descriptor handle.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Clone, Copy, Debug)]
pub struct Descriptor<T: AsGatt + ?Sized> {
    pub(crate) handle: u16,
    pub(crate) uuid: Uuid,
    pub(crate) phantom: PhantomData<T>,
}

impl<T: AsGatt> AttributeHandle for Descriptor<T> {
    type Value = T;

    fn handle(&self) -> u16 {
        self.handle
    }
}

impl<T: AsGatt + ?Sized> Descriptor<T> {
    /// Get the handle of this descriptor.
    pub fn handle(&self) -> u16 {
        self.handle
    }

    /// Get the UUID of this descriptor.
    pub fn uuid(&self) -> &Uuid {
        &self.uuid
    }

    /// Set the value of the descriptor in the provided attribute server.
    pub fn set<M: RawMutex, P: PacketPool, const AT: usize, const CT: usize, const CN: usize>(
        &self,
        server: &AttributeServer<'_, M, P, AT, CT, CN>,
        value: &T,
    ) -> Result<(), Error> {
        let value = value.as_gatt();
        server.table().set_raw(self.handle, value)?;
        Ok(())
    }

    /// Read the value of the descriptor.
    ///
    /// If the descriptor for the handle cannot be found, an error is returned.
    ///
    pub fn get<M: RawMutex, P: PacketPool, const AT: usize, const CT: usize, const CN: usize>(
        &self,
        server: &AttributeServer<'_, M, P, AT, CT, CN>,
    ) -> Result<T, Error>
    where
        T: FromGatt,
    {
        server.table().get(self)
    }
}

/// Iterator over attributes.
pub struct AttributeIterator<'a, 'd> {
    attributes: &'a [Attribute<'d>],
    pos: usize,
}

impl<'a, 'd> Iterator for AttributeIterator<'a, 'd> {
    type Item = (u16, &'a Attribute<'d>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos < self.attributes.len() {
            let att = &self.attributes[self.pos];
            self.pos += 1;
            let handle = self.pos as u16;
            Some((handle, att))
        } else {
            None
        }
    }
}

impl<'a, 'd> AttributeIterator<'a, 'd> {
    /// Find the handle of the last attribute in the current GATT service.
    ///
    /// Returns `u16::MAX` for the last service in the table.
    pub fn service_group_end(&self) -> u16 {
        // We return the 0-based index of the next service definition. When interpretted as a 1-based handle,
        // this represents the handle of the last attribute before the next service definition.
        self.attributes
            .iter()
            .enumerate()
            .skip(self.pos)
            .find(|(_, attr)| attr.uuid == PRIMARY_SERVICE.into() || attr.uuid == SECONDARY_SERVICE.into())
            .map(|(i, _)| i as u16)
            .unwrap_or(u16::MAX)
    }

    /// Find the handle of the last attribute in the current GATT characteristic.
    pub fn characteristic_group_end(&self) -> u16 {
        // We return the 0-based index of the next characteristic or service definition. When interpretted as a 1-based handle,
        // this represents the handle of the last attribute before the next characteristic or service definition.
        self.attributes
            .iter()
            .enumerate()
            .skip(self.pos)
            .find(|(_, attr)| {
                attr.uuid == PRIMARY_SERVICE.into()
                    || attr.uuid == SECONDARY_SERVICE.into()
                    || attr.uuid == CHARACTERISTIC.into()
            })
            .map(|(i, _)| i as u16)
            .unwrap_or(self.attributes.len() as u16)
    }
}

/// A GATT service.
pub struct Service {
    /// UUID of the service.
    pub uuid: Uuid,
}

impl Service {
    /// Create a new service with a uuid.
    pub fn new<U: Into<Uuid>>(uuid: U) -> Self {
        Self { uuid: uuid.into() }
    }
}

/// Properties of a characteristic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CharacteristicProps(u8);

impl<'a> From<&'a [CharacteristicProp]> for CharacteristicProps {
    fn from(props: &'a [CharacteristicProp]) -> Self {
        let mut val: u8 = 0;
        for prop in props {
            val |= *prop as u8;
        }
        CharacteristicProps(val)
    }
}

impl<'a, const N: usize> From<&'a [CharacteristicProp; N]> for CharacteristicProps {
    fn from(props: &'a [CharacteristicProp; N]) -> Self {
        let mut val: u8 = 0;
        for prop in props {
            val |= *prop as u8;
        }
        CharacteristicProps(val)
    }
}

impl<const N: usize> From<[CharacteristicProp; N]> for CharacteristicProps {
    fn from(props: [CharacteristicProp; N]) -> Self {
        let mut val: u8 = 0;
        for prop in props {
            val |= prop as u8;
        }
        CharacteristicProps(val)
    }
}

impl From<u8> for CharacteristicProps {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl CharacteristicProps {
    /// Check if any of the properties are set.
    pub fn any(&self, props: &[CharacteristicProp]) -> bool {
        for p in props {
            if (*p as u8) & self.0 != 0 {
                return true;
            }
        }
        false
    }

    pub(crate) fn default_permissions(&self) -> AttPermissions {
        let read = if (self.0 & CharacteristicProp::Read as u8) != 0 {
            PermissionLevel::Allowed
        } else {
            PermissionLevel::NotAllowed
        };

        let write = if (self.0
            & (CharacteristicProp::Write as u8
                | CharacteristicProp::WriteWithoutResponse as u8
                | CharacteristicProp::AuthenticatedWrite as u8))
            != 0
        {
            PermissionLevel::Allowed
        } else {
            PermissionLevel::NotAllowed
        };

        AttPermissions {
            read,
            write,
            #[cfg(feature = "legacy-pairing")]
            min_key_len: 0,
        }
    }

    /// Check if the characteristic will have a Client Characteristic Configuration Descriptor
    pub fn has_cccd(&self) -> bool {
        (self.0 & (CharacteristicProp::Indicate as u8 | CharacteristicProp::Notify as u8)) != 0
    }

    /// Get the raw value of the characteristic props
    pub fn to_raw(self) -> u8 {
        self.0
    }
}

impl FixedGattValue for CharacteristicProps {
    const SIZE: usize = 1;
}

impl FromGatt for CharacteristicProps {
    fn from_gatt(data: &[u8]) -> Result<Self, FromGattError> {
        if data.len() != Self::SIZE {
            return Err(FromGattError::InvalidLength);
        }

        Ok(CharacteristicProps(data[0]))
    }
}

impl AsGatt for CharacteristicProps {
    const MIN_SIZE: usize = Self::SIZE;
    const MAX_SIZE: usize = Self::SIZE;

    fn as_gatt(&self) -> &[u8] {
        AsGatt::as_gatt(&self.0)
    }
}

/// A value of an attribute.
pub struct AttributeValue<'d, M: RawMutex> {
    value: Mutex<M, &'d mut [u8]>,
}

impl<M: RawMutex> AttributeValue<'_, M> {}

/// CCCD flag values.
#[derive(Clone, Copy)]
pub enum CCCDFlag {
    /// Notifications enabled.
    Notify = 0x1,
    /// Indications enabled.
    Indicate = 0x2,
}

/// CCCD flag.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Clone, Copy, Default, Debug, PartialEq)]
pub struct CCCD(pub(crate) u16);

impl<const T: usize> From<[CCCDFlag; T]> for CCCD {
    fn from(props: [CCCDFlag; T]) -> Self {
        let mut val: u16 = 0;
        for prop in props {
            val |= prop as u16;
        }
        CCCD(val)
    }
}

impl From<u16> for CCCD {
    fn from(value: u16) -> Self {
        CCCD(value)
    }
}

impl CCCD {
    /// Get raw value
    pub fn raw(&self) -> u16 {
        self.0
    }

    /// Clear all properties
    pub fn disable(&mut self) {
        self.0 = 0;
    }

    /// Check if any of the properties are set.
    pub fn any(&self, props: &[CCCDFlag]) -> bool {
        for p in props {
            if (*p as u16) & self.0 != 0 {
                return true;
            }
        }
        false
    }

    /// Enable or disable notifications
    pub fn set_notify(&mut self, is_enabled: bool) {
        let mask: u16 = CCCDFlag::Notify as u16;
        self.0 = if is_enabled { self.0 | mask } else { self.0 & !mask };
    }

    /// Check if notifications are enabled
    pub fn should_notify(&self) -> bool {
        (self.0 & (CCCDFlag::Notify as u16)) != 0
    }

    /// Enable or disable indication
    pub fn set_indicate(&mut self, is_enabled: bool) {
        let mask: u16 = CCCDFlag::Indicate as u16;
        self.0 = if is_enabled { self.0 | mask } else { self.0 & !mask };
    }

    /// Check if indications are enabled
    pub fn should_indicate(&self) -> bool {
        (self.0 & (CCCDFlag::Indicate as u16)) != 0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    #[cfg(feature = "security")]
    #[test]
    fn database_hash() {
        use bt_hci::uuid::characteristic::{
            APPEARANCE, CLIENT_SUPPORTED_FEATURES, DATABASE_HASH, DEVICE_NAME, SERVICE_CHANGED,
        };
        use bt_hci::uuid::declarations::{CHARACTERISTIC, PRIMARY_SERVICE};
        use bt_hci::uuid::descriptors::{
            CHARACTERISTIC_PRESENTATION_FORMAT, CHARACTERISTIC_USER_DESCRIPTION, CLIENT_CHARACTERISTIC_CONFIGURATION,
        };
        use bt_hci::uuid::service::{GAP, GATT};
        use embassy_sync::blocking_mutex::raw::NoopRawMutex;

        use super::*;

        // The raw message data that should be hashed for this attribute table is:
        //
        // 0100 0028 0018
        // 0200 0328 020300002a
        // 0400 0328 020500012a
        //
        // 0600 0028 0118
        // 0700 0328 200800052a
        // 0900 0229
        // 0a00 0328 0a0b00292b
        // 0c00 0328 020d002a2b
        //
        // 0e00 0028 f0debc9a785634127856341278563412
        // 0f00 0328 121000f1debc9a785634127856341278563412
        // 1100 0229
        // 1200 0129
        // 1300 0429
        //
        // The message hash can be calculated on the command line with:
        // > xxd -plain -revert message.txt message.bin
        // > openssl mac -cipher AES-128-CBC -macopt hexkey:00000000000000000000000000000000 -in message.bin CMAC

        let mut table: AttributeTable<'static, NoopRawMutex, 20> = AttributeTable::new();

        let ro = AttPermissions::read_only();
        let cccd_perms = AttPermissions {
            read: PermissionLevel::Allowed,
            write: PermissionLevel::Allowed,
            #[cfg(feature = "legacy-pairing")]
            min_key_len: 0,
        };

        // GAP service (handles 0x001 - 0x005)
        table.push(Attribute::new(PRIMARY_SERVICE, ro, GAP));

        let expected = 0xd4cdec10804db3f147b4d7d10baa0120;
        let actual = table.hash();
        assert_eq!(
            actual, expected,
            "\nexpected: {:#032x}\nactual: {:#032x}",
            expected, actual
        );

        // Device name characteristic
        table.push(Attribute::new(
            CHARACTERISTIC,
            ro,
            CharacteristicDeclaration::new([CharacteristicProp::Read], 0x0003, DEVICE_NAME),
        ));

        table.push(Attribute::new(
            DEVICE_NAME,
            ro,
            AttributeData::ReadOnlyData { value: b"" },
        ));

        // Appearance characteristic
        table.push(Attribute::new(
            CHARACTERISTIC,
            ro,
            CharacteristicDeclaration::new([CharacteristicProp::Read], 0x0005, APPEARANCE),
        ));

        table.push(Attribute::new(
            APPEARANCE,
            ro,
            AttributeData::ReadOnlyData { value: b"" },
        ));

        let expected = 0x6c329e3f1d52c03f174980f6b4704875;
        let actual = table.hash();
        assert_eq!(
            actual, expected,
            "\nexpected: {:#032x}\n  actual: {:#032x}",
            expected, actual
        );

        // GATT service (handles 0x006 - 0x000d)
        table.push(Attribute::new(PRIMARY_SERVICE, ro, GATT));

        // Service changed characteristic
        table.push(Attribute::new(
            CHARACTERISTIC,
            ro,
            CharacteristicDeclaration::new([CharacteristicProp::Indicate], 0x0008, SERVICE_CHANGED),
        ));

        table.push(Attribute::new(
            SERVICE_CHANGED,
            ro,
            AttributeData::ReadOnlyData { value: b"" },
        ));

        table.push(Attribute::new(
            CLIENT_CHARACTERISTIC_CONFIGURATION,
            cccd_perms,
            AttributeData::ClientSpecific(2),
        ));

        // Client supported features characteristic
        table.push(Attribute::new(
            CHARACTERISTIC,
            ro,
            CharacteristicDeclaration::new(
                [CharacteristicProp::Read, CharacteristicProp::Write],
                0x000b,
                CLIENT_SUPPORTED_FEATURES,
            ),
        ));

        table.push(Attribute::new(
            CLIENT_SUPPORTED_FEATURES,
            ro,
            AttributeData::ReadOnlyData { value: b"" },
        ));

        // Database hash characteristic
        table.push(Attribute::new(
            CHARACTERISTIC,
            ro,
            CharacteristicDeclaration::new([CharacteristicProp::Read], 0x000d, DATABASE_HASH),
        ));

        table.push(Attribute::new(
            DATABASE_HASH,
            ro,
            AttributeData::ReadOnlyData { value: b"" },
        ));

        let expected = 0x16ce756326c5062bf74022f845c2b21f;
        let actual = table.hash();
        assert_eq!(
            actual, expected,
            "\nexpected: {:#032x}\n  actual: {:#032x}",
            expected, actual
        );

        const CUSTOM_SERVICE: u128 = 0x12345678_12345678_12345678_9abcdef0;
        const CUSTOM_CHARACTERISTIC: u128 = 0x12345678_12345678_12345678_9abcdef1;

        // Custom service (handles 0x00e - 0x0013)
        table.push(Attribute::new(PRIMARY_SERVICE, ro, Uuid::from(CUSTOM_SERVICE)));

        // Custom characteristic
        table.push(Attribute::new(
            CHARACTERISTIC,
            ro,
            CharacteristicDeclaration::new(
                [CharacteristicProp::Notify, CharacteristicProp::Read],
                0x0010,
                CUSTOM_CHARACTERISTIC,
            ),
        ));

        table.push(Attribute::new(
            CUSTOM_CHARACTERISTIC,
            ro,
            AttributeData::ReadOnlyData { value: b"" },
        ));

        table.push(Attribute::new(
            CLIENT_CHARACTERISTIC_CONFIGURATION,
            cccd_perms,
            AttributeData::ClientSpecific(2),
        ));

        table.push(Attribute::new(
            CHARACTERISTIC_USER_DESCRIPTION,
            ro,
            AttributeData::ReadOnlyData {
                value: b"Custom Characteristic",
            },
        ));

        table.push(Attribute::new(
            CHARACTERISTIC_PRESENTATION_FORMAT,
            ro,
            AttributeData::ReadOnlyData {
                value: &[4, 0, 0, 0x27, 1, 0, 0],
            },
        ));

        let expected = 0xc7352cced28d6608d4b057d247d8be76;
        let actual = table.hash();
        assert_eq!(
            actual, expected,
            "\nexpected: {:#032x}\n  actual: {:#032x}",
            expected, actual
        );
    }

    #[test]
    fn set_updates_variable_length_when_value_fills_backing_storage() {
        use embassy_sync::blocking_mutex::raw::NoopRawMutex;
        use heapless::Vec;

        use super::*;

        let mut storage = [0u8; 4];
        let mut table: AttributeTable<'_, NoopRawMutex, 4> = AttributeTable::new();
        let initial = Vec::<u8, 4>::from_slice(b"ab").unwrap();
        let characteristic = table
            .add_service(Service {
                uuid: Uuid::new_long([0x10; 16]),
            })
            .add_characteristic(
                Uuid::new_long([0x11; 16]),
                [CharacteristicProp::Read, CharacteristicProp::Write],
                initial,
                &mut storage,
            )
            .build();

        let replacement = Vec::<u8, 4>::from_slice(b"wxyz").unwrap();
        table.set(&characteristic, &replacement).unwrap();

        let stored: Vec<u8, 4> = table.get(&characteristic).unwrap();
        assert_eq!(stored.as_slice(), b"wxyz");
    }

    #[test]
    fn set_updates_small_variable_length_when_value_reaches_capacity() {
        use embassy_sync::blocking_mutex::raw::NoopRawMutex;
        use heapless::String;

        use super::*;

        let mut table: AttributeTable<'_, NoopRawMutex, 4> = AttributeTable::new();
        let initial = String::<8>::try_from("hi").unwrap();
        let characteristic = table
            .add_service(Service {
                uuid: Uuid::new_long([0x12; 16]),
            })
            .add_characteristic_small(
                Uuid::new_long([0x13; 16]),
                [CharacteristicProp::Read, CharacteristicProp::Write],
                initial,
            )
            .build();

        let replacement = String::<8>::try_from("12345678").unwrap();
        table.set(&characteristic, &replacement).unwrap();

        let stored: String<8> = table.get(&characteristic).unwrap();
        assert_eq!(stored.as_str(), "12345678");
    }
}

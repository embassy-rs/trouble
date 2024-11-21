//! Attribute protocol implementation.
use core::cell::RefCell;
use core::fmt;
use core::marker::PhantomData;

use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::blocking_mutex::Mutex;

use crate::att::AttErrorCode;
use crate::cursor::{ReadCursor, WriteCursor};
use crate::prelude::Connection;
use crate::types::gatt_traits::GattValue;
pub use crate::types::uuid::Uuid;
use crate::Error;

/// UUID for generic access service
pub const GENERIC_ACCESS_SERVICE_UUID16: Uuid = Uuid::Uuid16(0x1800u16.to_le_bytes());

/// UUID for device name characteristic
pub const CHARACTERISTIC_DEVICE_NAME_UUID16: Uuid = Uuid::Uuid16(0x2A00u16.to_le_bytes());

/// UUID for appearance characteristic
pub const CHARACTERISTIC_APPEARANCE_UUID16: Uuid = Uuid::Uuid16(0x2A03u16.to_le_bytes());

/// UUID for generic attribute service
pub const GENERIC_ATTRIBUTE_SERVICE_UUID16: Uuid = Uuid::Uuid16(0x1801u16.to_le_bytes());

/// UUID for primary service
pub const PRIMARY_SERVICE_UUID16: Uuid = Uuid::Uuid16(0x2800u16.to_le_bytes());

/// UUID for secondary service
pub const SECONDARY_SERVICE_UUID16: Uuid = Uuid::Uuid16(0x2801u16.to_le_bytes());

/// UUID for include service
pub const INCLUDE_SERVICE_UUID16: Uuid = Uuid::Uuid16(0x2802u16.to_le_bytes());

/// UUID for characteristic declaration
pub const CHARACTERISTIC_UUID16: Uuid = Uuid::Uuid16(0x2803u16.to_le_bytes());

/// UUID for characteristic notification/indication
pub const CHARACTERISTIC_CCCD_UUID16: Uuid = Uuid::Uuid16(0x2902u16.to_le_bytes());

/// UUID for generic attribute.
pub const GENERIC_ATTRIBUTE_UUID16: Uuid = Uuid::Uuid16(0x1801u16.to_le_bytes());

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

type WriteCallback = fn(&Connection, &[u8]) -> Result<(), ()>;

/// Attribute metadata.
pub struct Attribute<'a> {
    pub(crate) uuid: Uuid,
    pub(crate) handle: u16,
    pub(crate) last_handle_in_group: u16,
    pub(crate) data: AttributeData<'a>,
    pub(crate) on_read: Option<fn(&Connection)>,
    pub(crate) on_write: Option<WriteCallback>,
}

impl<'a> Attribute<'a> {
    const EMPTY: Option<Attribute<'a>> = None;

    pub(crate) fn read(&self, connection: &Connection, offset: usize, data: &mut [u8]) -> Result<usize, AttErrorCode> {
        if !self.data.readable() {
            return Err(AttErrorCode::ReadNotPermitted);
        }
        if let Some(callback) = self.on_read {
            callback(connection);
        }
        self.data.read(offset, data)
    }

    pub(crate) fn write(&mut self, connection: &Connection, offset: usize, data: &[u8]) -> Result<(), AttErrorCode> {
        if !self.data.writable() {
            return Err(AttErrorCode::WriteNotPermitted);
        }

        let mut callback_result = Ok(());
        if let Some(callback) = self.on_write {
            callback_result = callback(connection, data);
        }

        if callback_result.is_ok() {
            self.data.write(offset, data)
        } else {
            Err(AttErrorCode::ValueNotAllowed)
        }
    }
}

pub(crate) enum AttributeData<'d> {
    Service {
        uuid: Uuid,
    },
    ReadOnlyData {
        props: CharacteristicProps,
        value: &'d [u8],
    },
    Data {
        props: CharacteristicProps,
        value: &'d mut [u8],
    },
    Declaration {
        props: CharacteristicProps,
        handle: u16,
        uuid: Uuid,
    },
    Cccd {
        notifications: bool,
        indications: bool,
    },
}

impl<'d> AttributeData<'d> {
    pub(crate) fn readable(&self) -> bool {
        match self {
            Self::Data { props, value } => props.0 & (CharacteristicProp::Read as u8) != 0,
            _ => true,
        }
    }

    pub(crate) fn writable(&self) -> bool {
        match self {
            Self::Data { props, value } => {
                props.0
                    & (CharacteristicProp::Write as u8
                        | CharacteristicProp::WriteWithoutResponse as u8
                        | CharacteristicProp::AuthenticatedWrite as u8)
                    != 0
            }
            Self::Cccd {
                notifications,
                indications,
            } => true,
            _ => false,
        }
    }

    fn read(&self, offset: usize, data: &mut [u8]) -> Result<usize, AttErrorCode> {
        if !self.readable() {
            return Err(AttErrorCode::ReadNotPermitted);
        }
        match self {
            Self::ReadOnlyData { props, value } => {
                if offset > value.len() {
                    return Ok(0);
                }
                let len = data.len().min(value.len() - offset);
                if len > 0 {
                    data[..len].copy_from_slice(&value[offset..offset + len]);
                }
                Ok(len)
            }
            Self::Data { props, value } => {
                if offset > value.len() {
                    return Ok(0);
                }
                let len = data.len().min(value.len() - offset);
                if len > 0 {
                    data[..len].copy_from_slice(&value[offset..offset + len]);
                }
                Ok(len)
            }
            Self::Service { uuid } => {
                let val = uuid.as_raw();
                if offset > val.len() {
                    return Ok(0);
                }
                let len = data.len().min(val.len() - offset);
                if len > 0 {
                    data[..len].copy_from_slice(&val[offset..offset + len]);
                }
                Ok(len)
            }
            Self::Cccd {
                notifications,
                indications,
            } => {
                if offset > 0 {
                    return Err(AttErrorCode::InvalidOffset);
                }
                if data.len() < 2 {
                    return Err(AttErrorCode::UnlikelyError);
                }
                let mut v = 0;
                if *notifications {
                    v |= 0x01;
                }

                if *indications {
                    v |= 0x02;
                }
                data[0] = v;
                Ok(2)
            }
            Self::Declaration { props, handle, uuid } => {
                let val = uuid.as_raw();
                if offset > val.len() + 3 {
                    return Ok(0);
                }
                let mut w = WriteCursor::new(data);
                if offset == 0 {
                    w.write(props.0)?;
                    w.write(*handle)?;
                } else if offset == 1 {
                    w.write(*handle)?;
                } else if offset == 2 {
                    w.write(handle.to_le_bytes()[1])?;
                }

                let to_write = w.available().min(val.len());

                if to_write > 0 {
                    w.append(&val[..to_write])?;
                }
                Ok(w.len())
            }
        }
    }

    fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), AttErrorCode> {
        let writable = self.writable();

        match self {
            Self::Data { value, props } => {
                if !writable {
                    return Err(AttErrorCode::WriteNotPermitted);
                }

                if offset + data.len() <= value.len() {
                    value[offset..offset + data.len()].copy_from_slice(data);
                    Ok(())
                } else {
                    Err(AttErrorCode::InvalidOffset)
                }
            }
            Self::Cccd {
                notifications,
                indications,
            } => {
                if offset > 0 {
                    return Err(AttErrorCode::InvalidOffset);
                }

                if data.is_empty() {
                    return Err(AttErrorCode::UnlikelyError);
                }

                *notifications = data[0] & 0x01 != 0;
                *indications = data[0] & 0x02 != 0;
                Ok(())
            }
            _ => Err(AttErrorCode::WriteNotPermitted),
        }
    }

    pub(crate) fn decode_declaration(data: &[u8]) -> Result<Self, Error> {
        let mut r = ReadCursor::new(data);
        Ok(Self::Declaration {
            props: CharacteristicProps(r.read()?),
            handle: r.read()?,
            uuid: Uuid::from_slice(r.remaining()),
        })
    }
}

impl<'a> fmt::Debug for Attribute<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Attribute")
            .field("uuid", &self.uuid)
            .field("handle", &self.handle)
            .field("last_handle_in_group", &self.last_handle_in_group)
            .field("readable", &self.data.readable())
            .field("writable", &self.data.writable())
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
    pub(crate) fn new(
        uuid: Uuid,
        data: AttributeData<'a>,
        on_read: Option<fn(&Connection)>,
        on_write: Option<WriteCallback>,
    ) -> Attribute<'a> {
        Attribute {
            uuid,
            handle: 0,
            data,
            last_handle_in_group: 0xffff,
            on_read,
            on_write,
        }
    }
}

/// A table of attributes.
pub struct AttributeTable<'d, M: RawMutex, const MAX: usize> {
    inner: Mutex<M, RefCell<InnerTable<'d, MAX>>>,
    handle: u16,
}

pub(crate) struct InnerTable<'d, const MAX: usize> {
    attributes: [Option<Attribute<'d>>; MAX],
    len: usize,
}

impl<'d, const MAX: usize> InnerTable<'d, MAX> {
    fn push(&mut self, attribute: Attribute<'d>) {
        if self.len == MAX {
            panic!("no space for more attributes")
        }
        self.attributes[self.len].replace(attribute);
        self.len += 1;
    }
}

impl<'d, M: RawMutex, const MAX: usize> Default for AttributeTable<'d, M, MAX> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'d, M: RawMutex, const MAX: usize> AttributeTable<'d, M, MAX> {
    /// Create a new GATT table.
    pub fn new() -> Self {
        Self {
            handle: 1,
            inner: Mutex::new(RefCell::new(InnerTable {
                len: 0,
                attributes: [Attribute::EMPTY; MAX],
            })),
        }
    }

    pub(crate) fn with_inner<F: Fn(&mut InnerTable<'d, MAX>)>(&self, f: F) {
        self.inner.lock(|inner| {
            let mut table = inner.borrow_mut();
            f(&mut table);
        })
    }

    pub(crate) fn iterate<F: FnMut(AttributeIterator<'_, 'd>) -> R, R>(&self, mut f: F) -> R {
        self.inner.lock(|inner| {
            let mut table = inner.borrow_mut();
            let len = table.len;
            let it = AttributeIterator {
                attributes: &mut table.attributes[..],
                pos: 0,
                len,
            };
            f(it)
        })
    }

    fn push(&mut self, mut attribute: Attribute<'d>) -> u16 {
        let handle = self.handle;
        attribute.handle = handle;
        self.inner.lock(|inner| {
            let mut inner = inner.borrow_mut();
            inner.push(attribute);
        });
        self.handle += 1;
        handle
    }

    /// Add a service to the attribute table (group of characteristics)
    pub fn add_service(&mut self, service: Service) -> ServiceBuilder<'_, 'd, M, MAX> {
        let len = self.inner.lock(|i| i.borrow().len);
        let handle = self.handle;
        self.push(Attribute {
            uuid: PRIMARY_SERVICE_UUID16,
            handle: 0,
            last_handle_in_group: 0,
            data: AttributeData::Service { uuid: service.uuid },
            on_read: None,
            on_write: None,
        });
        ServiceBuilder {
            handle: AttributeHandle { handle },
            start: len,
            table: self,
        }
    }

    fn set_read_callback(&mut self, handle: u16, on_read: fn(&Connection)) {
        self.iterate(|mut it| {
            while let Some(att) = it.next() {
                if att.handle == handle {
                    att.on_read = Some(on_read);
                    break;
                }
            }
        })
    }

    fn set_write_callback(&mut self, handle: u16, on_write: fn(&Connection, &[u8]) -> Result<(), ()>) {
        self.iterate(|mut it| {
            while let Some(att) = it.next() {
                if att.handle == handle {
                    att.on_write = Some(on_write);
                    break;
                }
            }
        })
    }

    /// Set the value of a characteristic
    ///
    /// The provided data must exactly match the size of the storage for the characteristic,
    /// otherwise this function will panic.
    ///
    /// If the characteristic for the handle cannot be found, or the shape of the data does not match the type of the characterstic,
    /// an error is returned
    pub fn set<T: GattValue>(&self, characteristic: &Characteristic<T>, input: &T) -> Result<(), Error> {
        let gatt_value = input.to_gatt();
        self.iterate(|mut it| {
            while let Some(att) = it.next() {
                if att.handle == characteristic.handle {
                    if let AttributeData::Data { props, value } = &mut att.data {
                        if value.len() == gatt_value.len() {
                            value.copy_from_slice(gatt_value);
                            return Ok(());
                        } else {
                            return Err(Error::InvalidValue);
                        }
                    }
                }
            }
            Err(Error::NotFound)
        })
    }

    /// Read the value of the characteristic and pass the value to the provided closure.
    ///
    /// The return value of the closure is returned in this function and is assumed to be infallible.
    ///
    /// If the characteristic for the handle cannot be found, an error is returned.
    pub fn get<T: GattValue>(&self, characteristic: &Characteristic<T>) -> Result<T, Error> {
        self.iterate(|mut it| {
            while let Some(att) = it.next() {
                if att.handle == characteristic.handle {
                    if let AttributeData::Data { props, value } = &mut att.data {
                        let v = <T as GattValue>::from_gatt(value).map_err(|_| Error::InvalidValue)?;
                        return Ok(v);
                    }
                }
            }
            Err(Error::NotFound)
        })
    }

    /// Return the characteristic which corresponds to the supplied value handle
    ///
    /// If no characteristic corresponding to the given value handle was found, returns an error
    pub fn find_characteristic_by_value_handle<T: GattValue>(&self, handle: u16) -> Result<Characteristic<T>, Error> {
        self.iterate(|mut it| {
            while let Some(att) = it.next() {
                if att.handle == handle {
                    // If next is CCCD
                    if let Some(next) = it.next() {
                        if let AttributeData::Cccd {
                            notifications: _,
                            indications: _,
                        } = &next.data
                        {
                            return Ok(Characteristic {
                                handle,
                                cccd_handle: Some(next.handle),
                                phantom: PhantomData,
                            });
                        } else {
                            return Ok(Characteristic {
                                handle,
                                cccd_handle: None,
                                phantom: PhantomData,
                            });
                        }
                    } else {
                        return Ok(Characteristic {
                            handle,
                            cccd_handle: None,
                            phantom: PhantomData,
                        });
                    }
                }
            }
            Err(Error::NotFound)
        })
    }
}

/// Handle to an attribute in the attribute table.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AttributeHandle {
    pub(crate) handle: u16,
}

impl From<u16> for AttributeHandle {
    fn from(handle: u16) -> Self {
        Self { handle }
    }
}

/// Builder for constructing GATT service definitions.
pub struct ServiceBuilder<'r, 'd, M: RawMutex, const MAX: usize> {
    handle: AttributeHandle,
    start: usize,
    table: &'r mut AttributeTable<'d, M, MAX>,
}

impl<'r, 'd, M: RawMutex, const MAX: usize> ServiceBuilder<'r, 'd, M, MAX> {
    fn add_characteristic_internal<T: GattValue>(
        &mut self,
        uuid: Uuid,
        props: CharacteristicProps,
        data: AttributeData<'d>,
    ) -> CharacteristicBuilder<'_, 'd, T, M, MAX> {
        // First the characteristic declaration
        let next = self.table.handle + 1;
        let cccd = self.table.handle + 2;
        self.table.push(Attribute {
            uuid: CHARACTERISTIC_UUID16,
            handle: 0,
            last_handle_in_group: 0,
            data: AttributeData::Declaration {
                props,
                handle: next,
                uuid: uuid.clone(),
            },
            on_read: None,
            on_write: None,
        });

        // Then the value declaration
        self.table.push(Attribute {
            uuid,
            handle: 0,
            last_handle_in_group: 0,
            data,
            on_read: None,
            on_write: None,
        });

        // Add optional CCCD handle
        let cccd_handle = if props.any(&[CharacteristicProp::Notify, CharacteristicProp::Indicate]) {
            self.table.push(Attribute {
                uuid: CHARACTERISTIC_CCCD_UUID16,
                handle: 0,
                last_handle_in_group: 0,
                data: AttributeData::Cccd {
                    notifications: false,
                    indications: false,
                },
                on_read: None,
                on_write: None,
            });
            Some(cccd)
        } else {
            None
        };

        CharacteristicBuilder {
            handle: Characteristic {
                handle: next,
                cccd_handle,
                phantom: PhantomData,
            },
            table: self.table,
        }
    }

    /// Add a characteristic to this service with a refererence to a mutable storage buffer.
    pub fn add_characteristic<T: GattValue, U: Into<Uuid>>(
        &mut self,
        uuid: U,
        props: &[CharacteristicProp],
        storage: &'d mut [u8],
    ) -> CharacteristicBuilder<'_, 'd, T, M, MAX> {
        let props = props.into();
        self.add_characteristic_internal(uuid.into(), props, AttributeData::Data { props, value: storage })
    }

    /// Add a characteristic to this service with a refererence to an immutable storage buffer.
    pub fn add_characteristic_ro<T: GattValue, U: Into<Uuid>>(
        &mut self,
        uuid: U,
        value: &'d T,
    ) -> CharacteristicBuilder<'_, 'd, T, M, MAX> {
        let props = [CharacteristicProp::Read].into();
        self.add_characteristic_internal(
            uuid.into(),
            props,
            AttributeData::ReadOnlyData {
                props,
                value: value.to_gatt(),
            },
        )
    }

    /// Add a callback to be triggered when the attribute is read
    pub fn set_read_callback(&mut self, on_read: fn(&Connection)) {
        self.table.set_read_callback(self.handle.handle, on_read);
    }

    /// Finish construction of the service and return a handle.
    pub fn build(self) -> AttributeHandle {
        self.handle
    }
}

impl<'r, 'd, M: RawMutex, const MAX: usize> Drop for ServiceBuilder<'r, 'd, M, MAX> {
    fn drop(&mut self) {
        let last_handle = self.table.handle + 1;
        self.table.with_inner(|inner| {
            for item in inner.attributes[self.start..inner.len].iter_mut() {
                item.as_mut().unwrap().last_handle_in_group = last_handle;
            }
        });

        // Jump to next 16-aligned
        self.table.handle = self.table.handle + (0x10 - (self.table.handle % 0x10));
    }
}

/// A characteristic in the attribute table.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Characteristic<T: GattValue> {
    pub(crate) cccd_handle: Option<u16>,
    /// Handle value assigned to this characteristic when it is added to the Gatt Attribute Table
    pub handle: u16,
    pub(crate) phantom: PhantomData<T>,
}

/// Builder for characteristics.
pub struct CharacteristicBuilder<'r, 'd, T: GattValue, M: RawMutex, const MAX: usize> {
    handle: Characteristic<T>,
    table: &'r mut AttributeTable<'d, M, MAX>,
}

impl<'r, 'd, T: GattValue, M: RawMutex, const MAX: usize> CharacteristicBuilder<'r, 'd, T, M, MAX> {
    fn add_descriptor_internal(
        &mut self,
        uuid: Uuid,
        props: CharacteristicProps,
        data: AttributeData<'d>,
        on_read: Option<fn(&Connection)>,
        on_write: Option<WriteCallback>,
    ) -> DescriptorHandle {
        let handle = self.table.handle;
        self.table.push(Attribute {
            uuid,
            handle: 0,
            last_handle_in_group: 0,
            data,
            on_read,
            on_write,
        });

        DescriptorHandle { handle }
    }

    /// Add a characteristic descriptor for this characteristic.
    pub fn add_descriptor<U: Into<Uuid>>(
        &mut self,
        uuid: U,
        props: &[CharacteristicProp],
        data: &'d mut [u8],
        on_read: Option<fn(&Connection)>,
        on_write: Option<WriteCallback>,
    ) -> DescriptorHandle {
        let props = props.into();
        self.add_descriptor_internal(
            uuid.into(),
            props,
            AttributeData::Data { props, value: data },
            on_read,
            on_write,
        )
    }

    /// Add a read only characteristic descriptor for this characteristic.
    pub fn add_descriptor_ro<U: Into<Uuid>>(
        &mut self,
        uuid: U,
        data: &'d [u8],
        on_read: Option<fn(&Connection)>,
    ) -> DescriptorHandle {
        let props = [CharacteristicProp::Read].into();
        self.add_descriptor_internal(
            uuid.into(),
            props,
            AttributeData::ReadOnlyData { props, value: data },
            on_read,
            None,
        )
    }

    /// Add a callback to be triggered when a read event occurs
    pub fn set_read_callback(&mut self, on_read: fn(&Connection)) {
        self.table.set_read_callback(self.handle.handle, on_read);
    }

    /// Add a callback to be triggered when a write event occurs
    pub fn set_write_callback(&mut self, on_write: WriteCallback) {
        self.table.set_write_callback(self.handle.handle, on_write)
    }

    /// Return the built characteristic.
    pub fn build(self) -> Characteristic<T> {
        self.handle
    }
}

/// Characteristic descriptor handle.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Clone, Copy, Debug)]
pub struct DescriptorHandle {
    pub(crate) handle: u16,
}

/// Iterator over attributes.
pub struct AttributeIterator<'a, 'd> {
    attributes: &'a mut [Option<Attribute<'d>>],
    pos: usize,
    len: usize,
}

impl<'a, 'd> AttributeIterator<'a, 'd> {
    /// Return next attribute in iterator.
    pub fn next<'m>(&'m mut self) -> Option<&'m mut Attribute<'d>> {
        if self.pos < self.len {
            let i = self.attributes[self.pos].as_mut();
            self.pos += 1;
            i
        } else {
            None
        }
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
#[derive(Clone, Copy)]
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

impl<const T: usize> From<[CharacteristicProp; T]> for CharacteristicProps {
    fn from(props: [CharacteristicProp; T]) -> Self {
        let mut val: u8 = 0;
        for prop in props {
            val |= prop as u8;
        }
        CharacteristicProps(val)
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
}

/// A value of an attribute.
pub struct AttributeValue<'d, M: RawMutex> {
    value: Mutex<M, &'d mut [u8]>,
}

impl<'d, M: RawMutex> AttributeValue<'d, M> {}

/// CCCD flag values.
#[derive(Clone, Copy)]
pub enum CCCDFlag {
    /// Notifications enabled.
    Notify = 0x1,
    /// Indications enabled.
    Indicate = 0x2,
}

/// CCCD flag.
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

impl CCCD {
    /// Check if any of the properties are set.
    pub fn any(&self, props: &[CCCDFlag]) -> bool {
        for p in props {
            if (*p as u16) & self.0 != 0 {
                return true;
            }
        }
        false
    }
}

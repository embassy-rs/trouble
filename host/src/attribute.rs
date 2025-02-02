//! Attribute protocol implementation.
use core::cell::RefCell;
use core::fmt;
use core::marker::PhantomData;

use bt_hci::uuid::declarations::{CHARACTERISTIC, PRIMARY_SERVICE};
use bt_hci::uuid::descriptors::CLIENT_CHARACTERISTIC_CONFIGURATION;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::blocking_mutex::Mutex;

use crate::att::AttErrorCode;
use crate::attribute_server::AttributeServer;
use crate::cursor::{ReadCursor, WriteCursor};
use crate::prelude::Connection;
use crate::types::gatt_traits::GattValue;
pub use crate::types::uuid::Uuid;
use crate::Error;
use heapless::Vec;

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
}

impl<'a> Attribute<'a> {
    const EMPTY: Option<Attribute<'a>> = None;

    pub(crate) fn read(&self, offset: usize, data: &mut [u8]) -> Result<usize, AttErrorCode> {
        if !self.data.readable() {
            return Err(AttErrorCode::READ_NOT_PERMITTED);
        }
        self.data.read(offset, data)
    }

    pub(crate) fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), AttErrorCode> {
        if !self.data.writable() {
            return Err(AttErrorCode::WRITE_NOT_PERMITTED);
        }

        self.data.write(offset, data)
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
        variable_len: bool,
        len: u16,
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

impl AttributeData<'_> {
    pub(crate) fn readable(&self) -> bool {
        match self {
            Self::Data { props, .. } => props.0 & (CharacteristicProp::Read as u8) != 0,
            _ => true,
        }
    }

    pub(crate) fn writable(&self) -> bool {
        match self {
            Self::Data { props, .. } => {
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
            return Err(AttErrorCode::READ_NOT_PERMITTED);
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
            Self::Data {
                props,
                value,
                variable_len,
                len,
            } => {
                let value = &value[..*len as usize];
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
                    return Err(AttErrorCode::INVALID_OFFSET);
                }
                if data.len() < 2 {
                    return Err(AttErrorCode::UNLIKELY_ERROR);
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
            Self::Data {
                value,
                props,
                variable_len,
                len,
            } => {
                if !writable {
                    return Err(AttErrorCode::WRITE_NOT_PERMITTED);
                }

                if offset + data.len() <= value.len() {
                    value[offset..offset + data.len()].copy_from_slice(data);
                    *len = (offset + data.len()) as u16;
                    Ok(())
                } else {
                    Err(AttErrorCode::INVALID_OFFSET)
                }
            }
            Self::Cccd {
                notifications,
                indications,
            } => {
                if offset > 0 {
                    return Err(AttErrorCode::INVALID_OFFSET);
                }

                if data.is_empty() {
                    return Err(AttErrorCode::UNLIKELY_ERROR);
                }

                *notifications = data[0] & 0x01 != 0;
                *indications = data[0] & 0x02 != 0;
                Ok(())
            }
            _ => Err(AttErrorCode::WRITE_NOT_PERMITTED),
        }
    }

    pub(crate) fn decode_declaration(data: &[u8]) -> Result<Self, Error> {
        let mut r = ReadCursor::new(data);
        Ok(Self::Declaration {
            props: CharacteristicProps(r.read()?),
            handle: r.read()?,
            uuid: Uuid::try_from(r.remaining())?,
        })
    }
}

impl fmt::Debug for Attribute<'_> {
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
    pub(crate) fn new(uuid: Uuid, data: AttributeData<'a>) -> Attribute<'a> {
        Attribute {
            uuid,
            handle: 0,
            data,
            last_handle_in_group: 0xffff,
        }
    }
}

/// A table of attributes.
pub struct AttributeTable<'d, M: RawMutex, const MAX: usize> {
    inner: Mutex<M, RefCell<InnerTable<'d, MAX>>>,
    handle: u16,
}

pub(crate) struct InnerTable<'d, const MAX: usize> {
    attributes: Vec<Attribute<'d>, MAX>,
}

impl<'d, const MAX: usize> InnerTable<'d, MAX> {
    fn push(&mut self, attribute: Attribute<'d>) {
        self.attributes.push(attribute).unwrap();
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
            handle: 1,
            inner: Mutex::new(RefCell::new(InnerTable { attributes: Vec::new() })),
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
            let it = AttributeIterator {
                attributes: &mut table.attributes[..],
                pos: 0,
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
        let len = self.inner.lock(|i| i.borrow().attributes.len());
        let handle = self.handle;
        self.push(Attribute {
            uuid: PRIMARY_SERVICE.into(),
            handle: 0,
            last_handle_in_group: 0,
            data: AttributeData::Service { uuid: service.uuid },
        });
        ServiceBuilder {
            handle: AttributeHandle { handle },
            start: len,
            table: self,
        }
    }

    pub(crate) fn set_raw(&self, attribute: u16, input: &[u8]) -> Result<(), Error> {
        self.iterate(|mut it| {
            while let Some(att) = it.next() {
                if att.handle == attribute {
                    if let AttributeData::Data {
                        props: _,
                        value,
                        variable_len,
                        len,
                    } = &mut att.data
                    {
                        if value.len() == input.len() {
                            value.copy_from_slice(input);
                            return Ok(());
                        } else if *variable_len && input.len() <= value.len() {
                            value[..input.len()].copy_from_slice(input);
                            *len = input.len() as u16;
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

    /// Set the value of a characteristic
    ///
    /// The provided data must exactly match the size of the storage for the characteristic,
    /// otherwise this function will panic.
    ///
    /// If the characteristic for the handle cannot be found, or the shape of the data does not match the type of the characterstic,
    /// an error is returned
    pub fn set<T: GattValue>(&self, characteristic: &Characteristic<T>, input: &T) -> Result<(), Error> {
        let gatt_value = input.to_gatt();
        self.set_raw(characteristic.handle, gatt_value)
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
                    if let AttributeData::Data {
                        props,
                        value,
                        variable_len,
                        len,
                    } = &mut att.data
                    {
                        let value = if *variable_len { &value[..*len as usize] } else { value };
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

impl<'d, M: RawMutex, const MAX: usize> ServiceBuilder<'_, 'd, M, MAX> {
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
            uuid: CHARACTERISTIC.into(),
            handle: 0,
            last_handle_in_group: 0,
            data: AttributeData::Declaration {
                props,
                handle: next,
                uuid: uuid.clone(),
            },
        });

        // Then the value declaration
        self.table.push(Attribute {
            uuid,
            handle: 0,
            last_handle_in_group: 0,
            data,
        });

        // Add optional CCCD handle
        let cccd_handle = if props.any(&[CharacteristicProp::Notify, CharacteristicProp::Indicate]) {
            self.table.push(Attribute {
                uuid: CLIENT_CHARACTERISTIC_CONFIGURATION.into(),
                handle: 0,
                last_handle_in_group: 0,
                data: AttributeData::Cccd {
                    notifications: false,
                    indications: false,
                },
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
        value: T,
        store: &'d mut [u8],
    ) -> CharacteristicBuilder<'_, 'd, T, M, MAX> {
        let props = props.into();
        let bytes = value.to_gatt();
        store[..bytes.len()].copy_from_slice(bytes);
        let variable_len = T::MAX_SIZE != T::MIN_SIZE;
        let len = bytes.len() as u16;
        self.add_characteristic_internal(
            uuid.into(),
            props,
            AttributeData::Data {
                props,
                value: store,
                variable_len,
                len,
            },
        )
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

    /// Finish construction of the service and return a handle.
    pub fn build(self) -> AttributeHandle {
        self.handle
    }
}

impl<M: RawMutex, const MAX: usize> Drop for ServiceBuilder<'_, '_, M, MAX> {
    fn drop(&mut self) {
        let last_handle = self.table.handle + 1;
        self.table.with_inner(|inner| {
            for item in inner.attributes[self.start..].iter_mut() {
                item.last_handle_in_group = last_handle;
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
    /// Handle value assigned to the Client Characteristic Configuration Descriptor (if any)
    pub cccd_handle: Option<u16>,
    /// Handle value assigned to this characteristic when it is added to the Gatt Attribute Table
    pub handle: u16,
    pub(crate) phantom: PhantomData<T>,
}

impl<T: GattValue> Characteristic<T> {
    /// Write a value to a characteristic, and notify a connection with the new value of the characteristic.
    ///
    /// If the provided connection has not subscribed for this characteristic, it will not be notified.
    ///
    /// If the characteristic does not support notifications, an error is returned.
    pub async fn notify<M: RawMutex, const MAX: usize>(
        &self,
        server: &AttributeServer<'_, M, MAX>,
        connection: &Connection<'_>,
        value: &T,
    ) -> Result<(), Error> {
        let value = value.to_gatt();
        server.table().set_raw(self.handle, value)?;

        let cccd_handle = self.cccd_handle.ok_or(Error::NotFound)?;

        if !server.should_notify(connection, cccd_handle) {
            // No reason to fail?
            return Ok(());
        }

        let mut tx = connection.alloc_tx()?;
        let mut w = WriteCursor::new(tx.as_mut());
        let (mut header, mut data) = w.split(4)?;
        data.write(crate::att::ATT_HANDLE_VALUE_NTF)?;
        data.write(self.handle)?;
        data.append(value)?;

        header.write(data.len() as u16)?;
        header.write(4_u16)?;
        let total = header.len() + data.len();

        let pdu = crate::pdu::Pdu::new(tx, total);
        connection.send(pdu).await;
        Ok(())
    }

    /// Set the value of the characteristic in the provided attribute server.
    pub fn set<M: RawMutex, const MAX: usize>(
        &self,
        server: &AttributeServer<'_, M, MAX>,
        value: &T,
    ) -> Result<(), Error> {
        let value = value.to_gatt();
        server.table().set_raw(self.handle, value)?;
        Ok(())
    }

    /// Read the value of the characteristic.
    ///
    /// If the characteristic for the handle cannot be found, an error is returned.
    ///
    pub fn get<M: RawMutex, const MAX: usize>(&self, server: &AttributeServer<'_, M, MAX>) -> Result<T, Error> {
        server.table().get(self)
    }
}

/// Builder for characteristics.
pub struct CharacteristicBuilder<'r, 'd, T: GattValue, M: RawMutex, const MAX: usize> {
    handle: Characteristic<T>,
    table: &'r mut AttributeTable<'d, M, MAX>,
}

impl<'d, T: GattValue, M: RawMutex, const MAX: usize> CharacteristicBuilder<'_, 'd, T, M, MAX> {
    fn add_descriptor_internal(
        &mut self,
        uuid: Uuid,
        props: CharacteristicProps,
        data: AttributeData<'d>,
    ) -> DescriptorHandle {
        let handle = self.table.handle;
        self.table.push(Attribute {
            uuid,
            handle: 0,
            last_handle_in_group: 0,
            data,
        });

        DescriptorHandle { handle }
    }

    /// Add a characteristic descriptor for this characteristic.
    pub fn add_descriptor<U: Into<Uuid>>(
        &mut self,
        uuid: U,
        props: &[CharacteristicProp],
        data: &'d mut [u8],
    ) -> DescriptorHandle {
        let props = props.into();
        let len = data.len() as u16;
        self.add_descriptor_internal(
            uuid.into(),
            props,
            AttributeData::Data {
                props,
                value: data,
                variable_len: false,
                len,
            },
        )
    }

    /// Add a read only characteristic descriptor for this characteristic.
    pub fn add_descriptor_ro<U: Into<Uuid>>(&mut self, uuid: U, data: &'d [u8]) -> DescriptorHandle {
        let props = [CharacteristicProp::Read].into();
        self.add_descriptor_internal(uuid.into(), props, AttributeData::ReadOnlyData { props, value: data })
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
    attributes: &'a mut [Attribute<'d>],
    pos: usize,
}

impl<'d> AttributeIterator<'_, 'd> {
    /// Return next attribute in iterator.
    pub fn next<'m>(&'m mut self) -> Option<&'m mut Attribute<'d>> {
        if self.pos < self.attributes.len() {
            let i = &mut self.attributes[self.pos];
            self.pos += 1;
            Some(i)
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

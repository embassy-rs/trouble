//! Attribute protocol implementation.
use core::cell::RefCell;
use core::fmt;
use core::marker::PhantomData;

use bt_hci::uuid::declarations::{CHARACTERISTIC, PRIMARY_SERVICE};
use bt_hci::uuid::descriptors::CLIENT_CHARACTERISTIC_CONFIGURATION;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::blocking_mutex::Mutex;
use heapless::Vec;

use crate::att::{AttErrorCode, AttUns};
use crate::attribute_server::AttributeServer;
use crate::cursor::{ReadCursor, WriteCursor};
use crate::prelude::{AsGatt, FixedGattValue, FromGatt, GattConnection};
use crate::types::gatt_traits::FromGattError;
pub use crate::types::uuid::Uuid;
use crate::{gatt, Error, PacketPool, MAX_INVALID_DATA_LEN};

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

/// Attribute metadata.
pub struct Attribute<'a> {
    pub(crate) uuid: Uuid,
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

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AttributeData<'d> {
    Service {
        uuid: Uuid,
        last_handle_in_group: u16,
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
    SmallData {
        props: CharacteristicProps,
        variable_len: bool,
        capacity: u8,
        len: u8,
        value: [u8; 8],
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
            Self::Data { props, .. } | Self::SmallData { props, .. } => props.0 & (CharacteristicProp::Read as u8) != 0,
            _ => true,
        }
    }

    pub(crate) fn writable(&self) -> bool {
        match self {
            Self::Data { props, .. } | Self::SmallData { props, .. } => {
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
            Self::ReadOnlyData { value, .. } => {
                if offset > value.len() {
                    return Ok(0);
                }
                let len = data.len().min(value.len() - offset);
                if len > 0 {
                    data[..len].copy_from_slice(&value[offset..offset + len]);
                }
                Ok(len)
            }
            Self::Data { len, value, .. } => {
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
            Self::SmallData { len, value, .. } => {
                let value = &value[..*len as usize];
                let len = data.len().min(value.len().saturating_sub(offset));
                if len > 0 {
                    data[..len].copy_from_slice(&value[offset..offset + len]);
                }
                Ok(len)
            }
            Self::Service { uuid, .. } => {
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
                variable_len,
                len,
                ..
            } => {
                if !writable {
                    return Err(AttErrorCode::WRITE_NOT_PERMITTED);
                }

                if offset + data.len() <= value.len() {
                    value[offset..offset + data.len()].copy_from_slice(data);
                    if *variable_len {
                        *len = (offset + data.len()) as u16;
                    }
                    Ok(())
                } else {
                    Err(AttErrorCode::INVALID_OFFSET)
                }
            }
            Self::SmallData {
                variable_len,
                capacity,
                len,
                value,
                ..
            } => {
                if !writable {
                    return Err(AttErrorCode::WRITE_NOT_PERMITTED);
                }

                if offset + data.len() <= *capacity as usize {
                    value[offset..offset + data.len()].copy_from_slice(data);
                    if *variable_len {
                        *len = (offset + data.len()) as u8;
                    }
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
        Attribute { uuid, data }
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

    pub(crate) fn with_inner<F: FnOnce(&mut InnerTable<'d, MAX>) -> R, R>(&self, f: F) -> R {
        self.inner.lock(|inner| {
            let mut table = inner.borrow_mut();
            f(&mut table)
        })
    }

    pub(crate) fn iterate<F: FnOnce(AttributeIterator<'_, 'd>) -> R, R>(&self, f: F) -> R {
        self.with_inner(|table| {
            let it = AttributeIterator {
                attributes: table.attributes.as_mut_slice(),
                pos: 0,
            };
            f(it)
        })
    }

    pub(crate) fn with_attribute<F: FnOnce(&mut Attribute<'d>) -> R, R>(&self, handle: u16, f: F) -> Option<R> {
        if handle == 0 {
            return None;
        }

        self.with_inner(|table| {
            let i = usize::from(handle) - 1;
            table.attributes.get_mut(i).map(f)
        })
    }

    pub(crate) fn iterate_from<F: FnOnce(AttributeIterator<'_, 'd>) -> R, R>(&self, start: u16, f: F) -> R {
        self.with_inner(|table| {
            let it = AttributeIterator {
                attributes: &mut table.attributes[..],
                pos: usize::from(start).saturating_sub(1),
            };
            f(it)
        })
    }

    fn push(&mut self, attribute: Attribute<'d>) -> u16 {
        self.with_inner(|table| table.push(attribute))
    }

    /// Add a service to the attribute table (group of characteristics)
    pub fn add_service(&mut self, service: Service) -> ServiceBuilder<'_, 'd, M, MAX> {
        let handle = self.push(Attribute {
            uuid: PRIMARY_SERVICE.into(),
            data: AttributeData::Service {
                uuid: service.uuid,
                last_handle_in_group: 0,
            },
        });
        ServiceBuilder { handle, table: self }
    }

    pub(crate) fn set_ro(&self, attribute: u16, new_value: &'d [u8]) -> Result<(), Error> {
        self.with_attribute(attribute, |att| match &mut att.data {
            AttributeData::ReadOnlyData { value, .. } => {
                *value = new_value;
                Ok(())
            }
            _ => Err(Error::NotSupported),
        })
        .unwrap_or(Err(Error::NotFound))
    }

    pub(crate) fn set_raw(&self, attribute: u16, input: &[u8]) -> Result<(), Error> {
        self.with_attribute(attribute, |att| match &mut att.data {
            AttributeData::Data {
                value,
                variable_len,
                len,
                ..
            } => {
                let expected_len = value.len();
                let actual_len = input.len();

                if expected_len == actual_len {
                    value.copy_from_slice(input);
                    Ok(())
                } else if *variable_len && actual_len <= expected_len {
                    value[..input.len()].copy_from_slice(input);
                    *len = input.len() as u16;
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

                if expected_len == actual_len {
                    value[..expected_len].copy_from_slice(input);
                    Ok(())
                } else if *variable_len && actual_len <= expected_len {
                    value[..input.len()].copy_from_slice(input);
                    *len = input.len() as u8;
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

    /// Set the value of a characteristic
    ///
    /// The provided data must exactly match the size of the storage for the characteristic,
    /// otherwise this function will panic.
    ///
    /// If the characteristic for the handle cannot be found, or the shape of the data does not match the type of the characterstic,
    /// an error is returned
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
            let value_slice = match &mut att.data {
                AttributeData::Data { value, len, .. } => &value[..*len as usize],
                AttributeData::ReadOnlyData { value, .. } => value,
                AttributeData::SmallData { len, value, .. } => &value[..usize::from(*len)],
                _ => return Err(Error::NotSupported),
            };

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
        self.iterate_from(handle, |mut it| {
            if let Some(att) = it.next() {
                let cccd_handle = it
                    .next()
                    .and_then(|(handle, att)| matches!(att.data, AttributeData::Cccd { .. }).then_some(handle));

                Ok(Characteristic {
                    handle,
                    cccd_handle,
                    phantom: PhantomData,
                })
            } else {
                Err(Error::NotFound)
            }
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

        self.iterate(|mut it| {
            while let Some((handle, att)) = it.next() {
                match att.uuid {
                    PRIMARY_SERVICE
                    | SECONDARY_SERVICE
                    | INCLUDED_SERVICE
                    | CHARACTERISTIC
                    | CHARACTERISTIC_EXTENDED_PROPERTIES => {
                        mac.update(handle.to_le_bytes()).update(att.uuid.as_raw());
                        match &att.data {
                            AttributeData::ReadOnlyData { value, .. } => {
                                mac.update(value);
                            }
                            AttributeData::Data { len, value, .. } => {
                                mac.update(&value[..usize::from(*len)]);
                            }
                            AttributeData::Service { uuid, .. } => {
                                mac.update(uuid.as_raw());
                            }
                            AttributeData::Declaration { props, handle, uuid } => {
                                mac.update([props.0]).update(handle.to_le_bytes()).update(uuid.as_raw());
                            }
                            _ => unreachable!(),
                        }
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
        data: AttributeData<'d>,
    ) -> CharacteristicBuilder<'_, 'd, T, M, MAX> {
        // First the characteristic declaration
        let (handle, cccd_handle) = self.table.with_inner(|table| {
            let value_handle = table.next_handle() + 1;
            table.push(Attribute {
                uuid: CHARACTERISTIC.into(),
                data: AttributeData::Declaration {
                    props,
                    handle: value_handle,
                    uuid: uuid.clone(),
                },
            });

            // Then the value declaration
            let h = table.push(Attribute { uuid, data });
            debug_assert!(h == value_handle);

            // Add optional CCCD handle
            let cccd_handle = if props.any(&[CharacteristicProp::Notify, CharacteristicProp::Indicate]) {
                let handle = table.push(Attribute {
                    uuid: CLIENT_CHARACTERISTIC_CONFIGURATION.into(),
                    data: AttributeData::Cccd {
                        notifications: false,
                        indications: false,
                    },
                });

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
                phantom: PhantomData,
            },
            table: self.table,
        }
    }

    /// Add a characteristic to this service with a refererence to a mutable storage buffer.
    pub fn add_characteristic<T: AsGatt, U: Into<Uuid>>(
        &mut self,
        uuid: U,
        props: &[CharacteristicProp],
        value: T,
        store: &'d mut [u8],
    ) -> CharacteristicBuilder<'_, 'd, T, M, MAX> {
        let props = props.into();
        let bytes = value.as_gatt();
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

    /// Add a characteristic to this service using inline storage. The characteristic value must be 8 bytes or less.
    pub fn add_characteristic_small<T: AsGatt, U: Into<Uuid>>(
        &mut self,
        uuid: U,
        props: &[CharacteristicProp],
        value: T,
    ) -> CharacteristicBuilder<'_, 'd, T, M, MAX> {
        assert!(T::MAX_SIZE <= 8);

        let props = props.into();
        let bytes = value.as_gatt();
        let mut value = [0; 8];
        value[..bytes.len()].copy_from_slice(bytes);
        let variable_len = T::MAX_SIZE != T::MIN_SIZE;
        let capacity = T::MAX_SIZE as u8;
        let len = bytes.len() as u8;
        self.add_characteristic_internal(
            uuid.into(),
            props,
            AttributeData::SmallData {
                props,
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
        let props = [CharacteristicProp::Read].into();
        self.add_characteristic_internal(
            uuid.into(),
            props,
            AttributeData::ReadOnlyData {
                props,
                value: value.as_gatt(),
            },
        )
    }

    /// Finish construction of the service and return a handle.
    pub fn build(self) -> u16 {
        self.handle
    }
}

impl<M: RawMutex, const MAX: usize> Drop for ServiceBuilder<'_, '_, M, MAX> {
    fn drop(&mut self) {
        self.table.with_inner(|inner| {
            let last_handle = inner.next_handle() - 1;

            let i = usize::from(self.handle - 1);
            let AttributeData::Service {
                last_handle_in_group, ..
            } = &mut inner.attributes[i].data
            else {
                unreachable!()
            };

            *last_handle_in_group = last_handle;
        });
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
        let connection = connection.raw();
        if !server.should_notify(connection, cccd_handle) {
            // No reason to fail?
            return Ok(());
        }

        let uns = AttUns::Notify {
            handle: self.handle,
            data: value,
        };
        let pdu = gatt::assemble(connection, crate::att::AttServer::Unsolicited(uns))?;
        connection.send(pdu).await;
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
        let connection = connection.raw();
        if !server.should_indicate(connection, cccd_handle) {
            // No reason to fail?
            return Ok(());
        }

        let uns = AttUns::Indicate {
            handle: self.handle,
            data: value,
        };
        let pdu = gatt::assemble(connection, crate::att::AttServer::Unsolicited(uns))?;
        connection.send(pdu).await;
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

    /// Returns the attribute handle for the characteristic's properties (if available)
    pub fn cccd_handle(&self) -> Option<CharacteristicPropertiesHandle> {
        self.cccd_handle.map(CharacteristicPropertiesHandle)
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

impl<'d, T: AsGatt + ?Sized, M: RawMutex, const MAX: usize> CharacteristicBuilder<'_, 'd, T, M, MAX> {
    fn add_descriptor_internal<DT: AsGatt + ?Sized>(&mut self, uuid: Uuid, data: AttributeData<'d>) -> Descriptor<DT> {
        let handle = self.table.push(Attribute { uuid, data });

        Descriptor {
            handle,
            phantom: PhantomData,
        }
    }

    /// Add a characteristic descriptor for this characteristic.
    pub fn add_descriptor<DT: AsGatt, U: Into<Uuid>>(
        &mut self,
        uuid: U,
        props: &[CharacteristicProp],
        value: DT,
        store: &'d mut [u8],
    ) -> Descriptor<DT> {
        let props = props.into();
        let bytes = value.as_gatt();
        store[..bytes.len()].copy_from_slice(bytes);
        let variable_len = DT::MAX_SIZE != DT::MIN_SIZE;
        let len = bytes.len() as u16;
        self.add_descriptor_internal(
            uuid.into(),
            AttributeData::Data {
                props,
                value: store,
                variable_len,
                len,
            },
        )
    }

    /// Add a characteristic to this service using inline storage. The descriptor value must be 8 bytes or less.
    pub fn add_descriptor_small<DT: AsGatt, U: Into<Uuid>>(
        &mut self,
        uuid: U,
        props: &[CharacteristicProp],
        value: DT,
    ) -> Descriptor<DT> {
        assert!(DT::MAX_SIZE <= 8);

        let props = props.into();
        let bytes = value.as_gatt();
        let mut value = [0; 8];
        value[..bytes.len()].copy_from_slice(bytes);
        let variable_len = T::MAX_SIZE != T::MIN_SIZE;
        let capacity = T::MAX_SIZE as u8;
        let len = bytes.len() as u8;
        self.add_descriptor_internal(
            uuid.into(),
            AttributeData::SmallData {
                props,
                variable_len,
                capacity,
                len,
                value,
            },
        )
    }

    /// Add a read only characteristic descriptor for this characteristic.
    pub fn add_descriptor_ro<DT: AsGatt + ?Sized, U: Into<Uuid>>(&mut self, uuid: U, data: &'d DT) -> Descriptor<DT> {
        let props = [CharacteristicProp::Read].into();
        self.add_descriptor_internal(
            uuid.into(),
            AttributeData::ReadOnlyData {
                props,
                value: data.as_gatt(),
            },
        )
    }

    /// Return the built characteristic.
    pub fn build(self) -> Characteristic<T> {
        self.handle
    }
}

/// Characteristic descriptor handle.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Clone, Copy, Debug)]
pub struct Descriptor<T: AsGatt + ?Sized> {
    pub(crate) handle: u16,
    phantom: PhantomData<T>,
}

impl<T: AsGatt> AttributeHandle for Descriptor<T> {
    type Value = T;

    fn handle(&self) -> u16 {
        self.handle
    }
}

impl<T: AsGatt + ?Sized> Descriptor<T> {
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
    attributes: &'a mut [Attribute<'d>],
    pos: usize,
}

impl<'d> AttributeIterator<'_, 'd> {
    /// Return next attribute in iterator.
    pub fn next<'m>(&'m mut self) -> Option<(u16, &'m mut Attribute<'d>)> {
        if self.pos < self.attributes.len() {
            let att = &mut self.attributes[self.pos];
            self.pos += 1;
            let handle = self.pos as u16;
            Some((handle, att))
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

        // GAP service (handles 0x001 - 0x005)
        table.push(Attribute::new(
            PRIMARY_SERVICE.into(),
            AttributeData::Service { uuid: GAP.into() },
        ));

        let expected = 0xd4cdec10804db3f147b4d7d10baa0120;
        let actual = table.hash();
        assert_eq!(
            actual, expected,
            "\nexpected: {:#032x}\nactual: {:#032x}",
            expected, actual
        );

        // Device name characteristic
        table.push(Attribute::new(
            CHARACTERISTIC.into(),
            AttributeData::Declaration {
                props: [CharacteristicProp::Read].as_slice().into(),
                handle: 0x0003,
                uuid: DEVICE_NAME.into(),
            },
        ));

        table.push(Attribute::new(
            DEVICE_NAME.into(),
            AttributeData::ReadOnlyData {
                props: [CharacteristicProp::Read].as_slice().into(),
                value: b"",
            },
        ));

        // Appearance characteristic
        table.push(Attribute::new(
            CHARACTERISTIC.into(),
            AttributeData::Declaration {
                props: [CharacteristicProp::Read].as_slice().into(),
                handle: 0x0005,
                uuid: APPEARANCE.into(),
            },
        ));

        table.push(Attribute::new(
            APPEARANCE.into(),
            AttributeData::ReadOnlyData {
                props: [CharacteristicProp::Read].as_slice().into(),
                value: b"",
            },
        ));

        let expected = 0x6c329e3f1d52c03f174980f6b4704875;
        let actual = table.hash();
        assert_eq!(
            actual, expected,
            "\nexpected: {:#032x}\n  actual: {:#032x}",
            expected, actual
        );

        // GATT service (handles 0x006 - 0x000d)
        table.push(Attribute::new(
            PRIMARY_SERVICE.into(),
            AttributeData::Service { uuid: GATT.into() },
        ));

        // Service changed characteristic
        table.push(Attribute::new(
            CHARACTERISTIC.into(),
            AttributeData::Declaration {
                props: [CharacteristicProp::Indicate].as_slice().into(),
                handle: 0x0008,
                uuid: SERVICE_CHANGED.into(),
            },
        ));

        table.push(Attribute::new(
            SERVICE_CHANGED.into(),
            AttributeData::ReadOnlyData {
                props: [CharacteristicProp::Indicate].as_slice().into(),
                value: b"",
            },
        ));

        table.push(Attribute::new(
            CLIENT_CHARACTERISTIC_CONFIGURATION.into(),
            AttributeData::Cccd {
                notifications: false,
                indications: false,
            },
        ));

        // Client supported features characteristic
        table.push(Attribute::new(
            CHARACTERISTIC.into(),
            AttributeData::Declaration {
                props: [CharacteristicProp::Read, CharacteristicProp::Write].as_slice().into(),
                handle: 0x000b,
                uuid: CLIENT_SUPPORTED_FEATURES.into(),
            },
        ));

        table.push(Attribute::new(
            CLIENT_SUPPORTED_FEATURES.into(),
            AttributeData::ReadOnlyData {
                props: [CharacteristicProp::Read].as_slice().into(),
                value: b"",
            },
        ));

        // Database hash characteristic
        table.push(Attribute::new(
            CHARACTERISTIC.into(),
            AttributeData::Declaration {
                props: [CharacteristicProp::Read].as_slice().into(),
                handle: 0x000d,
                uuid: DATABASE_HASH.into(),
            },
        ));

        table.push(Attribute::new(
            DATABASE_HASH.into(),
            AttributeData::ReadOnlyData {
                props: [CharacteristicProp::Read].as_slice().into(),
                value: b"",
            },
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
        table.push(Attribute::new(
            PRIMARY_SERVICE.into(),
            AttributeData::Service {
                uuid: CUSTOM_SERVICE.into(),
            },
        ));

        // Custom characteristic
        table.push(Attribute::new(
            CHARACTERISTIC.into(),
            AttributeData::Declaration {
                props: [CharacteristicProp::Notify, CharacteristicProp::Read].as_slice().into(),
                handle: 0x0010,
                uuid: CUSTOM_CHARACTERISTIC.into(),
            },
        ));

        table.push(Attribute::new(
            CUSTOM_CHARACTERISTIC.into(),
            AttributeData::ReadOnlyData {
                props: [CharacteristicProp::Notify, CharacteristicProp::Read].as_slice().into(),
                value: b"",
            },
        ));

        table.push(Attribute::new(
            CLIENT_CHARACTERISTIC_CONFIGURATION.into(),
            AttributeData::Cccd {
                notifications: false,
                indications: false,
            },
        ));

        table.push(Attribute::new(
            CHARACTERISTIC_USER_DESCRIPTION.into(),
            AttributeData::ReadOnlyData {
                props: CharacteristicProps(0),
                value: b"Custom Characteristic",
            },
        ));

        table.push(Attribute::new(
            CHARACTERISTIC_PRESENTATION_FORMAT.into(),
            AttributeData::ReadOnlyData {
                props: CharacteristicProps(0),
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
}

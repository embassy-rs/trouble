//! Attribute protocol implementation.
use core::fmt;

use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::mutex::{Mutex, MutexGuard};

use crate::att::AttErrorCode;
use crate::attribute_server::AttrHandler;
use crate::cursor::{ReadCursor, WriteCursor};
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

/// Attribute metadata.
pub struct Attribute {
    pub(crate) uuid: Uuid,
    pub(crate) handle: u16,
    pub(crate) last_handle_in_group: u16,
    pub(crate) data: AttributeData,
}

impl Attribute {
    const EMPTY: Option<Attribute> = None;
}

pub(crate) struct AttrDataHandler<'a, T> {
    uuid: &'a Uuid,
    handle: u16,
    handler: T,
}

impl<'a, T> AttrDataHandler<'a, T>
where
    T: AttrHandler,
{
    pub(crate) const fn new(rw: T, uuid: &'a Uuid, handle: u16) -> Self {
        AttrDataHandler {
            uuid,
            handle,
            handler: rw,
        }
    }

    pub(crate) async fn read(&mut self, offset: usize, data: &mut [u8]) -> Result<usize, AttErrorCode> {
        self.handler.read(self.uuid, self.handle, offset, data).await
    }

    pub(crate) async fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), AttErrorCode> {
        self.handler.write(self.uuid, self.handle, offset, data).await
    }
}

pub(crate) enum AttributeData {
    Service {
        uuid: Uuid,
    },
    ReadOnlyData {
        props: CharacteristicProps,
    },
    Data {
        props: CharacteristicProps,
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

impl AttributeData {
    pub(crate) fn readable(&self) -> bool {
        match self {
            Self::Data { props } => props.0 & (CharacteristicProp::Read as u8) != 0,
            _ => true,
        }
    }

    pub(crate) fn writable(&self) -> bool {
        match self {
            Self::Data { props } => {
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

    pub(crate) async fn read<T>(
        &self,
        offset: usize,
        data: &mut [u8],
        read: &mut AttrDataHandler<'_, T>,
    ) -> Result<usize, AttErrorCode>
    where
        T: AttrHandler,
    {
        if !self.readable() {
            return Err(AttErrorCode::ReadNotPermitted);
        }
        match self {
            Self::ReadOnlyData { props } | Self::Data { props } => read.read(offset, data).await,
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

    pub(crate) async fn write<T>(
        &mut self,
        offset: usize,
        data: &[u8],
        write: &mut AttrDataHandler<'_, T>,
    ) -> Result<(), AttErrorCode>
    where
        T: AttrHandler,
    {
        let writable = self.writable();

        match self {
            Self::Data { props } => {
                if !writable {
                    return Err(AttErrorCode::WriteNotPermitted);
                }

                write.write(offset, data).await
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

impl fmt::Debug for Attribute {
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
impl defmt::Format for Attribute {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "{}", defmt::Debug2Format(self))
    }
}

impl Attribute {
    pub(crate) const fn new(uuid: Uuid, data: AttributeData) -> Attribute {
        Attribute {
            uuid,
            handle: 0,
            last_handle_in_group: 0xffff,
            data,
        }
    }
}

/// A table of attributes.
pub struct AttributeTable<M: RawMutex, const MAX: usize> {
    inner: Mutex<M, InnerTable<MAX>>,
    handle: u16,
}

pub(crate) struct InnerTable<const MAX: usize> {
    attributes: [Option<Attribute>; MAX],
    len: usize,
}

impl<const MAX: usize> InnerTable<MAX> {
    fn push(&mut self, attribute: Attribute) {
        if self.len == MAX {
            panic!("no space for more attributes")
        }
        self.attributes[self.len].replace(attribute);
        self.len += 1;
    }

    pub(crate) fn attr_iter(&mut self) -> AttributeIterator {
        let len = self.attributes.len();

        AttributeIterator {
            attributes: &mut self.attributes[..],
            pos: 0,
            len,
        }
    }
}

impl<M: RawMutex, const MAX: usize> Default for AttributeTable<M, MAX> {
    fn default() -> Self {
        Self::new()
    }
}

impl<M: RawMutex, const MAX: usize> AttributeTable<M, MAX> {
    /// Create a new GATT table.
    pub const fn new() -> Self {
        Self {
            handle: 1,
            inner: Mutex::new(InnerTable {
                len: 0,
                attributes: [Attribute::EMPTY; MAX],
            }),
        }
    }

    pub(crate) fn with_inner<F: Fn(&mut InnerTable<MAX>)>(&mut self, f: F) {
        // `try_lock` will always succeed since we have a `&mut` ref to ourselves
        let mut table = self.inner.try_lock().unwrap();
        f(&mut table);
    }

    pub(crate) async fn lock(&self) -> MutexGuard<'_, M, InnerTable<MAX>> {
        self.inner.lock().await
    }

    fn push(&mut self, mut attribute: Attribute) -> u16 {
        let handle = self.handle;
        attribute.handle = handle;
        // `try_lock` will always succeed since we have a `&mut` ref to ourselves
        self.inner.try_lock().unwrap().push(attribute);
        self.handle += 1;
        handle
    }

    /// Add a service to the attribute table (group of characteristics)
    pub fn add_service(&mut self, service: Service) -> ServiceBuilder<'_, M, MAX> {
        // `try_lock` will always succeed since we have a `&mut` ref to ourselves
        let len = self.inner.try_lock().unwrap().len;
        let handle = self.handle;
        self.push(Attribute {
            uuid: PRIMARY_SERVICE_UUID16,
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

    pub(crate) async fn find_characteristic_by_value_handle(&self, handle: u16) -> Result<Characteristic, Error> {
        let mut table = self.lock().await;
        let mut it = table.attr_iter();

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
                        });
                    } else {
                        return Ok(Characteristic {
                            handle,
                            cccd_handle: None,
                        });
                    }
                } else {
                    return Ok(Characteristic {
                        handle,
                        cccd_handle: None,
                    });
                }
            }
        }

        Err(Error::NotFound)
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
pub struct ServiceBuilder<'r, M: RawMutex, const MAX: usize> {
    handle: AttributeHandle,
    start: usize,
    table: &'r mut AttributeTable<M, MAX>,
}

impl<'r, M: RawMutex, const MAX: usize> ServiceBuilder<'r, M, MAX> {
    fn add_characteristic_internal(
        &mut self,
        uuid: Uuid,
        props: CharacteristicProps,
        data: AttributeData,
    ) -> CharacteristicBuilder<'_, M, MAX> {
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
                uuid: CHARACTERISTIC_CCCD_UUID16,
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
            },
            table: self.table,
        }
    }

    /// Add a characteristic to this service with a refererence to a mutable storage buffer.
    pub fn add_characteristic<U: Into<Uuid>>(
        &mut self,
        uuid: U,
        props: &[CharacteristicProp],
    ) -> CharacteristicBuilder<'_, M, MAX> {
        let props = props.into();
        self.add_characteristic_internal(uuid.into(), props, AttributeData::Data { props })
    }

    /// Add a characteristic to this service with a refererence to an immutable storage buffer.
    pub fn add_characteristic_ro<U: Into<Uuid>>(&mut self, uuid: U) -> CharacteristicBuilder<'_, M, MAX> {
        let props = [CharacteristicProp::Read].into();
        self.add_characteristic_internal(uuid.into(), props, AttributeData::ReadOnlyData { props })
    }

    /// Finish construction of the service and return a handle.
    pub fn build(self) -> AttributeHandle {
        self.handle
    }
}

impl<'r, M: RawMutex, const MAX: usize> Drop for ServiceBuilder<'r, M, MAX> {
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
pub struct Characteristic {
    pub(crate) cccd_handle: Option<u16>,
    pub(crate) handle: u16,
}

/// Builder for characteristics.
pub struct CharacteristicBuilder<'r, M: RawMutex, const MAX: usize> {
    handle: Characteristic,
    table: &'r mut AttributeTable<M, MAX>,
}

impl<'r, M: RawMutex, const MAX: usize> CharacteristicBuilder<'r, M, MAX> {
    fn add_descriptor_internal(
        &mut self,
        uuid: Uuid,
        props: CharacteristicProps,
        data: AttributeData,
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
    pub fn add_descriptor<U: Into<Uuid>>(&mut self, uuid: U, props: &[CharacteristicProp]) -> DescriptorHandle {
        let props = props.into();
        self.add_descriptor_internal(uuid.into(), props, AttributeData::Data { props })
    }

    /// Add a read only characteristic descriptor for this characteristic.
    pub fn add_descriptor_ro<U: Into<Uuid>>(&mut self, uuid: U) -> DescriptorHandle {
        let props = [CharacteristicProp::Read].into();
        self.add_descriptor_internal(uuid.into(), props, AttributeData::ReadOnlyData { props })
    }

    /// Return the built characteristic.
    pub fn build(self) -> Characteristic {
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
pub struct AttributeIterator<'a> {
    attributes: &'a mut [Option<Attribute>],
    pos: usize,
    len: usize,
}

impl<'a> AttributeIterator<'a> {
    /// Return next attribute in iterator.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<&mut Attribute> {
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

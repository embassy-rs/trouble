mod consts;
mod data;
pub mod server;
pub use consts::*;
pub use data::*;

use core::cell::RefCell;
use core::fmt;

use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::blocking_mutex::Mutex;

pub use crate::types::uuid::Uuid;
use crate::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
/// An enum of possible characteristic properties
///
/// Ref: BLUETOOTH CORE SPECIFICATION Version 6.0, Vol 3, Part G, Section 3.3.1.1 Characteristic Properties
pub enum CharacteristicProp {
    /// Permit broadcast of the Characteristic Value
    ///
    /// If set, permits broadcasts of the Characteristic Value using Server Characteristic
    /// Configuration Descriptor.
    Broadcast = 0x01,
    /// Permit read of the Characteristic Value
    Read = 0x02,
    /// Permit writes to the Characteristic Value without response
    WriteWithoutResponse = 0x04,
    /// Permit writes to the Characteristic Value
    Write = 0x08,
    /// Permit notification of a Characteristic Value without acknowledgment
    Notify = 0x10,
    /// Permit indication of a Characteristic Value with acknowledgment
    Indicate = 0x20,
    /// Permit signed writes to the Characteristic Value
    AuthenticatedWrite = 0x40,
    /// Permit writes to the Characteristic Value without response
    Extended = 0x80,
}

#[derive(PartialEq, Eq)]
pub struct Attribute<'d> {
    /// Attribute type UUID
    ///
    /// Do not mistake it with Characteristic UUID
    pub uuid: Uuid,
    /// Handle for the Attribute
    ///
    /// In case of a push, this value is ignored and set to the
    /// next available handle value in the attribute table.
    pub handle: u16,
    /// Last handle value in the group
    ///
    /// When a [`ServiceBuilder`] finishes building, it returns the handle for the service, but also
    pub(crate) last_handle_in_group: u16,
    pub data: AttributeData<'d>,
}

impl<'d> Attribute<'d> {
    const EMPTY: Option<Attribute<'d>> = None;
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
    pub fn new(uuid: Uuid, data: AttributeData<'a>) -> Attribute<'a> {
        Attribute {
            uuid,
            handle: 0,
            data,
            last_handle_in_group: u16::MAX,
        }
    }
}

/// Table of Attributes available to the [`crate::gatt::GattServer`].
pub struct AttributeTable<'d, M: RawMutex, const MAX: usize> {
    inner: Mutex<M, RefCell<InnerTable<'d, MAX>>>,

    /// Next available attribute handle value known by this table
    next_handle: u16,
}

/// Inner representation of [`AttributeTable`]
///
/// Represented by a stack allocated list of attributes with a len field to keep track of how many are actually present.
// TODO: Switch to heapless Vec
#[derive(Debug, PartialEq, Eq)]
pub struct InnerTable<'d, const MAX: usize> {
    attributes: [Option<Attribute<'d>>; MAX],

    /// Amount of attributes in the list.
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
    /// Create an empty table
    pub fn new() -> Self {
        Self {
            next_handle: 1,
            inner: Mutex::new(RefCell::new(InnerTable {
                len: 0,
                attributes: [Attribute::EMPTY; MAX],
            })),
        }
    }

    pub fn with_inner<F: Fn(&mut InnerTable<'d, MAX>)>(&self, f: F) {
        self.inner.lock(|inner| {
            let mut table = inner.borrow_mut();
            f(&mut table);
        })
    }

    pub fn iterate<F: FnMut(AttributeIterator<'_, 'd>) -> R, R>(&self, mut f: F) -> R {
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

    /// Push into the table a given attribute.
    ///
    /// Returns the attribute handle.
    fn push(&mut self, mut attribute: Attribute<'d>) -> u16 {
        let handle = self.next_handle;
        attribute.handle = handle;
        self.inner.lock(|inner| {
            let mut inner = inner.borrow_mut();
            inner.push(attribute);
        });
        self.next_handle += 1;
        handle
    }

    /// Create a service with a given UUID and return the [`ServiceBuilder`].
    ///
    /// Note: The service builder is tied to the AttributeTable.
    pub fn add_service(&mut self, service: Service) -> ServiceBuilder<'_, 'd, M, MAX> {
        let len = self.inner.lock(|i| i.borrow().len);
        let handle = self.next_handle;
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

    /// Set the value of a characteristic
    ///
    /// The provided data must exactly match the size of the storage for the characteristic,
    /// otherwise this function will panic.
    ///
    /// If the characteristic for the handle cannot be found, an error is returned.
    pub fn set(&self, handle: Characteristic, input: &[u8]) -> Result<(), Error> {
        self.iterate(|mut it| {
            while let Some(att) = it.next() {
                if att.handle == handle.handle {
                    if let AttributeData::Data { props, value } = &mut att.data {
                        assert_eq!(value.len(), input.len());
                        value.copy_from_slice(input);
                        return Ok(());
                    }
                }
            }
            Err(Error::NotFound)
        })
    }

    /// Read the value of the characteristic and pass the value to the provided closure
    ///
    /// The return value of the closure is returned in this function and is assumed to be infallible.
    ///
    /// If the characteristic for the handle cannot be found, an error is returned.
    pub fn get<F: FnMut(&[u8]) -> T, T>(&self, handle: Characteristic, mut f: F) -> Result<T, Error> {
        self.iterate(|mut it| {
            while let Some(att) = it.next() {
                if att.handle == handle.handle {
                    if let AttributeData::Data { props, value } = &mut att.data {
                        let v = f(value);
                        return Ok(v);
                    }
                }
            }
            Err(Error::NotFound)
        })
    }

    pub(crate) fn find_characteristic_by_value_handle(&self, handle: u16) -> Result<Characteristic, Error> {
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
        })
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttributeHandle {
    pub(crate) handle: u16,
}

impl From<u16> for AttributeHandle {
    fn from(handle: u16) -> Self {
        Self { handle }
    }
}

/// Builder type for creating a Service inside a given AttributeTable
pub struct ServiceBuilder<'r, 'd, M: RawMutex, const MAX: usize> {
    handle: AttributeHandle,
    start: usize,
    table: &'r mut AttributeTable<'d, M, MAX>,
}

impl<'r, 'd, M: RawMutex, const MAX: usize> ServiceBuilder<'r, 'd, M, MAX> {
    fn add_characteristic_internal(
        &mut self,
        uuid: Uuid,
        props: CharacteristicProps,
        data: AttributeData<'d>,
    ) -> Characteristic {
        // First the characteristic declaration
        let next = self.table.next_handle + 1;
        let cccd = self.table.next_handle + 2;
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

        Characteristic {
            handle: next,
            cccd_handle,
        }
    }

    pub fn add_characteristic<U: Into<Uuid>>(
        &mut self,
        uuid: U,
        props: &[CharacteristicProp],
        storage: &'d mut [u8],
    ) -> Characteristic {
        let props = props.into();
        self.add_characteristic_internal(uuid.into(), props, AttributeData::Data { props, value: storage })
    }

    pub fn add_characteristic_ro<U: Into<Uuid>>(&mut self, uuid: U, value: &'d [u8]) -> Characteristic {
        let props = [CharacteristicProp::Read].into();
        self.add_characteristic_internal(uuid.into(), props, AttributeData::ReadOnlyData { props, value })
    }

    pub fn build(self) -> AttributeHandle {
        self.handle
    }
}

impl<'r, 'd, M: RawMutex, const MAX: usize> Drop for ServiceBuilder<'r, 'd, M, MAX> {
    fn drop(&mut self) {
        let last_handle = self.table.next_handle + 1;
        self.table.with_inner(|inner| {
            for item in inner.attributes[self.start..inner.len].iter_mut() {
                item.as_mut().unwrap().last_handle_in_group = last_handle;
            }
        });

        // Jump to next 16-aligned
        self.table.next_handle = self.table.next_handle + (0x10 - (self.table.next_handle % 0x10));
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Characteristic {
    pub(crate) cccd_handle: Option<u16>,
    pub(crate) handle: u16,
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Clone, Copy, Debug)]
pub struct DescriptorHandle {
    pub(crate) handle: u16,
}

pub struct AttributeIterator<'a, 'd> {
    attributes: &'a mut [Option<Attribute<'d>>],
    pos: usize,
    len: usize,
}

impl<'a, 'd> AttributeIterator<'a, 'd> {
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

/// Service information.
///
/// Currently only has UUID.
#[derive(Clone, Debug)]
pub struct Service {
    pub uuid: Uuid,
}

impl Service {
    pub fn new<U: Into<Uuid>>(uuid: U) -> Self {
        Self { uuid: uuid.into() }
    }
}

/// A bitfield of [`CharacteristicProp`].
///
/// See the [`From`] implementation for this struct. Props are applied in order they are given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
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
    fn any(&self, props: &[CharacteristicProp]) -> bool {
        for p in props {
            if (*p as u8) & self.0 != 0 {
                return true;
            }
        }
        false
    }
}

pub struct AttributeValue<'d, M: RawMutex> {
    value: Mutex<M, &'d mut [u8]>,
}

impl<'d, M: RawMutex> AttributeValue<'d, M> {}

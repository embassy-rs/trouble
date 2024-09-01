mod consts;
mod data;
pub mod server;
pub use consts::*;
pub use data::*;
use heapless::Vec;

use core::cell::RefCell;
use core::fmt;
use core::ops::ControlFlow;

use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::blocking_mutex::Mutex;

use crate::att::AttErrorCode;
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
    inner: Mutex<M, RefCell<Vec<Attribute<'d>, MAX>>>,

    /// Next available attribute handle value known by this table
    next_handle: u16,
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
            inner: Mutex::new(RefCell::new(Vec::new())),
        }
    }

    pub fn with_inner<F: FnMut(&mut [Attribute<'d>])>(&self, mut f: F) {
        self.inner.lock(|inner| {
            let mut table = inner.borrow_mut();
            f(&mut table);
        })
    }

    /// Take a closure and call it with a mutable iterator over attributes.
    ///
    /// Returns whatever the given function returned.
    pub fn iterate<F: FnOnce(core::slice::IterMut<'_, Attribute<'d>>) -> R, R>(&self, f: F) -> R {
        self.inner.lock(|inner| {
            let mut table = inner.borrow_mut();
            f(table.iter_mut())
        })
    }

    /// Call a function **once** if an attribute with a given handle has been found, returning its output.
    ///
    /// Returns `R` if the handle was found, [`AttErrorCode::AttributeNotFound`] otherwise.
    ///
    /// `condition` function takes a borrow of a [`Attribute`]. If it returns `Some(...)`,
    /// a mutable reference to the same [`Attribute`] value gets passed to the main function `f`.
    ///
    /// Returns a [`Result`] with whatever the main function chooses to return
    /// as it's [`Ok`] output, or [`AttErrorCode::AttributeNotFound`] as the [`Err`] output
    /// (as the attribute with the same handle was not found).
    pub fn on_handle<F: FnOnce(&mut Attribute<'d>) -> Result<R, AttErrorCode>, R>(
        &self,
        handle: u16,
        f: F,
    ) -> Result<R, AttErrorCode> {
        self.iterate(|it| {
            for att in it {
                if att.handle == handle {
                    return f(att);
                }
            }
            Err(AttErrorCode::AttributeNotFound)
        })
    }

    /// Call a function **once** if a condition function chooses an attribute to process.
    ///
    /// `condition` function takes a borrow of a [`Attribute`]. If it returns `Some(...)`,
    /// a mutable reference to the same [`Attribute`] value gets passed to the main function `f`.
    ///
    /// Returns a [`Result`] with whatever the main function chooses to return
    /// as it's [`Ok`] output, or [`AttErrorCode`] as the [`Err`] output.
    pub fn on_attribute<
        FCondition: FnMut(&Attribute<'d>) -> Option<RCondition>,
        F: FnOnce(&mut Attribute<'d>, RCondition) -> Result<R, AttErrorCode>,
        R,
        RCondition,
    >(
        &self,
        mut condition: FCondition,
        f: F,
    ) -> Result<R, AttErrorCode> {
        self.iterate(|it| {
            for att in it {
                let res = condition(att);
                if let Some(r_cond_output) = res {
                    return f(att, r_cond_output);
                }
            }
            Err(AttErrorCode::AttributeNotFound)
        })
    }

    /// Call a function every time a condition function chooses to process an attribute, or break.
    ///
    /// `condition` function takes a borrow of a [`Attribute`].
    ///
    /// ## Map of behaviour depending on what `condition` returns:
    ///  
    ///   - `ControlFlow::Continue(Some(RCondition))` - the main function
    ///     gets called with a mutable borrow of an attribute and `RCondition`.
    ///     Execution continues for other attributes.
    ///   - `ControlFlow::Continue(None)` - the main function is not called.
    ///     Execution continues for other attributes.
    ///   - `ControlFlow::Break` - the main function is not called.
    ///     Execution stops.
    ///
    /// Returns a [`Result`] with it's [`Ok`] output being `()` (if you need to keep
    /// some kind of state between `f` runs, just modify stuff outside the closure),
    /// or `E` as the [`Err`] output.
    pub fn for_each_attribute<
        FCondition: FnMut(&Attribute<'d>) -> ControlFlow<(), Option<RCondition>>,
        F: FnMut(&mut Attribute<'d>, RCondition) -> Result<(), E>,
        RCondition,
        E,
    >(
        &self,
        mut condition: FCondition,
        mut f: F,
    ) -> Result<(), E> {
        self.iterate(|it| {
            for att in it {
                let res = condition(att);
                match res {
                    ControlFlow::Continue(r_cond_output) => {
                        if let Some(r_cond_output) = r_cond_output {
                            f(att, r_cond_output)?;
                        }
                    }
                    ControlFlow::Break(_) => break,
                }
            }
            Ok(())
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
            inner.push(attribute).expect("no more space for attributes");
        });
        self.next_handle += 1;
        handle
    }

    /// Create a service with a given UUID and return the [`ServiceBuilder`].
    ///
    /// Note: The service builder is tied to the AttributeTable.
    pub fn add_service(&mut self, service: Service) -> ServiceBuilder<'_, 'd, M, MAX> {
        let len = self.inner.lock(|i| i.borrow().len());
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
        self.iterate(|it| {
            for att in it {
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
    pub fn get<F: Fn(&[u8]) -> T, T>(&self, handle: Characteristic, f: F) -> Result<T, Error> {
        self.iterate(|it| {
            for att in it {
                if att.handle == handle.handle {
                    if let AttributeData::Data { props, value } = &att.data {
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
                uuid,
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
            for item in inner[self.start..].iter_mut() {
                item.last_handle_in_group = last_handle;
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

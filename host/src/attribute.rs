//! Attribute protocol implementation.
use core::cell::RefCell;
use core::fmt;
use core::marker::PhantomData;

use bt_hci::uuid::declarations::{CHARACTERISTIC, PRIMARY_SERVICE};
use bt_hci::uuid::descriptors::CLIENT_CHARACTERISTIC_CONFIGURATION;
use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::RawMutex;
use heapless::Vec;

use crate::att::{AttErrorCode, AttUns};
use crate::gatt;

use crate::cursor::{ReadCursor, WriteCursor};
use crate::gatt::{AttributeTable, PeerState};
use crate::prelude::{AsGatt, FixedGattValue, FromGatt, GattConnection};
use crate::types::gatt_traits::FromGattError;
pub use crate::types::uuid::Uuid;
use crate::{Error, MAX_INVALID_DATA_LEN, PacketPool};

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

/// A characteristic in the attribute table.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Characteristic<T: AsGatt> {
    /// Handle value assigned to the Client Characteristic Configuration Descriptor (if any)
    pub cccd_handle: Option<u16>,
    /// Handle value assigned to this characteristic when it is added to the Gatt Attribute Table
    pub handle: u16,
    pub(crate) phantom: PhantomData<T>,
}

impl<T: FromGatt> Characteristic<T> {
    /// Notify a connection with the new value of the characteristic.
    ///
    /// If the provided connection has not subscribed for this characteristic, it will not be notified.
    ///
    /// If the characteristic does not support notifications, an error is returned.
    pub async fn notify<P: PacketPool, AT: AttributeTable, C: PeerState>(
        &self,
        connection: &GattConnection<'_, '_, P, AT, C>,
        value: &T,
    ) -> Result<(), Error> {
        let value = value.as_gatt();
        let cccd_handle = self.cccd_handle.ok_or(Error::NotFound)?;
        if !connection.peer().should_notify(cccd_handle) {
            // No reason to fail?
            return Ok(());
        }
        let connection = connection.raw();

        let uns = AttUns::Notify {
            handle: self.handle,
            data: value,
        };
        let pdu = gatt::assemble(connection, crate::att::AttServer::Unsolicited(uns))?;
        connection.send(pdu).await;
        Ok(())
    }

    /// Indicate a connection with the new value of the characteristic.
    ///
    /// If the provided connection has not subscribed for this characteristic, it will not be sent an indication.
    ///
    /// If the characteristic does not support indications, an error is returned.
    ///
    /// This function does not block for the confirmation to the indication message, if the client sends a confirmation
    /// this will be seen on the [GattConnection] as a [crate::att::AttClient::Confirmation] event.
    pub async fn indicate<P: PacketPool, AT: AttributeTable, C: PeerState>(
        &self,
        connection: &GattConnection<'_, '_, P, AT, C>,
        value: &T,
    ) -> Result<(), Error> {
        let value = value.as_gatt();

        let cccd_handle = self.cccd_handle.ok_or(Error::NotFound)?;
        if !connection.peer().should_indicate(cccd_handle) {
            // No reason to fail?
            return Ok(());
        }
        let connection = connection.raw();

        let uns = AttUns::Indicate {
            handle: self.handle,
            data: value,
        };
        let pdu = gatt::assemble(connection, crate::att::AttServer::Unsolicited(uns))?;
        connection.send(pdu).await;
        Ok(())
    }

    /// Returns the attribute handle for the characteristic's properties (if available)
    pub fn cccd_handle(&self) -> Option<CharacteristicPropertiesHandle> {
        self.cccd_handle.map(CharacteristicPropertiesHandle)
    }
}

/// Attribute handle for a characteristic's properties
pub struct CharacteristicPropertiesHandle(u16);

/*
impl AttributeHandle for CharacteristicPropertiesHandle {
    type Value = CharacteristicProps;

    fn handle(&self) -> u16 {
        self.0
    }
}*/

/// Characteristic descriptor handle.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Clone, Copy, Debug)]
pub struct Descriptor<T: AsGatt> {
    pub(crate) handle: u16,
    phantom: PhantomData<T>,
}

/*
impl<T: AsGatt> AttributeHandle for Descriptor<T> {
    type Value = T;

    fn handle(&self) -> u16 {
        self.handle
    }
}*/

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

impl FixedGattValue for CharacteristicProps {
    const SIZE: usize = 1;

    fn from_gatt(data: &[u8]) -> Result<Self, FromGattError> {
        if data.len() != Self::SIZE {
            return Err(FromGattError::InvalidLength);
        }

        Ok(CharacteristicProps(data[0]))
    }

    fn as_gatt(&self) -> &[u8] {
        FixedGattValue::as_gatt(&self.0)
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

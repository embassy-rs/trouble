//! UUID types.

use bt_hci::uuid::BluetoothUuid16;

use crate::codec::{Decode, Encode, Error, Type};

/// A 16-bit or 128-bit UUID.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Clone)]
pub enum Uuid {
    /// 16-bit UUID
    Uuid16([u8; 2]),
    /// 128-bit UUID
    Uuid128([u8; 16]),
}

impl From<BluetoothUuid16> for Uuid {
    fn from(val: bt_hci::uuid::BluetoothUuid16) -> Self {
        Uuid::Uuid16(val.into())
    }
}

impl From<u128> for Uuid {
    fn from(val: u128) -> Self {
        Uuid::Uuid128(val.to_le_bytes())
    }
}

impl From<[u8; 16]> for Uuid {
    fn from(val: [u8; 16]) -> Self {
        Uuid::Uuid128(val)
    }
}

impl From<[u8; 2]> for Uuid {
    fn from(val: [u8; 2]) -> Self {
        Uuid::Uuid16(val)
    }
}

impl Uuid {
    /// Create a new 16-bit UUID.
    pub const fn new_short(val: u16) -> Self {
        Self::Uuid16(val.to_le_bytes())
    }

    /// Create a new 128-bit UUID.
    pub const fn new_long(val: [u8; 16]) -> Self {
        Self::Uuid128(val)
    }

    /// Copy the UUID bytes into a slice.
    pub fn bytes(&self, data: &mut [u8]) {
        match self {
            Uuid::Uuid16(uuid) => data.copy_from_slice(uuid),
            Uuid::Uuid128(uuid) => data.copy_from_slice(uuid),
        }
    }

    /// Get the UUID type.
    pub fn get_type(&self) -> u8 {
        match self {
            Uuid::Uuid16(_) => 0x01,
            Uuid::Uuid128(_) => 0x02,
        }
    }

    pub(crate) fn size(&self) -> usize {
        match self {
            Uuid::Uuid16(_) => 6,
            Uuid::Uuid128(_) => 20,
        }
    }

    /// Get the 16-bit UUID value.
    pub fn as_short(&self) -> u16 {
        match self {
            Uuid::Uuid16(data) => u16::from_le_bytes([data[0], data[1]]),
            _ => panic!("wrong type"),
        }
    }

    /// Get the 128-bit UUID value.
    pub fn as_raw(&self) -> &[u8] {
        match self {
            Uuid::Uuid16(uuid) => uuid,
            Uuid::Uuid128(uuid) => uuid,
        }
    }
}

impl From<u16> for Uuid {
    fn from(data: u16) -> Self {
        Uuid::Uuid16(data.to_le_bytes())
    }
}

impl TryFrom<&[u8]> for Uuid {
    type Error = crate::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match value.len() {
            // Slice length has already been verified, so unwrap can be used
            2 => Ok(Uuid::Uuid16(value.try_into().unwrap())),
            16 => {
                let mut bytes = [0; 16];
                bytes.copy_from_slice(value);
                Ok(Uuid::Uuid128(bytes))
            }
            _ => Err(crate::Error::InvalidValue),
        }
    }
}

impl Type for Uuid {
    fn size(&self) -> usize {
        self.as_raw().len()
    }
}

impl Decode<'_> for Uuid {
    fn decode(src: &[u8]) -> Result<Self, Error> {
        if src.len() < 2 {
            Err(Error::InvalidValue)
        } else {
            let val: u16 = u16::from_le_bytes([src[0], src[1]]);
            // Must be a long id
            if val == 0 {
                if src.len() < 16 {
                    return Err(Error::InvalidValue);
                }
                Ok(Uuid::Uuid128(src[0..16].try_into().map_err(|_| Error::InvalidValue)?))
            } else {
                Ok(Uuid::new_short(val))
            }
        }
    }
}

impl Encode for Uuid {
    fn encode(&self, dest: &mut [u8]) -> Result<(), Error> {
        self.bytes(dest);
        Ok(())
    }
}

//! UUID types.

use bt_hci::uuid::{BluetoothUuid128, BluetoothUuid16, BluetoothUuid32};

use crate::codec::{Decode, Encode, Error, Type};

/// A 16-bit or 128-bit UUID.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Uuid {
    /// 16-bit UUID
    Uuid16([u8; 2]),
    /// 32-bit UUID
    Uuid32([u8; 4]),
    /// 128-bit UUID
    Uuid128([u8; 16]),
}

impl From<BluetoothUuid16> for Uuid {
    fn from(data: bt_hci::uuid::BluetoothUuid16) -> Self {
        Uuid::Uuid16(data.into())
    }
}

impl From<BluetoothUuid32> for Uuid {
    fn from(data: bt_hci::uuid::BluetoothUuid32) -> Self {
        Uuid::Uuid32(data.into())
    }
}

impl From<BluetoothUuid128> for Uuid {
    fn from(data: bt_hci::uuid::BluetoothUuid128) -> Self {
        Uuid::Uuid128(data.into())
    }
}

impl From<u128> for Uuid {
    fn from(data: u128) -> Self {
        Uuid::Uuid128(data.to_le_bytes())
    }
}

impl From<[u8; 16]> for Uuid {
    fn from(data: [u8; 16]) -> Self {
        Uuid::Uuid128(data)
    }
}

impl From<[u8; 4]> for Uuid {
    fn from(data: [u8; 4]) -> Self {
        Uuid::Uuid32(data)
    }
}

impl From<u32> for Uuid {
    fn from(data: u32) -> Self {
        Uuid::Uuid32(data.to_le_bytes())
    }
}

impl From<[u8; 2]> for Uuid {
    fn from(data: [u8; 2]) -> Self {
        Uuid::Uuid16(data)
    }
}

impl From<u16> for Uuid {
    fn from(data: u16) -> Self {
        Uuid::Uuid16(data.to_le_bytes())
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
            Uuid::Uuid32(uuid) => data.copy_from_slice(uuid),
            Uuid::Uuid128(uuid) => data.copy_from_slice(uuid),
        }
    }

    /// Get the ATT Find Information Response format code for the UUID.
    ///
    /// Core Spec Vol 3 Part F, 3.4.3.2 defines only 0x01 (handle + 16-bit UUID pairs) and 0x02
    /// (handle + 128-bit UUID pairs). A 32-bit UUID has no form of its own, so it reports 0x02 and
    /// is written as its 128-bit equivalent; see [`Uuid::att_bytes`].
    pub fn get_att_type(&self) -> u8 {
        match self {
            Uuid::Uuid16(_) => 0x01,
            Uuid::Uuid32(_) | Uuid::Uuid128(_) => 0x02,
        }
    }

    /// The UUID as an ATT Find Information Response carries it, and its length: two bytes under
    /// format 0x01, sixteen under 0x02.
    ///
    /// A 32-bit UUID is expanded against the Bluetooth base UUID, which is the only way the 0x02
    /// [`get_att_type`](Self::get_att_type) reports for it can be honoured on air.
    pub(crate) fn att_bytes(&self) -> ([u8; 16], usize) {
        match self {
            Uuid::Uuid16(uuid) => {
                let mut bytes = [0; 16];
                bytes[..2].copy_from_slice(uuid);
                (bytes, 2)
            }
            Uuid::Uuid32(uuid) => (
                BluetoothUuid128::base()
                    .set_initial_group(u32::from_le_bytes(*uuid))
                    .to_le_bytes(),
                16,
            ),
            Uuid::Uuid128(uuid) => (*uuid, 16),
        }
    }

    pub(crate) fn size(&self) -> usize {
        match self {
            Uuid::Uuid16(_) => 6,
            Uuid::Uuid32(_) => 8,
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
            Uuid::Uuid32(uuid) => uuid,
            Uuid::Uuid128(uuid) => uuid,
        }
    }
}

impl TryFrom<&[u8]> for Uuid {
    type Error = crate::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match value.len() {
            // Slice length has already been verified, so unwrap can be used
            2 => Ok(Uuid::Uuid16(value.try_into().unwrap())),
            4 => Ok(Uuid::Uuid32(value.try_into().unwrap())),
            16 => {
                let mut bytes = [0; 16];
                bytes.copy_from_slice(value);
                Ok(Uuid::Uuid128(bytes))
            }
            _ => Err(crate::Error::InvalidUuidLength(value.len())),
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

use core::{mem, slice};

use bt_hci::uuid::BluetoothUuid16;
use heapless::{String, Vec};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// Error type to signify an issue when converting from GATT bytes to a concrete type
pub enum FromGattError {
    /// Byte array's length did not match what was expected for the converted type
    InvalidLength,
    /// Attempt to encode as string failed due to an invalid character representation in the byte array
    InvalidCharacter,
}

/// Trait to allow conversion of a fixed size type to and from a byte slice
#[allow(private_bounds)]
pub trait FixedGattValue: FromGatt {
    /// Size of the type in bytes
    const SIZE: usize;
}

/// Trait to allow conversion of a type to gatt bytes
pub trait AsGatt {
    /// The minimum size the type might be
    const MIN_SIZE: usize;
    /// The maximum size the type might be
    const MAX_SIZE: usize;
    /// Converts to gatt bytes.
    /// Must return a slice of len in MIN_SIZE..=MAX_SIZE
    fn as_gatt(&self) -> &[u8];
}

/// Trait to allow conversion of gatt bytes into a type
///
/// Requires that the type implements AsGatt
pub trait FromGatt: AsGatt + Sized {
    /// Converts from gatt bytes.
    /// Must return FromGattError::InvalidLength if data.len not in MIN_SIZE..=MAX_SIZE
    fn from_gatt(data: &[u8]) -> Result<Self, FromGattError>;
}

macro_rules! primitive {
    ($($ty:ty),*) => {
        $(
            impl FixedGattValue for $ty {
                const SIZE: usize = mem::size_of::<Self>();
            }

            impl FromGatt for $ty {
                fn from_gatt(data: &[u8]) -> Result<Self, FromGattError> {
                    if data.len() != Self::SIZE {
                        Err(FromGattError::InvalidLength)
                    } else {
                        // SAFETY
                        // - Pointer is considered "valid" as per the rules outlined for validity in std::ptr v1.82.0
                        // - Pointer was generated from a slice of bytes matching the size of the type, and all primitives are valid for all possible configurations of bits
                        // - Primitives are copy
                        unsafe { Ok((data.as_ptr() as *const Self).read_unaligned()) }
                    }
                }
            }

            impl AsGatt for $ty {
                const MIN_SIZE: usize = mem::size_of::<Self>();
                const MAX_SIZE: usize = mem::size_of::<Self>();

                fn as_gatt(&self) -> &[u8] {
                    // SAFETY
                    // - Slice is of type u8 so data is guaranteed valid for reads of any length
                    // - Data and len are tied to the address and size of the type
                    unsafe { slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
                }
            }
        )*
    };
}

primitive!(
    u8,
    u16,
    u32,
    u64,
    u128,
    i8,
    i16,
    i32,
    i64,
    i128,
    f32,
    f64,
    BluetoothUuid16
);

impl FixedGattValue for bool {
    const SIZE: usize = 1;
}

impl FromGatt for bool {
    fn from_gatt(data: &[u8]) -> Result<Self, FromGattError> {
        if data.len() != Self::SIZE {
            Err(FromGattError::InvalidLength)
        } else {
            Ok(data != [0x00])
        }
    }
}

impl AsGatt for bool {
    const MIN_SIZE: usize = Self::SIZE;
    const MAX_SIZE: usize = Self::SIZE;

    fn as_gatt(&self) -> &[u8] {
        match self {
            true => &[0x01],
            false => &[0x00],
        }
    }
}

impl<const N: usize> FromGatt for Vec<u8, N> {
    fn from_gatt(data: &[u8]) -> Result<Self, FromGattError> {
        Self::from_slice(data).map_err(|_| FromGattError::InvalidLength)
    }
}

impl<const N: usize> AsGatt for Vec<u8, N> {
    const MIN_SIZE: usize = 0;
    const MAX_SIZE: usize = N;

    fn as_gatt(&self) -> &[u8] {
        self
    }
}

impl<const N: usize> FromGatt for [u8; N] {
    fn from_gatt(data: &[u8]) -> Result<Self, FromGattError> {
        if data.len() <= Self::MAX_SIZE {
            let mut actual = [0; N];
            actual[..data.len()].copy_from_slice(data);
            Ok(actual)
        } else {
            data.try_into().map_err(|_| FromGattError::InvalidLength)
        }
    }
}

impl<const N: usize> AsGatt for [u8; N] {
    const MIN_SIZE: usize = 0;
    const MAX_SIZE: usize = N;

    fn as_gatt(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<const N: usize> FromGatt for String<N> {
    fn from_gatt(data: &[u8]) -> Result<Self, FromGattError> {
        String::from_utf8(unwrap!(Vec::from_slice(data).map_err(|_| FromGattError::InvalidLength)))
            .map_err(|_| FromGattError::InvalidCharacter)
    }
}

impl<const N: usize> AsGatt for String<N> {
    const MIN_SIZE: usize = 0;
    const MAX_SIZE: usize = N;

    fn as_gatt(&self) -> &[u8] {
        self.as_ref()
    }
}

impl AsGatt for str {
    const MIN_SIZE: usize = 0;

    const MAX_SIZE: usize = usize::MAX;

    fn as_gatt(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsGatt for [u8] {
    const MIN_SIZE: usize = 0;

    const MAX_SIZE: usize = usize::MAX;

    fn as_gatt(&self) -> &[u8] {
        self
    }
}

impl AsGatt for crate::types::uuid::Uuid {
    const MIN_SIZE: usize = 2;
    const MAX_SIZE: usize = 16;

    fn as_gatt(&self) -> &[u8] {
        self.as_raw()
    }
}

impl FromGatt for crate::types::uuid::Uuid {
    fn from_gatt(data: &[u8]) -> Result<Self, FromGattError> {
        Self::try_from(data).map_err(|_| FromGattError::InvalidLength)
    }
}

impl<T: AsGatt + ?Sized> AsGatt for &T {
    const MIN_SIZE: usize = T::MIN_SIZE;

    const MAX_SIZE: usize = T::MAX_SIZE;

    fn as_gatt(&self) -> &[u8] {
        <T as AsGatt>::as_gatt(*self)
    }
}

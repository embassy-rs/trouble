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
pub trait FixedGattValue: Sized {
    /// Size of the type in bytes
    const SIZE: usize;

    /// Converts from gatt bytes.
    /// Must return FromGattError::InvalidLength if data.len != Self::SIZE
    fn from_gatt(data: &[u8]) -> Result<Self, FromGattError>;

    /// Converts to gatt bytes.
    /// Must return a slice of len Self::SIZE
    fn to_gatt(&self) -> &[u8];
}

/// Trait to allow conversion of a type to and from a byte slice
pub trait GattValue: Sized {
    /// The minimum size the type might be
    const MIN_SIZE: usize;
    /// The maximum size the type might be
    const MAX_SIZE: usize;

    /// Converts from gatt bytes.
    /// Must return FromGattError::InvalidLength if data.len not in MIN_SIZE..=MAX_SIZE
    fn from_gatt(data: &[u8]) -> Result<Self, FromGattError>;

    /// Converts to gatt bytes.
    /// Must return a slice of len in MIN_SIZE..=MAX_SIZE
    fn to_gatt(&self) -> &[u8];
}

impl<T: FixedGattValue> GattValue for T {
    const MIN_SIZE: usize = Self::SIZE;
    const MAX_SIZE: usize = Self::SIZE;

    fn from_gatt(data: &[u8]) -> Result<Self, FromGattError> {
        <Self as FixedGattValue>::from_gatt(data)
    }

    fn to_gatt(&self) -> &[u8] {
        <Self as FixedGattValue>::to_gatt(self)
    }
}

trait Primitive: Copy {}
impl Primitive for u8 {}
impl Primitive for u16 {}
impl Primitive for u32 {}
impl Primitive for u64 {}
impl Primitive for i8 {}
impl Primitive for i16 {}
impl Primitive for i32 {}
impl Primitive for i64 {}
impl Primitive for f32 {}
impl Primitive for f64 {}
impl Primitive for BluetoothUuid16 {} // ok as this is just a NewType(u16)
impl Primitive for &'_ str {}

impl<T: Primitive> FixedGattValue for T {
    const SIZE: usize = mem::size_of::<Self>();

    fn from_gatt(data: &[u8]) -> Result<Self, FromGattError> {
        if data.len() != Self::SIZE {
            Err(FromGattError::InvalidLength)
        } else {
            // SAFETY
            // - Pointer is considered "valid" as per the rules outlined for validity in std::ptr v1.82.0
            // - Pointer was generated from a slice of bytes matching the size of the type implementing Primitive, and all types implementing Primitive are valid for all possible configurations of bits
            // - Primitive trait is constrained to require Copy
            unsafe { Ok((data.as_ptr() as *const Self).read_unaligned()) }
        }
    }

    fn to_gatt(&self) -> &[u8] {
        // SAFETY
        // - Slice is of type u8 so data is guaranteed valid for reads of any length
        // - Data and len are tied to the address and size of the type
        unsafe { slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
    }
}

impl FixedGattValue for bool {
    const SIZE: usize = 1;

    fn from_gatt(data: &[u8]) -> Result<Self, FromGattError> {
        if data.len() != Self::SIZE {
            Err(FromGattError::InvalidLength)
        } else {
            Ok(data != [0x00])
        }
    }

    fn to_gatt(&self) -> &[u8] {
        match self {
            true => &[0x01],
            false => &[0x00],
        }
    }
}

impl<const N: usize> GattValue for Vec<u8, N> {
    const MIN_SIZE: usize = 0;
    const MAX_SIZE: usize = N;

    fn from_gatt(data: &[u8]) -> Result<Self, FromGattError> {
        Self::from_slice(data).map_err(|_| FromGattError::InvalidLength)
    }

    fn to_gatt(&self) -> &[u8] {
        self
    }
}

impl<const N: usize> GattValue for [u8; N] {
    const MIN_SIZE: usize = 0;
    const MAX_SIZE: usize = N;

    fn from_gatt(data: &[u8]) -> Result<Self, FromGattError> {
        if data.len() <= Self::MAX_SIZE {
            let mut actual = [0; N];
            actual[..data.len()].copy_from_slice(data);
            Ok(actual)
        } else {
            data.try_into().map_err(|_| FromGattError::InvalidLength)
        }
    }

    fn to_gatt(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<const N: usize> GattValue for String<N> {
    const MIN_SIZE: usize = 0;
    const MAX_SIZE: usize = N;

    fn from_gatt(data: &[u8]) -> Result<Self, FromGattError> {
        String::from_utf8(unwrap!(Vec::from_slice(data).map_err(|_| FromGattError::InvalidLength)))
            .map_err(|_| FromGattError::InvalidCharacter)
    }

    fn to_gatt(&self) -> &[u8] {
        self.as_ref()
    }
}

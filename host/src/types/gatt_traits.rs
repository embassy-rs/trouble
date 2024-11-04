use core::{mem, slice};

use heapless::{String, Vec};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum FromGattError {
    InvalidLength,
    InvalidCharacter,
}

pub trait FixedGattValue: Sized {
    const SIZE: usize;

    // Converts from gatt bytes.
    // Must panic if and only if data.len != Self::SIZE
    fn from_gatt(data: &[u8]) -> Self;

    // Converts to gatt bytes.
    // Must return a slice of len Self::SIZE
    fn to_gatt(&self) -> &[u8];
}

pub trait GattValue: Sized {
    const MIN_SIZE: usize;
    const MAX_SIZE: usize;

    // Converts from gatt bytes.
    // Must panic if and only if data.len not in MIN_SIZE..=MAX_SIZE
    fn from_gatt(data: &[u8]) -> Self;

    // Converts to gatt bytes.
    // Must return a slice of len in MIN_SIZE..=MAX_SIZE
    fn to_gatt(&self) -> &[u8];
}

impl<T: FixedGattValue> GattValue for T {
    const MIN_SIZE: usize = Self::SIZE;
    const MAX_SIZE: usize = Self::SIZE;

    fn from_gatt(data: &[u8]) -> Self {
        <Self as FixedGattValue>::from_gatt(data)
    }

    fn to_gatt(&self) -> &[u8] {
        <Self as FixedGattValue>::to_gatt(self)
    }
}

pub unsafe trait Primitive: Copy {}
unsafe impl Primitive for u8 {}
unsafe impl Primitive for u16 {}
unsafe impl Primitive for u32 {}
unsafe impl Primitive for u64 {}
unsafe impl Primitive for i8 {}
unsafe impl Primitive for i16 {}
unsafe impl Primitive for i32 {}
unsafe impl Primitive for i64 {}
unsafe impl Primitive for f32 {}
unsafe impl Primitive for f64 {}

impl<T: Primitive> FixedGattValue for T {
    const SIZE: usize = mem::size_of::<Self>();

    fn from_gatt(data: &[u8]) -> Self {
        if data.len() != Self::SIZE {
            panic!("Bad len")
        }
        unsafe { (data.as_ptr() as *const Self).read_unaligned() }
    }

    fn to_gatt(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE) }
    }
}

impl FixedGattValue for bool {
    const SIZE: usize = 1;

    fn from_gatt(data: &[u8]) -> Self {
        data != [0x00]
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

    fn from_gatt(data: &[u8]) -> Self {
        unwrap!(Self::from_slice(data))
    }

    fn to_gatt(&self) -> &[u8] {
        &self
    }
}

impl<const N: usize> GattValue for [u8; N] {
    const MIN_SIZE: usize = 0;
    const MAX_SIZE: usize = N;

    fn from_gatt(data: &[u8]) -> Self {
        if data.len() < Self::MAX_SIZE {
            let mut actual = [0; N];
            actual[..data.len()].copy_from_slice(data);
            actual
        } else {
            unwrap!(data.try_into())
        }
    }

    fn to_gatt(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<const N: usize> GattValue for String<N> {
    const MIN_SIZE: usize = 0;
    const MAX_SIZE: usize = N;

    fn from_gatt(data: &[u8]) -> Self {
        unwrap!(
            String::from_utf8(unwrap!(Vec::from_slice(data).map_err(|_| FromGattError::InvalidLength)))
                .map_err(|_| FromGattError::InvalidCharacter)
        )
    }

    fn to_gatt(&self) -> &[u8] {
        self.as_ref()
    }
}

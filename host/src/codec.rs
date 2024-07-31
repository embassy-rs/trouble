//! Opinionated BLE codec
//!
//! Assumes little endian for all types

pub trait FixedSize: Sized {
    const SIZE: usize;
}

pub trait Type: Sized {
    fn size(&self) -> usize;
}

pub trait Encode: Type {
    fn encode(&self, dest: &mut [u8]) -> Result<(), Error>;
}

pub trait Decode<'d>: Type {
    fn decode(src: &'d [u8]) -> Result<Self, Error>;
}

impl<T: FixedSize> Type for T {
    fn size(&self) -> usize {
        Self::SIZE
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy)]
pub enum Error {
    InsufficientSpace,
    InvalidValue,
}

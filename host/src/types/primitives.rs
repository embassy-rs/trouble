use crate::codec::{Decode, Encode, Error, FixedSize};

//
// Implementations for primitives
//
impl FixedSize for u8 {
    const SIZE: usize = 1;
}

impl FixedSize for u16 {
    const SIZE: usize = 2;
}

impl FixedSize for u32 {
    const SIZE: usize = 4;
}

impl Decode<'_> for u8 {
    fn decode(src: &[u8]) -> Result<Self, Error> {
        Ok(src[0])
    }
}

impl Decode<'_> for u16 {
    fn decode(src: &[u8]) -> Result<Self, Error> {
        Ok(u16::from_le_bytes([src[0], src[1]]))
    }
}

impl Decode<'_> for u32 {
    fn decode(src: &[u8]) -> Result<Self, Error> {
        Ok(u32::from_le_bytes([src[0], src[1], src[2], src[3]]))
    }
}

impl Encode for u8 {
    fn encode(&self, dest: &mut [u8]) -> Result<(), Error> {
        dest[0] = *self;
        Ok(())
    }
}

impl Encode for u16 {
    fn encode(&self, dest: &mut [u8]) -> Result<(), Error> {
        dest.copy_from_slice(&self.to_le_bytes()[..]);
        Ok(())
    }
}

impl Encode for u32 {
    fn encode(&self, dest: &mut [u8]) -> Result<(), Error> {
        dest.copy_from_slice(&self.to_le_bytes()[..]);
        Ok(())
    }
}

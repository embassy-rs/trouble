//! BLE UUIDs (16, 32 or 128 bits).
//!
//! Bluetooth assigns UUIDs to identify services and characteristics. In order to save space, many
//! common UUIDs can be represented and transmitted as 16- or 32-bit aliases instead of the full
//! 128 bits.
//!
//! The shorter UUIDs can be converted to their full 128-bit counterparts by making use of the
//! Bluetooth Base UUID, which is defined as `00000000-0000-1000-8000-00805F9B34FB`.
//!
//! A 16-bit UUID alias can be converted to its 32-bit equivalent by zero-extending it: `0xABCD`
//! becomes `0x0000ABCD`.
//!
//! A 32-bit UUID alias can then be converted to its full 128-bit equivalent by placing it in the
//! first 4 Bytes of the Base UUID. Hence `0x1234ABCD` would become
//! `1234ABCD-0000-1000-8000-00805F9B34FB`.

use crate::{bytes::*, Error};
use core::fmt;

/// A 16-bit UUID alias.
///
/// Can be converted to its 32- and 128-bit equivalents via `.into()`.
#[derive(PartialEq, Eq, Copy, Clone)]
pub struct Uuid16(pub u16);

/// A 32-bit UUID alias.
///
/// Can be converted to its 128-bit equivalent via `.into()`.
#[derive(PartialEq, Eq, Copy, Clone)]
pub struct Uuid32(pub u32);

/// A full 128-bit UUID.
#[derive(PartialEq, Eq, Copy, Clone)]
pub struct Uuid128([u8; 16]);

impl Uuid128 {
    const BASE_UUID: Self = Self::parse_static("00000000-0000-1000-8000-00805f9b34fb");

    /// Creates a 128-bit UUID from 16 raw bytes (encoded in big-endian).
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Parses a UUID string literal, panicking when the string is malformed.
    ///
    /// This is meant to be used in constant contexts.
    pub const fn parse_static(s: &'static str) -> Self {
        const fn parse_nibble(nibble: u8) -> u8 {
            let hex_digit_out_of_range = 1;
            match nibble {
                b'0'..=b'9' => nibble - b'0',
                b'a'..=b'f' => nibble - b'a' + 10,
                _ => [0][hex_digit_out_of_range],
            }
        }

        let expected_dash = 1;
        let unexpected_trailing_data = 1;

        // full UUID: 0000fd6f-0000-1000-8000-00805f9b34fb (36 chars/bytes)
        // dashes at offsets 8, 13, 18, 23
        let mut index = 0;
        let mut bytes = [0; 16];

        macro_rules! eat_byte {
            ($s:ident[$i:ident..]) => {{
                let hi = parse_nibble($s.as_bytes()[$i]);
                $i += 1;
                let lo = parse_nibble($s.as_bytes()[$i]);
                $i += 1;
                (hi << 4) | lo
            }};
        }

        macro_rules! eat_dash {
            ($s:ident[$i:ident..]) => {{
                match $s.as_bytes()[$i] {
                    b'-' => {}
                    _ => [()][expected_dash],
                }
                $i += 1;
            }};
        }

        bytes[0] = eat_byte!(s[index..]);
        bytes[1] = eat_byte!(s[index..]);
        bytes[2] = eat_byte!(s[index..]);
        bytes[3] = eat_byte!(s[index..]);
        eat_dash!(s[index..]);
        bytes[4] = eat_byte!(s[index..]);
        bytes[5] = eat_byte!(s[index..]);
        eat_dash!(s[index..]);
        bytes[6] = eat_byte!(s[index..]);
        bytes[7] = eat_byte!(s[index..]);
        eat_dash!(s[index..]);
        bytes[8] = eat_byte!(s[index..]);
        bytes[9] = eat_byte!(s[index..]);
        eat_dash!(s[index..]);
        bytes[10] = eat_byte!(s[index..]);
        bytes[11] = eat_byte!(s[index..]);
        bytes[12] = eat_byte!(s[index..]);
        bytes[13] = eat_byte!(s[index..]);
        bytes[14] = eat_byte!(s[index..]);
        bytes[15] = eat_byte!(s[index..]);

        // String must end here.
        if s.len() > index {
            [()][unexpected_trailing_data];
        }

        Uuid128(bytes)
    }
}

impl From<Uuid16> for Uuid32 {
    fn from(smol: Uuid16) -> Self {
        Uuid32(smol.0.into())
    }
}

impl From<Uuid16> for Uuid128 {
    fn from(uuid: Uuid16) -> Self {
        Uuid32::from(uuid).into()
    }
}

impl From<Uuid32> for Uuid128 {
    fn from(uuid: Uuid32) -> Self {
        let mut buf = Self::BASE_UUID.0;
        buf[..4].copy_from_slice(&uuid.0.to_be_bytes());
        Uuid128(buf)
    }
}

impl ToBytes for Uuid16 {
    fn to_bytes(&self, buffer: &mut ByteWriter<'_>) -> Result<(), Error> {
        buffer.write_slice(&self.0.to_le_bytes())
    }
}

impl ToBytes for Uuid32 {
    fn to_bytes(&self, buffer: &mut ByteWriter<'_>) -> Result<(), Error> {
        buffer.write_slice(&self.0.to_le_bytes())
    }
}

impl ToBytes for Uuid128 {
    fn to_bytes(&self, buffer: &mut ByteWriter<'_>) -> Result<(), Error> {
        buffer.write_slice(&self.0)
    }
}

impl FromBytes<'_> for Uuid16 {
    fn from_bytes(bytes: &mut ByteReader<'_>) -> Result<Self, Error> {
        let array = bytes.read_array()?;
        Ok(Uuid16(u16::from_le_bytes(array)))
    }
}

impl FromBytes<'_> for Uuid32 {
    fn from_bytes(bytes: &mut ByteReader<'_>) -> Result<Self, Error> {
        let array = bytes.read_array()?;
        Ok(Uuid32(u32::from_le_bytes(array)))
    }
}

impl FromBytes<'_> for Uuid128 {
    fn from_bytes(bytes: &mut ByteReader<'_>) -> Result<Self, Error> {
        let array = bytes.read_array()?;
        Ok(Uuid128(array))
    }
}

impl fmt::Debug for Uuid16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Uuid16({:04x})", self.0)
    }
}

impl fmt::Debug for Uuid32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Uuid32({:08x})", self.0)
    }
}

impl fmt::Debug for Uuid128 {
    #[allow(clippy::many_single_char_names, clippy::just_underscores_and_digits)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15] = self.0;
        let a = u32::from_be_bytes([_0, _1, _2, _3]);
        let b = u16::from_be_bytes([_4, _5]);
        let c = u16::from_be_bytes([_6, _7]);
        let d = u16::from_be_bytes([_8, _9]);
        let e = u64::from_be_bytes([0, 0, _10, _11, _12, _13, _14, _15]);
        write!(f, "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}", a, b, c, d, e)
    }
}

impl defmt::Format for Uuid16 {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "Uuid16({=u16:04x})", self.0);
    }
}

impl defmt::Format for Uuid32 {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "Uuid32({=u32:08x})", self.0);
    }
}

impl defmt::Format for Uuid128 {
    #[allow(clippy::many_single_char_names, clippy::just_underscores_and_digits)]
    fn format(&self, f: defmt::Formatter<'_>) {
        let [_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15] = self.0;
        let a = u32::from_be_bytes([_0, _1, _2, _3]);
        let b = u16::from_be_bytes([_4, _5]);
        let c = u16::from_be_bytes([_6, _7]);
        let d = u16::from_be_bytes([_8, _9]);
        let e = u64::from_be_bytes([0, 0, _10, _11, _12, _13, _14, _15]);
        defmt::write!(
            f,
            "{=u32:08x}-{=u16:04x}-{=u16:04x}-{=u16:04x}-{=u64:012x}",
            a,
            b,
            c,
            d,
            e
        );
    }
}

/// List of the supported UUID types.
#[derive(Debug, Copy, Clone, defmt::Format)]
pub enum UuidKind {
    Uuid16,
    Uuid32,
    Uuid128,
}

/// Marker for UUID types.
///
/// This is useful when being generic over the specific type of UUID used. It
/// also brings in the `ToBytes` and `FromBytes` trait bounds that are likely
/// needed as well.
pub trait IsUuid: for<'a> FromBytes<'a> + ToBytes + Copy {
    const KIND: UuidKind;
}

impl IsUuid for Uuid16 {
    const KIND: UuidKind = UuidKind::Uuid16;
}

impl IsUuid for Uuid32 {
    const KIND: UuidKind = UuidKind::Uuid32;
}

impl IsUuid for Uuid128 {
    const KIND: UuidKind = UuidKind::Uuid128;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt() {
        // Check that all leading 0s are printed.
        let uuid = Uuid128::from_bytes([
            0x02, 0x3e, 0x45, 0x67, 0x08, 0x9b, 0x02, 0xd3, 0x04, 0x56, 0x00, 0x66, 0x14, 0x17,
            0x40, 0x00,
        ]);

        assert_eq!(
            format!("{:?}", uuid),
            "023e4567-089b-02d3-0456-006614174000"
        );
    }

    #[test]
    fn convert() {
        let uuid = 0xfd6f; // Apple Inc. / Exposure Notification Service
        let uuid = Uuid128::from(Uuid16(uuid));

        assert_eq!(
            format!("{:?}", uuid),
            "0000fd6f-0000-1000-8000-00805f9b34fb"
        );
    }

    #[test]
    fn parse() {
        let uuid = "0000fd6f-0000-1000-8000-00805f9b34fb";
        assert_eq!(format!("{:?}", Uuid128::parse_static(uuid)), uuid);
    }
}

use core::fmt::{self, Write};
use core::ops::{Add, AddAssign};

/// A 1-bit data packet sequence number.
///
/// This type implements wrapping arithmetic (although only `+` and `+=` operators are supported)
/// matching the expected behaviour of the BLE Link Layer.
#[derive(PartialEq, Eq, Copy, Clone, Default)]
pub struct SeqNum(bool);

impl SeqNum {
    /// A sequence number of 0 (default value).
    pub const ZERO: Self = SeqNum(false);

    /// A sequence number of 1.
    pub const ONE: Self = SeqNum(true);
}

impl fmt::Display for SeqNum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_char(if self.0 { '1' } else { '0' })
    }
}

impl fmt::Debug for SeqNum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as fmt::Display>::fmt(self, f)
    }
}

impl defmt::Format for SeqNum {
    fn format(&self, fmt: defmt::Formatter<'_>) {
        defmt::write!(fmt, "{=char}", if self.0 { '1' } else { '0' });
    }
}

impl Add for SeqNum {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)] // Use of `^` is correct
    fn add(self, rhs: Self) -> Self {
        SeqNum(self.0 ^ rhs.0)
    }
}

impl Add<&'_ SeqNum> for SeqNum {
    type Output = Self;

    fn add(self, rhs: &'_ SeqNum) -> Self {
        self + *rhs
    }
}

impl AddAssign for SeqNum {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl AddAssign<&'_ SeqNum> for SeqNum {
    fn add_assign(&mut self, rhs: &'_ SeqNum) {
        *self = *self + *rhs;
    }
}

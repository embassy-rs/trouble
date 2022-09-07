//! Time APIs for obtaining the current time and calculating with points in time and durations.
//!
//! These APIs are made for the BLE stack and are not meant to be general-purpose. The APIs here
//! have microsecond resolution and use 32-bit arithmetic wherever possible.

use core::fmt;
use core::ops::{Add, AddAssign, Sub, SubAssign};

/// A duration with microsecond resolution.
///
/// This can represent a maximum duration of about 1 hour. Overflows will result in a panic, but
/// shouldn't happen since the BLE stack doesn't deal with durations that large.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Duration(u32);

impl Duration {
    /// The duration of the interframe spacing between BLE packets.
    pub const T_IFS: Self = Duration(150);

    /// Creates a [`Duration`] from a number of microseconds.
    pub fn from_micros(micros: u32) -> Self {
        Duration(micros)
    }

    /// Creates a [`Duration`] representing the given number of milliseconds.
    pub fn from_millis(millis: u16) -> Self {
        Duration(u32::from(millis) * 1_000)
    }

    /// Creates a [`Duration`] representing a number of seconds.
    pub fn from_secs(secs: u16) -> Self {
        Duration(u32::from(secs) * 1_000_000)
    }

    /// Returns the number of whole seconds that fit in `self`.
    pub fn whole_secs(&self) -> u32 {
        self.0 / 1_000_000
    }

    /// Returns the number of whole milliseconds that fit in `self`.
    pub fn whole_millis(&self) -> u32 {
        self.0 / 1_000
    }

    /// Returns the number of microseconds represented by `self`.
    pub fn as_micros(&self) -> u32 {
        self.0
    }

    /// Returns the fractional part of microseconds in `self`.
    pub fn subsec_micros(&self) -> u32 {
        self.0 % 1_000_000
    }
}

impl Add for Duration {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Duration(self.0.checked_add(rhs.0).expect("duration overflow"))
    }
}

impl Add<&'_ Self> for Duration {
    type Output = Duration;

    fn add(self, rhs: &'_ Self) -> Self {
        self + *rhs
    }
}

impl AddAssign for Duration {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for Duration {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Duration(self.0.checked_sub(rhs.0).expect("duration underflow"))
    }
}

impl Sub<&'_ Self> for Duration {
    type Output = Self;

    fn sub(self, rhs: &'_ Self) -> Self {
        self - *rhs
    }
}

impl SubAssign for Duration {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 >= 1_000_000 {
            // s
            let (secs, subsec_micros) = (self.whole_secs(), self.subsec_micros());
            if subsec_micros == 0 {
                write!(f, "{}s", secs)
            } else {
                write!(f, "{}.{:06}s", secs, subsec_micros)
            }
        } else if self.0 >= 1000 {
            // ms
            let (millis, submilli_micros) = (self.whole_millis(), self.0 % 1000);
            if submilli_micros == 0 {
                write!(f, "{}ms", millis)
            } else {
                write!(f, "{}.{:03}ms", millis, submilli_micros)
            }
        } else {
            // µs
            write!(f, "{}µs", self.0)
        }
    }
}

impl fmt::Debug for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as fmt::Display>::fmt(self, f)
    }
}

impl defmt::Format for Duration {
    fn format(&self, fmt: defmt::Formatter<'_>) {
        defmt::write!(fmt, "{=u32:µs}s", self.0);
    }
}

/// A point in time, relative to an unspecfied epoch.
///
/// This has microsecond resolution and may wrap around after >1 hour. Apart from the wraparound, it
/// is monotonic.
///
/// `Instant`s are obtained from an implementation of [`Timer`]. `Instant`s created from different
/// [`Timer`] instances (even when using the same implementation) are not compatible, and mixing
/// them in operations causes unspecified results. [`Duration`]s are independent of the [`Timer`]
/// implementation and thus can be mixed freely.
#[derive(Copy, Clone)]
pub struct Instant(u32);

impl Instant {
    /// The maximum time between two `Instant`s that can be handled by [`Instant::duration_since`].
    ///
    /// This is defined to be a value of a few minutes, intended to be sufficient for the BLE stack.
    pub const MAX_TIME_BETWEEN: Duration = Duration(1_000_000 * 60 * 5); // 5 minutes

    /// Creates an `Instant` from raw microseconds since an arbitrary implementation-defined
    /// reference point.
    ///
    /// This should only be called from a [`Timer`] implementation.
    ///
    /// [`Timer`]: trait.Timer.html
    pub fn from_raw_micros(micros: u32) -> Self {
        Instant(micros)
    }

    /// Returns the raw value from which this `Instant` was created.
    ///
    /// This should only be called from a [`Timer`] implementation.
    ///
    /// [`Timer`]: trait.Timer.html
    pub fn raw_micros(&self) -> u32 {
        self.0
    }

    /// Calculates the duration of time that has passed between `earlier` and `self`.
    ///
    /// The maximum duration that can be calculated by this method is defined as
    /// [`Instant::MAX_TIME_BETWEEN`]. Calling this method when the `Instant`s are further apart is
    /// an error and may panic. This is done as a safeguard, since `Instant`s can wrap around,
    /// which can cause the result of this function to be incorrect. It does not prevent that
    /// from happening, but makes unexpected durations show up much earlier.
    ///
    /// Both `self` and `earlier` must have been created by the same [`Timer`], or the result of
    /// this function will be unspecified.
    pub fn duration_since(&self, earlier: Instant) -> Duration {
        let micros_passed = self.0.wrapping_sub(earlier.0);
        debug_assert!(
            micros_passed <= Self::MAX_TIME_BETWEEN.0,
            "{}µs between instants {} and {}",
            micros_passed,
            earlier,
            self
        );

        Duration(micros_passed)
    }
}

/// [`Instant`]s can be subtracted, which computes the [`Duration`] between the rhs and lhs using
/// [`Instant::duration_since`].
impl Sub<Instant> for Instant {
    type Output = Duration;

    fn sub(self, rhs: Self) -> Duration {
        self.duration_since(rhs)
    }
}

/// A [`Duration`] can be added to an [`Instant`], moving the [`Instant`] forwards in time.
impl Add<Duration> for Instant {
    type Output = Self;

    fn add(self, d: Duration) -> Self {
        Instant(self.0.wrapping_add(d.as_micros()))
    }
}

impl AddAssign<Duration> for Instant {
    fn add_assign(&mut self, d: Duration) {
        *self = *self + d;
    }
}

/// A [`Duration`] can be subtracted from an [`Instant`], moving the [`Instant`] backwards in time.
impl Sub<Duration> for Instant {
    type Output = Self;

    fn sub(self, d: Duration) -> Self {
        Instant(self.0.wrapping_sub(d.as_micros()))
    }
}

/// Subtracts a [`Duration`] from `self`.
impl SubAssign<Duration> for Instant {
    fn sub_assign(&mut self, d: Duration) {
        *self = *self - d;
    }
}

impl fmt::Display for Instant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 >= 1_000_000 {
            // s
            let (secs, subsec_micros) = (self.0 / 1_000_000, self.0 % 1_000_000);
            if subsec_micros == 0 {
                write!(f, "{}s", secs)
            } else {
                write!(f, "{}.{:06}s", secs, subsec_micros)
            }
        } else if self.0 >= 1000 {
            // ms
            let (millis, submilli_micros) = (self.0 / 1000, self.0 % 1000);
            if submilli_micros == 0 {
                write!(f, "{}ms", millis)
            } else {
                write!(f, "{}.{:03}ms", millis, submilli_micros)
            }
        } else {
            // µs
            write!(f, "{}µs", self.0)
        }
    }
}

impl fmt::Debug for Instant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as fmt::Display>::fmt(self, f)
    }
}

/// Trait for time providers.
///
/// The hardware interface has to provide an implementation of `Timer` to the stack. The
/// implementation must have microsecond accuracy.
///
/// This trait can also be implemented by a mock timer for testing.
pub trait Timer {
    /// Obtain the current time as an [`Instant`].
    ///
    /// The [`Instant`]s returned by this function must never move backwards in time, except when
    /// the underlying value wraps around.
    fn now(&self) -> Instant;
}

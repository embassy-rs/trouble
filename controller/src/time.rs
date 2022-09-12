//! Timer module.

use embassy_time::Instant;

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

use embassy_time::Duration;

/// 128-bit encryption key size
pub(crate) const ENCRYPTION_KEY_SIZE_128_BITS: u8 = 128 / 8;

/// Long duration, to disable the timer
pub(crate) const TIMEOUT_DISABLE: Duration = Duration::from_secs(3600*24*365*10); // ~10 years
// Workaround for Duration multiplication not being const
const TIMEOUT_SECS: u64 = 30;
/// Pairing time-out
pub(crate) const TIMEOUT: Duration = Duration::from_secs(TIMEOUT_SECS);

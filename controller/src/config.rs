//! Stack configuration trait.

use crate::phy::Radio;
use crate::time::Timer;

/// Trait for trouble stack configuration.
///
/// This trait defines a number of types to be used throughout the layers of the BLE stack, which
/// define capabilities, data structures, data, and hardware interface types to be used.
///
/// Every application must define a type implementing this trait and supply it to the stack.
pub trait Config {
    /// A time source with microsecond resolution.
    type Timer: Timer;

    /// The BLE tranciever (radio).
    type Radio: Radio;
}

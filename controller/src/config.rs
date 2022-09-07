//! Stack configuration trait.

use crate::link::{Transmitter};
use crate::phy::Radio;
use crate::{l2cap::ChannelMapper, time::Timer};

/// Trait for trouble stack configuration.
///
/// This trait defines a number of types to be used throughout the layers of the BLE stack, which
/// define capabilities, data structures, data, and hardware interface types to be used.
///
/// Every application must define a type implementing this trait and supply it to the stack.
pub trait Config {
    /// A time source with microsecond resolution.
    type Timer: Timer;

    /// The BLE packet transmitter (radio).
    type Transmitter: Transmitter;
}

// Helper aliases to make accessing producer/consumer more convenient.
pub(crate) type ConfProducer<C> = <<C as Config>::PacketQueue as PacketQueue>::Producer;
pub(crate) type ConfConsumer<C> = <<C as Config>::PacketQueue as PacketQueue>::Consumer;

// (`C::PacketQueue::Producer` should work, but doesn't)
// (see: https://github.com/rust-lang/rust/issues/22519)

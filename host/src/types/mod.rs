//! Common types.

/// Traits for conversion between types and their GATT representations
#[cfg(feature = "gatt")]
pub mod gatt_traits;
pub(crate) mod l2cap;
pub(crate) mod primitives;

pub(crate) mod capabilities;
pub mod uuid;

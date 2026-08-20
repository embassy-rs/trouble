#![cfg_attr(not(feature = "std"), no_std)]
#![allow(dead_code)]

pub(crate) mod common;
pub(crate) mod fmt;

pub mod ble_advertise;
#[cfg(feature = "extended-advertising")]
pub mod ble_advertise_multiple;
#[cfg(feature = "central")]
pub mod ble_bas_central;
#[cfg(all(feature = "security", feature = "central"))]
pub mod ble_bas_central_auth;
#[cfg(all(feature = "security", feature = "central"))]
pub mod ble_bas_central_bonding;
#[cfg(feature = "central")]
pub mod ble_bas_central_multiple;
#[cfg(all(feature = "security", feature = "central"))]
pub mod ble_bas_central_pass_key;
#[cfg(all(feature = "security", feature = "central"))]
pub mod ble_bas_central_sec;
pub mod ble_bas_peripheral;
#[cfg(feature = "security")]
pub mod ble_bas_peripheral_auth;
#[cfg(feature = "security")]
pub mod ble_bas_peripheral_bonding;
#[cfg(feature = "security")]
pub mod ble_bas_peripheral_custom_pass_key;
#[cfg(feature = "security")]
pub mod ble_bas_peripheral_pass_key;
#[cfg(feature = "security")]
pub mod ble_bas_peripheral_sec;
pub mod ble_beacon;
pub mod ble_dis_peripheral;
#[cfg(feature = "central")]
pub mod ble_l2cap_central;
pub mod ble_l2cap_peripheral;
#[cfg(feature = "scan")]
pub mod ble_scanner;
#[cfg(feature = "central")]
pub mod high_throughput_ble_l2cap_central;
pub mod high_throughput_ble_l2cap_peripheral;

#[cfg(feature = "std")]
mod alloc;

#[cfg(feature = "std")]
pub use alloc::BigAlloc;

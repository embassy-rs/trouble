#![feature(generic_associated_types)]
#![feature(type_alias_impl_trait)]
//! An troublesome BLE link layer
//!
//! Trouble-controller is based on [rubble](), with modifications to make it work in an async
//! environment.
//!
//! Trouble-controller is runtime and hardware-agnostic: It does not need an RTOS (although you can certainly
//! use one if you want) and provides hardware interfaces that need to be implemented once for
//! every supported MCU family.

// We're `#[no_std]`, except when we're testing
#![cfg_attr(not(test), no_std)]

mod fmt;

//mod utils;
//pub mod beacon;
//pub mod bytes;
//pub mod config;
//pub mod ecdh;
//mod error;
pub mod link;
pub mod phy;
//pub mod security;
//pub mod uuid;

//pub use self::error::Error;

//use self::link::llcp::VersionNumber;

// Version of the Bluetooth specification implemented by Rubble.
//pub const BLUETOOTH_VERSION: VersionNumber = VersionNumber::V4_2;

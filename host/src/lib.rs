//! Trouble is a Bluetooth Low Energy (BLE) Host implementation that communicates
//! with a controller over any transport implementing the traits from the `bt-hci`
//! crate.
//!
//! Trouble can run on embedded devices (`no_std`) and be configured to consume
//! as little resources are needed depending on your required configuration.
#![no_std]
#![allow(async_fn_in_trait)]
#![allow(dead_code)]
#![allow(unused_variables)]

use advertise::AdvertisementDataError;
pub use bt_hci::param::{AddrKind, BdAddr, LeConnRole as Role};
use bt_hci::FromHciBytesError;

mod fmt;

mod att;
mod channel_manager;
mod codec;
mod connection_manager;
mod cursor;
mod packet_pool;
mod pdu;
pub mod types;

pub use packet_pool::Qos as PacketQos;

pub mod adapter;
pub mod advertise;
pub mod connection;
pub mod l2cap;
pub mod scan;

#[cfg(feature = "gatt")]
pub mod attribute;
#[cfg(feature = "gatt")]
mod attribute_server;
#[cfg(feature = "gatt")]
pub mod gatt;

/// A BLE address.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Address {
    pub kind: AddrKind,
    pub addr: BdAddr,
}

impl Address {
    pub fn random(val: [u8; 6]) -> Self {
        Self {
            kind: AddrKind::RANDOM,
            addr: BdAddr::new(val),
        }
    }
}

/// Errors returned by the adapter.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum StackError<E> {
    Controller(E),
    Stack(Error),
}

/// Errors related to Host.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Error {
    HciEncode(bt_hci::param::Error),
    HciDecode(FromHciBytesError),
    InsufficientSpace,
    InvalidValue,
    Advertisement(AdvertisementDataError),
    InvalidChannelId,
    NoChannelAvailable,
    NotFound,
    InvalidState,
    OutOfMemory,
    NotSupported,
    ChannelClosed,
    Timeout,
    Busy,
    NoPermits,
    Disconnected,
    Other,
}

impl<E> From<Error> for StackError<E> {
    fn from(value: Error) -> Self {
        Self::Stack(value)
    }
}

impl From<FromHciBytesError> for Error {
    fn from(error: FromHciBytesError) -> Self {
        Self::HciDecode(error)
    }
}

impl<E> From<bt_hci::controller::CmdError<E>> for StackError<E> {
    fn from(error: bt_hci::controller::CmdError<E>) -> Self {
        match error {
            bt_hci::controller::CmdError::Hci(p) => Self::Stack(Error::HciEncode(p)),
            bt_hci::controller::CmdError::Io(p) => Self::Controller(p),
        }
    }
}

impl<E> From<bt_hci::param::Error> for StackError<E> {
    fn from(error: bt_hci::param::Error) -> Self {
        Self::Stack(Error::HciEncode(error))
    }
}

impl From<codec::Error> for Error {
    fn from(error: codec::Error) -> Self {
        match error {
            codec::Error::InsufficientSpace => Error::InsufficientSpace,
            codec::Error::InvalidValue => Error::InvalidValue,
        }
    }
}

impl<E> From<codec::Error> for StackError<E> {
    fn from(error: codec::Error) -> Self {
        match error {
            codec::Error::InsufficientSpace => StackError::Stack(Error::InsufficientSpace),
            codec::Error::InvalidValue => StackError::Stack(Error::InvalidValue),
        }
    }
}

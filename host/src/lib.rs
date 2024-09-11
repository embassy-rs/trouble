//! Trouble is a Bluetooth Low Energy (BLE) Host implementation that communicates
//! with a controller over any transport implementing the traits from the `bt-hci`
//! crate.
//!
//! Trouble can run on embedded devices (`no_std`) and be configured to consume
//! as little resources are needed depending on your required configuration.
#![no_std]
#![allow(dead_code)]
#![allow(unused_variables)]

use advertise::AdvertisementDataError;
pub use bt_hci::param::{AddrKind, BdAddr, LeConnRole as Role};
use bt_hci::FromHciBytesError;

use crate::att::AttErrorCode;

mod fmt;

mod att;
mod channel_manager;
mod codec;
mod command;
pub mod config;
mod connection_manager;
mod cursor;
pub mod packet_pool;
mod pdu;
pub mod types;

pub use packet_pool::Qos as PacketQos;

pub mod advertise;
pub mod connection;
pub mod l2cap;
pub mod scan;

#[cfg(test)]
pub(crate) mod mock_controller;

pub(crate) mod host;
pub use host::*;

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

/// Errors returned by the host.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BleHostError<E> {
    Controller(E),
    BleHost(Error),
}

/// Errors related to Host.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Error {
    Hci(bt_hci::param::Error),
    HciDecode(FromHciBytesError),
    Att(AttErrorCode),
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

impl<E> From<Error> for BleHostError<E> {
    fn from(value: Error) -> Self {
        Self::BleHost(value)
    }
}

impl From<FromHciBytesError> for Error {
    fn from(error: FromHciBytesError) -> Self {
        Self::HciDecode(error)
    }
}

impl From<AttErrorCode> for Error {
    fn from(error: AttErrorCode) -> Self {
        Self::Att(error)
    }
}

impl<E> From<bt_hci::cmd::Error<E>> for BleHostError<E> {
    fn from(error: bt_hci::cmd::Error<E>) -> Self {
        match error {
            bt_hci::cmd::Error::Hci(p) => Self::BleHost(Error::Hci(p)),
            bt_hci::cmd::Error::Io(p) => Self::Controller(p),
        }
    }
}

impl<E> From<bt_hci::param::Error> for BleHostError<E> {
    fn from(error: bt_hci::param::Error) -> Self {
        Self::BleHost(Error::Hci(error))
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

impl<E> From<codec::Error> for BleHostError<E> {
    fn from(error: codec::Error) -> Self {
        match error {
            codec::Error::InsufficientSpace => BleHostError::BleHost(Error::InsufficientSpace),
            codec::Error::InvalidValue => BleHostError::BleHost(Error::InvalidValue),
        }
    }
}

use bt_hci::cmd::controller_baseband::*;
use bt_hci::cmd::le::*;
use bt_hci::cmd::link_control::*;
use bt_hci::controller::{ControllerCmdAsync, ControllerCmdSync};

pub trait Controller:
    bt_hci::controller::Controller
    + embedded_io::ErrorType
    + ControllerCmdSync<LeReadBufferSize>
    + ControllerCmdSync<Disconnect>
    + ControllerCmdSync<SetEventMask>
    + ControllerCmdSync<LeSetEventMask>
    + ControllerCmdSync<LeSetRandomAddr>
    + ControllerCmdSync<HostBufferSize>
    + ControllerCmdAsync<LeConnUpdate>
    + ControllerCmdSync<LeReadFilterAcceptListSize>
    + ControllerCmdSync<SetControllerToHostFlowControl>
    + ControllerCmdSync<Reset>
    + ControllerCmdSync<LeCreateConnCancel>
    + ControllerCmdAsync<LeCreateConn>
    + ControllerCmdSync<LeClearFilterAcceptList>
    + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
    + for<'t> ControllerCmdSync<LeSetAdvEnable>
    + for<'t> ControllerCmdSync<LeSetExtAdvEnable<'t>>
    + for<'t> ControllerCmdSync<HostNumberOfCompletedPackets<'t>>
    + ControllerCmdSync<LeReadBufferSize>
    + for<'t> ControllerCmdSync<LeSetAdvData>
    + ControllerCmdSync<LeSetAdvParams>
    + for<'t> ControllerCmdSync<LeSetAdvEnable>
    + for<'t> ControllerCmdSync<LeSetScanResponseData>
{
}

impl<
        C: bt_hci::controller::Controller
            + embedded_io::ErrorType
            + ControllerCmdSync<LeReadBufferSize>
            + ControllerCmdSync<Disconnect>
            + ControllerCmdSync<SetEventMask>
            + ControllerCmdSync<LeSetEventMask>
            + ControllerCmdSync<LeSetRandomAddr>
            + ControllerCmdSync<HostBufferSize>
            + ControllerCmdAsync<LeConnUpdate>
            + ControllerCmdSync<LeReadFilterAcceptListSize>
            + ControllerCmdSync<LeClearFilterAcceptList>
            + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
            + ControllerCmdSync<SetControllerToHostFlowControl>
            + ControllerCmdSync<Reset>
            + ControllerCmdSync<LeCreateConnCancel>
            + ControllerCmdAsync<LeCreateConn>
            + for<'t> ControllerCmdSync<LeSetAdvEnable>
            + for<'t> ControllerCmdSync<LeSetExtAdvEnable<'t>>
            + for<'t> ControllerCmdSync<HostNumberOfCompletedPackets<'t>>
            + ControllerCmdSync<LeReadBufferSize>
            + for<'t> ControllerCmdSync<LeSetAdvData>
            + ControllerCmdSync<LeSetAdvParams>
            + for<'t> ControllerCmdSync<LeSetAdvEnable>
            + for<'t> ControllerCmdSync<LeSetScanResponseData>,
    > Controller for C
{
}

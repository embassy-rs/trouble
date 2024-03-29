#![no_std]
#![allow(async_fn_in_trait)]
#![allow(dead_code)]
#![allow(unused_variables)]

use advertise::AdvertisementDataError;
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
pub mod gatt;
pub mod l2cap;
pub mod scan;

pub mod attribute;
mod attribute_server;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AdapterError<E> {
    Controller(E),
    Adapter(Error),
}

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
    OutOfMemory,
    NotSupported,
    ChannelClosed,
    Other,
}

impl<E> From<Error> for AdapterError<E> {
    fn from(value: Error) -> Self {
        Self::Adapter(value)
    }
}

impl From<FromHciBytesError> for Error {
    fn from(error: FromHciBytesError) -> Self {
        Self::HciDecode(error)
    }
}

impl<E> From<bt_hci::CmdError<E>> for AdapterError<E> {
    fn from(error: bt_hci::CmdError<E>) -> Self {
        match error {
            bt_hci::CmdError::Param(p) => Self::Adapter(Error::HciEncode(p)),
            bt_hci::CmdError::Controller(p) => Self::Controller(p),
        }
    }
}

impl<E> From<bt_hci::param::Error> for AdapterError<E> {
    fn from(error: bt_hci::param::Error) -> Self {
        Self::Adapter(Error::HciEncode(error))
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

impl<E> From<codec::Error> for AdapterError<E> {
    fn from(error: codec::Error) -> Self {
        match error {
            codec::Error::InsufficientSpace => AdapterError::Adapter(Error::InsufficientSpace),
            codec::Error::InvalidValue => AdapterError::Adapter(Error::InvalidValue),
        }
    }
}

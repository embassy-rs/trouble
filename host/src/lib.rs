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
pub enum Error<E> {
    Controller(E),
    Encode(bt_hci::param::Error),
    Decode(FromHciBytesError),
    Codec(codec::Error),
    Timeout,
    Advertisement(AdvertisementDataError),
    Failed(u8),
}

impl<E> From<FromHciBytesError> for Error<E> {
    fn from(error: FromHciBytesError) -> Self {
        Self::Decode(error)
    }
}

impl<E> From<bt_hci::CmdError<E>> for Error<E> {
    fn from(error: bt_hci::CmdError<E>) -> Self {
        match error {
            bt_hci::CmdError::Param(p) => Self::Encode(p),
            bt_hci::CmdError::Controller(p) => Self::Controller(p),

        }
    }
}

impl<E> From<bt_hci::param::Error> for Error<E> {
    fn from(error: bt_hci::param::Error) -> Self {
        Self::Encode(error)
    }
}

impl<E> From<codec::Error> for Error<E> {
    fn from(error: codec::Error) -> Self {
        Self::Codec(error)
    }
}

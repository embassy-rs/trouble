#![no_std]
#![allow(async_fn_in_trait)]
#![allow(dead_code)]
#![allow(unused_variables)]

use ad_structure::AdvertisementDataError;
use bt_hci::FromHciBytesError;

// TODO: Make these configurable
pub(crate) const ATT_MTU: usize = 64;

pub(crate) const ATT_RXQ: usize = 3;
pub(crate) const L2CAP_RXQ: usize = 3;
// NOTE: This one is actually shared for all connections
pub(crate) const L2CAP_TXQ: usize = 3;

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
pub mod connection;
pub mod gatt;
pub mod l2cap;

pub mod ad_structure;

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

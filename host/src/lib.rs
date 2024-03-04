#![no_std]
#![allow(async_fn_in_trait)]
#![allow(dead_code)]
#![allow(unused_variables)]

use ad_structure::AdvertisementDataError;
use bt_hci::FromHciBytesError;

// TODO: Make these configurable
pub(crate) const ATT_MTU: usize = 23;
pub(crate) const L2CAP_MTU: usize = 247;

pub(crate) const L2CAP_RXQ: usize = 3;
// NOTE: This one is actually shared for all connections
pub(crate) const L2CAP_TXQ: usize = 3;

mod fmt;

mod att;
mod codec;
mod cursor;
pub(crate) mod types;

pub mod adapter;
pub mod gatt;
pub mod l2cap;

pub mod ad_structure;

pub mod attribute;
mod attribute_server;

#[derive(Debug)]
pub enum Error<E> {
    Timeout,
    Advertisement(AdvertisementDataError),
    Failed(u8),
    Controller(E),
    Encode(bt_hci::param::Error),
    Decode(FromHciBytesError),
    Codec(codec::Error),
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

#[cfg(feature = "defmt")]
impl<E> defmt::Format for Error<E>
where
    E: defmt::Format,
{
    fn format(&self, fmt: defmt::Formatter) {
        match self {
            Error::Encode(_) => {
                defmt::write!(fmt, "Encode")
            }
            Error::Decode(_) => {
                defmt::write!(fmt, "Decode")
            }
            Error::Codec(_) => {
                defmt::write!(fmt, "Codec")
            }
            Error::Timeout => {
                defmt::write!(fmt, "Timeout")
            }
            Error::Failed(value) => {
                defmt::write!(fmt, "Failed({})", value)
            }
            Error::Controller(value) => {
                defmt::write!(fmt, "Controller({})", value)
            }
            Error::Advertisement(value) => {
                defmt::write!(fmt, "Advertisement({})", value)
            }
        }
    }
}

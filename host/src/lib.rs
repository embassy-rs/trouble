#![no_std]
#![allow(async_fn_in_trait)]

use ad_structure::AdvertisementDataError;
use bt_hci::FromHciBytesError;

mod fmt;

mod byte_reader;
mod byte_writer;

pub mod adapter;
pub mod att;
pub mod driver;
pub mod l2cap;

pub mod ad_structure;

pub mod attribute;
pub mod attribute_server;

#[derive(Debug)]
pub enum Error<E> {
    Timeout,
    Advertisement(AdvertisementDataError),
    Failed(u8),
    Controller(E),
    Encode(bt_hci::param::Error),
    Decode(FromHciBytesError),
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

/// 56-bit device address in big-endian byte order used by [`DHKey::f5`] and
/// [`MacKey::f6`] functions ([Vol 3] Part H, Section 2.2.7 and 2.2.8).
#[derive(Clone, Copy, Debug)]
#[must_use]
#[repr(transparent)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Addr(pub [u8; 7]);

impl Addr {
    /// Creates a device address from a little-endian byte array.
    #[inline]
    pub fn from_le_bytes(is_random: bool, mut v: [u8; 6]) -> Self {
        v.reverse();
        let mut a = [0; 7];
        a[0] = u8::from(is_random);
        a[1..].copy_from_slice(&v);
        Self(a)
    }
}

#[cfg(not(feature = "crypto"))]
pub mod no_rng {
    pub struct NoRng;

    impl rand_core::CryptoRng for NoRng {}

    impl rand_core::RngCore for NoRng {
        fn next_u32(&mut self) -> u32 {
            unimplemented!()
        }

        fn next_u64(&mut self) -> u64 {
            unimplemented!()
        }

        fn fill_bytes(&mut self, _dest: &mut [u8]) {
            unimplemented!()
        }

        fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand_core::Error> {
            unimplemented!()
        }
    }
}

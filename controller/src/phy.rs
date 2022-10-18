//! Physical layer interactions.
//!
//! Don't expect to see much code here: Most of this layer is hardware.
//!
//! BLE data is transmitted on 40 different RF channels numbered from 0 to 39 with ascending
//! frequencies. Channels 0, 12 and 39 are reserved for advertising, all others are used for data
//! transmission. BLE internally uses so-called "Channel Indices" which reorder the RF channels so
//! that indices 0..=36 refer to data channels and 37..=39 refer to the advertising channels
//! (presumably to simplify channel hopping). The Link-Layer is only interested in these channel
//! indices, so only those are implemented here.
//!

use core::future::Future;

/// Returns the center frequency in MHz corresponding to an RF channel.
fn rf_channel_freq(rf_channel: u8) -> u16 {
    2402 + u16::from(rf_channel) * 2
}

/// Returns the data whitening IV for a channel index (not RF channel).
fn whitening_iv(channel_idx: u8) -> u8 {
    debug_assert!(channel_idx <= 39);
    0b01000000 | channel_idx
}

/// One of the three advertising channels (channel indices 37, 38 or 39).
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AdvertisingChannel(u8);

impl AdvertisingChannel {
    /// Returns the first (lowest-numbered) advertising channel.
    pub fn first() -> Self {
        AdvertisingChannel(37)
    }

    /// Returns an iterator that yields all 3 advertising channels in ascending order.
    pub fn iter_all() -> impl Iterator<Item = Self> {
        [
            AdvertisingChannel(37),
            AdvertisingChannel(38),
            AdvertisingChannel(39),
        ]
        .iter()
        .cloned()
    }

    /// Returns the next advertising channel, or the first one if `self` is the last channel.
    pub fn cycle(&self) -> Self {
        if self.0 == 39 {
            AdvertisingChannel(37)
        } else {
            AdvertisingChannel(self.0 + 1)
        }
    }

    /// Returns the channel index.
    ///
    /// Channels 37, 38 and 39 are used for advertising.
    pub fn channel(&self) -> u8 {
        self.0
    }

    /// Returns the physical RF channel corresponding to this advertising channel index.
    ///
    /// RF channels 0, 12 and 39 are used for advertising.
    pub fn rf_channel(&self) -> u8 {
        match self.0 {
            37 => 0,
            38 => 12,
            39 => 39,
            _ => unreachable!(),
        }
    }

    /// Returns the center frequency of this channel in MHz.
    pub fn freq(&self) -> u16 {
        rf_channel_freq(self.rf_channel())
    }

    /// Calculates the initial value of the LFSR to use for data whitening.
    ///
    /// The value is a 7-bit value. The MSb will always be 0, and the 2nd MSb always 1 (Position 0).
    /// The LSb contains Position 6. Refer to the specification for details about the bit positions.
    ///
    /// The polynomial is always `x^7 + x^4 + 1`.
    ///
    /// Whitening is applied to PDU and CRC.
    pub fn whitening_iv(&self) -> u8 {
        whitening_iv(self.0)
    }
}

/// One of 37 data channels on which data channel PDUs are sent between connected devices.
///
/// (channel indices 0..=36)
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DataChannel(u8);

impl DataChannel {
    /// Creates a `DataChannel` from a raw index.
    ///
    /// # Panics
    ///
    /// This will panic if `index` is not a valid data channel index. Valid indices are 0..=36.
    pub fn new(index: u8) -> Self {
        assert!(index <= 36);
        DataChannel(index)
    }

    /// Returns the data channel index.
    ///
    /// The returned value is always in range 0..=36.
    pub fn index(&self) -> u8 {
        self.0
    }

    /// Returns the RF channel corresponding to this data channel index.
    ///
    /// RF channels 1-11 and 13-38 are used for data transmission.
    pub fn rf_channel(&self) -> u8 {
        match self.0 {
            ch @ 0..=10 => ch + 1,
            ch @ 11..=36 => ch + 2,
            _ => unreachable!(),
        }
    }

    /// Returns the center frequency of this channel in MHz.
    pub fn freq(&self) -> u16 {
        rf_channel_freq(self.rf_channel())
    }

    /// Calculates the initial value of the LFSR to use for data whitening.
    ///
    /// The value is a 7-bit value. The MSb will always be 0, and the 2nd MSb always 1 (Position 0).
    /// The LSb contains Position 6. Refer to the specification for details about the bit positions.
    ///
    /// The polynomial is always `x^7 + x^4 + 1`.
    ///
    /// Whitening is applied to PDU and CRC.
    pub fn whitening_iv(&self) -> u8 {
        whitening_iv(self.0)
    }
}

/// Trait for raw 2.4 GHz non-BLE-specific radios.
///
/// You probably won't need to implement this trait, unless you're working with hardware that has
/// absolutely no special support for BLE. Usually, the Link-Layer `Transmitter` should be
/// implemented.
pub trait Radio {
    type Error;

    type TransmitFuture<'m>: Future<Output = Result<(), Self::Error>> + 'm
    where
        Self: 'm;
    fn transmit<'m>(&'m mut self, buf: &'m [u8], freq: u16) -> Self::TransmitFuture<'m>;

    type ReceiveFuture<'m>: Future<Output = Result<usize, Self::Error>> + 'm
    where
        Self: 'm;
    fn receive<'m>(&'m mut self, buf: &'m mut [u8], freq: u16) -> Self::ReceiveFuture<'m>;
}

use crate::{bytes::RawRepr, phy::DataChannel};
use core::fmt;

/// A map marking data channels as used or unused.
///
/// A channel map must mark at least 2 channels as used.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct ChannelMap {
    raw: [u8; 5],
    num_used_channels: u8,
}

impl ChannelMap {
    /// Create a new channel map from the raw format used in Connection Request PDUs (`ChM`).
    ///
    /// The first byte (LSB) contains flags for data channels 0 to 7, where the least significant
    /// bit is the flag for channel 0, and so on.
    ///
    /// Since there are only 37 data channels, but 40 bits in the 5 Bytes, the 3 most significant
    /// bits in the last Byte of `raw` are considered reserved for future use (RFU) and are ignored
    /// by this function.
    pub fn from_raw(mut raw: [u8; 5]) -> Self {
        raw[4] &= 0b11111; // clear RFU bits
        Self {
            raw,
            num_used_channels: raw.iter().map(|b| b.count_ones() as u8).sum(),
        }
    }

    /// Returns the raw bytes encoding this channel map.
    pub fn to_raw(&self) -> [u8; 5] {
        self.raw
    }

    /// Creates a new channel map that marks all data channels as used.
    pub fn with_all_channels() -> Self {
        Self {
            raw: [0xff, 0xff, 0xff, 0xff, 0b11111],
            num_used_channels: 37,
        }
    }

    /// Returns the number of data channels marked as used by this map.
    pub fn num_used_channels(&self) -> u8 {
        self.num_used_channels
    }

    /// Returns whether the given data channel is marked as used.
    pub fn is_used(&self, channel: DataChannel) -> bool {
        let byte = self.raw[channel.index() as usize / 8];
        let bitnum = channel.index() % 8;
        let mask = 1 << bitnum;

        byte & mask != 0
    }

    /// Returns an iterator over all data channels marked as used in this map.
    pub fn iter_used<'a>(&'a self) -> impl Iterator<Item = DataChannel> + 'a {
        self.raw
            .iter()
            .enumerate()
            .flat_map(move |(byteindex, byte)| {
                (0..8).filter_map(move |bitindex| {
                    if byte & (1 << bitindex) != 0 {
                        Some(DataChannel::new(byteindex as u8 * 8 + bitindex))
                    } else {
                        None
                    }
                })
            })
    }

    /// Returns the `n`th channel marked as used.
    ///
    /// # Panics
    ///
    /// This will panic when `n >= self.num_used_channels()`.
    pub fn by_index(&self, n: u8) -> DataChannel {
        self.iter_used()
            .nth(n.into())
            .expect("by_index: index out of bounds")
    }
}

impl fmt::Display for ChannelMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.raw[..4] {
            write!(f, "{:08b}", b.reverse_bits())?;
        }
        write!(f, "{:05b}", self.raw[4].reverse_bits() >> 3)?;
        Ok(())
    }
}

impl fmt::Debug for ChannelMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({:?})", self, self.raw)
    }
}

impl RawRepr<[u8; 5]> for ChannelMap {
    fn from_raw(raw: [u8; 5]) -> Self {
        ChannelMap::from_raw(raw)
    }

    fn as_raw(&self) -> [u8; 5] {
        self.raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_channel() {
        // Channel map where only channel 0 is used.
        // Not valid, since only 1 channel in the map. Still useful for testing.
        let map = ChannelMap::from_raw([0x01, 0, 0, 0, 0]);
        assert_eq!(map.num_used_channels(), 1);
        assert!(map.is_used(DataChannel::new(0)));
        assert!(!map.is_used(DataChannel::new(1)));
        assert!(!map.is_used(DataChannel::new(2)));
        assert!(!map.is_used(DataChannel::new(7)));
        assert!(!map.is_used(DataChannel::new(8)));
        assert!(!map.is_used(DataChannel::new(36)));
        assert_eq!(map.by_index(0), DataChannel::new(0));
        assert!(map.iter_used().eq(vec![DataChannel::new(0)]));
    }

    #[test]
    fn from_raw() {
        let map = ChannelMap::from_raw([0xff; 5]);
        assert_eq!(map.num_used_channels(), 37);
        assert_eq!(map, ChannelMap::with_all_channels());
    }

    #[test]
    fn all_channels() {
        let map = ChannelMap::with_all_channels();
        for ch in 0..=36 {
            assert!(map.is_used(DataChannel::new(ch)));
        }
    }
}

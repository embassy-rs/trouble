//! Advertisement config.
use bt_hci::param::AdvEventProps;
pub use bt_hci::param::{AdvChannelMap, AdvFilterPolicy, PhyKind};
use embassy_time::Duration;

use crate::cursor::{ReadCursor, WriteCursor};
use crate::types::uuid::Uuid;
use crate::{codec, Address};

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
#[repr(i8)]
pub enum TxPower {
    Minus40dBm = -40,
    Minus20dBm = -20,
    Minus16dBm = -16,
    Minus12dBm = -12,
    Minus8dBm = -8,
    Minus4dBm = -4,
    ZerodBm = 0,
    Plus2dBm = 2,
    Plus3dBm = 3,
    Plus4dBm = 4,
    Plus5dBm = 5,
    Plus6dBm = 6,
    Plus7dBm = 7,
    Plus8dBm = 8,
    Plus10dBm = 10,
    Plus12dBm = 12,
    Plus14dBm = 14,
    Plus16dBm = 16,
    Plus18dBm = 18,
    Plus20dBm = 20,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AdvertisementSet<'d> {
    pub handle: u8,
    pub params: AdvertisementParameters,
    pub data: Advertisement<'d>,
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Copy, Clone, Debug)]
pub struct AdvertisementParameters {
    pub primary_phy: PhyKind,
    pub secondary_phy: PhyKind,
    pub tx_power: TxPower,

    /// Timeout duration
    pub timeout: Option<Duration>,
    pub max_events: Option<u8>,

    /// Advertising interval
    pub interval_min: Duration,
    pub interval_max: Duration,

    pub channel_map: Option<AdvChannelMap>,
    pub filter_policy: AdvFilterPolicy,
}

impl Default for AdvertisementParameters {
    fn default() -> Self {
        Self {
            primary_phy: PhyKind::Le1M,
            secondary_phy: PhyKind::Le1M,
            tx_power: TxPower::ZerodBm,
            timeout: None,
            max_events: None,
            interval_min: Duration::from_millis(250),
            interval_max: Duration::from_millis(250),
            filter_policy: AdvFilterPolicy::default(),
            channel_map: None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RawAdvertisement<'d> {
    pub(crate) props: AdvEventProps,
    pub(crate) adv_data: &'d [u8],
    pub(crate) scan_data: &'d [u8],
    pub(crate) peer: Option<Address>,
}

impl<'d> Default for RawAdvertisement<'d> {
    fn default() -> Self {
        Self {
            props: AdvEventProps::new()
                .set_connectable_adv(true)
                .set_scannable_adv(true)
                .set_legacy_adv(true),
            adv_data: &[],
            scan_data: &[],
            peer: None,
        }
    }
}

/// Advertisement payload depending on which advertisement kind requested.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Advertisement<'d> {
    ConnectableScannableUndirected {
        adv_data: &'d [u8],
        scan_data: &'d [u8],
    },
    ConnectableNonscannableDirected {
        peer: Address,
    },
    ConnectableNonscannableDirectedHighDuty {
        peer: Address,
    },
    NonconnectableScannableUndirected {
        adv_data: &'d [u8],
        scan_data: &'d [u8],
    },
    NonconnectableNonscannableUndirected {
        adv_data: &'d [u8],
    },
    ExtConnectableNonscannableUndirected {
        adv_data: &'d [u8],
    },
    ExtConnectableNonscannableDirected {
        peer: Address,
        adv_data: &'d [u8],
    },
    ExtNonconnectableScannableUndirected {
        scan_data: &'d [u8],
    },
    ExtNonconnectableScannableDirected {
        peer: Address,
        scan_data: &'d [u8],
    },
    ExtNonconnectableNonscannableUndirected {
        anonymous: bool,
        adv_data: &'d [u8],
    },
    ExtNonconnectableNonscannableDirected {
        anonymous: bool,
        peer: Address,
        adv_data: &'d [u8],
    },
}

impl<'d> From<Advertisement<'d>> for RawAdvertisement<'d> {
    fn from(val: Advertisement<'d>) -> RawAdvertisement<'d> {
        match val {
            Advertisement::ConnectableScannableUndirected { adv_data, scan_data } => RawAdvertisement {
                props: AdvEventProps::new()
                    .set_connectable_adv(true)
                    .set_scannable_adv(true)
                    .set_anonymous_adv(false)
                    .set_legacy_adv(true),
                adv_data,
                scan_data,
                peer: None,
            },
            Advertisement::ConnectableNonscannableDirected { peer } => RawAdvertisement {
                props: AdvEventProps::new()
                    .set_connectable_adv(true)
                    .set_scannable_adv(false)
                    .set_directed_adv(true)
                    .set_anonymous_adv(false)
                    .set_legacy_adv(true),
                adv_data: &[],
                scan_data: &[],
                peer: Some(peer),
            },
            Advertisement::ConnectableNonscannableDirectedHighDuty { peer } => RawAdvertisement {
                props: AdvEventProps::new()
                    .set_connectable_adv(true)
                    .set_scannable_adv(false)
                    .set_high_duty_cycle_directed_connectable_adv(true)
                    .set_anonymous_adv(false)
                    .set_legacy_adv(true),
                adv_data: &[],
                scan_data: &[],
                peer: Some(peer),
            },
            Advertisement::NonconnectableScannableUndirected { adv_data, scan_data } => RawAdvertisement {
                props: AdvEventProps::new()
                    .set_connectable_adv(false)
                    .set_scannable_adv(true)
                    .set_anonymous_adv(false)
                    .set_legacy_adv(true),
                adv_data,
                scan_data,
                peer: None,
            },
            Advertisement::NonconnectableNonscannableUndirected { adv_data } => RawAdvertisement {
                props: AdvEventProps::new()
                    .set_connectable_adv(false)
                    .set_scannable_adv(false)
                    .set_anonymous_adv(false)
                    .set_legacy_adv(true),
                adv_data,
                scan_data: &[],
                peer: None,
            },
            Advertisement::ExtConnectableNonscannableUndirected { adv_data } => RawAdvertisement {
                props: AdvEventProps::new().set_connectable_adv(true).set_scannable_adv(false),
                adv_data,
                scan_data: &[],
                peer: None,
            },
            Advertisement::ExtConnectableNonscannableDirected { adv_data, peer } => RawAdvertisement {
                props: AdvEventProps::new().set_connectable_adv(true).set_scannable_adv(false),
                adv_data,
                scan_data: &[],
                peer: Some(peer),
            },

            Advertisement::ExtNonconnectableScannableUndirected { scan_data } => RawAdvertisement {
                props: AdvEventProps::new().set_connectable_adv(false).set_scannable_adv(true),
                adv_data: &[],
                scan_data,
                peer: None,
            },
            Advertisement::ExtNonconnectableScannableDirected { scan_data, peer } => RawAdvertisement {
                props: AdvEventProps::new()
                    .set_connectable_adv(false)
                    .set_scannable_adv(true)
                    .set_directed_adv(true),
                adv_data: &[],
                scan_data,
                peer: Some(peer),
            },
            Advertisement::ExtNonconnectableNonscannableUndirected { adv_data, anonymous } => RawAdvertisement {
                props: AdvEventProps::new()
                    .set_connectable_adv(false)
                    .set_scannable_adv(false)
                    .set_anonymous_adv(anonymous)
                    .set_directed_adv(false),
                adv_data,
                scan_data: &[],
                peer: None,
            },
            Advertisement::ExtNonconnectableNonscannableDirected {
                adv_data,
                peer,
                anonymous,
            } => RawAdvertisement {
                props: AdvEventProps::new()
                    .set_connectable_adv(false)
                    .set_scannable_adv(false)
                    .set_anonymous_adv(anonymous)
                    .set_directed_adv(true),
                adv_data,
                scan_data: &[],
                peer: Some(peer),
            },
        }
    }
}

pub const AD_FLAG_LE_LIMITED_DISCOVERABLE: u8 = 0b00000001;
pub const LE_GENERAL_DISCOVERABLE: u8 = 0b00000010;
pub const BR_EDR_NOT_SUPPORTED: u8 = 0b00000100;
pub const SIMUL_LE_BR_CONTROLLER: u8 = 0b00001000;
pub const SIMUL_LE_BR_HOST: u8 = 0b00010000;

#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AdvertisementDataError {
    TooLong,
}

#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AdStructure<'a> {
    /// Device flags and baseband capabilities.
    ///
    /// This should be sent if any flags apply to the device. If not (ie. the value sent would be
    /// 0), this may be omitted.
    ///
    /// Must not be used in scan response data.
    Flags(u8),

    ServiceUuids16(&'a [Uuid]),
    ServiceUuids128(&'a [Uuid]),

    /// Service data with 16-bit service UUID.
    ServiceData16 {
        /// The 16-bit service UUID.
        uuid: u16,
        /// The associated service data. May be empty.
        data: &'a [u8],
    },

    /// Sets the full (unabbreviated) device name.
    ///
    /// This will be shown to the user when this device is found.
    CompleteLocalName(&'a [u8]),

    /// Sets the shortened device name.
    ShortenedLocalName(&'a [u8]),

    /// Set manufacturer specific data
    ManufacturerSpecificData {
        company_identifier: u16,
        payload: &'a [u8],
    },

    /// An unknown or unimplemented AD structure stored as raw bytes.
    Unknown {
        /// Type byte.
        ty: u8,
        /// Raw data transmitted after the type.
        data: &'a [u8],
    },
}

impl<'d> AdStructure<'d> {
    pub fn encode_slice(data: &[AdStructure<'_>], dest: &mut [u8]) -> Result<usize, codec::Error> {
        let mut w = WriteCursor::new(dest);
        for item in data.iter() {
            item.encode(&mut w)?;
        }
        Ok(w.len())
    }

    pub fn encode(&self, w: &mut WriteCursor<'_>) -> Result<(), codec::Error> {
        match self {
            AdStructure::Flags(flags) => {
                w.append(&[0x02, 0x01, *flags])?;
            }
            AdStructure::ServiceUuids16(uuids) => {
                w.append(&[(uuids.len() * 2 + 1) as u8, 0x02])?;
                for uuid in uuids.iter() {
                    w.write(*uuid)?;
                }
            }
            AdStructure::ServiceUuids128(uuids) => {
                w.append(&[(uuids.len() * 16 + 1) as u8, 0x07])?;
                for uuid in uuids.iter() {
                    w.write(*uuid)?;
                }
            }
            AdStructure::ShortenedLocalName(name) => {
                w.append(&[(name.len() + 1) as u8, 0x08])?;
                w.append(name)?;
            }
            AdStructure::CompleteLocalName(name) => {
                w.append(&[(name.len() + 1) as u8, 0x09])?;
                w.append(name)?;
            }
            AdStructure::ServiceData16 { uuid, data } => {
                w.append(&[(data.len() + 3) as u8, 0x16])?;
                w.write(*uuid)?;
                w.append(data)?;
            }
            AdStructure::ManufacturerSpecificData {
                company_identifier,
                payload,
            } => {
                w.append(&[(payload.len() + 3) as u8, 0xff])?;
                w.write(*company_identifier)?;
                w.append(payload)?;
            }
            AdStructure::Unknown { ty, data } => {
                w.append(&[(data.len() + 1) as u8, *ty])?;
                w.append(data)?;
            }
        }
        Ok(())
    }

    pub fn decode(data: &[u8]) -> impl Iterator<Item = Result<AdStructure<'_>, codec::Error>> {
        AdStructureIter {
            cursor: ReadCursor::new(data),
        }
    }
}

pub struct AdStructureIter<'d> {
    cursor: ReadCursor<'d>,
}

impl<'d> AdStructureIter<'d> {
    fn read(&mut self) -> Result<AdStructure<'d>, codec::Error> {
        let len: u8 = self.cursor.read()?;
        let code: u8 = self.cursor.read()?;
        let data = self.cursor.slice(len as usize - 1)?;
        match code {
            0x01 => Ok(AdStructure::Flags(data[0])),
            // 0x02 => unimplemented!(),
            // 0x07 => unimplemented!(),
            0x08 => Ok(AdStructure::ShortenedLocalName(data)),
            0x09 => Ok(AdStructure::CompleteLocalName(data)),
            // 0x16 => unimplemented!(),
            // 0xff => unimplemented!(),
            ty => Ok(AdStructure::Unknown { ty, data }),
        }
    }
}

impl<'d> Iterator for AdStructureIter<'d> {
    type Item = Result<AdStructure<'d>, codec::Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor.available() == 0 {
            return None;
        }
        Some(self.read())
    }
}

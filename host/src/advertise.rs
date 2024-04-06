use crate::{
    codec,
    cursor::{ReadCursor, WriteCursor},
    types::uuid::Uuid,
    Address,
};
use bt_hci::param::{AdvChannelMap, AdvEventProps, AdvFilterPolicy, AdvKind, PhyKind};
use embassy_time::Duration;

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Eq, PartialEq, Copy, Clone)]
#[repr(i8)]
pub enum TxPower {
    Minus40dBm = -40,
    Minus20dBm = -20,
    Minus16dBm = -16,
    Minus12dBm = -12,
    Minus8dBm = -8,
    Minus4dBm = -4,
    ZerodBm = 0,
    #[cfg(feature = "s140")]
    Plus2dBm = 2,
    Plus3dBm = 3,
    Plus4dBm = 4,
    #[cfg(feature = "s140")]
    Plus5dBm = 5,
    #[cfg(feature = "s140")]
    Plus6dBm = 6,
    #[cfg(feature = "s140")]
    Plus7dBm = 7,
    #[cfg(feature = "s140")]
    Plus8dBm = 8,
}

#[derive(Copy, Clone)]
pub struct AdvertisementConfig {
    pub primary_phy: PhyKind,
    pub secondary_phy: PhyKind,
    pub tx_power: TxPower,

    /// Timeout duration
    pub timeout: Option<Duration>,
    pub max_events: Option<u8>,

    /// Advertising interval
    pub interval_min: Duration,
    pub interval_max: Duration,

    pub channel_map: AdvChannelMap,
    pub filter_policy: AdvFilterPolicy,
}

impl Default for AdvertisementConfig {
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
            channel_map: AdvChannelMap::ALL,
        }
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum AdvertisementKind {
    Legacy(AdvKind),
    Extended(AdvEventProps),
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RawAdvertisement<'d> {
    pub(crate) kind: AdvertisementKind,
    pub(crate) adv_data: &'d [AdStructure<'d>],
    pub(crate) scan_data: &'d [AdStructure<'d>],
    pub(crate) peer: Option<Address>,
    pub(crate) anonymous: bool,
    pub(crate) set_id: u8,
}

impl<'d> Default for RawAdvertisement<'d> {
    fn default() -> Self {
        Self {
            kind: AdvertisementKind::Legacy(AdvKind::AdvInd),
            adv_data: &[],
            scan_data: &[],
            peer: None,
            anonymous: false,
            set_id: 0,
        }
    }
}

/// Legacy advertisement types, which works with BLE 4.0 and newer
pub enum Advertisement<'d> {
    ConnectableScannableUndirected {
        adv_data: &'d [AdStructure<'d>],
        scan_data: &'d [AdStructure<'d>],
    },
    ConnectableNonscannableDirected {
        peer: Address,
    },
    ConnectableNonscannableDirectedHighDuty {
        peer: Address,
    },
    NonconnectableScannableUndirected {
        adv_data: &'d [AdStructure<'d>],
        scan_data: &'d [AdStructure<'d>],
    },
    NonconnectableNonscannableUndirected {
        adv_data: &'d [AdStructure<'d>],
    },
}

/// Extended advertisement types, which works with BLE 5.0 and newer
pub enum ExtendedAdvertisement<'d> {
    ConnectableNonscannableUndirected {
        set_id: u8,
        adv_data: &'d [AdStructure<'d>],
    },
    ConnectableNonscannableDirected {
        set_id: u8,
        peer: Address,
        adv_data: &'d [AdStructure<'d>],
    },
    NonconnectableScannableUndirected {
        set_id: u8,
        scan_data: &'d [AdStructure<'d>],
    },
    NonconnectableScannableDirected {
        set_id: u8,
        peer: Address,
        scan_data: &'d [AdStructure<'d>],
    },
    NonconnectableNonscannableUndirected {
        set_id: u8,
        anonymous: bool,
        adv_data: &'d [AdStructure<'d>],
    },
    NonconnectableNonscannableDirected {
        set_id: u8,
        anonymous: bool,
        peer: Address,
        adv_data: &'d [AdStructure<'d>],
    },
}

impl<'d> From<Advertisement<'d>> for RawAdvertisement<'d> {
    fn from(val: Advertisement<'d>) -> RawAdvertisement<'d> {
        match val {
            Advertisement::ConnectableScannableUndirected { adv_data, scan_data } => RawAdvertisement {
                kind: AdvertisementKind::Legacy(AdvKind::AdvInd),
                adv_data,
                scan_data,
                peer: None,
                anonymous: false,
                set_id: 0,
            },
            Advertisement::ConnectableNonscannableDirected { peer } => RawAdvertisement {
                kind: AdvertisementKind::Legacy(AdvKind::AdvDirectIndLow),
                adv_data: &[],
                scan_data: &[],
                peer: Some(peer),
                anonymous: false,
                set_id: 0,
            },
            Advertisement::ConnectableNonscannableDirectedHighDuty { peer } => RawAdvertisement {
                kind: AdvertisementKind::Legacy(AdvKind::AdvDirectIndHigh),
                adv_data: &[],
                scan_data: &[],
                peer: Some(peer),
                anonymous: false,
                set_id: 0,
            },
            Advertisement::NonconnectableScannableUndirected { adv_data, scan_data } => RawAdvertisement {
                kind: AdvertisementKind::Legacy(AdvKind::AdvScanInd),
                adv_data,
                scan_data,
                peer: None,
                anonymous: false,
                set_id: 0,
            },
            Advertisement::NonconnectableNonscannableUndirected { adv_data } => RawAdvertisement {
                kind: AdvertisementKind::Legacy(AdvKind::AdvNonconnInd),
                adv_data,
                scan_data: &[],
                peer: None,
                anonymous: false,
                set_id: 0,
            },
        }
    }
}

impl<'d> From<ExtendedAdvertisement<'d>> for RawAdvertisement<'d> {
    fn from(val: ExtendedAdvertisement<'d>) -> RawAdvertisement<'d> {
        match val {
            ExtendedAdvertisement::ConnectableNonscannableUndirected { adv_data, set_id } => RawAdvertisement {
                kind: AdvertisementKind::Extended(
                    AdvEventProps::new().set_connectable_adv(true).set_scannable_adv(false),
                ),
                adv_data,
                scan_data: &[],
                peer: None,
                anonymous: false,
                set_id,
            },
            ExtendedAdvertisement::ConnectableNonscannableDirected { adv_data, peer, set_id } => RawAdvertisement {
                kind: AdvertisementKind::Extended(
                    AdvEventProps::new().set_connectable_adv(true).set_scannable_adv(false),
                ),
                adv_data,
                scan_data: &[],
                peer: Some(peer),
                anonymous: false,
                set_id,
            },

            ExtendedAdvertisement::NonconnectableScannableUndirected { scan_data, set_id } => RawAdvertisement {
                kind: AdvertisementKind::Extended(
                    AdvEventProps::new().set_connectable_adv(false).set_scannable_adv(false),
                ),
                adv_data: &[],
                scan_data,
                peer: None,
                anonymous: false,
                set_id,
            },
            ExtendedAdvertisement::NonconnectableScannableDirected {
                scan_data,
                peer,
                set_id,
            } => RawAdvertisement {
                kind: AdvertisementKind::Extended(
                    AdvEventProps::new()
                        .set_connectable_adv(false)
                        .set_scannable_adv(true)
                        .set_directed_adv(true),
                ),
                adv_data: &[],
                scan_data,
                peer: Some(peer),
                anonymous: false,
                set_id,
            },
            ExtendedAdvertisement::NonconnectableNonscannableUndirected {
                adv_data,
                anonymous,
                set_id,
            } => RawAdvertisement {
                kind: AdvertisementKind::Extended(
                    AdvEventProps::new()
                        .set_connectable_adv(false)
                        .set_scannable_adv(false)
                        .set_directed_adv(false),
                ),
                adv_data,
                scan_data: &[],
                peer: None,
                anonymous,
                set_id,
            },
            ExtendedAdvertisement::NonconnectableNonscannableDirected {
                adv_data,
                peer,
                anonymous,
                set_id,
            } => RawAdvertisement {
                kind: AdvertisementKind::Extended(
                    AdvEventProps::new()
                        .set_connectable_adv(false)
                        .set_scannable_adv(false)
                        .set_directed_adv(true),
                ),
                adv_data,
                scan_data: &[],
                peer: Some(peer),
                anonymous,
                set_id,
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

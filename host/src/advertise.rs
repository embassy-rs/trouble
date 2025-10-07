//! Advertisement config.
use bt_hci::param::AdvEventProps;
pub use bt_hci::param::{AdvChannelMap, AdvFilterPolicy, AdvHandle, AdvSet, PhyKind};
use embassy_time::Duration;

use crate::cursor::{ReadCursor, WriteCursor};
use crate::types::uuid::Uuid;
use crate::{bt_hci_duration, codec, Address};

/// Transmit power levels.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
#[repr(i8)]
#[allow(missing_docs)]
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

/// Configuration for a single advertisement set.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AdvertisementSet<'d> {
    /// Parameters for the advertisement.
    pub params: AdvertisementParameters,
    /// Advertisement data.
    pub data: Advertisement<'d>,
}

impl<'d> AdvertisementSet<'d> {
    /// Create a new advertisement set that can be passed to advertisement functions.
    pub fn handles<const N: usize>(sets: &[AdvertisementSet<'d>; N]) -> [AdvSet; N] {
        const NEW_SET: AdvSet = AdvSet {
            adv_handle: AdvHandle::new(0),
            duration: bt_hci::param::Duration::from_u16(0),
            max_ext_adv_events: 0,
        };

        let mut ret = [NEW_SET; N];
        for (i, set) in sets.iter().enumerate() {
            ret[i].adv_handle = AdvHandle::new(i as u8);
            ret[i].duration = bt_hci_duration(set.params.timeout.unwrap_or(embassy_time::Duration::from_micros(0)));
            ret[i].max_ext_adv_events = set.params.max_events.unwrap_or(0);
        }
        ret
    }
}

/// Parameters for an advertisement.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Copy, Clone, Debug)]
pub struct AdvertisementParameters {
    /// Phy selection
    pub primary_phy: PhyKind,

    /// Secondary phy selection
    pub secondary_phy: PhyKind,

    /// Transmission power
    pub tx_power: TxPower,

    /// Timeout duration
    pub timeout: Option<Duration>,

    /// Max advertising events
    pub max_events: Option<u8>,

    /// Minimum advertising interval
    pub interval_min: Duration,

    /// Maximum advertising interval
    pub interval_max: Duration,

    /// Which advertising channels to use
    pub channel_map: Option<AdvChannelMap>,

    /// Filtering policy
    pub filter_policy: AdvFilterPolicy,

    /// Fragmentation preference
    pub fragment: bool,
}

impl Default for AdvertisementParameters {
    fn default() -> Self {
        Self {
            primary_phy: PhyKind::Le1M,
            secondary_phy: PhyKind::Le1M,
            tx_power: TxPower::ZerodBm,
            timeout: None,
            max_events: None,
            interval_min: Duration::from_millis(160),
            interval_max: Duration::from_millis(160),
            filter_policy: AdvFilterPolicy::default(),
            channel_map: None,
            fragment: false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct RawAdvertisement<'d> {
    pub(crate) props: AdvEventProps,
    pub(crate) adv_data: &'d [u8],
    pub(crate) scan_data: &'d [u8],
    pub(crate) peer: Option<Address>,
}

impl Default for RawAdvertisement<'_> {
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
    /// Connectable and scannable undirected advertisement.
    ConnectableScannableUndirected {
        /// Advertisement data.
        adv_data: &'d [u8],
        /// Scan data.
        scan_data: &'d [u8],
    },
    /// Connectable and non-scannable directed advertisement.
    ConnectableNonscannableDirected {
        /// Address of the peer to direct the advertisement to.
        peer: Address,
    },
    /// Connectable and non-scannable directed advertisement with high duty cycle.
    ConnectableNonscannableDirectedHighDuty {
        /// Address of the peer to direct the advertisement to.
        peer: Address,
    },
    /// Nonconnectable and scannable undirected advertisement.
    NonconnectableScannableUndirected {
        /// Advertisement data.
        adv_data: &'d [u8],
        /// Scan data.
        scan_data: &'d [u8],
    },
    /// Nonconnectable and nonscannable undirected advertisement.
    NonconnectableNonscannableUndirected {
        /// Advertisement data.
        adv_data: &'d [u8],
    },
    /// Extended connectable and non-scannable undirected advertisement.
    ExtConnectableNonscannableUndirected {
        /// Advertisement data.
        adv_data: &'d [u8],
    },
    /// Extended connectable and non-scannable directed advertisement.
    ExtConnectableNonscannableDirected {
        /// Address of the peer to direct the advertisement to.
        peer: Address,
        /// Advertisement data.
        adv_data: &'d [u8],
    },
    /// Extended nonconnectable and scannable undirected advertisement.
    ExtNonconnectableScannableUndirected {
        /// Scan data.
        scan_data: &'d [u8],
    },
    /// Extended nonconnectable and scannable directed advertisement.
    ExtNonconnectableScannableDirected {
        /// Address of the peer to direct the advertisement to.
        peer: Address,
        /// Scan data.
        scan_data: &'d [u8],
    },
    /// Extended nonconnectable and nonscannable undirected advertisement.
    ExtNonconnectableNonscannableUndirected {
        /// Whether the advertisement is anonymous.
        anonymous: bool,
        /// Advertisement data.
        adv_data: &'d [u8],
    },
    /// Extended nonconnectable and nonscannable directed advertisement.
    ExtNonconnectableNonscannableDirected {
        /// Whether the advertisement is anonymous.
        anonymous: bool,
        /// Address of the peer to direct the advertisement to.
        peer: Address,
        /// Advertisement data.
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

/// Le advertisement.
pub const AD_FLAG_LE_LIMITED_DISCOVERABLE: u8 = 0b00000001;

/// Discoverable flag.
pub const LE_GENERAL_DISCOVERABLE: u8 = 0b00000010;

/// BR/EDR not supported.
pub const BR_EDR_NOT_SUPPORTED: u8 = 0b00000100;

/// Simultaneous LE and BR/EDR to same device capable (controller).
pub const SIMUL_LE_BR_CONTROLLER: u8 = 0b00001000;

/// Simultaneous LE and BR/EDR to same device capable (Host).
pub const SIMUL_LE_BR_HOST: u8 = 0b00010000;

/// Error encoding advertisement data.
#[derive(Debug, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AdvertisementDataError {
    /// Advertisement data too long for buffer.
    TooLong,
}

/// Advertisement data structure.
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

    /// List of 16-bit service UUIDs.
    /// The UUID data matches the ble network's endian order (should be little endian).
    ServiceUuids16(&'a [[u8; 2]]),

    /// List of 128-bit service UUIDs.
    /// The UUID data matches the ble network's endian order (should be little endian).
    ServiceUuids128(&'a [[u8; 16]]),

    /// Service data with 16-bit service UUID.
    /// The UUID data matches the ble network's endian order (should be little endian).
    ServiceData16 {
        /// The 16-bit service UUID.
        uuid: [u8; 2],
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
        /// Company identifier.
        company_identifier: u16,
        /// Payload data.
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

impl AdStructure<'_> {
    /// Encode a slice of advertisement structures into a buffer.
    pub fn encode_slice(data: &[AdStructure<'_>], dest: &mut [u8]) -> Result<usize, codec::Error> {
        let mut w = WriteCursor::new(dest);
        for item in data.iter() {
            item.encode(&mut w)?;
        }
        Ok(w.len())
    }

    pub(crate) fn encode(&self, w: &mut WriteCursor<'_>) -> Result<(), codec::Error> {
        match self {
            AdStructure::Flags(flags) => {
                w.append(&[0x02, 0x01, *flags])?;
            }
            AdStructure::ServiceUuids16(uuids) => {
                w.append(&[(uuids.len() * 2 + 1) as u8, 0x02])?;
                for uuid in uuids.iter() {
                    w.write_ref(&Uuid::Uuid16(*uuid))?;
                }
            }
            AdStructure::ServiceUuids128(uuids) => {
                w.append(&[(uuids.len() * 16 + 1) as u8, 0x07])?;
                for uuid in uuids.iter() {
                    w.write_ref(&Uuid::Uuid128(*uuid))?;
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
                w.write(Uuid::Uuid16(*uuid))?;
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

    /// Decode a slice of advertisement structures from a buffer.
    pub fn decode(data: &[u8]) -> impl Iterator<Item = Result<AdStructure<'_>, codec::Error>> {
        AdStructureIter {
            cursor: ReadCursor::new(data),
        }
    }
}

/// Iterator over advertisement structures.
pub struct AdStructureIter<'d> {
    cursor: ReadCursor<'d>,
}

impl<'d> AdStructureIter<'d> {
    fn read(&mut self) -> Result<AdStructure<'d>, codec::Error> {
        let len: u8 = self.cursor.read()?;
        if len < 2 {
            return Err(codec::Error::InvalidValue);
        }
        let code: u8 = self.cursor.read()?;
        let data = self.cursor.slice(len as usize - 1)?;
        // These codes correspond to the table in 2.3 Common Data Types table `assigned_numbers/core/ad_types.yaml` from <https://www.bluetooth.com/specifications/assigned-numbers/>
        // Look there for more information on each.
        match code {
            // Flags
            0x01 => Ok(AdStructure::Flags(data[0])),
            // Incomplete List of 16-bit Service or Service Class UUIDs
            // 0x02 =>
            // Complete List of 16-bit Service or Service Class UUIDs
            0x03 => match zerocopy::FromBytes::ref_from_bytes(data) {
                Ok(x) => Ok(AdStructure::ServiceUuids16(x)),
                Err(e) => {
                    let _ = zerocopy::SizeError::from(e);
                    Err(codec::Error::InvalidValue)
                }
            },
            // Incomplete List of 32-bit Service or Service Class UUIDs
            // 0x04 =>
            // Complete List of 32-bit Service or Service Class UUIDs
            // 0x05
            // Incomplete List of 128-bit Service or Service Class UUIDs
            // 0x06
            // Complete List of 128-bit Service or Service Class UUIDs
            0x07 => match zerocopy::FromBytes::ref_from_bytes(data) {
                Ok(x) => Ok(AdStructure::ServiceUuids128(x)),
                Err(e) => {
                    let _ = zerocopy::SizeError::from(e);
                    Err(codec::Error::InvalidValue)
                }
            },
            // Shortened Local Name
            0x08 => Ok(AdStructure::ShortenedLocalName(data)),
            // Complete Local Name
            0x09 => Ok(AdStructure::CompleteLocalName(data)),
            /*
            0x0A Tx Power Level
            0x0D Class of Device
            0x0E Simple Pairing Hash C-192
            0x0F Simple Pairing Randomizer R-192
            0x10 Device ID Device: ID Profile (when used in EIR data)
            0x10 Security Manager TK Value when used in OOB data blocks
            0x11 Security Manager Out of Band Flags
            0x12 Peripheral Connection Interval Range
            0x14 List of 16-bit Service Solicitation UUIDs
            0x15 List of 128-bit Service Solicitation UUIDs
            */
            // Service Data - 16-bit UUID
            0x16 => {
                if data.len() < 2 {
                    return Err(codec::Error::InvalidValue);
                }
                let uuid = data[0..2].try_into().unwrap();
                Ok(AdStructure::ServiceData16 { uuid, data: &data[2..] })
            }
            /*
            0x17 Public Target Address
            0x18 Random Target Address
            0x19 Appearance
            0x1A Advertising Interval
            0x1B LE Bluetooth Device Address
            0x1C LE Role
            0x1D Simple Pairing Hash C-256
            0x1E Simple Pairing Randomizer R-256
            0x1F List of 32-bit Service Solicitation UUIDs
            0x20 Service Data - 32-bit UUID
            0x21 Service Data - 128-bit UUID
            0x22 LE Secure Connections Confirmation Value
            0x23 LE Secure Connections Random Value
            0x24 URI
            0x25 Indoor Positioning
            0x26 Transport Discovery Data
            0x27 LE Supported Features
            0x28 Channel Map Update Indication
            0x29 PB-ADV
            0x2A Mesh Message
            0x2B Mesh Beacon
            0x2C BIGInfo
            0x2D Broadcast_Code
            0x2E Resolvable Set Identifier
            0x2F Advertising Interval - long
            0x30 Broadcast_Name
            0x31 Encrypted Advertising Data
            0x32 Periodic Advertising Response Timing
            0x34 Electronic Shelf Label
            0x3D 3D Information Data
            */
            // Manufacturer Specific Data
            0xff if data.len() >= 2 => Ok(AdStructure::ManufacturerSpecificData {
                company_identifier: u16::from_le_bytes([data[0], data[1]]),
                payload: &data[2..],
            }),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adv_name_truncate() {
        let mut adv_data = [0; 31];
        assert!(AdStructure::encode_slice(
            &[
                AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
                AdStructure::ServiceUuids16(&[[0x0f, 0x18]]),
                AdStructure::CompleteLocalName(b"12345678901234567890123"),
            ],
            &mut adv_data[..],
        )
        .is_err());
    }
}

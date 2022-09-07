//! Advertising channel operations.
//!
//! This module defines PDUs, states and fields used by packets transmitted on the advertising
//! channels. Generally, this includes everything needed to advertise as and scan for slave devices
//! and to establish connections.
//!
//! Note that while the types in here do not completely eliminate illegal values to be created, they
//! do employ a range of sanity checks that prevent bogus packets from being sent by the stack.

use crate::link::ad_structure::{AdStructure, Flags};
use crate::link::{channel_map::ChannelMap, AddressKind, DeviceAddress};
use crate::utils::{Hex, HexSlice};
use crate::{bytes::*, time::Duration, Error};
use core::{convert::TryInto, fmt, iter};

/// CRC initialization value for advertising channel packets.
///
/// Data channel packets use a preset shared when initiating the connection.
///
/// (as with `CRC_POLY`, only the least significant 24 bits count)
pub const CRC_PRESET: u32 = 0x00555555;

/// Max. advertising PDU payload size in Bytes.
///
/// Note that data channel PDUs can carry much larger payloads.
pub const MAX_PAYLOAD_SIZE: usize = 37;

/// Access Address to use for all advertising channel packets.
pub const ACCESS_ADDRESS: u32 = 0x8E89BED6;

/// A parsed advertising channel PDU.
#[derive(Debug, Copy, Clone)]
pub enum Pdu<'a> {
    /// Connectable and scannable advertisement.
    ConnectableUndirected {
        /// Address of the advertising device that is sending this PDU.
        advertiser_addr: DeviceAddress,

        /// AD structures sent along with the advertisement.
        advertising_data: BytesOr<'a, [AdStructure<'a>]>,
    },

    /// Directed connectable advertisement sent to an initiator.
    ///
    /// Does not contain advertisement data.
    ConnectableDirected {
        /// Address of the advertising device that is sending this PDU.
        advertiser_addr: DeviceAddress,

        /// Intended receiver of the advertisement.
        initiator_addr: DeviceAddress,
    },

    /// A non-connectable undirected advertisement (aka "beacon").
    NonconnectableUndirected {
        /// Address of the advertising device (beacon) that is sending this PDU.
        advertiser_addr: DeviceAddress,

        /// AD structures sent along with the advertisement.
        advertising_data: BytesOr<'a, [AdStructure<'a>]>,
    },

    /// Scannable advertisement.
    ScannableUndirected {
        /// Address of the advertising device that is sending this PDU.
        advertiser_addr: DeviceAddress,

        /// AD structures sent along with the advertisement.
        advertising_data: BytesOr<'a, [AdStructure<'a>]>,
    },

    /// Scan request sent from a scanner to an advertising device.
    ///
    /// This can only be sent in response to an advertising PDU that indicates
    /// that the advertising device is scannable (`ConnectableUndirected` and
    /// `ScannableUndirected`).
    ScanRequest {
        /// Address of the scanning device sending this PDU.
        scanner_addr: DeviceAddress,

        /// Address of the advertising device that should be scanned.
        advertiser_addr: DeviceAddress,
    },

    /// Response to a scan request, sent by the scanned advertising device.
    ScanResponse {
        /// Address of the advertising device that responds to a scan request by
        /// sending this PDU.
        advertiser_addr: DeviceAddress,

        /// Scan data payload, consisting of additional user-defined AD
        /// structures.
        scan_data: BytesOr<'a, [AdStructure<'a>]>,
    },

    /// A request to establish a connection, sent by an initiating device.
    ///
    /// This may only be sent to an advertising device that has broadcast a
    /// connectable advertisement (`ConnectableUndirected` or
    /// `ConnectableDirected`).
    ConnectRequest {
        /// Address of the device initiating the connection by sending this PDU.
        initiator_addr: DeviceAddress,

        /// Address of the intended receiver of this packet.
        advertiser_addr: DeviceAddress,

        /// Connection parameters.
        lldata: ConnectRequestData,
    },
}

impl<'a> Pdu<'a> {
    /// Constructs a PDU by parsing `payload`.
    pub fn from_header_and_payload(
        header: Header,
        payload: &mut ByteReader<'a>,
    ) -> Result<Self, Error> {
        use self::Pdu::*;

        if usize::from(header.payload_length()) != payload.bytes_left() {
            return Err(Error::InvalidLength);
        }

        Ok(match header.type_() {
            PduType::AdvInd => ConnectableUndirected {
                advertiser_addr: {
                    let kind = if header.tx_add() {
                        AddressKind::Random
                    } else {
                        AddressKind::Public
                    };
                    DeviceAddress::new(payload.read_array::<[u8; 6]>()?, kind)
                },
                advertising_data: BytesOr::from_bytes(payload)?,
            },
            PduType::AdvDirectInd => ConnectableDirected {
                advertiser_addr: {
                    let kind = if header.tx_add() {
                        AddressKind::Random
                    } else {
                        AddressKind::Public
                    };
                    DeviceAddress::new(payload.read_array::<[u8; 6]>()?, kind)
                },
                initiator_addr: {
                    let kind = if header.rx_add() {
                        AddressKind::Random
                    } else {
                        AddressKind::Public
                    };
                    DeviceAddress::new(payload.read_array::<[u8; 6]>()?, kind)
                },
            },
            PduType::AdvNonconnInd => NonconnectableUndirected {
                advertiser_addr: {
                    let kind = if header.tx_add() {
                        AddressKind::Random
                    } else {
                        AddressKind::Public
                    };
                    DeviceAddress::new(payload.read_array::<[u8; 6]>()?, kind)
                },
                advertising_data: BytesOr::from_bytes(payload)?,
            },
            PduType::AdvScanInd => ScannableUndirected {
                advertiser_addr: {
                    let kind = if header.tx_add() {
                        AddressKind::Random
                    } else {
                        AddressKind::Public
                    };
                    DeviceAddress::new(payload.read_array::<[u8; 6]>()?, kind)
                },
                advertising_data: BytesOr::from_bytes(payload)?,
            },
            PduType::ScanReq => ScanRequest {
                scanner_addr: {
                    // Scanning device sends this PDU
                    let kind = if header.tx_add() {
                        AddressKind::Random
                    } else {
                        AddressKind::Public
                    };
                    DeviceAddress::new(payload.read_array::<[u8; 6]>()?, kind)
                },
                advertiser_addr: {
                    // Advertiser receives this PDU (when it broadcasts an advertisement that
                    // indicates that the device is scannable).
                    let kind = if header.rx_add() {
                        AddressKind::Random
                    } else {
                        AddressKind::Public
                    };
                    DeviceAddress::new(payload.read_array::<[u8; 6]>()?, kind)
                },
            },
            PduType::ScanRsp => ScanResponse {
                advertiser_addr: {
                    let kind = if header.tx_add() {
                        AddressKind::Random
                    } else {
                        AddressKind::Public
                    };
                    DeviceAddress::new(payload.read_array::<[u8; 6]>()?, kind)
                },
                scan_data: BytesOr::from_bytes(payload)?,
            },
            PduType::ConnectReq => ConnectRequest {
                // Initiator sends this PDU
                initiator_addr: {
                    // Scanning device sends this PDU
                    let kind = if header.tx_add() {
                        AddressKind::Random
                    } else {
                        AddressKind::Public
                    };
                    DeviceAddress::new(payload.read_array::<[u8; 6]>()?, kind)
                },
                // Advertiser receives this PDU (if it has sent a connectable advertisement)
                advertiser_addr: {
                    // Advertiser receives this PDU (when it broadcasts an advertisement that
                    // indicates that the device is scannable).
                    let kind = if header.rx_add() {
                        AddressKind::Random
                    } else {
                        AddressKind::Public
                    };
                    DeviceAddress::new(payload.read_array::<[u8; 6]>()?, kind)
                },
                lldata: ConnectRequestData::from_bytes(payload)?,
            },
            PduType::Unknown(_) => return Err(Error::InvalidValue),
        })
    }

    /// Returns the device address of the sender of this PDU.
    pub fn sender(&self) -> &DeviceAddress {
        use self::Pdu::*;

        match self {
            ConnectableUndirected {
                advertiser_addr, ..
            }
            | ConnectableDirected {
                advertiser_addr, ..
            }
            | NonconnectableUndirected {
                advertiser_addr, ..
            }
            | ScannableUndirected {
                advertiser_addr, ..
            }
            | ScanResponse {
                advertiser_addr, ..
            } => advertiser_addr,

            ScanRequest { scanner_addr, .. } => scanner_addr,

            ConnectRequest { initiator_addr, .. } => initiator_addr,
        }
    }

    /// Returns the intended receiver of this PDU.
    ///
    /// This may be `None` if the PDU doesn't have a fixed receiver.
    pub fn receiver(&self) -> Option<&DeviceAddress> {
        use self::Pdu::*;

        match self {
            ConnectableUndirected { .. }
            | NonconnectableUndirected { .. }
            | ScannableUndirected { .. }
            | ScanResponse { .. } => None,

            ConnectableDirected { initiator_addr, .. } => Some(initiator_addr),
            ScanRequest {
                advertiser_addr, ..
            }
            | ConnectRequest {
                advertiser_addr, ..
            } => Some(advertiser_addr),
        }
    }

    /// Returns the PDU type of `self`.
    pub fn ty(&self) -> PduType {
        use self::Pdu::*;

        match self {
            ConnectableUndirected { .. } => PduType::AdvInd,
            ConnectableDirected { .. } => PduType::AdvDirectInd,
            NonconnectableUndirected { .. } => PduType::AdvNonconnInd,
            ScannableUndirected { .. } => PduType::AdvScanInd,
            ScanRequest { .. } => PduType::ScanReq,
            ScanResponse { .. } => PduType::ScanRsp,
            ConnectRequest { .. } => PduType::ConnectReq,
        }
    }

    /// Returns an iterator over all AD structures encoded in the PDU.
    ///
    /// If this PDU doesn't support attaching AD structures, this will return `None`.
    pub fn advertising_data(&self) -> Option<impl Iterator<Item = AdStructure<'a>>> {
        use self::Pdu::*;

        match self {
            ConnectableUndirected {
                advertising_data, ..
            }
            | NonconnectableUndirected {
                advertising_data, ..
            }
            | ScannableUndirected {
                advertising_data, ..
            } => Some(advertising_data.iter()),
            ScanResponse { scan_data, .. } => Some(scan_data.iter()),
            ScanRequest { .. } | ConnectableDirected { .. } | ConnectRequest { .. } => None,
        }
    }
}

/// Decodes an advertising channel PDU (consisting of header and payload) from raw bytes.
impl<'a> FromBytes<'a> for Pdu<'a> {
    fn from_bytes(bytes: &mut ByteReader<'a>) -> Result<Self, Error> {
        let header = Header::from_bytes(bytes)?;
        Self::from_header_and_payload(header, bytes)
    }
}

/// Connection parameters sent along with a `ConnectRequest` PDU (also known as `LLData`).
#[derive(Copy, Clone, Debug)]
pub struct ConnectRequestData {
    access_address: Hex<u32>,
    crc_init: Hex<u32>,
    /// Transmit window size in µs.
    win_size: Duration,
    /// Transmit window offset in µs.
    win_offset: Duration,
    /// Connection interval in µs.
    interval: Duration,
    /// Slave latency (number of connection events).
    latency: u16,
    /// Connection timeout.
    timeout: Duration,
    chm: ChannelMap,
    hop: u8,
    sca: SleepClockAccuracy,
}

impl ConnectRequestData {
    /// Returns the Access Address to use for data channel communication.
    ///
    /// The address is randomly generated by the initiator (the device sending the connection
    /// request) according to the requirements in the Bluetooth specification.
    pub fn access_address(&self) -> u32 {
        self.access_address.0
    }

    /// Returns the initialization value for the CRC calculation.
    ///
    /// The CRC *polynomial* is always the same.
    pub fn crc_init(&self) -> u32 {
        self.crc_init.0
    }

    /// Returns the channel map specified by the initiator.
    pub fn channel_map(&self) -> &ChannelMap {
        &self.chm
    }

    /// Returns the channel hop distance.
    ///
    /// This must be in range `5..=16`.
    pub fn hop(&self) -> u8 {
        self.hop
    }

    /// Returns the end of the transmit window from reception of the `CONNECT_REQ` containing
    /// `self`.
    pub fn end_of_tx_window(&self) -> Duration {
        // We only handle `CONNECT_IND`, so transmitWindowDelay is 1.25 ms
        let transmit_window_delay = Duration::from_micros(1250);

        self.win_offset + self.win_size + transmit_window_delay
    }

    /// Returns the connection event interval in µs.
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// Returns the slave latency (as the number of connection events).
    pub fn slave_latency(&self) -> u16 {
        self.latency
    }

    /// Returns the connection supervision timeout (`connSupervisionTimeout`) to use for this
    /// connection.
    ///
    /// If no data packet is received for this duration, the connection should be considered lost.
    pub fn supervision_timeout(&self) -> Duration {
        self.timeout
    }
}

impl FromBytes<'_> for ConnectRequestData {
    fn from_bytes(bytes: &mut ByteReader<'_>) -> Result<Self, Error> {
        let sca;
        Ok(Self {
            access_address: Hex(bytes.read_u32_le()?),
            crc_init: {
                let mut le_bytes = [0u8; 4];
                le_bytes[..3].copy_from_slice(bytes.read_slice(3)?);
                Hex(u32::from_le_bytes(le_bytes))
            },
            // transmitWindowSize in 1.25 ms steps
            win_size: Duration::from_micros(u32::from(bytes.read_u8()?) * 1250),
            // transmitWindowOffset in 1.25 ms steps
            win_offset: Duration::from_micros(u32::from(bytes.read_u16_le()?) * 1250),
            // connInterval in 1.25 ms steps
            interval: Duration::from_micros(u32::from(bytes.read_u16_le()?) * 1250),
            // connSlaveLatency in no. of events
            latency: bytes.read_u16_le()?,
            // supervision timeout in 10 ms steps
            timeout: Duration::from_micros(u32::from(bytes.read_u16_le()?) * 10_000),
            chm: ChannelMap::from_raw(bytes.read_array()?),
            hop: {
                let hop_and_sca = bytes.read_u8()?;
                sca = (hop_and_sca >> 5) & 0b111;
                hop_and_sca & 0b11111
            },
            sca: {
                use self::SleepClockAccuracy::*;
                match sca {
                    0 => Ppm251To500,
                    1 => Ppm151To250,
                    2 => Ppm101To150,
                    3 => Ppm76To100,
                    4 => Ppm51To75,
                    5 => Ppm31To50,
                    6 => Ppm21To30,
                    7 => Ppm0To20,
                    _ => unreachable!(), // only 3 bits
                }
            },
        })
    }
}

/// Indicates the master's sleep clock accuracy (SCA) in ppm (parts per
/// million).
///
/// The lower the PPM, the higher the accuracy.
#[derive(Copy, Clone, Debug)]
pub enum SleepClockAccuracy {
    Ppm251To500,
    Ppm151To250,
    Ppm101To150,
    Ppm76To100,
    Ppm51To75,
    Ppm31To50,
    Ppm21To30,
    Ppm0To20,
}

/// Stores an advertising channel PDU.
///
/// This is an owned version of `Pdu` and should be used when *creating* a PDU
/// to be sent out.
pub struct PduBuf {
    /// 2-Byte header.
    header: Header,
    /// Fixed-size buffer that can store the largest PDU. Actual length is
    /// stored in the header.
    payload_buf: [u8; MAX_PAYLOAD_SIZE],
}

impl PduBuf {
    /// Builds a PDU buffer containing advertiser address and data.
    fn adv(
        ty: PduType,
        adv: DeviceAddress,
        adv_data: &mut dyn Iterator<Item = &AdStructure<'_>>,
    ) -> Result<Self, Error> {
        let mut payload = [0; MAX_PAYLOAD_SIZE];
        let mut buf = ByteWriter::new(&mut payload[..]);
        buf.write_slice(adv.raw()).unwrap();
        for ad in adv_data {
            ad.to_bytes(&mut buf)?;
        }

        let left = buf.space_left();
        let used = payload.len() - left;
        let mut header = Header::new(ty);
        header.set_payload_length(used as u8);
        header.set_tx_add(adv.is_random());
        header.set_rx_add(false);
        Ok(Self {
            header,
            payload_buf: payload,
        })
    }

    /// Creates a connectable undirected advertising PDU (`ADV_IND`).
    ///
    /// # Parameters
    ///
    /// * `adv`: The advertiser address, the address of the device sending this
    ///   PDU.
    /// * `adv_data`: Additional advertising data to send.
    pub fn connectable_undirected(
        advertiser_addr: DeviceAddress,
        advertiser_data: &[AdStructure<'_>],
    ) -> Result<Self, Error> {
        Self::adv(
            PduType::AdvInd,
            advertiser_addr,
            &mut advertiser_data.iter(),
        )
    }

    /// Creates a connectable directed advertising PDU (`ADV_DIRECT_IND`).
    pub fn connectable_directed(
        advertiser_addr: DeviceAddress,
        initiator_addr: DeviceAddress,
    ) -> Self {
        let mut payload = [0; 37];
        payload[0..6].copy_from_slice(advertiser_addr.raw());
        payload[6..12].copy_from_slice(initiator_addr.raw());

        let mut header = Header::new(PduType::AdvDirectInd);
        header.set_payload_length(6 + 6);
        header.set_tx_add(advertiser_addr.is_random());
        header.set_rx_add(initiator_addr.is_random());

        Self {
            header,
            payload_buf: payload,
        }
    }

    /// Creates a non-connectable undirected advertising PDU
    /// (`ADV_NONCONN_IND`).
    ///
    /// This is equivalent to `PduBuf::beacon`, which should be preferred when
    /// building a beacon PDU to improve clarity.
    pub fn nonconnectable_undirected(
        advertiser_addr: DeviceAddress,
        advertiser_data: &[AdStructure<'_>],
    ) -> Result<Self, Error> {
        Self::adv(
            PduType::AdvNonconnInd,
            advertiser_addr,
            &mut advertiser_data.iter(),
        )
    }

    /// Creates a scannable undirected advertising PDU (`ADV_SCAN_IND`).
    ///
    /// Note that scanning is not supported at the moment.
    pub fn scannable_undirected(
        advertiser_addr: DeviceAddress,
        advertiser_data: &[AdStructure<'_>],
    ) -> Result<Self, Error> {
        Self::adv(
            PduType::AdvScanInd,
            advertiser_addr,
            &mut advertiser_data.iter(),
        )
    }

    /// Creates an advertising channel PDU suitable for building a simple
    /// beacon.
    ///
    /// This is equivalent to `PduBuf::nonconnectable_undirected`.
    pub fn beacon(
        advertiser_addr: DeviceAddress,
        advertiser_data: &[AdStructure<'_>],
    ) -> Result<Self, Error> {
        Self::nonconnectable_undirected(advertiser_addr, advertiser_data)
    }

    /// Creates an advertising PDU that makes this device "visible" for scanning
    /// devices that want to establish a connection.
    ///
    /// This should be used when this device would like to initiate pairing.
    ///
    /// This function is mostly equivalent to `PduBuf::connectable_undirected`,
    /// but will automatically add a suitable `Flags` AD structure to the
    /// advertising data.
    ///
    /// To establish a connection with an already paired device, a "directed"
    /// advertisement must be sent instead.
    pub fn discoverable(
        advertiser_addr: DeviceAddress,
        advertiser_data: &[AdStructure<'_>],
    ) -> Result<Self, Error> {
        // TODO what's the difference between "general" and "limited" discoverability?
        Self::adv(
            PduType::AdvInd,
            advertiser_addr,
            &mut iter::once(&AdStructure::from(Flags::discoverable())).chain(advertiser_data),
        )
    }

    /// Creates a scan request PDU.
    ///
    /// Note that scanning is not yet implemented.
    ///
    /// # Parameters
    ///
    /// * `scanner`: Device address of the device in scanning state (sender of
    ///   the request).
    /// * `adv`: Device address of the advertising device that this scan request
    ///   is directed towards.
    pub fn scan_request(_scanner: DeviceAddress, _adv: DeviceAddress) -> Result<Self, Error> {
        unimplemented!()
    }

    /// Creates a scan response PDU.
    ///
    /// Note that scanning is not yet implemented.
    pub fn scan_response(
        advertiser_addr: DeviceAddress,
        scan_data: &[AdStructure<'_>],
    ) -> Result<Self, Error> {
        let mut payload = [0; MAX_PAYLOAD_SIZE];
        let mut buf = ByteWriter::new(&mut payload[..]);
        buf.write_slice(advertiser_addr.raw()).unwrap();
        for ad in scan_data {
            ad.to_bytes(&mut buf)?;
        }

        let left = buf.space_left();
        let used = payload.len() - left;
        let mut header = Header::new(PduType::ScanRsp);
        header.set_payload_length(used as u8);
        header.set_tx_add(advertiser_addr.is_random());
        header.set_rx_add(false);
        Ok(Self {
            header,
            payload_buf: payload,
        })
    }

    pub fn header(&self) -> Header {
        self.header
    }

    pub fn payload(&self) -> &[u8] {
        let len = self.header.payload_length() as usize;
        &self.payload_buf[..len]
    }
}

impl fmt::Debug for PduBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({:?}, {:?})", self.header(), HexSlice(self.payload()))
    }
}

/// 16-bit Advertising Channel PDU header preceding the Payload.
///
/// The header looks like this:
///
/// ```notrust
/// LSB                                                                     MSB
/// +------------+------------+---------+---------+--------------+------------+
/// |  PDU Type  |     -      |  TxAdd  |  RxAdd  |    Length    |     -      |
/// |  (4 bits)  |  (2 bits)  | (1 bit) | (1 bit) |   (6 bits)   |  (2 bits)  |
/// +------------+------------+---------+---------+--------------+------------+
/// ```
///
/// The `TxAdd` and `RxAdd` field are only used for some payloads, for all others, they should be
/// set to 0.
///
/// Length may be in range 6 to 37 (inclusive). With the 2-Byte header this is exactly the max.
/// on-air packet size.
#[derive(Copy, Clone)]
pub struct Header(u16);

const TXADD_MASK: u16 = 0b00000000_01000000;
const RXADD_MASK: u16 = 0b00000000_10000000;

impl Header {
    /// Creates a new Advertising Channel PDU header specifying the Payload type `ty`.
    pub fn new(ty: PduType) -> Self {
        Header(u16::from(u8::from(ty)))
    }

    pub fn parse(raw: &[u8]) -> Self {
        let bytes: [u8; 2] = raw[..2].try_into().expect("raw has fewer than 2 bytes");
        Header(u16::from_le_bytes(bytes))
    }

    /// Returns the raw representation of the header.
    ///
    /// The returned `u16` must be transmitted LSb first as the first 2 octets of the PDU.
    pub fn to_u16(&self) -> u16 {
        self.0
    }

    /// Sets all bits in the header that are set in `mask`.
    fn set_header_bits(&mut self, mask: u16) {
        self.0 |= mask;
    }

    /// Clears all bits in the header that are set in `mask`.
    fn clear_header_bits(&mut self, mask: u16) {
        self.0 &= !mask;
    }

    /// Returns the PDU type specified in the header.
    pub fn type_(&self) -> PduType {
        PduType::from((self.0 & 0b00000000_00001111) as u8)
    }

    /// Returns the state of the `TxAdd` field.
    pub fn tx_add(&self) -> bool {
        self.0 & TXADD_MASK != 0
    }

    /// Sets the `TxAdd` field's value.
    pub fn set_tx_add(&mut self, value: bool) {
        if value {
            self.set_header_bits(TXADD_MASK);
        } else {
            self.clear_header_bits(TXADD_MASK);
        }
    }

    /// Returns the state of the `RxAdd` field.
    pub fn rx_add(&self) -> bool {
        self.0 & RXADD_MASK != 0
    }

    /// Sets the `RxAdd` field's value.
    pub fn set_rx_add(&mut self, value: bool) {
        if value {
            self.set_header_bits(RXADD_MASK);
        } else {
            self.clear_header_bits(RXADD_MASK);
        }
    }

    /// Returns the length of the payload in octets as specified in the `Length` field.
    ///
    /// According to the spec, the length must be in range 6...37, but this isn't checked by this
    /// function.
    pub fn payload_length(&self) -> u8 {
        ((self.0 & 0b00111111_00000000) >> 8) as u8
    }

    /// Sets the payload length of this PDU.
    ///
    /// The `length` must be in range 6...37, otherwise this function panics.
    pub fn set_payload_length(&mut self, length: u8) {
        assert!(6 <= length && length <= 37);

        let header = self.0 & !0b00111111_00000000;
        self.0 = header | (u16::from(length) << 8);
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Header")
            .field("PDU Type", &self.type_())
            .field("TxAdd", &self.tx_add())
            .field("RxAdd", &self.rx_add())
            .field("len", &self.payload_length())
            .finish()
    }
}

impl<'a> FromBytes<'a> for Header {
    fn from_bytes(bytes: &mut ByteReader<'a>) -> Result<Self, Error> {
        let raw = bytes.read_u16_le()?;
        Ok(Header(raw))
    }
}

impl ToBytes for Header {
    fn to_bytes(&self, writer: &mut ByteWriter<'_>) -> Result<(), Error> {
        writer.write_u16_le(self.0)
    }
}

enum_with_unknown! {
    /// 4-bit PDU type in [`Header`].
    ///
    /// For more details, see [`PduBuf`].
    #[derive(Debug, PartialEq, Eq)]
    pub enum PduType(u8) {
        /// Connectable undirected advertising event (`ADV_IND`).
        AdvInd = 0b0000,
        /// Connectable directed advertising event (`ADV_DIRECT_IND`).
        AdvDirectInd = 0b0001,
        /// Non-connectable undirected advertising event (`ADV_NONCONN_IND`).
        AdvNonconnInd = 0b0010,
        /// Scannable undirected advertising event (`ADV_SCAN_IND`).
        AdvScanInd = 0b0110,

        /// Scan request (`SCAN_REQ`).
        ///
        /// Sent by device in Scanning State, received by device in Advertising
        /// State.
        ScanReq = 0b0011,
        /// Scan response (`SCAN_RSP`).
        ///
        /// Sent by device in Advertising State, received by devicein Scanning
        /// State.
        ScanRsp = 0b0100,
        /// Connect request (`CONNECT_REQ`).
        ///
        /// Sent by device in Initiating State, received by device in
        /// Advertising State.
        ConnectReq = 0b0101,
    }
}

impl PduType {
    /// Returns whether this PDU type is a beacon advertisement.
    pub fn is_beacon(&self) -> bool {
        *self == PduType::AdvNonconnInd
    }

    /// Whether AD structures can follow the fixed data in a PDU of this type.
    pub fn allows_adv_data(&self) -> bool {
        match self {
            PduType::AdvInd | PduType::AdvNonconnInd | PduType::AdvScanInd | PduType::ScanRsp => {
                true
            }
            PduType::AdvDirectInd
            | PduType::ScanReq
            | PduType::ConnectReq
            | PduType::Unknown(_) => false,
        }
    }
}

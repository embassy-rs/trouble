//! Data Channel structures.

use crate::link::{llcp::ControlPdu, SeqNum};
use crate::{bytes::*, Error};
use core::{convert::TryInto, fmt};

/// 16-bit data channel header preceding the payload.
///
/// Layout (in Bluetooth 4.2):
///
/// ```notrust
/// LSB                                                                MSB
/// +----------+---------+---------+---------+------------+--------------+
/// |   LLID   |  NESN   |   SN    |   MD    |     -      |    Length    |
/// | (2 bits) | (1 bit) | (1 bit) | (1 bit) |  (3 bits)  |   (8 bits)   |
/// +----------+---------+---------+---------+------------+--------------+
/// ```
///
/// Payload format depends on the value of the 2-bit `LLID` field:
///
/// * `0b00`: Reserved value.
/// * `0b01`: LL Data PDU Continuation fragment or empty PDU.
/// * `0b10`: LL Data PDU Start of L2CAP message (or complete message if no fragmentation
///   necessary).
/// * `0b11`: LL Control PDU.
///
/// The `NESN` field specifies the **N**ext **E**xpected **S**equence **N**umber. The `SN` field
/// specifies the **S**equence **N**umber of this PDU.
///
/// The `MD` field specifies that the device sending the packet has more data to send during this
/// *connection event*. When both slave and master send a packet with the `MD` bit set to 0, the
/// connection event ends.
///
/// The `Length` field specifies the length of payload **and `MIC`**. Prior to Bluetooth 4.2, this
/// was a 5-bit field, resulting in payloads + MICs of up to 31 Bytes. With Bluetooth 4.2, devices
/// can communicate their buffer sizes and optionally transmit larger packets.
///
/// ## Sequence Numbers
///
/// The `NESN` and `SN` fields are used for retransmission and acknowledgement. The link layer
/// stores two 1-bit parameters for an established connection, called `transmitSeqNum` and
/// `nextExpectedSeqNum`. When a connection is established, both start out as 0. Both parameters are
/// repeatedly incremented by 1 when data is transmitted, using wrapping arithmetic.
///
/// When a data channel packet is sent for the first time (ie. not retransmitted), the `SN` field is
/// set to `transmitSeqNum`. When the packet is resent, the `SN` field is not modified. In both
/// cases, the `NESN` bit is set to `nextExpectedSeqNum`.
///
/// The `NESN` bit tells the receiver whether its last packet has arrived: When a packet is
/// received with an `NESN` value equal to the receiver's `transmitSeqNum`, the receiver has already
/// sent a packet with the expected `SN`, but the other side hasn't received it yet. The receiver
/// must resend the last data channel PDU. No other data channel PDU must be sent by it.
///
/// When the received packet's `NESN` bit is different from `transmitSeqNum`, the last PDU has been
/// acknowledged and the receiver should increment `transmitSeqNum` by 1.
///
/// Similarly, the `SN` bit is used to distinguish retransmitted and new packets: When a packet is
/// received with an `SN` value equal to the receiver's `nextExpectedSeqNum` value, the packet is
/// new (not a retransmission), and `nextExpectedSeqNum` should be incremented by 1. If the value is
/// not equal to `nextExpectedSeqNum`, this packet is a retransmission, so `nextExpectedSeqNum`
/// should not be changed.
#[derive(Copy, Clone)]
pub struct Header(u16);

impl Header {
    /// Creates a header with the given LLID field and all other fields set to 0 (including the
    /// payload length).
    pub fn new(llid: Llid) -> Self {
        Header(llid as u16)
    }

    /// Parses a header from raw bytes.
    ///
    /// Panics when `raw` contains less than 2 Bytes.
    pub fn parse(raw: &[u8]) -> Self {
        let bytes: [u8; 2] = raw[..2].try_into().expect("raw has fewer than 2 bytes");
        Header(u16::from_le_bytes(bytes))
    }

    /// Returns the raw representation of the header.
    ///
    /// The returned `u16` must be transmitted LSB and LSb first as the first 2 octets of the PDU.
    pub fn to_u16(&self) -> u16 {
        self.0
    }

    /// Returns the length of the payload in octets as specified in the `Length` field.
    pub fn payload_length(&self) -> u8 {
        ((self.0 & 0b11111111_00000000) >> 8) as u8
    }

    /// Sets the payload length field to `len`.
    ///
    /// Note that BLE <4.2 is restricted to 5-bit payload lengths.
    pub fn set_payload_length(&mut self, len: u8) {
        self.0 = (u16::from(len) << 8) | (self.0 & 0x00ff);
    }

    /// Returns the `LLID` field (PDU type).
    pub fn llid(&self) -> Llid {
        let bits = self.0 & 0b11;
        match bits {
            0b00 => Llid::Reserved,
            0b01 => Llid::DataCont,
            0b10 => Llid::DataStart,
            0b11 => Llid::Control,
            _ => unreachable!(),
        }
    }

    /// Returns the value of the `NESN` field (Next Expected Sequence Number).
    pub fn nesn(&self) -> SeqNum {
        let bit = self.0 & 0b0100;
        if bit == 0 {
            SeqNum::ZERO
        } else {
            SeqNum::ONE
        }
    }

    /// Sets the value of the `NESN` field.
    pub fn set_nesn(&mut self, nesn: SeqNum) {
        if nesn == SeqNum::ONE {
            self.0 |= 0b0100;
        } else {
            self.0 &= !0b0100;
        }
    }

    /// Returns the value of the `SN` field (Sequence Number).
    pub fn sn(&self) -> SeqNum {
        let bit = self.0 & 0b1000;
        if bit == 0 {
            SeqNum::ZERO
        } else {
            SeqNum::ONE
        }
    }

    /// Sets the value of the `SN` field.
    pub fn set_sn(&mut self, sn: SeqNum) {
        if sn == SeqNum::ONE {
            self.0 |= 0b1000;
        } else {
            self.0 &= !0b1000;
        }
    }

    /// Returns whether the `MD` field is set (More Data).
    pub fn md(&self) -> bool {
        let bit = self.0 & 0b10000;
        bit != 0
    }

    /// Sets the value of the `MD` field.
    pub fn set_md(&mut self, md: bool) {
        if md {
            self.0 |= 0b10000;
        } else {
            self.0 &= !0b10000;
        }
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Header")
            .field("LLID", &self.llid())
            .field("NESN", &self.nesn())
            .field("SN", &self.sn())
            .field("MD", &self.md())
            .field("Length", &self.payload_length())
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
        writer.write_u16_le(self.to_u16())
    }
}

/// Values of the LLID field in `Header`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Llid {
    /// Reserved for future use.
    Reserved = 0b00,

    /// Continuation of L2CAP message, or empty PDU.
    DataCont = 0b01,

    /// Start of L2CAP message.
    DataStart = 0b10,

    /// LL control PDU.
    Control = 0b11,
}

/// Structured representation of a data channel PDU.
#[derive(Debug)]
pub enum Pdu<'a, L> {
    /// Continuation of an L2CAP message (or empty PDU).
    DataCont { message: L },

    /// Start of an L2CAP message (must not be empty).
    DataStart { message: L },

    /// LL Control PDU for controlling the Link-Layer connection.
    Control { data: BytesOr<'a, ControlPdu<'a>> },
}

impl<'a> Pdu<'a, &'a [u8]> {
    /// Creates an empty PDU that carries no message.
    ///
    /// This PDU can be sent whenever there's no actual data to be transferred.
    pub fn empty() -> Self {
        Pdu::DataCont { message: &[] }
    }
}

impl<'a, L> Pdu<'a, L> {
    /// Returns the `LLID` field to use for this PDU.
    pub fn llid(&self) -> Llid {
        match self {
            Pdu::DataCont { .. } => Llid::DataCont,
            Pdu::DataStart { .. } => Llid::DataStart,
            Pdu::Control { .. } => Llid::Control,
        }
    }
}

impl<'a, L: FromBytes<'a> + ?Sized> Pdu<'a, L> {
    /// Parses a PDU from a `Header` and raw payload.
    pub fn parse(header: Header, payload: &'a [u8]) -> Result<Self, Error> {
        match header.llid() {
            Llid::DataCont => Ok(Pdu::DataCont {
                message: L::from_bytes(&mut ByteReader::new(payload))?,
            }),
            Llid::DataStart => Ok(Pdu::DataStart {
                message: L::from_bytes(&mut ByteReader::new(payload))?,
            }),
            Llid::Control => Ok(Pdu::Control {
                data: BytesOr::from_bytes(&mut ByteReader::new(payload))?,
            }),
            Llid::Reserved => Err(Error::InvalidValue),
        }
    }
}

impl<'a> From<&'a ControlPdu<'a>> for Pdu<'a, &'a [u8]> {
    fn from(c: &'a ControlPdu<'a>) -> Self {
        Pdu::Control { data: c.into() }
    }
}

/// Serializes the payload of the PDU to bytes.
///
/// The PDU header must be constructed using Link-Layer state (and `Pdu::llid`).
impl<'a, L: ToBytes> ToBytes for Pdu<'a, L> {
    fn to_bytes(&self, buffer: &mut ByteWriter<'_>) -> Result<(), Error> {
        match self {
            Pdu::DataCont { message } | Pdu::DataStart { message } => message.to_bytes(buffer),
            Pdu::Control { data } => data.to_bytes(buffer),
        }
    }
}

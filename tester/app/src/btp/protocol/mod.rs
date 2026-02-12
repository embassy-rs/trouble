//! BTP protocol definitions and parsing.
//!
//! This module contains type-safe representations of all BTP packets,
//! commands, responses, and events. Parsing and serialization are
//! implemented here, completely independent of the functional BTP
//! implementation.

pub mod core;
pub mod gap;
pub mod gatt;
pub mod header;
pub mod l2cap;

use embedded_io_async::{Read, Write};
pub use header::{BtpHeader, HEADER_SIZE};

use crate::btp::error::{Error, from_read_exact_error};
use crate::btp::types::{AddrKind, Address, BdAddr, Opcode, ServiceId};

/// Compute a supported-commands bitmask from a list of opcodes.
///
/// Each opcode sets bit `opcode` in the resulting byte array (i.e., bit
/// `opcode % 8` of byte `opcode / 8`).
///
/// # Panics
///
/// Panics at compile time if any opcode exceeds the bitmask size, or if the
/// most significant byte of the result is zero (meaning `N` is too large).
pub(crate) const fn supported_commands_bitmask<const N: usize>(opcodes: &[Opcode]) -> [u8; N] {
    let mut result = [0u8; N];
    let mut i = 0;
    while i < opcodes.len() {
        let opcode = opcodes[i].0 as usize;
        let byte_idx = opcode / 8;
        let bit_idx = opcode % 8;
        ::core::assert!(byte_idx < N, "opcode exceeds bitmask size");
        result[byte_idx] |= 1 << bit_idx;
        i += 1;
    }
    ::core::assert!(result[N - 1] != 0, "bitmask array is larger than needed");
    result
}

/// A synchronous, bounds-checked cursor for parsing borrowed data from a byte slice.
pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// Create a new cursor over the given data.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Read exactly `n` bytes, returning a borrowed sub-slice.
    pub fn read_exact(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.pos + n > self.data.len() {
            return Err(Error::BufferTooShort);
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    /// Read a single byte.
    pub fn read_u8(&mut self) -> Result<u8, Error> {
        let slice = self.read_exact(1)?;
        Ok(slice[0])
    }

    /// Read a little-endian u16.
    pub fn read_u16_le(&mut self) -> Result<u16, Error> {
        let slice = self.read_exact(2)?;
        Ok(u16::from_le_bytes([slice[0], slice[1]]))
    }

    /// Read a little-endian u32.
    pub fn read_u32_le(&mut self) -> Result<u32, Error> {
        let slice = self.read_exact(4)?;
        Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    }

    /// Read a 7-byte address (1 byte addr_type + 6 bytes BdAddr).
    pub fn read_address(&mut self) -> Result<Address, Error> {
        let slice = self.read_exact(7)?;
        Ok(Address {
            kind: AddrKind::new(slice[0]),
            addr: BdAddr::new([slice[1], slice[2], slice[3], slice[4], slice[5], slice[6]]),
        })
    }

    /// Return the number of remaining unconsumed bytes.
    pub fn remaining_len(&self) -> usize {
        self.data.len() - self.pos
    }
}

/// BTP MTU (maximum packet size including header).
pub const MTU: u16 = 1024;

/// Maximum data size for a BTP packet (MTU minus header).
pub const MAX_DATA_SIZE: usize = MTU as usize - HEADER_SIZE;

/// BTP protocol status codes returned in error responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum BtpStatus {
    /// Command failed.
    Fail = 0x01,
    /// Unknown command opcode.
    UnknownCommand = 0x02,
    /// IUT not ready to receive commands.
    NotReady = 0x03,
    /// Invalid controller index.
    InvalidIndex = 0x04,
}

impl From<Error> for BtpStatus {
    /// Convert this error to a BTP status code for error responses.
    fn from(err: Error) -> Self {
        match err {
            Error::UnknownCommand { .. } => BtpStatus::UnknownCommand,
            Error::InvalidIndex => BtpStatus::InvalidIndex,
            Error::UnknownService(_) => BtpStatus::UnknownCommand,
            _ => BtpStatus::Fail,
        }
    }
}

/// A BTP packet with header and data buffer.
#[derive(Debug, Clone)]
pub struct BtpPacket {
    /// The packet header.
    pub header: BtpHeader,
    /// Data buffer (only first `header.data_len` bytes are valid).
    data: [u8; MAX_DATA_SIZE],
}

impl BtpPacket {
    /// Create a new empty packet.
    pub const fn new() -> Self {
        Self {
            header: BtpHeader::new(ServiceId(0), Opcode(0), None, 0),
            data: [0u8; MAX_DATA_SIZE],
        }
    }

    /// Read a packet from the reader.
    pub async fn read<R: Read>(&mut self, mut reader: R) -> Result<(), Error> {
        self.header = BtpHeader::read(&mut reader).await?;
        let len = self.header.data_len as usize;
        if len > MAX_DATA_SIZE {
            return Err(Error::BufferTooShort);
        }
        if len > 0 {
            reader
                .read_exact(&mut self.data[..len])
                .await
                .map_err(from_read_exact_error)?;
        }
        Ok(())
    }

    /// Get the packet data.
    pub fn data(&self) -> &[u8] {
        &self.data[..self.header.data_len as usize]
    }
}

impl Default for BtpPacket {
    fn default() -> Self {
        Self::new()
    }
}

/// A parsed BTP command packet.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BtpCommand<'a> {
    /// Core service command.
    Core(core::CoreCommand),
    /// GAP service command.
    Gap(gap::GapCommand<'a>),
    /// GATT Server service command.
    Gatt(gatt::GattCommand<'a>),
    /// L2CAP service command.
    L2cap(l2cap::L2capCommand<'a>),
}

impl<'a> BtpCommand<'a> {
    /// Parse a command from header and data slice.
    pub fn parse(header: &BtpHeader, data: &'a [u8]) -> Result<Self, Error> {
        if !header.opcode.is_command() {
            return Err(Error::InvalidPacket);
        }

        let mut cursor = Cursor::new(data);
        let cmd = match header.service_id {
            ServiceId::CORE => {
                let cmd = core::CoreCommand::parse(header, &mut cursor)?;
                BtpCommand::Core(cmd)
            }
            ServiceId::GAP => {
                let cmd = gap::GapCommand::parse(header, &mut cursor)?;
                BtpCommand::Gap(cmd)
            }
            ServiceId::GATT => {
                let cmd = gatt::GattCommand::parse(header, &mut cursor)?;
                BtpCommand::Gatt(cmd)
            }
            ServiceId::L2CAP => {
                let cmd = l2cap::L2capCommand::parse(header, &mut cursor)?;
                BtpCommand::L2cap(cmd)
            }
            _ => return Err(Error::UnknownService(header.service_id)),
        };
        let remaining = cursor.remaining_len();
        if remaining > 0 {
            warn!(
                "Command {:?} has {} unconsumed trailing byte(s)",
                header.opcode, remaining
            );
        }
        Ok(cmd)
    }
}

/// A BTP response to be sent.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BtpResponse<'a> {
    /// Core service response.
    Core(core::CoreResponse),
    /// GAP service response.
    Gap(gap::GapResponse<'a>),
    /// GATT service response.
    Gatt(gatt::GattResponse),
    /// L2CAP service response.
    L2cap(l2cap::L2capResponse),
}

impl BtpResponse<'_> {
    /// Get the data length for this response.
    pub fn data_len(&self) -> u16 {
        match self {
            BtpResponse::Core(resp) => resp.data_len(),
            BtpResponse::Gap(resp) => resp.data_len(),
            BtpResponse::Gatt(resp) => resp.data_len(),
            BtpResponse::L2cap(resp) => resp.data_len(),
        }
    }

    /// Write the complete response (header + data).
    ///
    /// The response header is derived from the command header.
    pub async fn write<W: Write>(&self, cmd_header: &BtpHeader, mut writer: W) -> Result<(), W::Error> {
        let header = cmd_header.response(self.data_len());
        header.write(&mut writer).await?;
        match self {
            BtpResponse::Core(resp) => resp.write(&mut writer).await?,
            BtpResponse::Gap(resp) => resp.write(&mut writer).await?,
            BtpResponse::Gatt(resp) => resp.write(&mut writer).await?,
            BtpResponse::L2cap(resp) => resp.write(&mut writer).await?,
        }
        writer.flush().await
    }
}

/// A BTP event to be sent.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BtpEvent<'a> {
    /// Core service event.
    Core(core::CoreEvent),
    /// GAP service event.
    Gap(gap::GapEvent<'a>),
    /// GATT service event.
    Gatt(gatt::GattEvent<'a>),
    /// L2CAP service event.
    #[allow(unused)]
    L2cap(l2cap::L2capEvent<'a>),
}

impl BtpEvent<'_> {
    /// Get the header for this event.
    pub fn header(&self) -> BtpHeader {
        match self {
            BtpEvent::Core(evt) => evt.header(),
            BtpEvent::Gap(evt) => evt.header(),
            BtpEvent::Gatt(evt) => evt.header(),
            BtpEvent::L2cap(evt) => evt.header(),
        }
    }

    /// Write the complete event (header + data) and flush.
    pub async fn write<W: Write>(&self, mut writer: W) -> Result<(), W::Error> {
        self.header().write(&mut writer).await?;
        match self {
            BtpEvent::Core(evt) => evt.write(&mut writer).await?,
            BtpEvent::Gap(evt) => evt.write(&mut writer).await?,
            BtpEvent::Gatt(evt) => evt.write(&mut writer).await?,
            BtpEvent::L2cap(evt) => evt.write(&mut writer).await?,
        }
        writer.flush().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btp::error::Error;

    #[test]
    fn type_sizes() {
        use ::core::mem::size_of;
        assert!(
            size_of::<BtpCommand>() <= 64,
            "BtpCommand is {} bytes",
            size_of::<BtpCommand>()
        );
        assert!(
            size_of::<BtpResponse>() <= 64,
            "BtpResponse is {} bytes",
            size_of::<BtpResponse>()
        );
        assert!(
            size_of::<BtpEvent>() <= 48,
            "BtpEvent is {} bytes",
            size_of::<BtpEvent>()
        );
    }

    // --- Cursor tests ---

    #[test]
    fn cursor_empty_data() {
        let cursor = Cursor::new(&[]);
        assert_eq!(cursor.remaining_len(), 0);
    }

    #[test]
    fn cursor_read_exact_empty() {
        let mut cursor = Cursor::new(&[1, 2, 3]);
        let slice = cursor.read_exact(0).unwrap();
        assert!(slice.is_empty());
        assert_eq!(cursor.remaining_len(), 3);
    }

    #[test]
    fn cursor_read_exact_full() {
        let data = [0xAA, 0xBB, 0xCC];
        let mut cursor = Cursor::new(&data);
        let slice = cursor.read_exact(3).unwrap();
        assert_eq!(slice, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(cursor.remaining_len(), 0);
    }

    #[test]
    fn cursor_read_exact_overflow() {
        let mut cursor = Cursor::new(&[1, 2]);
        let result = cursor.read_exact(3);
        assert_eq!(result, Err(Error::BufferTooShort));
    }

    #[test]
    fn cursor_read_u8_empty() {
        let mut cursor = Cursor::new(&[]);
        assert_eq!(cursor.read_u8(), Err(Error::BufferTooShort));
    }

    #[test]
    fn cursor_read_u16_le_value() {
        let mut cursor = Cursor::new(&[0x34, 0x12]);
        assert_eq!(cursor.read_u16_le().unwrap(), 0x1234);
        assert_eq!(cursor.remaining_len(), 0);
    }

    #[test]
    fn cursor_read_u16_le_insufficient() {
        let mut cursor = Cursor::new(&[0x34]);
        assert_eq!(cursor.read_u16_le(), Err(Error::BufferTooShort));
    }

    #[test]
    fn cursor_read_u32_le_value() {
        let mut cursor = Cursor::new(&[0x78, 0x56, 0x34, 0x12]);
        assert_eq!(cursor.read_u32_le().unwrap(), 0x12345678);
    }

    #[test]
    fn cursor_read_u32_le_insufficient() {
        let mut cursor = Cursor::new(&[0x01, 0x02, 0x03]);
        assert_eq!(cursor.read_u32_le(), Err(Error::BufferTooShort));
    }

    #[test]
    fn cursor_read_address() {
        let mut cursor = Cursor::new(&[0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let addr = cursor.read_address().unwrap();
        assert_eq!(addr.kind, AddrKind::RANDOM);
        assert_eq!(addr.addr.raw(), &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(cursor.remaining_len(), 0);
    }

    #[test]
    fn cursor_read_address_insufficient() {
        let mut cursor = Cursor::new(&[0x01, 0x11, 0x22]);
        assert_eq!(cursor.read_address(), Err(Error::BufferTooShort));
    }

    #[test]
    fn cursor_sequential_reads() {
        let mut cursor = Cursor::new(&[0xAA, 0x34, 0x12, 0xBB]);
        assert_eq!(cursor.read_u8().unwrap(), 0xAA);
        assert_eq!(cursor.read_u16_le().unwrap(), 0x1234);
        assert_eq!(cursor.read_u8().unwrap(), 0xBB);
        assert_eq!(cursor.remaining_len(), 0);
    }

    #[test]
    fn cursor_remaining_after_partial_read() {
        let mut cursor = Cursor::new(&[1, 2, 3, 4, 5]);
        cursor.read_exact(2).unwrap();
        assert_eq!(cursor.remaining_len(), 3);
    }

    // --- BtpStatus conversion tests ---

    #[test]
    fn btp_status_from_unknown_command() {
        let err = Error::UnknownCommand {
            service: ServiceId::GAP,
            opcode: Opcode(0x7F),
        };
        assert_eq!(BtpStatus::from(err), BtpStatus::UnknownCommand);
    }

    #[test]
    fn btp_status_from_invalid_index() {
        assert_eq!(BtpStatus::from(Error::InvalidIndex), BtpStatus::InvalidIndex);
    }

    #[test]
    fn btp_status_from_unknown_service() {
        let err = Error::UnknownService(ServiceId(0xFF));
        assert_eq!(BtpStatus::from(err), BtpStatus::UnknownCommand);
    }

    #[test]
    fn btp_status_from_buffer_too_short() {
        assert_eq!(BtpStatus::from(Error::BufferTooShort), BtpStatus::Fail);
    }

    #[test]
    fn btp_status_from_invalid_packet() {
        assert_eq!(BtpStatus::from(Error::InvalidPacket), BtpStatus::Fail);
    }

    // --- BtpCommand::parse dispatch tests ---

    #[test]
    fn parse_rejects_event_opcode() {
        let header = BtpHeader::new(ServiceId::CORE, Opcode(0x80), None, 0);
        let result = BtpCommand::parse(&header, &[]);
        assert_eq!(result.unwrap_err(), Error::InvalidPacket);
    }

    #[test]
    fn parse_unknown_service() {
        let header = BtpHeader::new(ServiceId(0xFF), Opcode(0x01), None, 0);
        let result = BtpCommand::parse(&header, &[]);
        assert!(matches!(result, Err(Error::UnknownService(ServiceId(0xFF)))));
    }
}

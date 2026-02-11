//! BTP packet header parsing and serialization.

use embedded_io_async::{Read, Write};

use super::BtpStatus;
use crate::btp::error::{Error, from_read_exact_error};
use crate::btp::types::{Opcode, ServiceId};

/// BTP packet header size in bytes.
pub const HEADER_SIZE: usize = 5;

/// Wire value for non-controller index.
const NON_CONTROLLER: u8 = 0xFF;

/// BTP packet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BtpHeader {
    /// Service ID (0-255).
    pub service_id: ServiceId,
    /// Opcode (0x00 = error, 0x01-0x7F = commands, 0x80-0xFF = events).
    pub opcode: Opcode,
    /// Controller index (None = non-controller, Some(i) = controller i).
    pub controller_index: Option<u8>,
    /// Data length (little-endian).
    pub data_len: u16,
}

impl BtpHeader {
    /// Create a new header.
    pub const fn new(service_id: ServiceId, opcode: Opcode, controller_index: Option<u8>, data_len: u16) -> Self {
        Self {
            service_id,
            opcode,
            controller_index,
            data_len,
        }
    }

    /// Create a response header for a command (same service, opcode, and controller index).
    pub const fn response(&self, data_len: u16) -> Self {
        Self {
            service_id: self.service_id,
            opcode: self.opcode,
            controller_index: self.controller_index,
            data_len,
        }
    }

    /// Create an error response header.
    pub const fn error_response(&self) -> Self {
        Self {
            service_id: self.service_id,
            opcode: Opcode::ERROR,
            controller_index: self.controller_index,
            data_len: 1, // Status byte
        }
    }

    /// Create an event header.
    pub const fn event(service_id: ServiceId, opcode: Opcode, controller_index: Option<u8>, data_len: u16) -> Self {
        Self {
            service_id,
            opcode,
            controller_index,
            data_len,
        }
    }

    /// Read a 5-byte BTP header from the reader.
    pub async fn read<R: Read>(mut reader: R) -> Result<Self, Error> {
        let mut buf = [0; HEADER_SIZE];
        reader.read_exact(&mut buf).await.map_err(from_read_exact_error)?;

        let controller_index = match buf[2] {
            NON_CONTROLLER => None,
            i => Some(i),
        };

        Ok(Self {
            service_id: ServiceId(buf[0]),
            opcode: Opcode(buf[1]),
            controller_index,
            data_len: u16::from_le_bytes([buf[3], buf[4]]),
        })
    }

    /// Serialize this header as 5 bytes and write to the writer.
    pub async fn write<W: Write>(&self, mut writer: W) -> Result<(), W::Error> {
        let mut buf = [0; HEADER_SIZE];
        buf[0] = self.service_id.0;
        buf[1] = self.opcode.0;
        buf[2] = self.controller_index.unwrap_or(NON_CONTROLLER);
        let len_bytes = self.data_len.to_le_bytes();
        buf[3] = len_bytes[0];
        buf[4] = len_bytes[1];
        writer.write_all(&buf).await
    }

    /// Write a complete error response (error header + status byte) and flush.
    pub async fn write_err<W: Write>(&self, status: BtpStatus, mut writer: W) -> Result<(), W::Error> {
        let err_header = self.error_response();
        err_header.write(&mut writer).await?;
        writer.write_all(&[status as u8]).await?;
        writer.flush().await
    }
}

#[cfg(test)]
mod tests {
    use futures_executor::block_on;

    use super::*;

    #[test]
    fn test_header_parse_non_controller() {
        let mut buf = [0x01, 0x03, 0xFF, 0x04, 0x00].as_slice();
        let header = block_on(BtpHeader::read(&mut buf)).unwrap();

        assert_eq!(header.service_id, ServiceId(0x01));
        assert_eq!(header.opcode, Opcode(0x03));
        assert_eq!(header.controller_index, None);
        assert_eq!(header.data_len, 4);
    }

    #[test]
    fn test_header_parse_with_controller() {
        let mut buf = [0x01, 0x03, 0x02, 0x04, 0x00].as_slice();
        let header = block_on(BtpHeader::read(&mut buf)).unwrap();

        assert_eq!(header.controller_index, Some(2));
        assert_eq!(header.data_len, 4);
    }

    #[test]
    fn test_header_serialize() {
        let header = BtpHeader::new(ServiceId(0x01), Opcode(0x03), None, 4);

        let mut buf = [0u8; HEADER_SIZE];
        block_on(header.write(&mut buf.as_mut_slice())).unwrap();

        assert_eq!(buf, [0x01, 0x03, 0xFF, 0x04, 0x00]);
    }

    #[test]
    fn test_header_roundtrip() {
        let original = BtpHeader::new(ServiceId(0x07), Opcode(0x42), Some(0), 256);

        let mut buf = [0u8; HEADER_SIZE];
        block_on(original.write(&mut buf.as_mut_slice())).unwrap();

        let parsed = block_on(BtpHeader::read(&mut buf.as_slice())).unwrap();
        assert_eq!(parsed.service_id, original.service_id);
        assert_eq!(parsed.opcode, original.opcode);
        assert_eq!(parsed.controller_index, original.controller_index);
        assert_eq!(parsed.data_len, original.data_len);
    }
}

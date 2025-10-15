//! Attribute Protocol (ATT) PDU definitions
use core::fmt::Display;
use core::mem;

use crate::codec;
use crate::cursor::{ReadCursor, WriteCursor};
use crate::types::uuid::*;

pub(crate) const ATT_READ_BY_GROUP_TYPE_REQ: u8 = 0x10;
pub(crate) const ATT_READ_BY_GROUP_TYPE_RSP: u8 = 0x11;
pub(crate) const ATT_ERROR_RSP: u8 = 0x01;
pub(crate) const ATT_READ_BY_TYPE_REQ: u8 = 0x08;
pub(crate) const ATT_READ_BY_TYPE_RSP: u8 = 0x09;
pub(crate) const ATT_READ_REQ: u8 = 0x0a;
pub(crate) const ATT_READ_RSP: u8 = 0x0b;
pub(crate) const ATT_WRITE_REQ: u8 = 0x12;
pub(crate) const ATT_WRITE_CMD: u8 = 0x52;
pub(crate) const ATT_WRITE_RSP: u8 = 0x13;
pub(crate) const ATT_EXCHANGE_MTU_REQ: u8 = 0x02;
pub(crate) const ATT_EXCHANGE_MTU_RSP: u8 = 0x03;
pub(crate) const ATT_FIND_BY_TYPE_VALUE_REQ: u8 = 0x06;
pub(crate) const ATT_FIND_BY_TYPE_VALUE_RSP: u8 = 0x07;
pub(crate) const ATT_FIND_INFORMATION_REQ: u8 = 0x04;
pub(crate) const ATT_FIND_INFORMATION_RSP: u8 = 0x05;
pub(crate) const ATT_PREPARE_WRITE_REQ: u8 = 0x16;
pub(crate) const ATT_PREPARE_WRITE_RSP: u8 = 0x17;
pub(crate) const ATT_EXECUTE_WRITE_REQ: u8 = 0x18;
pub(crate) const ATT_EXECUTE_WRITE_RSP: u8 = 0x19;
pub(crate) const ATT_READ_MULTIPLE_REQ: u8 = 0x20;
pub(crate) const ATT_READ_MULTIPLE_RSP: u8 = 0x21;
pub(crate) const ATT_READ_BLOB_REQ: u8 = 0x0c;
pub(crate) const ATT_READ_BLOB_RSP: u8 = 0x0d;
pub(crate) const ATT_HANDLE_VALUE_NTF: u8 = 0x1b;
pub(crate) const ATT_HANDLE_VALUE_IND: u8 = 0x1d;
pub(crate) const ATT_HANDLE_VALUE_CMF: u8 = 0x1e;

/// Attribute Error Code
///
/// This enum type describes the `ATT_ERROR_RSP` PDU from the Bluetooth Core Specification
/// Version 6.0 | Vol 3, Part F (page 1491)
/// See also: Core Specification Supplement, Part B: Common Profile and Service Error Codes
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct AttErrorCode {
    value: u8,
}

impl AttErrorCode {
    /// Attempted to use a handle that isn't valid on this server
    pub const INVALID_HANDLE: Self = Self { value: 0x01 };
    /// The attribute cannot be read
    pub const READ_NOT_PERMITTED: Self = Self { value: 0x02 };
    /// The attribute cannot be written due to permissions
    pub const WRITE_NOT_PERMITTED: Self = Self { value: 0x03 };
    /// The attribute PDU was invalid
    pub const INVALID_PDU: Self = Self { value: 0x04 };
    /// The attribute requires authentication before it can be read or written
    pub const INSUFFICIENT_AUTHENTICATION: Self = Self { value: 0x05 };
    /// ATT Server does not support the request received from the client
    pub const REQUEST_NOT_SUPPORTED: Self = Self { value: 0x06 };
    /// Offset specified was past the end of the attribute
    pub const INVALID_OFFSET: Self = Self { value: 0x07 };
    /// The attribute requires authorisation before it can be read or written
    pub const INSUFFICIENT_AUTHORISATION: Self = Self { value: 0x08 };
    /// Too many prepare writes have been queued
    pub const PREPARE_QUEUE_FULL: Self = Self { value: 0x09 };
    /// No attribute found within the given attribute handle range
    pub const ATTRIBUTE_NOT_FOUND: Self = Self { value: 0x0a };
    /// The attribute cannot be read using the ATT_READ_BLOB_REQ PDU
    pub const ATTRIBUTE_NOT_LONG: Self = Self { value: 0x0b };
    /// The Encryption Key Size used for encrypting this link is too short
    pub const INSUFFICIENT_ENCRYPTION_KEY_SIZE: Self = Self { value: 0x0c };
    /// The attribute value length is invalid for the operation
    pub const INVALID_ATTRIBUTE_VALUE_LENGTH: Self = Self { value: 0x0d };
    /// The attribute request that was requested had encountered an error that was unlikely, and therefore could not be completed as requested
    pub const UNLIKELY_ERROR: Self = Self { value: 0x0e };
    /// The attribute requires encryption before it can be read or written
    pub const INSUFFICIENT_ENCRYPTION: Self = Self { value: 0x0f };
    /// The attribute type is not a supported grouping attribute as defined by a higher layer specification
    pub const UNSUPPORTED_GROUP_TYPE: Self = Self { value: 0x10 };
    /// Insufficient Resources to complete the request
    pub const INSUFFICIENT_RESOURCES: Self = Self { value: 0x11 };
    /// The server requests the client to rediscover the database
    pub const DATABASE_OUT_OF_SYNC: Self = Self { value: 0x12 };
    /// The attribute parameter value was not allowed
    pub const VALUE_NOT_ALLOWED: Self = Self { value: 0x13 };

    /// Common profile and service error codes
    /// The write request could not be fulfilled for reasons other than permissions
    pub const WRITE_REQUEST_REJECTED: Self = Self { value: 0xFC };
    /// The client characteristic configuration descriptor (CCCD) is not configured according to the requirements of the profile or service
    pub const CCCD_IMPROPERLY_CONFIGURED: Self = Self { value: 0xFD };
    /// The profile or service request could not be serviced because an operation that has been previously triggered is still in progress
    pub const PROCEDURE_ALREADY_IN_PROGRESS: Self = Self { value: 0xFE };
    /// The attribute value is out of range as defined by a profile or service specification
    pub const OUT_OF_RANGE: Self = Self { value: 0xFF };
}

impl Display for AttErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            &Self::INVALID_HANDLE => {
                f.write_str("invalid handle: Attempted to use a handle that isn't valid on this server")
            }
            &Self::READ_NOT_PERMITTED => f.write_str("read not permitted: the attribute cannot be read"),
            &Self::WRITE_NOT_PERMITTED => f.write_str("write not permitted: the attribute cannot be written due to permissions"),
            &Self::INVALID_PDU => f.write_str("invalid pdu: the attribute PDU was invalid"),
            &Self::INSUFFICIENT_AUTHENTICATION => f.write_str(
                "insufficient authentication: the attribute requires authentication before it can be written",
            ),
            &Self::REQUEST_NOT_SUPPORTED => {
                f.write_str("request not supported: ATT server does not support the request received from the client")
            }
            &Self::INVALID_OFFSET => f.write_str("Offset specified was past the end of the attribute"),
            &Self::INSUFFICIENT_AUTHORISATION => f.write_str(
                "insufficient authorisation: the attribute requires authorisation before it can be read or written",
            ),
            &Self::PREPARE_QUEUE_FULL => f.write_str("prepare queue full: too many prepare writes have been queued"),
            &Self::ATTRIBUTE_NOT_FOUND => f.write_str("attribute not found: no attribute found within the given attribute handle range"),
            &Self::ATTRIBUTE_NOT_LONG => f.write_str("The attribute cannot be read using the ATT_READ_BLOB_REQ PDU"),
            &Self::INSUFFICIENT_ENCRYPTION_KEY_SIZE => f.write_str("insufficient encryption key size: the encryption key size used for encrypting this link is too short"),
            &Self::INVALID_ATTRIBUTE_VALUE_LENGTH => f.write_str("invalid attribute value length: the attribute value length is invalid for the operation"),
            &Self::UNLIKELY_ERROR => f.write_str("unlikely error: the attribute request encountered an error that was unlikely, and therefore could not be completed"),
            &Self::INSUFFICIENT_ENCRYPTION => f.write_str("insufficient encryption: the attribute requires encryption before it can be read or written"),
            &Self::UNSUPPORTED_GROUP_TYPE => f.write_str("unsupported group type: the attribute type is not a supported grouping attribute as defined by a higher layer specification"),
            &Self::INSUFFICIENT_RESOURCES => f.write_str("insufficient resources: insufficient resources to complete the request"),
            &Self::DATABASE_OUT_OF_SYNC => f.write_str("the server requests the client to rediscover the database"),
            &Self::VALUE_NOT_ALLOWED => f.write_str("value not allowed: the attribute parameter value was not allowed"),

            &Self{value: 0x80..=0x9F} => write!(f, "application error code {}: check the application documentation of the device which produced this error code", self.value),

            &Self::WRITE_REQUEST_REJECTED => f.write_str("write request rejected: the write request could not be fulfilled for reasons other than permissions"),
            &Self::CCCD_IMPROPERLY_CONFIGURED => f.write_str("CCCD improperly configured: the client characteristic configuration descriptor (CCCD) is not configured according to the requirements of the profile or service"),
            &Self::PROCEDURE_ALREADY_IN_PROGRESS => f.write_str("procedure already in progress: the profile or service request could not be serviced because an operation that has been previously triggered is still in progress"),
            &Self::OUT_OF_RANGE => f.write_str("out of range: the attribute value is out of range as defined by a profile or service specification"),

            other => write!(f, "unknown error code {other}: check the most recent bluetooth spec"),
        }
    }
}

impl codec::Encode for AttErrorCode {
    fn encode(&self, dest: &mut [u8]) -> Result<(), codec::Error> {
        dest[0] = self.value;
        Ok(())
    }
}

impl codec::Decode<'_> for AttErrorCode {
    fn decode(src: &[u8]) -> Result<Self, codec::Error> {
        Ok(Self { value: src[0] })
    }
}

impl codec::Type for AttErrorCode {
    fn size(&self) -> usize {
        mem::size_of::<u8>()
    }
}

/// ATT Client PDU (Request, Command, Confirmation)
///
/// The ATT Client PDU is used to send requests, commands and confirmations to the ATT Server
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub enum AttClient<'d> {
    /// ATT Request PDU
    Request(AttReq<'d>),
    /// ATT Command PDU
    Command(AttCmd<'d>),
    /// ATT Confirmation PDU
    Confirmation(AttCfm),
}

/// ATT Request PDU
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub enum AttReq<'d> {
    /// Read By Group Type Request
    ReadByGroupType {
        /// Start attribute handle
        start: u16,
        /// End attribute handle
        end: u16,
        /// Group type
        group_type: Uuid,
    },
    /// Read By Type Request
    ReadByType {
        /// Start attribute handle
        start: u16,
        /// End attribute handle
        end: u16,
        /// Attribute type
        attribute_type: Uuid,
    },
    /// Read Request
    Read {
        /// Attribute handle
        handle: u16,
    },
    /// Write Request
    Write {
        /// Attribute handle
        handle: u16,
        /// Attribute value
        data: &'d [u8],
    },
    /// Exchange MTU Request
    ExchangeMtu {
        /// Client MTU
        mtu: u16,
    },
    /// Find By Type Value Request
    FindByTypeValue {
        /// Start attribute handle
        start_handle: u16,
        /// End attribute handle
        end_handle: u16,
        /// Attribute type
        att_type: u16,
        /// Attribute value
        att_value: &'d [u8],
    },
    /// Find Information Request
    FindInformation {
        /// Start attribute handle
        start_handle: u16,
        /// End attribute handle
        end_handle: u16,
    },
    /// Prepare Write Request
    PrepareWrite {
        /// Attribute handle
        handle: u16,
        /// Attribute offset
        offset: u16,
        /// Attribute value
        value: &'d [u8],
    },
    /// Execute Write Request
    ExecuteWrite {
        /// Flags
        flags: u8,
    },
    /// Read Multiple Request
    ReadMultiple {
        /// Attribute handles
        handles: &'d [u8],
    },
    /// Read Blob Request
    ReadBlob {
        /// Attribute handle
        handle: u16,
        /// Attribute offset
        offset: u16,
    },
}

/// ATT Command PDU
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub enum AttCmd<'d> {
    /// Write Command
    Write {
        /// Attribute handle
        handle: u16,
        /// Attribute value
        data: &'d [u8],
    },
}

/// ATT Confirmation PDU
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub enum AttCfm {
    /// Confirm Indication
    ConfirmIndication,
}

/// ATT Server PDU (Response, Unsolicited)
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub enum AttServer<'d> {
    /// ATT Response PDU
    Response(AttRsp<'d>),
    /// ATT Unsolicited PDU
    Unsolicited(AttUns<'d>),
}

/// ATT Response PDU
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub enum AttRsp<'d> {
    /// Exchange MTU Response
    ExchangeMtu {
        /// Server MTU
        mtu: u16,
    },
    /// Find By Type Value Response
    FindByTypeValue {
        /// Iterator over the found handles
        it: FindByTypeValueIter<'d>,
    },
    /// Find Information Response
    FindInformation {
        /// Iterator over the found handles and UUIDs
        it: FindInformationIter<'d>,
    },
    /// Error Response
    Error {
        /// Request opcode
        request: u8,
        /// Attribute handle
        handle: u16,
        /// Error code
        code: AttErrorCode,
    },
    /// Read Response
    ReadByType {
        /// Iterator over the found handles
        it: ReadByTypeIter<'d>,
    },
    /// Read Response
    Read {
        /// Attribute value
        data: &'d [u8],
    },
    /// Read Blob Response
    ReadBlob {
        /// Attribute value part
        data: &'d [u8],
    },
    /// Write Response
    Write,
}

/// ATT Unsolicited PDU
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub enum AttUns<'d> {
    /// Notify
    Notify {
        /// Attribute handle
        handle: u16,
        /// Attribute value
        data: &'d [u8],
    },
    /// Indicate
    Indicate {
        /// Attribute handle
        handle: u16,
        /// Attribute value
        data: &'d [u8],
    },
}

/// ATT Protocol Data Unit (PDU)
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub enum Att<'d> {
    /// ATT Client PDU (Request, Command, Confirmation)
    ///
    /// The ATT Client PDU is used to send requests, commands and confirmations to the ATT Server
    Client(AttClient<'d>),
    /// ATT Server PDU (Response, Unsolicited)
    ///
    /// The ATT Server PDU is used to send responses and unsolicited ATT PDUs (notifications and indications) to the ATT Client
    Server(AttServer<'d>),
}

/// An Iterator-like type for iterating over the found handles
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Clone, Debug)]
pub struct FindByTypeValueIter<'d> {
    cursor: ReadCursor<'d>,
}

impl FindByTypeValueIter<'_> {
    /// Get the next pair of start and end attribute handles
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<Result<(u16, u16), crate::Error>> {
        if self.cursor.available() >= 4 {
            let res = (|| {
                let handle: u16 = self.cursor.read()?;
                let end: u16 = self.cursor.read()?;
                Ok((handle, end))
            })();
            Some(res)
        } else {
            None
        }
    }
}

/// An Iterator-like type for iterating over the found handles
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Clone, Debug)]
pub struct ReadByTypeIter<'d> {
    item_len: usize,
    cursor: ReadCursor<'d>,
}

impl<'d> ReadByTypeIter<'d> {
    /// Get the next pair of attribute handle and attribute data
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<Result<(u16, &'d [u8]), crate::Error>> {
        if self.cursor.available() >= self.item_len {
            let res = (|| {
                let handle: u16 = self.cursor.read()?;
                let item = self.cursor.slice(self.item_len - 2)?;
                Ok((handle, item))
            })();
            Some(res)
        } else {
            None
        }
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Copy, Clone)]
enum FindInformationUuidFormat {
    Uuid16 = 1,
    Uuid128 = 2,
}

impl FindInformationUuidFormat {
    fn num_bytes(self) -> usize {
        match self {
            Self::Uuid16 => 2,
            Self::Uuid128 => 16,
        }
    }

    fn from(format: u8) -> Result<Self, codec::Error> {
        match format {
            1 => Ok(Self::Uuid16),
            2 => Ok(Self::Uuid128),
            _ => Err(codec::Error::InvalidValue),
        }
    }
}

/// An Iterator-like type for iterating over the handle/UUID pairs in a Find Information Response
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Clone, Debug)]
pub struct FindInformationIter<'d> {
    /// Format type: 1 = 16-bit UUIDs, 2 = 128-bit UUIDs
    format: FindInformationUuidFormat,
    cursor: ReadCursor<'d>,
}

impl<'d> FindInformationIter<'d> {
    /// Get the next pair of attribute handle and UUID
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<Result<(u16, Uuid), crate::Error>> {
        let uuid_len = self.format.num_bytes();

        if self.cursor.available() >= 2 + uuid_len {
            let res = (|| {
                let handle: u16 = self.cursor.read()?;
                let uuid = Uuid::try_from(self.cursor.slice(uuid_len)?)?;
                Ok((handle, uuid))
            })();
            Some(res)
        } else {
            None
        }
    }
}

impl<'d> AttServer<'d> {
    fn size(&self) -> usize {
        match self {
            Self::Response(rsp) => rsp.size(),
            Self::Unsolicited(uns) => uns.size(),
        }
    }

    fn encode(&self, dest: &mut [u8]) -> Result<(), codec::Error> {
        match self {
            Self::Response(rsp) => rsp.encode(dest),
            Self::Unsolicited(uns) => uns.encode(dest),
        }
    }

    fn decode_with_opcode(opcode: u8, r: ReadCursor<'d>) -> Result<Self, codec::Error> {
        let decoded = match opcode {
            ATT_HANDLE_VALUE_NTF | ATT_HANDLE_VALUE_IND => Self::Unsolicited(AttUns::decode_with_opcode(opcode, r)?),
            _ => Self::Response(AttRsp::decode_with_opcode(opcode, r)?),
        };
        Ok(decoded)
    }
}

impl<'d> AttRsp<'d> {
    fn size(&self) -> usize {
        1 + match self {
            Self::ExchangeMtu { mtu: u16 } => 2,
            Self::FindByTypeValue { it } => it.cursor.len(),
            Self::FindInformation { it } => 1 + it.cursor.len(), // 1 for format byte
            Self::Error { .. } => 4,
            Self::Read { data } => data.len(),
            Self::ReadBlob { data } => data.len(),
            Self::ReadByType { it } => it.cursor.len(),
            Self::Write => 0,
        }
    }

    fn encode(&self, dest: &mut [u8]) -> Result<(), codec::Error> {
        let mut w = WriteCursor::new(dest);
        match self {
            Self::ExchangeMtu { mtu } => {
                w.write(ATT_EXCHANGE_MTU_RSP)?;
                w.write(*mtu)?;
            }
            Self::FindByTypeValue { it } => {
                w.write(ATT_FIND_BY_TYPE_VALUE_RSP)?;
                let mut it = it.clone();
                while let Some(Ok((start, end))) = it.next() {
                    w.write(start)?;
                    w.write(end)?;
                }
            }
            Self::FindInformation { it } => {
                w.write(ATT_FIND_INFORMATION_RSP)?;
                w.write(it.format as u8)?;
                let mut it = it.clone();
                while let Some(Ok((handle, uuid))) = it.next() {
                    w.write(handle)?;
                    w.append(uuid.as_raw())?;
                }
            }
            Self::Error { request, handle, code } => {
                w.write(ATT_ERROR_RSP)?;
                w.write(*request)?;
                w.write(*handle)?;
                w.write(*code)?;
            }
            Self::ReadByType { it } => {
                w.write(ATT_READ_BY_TYPE_RSP)?;
                w.write(it.item_len as u8)?;
                let mut it = it.clone();
                while let Some(Ok((handle, item))) = it.next() {
                    w.write(handle)?;
                    w.append(item)?;
                }
            }
            Self::Read { data } => {
                w.write(ATT_READ_RSP)?;
                w.append(data)?;
            }
            Self::ReadBlob { data } => {
                w.write(ATT_READ_BLOB_RSP)?;
                w.append(data)?;
            }
            Self::Write => {
                w.write(ATT_WRITE_RSP)?;
            }
        }
        Ok(())
    }

    fn decode_with_opcode(opcode: u8, mut r: ReadCursor<'d>) -> Result<Self, codec::Error> {
        match opcode {
            ATT_FIND_BY_TYPE_VALUE_RSP => Ok(Self::FindByTypeValue {
                it: FindByTypeValueIter { cursor: r },
            }),
            ATT_FIND_INFORMATION_RSP => Ok(Self::FindInformation {
                it: FindInformationIter {
                    format: FindInformationUuidFormat::from(r.read()?)?,
                    cursor: r,
                },
            }),
            ATT_EXCHANGE_MTU_RSP => {
                let mtu: u16 = r.read()?;
                Ok(Self::ExchangeMtu { mtu })
            }
            ATT_ERROR_RSP => {
                let request = r.read()?;
                let handle = r.read()?;
                let code = r.read()?;
                Ok(Self::Error { request, handle, code })
            }
            ATT_READ_RSP => Ok(Self::Read { data: r.remaining() }),
            ATT_READ_BLOB_RSP => Ok(Self::ReadBlob { data: r.remaining() }),
            ATT_READ_BY_TYPE_RSP => {
                let item_len: u8 = r.read()?;
                Ok(Self::ReadByType {
                    it: ReadByTypeIter {
                        item_len: item_len as usize,
                        cursor: r,
                    },
                })
            }
            ATT_WRITE_RSP => Ok(Self::Write),
            _ => Err(codec::Error::InvalidValue),
        }
    }
}

impl<'d> AttUns<'d> {
    fn size(&self) -> usize {
        1 + match self {
            Self::Notify { data, .. } => 2 + data.len(),
            Self::Indicate { data, .. } => 2 + data.len(),
        }
    }

    fn encode(&self, dest: &mut [u8]) -> Result<(), codec::Error> {
        let mut w = WriteCursor::new(dest);
        match self {
            Self::Notify { handle, data } => {
                w.write(ATT_HANDLE_VALUE_NTF)?;
                w.write(*handle)?;
                w.append(data)?;
            }
            Self::Indicate { handle, data } => {
                w.write(ATT_HANDLE_VALUE_IND)?;
                w.write(*handle)?;
                w.append(data)?;
            }
        }
        Ok(())
    }

    fn decode_with_opcode(opcode: u8, mut r: ReadCursor<'d>) -> Result<Self, codec::Error> {
        match opcode {
            ATT_HANDLE_VALUE_NTF => {
                let handle = r.read()?;
                Ok(Self::Notify {
                    handle,
                    data: r.remaining(),
                })
            }
            ATT_HANDLE_VALUE_IND => {
                let handle = r.read()?;
                Ok(Self::Indicate {
                    handle,
                    data: r.remaining(),
                })
            }
            _ => Err(codec::Error::InvalidValue),
        }
    }
}

impl<'d> AttClient<'d> {
    fn size(&self) -> usize {
        match self {
            Self::Request(req) => req.size(),
            Self::Command(cmd) => cmd.size(),
            Self::Confirmation(cfm) => cfm.size(),
        }
    }

    fn encode(&self, dest: &mut [u8]) -> Result<(), codec::Error> {
        match self {
            Self::Request(req) => req.encode(dest),
            Self::Command(cmd) => cmd.encode(dest),
            Self::Confirmation(cfm) => cfm.encode(dest),
        }
    }

    fn decode_with_opcode(opcode: u8, r: ReadCursor<'d>) -> Result<Self, codec::Error> {
        let decoded = match opcode {
            ATT_WRITE_CMD => Self::Command(AttCmd::decode_with_opcode(opcode, r)?),
            ATT_HANDLE_VALUE_CMF => Self::Confirmation(AttCfm::decode_with_opcode(opcode, r)?),
            _ => Self::Request(AttReq::decode_with_opcode(opcode, r)?),
        };
        Ok(decoded)
    }
}

impl<'d> AttReq<'d> {
    fn size(&self) -> usize {
        1 + match self {
            Self::ExchangeMtu { .. } => 2,
            Self::FindByTypeValue {
                start_handle,
                end_handle,
                att_type,
                att_value,
            } => 6 + att_value.len(),
            Self::FindInformation {
                start_handle,
                end_handle,
            } => 4,
            Self::ReadByType {
                start,
                end,
                attribute_type,
            } => 4 + attribute_type.as_raw().len(),
            Self::Read { .. } => 2,
            Self::ReadBlob { .. } => 4, // handle (2 bytes) + offset (2 bytes)
            Self::Write { handle, data } => 2 + data.len(),
            _ => unimplemented!(),
        }
    }
    fn encode(&self, dest: &mut [u8]) -> Result<(), codec::Error> {
        let mut w = WriteCursor::new(dest);
        match self {
            Self::ExchangeMtu { mtu } => {
                w.write(ATT_EXCHANGE_MTU_REQ)?;
                w.write(*mtu)?;
            }
            Self::FindByTypeValue {
                start_handle,
                end_handle,
                att_type,
                att_value,
            } => {
                w.write(ATT_FIND_BY_TYPE_VALUE_REQ)?;
                w.write(*start_handle)?;
                w.write(*end_handle)?;
                w.write(*att_type)?;
                w.append(att_value)?;
            }
            Self::FindInformation {
                start_handle,
                end_handle,
            } => {
                w.write(ATT_FIND_INFORMATION_REQ)?;
                w.write(*start_handle)?;
                w.write(*end_handle)?;
            }
            Self::ReadByType {
                start,
                end,
                attribute_type,
            } => {
                w.write(ATT_READ_BY_TYPE_REQ)?;
                w.write(*start)?;
                w.write(*end)?;
                w.write_ref(attribute_type)?;
            }
            Self::Read { handle } => {
                w.write(ATT_READ_REQ)?;
                w.write(*handle)?;
            }
            Self::ReadBlob { handle, offset } => {
                w.write(ATT_READ_BLOB_REQ)?;
                w.write(*handle)?;
                w.write(*offset)?;
            }
            Self::Write { handle, data } => {
                w.write(ATT_WRITE_REQ)?;
                w.write(*handle)?;
                w.append(data)?;
            }
            _ => unimplemented!(),
        }
        Ok(())
    }

    fn decode_with_opcode(opcode: u8, r: ReadCursor<'d>) -> Result<Self, codec::Error> {
        let payload = r.remaining();
        match opcode {
            ATT_READ_BY_GROUP_TYPE_REQ => {
                let start_handle = (payload[0] as u16) + ((payload[1] as u16) << 8);
                let end_handle = (payload[2] as u16) + ((payload[3] as u16) << 8);

                let group_type = if payload.len() == 6 {
                    Uuid::Uuid16([payload[4], payload[5]])
                } else if payload.len() == 20 {
                    let uuid = payload[4..21].try_into().map_err(|_| codec::Error::InvalidValue)?;
                    Uuid::Uuid128(uuid)
                } else {
                    return Err(codec::Error::InvalidValue);
                };

                Ok(Self::ReadByGroupType {
                    start: start_handle,
                    end: end_handle,
                    group_type,
                })
            }
            ATT_READ_BY_TYPE_REQ => {
                let start_handle = (payload[0] as u16) + ((payload[1] as u16) << 8);
                let end_handle = (payload[2] as u16) + ((payload[3] as u16) << 8);

                let attribute_type = if payload.len() == 6 {
                    Uuid::Uuid16([payload[4], payload[5]])
                } else if payload.len() == 20 {
                    let uuid = payload[4..20].try_into().map_err(|_| codec::Error::InvalidValue)?;
                    Uuid::Uuid128(uuid)
                } else {
                    return Err(codec::Error::InvalidValue);
                };

                Ok(Self::ReadByType {
                    start: start_handle,
                    end: end_handle,
                    attribute_type,
                })
            }
            ATT_READ_REQ => {
                let handle = (payload[0] as u16) + ((payload[1] as u16) << 8);

                Ok(Self::Read { handle })
            }
            ATT_WRITE_REQ => {
                let handle = (payload[0] as u16) + ((payload[1] as u16) << 8);
                let data = &payload[2..];

                Ok(Self::Write { handle, data })
            }
            ATT_EXCHANGE_MTU_REQ => {
                let mtu = (payload[0] as u16) + ((payload[1] as u16) << 8);
                Ok(Self::ExchangeMtu { mtu })
            }
            ATT_FIND_BY_TYPE_VALUE_REQ => {
                let start_handle = (payload[0] as u16) + ((payload[1] as u16) << 8);
                let end_handle = (payload[2] as u16) + ((payload[3] as u16) << 8);
                let att_type = (payload[4] as u16) + ((payload[5] as u16) << 8);
                let att_value = &payload[6..];

                Ok(Self::FindByTypeValue {
                    start_handle,
                    end_handle,
                    att_type,
                    att_value,
                })
            }
            ATT_FIND_INFORMATION_REQ => {
                let start_handle = (payload[0] as u16) + ((payload[1] as u16) << 8);
                let end_handle = (payload[2] as u16) + ((payload[3] as u16) << 8);

                Ok(Self::FindInformation {
                    start_handle,
                    end_handle,
                })
            }
            ATT_PREPARE_WRITE_REQ => {
                let handle = (payload[0] as u16) + ((payload[1] as u16) << 8);
                let offset = (payload[2] as u16) + ((payload[3] as u16) << 8);
                Ok(Self::PrepareWrite {
                    handle,
                    offset,
                    value: &payload[4..],
                })
            }
            ATT_EXECUTE_WRITE_REQ => {
                let flags = payload[0];
                Ok(Self::ExecuteWrite { flags })
            }
            ATT_READ_MULTIPLE_REQ => Ok(Self::ReadMultiple { handles: payload }),
            ATT_READ_BLOB_REQ => {
                let handle = (payload[0] as u16) + ((payload[1] as u16) << 8);
                let offset = (payload[2] as u16) + ((payload[3] as u16) << 8);
                Ok(Self::ReadBlob { handle, offset })
            }
            code => {
                warn!("[att] unknown opcode {:x}", code);
                Err(codec::Error::InvalidValue)
            }
        }
    }
}

impl<'d> AttCmd<'d> {
    fn size(&self) -> usize {
        1 + match self {
            Self::Write { handle, data } => 2 + data.len(),
        }
    }

    fn encode(&self, dest: &mut [u8]) -> Result<(), codec::Error> {
        let mut w = WriteCursor::new(dest);
        match self {
            Self::Write { handle, data } => {
                w.write(ATT_WRITE_CMD)?;
                w.write(*handle)?;
                w.append(data)?;
            }
        }
        Ok(())
    }

    fn decode_with_opcode(opcode: u8, r: ReadCursor<'d>) -> Result<Self, codec::Error> {
        let payload = r.remaining();
        match opcode {
            ATT_WRITE_CMD => {
                let handle = (payload[0] as u16) + ((payload[1] as u16) << 8);
                let data = &payload[2..];

                Ok(Self::Write { handle, data })
            }
            code => {
                warn!("[att] unknown opcode {:x}", code);
                Err(codec::Error::InvalidValue)
            }
        }
    }
}

impl AttCfm {
    fn size(&self) -> usize {
        1
    }

    fn encode(&self, dest: &mut [u8]) -> Result<(), codec::Error> {
        let mut w = WriteCursor::new(dest);
        match self {
            Self::ConfirmIndication => {
                w.write(ATT_HANDLE_VALUE_CMF)?;
            }
        }
        Ok(())
    }

    fn decode_with_opcode(opcode: u8, r: ReadCursor<'_>) -> Result<Self, codec::Error> {
        let payload = r.remaining();
        match opcode {
            ATT_HANDLE_VALUE_CMF => Ok(Self::ConfirmIndication),
            code => {
                warn!("[att] unknown opcode {:x}", code);
                Err(codec::Error::InvalidValue)
            }
        }
    }
}

impl<'d> Att<'d> {
    /// Get the wire-size of the ATT PDU
    pub fn size(&self) -> usize {
        match self {
            Self::Client(client) => client.size(),
            Self::Server(server) => server.size(),
        }
    }

    /// Encode the ATT PDU into a byte buffer
    pub fn encode(&self, dest: &mut [u8]) -> Result<(), codec::Error> {
        match self {
            Self::Client(client) => client.encode(dest),
            Self::Server(server) => server.encode(dest),
        }
    }

    /// Decode an ATT PDU from a byte buffer
    pub fn decode(data: &'d [u8]) -> Result<Att<'d>, codec::Error> {
        let mut r = ReadCursor::new(data);
        let opcode: u8 = r.read()?;
        if opcode % 2 == 0 {
            let client = AttClient::decode_with_opcode(opcode, r)?;
            Ok(Att::Client(client))
        } else {
            let server = AttServer::decode_with_opcode(opcode, r)?;
            Ok(Att::Server(server))
        }
    }
}

impl From<codec::Error> for AttErrorCode {
    fn from(e: codec::Error) -> Self {
        AttErrorCode::INVALID_PDU
    }
}

impl codec::Type for Att<'_> {
    fn size(&self) -> usize {
        Self::size(self)
    }
}

impl codec::Encode for Att<'_> {
    fn encode(&self, dest: &mut [u8]) -> Result<(), codec::Error> {
        Self::encode(self, dest)
    }
}

impl<'d> codec::Decode<'d> for Att<'d> {
    fn decode(data: &'d [u8]) -> Result<Self, codec::Error> {
        Self::decode(data)
    }
}

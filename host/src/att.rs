use num_enum::TryFromPrimitive;
use thiserror::Error;

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

/// Attribute Error Code
///
/// This enum type describes the `ATT_ERROR_RSP` PDU from the Bluetooth Core Specification
/// Version 6.0 | Vol 3, Part F (page 1491)
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Clone, Copy, TryFromPrimitive, Error)]
#[repr(u8)]
pub enum AttErrorCode {
    /// The attribute handle given was not valid on this server.
    #[error("Attempted to use an `Handle` that isn't valid on this server.")]
    InvalidHandle = 0x01,
    /// The attribute cannot be read.
    #[error("Attribute isn't readable.")]
    ReadNotPermitted = 0x02,
    /// The attribute cannot be written.
    #[error("Attribute isn't writable.")]
    WriteNotPermitted = 0x03,
    /// The attribute PDU was invalid.
    #[error("Attribute PDU is invalid.")]
    InvalidPdu = 0x04,
    /// The attribute requires authentication before it can be read or written.
    #[error("Authentication needed before attribute can be read/written.")]
    InsufficientAuthentication = 0x05,
    /// ATT Server does not support the request reveived from the client.
    #[error("Server doesn't support this operation.")]
    RequestNotSupported = 0x06,
    /// Offset specified was past the end of the attribute.
    #[error("Offset was past the end of the attribute.")]
    InvalidOffset = 0x07,
    /// The attribute requires authorisation before it can be read or written.
    #[error("Authorization needed before attribute can be read/written.")]
    InsufficientAuthorization = 0x08,
    /// Too many prepare writes have been queued.
    #[error("Too many 'prepare write' requests have been queued.")]
    PrepareQueueFull = 0x09,
    /// No attribute found within the given attribute handle range.
    #[error("No attribute found within the specified attribute handle range.")]
    AttributeNotFound = 0x0A,
    /// The attribute cannot be read using the ATT_READ_BLOB_REQ PDU.
    #[error("Attribute can't be read using *Read Key Blob* request.")]
    AttributeNotLong = 0x0B,
    /// The Encryption Key Size used for encrypting this link is too short.
    #[error("The encryption key in use is too weak to access an attribute.")]
    InsufficientEncryptionKeySize = 0x0C,
    /// The attribute value length is invalid for the operation.
    #[error("Attribute value has an incorrect length for the operation.")]
    InvalidAttributeValueLength = 0x0D,
    /// The attribute request that was requested had encountered an error that was unlikely, and therefore could not be completed as requested.
    #[error("Request has encountered an 'unlikely' error and could not be completed.")]
    UnlikelyError = 0x0E,
    /// The attribute requires encryption before it can be read or written.
    #[error("Attribute cannot be read/written without an encrypted connection.")]
    InsufficientEncryption = 0x0F,
    /// The attribute type is not a supported grouping attribute as defined by a higher layer specification.
    #[error("Attribute type is an invalid grouping attribute according to a higher-layer spec.")]
    UnsupportedGroupType = 0x10,
    /// Insufficient Resources to complete the request.
    #[error("Server didn't have enough resources to complete a request.")]
    InsufficientResources = 0x11,
    /// The server requests the client to rediscover the database.
    #[error("The server requests the client to rediscover the database.")]
    DatabaseOutOfSync = 0x12,
    /// The attribute parameter value was not allowed.
    #[error("The attribute parameter value was not allowed.")]
    ValueNotAllowed = 0x13,
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub enum AttReq<'d> {
    ReadByGroupType {
        start: u16,
        end: u16,
        group_type: Uuid,
    },
    ReadByType {
        start: u16,
        end: u16,
        attribute_type: Uuid,
    },
    Read {
        handle: u16,
    },
    Write {
        handle: u16,
        data: &'d [u8],
    },
    WriteCmd {
        handle: u16,
        data: &'d [u8],
    },
    ExchangeMtu {
        mtu: u16,
    },
    FindByTypeValue {
        start_handle: u16,
        end_handle: u16,
        att_type: u16,
        att_value: &'d [u8],
    },
    FindInformation {
        start_handle: u16,
        end_handle: u16,
    },
    PrepareWrite {
        handle: u16,
        offset: u16,
        value: &'d [u8],
    },
    ExecuteWrite {
        flags: u8,
    },
    ReadMultiple {
        handles: &'d [u8],
    },
    ReadBlob {
        handle: u16,
        offset: u16,
    },
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub enum AttRsp<'d> {
    ExchangeMtu {
        mtu: u16,
    },
    FindByTypeValue {
        it: FindByTypeValueIter<'d>,
    },
    Error {
        request: u8,
        handle: u16,
        code: AttErrorCode,
    },
    ReadByType {
        it: ReadByTypeIter<'d>,
    },
    Read {
        data: &'d [u8],
    },
    Write,
}

pub enum Att<'d> {
    Req(AttReq<'d>),
    Rsp(AttRsp<'d>),
}

impl codec::Type for AttRsp<'_> {
    fn size(&self) -> usize {
        AttRsp::size(self)
    }
}

impl codec::Encode for AttRsp<'_> {
    fn encode(&self, dest: &mut [u8]) -> Result<(), codec::Error> {
        AttRsp::encode(self, dest)
    }
}

impl<'d> codec::Decode<'d> for AttRsp<'d> {
    fn decode(src: &'d [u8]) -> Result<AttRsp<'d>, codec::Error> {
        AttRsp::decode(src)
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Clone, Debug)]
pub struct FindByTypeValueIter<'d> {
    cursor: ReadCursor<'d>,
}

impl FindByTypeValueIter<'_> {
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

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Clone, Debug)]
pub struct ReadByTypeIter<'d> {
    item_len: usize,
    cursor: ReadCursor<'d>,
}

impl<'d> ReadByTypeIter<'d> {
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

impl<'d> AttRsp<'d> {
    pub fn size(&self) -> usize {
        1 + match self {
            Self::ExchangeMtu { mtu: u16 } => 2,
            Self::FindByTypeValue { it } => it.cursor.len(),
            Self::Error { .. } => 4,
            Self::Read { data } => data.len(),
            Self::ReadByType { it } => it.cursor.len(),
            Self::Write => 0,
        }
    }

    pub fn encode(&self, dest: &mut [u8]) -> Result<(), codec::Error> {
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
            Self::Error { request, handle, code } => {
                w.write(ATT_ERROR_RSP)?;
                w.write(*request)?;
                w.write(*handle)?;
                w.write(*code as u8)?;
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
            Self::Write => {
                w.write(ATT_WRITE_RSP)?;
            }
        }
        Ok(())
    }

    pub fn decode(data: &'d [u8]) -> Result<AttRsp<'d>, codec::Error> {
        let mut r = ReadCursor::new(data);
        let opcode: u8 = r.read()?;
        AttRsp::decode_with_opcode(opcode, r)
    }

    pub fn decode_with_opcode(opcode: u8, mut r: ReadCursor<'d>) -> Result<AttRsp<'d>, codec::Error> {
        match opcode {
            ATT_FIND_BY_TYPE_VALUE_RSP => Ok(Self::FindByTypeValue {
                it: FindByTypeValueIter { cursor: r },
            }),
            ATT_EXCHANGE_MTU_RSP => {
                let mtu: u16 = r.read()?;
                Ok(Self::ExchangeMtu { mtu })
            }
            ATT_ERROR_RSP => {
                let request: u8 = r.read()?;
                let handle: u16 = r.read()?;
                let code: u8 = r.read()?;
                let code: AttErrorCode = code.try_into().map_err(|_| codec::Error::InvalidValue)?;
                Ok(Self::Error { request, handle, code })
            }
            ATT_READ_RSP => Ok(Self::Read { data: r.remaining() }),
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

impl From<codec::Error> for AttErrorCode {
    fn from(e: codec::Error) -> Self {
        AttErrorCode::InvalidPdu
    }
}

impl codec::Type for AttReq<'_> {
    fn size(&self) -> usize {
        AttReq::size(self)
    }
}

impl codec::Encode for AttReq<'_> {
    fn encode(&self, dest: &mut [u8]) -> Result<(), codec::Error> {
        AttReq::encode(self, dest)
    }
}

impl<'d> codec::Decode<'d> for AttReq<'d> {
    fn decode(data: &'d [u8]) -> Result<AttReq<'d>, codec::Error> {
        AttReq::decode(data)
    }
}

impl<'d> Att<'d> {
    pub fn decode(data: &'d [u8]) -> Result<Att<'d>, codec::Error> {
        let mut r = ReadCursor::new(data);
        let opcode: u8 = r.read()?;
        if opcode % 2 == 0 {
            let req = AttReq::decode_with_opcode(opcode, r)?;
            Ok(Att::Req(req))
        } else {
            let rsp = AttRsp::decode_with_opcode(opcode, r)?;
            Ok(Att::Rsp(rsp))
        }
    }
}

impl<'d> AttReq<'d> {
    pub fn size(&self) -> usize {
        1 + match self {
            Self::ExchangeMtu { .. } => 2,
            Self::FindByTypeValue {
                start_handle,
                end_handle,
                att_type,
                att_value,
            } => 6 + att_value.len(),
            Self::ReadByType {
                start,
                end,
                attribute_type,
            } => 4 + attribute_type.as_raw().len(),
            Self::Read { .. } => 2,
            Self::Write { handle, data } => 2 + data.len(),
            _ => unimplemented!(),
        }
    }
    pub fn encode(&self, dest: &mut [u8]) -> Result<(), codec::Error> {
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
            Self::Write { handle, data } => {
                w.write(ATT_WRITE_REQ)?;
                w.write(*handle)?;
                w.append(data)?;
            }
            _ => unimplemented!(),
        }
        Ok(())
    }

    pub fn decode(data: &'d [u8]) -> Result<AttReq<'d>, codec::Error> {
        let mut r = ReadCursor::new(data);
        let opcode: u8 = r.read()?;
        AttReq::decode_with_opcode(opcode, r)
    }

    pub fn decode_with_opcode(opcode: u8, r: ReadCursor<'d>) -> Result<AttReq<'d>, codec::Error> {
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
            ATT_WRITE_CMD => {
                let handle = (payload[0] as u16) + ((payload[1] as u16) << 8);
                let data = &payload[2..];

                Ok(Self::WriteCmd { handle, data })
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

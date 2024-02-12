use core::convert::TryInto;

use crate::{l2cap::L2capPacket, Data};

pub const ATT_READ_BY_GROUP_TYPE_REQUEST_OPCODE: u8 = 0x10;
const ATT_READ_BY_GROUP_TYPE_RESPONSE_OPCODE: u8 = 0x11;
const ATT_ERROR_RESPONSE_OPCODE: u8 = 0x01;
pub const ATT_READ_BY_TYPE_REQUEST_OPCODE: u8 = 0x08;
const ATT_READ_BY_TYPE_RESPONSE_OPCODE: u8 = 0x09;
pub const ATT_READ_REQUEST_OPCODE: u8 = 0x0a;
const ATT_READ_RESPONSE_OPCODE: u8 = 0x0b;
pub const ATT_WRITE_REQUEST_OPCODE: u8 = 0x12;
pub const ATT_WRITE_CMD_OPCODE: u8 = 0x52;
const ATT_WRITE_RESPONSE_OPCODE: u8 = 0x13;
pub const ATT_EXCHANGE_MTU_REQUEST_OPCODE: u8 = 0x02;
const ATT_EXCHANGE_MTU_RESPONSE_OPCODE: u8 = 0x03;
pub const ATT_FIND_BY_TYPE_VALUE_REQUEST_OPCODE: u8 = 0x06;
//const ATT_FIND_BY_TYPE_VALUE_RESPONSE_OPCODE: u8 = 0x07;
pub const ATT_FIND_INFORMATION_REQ_OPCODE: u8 = 0x04;
const ATT_FIND_INFORMATION_RSP_OPCODE: u8 = 0x05;
pub const ATT_PREPARE_WRITE_REQ_OPCODE: u8 = 0x16;
const ATT_PREPARE_WRITE_RESP_OPCODE: u8 = 0x17;
pub const ATT_EXECUTE_WRITE_REQ_OPCODE: u8 = 0x18;
const ATT_EXECUTE_WRITE_RESP_OPCODE: u8 = 0x19;
pub const ATT_READ_BLOB_REQ_OPCODE: u8 = 0x0c;
const ATT_READ_BLOB_RESP_OPCODE: u8 = 0x0d;
const ATT_HANDLE_VALUE_NTF_OPTCODE: u8 = 0x1b;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Uuid {
    Uuid16(u16),
    Uuid128([u8; 16]),
}

impl Data {
    pub fn append_uuid(&mut self, uuid: &Uuid) {
        match uuid {
            Uuid::Uuid16(uuid) => {
                self.append_value(*uuid);
            }
            Uuid::Uuid128(uuid) => {
                self.append(&uuid[..]);
            }
        }
    }
}

impl Uuid {
    pub fn bytes(&self, data: &mut [u8]) {
        match self {
            Uuid::Uuid16(uuid) => data.copy_from_slice(&uuid.to_be_bytes()),
            Uuid::Uuid128(uuid) => data.copy_from_slice(uuid),
        }
    }

    pub fn get_type(&self) -> u8 {
        match self {
            Uuid::Uuid16(_) => 0x01,
            Uuid::Uuid128(_) => 0x02,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Uuid::Uuid16(_) => 6,
            Uuid::Uuid128(_) => 20,
        }
    }
}

impl From<Data> for Uuid {
    fn from(data: Data) -> Self {
        match data.len() {
            2 => Uuid::Uuid16(u16::from_le_bytes(data.as_slice().try_into().unwrap())),
            16 => {
                let bytes: [u8; 16] = data.as_slice().try_into().unwrap();
                Uuid::Uuid128(bytes)
            }
            _ => panic!(),
        }
    }
}

impl From<&[u8]> for Uuid {
    fn from(data: &[u8]) -> Self {
        match data.len() {
            2 => Uuid::Uuid16(u16::from_le_bytes(data.try_into().unwrap())),
            16 => {
                let bytes: [u8; 16] = data.try_into().unwrap();
                Uuid::Uuid128(bytes)
            }
            _ => panic!(),
        }
    }
}

#[derive(Debug)]
pub enum AttErrorCode {
    /// Attempted to use an `Handle` that isn't valid on this server.
    InvalidHandle = 0x01,
    /// Attribute isn't readable.
    ReadNotPermitted = 0x02,
    /// Attribute isn't writable.
    WriteNotPermitted = 0x03,
    /// Attribute PDU is invalid.
    InvalidPdu = 0x04,
    /// Authentication needed before attribute can be read/written.
    InsufficientAuthentication = 0x05,
    /// Server doesn't support this operation.
    RequestNotSupported = 0x06,
    /// Offset was past the end of the attribute.
    InvalidOffset = 0x07,
    /// Authorization needed before attribute can be read/written.
    InsufficientAuthorization = 0x08,
    /// Too many "prepare write" requests have been queued.
    PrepareQueueFull = 0x09,
    /// No attribute found within the specified attribute handle range.
    AttributeNotFound = 0x0A,
    /// Attribute can't be read/written using *Read Key Blob* request.
    AttributeNotLong = 0x0B,
    /// The encryption key in use is too weak to access an attribute.
    InsufficientEncryptionKeySize = 0x0C,
    /// Attribute value has an incorrect length for the operation.
    InvalidAttributeValueLength = 0x0D,
    /// Request has encountered an "unlikely" error and could not be completed.
    UnlikelyError = 0x0E,
    /// Attribute cannot be read/written without an encrypted connection.
    InsufficientEncryption = 0x0F,
    /// Attribute type is an invalid grouping attribute according to a higher-layer spec.
    UnsupportedGroupType = 0x10,
    /// Server didn't have enough resources to complete a request.
    InsufficientResources = 0x11,
}

#[derive(Debug)]
pub enum Att {
    ReadByGroupTypeReq {
        start: u16,
        end: u16,
        group_type: Uuid,
    },
    ReadByTypeReq {
        start: u16,
        end: u16,
        attribute_type: Uuid,
    },
    ReadReq {
        handle: u16,
    },
    WriteReq {
        handle: u16,
        data: Data,
    },
    WriteCmd {
        handle: u16,
        data: Data,
    },
    ExchangeMtu {
        mtu: u16,
    },
    FindByTypeValue {
        start_handle: u16,
        end_handle: u16,
        att_type: u16,
        att_value: u16,
    },
    FindInformation {
        start_handle: u16,
        end_handle: u16,
    },
    PrepareWriteReq {
        handle: u16,
        offset: u16,
        value: Data,
    },
    ExecuteWriteReq {
        flags: u8,
    },
    ReadBlobReq {
        handle: u16,
        offset: u16,
    },
}

#[derive(Debug)]
pub enum AttDecodeError {
    Other,
    UnknownOpcode(u8, Data),
    UnexpectedPayload,
}

impl Att {
    pub fn decode(packet: L2capPacket) -> Result<Self, AttDecodeError> {
        let opcode = packet.payload.as_slice()[0];
        let payload = &packet.payload.as_slice()[1..];

        match opcode {
            ATT_READ_BY_GROUP_TYPE_REQUEST_OPCODE => {
                let start_handle = (payload[0] as u16) + ((payload[1] as u16) << 8);
                let end_handle = (payload[2] as u16) + ((payload[3] as u16) << 8);

                let group_type = if payload.len() == 6 {
                    Uuid::Uuid16((payload[4] as u16) + ((payload[5] as u16) << 8))
                } else if payload.len() == 20 {
                    let uuid = payload[4..21].try_into().map_err(|_| AttDecodeError::Other)?;
                    Uuid::Uuid128(uuid)
                } else {
                    return Err(AttDecodeError::UnexpectedPayload);
                };

                Ok(Self::ReadByGroupTypeReq {
                    start: start_handle,
                    end: end_handle,
                    group_type,
                })
            }
            ATT_READ_BY_TYPE_REQUEST_OPCODE => {
                let start_handle = (payload[0] as u16) + ((payload[1] as u16) << 8);
                let end_handle = (payload[2] as u16) + ((payload[3] as u16) << 8);

                let attribute_type = if payload.len() == 6 {
                    Uuid::Uuid16((payload[4] as u16) + ((payload[5] as u16) << 8))
                } else if payload.len() == 20 {
                    let uuid = payload[4..21].try_into().map_err(|_| AttDecodeError::Other)?;
                    Uuid::Uuid128(uuid)
                } else {
                    return Err(AttDecodeError::UnexpectedPayload);
                };

                Ok(Self::ReadByTypeReq {
                    start: start_handle,
                    end: end_handle,
                    attribute_type,
                })
            }
            ATT_READ_REQUEST_OPCODE => {
                let handle = (payload[0] as u16) + ((payload[1] as u16) << 8);

                Ok(Self::ReadReq { handle })
            }
            ATT_WRITE_REQUEST_OPCODE => {
                let handle = (payload[0] as u16) + ((payload[1] as u16) << 8);
                let mut data = Data::default();
                data.append(&payload[2..]);

                Ok(Self::WriteReq { handle, data })
            }
            ATT_WRITE_CMD_OPCODE => {
                let handle = (payload[0] as u16) + ((payload[1] as u16) << 8);
                let mut data = Data::default();
                data.append(&payload[2..]);

                Ok(Self::WriteCmd { handle, data })
            }
            ATT_EXCHANGE_MTU_REQUEST_OPCODE => {
                let mtu = (payload[0] as u16) + ((payload[1] as u16) << 8);
                Ok(Self::ExchangeMtu { mtu })
            }
            ATT_FIND_BY_TYPE_VALUE_REQUEST_OPCODE => {
                let start_handle = (payload[0] as u16) + ((payload[1] as u16) << 8);
                let end_handle = (payload[2] as u16) + ((payload[3] as u16) << 8);
                let att_type = (payload[4] as u16) + ((payload[5] as u16) << 8);
                let att_value = (payload[6] as u16) + ((payload[7] as u16) << 8); // only U16 supported here

                Ok(Self::FindByTypeValue {
                    start_handle,
                    end_handle,
                    att_type,
                    att_value,
                })
            }
            ATT_FIND_INFORMATION_REQ_OPCODE => {
                let start_handle = (payload[0] as u16) + ((payload[1] as u16) << 8);
                let end_handle = (payload[2] as u16) + ((payload[3] as u16) << 8);

                Ok(Self::FindInformation {
                    start_handle,
                    end_handle,
                })
            }
            ATT_PREPARE_WRITE_REQ_OPCODE => {
                let handle = (payload[0] as u16) + ((payload[1] as u16) << 8);
                let offset = (payload[2] as u16) + ((payload[3] as u16) << 8);
                let value = &payload[4..];
                Ok(Self::PrepareWriteReq {
                    handle,
                    offset,
                    value: Data::new(value),
                })
            }
            ATT_EXECUTE_WRITE_REQ_OPCODE => {
                let flags = payload[0];
                Ok(Self::ExecuteWriteReq { flags })
            }
            ATT_READ_BLOB_REQ_OPCODE => {
                let handle = (payload[0] as u16) + ((payload[1] as u16) << 8);
                let offset = (payload[2] as u16) + ((payload[3] as u16) << 8);
                Ok(Self::ReadBlobReq { handle, offset })
            }
            _ => Err(AttDecodeError::UnknownOpcode(opcode, Data::new(payload))),
        }
    }
}

impl Data {
    pub fn append_attribute_data(&mut self, attribute_handle: u16, end_group_handle: u16, attribute_value: &Uuid) {
        self.append_value(attribute_handle);
        self.append_value(end_group_handle);
        self.append_uuid(attribute_value);
    }

    pub fn new_att_read_by_group_type_response() -> Self {
        Self::new(&[
            ATT_READ_BY_GROUP_TYPE_RESPONSE_OPCODE,
            0u8, /* size to modify/check later */
        ])
    }

    pub fn append_att_read_by_group_type_response(
        &mut self,
        attribute_handle: u16,
        end_group_handle: u16,
        attribute_value: &Uuid,
    ) {
        let len = attribute_value.len() as u8;
        if self.data[1] == 0 {
            self.data[1] = len;
        } else if self.data[1] != len {
            panic!("Non-uniform UUIDs");
        }
        self.append_attribute_data(attribute_handle, end_group_handle, attribute_value);
    }

    pub fn new_att_error_response(opcode: u8, handle: u16, code: AttErrorCode) -> Self {
        let mut data = Self::new(&[ATT_ERROR_RESPONSE_OPCODE, opcode]);
        data.append_value(handle);
        data.append_value(code as u8);
        data
    }

    pub fn new_att_read_by_type_response() -> Self {
        Self::new(&[ATT_READ_BY_TYPE_RESPONSE_OPCODE, 0u8 /* size to set/check later */])
    }

    pub fn append_att_read_by_type_response(&mut self) {
        let size = self.len() - 2;
        // check if empty
        if size == 0 {
            panic!("Missing attribute payloads");
        }
        if self.data[1] == 0 {
            /* set size */
            self.data[1] = size as u8;
        } else {
            if size % self.data[1] as usize > 0 {
                panic!("Non-uniform attribute payloads");
            }
        }
    }

    pub fn new_att_read_response() -> Self {
        Self::new(&[ATT_READ_RESPONSE_OPCODE])
    }

    pub fn has_att_read_response_data(&self) -> bool {
        self.len() > 1
    }

    pub fn new_att_write_response() -> Self {
        Self::new(&[ATT_WRITE_RESPONSE_OPCODE])
    }

    pub fn new_att_exchange_mtu_response(mtu: u16) -> Self {
        let mut data = Self::new(&[ATT_EXCHANGE_MTU_RESPONSE_OPCODE]);
        data.append_value(mtu);
        data
    }

    pub fn new_att_find_information_response() -> Self {
        Self::new(&[
            ATT_FIND_INFORMATION_RSP_OPCODE,
            0u8, /* uuid_type to set/check later */
        ])
    }

    pub fn append_att_find_information_response(&mut self, handle: u16, uuid: &Uuid) -> bool {
        if self.data[1] == 0 {
            self.data[1] = uuid.get_type();
        } else if self.data[1] != uuid.get_type() {
            return false;
        }

        self.append_value(handle);
        self.append_uuid(&uuid);

        true
    }

    pub fn has_att_find_information_response_data(&self) -> bool {
        self.len() > 2
    }

    pub fn new_att_prepare_write_response(handle: u16, offset: u16) -> Self {
        let mut data = Self::new(&[ATT_PREPARE_WRITE_RESP_OPCODE]);
        data.append_value(handle);
        data.append_value(offset);
        data
    }

    pub fn has_att_prepare_write_response_data(&self) -> bool {
        self.len() > 5
    }

    pub fn new_att_execute_write_response() -> Self {
        Self::new(&[ATT_EXECUTE_WRITE_RESP_OPCODE])
    }

    pub fn new_att_read_blob_response() -> Self {
        Self::new(&[ATT_READ_BLOB_RESP_OPCODE])
    }

    pub fn has_att_read_blob_response_data(&self) -> bool {
        self.len() > 1
    }

    pub fn new_att_value_ntf(handle: u16) -> Self {
        let mut data = Self::new(&[ATT_HANDLE_VALUE_NTF_OPTCODE]);
        data.append_value(handle);
        data
    }
}

use super::CharacteristicProp;
use super::CharacteristicProps;
use crate::att::AttErrorCode;
use crate::cursor::WriteCursor;
use crate::types::uuid::Uuid;

/// The underlying data behind an attribute.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttributeData<'d> {
    /// Service UUID Data
    ///
    /// Serializes to raw bytes of UUID.
    Service { uuid: Uuid },
    /// Read only data
    ///
    /// Implemented by storing a borrow of a slice.
    /// The slice has to live at least as much as the device.
    ReadOnlyData {
        props: CharacteristicProps,
        value: &'d [u8],
    },
    /// Read and write data
    ///
    /// Implemented by storing a mutable borrow of a slice.
    /// The slice has to live at least as much as the device.
    Data {
        props: CharacteristicProps,
        value: &'d mut [u8],
    },
    /// Characteristic declaration
    Declaration {
        props: CharacteristicProps,
        handle: u16,
        uuid: Uuid,
    },
    /// Client Characteristic Configuration Descriptor
    ///
    /// Ref: BLUETOOTH CORE SPECIFICATION Version 6.0, Vol 3, Part G, Section 3.3.3.3 Client Characteristic Configuration
    Cccd { notifications: bool, indications: bool },
}

impl<'d> AttributeData<'d> {
    pub fn readable(&self) -> bool {
        match self {
            Self::Data { props, value } => props.0 & (CharacteristicProp::Read as u8) != 0,
            _ => true,
        }
    }

    pub fn writable(&self) -> bool {
        match self {
            Self::Data { props, value } => {
                props.0
                    & (CharacteristicProp::Write as u8
                        | CharacteristicProp::WriteWithoutResponse as u8
                        | CharacteristicProp::AuthenticatedWrite as u8)
                    != 0
            }
            Self::Cccd {
                notifications,
                indications,
            } => true,
            _ => false,
        }
    }

    /// Read the attribute value from some kind of a readable attribute data source
    ///
    /// Seek to to the `offset`-nth byte in the source data, fill the response data slice `data` up to the end or lower.
    ///
    /// The data buffer is always sized L2CAP_MTU, minus the 4 bytes for the L2CAP header)
    /// The max stated value of an attribute in the GATT specification is 512 bytes.
    ///
    /// Returns the amount of bytes that have been written into `data`.
    pub fn read(&self, offset: usize, data: &mut [u8]) -> Result<usize, AttErrorCode> {
        if !self.readable() {
            return Err(AttErrorCode::ReadNotPermitted);
        }
        match self {
            Self::ReadOnlyData { props, value } => {
                if offset > value.len() {
                    return Ok(0);
                }
                let len = data.len().min(value.len() - offset);
                if len > 0 {
                    data[..len].copy_from_slice(&value[offset..offset + len]);
                }
                Ok(len)
            }
            Self::Data { props, value } => {
                if offset > value.len() {
                    return Ok(0);
                }
                let len = data.len().min(value.len() - offset);
                if len > 0 {
                    data[..len].copy_from_slice(&value[offset..offset + len]);
                }
                Ok(len)
            }
            Self::Service { uuid } => {
                let val = uuid.as_raw();
                if offset > val.len() {
                    return Ok(0);
                }
                let len = data.len().min(val.len() - offset);
                if len > 0 {
                    data[..len].copy_from_slice(&val[offset..offset + len]);
                }
                Ok(len)
            }
            Self::Cccd {
                notifications,
                indications,
            } => {
                if offset > 0 {
                    return Err(AttErrorCode::InvalidOffset);
                }
                if data.len() < 2 {
                    return Err(AttErrorCode::UnlikelyError);
                }
                let mut v = 0;
                if *notifications {
                    v |= 0x01;
                }

                if *indications {
                    v |= 0x02;
                }
                data[0] = v;
                Ok(2)
            }
            Self::Declaration { props, handle, uuid } => {
                let val = uuid.as_raw();
                if offset > val.len() + 3 {
                    return Ok(0);
                }
                let mut w = WriteCursor::new(data);
                if offset == 0 {
                    w.write(props.0)?;
                    w.write(*handle)?;
                } else if offset == 1 {
                    w.write(*handle)?;
                } else if offset == 2 {
                    w.write(handle.to_le_bytes()[1])?;
                }

                let to_write = w.available().min(val.len());

                if to_write > 0 {
                    w.append(&val[..to_write])?;
                }
                Ok(w.len())
            }
        }
    }

    /// Write into the attribute value at 'offset' data from `data` buffer
    ///
    /// Expect the writes to be fragmented, like with [`AttributeData::read`]
    pub fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), AttErrorCode> {
        let writable = self.writable();

        match self {
            Self::Data { value, props } => {
                if !writable {
                    return Err(AttErrorCode::WriteNotPermitted);
                }

                if offset + data.len() <= value.len() {
                    value[offset..offset + data.len()].copy_from_slice(data);
                    Ok(())
                } else {
                    Err(AttErrorCode::InvalidOffset)
                }
            }
            Self::Cccd {
                notifications,
                indications,
            } => {
                if offset > 0 {
                    return Err(AttErrorCode::InvalidOffset);
                }

                if data.is_empty() {
                    return Err(AttErrorCode::UnlikelyError);
                }

                *notifications = data[0] & 0b00000001 != 0;
                *indications = data[0] & 0b00000010 != 0;
                Ok(())
            }
            _ => Err(AttErrorCode::WriteNotPermitted),
        }
    }
}

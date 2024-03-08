use crate::{
    codec::{Decode, Encode, Error, FixedSize, Type},
    cursor::{ReadCursor, WriteCursor},
};
use trouble_host_macros::*;

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum SignalCode {
    CommandRejectRes = 0x01,
    ConnectionReq = 0x02,
    ConnectionRes = 0x03,
    ConfigurationReq = 0x04,
    ConfigurationRes = 0x05,
    DisconnectionReq = 0x06,
    DisconnectionRes = 0x07,
    EchoReq = 0x08,
    EchoRes = 0x09,
    InformationReq = 0x0A,
    InformationRes = 0x0B,
    ConnParamUpdateReq = 0x12,
    ConnParamUpdateRes = 0x13,
    LeCreditConnReq = 0x14,
    LeCreditConnRes = 0x15,
    LeCreditFlowInd = 0x16,
    CreditConnReq = 0x17,
    CreditConnRes = 0x18,
    CreditConnReconfigReq = 0x19,
    CreditConnReconfigRes = 0x1A,
}

impl TryFrom<u8> for SignalCode {
    type Error = Error;
    fn try_from(val: u8) -> Result<Self, Error> {
        Ok(match val {
            0x01 => Self::CommandRejectRes,
            0x02 => Self::ConnectionReq,
            0x03 => Self::ConnectionRes,
            0x04 => Self::ConfigurationReq,
            0x05 => Self::ConfigurationRes,
            0x06 => Self::DisconnectionReq,
            0x07 => Self::DisconnectionRes,
            0x08 => Self::EchoReq,
            0x09 => Self::EchoRes,
            0x0A => Self::InformationReq,
            0x0B => Self::InformationRes,
            0x12 => Self::ConnParamUpdateReq,
            0x13 => Self::ConnParamUpdateRes,
            0x14 => Self::LeCreditConnReq,
            0x15 => Self::LeCreditConnRes,
            0x16 => Self::LeCreditFlowInd,
            0x17 => Self::CreditConnReq,
            0x18 => Self::CreditConnRes,
            0x19 => Self::CreditConnReconfigReq,
            0x1A => Self::CreditConnReconfigRes,
            _ => return Err(Error::InvalidValue),
        })
    }
}

impl FixedSize for SignalCode {
    const SIZE: usize = 1;
}

impl Encode for SignalCode {
    fn encode(&self, dest: &mut [u8]) -> Result<(), Error> {
        dest[0] = *self as u8;
        Ok(())
    }
}

impl Decode for SignalCode {
    fn decode(src: &[u8]) -> Result<Self, Error> {
        Ok(src[0].try_into()?)
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub struct L2capLeSignal {
    pub id: u8,
    pub data: L2capLeSignalData,
}

impl L2capLeSignal {
    pub fn new(id: u8, data: L2capLeSignalData) -> Self {
        Self { id, data }
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub enum L2capLeSignalData {
    CommandRejectRes(CommandRejectRes),
    LeCreditConnReq(LeCreditConnReq),
    LeCreditConnRes(LeCreditConnRes),
    LeCreditFlowInd(LeCreditFlowInd),
}

impl Type for L2capLeSignal {
    fn size(&self) -> usize {
        4 + match &self.data {
            L2capLeSignalData::CommandRejectRes(r) => r.size(),
            L2capLeSignalData::LeCreditConnReq(r) => r.size(),
            L2capLeSignalData::LeCreditConnRes(r) => r.size(),
            L2capLeSignalData::LeCreditFlowInd(r) => r.size(),
        }
    }
}

impl Encode for L2capLeSignal {
    fn encode(&self, dest: &mut [u8]) -> Result<(), Error> {
        let mut w = WriteCursor::new(dest);
        let (mut header, mut data) = w.split(4)?;
        let (code, len) = match &self.data {
            L2capLeSignalData::LeCreditConnReq(r) => {
                data.write_ref(r)?;
                (SignalCode::LeCreditConnReq, r.size())
            }
            L2capLeSignalData::LeCreditConnRes(r) => {
                data.write_ref(r)?;
                (SignalCode::LeCreditConnRes, r.size())
            }
            L2capLeSignalData::CommandRejectRes(r) => {
                data.write_ref(r)?;
                (SignalCode::CommandRejectRes, r.size())
            }
            L2capLeSignalData::LeCreditFlowInd(r) => {
                data.write_ref(r)?;
                (SignalCode::LeCreditFlowInd, r.size())
            }
        };
        header.write(code)?;
        header.write(self.id)?;
        header.write(len as u16)?;

        Ok(())
    }
}

impl Decode for L2capLeSignal {
    fn decode(src: &[u8]) -> Result<Self, Error> {
        let mut r = ReadCursor::new(src);
        let code: SignalCode = r.read()?;
        let id: u8 = r.read()?;
        let len: u16 = r.read()?;
        assert!(len <= r.available() as u16);
        let data = match code {
            SignalCode::LeCreditConnReq => {
                let req = r.read()?;
                L2capLeSignalData::LeCreditConnReq(req)
            }
            SignalCode::LeCreditConnRes => {
                let res = r.read()?;
                L2capLeSignalData::LeCreditConnRes(res)
            }
            SignalCode::CommandRejectRes => {
                let res = r.read()?;
                L2capLeSignalData::CommandRejectRes(res)
            }
            SignalCode::LeCreditFlowInd => {
                let res = r.read()?;
                L2capLeSignalData::LeCreditFlowInd(res)
            }
            code => {
                warn!("Unimplemented signal code: {:02x}", code);
                panic!();
            }
        };
        Ok(Self { id, data })
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Codec)]
pub struct LeCreditConnReq {
    pub psm: u16,
    pub scid: u16,
    pub mtu: u16,
    pub mps: u16,
    pub credits: u16,
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub enum LeCreditConnResultCode {
    Success = 0x0000,
    SpsmNotSupported = 0x0002,
    NoResources = 0x0004,
    InsufficientAuthentication = 0x0005,
    InsufficientAuthorization = 0x0006,
    EncryptionKeyTooShort = 0x0007,
    InsufficientEncryption = 0x0008,
    InvalidSourceId = 0x0009,
    ScidAlreadyAllocated = 0x000A,
    UnacceptableParameters = 0x000B,
}

impl TryFrom<u16> for LeCreditConnResultCode {
    type Error = Error;
    fn try_from(val: u16) -> Result<Self, Error> {
        Ok(match val {
            0x0000 => Self::Success,
            0x0002 => Self::SpsmNotSupported,
            0x0004 => Self::NoResources,
            0x0005 => Self::InsufficientAuthentication,
            0x0006 => Self::InsufficientAuthorization,
            0x0007 => Self::EncryptionKeyTooShort,
            0x0008 => Self::InsufficientEncryption,
            0x0009 => Self::InvalidSourceId,
            0x000A => Self::ScidAlreadyAllocated,
            0x000B => Self::UnacceptableParameters,
            _ => return Err(Error::InvalidValue),
        })
    }
}

impl FixedSize for LeCreditConnResultCode {
    const SIZE: usize = 2;
}

impl Encode for LeCreditConnResultCode {
    fn encode(&self, dest: &mut [u8]) -> Result<(), Error> {
        dest.copy_from_slice(&(*self as u16).to_le_bytes()[..]);
        Ok(())
    }
}

impl Decode for LeCreditConnResultCode {
    fn decode(src: &[u8]) -> Result<Self, Error> {
        Ok(u16::from_le_bytes([src[0], src[1]]).try_into()?)
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Codec)]
pub struct LeCreditConnRes {
    pub dcid: u16,
    pub mtu: u16,
    pub mps: u16,
    pub credits: u16,
    pub result: LeCreditConnResultCode,
}

#[derive(Debug, Codec)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LeCreditFlowInd {
    pub cid: u16,
    pub credits: u16,
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Codec)]
pub struct CommandRejectRes {
    pub reason: u16,
    // TODO: Optional fields pub data: u16,
}

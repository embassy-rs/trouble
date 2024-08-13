use bt_hci::{FixedSizeValue, WriteHci};

use crate::codec::Error;

pub(crate) const L2CAP_CID_ATT: u16 = 0x0004;
pub(crate) const L2CAP_CID_LE_U_SIGNAL: u16 = 0x0005;
pub(crate) const L2CAP_CID_DYN_START: u16 = 0x0040;

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct L2capHeader {
    pub length: u16,
    pub channel: u16,
}

unsafe impl FixedSizeValue for L2capHeader {
    fn is_valid(data: &[u8]) -> bool {
        true
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct L2capSignalHeader {
    pub code: L2capSignalCode,
    pub identifier: u8,
    pub length: u16,
}

unsafe impl FixedSizeValue for L2capSignalHeader {
    fn is_valid(data: &[u8]) -> bool {
        true
    }
}

#[cfg(not(feature = "defmt"))]
pub trait L2capSignal: WriteHci + FixedSizeValue + core::fmt::Debug {
    fn channel() -> u16 {
        L2CAP_CID_LE_U_SIGNAL
    }
    fn code() -> L2capSignalCode;
}

#[cfg(feature = "defmt")]
pub trait L2capSignal: WriteHci + FixedSizeValue + defmt::Format {
    fn channel() -> u16 {
        L2CAP_CID_LE_U_SIGNAL
    }
    fn code() -> L2capSignalCode;
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum L2capSignalCode {
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

impl TryFrom<u8> for L2capSignalCode {
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

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LeCreditConnReq {
    pub psm: u16,
    pub scid: u16,
    pub mtu: u16,
    pub mps: u16,
    pub credits: u16,
}

unsafe impl FixedSizeValue for LeCreditConnReq {
    fn is_valid(data: &[u8]) -> bool {
        true
    }
}

impl L2capSignal for LeCreditConnReq {
    fn code() -> L2capSignalCode {
        L2capSignalCode::LeCreditConnReq
    }
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

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LeCreditConnRes {
    pub dcid: u16,
    pub mtu: u16,
    pub mps: u16,
    pub credits: u16,
    pub result: LeCreditConnResultCode,
}

impl L2capSignal for LeCreditConnRes {
    fn code() -> L2capSignalCode {
        L2capSignalCode::LeCreditConnRes
    }
}

unsafe impl FixedSizeValue for LeCreditConnRes {
    fn is_valid(data: &[u8]) -> bool {
        true
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LeCreditFlowInd {
    pub cid: u16,
    pub credits: u16,
}

unsafe impl FixedSizeValue for LeCreditFlowInd {
    fn is_valid(data: &[u8]) -> bool {
        true
    }
}

impl L2capSignal for LeCreditFlowInd {
    fn code() -> L2capSignalCode {
        L2capSignalCode::LeCreditFlowInd
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CommandRejectRes {
    pub reason: u16,
    // TODO: Optional fields pub data: u16,
}

unsafe impl FixedSizeValue for CommandRejectRes {
    fn is_valid(data: &[u8]) -> bool {
        true
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DisconnectionReq {
    pub dcid: u16,
    pub scid: u16,
}

unsafe impl FixedSizeValue for DisconnectionReq {
    fn is_valid(data: &[u8]) -> bool {
        true
    }
}

impl L2capSignal for DisconnectionReq {
    fn code() -> L2capSignalCode {
        L2capSignalCode::DisconnectionReq
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DisconnectionRes {
    pub dcid: u16,
    pub scid: u16,
}

unsafe impl FixedSizeValue for DisconnectionRes {
    fn is_valid(data: &[u8]) -> bool {
        true
    }
}

impl L2capSignal for DisconnectionRes {
    fn code() -> L2capSignalCode {
        L2capSignalCode::DisconnectionRes
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ConnParamUpdateReq {
    pub interval_min: u16,
    pub interval_max: u16,
    pub latency: u16,
    pub timeout: u16,
}

unsafe impl FixedSizeValue for ConnParamUpdateReq {
    fn is_valid(data: &[u8]) -> bool {
        true
    }
}

impl L2capSignal for ConnParamUpdateReq {
    fn code() -> L2capSignalCode {
        L2capSignalCode::ConnParamUpdateReq
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ConnParamUpdateRes {
    pub result: u16,
}

unsafe impl FixedSizeValue for ConnParamUpdateRes {
    fn is_valid(data: &[u8]) -> bool {
        true
    }
}

impl L2capSignal for ConnParamUpdateRes {
    fn code() -> L2capSignalCode {
        L2capSignalCode::ConnParamUpdateRes
    }
}

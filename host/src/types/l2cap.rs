use bt_hci::{FixedSizeValue, WriteHci};

pub(crate) const L2CAP_CID_ATT: u16 = 0x0004;
pub(crate) const L2CAP_CID_LE_U_SIGNAL: u16 = 0x0005;
pub(crate) const L2CAP_CID_LE_U_SECURITY_MANAGER: u16 = 0x0006;
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

#[derive(Clone, Copy, PartialEq)]
#[repr(transparent)]
pub struct L2capSignalCode(pub u8);

unsafe impl FixedSizeValue for L2capSignalCode {
    fn is_valid(_data: &[u8]) -> bool {
        true
    }
}

impl core::fmt::Debug for L2capSignalCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::COMMAND_REJECT_RES => write!(f, "CommandRejectRes"),
            Self::CONNECTION_REQ => write!(f, "ConnectionReq"),
            Self::CONNECTION_RES => write!(f, "ConnectionRes"),
            Self::CONFIGURATION_REQ => write!(f, "ConfigurationReq"),
            Self::CONFIGURATION_RES => write!(f, "ConfigurationRes"),
            Self::DISCONNECTION_REQ => write!(f, "DisconnectionReq"),
            Self::DISCONNECTION_RES => write!(f, "DisconnectionRes"),
            Self::ECHO_REQ => write!(f, "EchoReq"),
            Self::ECHO_RES => write!(f, "EchoRes"),
            Self::INFORMATION_REQ => write!(f, "InformationReq"),
            Self::INFORMATION_RES => write!(f, "InformationRes"),
            Self::CONN_PARAM_UPDATE_REQ => write!(f, "ConnParamUpdateReq"),
            Self::CONN_PARAM_UPDATE_RES => write!(f, "ConnParamUpdateRes"),
            Self::LE_CREDIT_CONN_REQ => write!(f, "LeCreditConnReq"),
            Self::LE_CREDIT_CONN_RES => write!(f, "LeCreditConnRes"),
            Self::LE_CREDIT_FLOW_IND => write!(f, "LeCreditFlowInd"),
            Self::CREDIT_CONN_REQ => write!(f, "CreditConnReq"),
            Self::CREDIT_CONN_RES => write!(f, "CreditConnRes"),
            Self::CREDIT_CONN_RECONFIG_REQ => write!(f, "CreditConnReconfigReq"),
            Self::CREDIT_CONN_RECONFIG_RES => write!(f, "CreditConnReconfigRes"),
            _ => write!(f, "Unknown(0x{:02x})", self.0),
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for L2capSignalCode {
    fn format(&self, f: defmt::Formatter<'_>) {
        match *self {
            Self::COMMAND_REJECT_RES => defmt::write!(f, "CommandRejectRes"),
            Self::CONNECTION_REQ => defmt::write!(f, "ConnectionReq"),
            Self::CONNECTION_RES => defmt::write!(f, "ConnectionRes"),
            Self::CONFIGURATION_REQ => defmt::write!(f, "ConfigurationReq"),
            Self::CONFIGURATION_RES => defmt::write!(f, "ConfigurationRes"),
            Self::DISCONNECTION_REQ => defmt::write!(f, "DisconnectionReq"),
            Self::DISCONNECTION_RES => defmt::write!(f, "DisconnectionRes"),
            Self::ECHO_REQ => defmt::write!(f, "EchoReq"),
            Self::ECHO_RES => defmt::write!(f, "EchoRes"),
            Self::INFORMATION_REQ => defmt::write!(f, "InformationReq"),
            Self::INFORMATION_RES => defmt::write!(f, "InformationRes"),
            Self::CONN_PARAM_UPDATE_REQ => defmt::write!(f, "ConnParamUpdateReq"),
            Self::CONN_PARAM_UPDATE_RES => defmt::write!(f, "ConnParamUpdateRes"),
            Self::LE_CREDIT_CONN_REQ => defmt::write!(f, "LeCreditConnReq"),
            Self::LE_CREDIT_CONN_RES => defmt::write!(f, "LeCreditConnRes"),
            Self::LE_CREDIT_FLOW_IND => defmt::write!(f, "LeCreditFlowInd"),
            Self::CREDIT_CONN_REQ => defmt::write!(f, "CreditConnReq"),
            Self::CREDIT_CONN_RES => defmt::write!(f, "CreditConnRes"),
            Self::CREDIT_CONN_RECONFIG_REQ => defmt::write!(f, "CreditConnReconfigReq"),
            Self::CREDIT_CONN_RECONFIG_RES => defmt::write!(f, "CreditConnReconfigRes"),
            _ => defmt::write!(f, "Unknown(0x{:02x})", self.0),
        }
    }
}

impl From<u8> for L2capSignalCode {
    fn from(val: u8) -> Self {
        Self(val)
    }
}

#[allow(non_upper_case_globals)]
impl L2capSignalCode {
    pub const COMMAND_REJECT_RES: Self = Self(0x01);
    pub const CONNECTION_REQ: Self = Self(0x02);
    pub const CONNECTION_RES: Self = Self(0x03);
    pub const CONFIGURATION_REQ: Self = Self(0x04);
    pub const CONFIGURATION_RES: Self = Self(0x05);
    pub const DISCONNECTION_REQ: Self = Self(0x06);
    pub const DISCONNECTION_RES: Self = Self(0x07);
    pub const ECHO_REQ: Self = Self(0x08);
    pub const ECHO_RES: Self = Self(0x09);
    pub const INFORMATION_REQ: Self = Self(0x0A);
    pub const INFORMATION_RES: Self = Self(0x0B);
    pub const CONN_PARAM_UPDATE_REQ: Self = Self(0x12);
    pub const CONN_PARAM_UPDATE_RES: Self = Self(0x13);
    pub const LE_CREDIT_CONN_REQ: Self = Self(0x14);
    pub const LE_CREDIT_CONN_RES: Self = Self(0x15);
    pub const LE_CREDIT_FLOW_IND: Self = Self(0x16);
    pub const CREDIT_CONN_REQ: Self = Self(0x17);
    pub const CREDIT_CONN_RES: Self = Self(0x18);
    pub const CREDIT_CONN_RECONFIG_REQ: Self = Self(0x19);
    pub const CREDIT_CONN_RECONFIG_RES: Self = Self(0x1A);
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
        L2capSignalCode::LE_CREDIT_CONN_REQ
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
/// Result code for an LE Credit Based Connection Response.
pub enum LeCreditConnResultCode {
    /// Connection successful.
    Success = 0x0000,
    /// Connection refused — LE_PSM not supported.
    SpsmNotSupported = 0x0002,
    /// Connection refused — no resources available.
    NoResources = 0x0004,
    /// Connection refused — insufficient authentication.
    InsufficientAuthentication = 0x0005,
    /// Connection refused — insufficient authorization.
    InsufficientAuthorization = 0x0006,
    /// Connection refused — encryption key size too short.
    EncryptionKeyTooShort = 0x0007,
    /// Connection refused — insufficient encryption.
    InsufficientEncryption = 0x0008,
    /// Connection refused — invalid Source CID.
    InvalidSourceId = 0x0009,
    /// Connection refused — Source CID already allocated.
    ScidAlreadyAllocated = 0x000A,
    /// Connection refused — unacceptable parameters.
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
        L2capSignalCode::LE_CREDIT_CONN_RES
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
        L2capSignalCode::LE_CREDIT_FLOW_IND
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
        L2capSignalCode::DISCONNECTION_REQ
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
        L2capSignalCode::DISCONNECTION_RES
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
        L2capSignalCode::CONN_PARAM_UPDATE_REQ
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
        L2capSignalCode::CONN_PARAM_UPDATE_RES
    }
}

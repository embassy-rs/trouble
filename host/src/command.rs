use crate::{AdvertisingParameters, Data};

pub const CONTROLLER_OGF: u8 = 0x03;
pub const RESET_OCF: u16 = 0x03;
pub const SET_EVENT_MASK_OCF: u16 = 0x01;

pub const LE_OGF: u8 = 0x08;
pub const SET_ADVERTISING_PARAMETERS_OCF: u16 = 0x06;
pub const SET_ADVERTISING_DATA_OCF: u16 = 0x08;
pub const SET_SCAN_RSP_DATA_OCF: u16 = 0x09;
pub const SET_ADVERTISE_ENABLE_OCF: u16 = 0x0a;
pub const LONG_TERM_KEY_REQUEST_REPLY_OCF: u16 = 0x1a;

pub const LINK_CONTROL_OGF: u8 = 0x01;
pub const DISCONNECT_OCF: u16 = 0x06;

pub const INFORMATIONAL_OGF: u8 = 0x04;
pub const READ_BD_ADDR_OCF: u16 = 0x09;

#[derive(Debug)]
pub struct CommandHeader {
    pub opcode: u16,
    pub len: u8,
}

pub const fn opcode(ogf: u8, ocf: u16) -> u16 {
    ((ogf as u16) << 10) + ocf as u16
}

impl CommandHeader {
    pub fn from_bytes(bytes: &[u8]) -> CommandHeader {
        CommandHeader {
            opcode: ((bytes[1] as u16) << 8) + bytes[0] as u16,
            len: bytes[2],
        }
    }

    pub fn from_ogf_ocf(ogf: u8, ocf: u16, len: u8) -> CommandHeader {
        let opcode = opcode(ogf, ocf);
        CommandHeader { opcode, len }
    }

    pub fn write_into(&self, dst: &mut [u8]) {
        dst[0] = (self.opcode & 0xff) as u8;
        dst[1] = ((self.opcode & 0xff00) >> 8) as u8;
        dst[2] = self.len;
    }

    pub fn ogf(&self) -> u8 {
        ((self.opcode & 0b1111110000000000) >> 10) as u8
    }

    pub fn ocf(&self) -> u16 {
        self.opcode & 0b1111111111
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Command<'a> {
    Reset,
    LeSetAdvertisingParameters,
    LeSetAdvertisingParametersCustom(&'a AdvertisingParameters),
    LeSetAdvertisingData { data: &'d [u8] },
    LeSetScanRspData { data: &'d [u8] },
    LeSetAdvertiseEnable(bool),
    Disconnect { connection_handle: u16, reason: u8 },
    LeLongTermKeyRequestReply { handle: u16, ltk: u128 },
    ReadBrAddr,
    SetEventMask { events: [u8; 8] },
}

impl<'a> Command<'a> {
    pub fn opcode(&self) -> (u8, u16) {
        match self {
            Self::Reset => (CONTROLLER_OGF, RESET_OCF),
            Self::LeSetAdvertisingParameters => (LE_OGF, SET_ADVERTISING_PARAMETERS_OCF),
            Self::LeSetAdvertisingParametersCustom(_) => (LE_OGF, SET_ADVERTISING_PARAMETERS_OCF),
            Self::LeSetAdvertisingData { .. } => (LE_OGF, SET_ADVERTISING_DATA_OCF),
            Self::LeSetScanRspData { .. } => (LE_OGF, SET_SCAN_RSP_DATA_OCF),
            Self::LeSetAdvertiseEnable(_) => (LE_OGF, SET_ADVERTISE_ENABLE_OCF),
            Self::Disconnect { .. } => (LINK_CONTROL_OGF, DISCONNECT_OCF),
            Self::LeLongTermKeyRequestReply { .. } => (LE_OGF, LONG_TERM_KEY_REQUEST_REPLY_OCF),
            Self::ReadBrAddr => (INFORMATIONAL_OGF, READ_BD_ADDR_OCF),
            Self::SetEventMask { .. } => (CONTROLLER_OGF, SET_EVENT_MASK_OCF),
        }
    }

    pub fn encode(&self, dest: &mut [u8]) -> usize {
        let w = ByteWriter::new(dest);
        match self {
            Command::Reset => {
                CommandHeader::from_ogf_ocf(CONTROLLER_OGF, RESET_OCF, 0x00).write_into(w.slice(3));
            }
            Command::LeSetAdvertisingParameters => {
                let mut data = [0u8; 3 + 0xf];
                CommandHeader::from_ogf_ocf(LE_OGF, SET_ADVERTISING_PARAMETERS_OCF, 0x0f).write_into(w.slice(3));
                w.append(&[0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0]);
            }
            Command::LeSetAdvertisingParametersCustom(params) => {
                CommandHeader::from_ogf_ocf(LE_OGF, SET_ADVERTISING_PARAMETERS_OCF, 0x0f).write_into(w.slice(3));

                w.append(&params.advertising_interval_min.to_be_bytes());
                w.append(&params.advertising_interval_max.to_be_bytes());
                w.append(&[params.advertising_type as u8]);
                w.append(&[params.own_address_type as u8]);
                w.append(&[params.peer_address_type as u8]);
                w.append(&params.peer_address);
                w.append(&[params.advertising_channel_map]);
                w.append(&[params.filter_policy as u8]);
            }
            Command::LeSetAdvertisingData { ref data } => {
                CommandHeader::from_ogf_ocf(LE_OGF, SET_ADVERTISING_DATA_OCF, data.len as u8).write_into(w.slice(3));
                w.append(data.as_slice());
            }
            Command::LeSetScanRspData { ref data } => {
                CommandHeader::from_ogf_ocf(LE_OGF, SET_SCAN_RSP_DATA_OCF, data.len as u8).write_into(w.slice(3));
                w.append(data.as_slice());
            }
            Command::LeSetAdvertiseEnable(enable) => {
                CommandHeader::from_ogf_ocf(LE_OGF, SET_ADVERTISE_ENABLE_OCF, 0x01).write_into(w.slice(3));
                w.write_u8(if *enable { 1 } else { 0 });
            }
            Command::Disconnect {
                connection_handle,
                reason,
            } => {
                CommandHeader::from_ogf_ocf(LINK_CONTROL_OGF, DISCONNECT_OCF, 0x03).write_into(w.slice(3));
                w.write_u16_le(connection_handle);
                w.write_u8(*reason);
            }
            Command::LeLongTermKeyRequestReply { handle, ltk } => {
                let mut data = [0u8; 21];
                CommandHeader::from_ogf_ocf(LE_OGF, LONG_TERM_KEY_REQUEST_REPLY_OCF, 18).write_into(w.slice(3));
                w.write_u16_le(handle);
                w.append(&ltk.to_le_bytes());
            }
            Command::ReadBrAddr => {
                let mut data = [0u8; 3];
                CommandHeader::from_ogf_ocf(INFORMATIONAL_OGF, READ_BD_ADDR_OCF, 0x00).write_into(w.slice(3));
            }
            Command::SetEventMask { events } => {
                CommandHeader::from_ogf_ocf(CONTROLLER_OGF, SET_EVENT_MASK_OCF, 0x08).write_into(w.slice(3));
                w.append(events);
            }
        }
        w.len()
    }
}

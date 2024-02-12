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

pub enum Command<'a> {
    Reset,
    LeSetAdvertisingParameters,
    LeSetAdvertisingParametersCustom(&'a AdvertisingParameters),
    LeSetAdvertisingData { data: Data },
    LeSetScanRspData { data: Data },
    LeSetAdvertiseEnable(bool),
    Disconnect { connection_handle: u16, reason: u8 },
    LeLongTermKeyRequestReply { handle: u16, ltk: u128 },
    ReadBrAddr,
    SetEventMask { events: [u8; 8] },
}

impl<'a> Command<'a> {
    pub fn encode(self) -> Data {
        match self {
            Command::Reset => {
                info!("encode reset command");
                let mut data = [0u8; 4];
                data[0] = 0x01;
                CommandHeader::from_ogf_ocf(CONTROLLER_OGF, RESET_OCF, 0x00).write_into(&mut data[1..]);
                Data::new(&data)
            }
            Command::LeSetAdvertisingParameters => {
                let mut data = [0u8; 4 + 0xf];
                data[0] = 0x01;
                CommandHeader::from_ogf_ocf(LE_OGF, SET_ADVERTISING_PARAMETERS_OCF, 0x0f).write_into(&mut data[1..]);
                data[4..].copy_from_slice(&[0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0]);
                Data::new(&data)
            }
            Command::LeSetAdvertisingParametersCustom(params) => {
                let mut data = [0u8; 4 + 0xf];
                data[0] = 0x01;
                CommandHeader::from_ogf_ocf(LE_OGF, SET_ADVERTISING_PARAMETERS_OCF, 0x0f).write_into(&mut data[1..]);

                let mut adv_params = Data::new(&[]);
                adv_params.append(&params.advertising_interval_min.to_be_bytes());
                adv_params.append(&params.advertising_interval_max.to_be_bytes());
                adv_params.append(&[params.advertising_type as u8]);
                adv_params.append(&[params.own_address_type as u8]);
                adv_params.append(&[params.peer_address_type as u8]);
                adv_params.append(&params.peer_address);
                adv_params.append(&[params.advertising_channel_map]);
                adv_params.append(&[params.filter_policy as u8]);

                data[4..].copy_from_slice(adv_params.as_slice());
                Data::new(&data)
            }
            Command::LeSetAdvertisingData { ref data } => {
                let mut header = [0u8; 4];
                header[0] = 0x01;
                CommandHeader::from_ogf_ocf(LE_OGF, SET_ADVERTISING_DATA_OCF, data.len as u8)
                    .write_into(&mut header[1..]);
                let mut res = Data::new(&header);
                res.append(data.as_slice());
                res
            }
            Command::LeSetScanRspData { ref data } => {
                let mut header = [0u8; 4];
                header[0] = 0x01;
                CommandHeader::from_ogf_ocf(LE_OGF, SET_SCAN_RSP_DATA_OCF, data.len as u8).write_into(&mut header[1..]);
                let mut res = Data::new(&header);
                res.append(data.as_slice());
                res
            }
            Command::LeSetAdvertiseEnable(enable) => {
                let mut data = [0u8; 5];
                data[0] = 0x01;
                CommandHeader::from_ogf_ocf(LE_OGF, SET_ADVERTISE_ENABLE_OCF, 0x01).write_into(&mut data[1..]);
                data[4] = if enable { 1 } else { 0 };
                Data::new(&data)
            }
            Command::Disconnect {
                connection_handle,
                reason,
            } => {
                let mut data = [0u8; 7];
                data[0] = 0x01;
                CommandHeader::from_ogf_ocf(LINK_CONTROL_OGF, DISCONNECT_OCF, 0x03).write_into(&mut data[1..]);
                data[4..][..2].copy_from_slice(&connection_handle.to_le_bytes());
                data[6] = reason;
                Data::new(&data)
            }
            Command::LeLongTermKeyRequestReply { handle, ltk } => {
                let mut data = [0u8; 22];
                data[0] = 0x01;
                CommandHeader::from_ogf_ocf(LE_OGF, LONG_TERM_KEY_REQUEST_REPLY_OCF, 18).write_into(&mut data[1..]);
                data[4..][..2].copy_from_slice(&handle.to_le_bytes());
                data[6..].copy_from_slice(&ltk.to_le_bytes());
                Data::new(&data)
            }
            Command::ReadBrAddr => {
                info!("command read br addr");
                let mut data = [0u8; 4];
                data[0] = 0x01;
                CommandHeader::from_ogf_ocf(INFORMATIONAL_OGF, READ_BD_ADDR_OCF, 0x00).write_into(&mut data[1..]);
                Data::new(&data)
            }
            Command::SetEventMask { events } => {
                info!("command set event mask");
                let mut data = [0u8; 12];
                data[0] = 0x01;
                CommandHeader::from_ogf_ocf(CONTROLLER_OGF, SET_EVENT_MASK_OCF, 0x08).write_into(&mut data[1..]);
                data[4..].copy_from_slice(&events);
                Data::new(&data)
            }
        }
    }
}

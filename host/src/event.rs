use crate::{Addr, Data, Error};

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy)]
pub enum Event<'d> {
    CommandComplete {
        num_packets: u8,
        opcode: u16,
        data: &'d [u8],
    },
    DisconnectComplete {
        handle: u16,
        status: ErrorCode,
        reason: ErrorCode,
    },
    NumberOfCompletedPackets {
        number_of_connection_handles: u8,
        connection_handles: u16, // should be list
        completed_packets: u16,  // should be list
    },
    ConnectionComplete {
        status: u8,
        handle: u16,
        role: u8,
        peer_address: Addr,
        interval: u16,
        latency: u16,
        timeout: u16,
    },
    LongTermKeyRequest {
        handle: u16,
        random: u64,
        diversifier: u16,
    },
    CommandStatus {
        status: u8,
        num_packets: u8,
        opcode: u16,
    },
    Unknown,
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy)]
pub enum ErrorCode {
    Okay = 0x00,
    UnknownHciCommand = 0x01,
    UnknownConnectionIdentifier = 0x02,
    HardwareFailure = 0x03,
    PageTimeout = 0x04,
    AuthenticationFailure = 0x05,
    PinOrKeyMissing = 0x06,
    MemoryCapacityExceeded = 0x07,
    ConnectionTimeout = 0x08,
    ConnectionLimitExceeded = 0x09,
    AclConnectionAlreadyExists = 0x0b,
    CommandDisallowed = 0x0c,
    RemoteUserTerminatedConnection = 0x13,
    // see Error Codes Description in spec
    Unknown = 0xff,
}

impl ErrorCode {
    pub fn from_u8(value: u8) -> ErrorCode {
        match value {
            0x00 => ErrorCode::Okay,
            0x01 => ErrorCode::UnknownHciCommand,
            0x02 => ErrorCode::UnknownConnectionIdentifier,
            0x03 => ErrorCode::HardwareFailure,
            0x04 => ErrorCode::PageTimeout,
            0x05 => ErrorCode::AuthenticationFailure,
            0x06 => ErrorCode::PinOrKeyMissing,
            0x07 => ErrorCode::MemoryCapacityExceeded,
            0x08 => ErrorCode::ConnectionTimeout,
            0x09 => ErrorCode::ConnectionLimitExceeded,
            0x0b => ErrorCode::AclConnectionAlreadyExists,
            0x0c => ErrorCode::CommandDisallowed,
            0x13 => ErrorCode::RemoteUserTerminatedConnection,

            _ => ErrorCode::Unknown,
        }
    }
}

const EVENT_COMMAND_COMPLETE: u8 = 0x0e;
const EVENT_COMMAND_STATUS: u8 = 0x0f;
const EVENT_DISCONNECTION_COMPLETE: u8 = 0x05;
const EVENT_NUMBER_OF_COMPLETED_PACKETS: u8 = 0x13;
const EVENT_LE_META: u8 = 0x3e;
const EVENT_LE_META_CONNECTION_COMPLETE: u8 = 0x01;
// TODO ENHANCED_CONNECTION_COMPLETE
const EVENT_LE_META_LONG_TERM_KEY_REQUEST: u8 = 0x05;

impl Event {
    /// Reads and decodes an event and assumes the packet type (0x04) is already read.
    pub fn read(data: &[u8]) -> Self {
        let mut r = ByteReader::new(data);
        match r.read_u8() {
            EVENT_COMMAND_COMPLETE => {
                let num_packets = r.read_u8();
                let opcode = r.read_u16_le();
                let data = r.consume();
                Self::CommandComplete {
                    num_packets,
                    opcode,
                    data,
                }
            }
            EVENT_COMMAND_STATUS => {
                let status = r.read_u8();
                let num_packets = r.read_u8();
                let opcode = r.read_u16_le();
                Self::CommandStatus {
                    status,
                    num_packets,
                    opcode,
                }
            }
            EVENT_DISCONNECTION_COMPLETE => {
                let status = r.read_u8();
                let handle = r.read_u16_le();
                let reason = r.read_u8();
                let status = ErrorCode::from_u8(status);
                let reason = ErrorCode::from_u8(reason);
                Self::DisconnectComplete { handle, status, reason }
            }
            EVENT_NUMBER_OF_COMPLETED_PACKETS => {
                let data = event.data.as_slice();
                let num_handles = data[0];
                let connection_handle = ((data[2] as u16) << 8) + data[1] as u16;
                let completed_packet = ((data[4] as u16) << 8) + data[3] as u16;
                Self::NumberOfCompletedPackets {
                    number_of_connection_handles: num_handles,
                    connection_handles: connection_handle,
                    completed_packets: completed_packet,
                }
            }
            EVENT_LE_META => {
                let sub_event = event.data.as_slice()[0];
                let data = &event.data.as_slice()[1..];

                match sub_event {
                    EVENT_LE_META_CONNECTION_COMPLETE => {
                        let status = data[0];
                        let handle = ((data[2] as u16) << 8) + data[1] as u16;
                        let role = data[3];
                        let peer_address = Addr::from_le_bytes(data[4] != 0, data[5..][..6].try_into().unwrap());
                        let interval = ((data[2] as u16) << 8) + data[1] as u16;
                        let latency = ((data[2] as u16) << 8) + data[1] as u16;
                        let timeout = ((data[2] as u16) << 8) + data[1] as u16;

                        Self::ConnectionComplete {
                            status,
                            handle,
                            role,
                            peer_address,
                            interval,
                            latency,
                            timeout,
                        }
                    }
                    EVENT_LE_META_LONG_TERM_KEY_REQUEST => {
                        let handle = ((data[1] as u16) << 8) + data[0] as u16;
                        let random = u64::from_be_bytes((&data[2..][..8]).try_into().unwrap());
                        let diversifier = ((data[11] as u16) << 8) + data[10] as u16;
                        Self::LongTermKeyRequest {
                            handle,
                            random,
                            diversifier,
                        }
                    }
                    _ => {
                        warn!("Ignoring unknown le-meta event {:02x} data = {:02x}", sub_event, data);
                        Self::Unknown
                    }
                }
            }
            _ => {
                warn!(
                    "Ignoring unknown event {:02x} data = {:02x}",
                    event.code,
                    event.data.as_slice()
                );
                Self::Unknown
            }
        }
    }
}

impl Event {
    fn read(data: &[u8]) -> Self {
        assert!(data.len() >= 2);
        let code = data[0];
        let len = data[1];
        let data = Data::new(&data[2..2 + len as usize]);
        Self { code, data }
    }
}

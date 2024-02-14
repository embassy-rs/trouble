use crate::Data;

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy)]
pub struct AclPacket {
    pub handle: u16,
    pub boundary_flag: BoundaryFlag,
    pub bc_flag: ControllerBroadcastFlag,
    pub data: Data,
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy)]
pub enum BoundaryFlag {
    FirstNonAutoFlushable,
    Continuing,
    FirstAutoFlushable,
    Complete,
}

/// BC flag from controller to host
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy)]
pub enum ControllerBroadcastFlag {
    PointToPoint,
    NotParkedState,
    ParkedState,
    Reserved,
}

/// BC flag from host to controller
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy)]
pub enum HostBroadcastFlag {
    NoBroadcast,
    ActiveSlaveBroadcast,
    ParkedSlaveBroadcast,
    Reserved,
}

impl AclPacket {
    pub fn read(data: &[u8]) -> Self {
        assert!(data.len() >= 4);
        let raw_handle_buffer = [data[0], data[1]];
        let (pb, bc, handle) = Self::decode_raw_handle(raw_handle_buffer);
        debug!(
            "raw handle {:08b} {:08b} - boundary {:?}",
            raw_handle_buffer[0], raw_handle_buffer[1], pb
        );

        let len = u16::from_le_bytes([data[2], data[3]]);
        info!("read len {}", len);
        let data = Data::new(&data[4..4 + len as usize]);

        Self {
            handle,
            boundary_flag: pb,
            bc_flag: bc,
            data,
        }
    }

    fn decode_raw_handle(raw_handle_buffer: [u8; 2]) -> (BoundaryFlag, ControllerBroadcastFlag, u16) {
        let raw_handle = u16::from_le_bytes(raw_handle_buffer);

        let pb = (raw_handle & 0b0011000000000000) >> 12;
        let pb = match pb {
            0b00 => BoundaryFlag::FirstNonAutoFlushable,
            0b01 => BoundaryFlag::Continuing,
            0b10 => BoundaryFlag::FirstAutoFlushable,
            0b11 => BoundaryFlag::Complete,
            _ => panic!("Unexpected boundary flag"),
        };

        let bc = (raw_handle & 0b1100000000000000) >> 14;
        let bc = match bc {
            0b00 => ControllerBroadcastFlag::PointToPoint,
            0b01 => ControllerBroadcastFlag::NotParkedState,
            0b10 => ControllerBroadcastFlag::ParkedState,
            0b11 => ControllerBroadcastFlag::Reserved,
            _ => panic!("Unexpected broadcast flag"),
        };

        let handle = raw_handle & 0b111111111111;

        (pb, bc, handle)
    }

    pub fn encode(handle: u16, pb: BoundaryFlag, bc: HostBroadcastFlag, payload: Data) -> Data {
        let mut data = Data::new(&[]);

        let mut raw_handle = handle;

        raw_handle |= match pb {
            BoundaryFlag::FirstNonAutoFlushable => 0b00,
            BoundaryFlag::Continuing => 0b01,
            BoundaryFlag::FirstAutoFlushable => 0b10,
            BoundaryFlag::Complete => 0b11,
        } << 12;

        raw_handle |= match bc {
            HostBroadcastFlag::NoBroadcast => 0b00,
            HostBroadcastFlag::ActiveSlaveBroadcast => 0b01,
            HostBroadcastFlag::ParkedSlaveBroadcast => 0b10,
            HostBroadcastFlag::Reserved => 0b11,
        } << 14;

        data.append(&[(raw_handle & 0xff) as u8, ((raw_handle >> 8) & 0xff) as u8]);

        let len = payload.len;
        data.append(&[(len & 0xff) as u8, ((len >> 8) & 0xff) as u8]);

        data.append(payload.as_slice());

        data
    }
}

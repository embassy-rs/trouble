use crate::{acl::AclPacket, Data};

#[derive(Debug)]
pub struct L2capPacket {
    pub length: u16,
    pub channel: u16,
    pub payload: Data,
}

#[derive(Debug)]
pub enum L2capDecodeError {
    Other,
}

impl L2capPacket {
    pub fn decode(packet: AclPacket) -> Result<(u16, Self), L2capDecodeError> {
        let data = packet.data.as_slice();
        debug!("L2CAP {:02x}", data);
        let length = (data[0] as u16) + ((data[1] as u16) << 8);
        let channel = (data[2] as u16) + ((data[3] as u16) << 8);
        let payload = Data::new(&data[4..]);

        Ok((
            packet.handle,
            L2capPacket {
                length,
                channel,
                payload,
            },
        ))
    }

    pub fn encode(att_data: Data) -> Data {
        let mut data = Data::new(&[
            0, 0, // len set later
            0x04, 0x00, // channel
        ]);
        data.append(att_data.as_slice());

        let len = data.len - 4;
        data.set(0, (len & 0xff) as u8);
        data.set(1, ((len >> 8) & 0xff) as u8);

        data
    }

    pub fn encode_sm(att_data: Data) -> Data {
        let mut data = Data::new(&[
            0, 0, // len set later
            0x06, 0x00, // channel
        ]);
        data.append(att_data.as_slice());

        let len = data.len - 4;
        data.set(0, (len & 0xff) as u8);
        data.set(1, ((len >> 8) & 0xff) as u8);

        data
    }
}

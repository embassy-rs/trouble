use crate::byte_reader::ByteReader;
use crate::byte_writer::ByteWriter;
use bt_hci::data::AclPacket;

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub struct L2capPacket<'d> {
    pub channel: u16,
    pub payload: &'d [u8],
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub enum L2capDecodeError {
    Other,
}

impl<'d> L2capPacket<'d> {
    pub fn decode(packet: AclPacket<'d>) -> Result<(bt_hci::param::ConnHandle, L2capPacket<'d>), L2capDecodeError> {
        let handle = packet.handle();
        let data = packet.data();
        drop(packet);
        let mut r = ByteReader::new(data);
        let length = r.read_u16_le();
        let channel = r.read_u16_le();
        let payload = r.read_slice(length as usize);

        Ok((handle, L2capPacket { channel, payload }))
    }

    pub fn encode(&self, dest: &mut [u8]) {
        let mut w = ByteWriter::new(dest);
        w.write_u16_le(self.payload.len() as u16);
        w.write_u16_le(self.channel);
        w.append(self.payload);
    }
}

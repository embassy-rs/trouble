use crate::packet_pool::Packet;

pub struct Pdu<'d> {
    pub packet: Packet<'d>,
    pub len: usize,
}

impl<'d> Pdu<'d> {
    pub fn new(packet: Packet<'d>, len: usize) -> Self {
        Self { packet, len }
    }
}

impl<'d> AsRef<[u8]> for Pdu<'d> {
    fn as_ref(&self) -> &[u8] {
        &self.packet.as_ref()[..self.len]
    }
}

impl<'d> AsMut<[u8]> for Pdu<'d> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.packet.as_mut()[..self.len]
    }
}

use crate::packet_pool::Packet;

pub(crate) struct Pdu<'d> {
    pub packet: Packet<'d>,
    pub len: usize,
}

impl<'d> Pdu<'d> {
    pub(crate) fn new(packet: Packet<'d>, len: usize) -> Self {
        Self { packet, len }
    }
}

impl AsRef<[u8]> for Pdu<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.packet.as_ref()[..self.len]
    }
}

impl AsMut<[u8]> for Pdu<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.packet.as_mut()[..self.len]
    }
}

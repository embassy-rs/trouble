use crate::pool::Packet;

pub(crate) struct Pdu {
    pub packet: Packet,
    pub len: usize,
}

impl Pdu {
    pub(crate) fn new(packet: Packet, len: usize) -> Self {
        Self { packet, len }
    }
}

impl AsRef<[u8]> for Pdu {
    fn as_ref(&self) -> &[u8] {
        &self.packet.as_ref()[..self.len]
    }
}

impl AsMut<[u8]> for Pdu {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.packet.as_mut()[..self.len]
    }
}

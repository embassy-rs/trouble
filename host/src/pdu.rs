use crate::Packet;

pub(crate) struct Pdu<P> {
    pub packet: P,
    pub len: usize,
}

impl<P> Pdu<P> {
    pub(crate) fn new(packet: P, len: usize) -> Self {
        Self { packet, len }
    }
}

impl<P: Packet> AsRef<[u8]> for Pdu<P> {
    fn as_ref(&self) -> &[u8] {
        &self.packet.as_ref()[..self.len]
    }
}

impl<P: Packet> AsMut<[u8]> for Pdu<P> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.packet.as_mut()[..self.len]
    }
}

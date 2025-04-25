use crate::{Packet, PacketPool};

pub(crate) struct Pdu<P> {
    packet: P,
    len: usize,
}

impl<P> Pdu<P> {
    pub(crate) fn new(packet: P, len: usize) -> Self {
        Self { packet, len }
    }
    pub(crate) fn len(&self) -> usize {
        self.len
    }
    pub(crate) fn into_inner(self) -> P {
        self.packet
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

/// Service Data Unit
///
/// A unit of payload that can be received or sent over an L2CAP channel.
pub struct Sdu<P> {
    pdu: Pdu<P>,
}

impl<P> Sdu<P> {
    /// Create a new SDU using the allocated packet that has been pre-populated with data.
    pub fn new(packet: P, len: usize) -> Self {
        Self {
            pdu: Pdu::new(packet, len),
        }
    }

    pub(crate) fn from_pdu(pdu: Pdu<P>) -> Self {
        Self { pdu }
    }

    /// Payload length.
    pub fn len(&self) -> usize {
        self.pdu.len()
    }

    /// Payload length.
    pub fn is_empty(&self) -> bool {
        self.pdu.len() == 0
    }

    pub(crate) fn into_pdu(self) -> Pdu<P> {
        self.pdu
    }

    /// Retrieve the inner packet.
    pub fn into_inner(self) -> P {
        self.pdu.into_inner()
    }
}

impl<P: Packet> Sdu<P> {
    /// Create SDU from a slice.
    pub fn from_slice<POOL>(data: &[u8]) -> Result<Self, ()>
    where
        POOL: PacketPool<Packet = P>,
    {
        assert!(data.len() <= POOL::MTU);
        if let Some(mut buf) = POOL::allocate() {
            buf.as_mut()[..data.len()].copy_from_slice(data);
            Ok(Sdu::new(buf, data.len()))
        } else {
            Err(())
        }
    }
}

impl<P: Packet> AsRef<[u8]> for Sdu<P> {
    fn as_ref(&self) -> &[u8] {
        self.pdu.as_ref()
    }
}

impl<P: Packet> AsMut<[u8]> for Sdu<P> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.pdu.as_mut()
    }
}

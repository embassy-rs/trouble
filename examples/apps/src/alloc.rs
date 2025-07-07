use std::boxed::Box;
use trouble_host::prelude::{Packet, PacketPool};

const MTU: usize = 2510;

pub struct Buf {
    pub data: [u8; MTU],
}

pub struct BigAlloc;
pub struct BigBuf(Box<Buf>);

impl PacketPool for BigAlloc {
    type Packet = BigBuf;
    const MTU: usize = MTU;
    fn allocate() -> Option<Self::Packet> {
        let b = Buf { data: [0; MTU] };
        Some(BigBuf(Box::new(b)))
    }

    fn capacity() -> usize {
        64
    }
}

impl AsRef<[u8]> for BigBuf {
    fn as_ref(&self) -> &[u8] {
        &self.0.data[..]
    }
}

impl AsMut<[u8]> for BigBuf {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0.data[..]
    }
}

impl Packet for BigBuf {}

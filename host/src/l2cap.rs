use crate::byte_reader::ByteReader;
use crate::byte_writer::ByteWriter;
use bt_hci::data::AclPacket;
use bt_hci::param::ConnHandle;
use bt_hci::FromHciBytesError;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::channel::{Channel, Receiver, Sender};
use heapless::Vec;

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub struct L2capPacket<'d> {
    pub channel: u16,
    pub payload: &'d [u8],
}

impl<'d> L2capPacket<'d> {
    pub fn decode(packet: AclPacket<'_>) -> Result<(bt_hci::param::ConnHandle, L2capPacket), FromHciBytesError> {
        let handle = packet.handle();
        let data = packet.data();
        drop(packet);
        let mut r = ByteReader::new(data);
        let length = r.read_u16_le();
        let channel = r.read_u16_le();
        let payload = r.read_slice(length as usize);

        Ok((handle, L2capPacket { channel, payload }))
    }

    pub fn encode(&self, dest: &mut [u8]) -> usize {
        let mut w = ByteWriter::new(dest);
        w.write_u16_le(self.payload.len() as u16);
        w.write_u16_le(self.channel);
        w.append(&self.payload[..]);
        w.len()
    }
}

pub const TXQ: usize = 3;
pub const RXQ: usize = 3;

pub struct L2capState<M: RawMutex, const MTU: usize> {
    cid: u16,
    rx: Channel<M, (ConnHandle, Vec<u8, MTU>), RXQ>,
}

impl<M: RawMutex, const MTU: usize> L2capState<M, MTU> {
    pub const fn new() -> Self {
        Self {
            cid: u16::MAX,
            rx: Channel::new(),
        }
    }

    pub fn receiver(&self) -> Receiver<'_, M, (ConnHandle, Vec<u8, MTU>), RXQ> {
        self.rx.receiver()
    }

    pub fn sender(&self) -> Sender<'_, M, (ConnHandle, Vec<u8, MTU>), RXQ> {
        self.rx.sender()
    }
}

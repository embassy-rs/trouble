use crate::codec;
use crate::cursor::{ReadCursor, WriteCursor};
use crate::L2CAP_RXQ;
use bt_hci::data::AclPacket;
use bt_hci::param::ConnHandle;
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
    pub fn decode(packet: AclPacket<'_>) -> Result<(bt_hci::param::ConnHandle, L2capPacket), codec::Error> {
        let handle = packet.handle();
        let data = packet.data();
        let mut r = ReadCursor::new(data);
        let length: u16 = r.read()?;
        let channel: u16 = r.read()?;
        let payload = r.consume(length as usize)?;

        Ok((handle, L2capPacket { channel, payload }))
    }

    pub fn encode(&self, dest: &mut [u8]) -> Result<usize, codec::Error> {
        let mut w = WriteCursor::new(dest);
        w.write(self.payload.len() as u16)?;
        w.write(self.channel)?;
        w.append(&self.payload[..])?;
        Ok(w.len())
    }
}

pub struct L2capState<M: RawMutex, const MTU: usize> {
    //conn: ConnHandle,
    //mtu: u16,

    //cid: u16,
    //peer_cid: u16,
    rx: Channel<M, (ConnHandle, Vec<u8, MTU>), L2CAP_RXQ>,
}

impl<M: RawMutex, const MTU: usize> L2capState<M, MTU> {
    pub const fn new() -> Self {
        Self { rx: Channel::new() }
    }
    /*
    pub const fn new(conn: ConnHandle, cid: u16, peer_cid: u16, mtu: u16, peer_credits: u16) -> Self {
        Self {
            conn,
            mtu,
            cid,
            //credits: 0,
            peer_cid,
            //peer_credits,
            rx: Channel::new(),
        }
    }*/

    pub fn receiver(&self) -> Receiver<'_, M, (ConnHandle, Vec<u8, MTU>), L2CAP_RXQ> {
        self.rx.receiver()
    }

    pub fn sender(&self) -> Sender<'_, M, (ConnHandle, Vec<u8, MTU>), L2CAP_RXQ> {
        self.rx.sender()
    }
}

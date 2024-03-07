use crate::adapter::{self, Adapter};
use crate::channel_manager::ChannelManager;
use crate::codec;
use crate::connection::Connection;
use crate::connection_manager::ConnectionManager;
use crate::cursor::{ReadCursor, WriteCursor};
use crate::packet_pool::DynamicPacketPool;
use crate::pdu::Pdu;
use bt_hci::data::AclPacket;
use bt_hci::param::ConnHandle;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::channel::{Channel, DynamicReceiver, DynamicSender};

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

pub struct L2capChannel<'d, M: RawMutex, const MTU: usize> {
    pool: &'d dyn DynamicPacketPool<'d>,
    pool_client: usize,
    cid: u16,
    mgr: &'d ChannelManager<'d, M>,
    rx: DynamicReceiver<'d, Pdu<'d>>,
    tx: DynamicSender<'d, (ConnHandle, Pdu<'d>)>,
}

impl<'d, M: RawMutex, const MTU: usize> L2capChannel<'d, M, MTU> {
    pub async fn send(&mut self, buf: &[u8]) -> Result<(), ()> {
        todo!()
        /*
        for chunk in buf.chunks(MTU - 4) {
            // TODO: Take credit into account!!
            if let Some(pdu) = self.pool.alloc(self.pool_client) {
                let mut w = WriteCursor::new(pdu.as_mut());
                w.write(chunk.len() as u16)?;
                w.write(self.cid as u16)?;
                w.append(chunk)?;
            } else {
                return Err(());
            }
        }
        Ok(())*/
    }

    pub async fn receive(&mut self, buf: &mut [u8]) -> Result<(), ()> {
        /*
        for chunk in buf.chunks(MTU - 4) {
            // TODO: Take credit into account!!
            if let Some(pdu) = self.pool.alloc(self.pool_client) {
                let mut w = WriteCursor::new(pdu.as_mut());
                w.write(chunk.len() as u16)?;
                w.write(self.cid as u16)?;
                w.append(chunk)?;
            } else {
                return Err(());
            }
        }

        Ok(())*/
        todo!()
    }

    pub async fn accept<const CHANNELS: usize, const L2CAP_TXQ: usize, const L2CAP_RXQ: usize>(
        adapter: &'d Adapter<'d, M, CHANNELS, L2CAP_TXQ, L2CAP_RXQ>,
        connection: &Connection<'d>,
    ) {
        let connections = &adapter.connections;
        let channels = &adapter.channels;

        // TODO:
        // - Merge AdapterResources and Adapter
        // - Pass adapter on accept
        // - Wait until channel manager has a new channel (how? use poll_fn/signal/channel per connection in conn manager perhaps?)
        // - Store connection/channel manager here
        // - Store rx/tx, channel details
        todo!()
    }

    pub async fn create(connection: &Connection<'d>) -> Self {
        todo!()
    }
}

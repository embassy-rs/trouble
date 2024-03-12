use core::future::poll_fn;

use crate::adapter::Adapter;
use crate::channel_manager::{self, DynamicChannelManager};
use crate::codec;
use crate::connection::Connection;
use crate::cursor::{ReadCursor, WriteCursor};
use crate::packet_pool::{AllocId, DynamicPacketPool};
use crate::pdu::Pdu;
use bt_hci::data::AclPacket;
use bt_hci::param::ConnHandle;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::channel::{DynamicReceiver, DynamicSender};

pub(crate) const L2CAP_CID_ATT: u16 = 0x0004;
pub(crate) const L2CAP_CID_LE_U_SIGNAL: u16 = 0x0005;
pub(crate) const L2CAP_CID_DYN_START: u16 = 0x0040;

pub use channel_manager::Error;

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

pub struct L2capChannel<'d, const MTU: usize> {
    conn: ConnHandle,
    pool_id: AllocId,
    cid: u16,
    peer_cid: u16,
    mps: usize,
    pool: &'d dyn DynamicPacketPool<'d>,
    manager: &'d dyn DynamicChannelManager<'d>,
    rx: DynamicReceiver<'d, Option<Pdu<'d>>>,
    tx: DynamicSender<'d, (ConnHandle, Pdu<'d>)>,
}

impl<'d, const MTU: usize> L2capChannel<'d, MTU> {
    pub async fn send(&mut self, buf: &[u8]) -> Result<(), Error> {
        // The number of packets we'll need to send for this payload
        let n_packets = 1 + (buf.len().saturating_sub(self.mps - 2)).div_ceil(self.mps);

        // TODO: We could potentially make this more graceful by sending as much as we can, and wait
        // for pool to get the available packets back, which would require some poll/async behavior
        // support for the pool.
        if self.pool.available(self.pool_id) < n_packets {
            return Err(Error::OutOfMemory);
        }

        poll_fn(|cx| self.manager.poll_request_to_send(self.cid, n_packets, cx)).await?;

        // Segment using mps
        let (first, remaining) = buf.split_at(self.mps - 2);
        if let Some(mut packet) = self.pool.alloc(self.pool_id) {
            let len = {
                let mut w = WriteCursor::new(packet.as_mut());
                w.write(2 + first.len() as u16)?;
                w.write(self.peer_cid as u16)?;
                let len = buf.len() as u16;
                w.write(len)?;
                w.append(first)?;
                w.len()
            };
            let pdu = if remaining.is_empty() {
                Pdu::new(packet, len)
            } else {
                Pdu::new(packet, len)
            };
            self.tx.send((self.conn, pdu)).await;
        } else {
            return Err(Error::OutOfMemory);
        }

        let chunks = remaining.chunks(self.mps);
        let num_chunks = chunks.len();
        for (i, chunk) in chunks.enumerate() {
            if let Some(mut packet) = self.pool.alloc(self.pool_id) {
                let len = {
                    let mut w = WriteCursor::new(packet.as_mut());
                    w.write(chunk.len() as u16)?;
                    w.write(self.peer_cid as u16)?;
                    w.append(chunk)?;
                    w.len()
                };
                let pdu = if i == num_chunks - 1 {
                    Pdu::new(packet, len)
                } else {
                    Pdu::new(packet, len)
                };
                self.tx.send((self.conn, pdu)).await;
            } else {
                return Err(Error::OutOfMemory);
            }
        }

        Ok(())
    }

    async fn receive_pdu(&mut self) -> Result<Pdu<'d>, Error> {
        match self.rx.receive().await {
            Some(pdu) => Ok(pdu),
            None => {
                self.manager.confirm_disconnected(self.cid)?;
                Err(Error::ChannelClosed)
            }
        }
    }

    pub async fn receive(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let mut n_received = 1;
        let packet = self.receive_pdu().await?;
        let mut r = ReadCursor::new(&packet.as_ref());
        let remaining: u16 = r.read()?;
        let data = r.remaining();

        let to_copy = data.len().min(buf.len());
        buf[..to_copy].copy_from_slice(&data[..to_copy]);
        let mut pos = to_copy;

        let mut remaining = remaining as usize - data.len();
        // We have some k-frames to reassemble
        while remaining > 0 {
            let packet = self.receive_pdu().await?;
            n_received += 1;
            let to_copy = packet.len.min(buf.len() - pos);
            if to_copy > 0 {
                buf[pos..pos + to_copy].copy_from_slice(&packet.as_ref()[..to_copy]);
                pos += to_copy;
            }
            remaining -= packet.len;
        }

        self.manager.confirm_received(self.cid, n_received)?.await;

        Ok(pos)
    }

    pub async fn accept<
        M: RawMutex,
        const CONNS: usize,
        const CHANNELS: usize,
        const L2CAP_TXQ: usize,
        const L2CAP_RXQ: usize,
    >(
        adapter: &'d Adapter<'d, M, CONNS, CHANNELS, L2CAP_TXQ, L2CAP_RXQ>,
        connection: &Connection<'d>,
        psm: u16,
    ) -> Result<Self, Error> {
        let connections = &adapter.connections;
        let channels = &adapter.channels;

        let (state, rx) = channels.accept(connection.handle(), psm, MTU as u16).await?;

        let tx = adapter.outbound.sender().into();
        Ok(Self {
            conn: connection.handle(),
            cid: state.cid,
            peer_cid: state.peer_cid,
            mps: state.mps as usize,
            pool: adapter.pool,
            pool_id: state.pool_id,
            manager: &adapter.channels,
            tx,
            rx,
        })
    }

    pub async fn create<
        M: RawMutex,
        const CONNS: usize,
        const CHANNELS: usize,
        const L2CAP_TXQ: usize,
        const L2CAP_RXQ: usize,
    >(
        adapter: &'d Adapter<'d, M, CONNS, CHANNELS, L2CAP_TXQ, L2CAP_RXQ>,
        connection: &Connection<'d>,
        psm: u16,
    ) -> Result<Self, Error> {
        // TODO: Use unique signal ID to ensure no collision of signal messages
        //
        let (state, rx) = adapter.channels.create(connection.handle(), psm, MTU as u16).await?;
        let tx = adapter.outbound.sender().into();

        Ok(Self {
            conn: connection.handle(),
            pool_id: state.pool_id,
            cid: state.cid,
            peer_cid: state.peer_cid,
            mps: state.mps as usize,
            pool: adapter.pool,
            manager: &adapter.channels,
            tx,
            rx,
        })
    }
}

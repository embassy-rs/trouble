use crate::adapter::Adapter;
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
    cid: u16,
    mps: u16,
    pool: &'d dyn DynamicPacketPool<'d>,
    rx: DynamicReceiver<'d, Pdu<'d>>,
    tx: DynamicSender<'d, (ConnHandle, Pdu<'d>)>,
}

impl<'d, const MTU: usize> L2capChannel<'d, MTU> {
    pub async fn send(&mut self, buf: &[u8]) -> Result<(), ()> {
        // TODO: Take credit into account!!
        let pool_id = AllocId::dynamic(self.cid as usize);

        // Segment using mps
        let mut first = true;
        for chunk in buf.chunks(self.mps as usize) {
            if let Some(mut packet) = self.pool.alloc(pool_id) {
                let len = {
                    let mut w = WriteCursor::new(packet.as_mut());
                    if first {
                        w.write(2 + chunk.len() as u16).map_err(|_| ())?;
                        w.write(self.cid as u16).map_err(|_| ())?;
                        w.write(buf.len() as u16).map_err(|_| ())?;
                        first = false;
                    } else {
                        w.write(chunk.len() as u16).map_err(|_| ())?;
                        w.write(self.cid as u16).map_err(|_| ())?;
                    }
                    w.append(chunk).map_err(|_| ())?;
                    w.len()
                };
                self.tx.send((self.conn, Pdu::new(packet, len))).await;
            } else {
                return Err(());
            }
        }
        Ok(())
    }

    pub async fn receive(&mut self, buf: &mut [u8]) -> Result<usize, ()> {
        let packet = self.rx.receive().await;
        let mut r = ReadCursor::new(&packet.as_ref());
        let remaining: u16 = r.read().map_err(|_| ())?;
        let data = r.remaining();

        let to_copy = data.len().min(buf.len());
        buf[..to_copy].copy_from_slice(&data[..to_copy]);
        let mut pos = to_copy;

        let mut remaining = remaining as usize - data.len();
        // We have some k-frames to reassemble
        while remaining > 0 {
            let packet = self.rx.receive().await;
            let to_copy = packet.len.min(buf.len() - pos);
            if to_copy > 0 {
                buf[pos..pos + to_copy].copy_from_slice(&packet.as_ref()[..to_copy]);
                pos += to_copy;
            }
            remaining -= packet.len;
        }
        // TODO: Send more credits back!
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
    ) -> Result<Self, ()> {
        let connections = &adapter.connections;
        let channels = &adapter.channels;

        let (state, rx) = channels.accept(connection.handle(), psm, MTU as u16).await?;
        let tx = adapter.outbound.sender().into();
        Ok(Self {
            conn: connection.handle(),
            cid: state.cid,
            mps: state.mps,
            pool: adapter.pool,
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
    ) -> Result<Self, ()> {
        // TODO: Use unique signal ID to ensure no collision of signal messages
        let (state, rx) = adapter.channels.accept(connection.handle(), psm, MTU as u16).await?;
        let tx = adapter.outbound.sender().into();

        Ok(Self {
            conn: connection.handle(),
            cid: state.cid,
            mps: state.mps,
            pool: adapter.pool,
            tx,
            rx,
        })
    }
}

use crate::adapter::Adapter;
use crate::codec;
use crate::connection::Connection;
use crate::cursor::{ReadCursor, WriteCursor};
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
    rx: DynamicReceiver<'d, Pdu<'d>>,
    tx: DynamicSender<'d, (ConnHandle, Pdu<'d>)>,
}

impl<'d, const MTU: usize> L2capChannel<'d, MTU> {
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

        let (cid, rx) = channels.accept(connection.handle(), psm, MTU as u16).await?;
        let tx = adapter.outbound.sender().into();
        Ok(Self {
            conn: connection.handle(),
            cid,
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
        let (cid, rx) = adapter.channels.accept(connection.handle(), psm, MTU as u16).await?;
        let tx = adapter.outbound.sender().into();

        Ok(Self {
            conn: connection.handle(),
            cid,
            tx,
            rx,
        })
    }
}

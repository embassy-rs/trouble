use crate::adapter::{self, Adapter};
use crate::channel_manager::ChannelManager;
use crate::codec;
use crate::connection::{ConnEvent, Connection};
use crate::connection_manager::ConnectionManager;
use crate::cursor::{ReadCursor, WriteCursor};
use crate::packet_pool::{DynamicPacketPool, L2CAP_SIGNAL_ID};
use crate::pdu::Pdu;
use crate::types::l2cap::{L2capLeSignal, L2capLeSignalData, LeCreditConnReq};
use bt_hci::data::AclPacket;
use bt_hci::param::ConnHandle;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::channel::{Channel, DynamicReceiver, DynamicSender};

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

pub struct L2capChannel<'d, M: RawMutex> {
    pool: &'d dyn DynamicPacketPool<'d>,
    pool_id: usize,
    cid: u16,
    mgr: &'d ChannelManager<'d, M>,
    rx: DynamicReceiver<'d, Pdu<'d>>,
    tx: DynamicSender<'d, (ConnHandle, Pdu<'d>)>,
}

impl<'d, M: RawMutex> L2capChannel<'d, M> {
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
    ) -> Self {
        let connections = &adapter.connections;
        let channels = &adapter.channels;
        let events = connection.event_receiver();
        loop {
            match events.receive().await {
                ConnEvent::Bound(state) => {
                    return Self {
                        mgr: &adapter.channels,
                        cid: state.cid,
                        pool: adapter.pool,
                        pool_id: state.idx,
                        tx: adapter.outbound.sender().into(),
                        rx: adapter.l2cap_channels[state.idx].receiver().into(),
                    }
                }
                _ => {
                    todo!()
                }
            }
        }
    }

    pub async fn create<const CHANNELS: usize, const L2CAP_TXQ: usize, const L2CAP_RXQ: usize>(
        adapter: &'d Adapter<'d, M, CHANNELS, L2CAP_TXQ, L2CAP_RXQ>,
        connection: &Connection<'d>,
    ) -> Result<Self, ()> {
        // TODO: Use unique signal ID to ensure no collision of signal messages
        let cid = adapter.channels.alloc(0)?;
        // TODO: error
        let mut packet = adapter.pool.alloc(L2CAP_SIGNAL_ID).unwrap();

        let mut w = WriteCursor::new(packet.as_mut());
        let (mut header, mut body) = w.split(4).map_err(|_| ())?;
        body.write(L2capLeSignal::new(
            0,
            L2capLeSignalData::CreditConnReq(LeCreditConnReq {
                psm: 0,
                mps: 10,
                scid: cid,
                mtu: 10,
                credits: 10,
            }),
        ))
        .map_err(|_| ())?;

        // TODO: Move into l2cap packet type
        header.write(body.len() as u16).map_err(|_| ())?;
        header.write(L2CAP_CID_LE_U_SIGNAL).map_err(|_| ())?;
        let len = header.len() + body.len();
        header.finish();
        body.finish();
        w.finish();

        adapter
            .outbound
            .send((connection.handle(), Pdu::new(packet, len)))
            .await;

        let connections = &adapter.connections;
        let channels = &adapter.channels;
        let events = connection.event_receiver();
        loop {
            match events.receive().await {
                ConnEvent::Bound(state) => {
                    return Ok(Self {
                        mgr: &adapter.channels,
                        cid: state.cid,
                        pool: adapter.pool,
                        pool_id: state.idx,
                        tx: adapter.outbound.sender().into(),
                        rx: adapter.l2cap_channels[state.idx].receiver().into(),
                    })
                }
                _ => {
                    todo!()
                }
            }
        }
    }
}

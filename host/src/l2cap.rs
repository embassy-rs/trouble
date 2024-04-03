use core::future::poll_fn;

use crate::adapter::{Adapter, ControlCommand, HciController};
use crate::channel_manager::DynamicChannelManager;
use crate::codec;
use crate::connection::Connection;
use crate::cursor::{ReadCursor, WriteCursor};
use crate::packet_pool::{AllocId, DynamicPacketPool};
use crate::pdu::Pdu;
use crate::{AdapterError, Error};
use bt_hci::cmd::link_control::DisconnectParams;
use bt_hci::controller::Controller;
use bt_hci::data::AclPacket;
use bt_hci::param::ConnHandle;
use bt_hci::param::DisconnectReason;
use core::task::Poll;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::channel::DynamicReceiver;
use embassy_sync::channel::DynamicSender;

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
        w.append(self.payload)?;
        Ok(w.len())
    }
}

pub struct L2capChannel<'a, 'd, T: Controller, const MTU: usize> {
    conn: ConnHandle,
    pool_id: AllocId,
    cid: u16,
    peer_cid: u16,
    mps: usize,
    pool: &'d dyn DynamicPacketPool<'d>,
    manager: &'a dyn DynamicChannelManager<'d>,
    rx: DynamicReceiver<'a, Option<Pdu<'d>>>,
    control: DynamicSender<'a, ControlCommand>,
    tx: HciController<'a, T>,
}

impl<'a, 'd, T: Controller, const MTU: usize> Clone for L2capChannel<'a, 'd, T, MTU> {
    fn clone(&self) -> Self {
        Self {
            conn: self.conn,
            pool_id: self.pool_id,
            cid: self.cid,
            peer_cid: self.peer_cid,
            mps: self.mps,
            pool: self.pool,
            manager: self.manager,
            rx: self.rx,
            tx: HciController {
                controller: self.tx.controller,
                permits: self.tx.permits,
            },
            control: self.control,
        }
    }
}

impl<'a, 'd, T: Controller, const MTU: usize> L2capChannel<'a, 'd, T, MTU> {
    fn encode(&self, data: &[u8], header: Option<u16>) -> Result<Pdu<'d>, Error> {
        if let Some(mut packet) = self.pool.alloc(self.pool_id) {
            let mut w = WriteCursor::new(packet.as_mut());
            if header.is_some() {
                w.write(2 + data.len() as u16)?;
            } else {
                w.write(data.len() as u16)?;
            }
            w.write(self.peer_cid)?;

            if let Some(len) = header {
                w.write(len)?;
            }

            w.append(data)?;
            let len = w.len();
            let pdu = Pdu::new(packet, len);
            Ok(pdu)
        } else {
            Err(Error::OutOfMemory)
        }
    }

    pub async fn send(&mut self, buf: &[u8]) -> Result<(), AdapterError<T::Error>> {
        // The number of packets we'll need to send for this payload
        let n_packets = 1 + (buf.len().saturating_sub(self.mps - 2)).div_ceil(self.mps);

        // TODO: We could potentially make this more graceful by sending as much as we can, and wait
        // for pool to get the available packets back, which would require some poll/async behavior
        // support for the pool.
        if self.pool.available(self.pool_id) < n_packets {
            return Err(Error::OutOfMemory.into());
        }

        poll_fn(|cx| self.manager.poll_request_to_send(self.cid, n_packets, Some(cx))).await?;

        // Segment using mps
        let (first, remaining) = buf.split_at(buf.len().min(self.mps - 2));

        let pdu = self.encode(first, Some(buf.len() as u16))?;
        self.tx.send(self.conn, pdu.as_ref()).await?;

        let chunks = remaining.chunks(self.mps);
        let num_chunks = chunks.len();

        for (i, chunk) in chunks.enumerate() {
            let pdu = self.encode(chunk, None)?;
            self.tx.send(self.conn, pdu.as_ref()).await?;
        }

        Ok(())
    }

    pub fn try_send(&mut self, buf: &[u8]) -> Result<(), AdapterError<T::Error>> {
        // The number of packets we'll need to send for this payload
        let n_packets = 1 + (buf.len().saturating_sub(self.mps - 2)).div_ceil(self.mps);

        // TODO: We could potentially make this more graceful by sending as much as we can, and wait
        // for pool to get the available packets back, which would require some poll/async behavior
        // support for the pool.
        if self.pool.available(self.pool_id) < n_packets {
            return Err(Error::OutOfMemory.into());
        }

        match self.manager.poll_request_to_send(self.cid, n_packets, None) {
            Poll::Ready(res) => res?,
            Poll::Pending => return Err(Error::Busy.into()),
        }

        // Segment using mps
        let (first, remaining) = buf.split_at(buf.len().min(self.mps - 2));

        let pdu = self.encode(first, Some(buf.len() as u16))?;
        self.tx.try_send(self.conn, pdu.as_ref())?;

        let chunks = remaining.chunks(self.mps);
        let num_chunks = chunks.len();

        for (i, chunk) in chunks.enumerate() {
            let pdu = self.encode(chunk, None)?;
            self.tx.try_send(self.conn, pdu.as_ref())?;
        }

        Ok(())
    }

    async fn receive_pdu(&mut self) -> Result<Pdu<'d>, AdapterError<T::Error>> {
        match self.rx.receive().await {
            Some(pdu) => Ok(pdu),
            None => {
                self.manager.confirm_disconnected(self.cid)?;
                Err(Error::ChannelClosed.into())
            }
        }
    }

    pub async fn receive(&mut self, buf: &mut [u8]) -> Result<usize, AdapterError<T::Error>> {
        let mut n_received = 1;
        let packet = self.receive_pdu().await?;
        let len = packet.len;

        let mut r = ReadCursor::new(packet.as_ref());
        let remaining: u16 = r.read()?;
        // info!("Total expected: {}", remaining);

        let data = r.remaining();
        let to_copy = data.len().min(buf.len());
        buf[..to_copy].copy_from_slice(&data[..to_copy]);
        let mut pos = to_copy;
        // info!("Received {} bytes so far", pos);

        let mut remaining = remaining as usize - data.len();
        //info!(
        //    "Total size of PDU is {}, read buffer size is {} remaining; {}",
        //    len,
        //    buf.len(),
        //    remaining
        //);
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

        let (handle, response) = self.manager.confirm_received(self.cid, n_received)?;
        self.tx.signal(handle, response).await?;

        // info!("Total reserved {} bytes", pos);
        Ok(pos)
    }

    pub async fn accept<
        M: RawMutex,
        const CONNS: usize,
        const CHANNELS: usize,
        const L2CAP_TXQ: usize,
        const L2CAP_RXQ: usize,
    >(
        adapter: &'a Adapter<'d, M, T, CONNS, CHANNELS, L2CAP_TXQ, L2CAP_RXQ>,
        connection: &Connection<'a>,
        psm: u16,
    ) -> Result<L2capChannel<'a, 'd, T, MTU>, AdapterError<T::Error>> {
        let connections = &adapter.connections;
        let channels = &adapter.channels;

        let (state, rx) = channels
            .accept(connection.handle(), psm, MTU as u16, &adapter.hci())
            .await?;

        Ok(Self {
            conn: connection.handle(),
            cid: state.cid,
            peer_cid: state.peer_cid,
            mps: state.mps as usize,
            pool: adapter.pool,
            pool_id: state.pool_id,
            manager: &adapter.channels,
            tx: adapter.hci(),
            control: adapter.control.sender().into(),
            rx,
        })
    }

    pub fn disconnect(&self, close_connection: bool) -> Result<(), AdapterError<T::Error>> {
        self.manager.confirm_disconnected(self.cid)?;
        if close_connection {
            self.control
                .try_send(ControlCommand::Disconnect(DisconnectParams {
                    handle: self.conn,
                    reason: DisconnectReason::RemoteUserTerminatedConn,
                }))
                .map_err(|_| Error::Busy)?;
        }
        Ok(())
    }

    pub async fn create<
        M: RawMutex,
        const CONNS: usize,
        const CHANNELS: usize,
        const L2CAP_TXQ: usize,
        const L2CAP_RXQ: usize,
    >(
        adapter: &'a Adapter<'d, M, T, CONNS, CHANNELS, L2CAP_TXQ, L2CAP_RXQ>,
        connection: &Connection<'a>,
        psm: u16,
    ) -> Result<Self, AdapterError<T::Error>>
where {
        // TODO: Use unique signal ID to ensure no collision of signal messages
        //
        let (state, rx) = adapter
            .channels
            .create(connection.handle(), psm, MTU as u16, &adapter.hci())
            .await?;

        Ok(Self {
            conn: connection.handle(),
            pool_id: state.pool_id,
            cid: state.cid,
            peer_cid: state.peer_cid,
            mps: state.mps as usize,
            pool: adapter.pool,
            manager: &adapter.channels,
            tx: adapter.hci(),
            control: adapter.control.sender().into(),
            rx,
        })
    }
}

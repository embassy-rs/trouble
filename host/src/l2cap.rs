use core::cell::RefCell;
use core::future::poll_fn;

use crate::adapter::{Adapter, ControlCommand, HciController};
use crate::channel_manager::DynamicChannelManager;
use crate::codec;
use crate::connection::Connection;
use crate::cursor::{ReadCursor, WriteCursor};
use crate::packet_pool::{AllocId, DynamicPacketPool, Packet};
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

pub use crate::channel_manager::CreditFlowPolicy;

pub(crate) const L2CAP_CID_ATT: u16 = 0x0004;
pub(crate) const L2CAP_CID_LE_U_SIGNAL: u16 = 0x0005;
pub(crate) const L2CAP_CID_DYN_START: u16 = 0x0040;

pub struct AssembledPacket<'d> {
    packet: Packet<'d>,
    written: usize,
}

impl<'d> AssembledPacket<'d> {
    pub fn new(packet: Packet<'d>, initial: usize) -> Self {
        Self {
            packet,
            written: initial,
        }
    }

    pub fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.written + data.len() > self.packet.len() {
            return Err(Error::InsufficientSpace);
        }
        self.packet.as_mut()[self.written..self.written + data.len()].copy_from_slice(data);
        self.written += data.len();
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.written
    }

    pub fn finalize(self, header: L2capHeader) -> Result<(L2capHeader, Packet<'d>), Error> {
        if header.length as usize != self.written {
            return Err(Error::InvalidValue);
        }
        Ok((header, self.packet))
    }
}

// Handles reassembling of packets
pub struct PacketReassembly<'d, const CONNS: usize> {
    handles: RefCell<[Option<(ConnHandle, L2capHeader, AssembledPacket<'d>)>; CONNS]>,
}

impl<'d, const CONNS: usize> PacketReassembly<'d, CONNS> {
    const EMPTY: Option<(ConnHandle, L2capHeader, AssembledPacket<'d>)> = None;
    pub fn new() -> Self {
        Self {
            handles: RefCell::new([Self::EMPTY; CONNS]),
        }
    }

    /// Initializes a reassembly for a given connection
    ///
    /// Returns InvalidState if there is already an ongoing reassembly for this connection
    /// Returns InsufficientSpace if there is no space for this reassembly
    pub fn init(&self, handle: ConnHandle, header: L2capHeader, p: Packet<'d>, initial: usize) -> Result<(), Error> {
        let mut state = self.handles.borrow_mut();

        // Sanity check
        for entry in state.iter() {
            if let Some(entry) = entry {
                if entry.0 == handle {
                    return Err(Error::InvalidState);
                }
            }
        }

        // Sanity check
        for entry in state.iter_mut() {
            if entry.is_none() {
                entry.replace((handle, header, AssembledPacket::new(p, initial)));
                return Ok(());
            }
        }
        Err(Error::InsufficientSpace)
    }

    /// Updates any in progress packet assembly for the connection
    ///
    /// If the reassembly is complete, the l2cap header + packet is returned.
    pub fn update(&self, handle: ConnHandle, data: &[u8]) -> Result<Option<(L2capHeader, Packet<'d>)>, Error> {
        let mut state = self.handles.borrow_mut();

        for entry in state.iter_mut() {
            match entry {
                Some((conn, header, packet)) if *conn == handle => {
                    let (conn, header, mut packet) = entry.take().unwrap();
                    packet.write(data)?;
                    if packet.len() == header.length as usize {
                        return Ok(Some(packet.finalize(header)?));
                    } else {
                        entry.replace((conn, header, packet));
                        return Ok(None);
                    }
                }
                _ => {}
            }
        }
        Err(Error::NotFound)
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub struct L2capHeader {
    pub length: u16,
    pub channel: u16,
}

impl L2capHeader {
    pub fn decode<'m>(packet: &AclPacket<'m>) -> Result<(L2capHeader, &'m [u8]), codec::Error> {
        let data = packet.data();
        let mut r = ReadCursor::new(data);
        let length: u16 = r.read()?;
        let channel: u16 = r.read()?;
        Ok((Self { length, channel }, &packet.data()[4..]))
    }
}

pub struct L2capChannel<'a, 'd, T: Controller, const L2CAP_MTU: usize = 27> {
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

impl<'a, 'd, T: Controller, const L2CAP_MTU: usize> Clone for L2capChannel<'a, 'd, T, L2CAP_MTU> {
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

impl<'a, 'd, T: Controller, const L2CAP_MTU: usize> L2capChannel<'a, 'd, T, L2CAP_MTU> {
    fn encode(&self, data: &[u8], packet: &mut [u8], header: Option<u16>) -> Result<usize, Error> {
        let mut w = WriteCursor::new(packet);
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
        Ok(w.len())
    }

    pub async fn send(&mut self, buf: &[u8]) -> Result<(), AdapterError<T::Error>> {
        let mut p_buf = [0u8; L2CAP_MTU];
        assert!(p_buf.len() >= self.mps + 4);
        // The number of packets we'll need to send for this payload
        let n_packets = 1 + (buf.len().saturating_sub(self.mps - 2)).div_ceil(self.mps);
        // info!("Sending data of len {} into {} packets", buf.len(), n_packets);

        poll_fn(|cx| self.manager.poll_request_to_send(self.cid, n_packets, Some(cx))).await?;

        // Segment using mps
        let (first, remaining) = buf.split_at(buf.len().min(self.mps - 2));

        let len = self.encode(first, &mut p_buf[..], Some(buf.len() as u16))?;
        self.tx.send(self.conn, &p_buf[..len]).await?;

        let chunks = remaining.chunks(self.mps);
        let num_chunks = chunks.len();

        for (i, chunk) in chunks.enumerate() {
            let len = self.encode(chunk, &mut p_buf[..], None)?;
            self.tx.send(self.conn, &p_buf[..len]).await?;
        }

        Ok(())
    }

    pub fn try_send(&mut self, buf: &[u8]) -> Result<(), AdapterError<T::Error>> {
        let mut p_buf = [0u8; L2CAP_MTU];
        assert!(p_buf.len() >= self.mps + 4);

        // The number of packets we'll need to send for this payload
        let n_packets = 1 + (buf.len().saturating_sub(self.mps - 2)).div_ceil(self.mps);
        //info!("Sending data of len {} into {} packets", buf.len(), n_packets);

        match self.manager.poll_request_to_send(self.cid, n_packets, None) {
            Poll::Ready(res) => res?,
            Poll::Pending => return Err(Error::Busy.into()),
        }

        // Segment using mps
        let (first, remaining) = buf.split_at(buf.len().min(self.mps - 2));

        let len = self.encode(first, &mut p_buf[..], Some(buf.len() as u16))?;
        self.tx.try_send(self.conn, &p_buf[..len])?;

        let chunks = remaining.chunks(self.mps);
        let num_chunks = chunks.len();

        for (i, chunk) in chunks.enumerate() {
            let len = self.encode(chunk, &mut p_buf[..], None)?;
            self.tx.try_send(self.conn, &p_buf[..len])?;
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

        drop(packet);
        self.flow_control().await?;
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
            drop(packet);
            self.flow_control().await?;
        }

        // info!("Total reserved {} bytes", pos);
        Ok(pos)
    }

    async fn flow_control(&mut self) -> Result<(), AdapterError<T::Error>> {
        if let Some((handle, response)) = self.manager.flow_control(self.cid)? {
            self.tx.signal(handle, response).await?;
        }
        Ok(())
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
        psm: &[u16],
        mtu: u16,
        flow_policy: CreditFlowPolicy,
    ) -> Result<L2capChannel<'a, 'd, T, L2CAP_MTU>, AdapterError<T::Error>> {
        let connections = &adapter.connections;
        let channels = &adapter.channels;

        let (state, rx) = channels
            .accept(connection.handle(), psm, mtu, flow_policy, &adapter.hci())
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
        self.manager.disconnect(self.cid)?;
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
        mtu: u16,
        flow_policy: CreditFlowPolicy,
    ) -> Result<Self, AdapterError<T::Error>>
where {
        let (state, rx) = adapter
            .channels
            .create(connection.handle(), psm, mtu, flow_policy, &adapter.hci())
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

use core::cell::RefCell;

use crate::adapter::Adapter;
pub use crate::channel_manager::CreditFlowPolicy;
use crate::codec;
use crate::connection::Connection;
use crate::cursor::ReadCursor;
use crate::packet_pool::Packet;
use crate::{AdapterError, Error};
use bt_hci::cmd::link_control::Disconnect;
use bt_hci::controller::{Controller, ControllerCmdSync};
use bt_hci::data::AclPacket;
use bt_hci::param::ConnHandle;
use bt_hci::param::DisconnectReason;
use embassy_sync::blocking_mutex::raw::RawMutex;

pub(crate) const L2CAP_CID_ATT: u16 = 0x0004;
pub(crate) const L2CAP_CID_LE_U_SIGNAL: u16 = 0x0005;
pub(crate) const L2CAP_CID_DYN_START: u16 = 0x0040;

pub struct AssembledPacket<'d> {
    packet: Packet<'d>,
    written: usize,
}

impl<'d> AssembledPacket<'d> {
    pub(crate) fn new(packet: Packet<'d>, initial: usize) -> Self {
        Self {
            packet,
            written: initial,
        }
    }

    pub(crate) fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.written + data.len() > self.packet.len() {
            return Err(Error::InsufficientSpace);
        }
        self.packet.as_mut()[self.written..self.written + data.len()].copy_from_slice(data);
        self.written += data.len();
        Ok(())
    }

    pub(crate) fn len(&self) -> usize {
        self.written
    }

    pub(crate) fn finalize(self, header: L2capHeader) -> Result<(L2capHeader, Packet<'d>), Error> {
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
impl<'d, const CONNS: usize> Default for PacketReassembly<'d, CONNS> {
    fn default() -> Self {
        Self::new()
    }
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
        for entry in state.iter().flatten() {
            if entry.0 == handle {
                return Err(Error::InvalidState);
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

#[derive(Clone)]
pub struct L2capChannel {
    handle: ConnHandle,
    cid: u16,
}

impl L2capChannel {
    pub async fn send<
        M: RawMutex,
        T: Controller,
        const CONNS: usize,
        const CHANNELS: usize,
        const L2CAP_MTU: usize,
        const L2CAP_TXQ: usize,
        const L2CAP_RXQ: usize,
    >(
        &mut self,
        adapter: &Adapter<'_, M, T, CONNS, CHANNELS, L2CAP_MTU, L2CAP_TXQ, L2CAP_RXQ>,
        buf: &[u8],
    ) -> Result<(), AdapterError<T::Error>> {
        adapter.channels.send(self.cid, buf, &adapter.hci()).await
    }

    pub fn try_send<
        M: RawMutex,
        T: Controller,
        const CONNS: usize,
        const CHANNELS: usize,
        const L2CAP_MTU: usize,
        const L2CAP_TXQ: usize,
        const L2CAP_RXQ: usize,
    >(
        &mut self,
        adapter: &Adapter<'_, M, T, CONNS, CHANNELS, L2CAP_MTU, L2CAP_TXQ, L2CAP_RXQ>,
        buf: &[u8],
    ) -> Result<(), AdapterError<T::Error>> {
        adapter.channels.try_send(self.cid, buf, &adapter.hci())
    }

    pub async fn receive<
        M: RawMutex,
        T: Controller,
        const CONNS: usize,
        const CHANNELS: usize,
        const L2CAP_MTU: usize,
        const L2CAP_TXQ: usize,
        const L2CAP_RXQ: usize,
    >(
        &mut self,
        adapter: &Adapter<'_, M, T, CONNS, CHANNELS, L2CAP_MTU, L2CAP_TXQ, L2CAP_RXQ>,
        buf: &mut [u8],
    ) -> Result<usize, AdapterError<T::Error>> {
        adapter.channels.receive(self.cid, buf, &adapter.hci()).await
    }

    pub async fn accept<
        M: RawMutex,
        T: Controller,
        const CONNS: usize,
        const CHANNELS: usize,
        const L2CAP_MTU: usize,
        const L2CAP_TXQ: usize,
        const L2CAP_RXQ: usize,
    >(
        adapter: &Adapter<'_, M, T, CONNS, CHANNELS, L2CAP_MTU, L2CAP_TXQ, L2CAP_RXQ>,
        connection: &Connection,
        psm: &[u16],
        mtu: u16,
        flow_policy: CreditFlowPolicy,
    ) -> Result<L2capChannel, AdapterError<T::Error>> {
        let handle = connection.handle();
        let cid = adapter
            .channels
            .accept(handle, psm, mtu, flow_policy, &adapter.hci())
            .await?;

        Ok(Self { cid, handle })
    }

    pub fn disconnect<
        M: RawMutex,
        T: Controller + ControllerCmdSync<Disconnect>,
        const CONNS: usize,
        const CHANNELS: usize,
        const L2CAP_MTU: usize,
        const L2CAP_TXQ: usize,
        const L2CAP_RXQ: usize,
    >(
        &mut self,
        adapter: &Adapter<'_, M, T, CONNS, CHANNELS, L2CAP_MTU, L2CAP_TXQ, L2CAP_RXQ>,
        close_connection: bool,
    ) -> Result<(), AdapterError<T::Error>> {
        adapter.channels.disconnect(self.cid)?;
        if close_connection {
            adapter.try_command(Disconnect::new(self.handle, DisconnectReason::RemoteUserTerminatedConn))?;
        }
        Ok(())
    }

    pub async fn create<
        M: RawMutex,
        T: Controller,
        const CONNS: usize,
        const CHANNELS: usize,
        const L2CAP_MTU: usize,
        const L2CAP_TXQ: usize,
        const L2CAP_RXQ: usize,
    >(
        adapter: &Adapter<'_, M, T, CONNS, CHANNELS, L2CAP_MTU, L2CAP_TXQ, L2CAP_RXQ>,
        connection: &Connection,
        psm: u16,
        mtu: u16,
        flow_policy: CreditFlowPolicy,
    ) -> Result<Self, AdapterError<T::Error>>
where {
        let handle = connection.handle();
        let cid = adapter
            .channels
            .create(connection.handle(), psm, mtu, flow_policy, &adapter.hci())
            .await?;

        Ok(Self { handle, cid })
    }
}

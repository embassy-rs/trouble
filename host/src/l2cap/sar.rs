use core::cell::RefCell;

use bt_hci::param::ConnHandle;

use crate::packet_pool::Packet;
use crate::types::l2cap::L2capHeader;
use crate::Error;

pub(crate) struct AssembledPacket<'d> {
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

use core::cell::RefCell;

use bt_hci::param::ConnHandle;

use crate::packet_pool::Packet;
use crate::types::l2cap::L2capHeader;
use crate::Error;

pub(crate) struct AssembledPacket {
    packet: Packet,
    written: usize,
}

impl AssembledPacket {
    pub(crate) fn new(packet: Packet, initial: usize) -> Self {
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

    pub(crate) fn finalize(self, header: L2capHeader) -> Result<(L2capHeader, Packet), Error> {
        if header.length as usize != self.written {
            return Err(Error::InvalidValue);
        }
        Ok((header, self.packet))
    }
}

pub(crate) type SarType = Option<(ConnHandle, L2capHeader, AssembledPacket)>;
pub(crate) const EMPTY_SAR: Option<(ConnHandle, L2capHeader, AssembledPacket)> = None;

// Handles reassembling of packets
pub struct PacketReassembly<'d> {
    handles: RefCell<&'d mut [SarType]>,
}
impl<'d> PacketReassembly<'d> {
    pub fn new(handles: &'d mut [Option<(ConnHandle, L2capHeader, AssembledPacket)>]) -> Self {
        Self {
            handles: RefCell::new(handles), //[Self::EMPTY; CONNS]),
        }
    }

    /// Initializes a reassembly for a given connection
    ///
    /// Returns InvalidState if there is already an ongoing reassembly for this connection
    /// Returns InsufficientSpace if there is no space for this reassembly
    pub fn init(&self, handle: ConnHandle, header: L2capHeader, p: Packet, initial: usize) -> Result<(), Error> {
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
    pub fn update(&self, handle: ConnHandle, data: &[u8]) -> Result<Option<(L2capHeader, Packet)>, Error> {
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

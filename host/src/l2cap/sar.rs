use bt_hci::param::ConnHandle;

use crate::packet_pool::Packet;
use crate::pdu::Pdu;
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

    pub(crate) fn finalize(self, length: usize) -> Result<Pdu, Error> {
        if length != self.written {
            return Err(Error::InvalidValue);
        }
        Ok(Pdu::new(self.packet, length))
    }
}

pub(crate) type SarType = Option<(ConnHandle, L2capHeader, AssembledPacket)>;

// Handles reassembling of a packet.
pub(crate) struct PacketReassembly {
    state: Option<State>,
}

pub(crate) struct State {
    // L2cap header of this reassembly
    header: L2capHeader,
    // Assembled length so far
    packet: AssembledPacket,
}

impl PacketReassembly {
    pub const fn new() -> Self {
        Self { state: None }
    }

    /// Initializes a reassembly.
    ///
    /// Returns InvalidState if there is already an ongoing reassembly for this connection
    /// Returns InsufficientSpace if there is no space for this reassembly
    pub fn init(&mut self, header: L2capHeader, p: Packet, initial: usize) -> Result<(), Error> {
        if self.state.is_some() {
            return Err(Error::InvalidState);
        }
        self.state.replace(State {
            header,
            packet: AssembledPacket::new(p, initial),
        });
        Ok(())
    }

    /// Deletes any reassemblies for the disconnected handle.
    pub fn disconnected(&mut self) {
        self.state.take();
    }

    /// Updates any in progress packet assembly for the connection
    ///
    /// If the reassembly is complete, the complete PDU is returned.
    pub fn update(&mut self, data: &[u8]) -> Result<Option<(L2capHeader, Pdu)>, Error> {
        if let Some(mut state) = self.state.take() {
            state.packet.write(data)?;
            if state.packet.len() == state.header.length as usize {
                let length = state.header.length as usize;
                Ok(Some((state.header, state.packet.finalize(length)?)))
            } else {
                self.state.replace(state);
                Ok(None)
            }
        } else {
            Err(Error::NotFound)
        }
    }
}

use crate::pdu::Pdu;
use crate::types::l2cap::L2capHeader;
use crate::{Error, Packet};

pub(crate) struct AssembledPacket<P> {
    packet: P,
    written: usize,
}

impl<P> AssembledPacket<P> {
    pub(crate) fn new(packet: P, initial: usize) -> Self {
        Self {
            packet,
            written: initial,
        }
    }

    pub(crate) fn write(&mut self, data: &[u8]) -> Result<(), Error>
    where
        P: Packet,
    {
        if self.written + data.len() > self.packet.as_ref().len() {
            return Err(Error::InsufficientSpace);
        }
        self.packet.as_mut()[self.written..self.written + data.len()].copy_from_slice(data);
        self.written += data.len();
        Ok(())
    }

    pub(crate) fn len(&self) -> usize {
        self.written
    }

    pub(crate) fn finalize(self, length: usize) -> Result<Pdu<P>, Error> {
        if length != self.written {
            return Err(Error::InvalidValue);
        }
        Ok(Pdu::new(self.packet, length))
    }
}

// Handles reassembling of a packet.
pub(crate) struct PacketReassembly<P> {
    state: Option<State<P>>,
}

pub(crate) struct State<P> {
    // L2cap header of this reassembly
    header: L2capHeader,
    // Assembled length so far
    packet: AssembledPacket<P>,
}

impl<P> PacketReassembly<P> {
    pub const fn new() -> Self {
        Self { state: None }
    }

    /// Initializes a reassembly.
    ///
    /// Returns InvalidState if there is already an ongoing reassembly for this connection
    /// Returns InsufficientSpace if there is no space for this reassembly
    pub fn init(&mut self, header: L2capHeader, p: P, initial: usize) -> Result<(), Error> {
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
        let _ = self.state.take();
    }

    /// Updates any in progress packet assembly for the connection
    ///
    /// If the reassembly is complete, the complete PDU is returned.
    pub fn update(&mut self, data: &[u8]) -> Result<Option<(L2capHeader, Pdu<P>)>, Error>
    where
        P: Packet,
    {
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

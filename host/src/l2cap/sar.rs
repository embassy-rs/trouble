use crate::pdu::Pdu;
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
            return Err(Error::FailedToFinalize {
                expected: length,
                actual: self.written,
            });
        }
        Ok(Pdu::new(self.packet, length))
    }
}

// Handles reassembling of a HCI packet.
pub(crate) struct PacketReassembly<P> {
    state: Option<State<P>>,
}

pub(crate) struct State<P> {
    state: AssemblyState,
    packet: AssembledPacket<P>,
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct AssemblyState {
    // Target channel of current assembly.
    pub channel: u16,
    // Target length of the assembly.
    pub length: u16,
}

impl<P> PacketReassembly<P> {
    pub const fn new() -> Self {
        Self { state: None }
    }

    /// Initializes a reassembly.
    ///
    /// Returns InvalidState if there is already an ongoing reassembly for this connection
    /// Returns InsufficientSpace if there is no space for this reassembly
    pub fn init(&mut self, channel: u16, length: u16, p: P) -> Result<(), Error> {
        self.init_with_written(channel, length, p, 0)
    }

    /// Initializes a reassembly where data is already written.
    pub fn init_with_written(&mut self, channel: u16, length: u16, p: P, written: usize) -> Result<(), Error> {
        if self.state.is_some() {
            return Err(Error::InvalidState);
        }
        self.state.replace(State {
            state: AssemblyState { channel, length },
            packet: AssembledPacket::new(p, written),
        });
        //info!(
        //    "[host] initial reassembly on {} starting at {}, target {})",
        //    channel, written, length
        //);
        Ok(())
    }

    /// Deletes any reassemblies for the disconnected handle.
    pub fn disconnected(&mut self) {
        let _ = self.state.take();
    }

    /// Returns whether or not there is a reassembly in progress.
    pub fn in_progress(&self) -> bool {
        self.state.is_some()
    }

    /// Updates any in progress packet assembly for the connection
    ///
    /// If the reassembly is complete, the complete PDU is returned.
    pub fn update(&mut self, data: &[u8]) -> Result<Option<(AssemblyState, Pdu<P>)>, Error>
    where
        P: Packet,
    {
        if let Some(mut state) = self.state.take() {
            state.packet.write(data)?;
            let target = state.state.length as usize;
            //info!(
            //    "[host] update reassembly on {} written {}, target {})",
            //    state.state.channel, state.packet.written, target
            //);
            if state.packet.len() == target {
                Ok(Some((state.state, state.packet.finalize(target)?)))
            } else {
                self.state.replace(state);
                Ok(None)
            }
        } else {
            Err(Error::NotFound)
        }
    }
}

use core::task::{Context, Poll, Waker};

pub use embedded_io_async::ErrorKind;

///
/// This trait allows generic code to do limited inspecting of errors,
/// to react differently to different kinds.
pub trait Error: core::fmt::Debug {
    /// Get the kind of this error.
    fn kind(&self) -> ErrorKind;
}

impl Error for core::convert::Infallible {
    fn kind(&self) -> ErrorKind {
        match *self {}
    }
}

impl Error for ErrorKind {
    fn kind(&self) -> ErrorKind {
        *self
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum HciMessageType {
    Command = 0x01,
    Data = 0x02,
    Event = 0x04,
}

/// Interface to a driver for a HCI adapter
pub trait HciDriver {
    type Error: Error;

    // Register interest in available reads.
    fn register_read_waker(&mut self, waker: &Waker);

    /// Attempt reading a HCI packet. If a packet is pending, put it into buf.
    fn try_read(&mut self, buf: &mut [u8]) -> Result<Option<HciMessageType>, Self::Error>;

    /// Write the provided data as a single HCI packet.
    fn try_write(&mut self, kind: HciMessageType, data: &[u8]) -> Result<usize, Self::Error>;

    // Register interest in available writes.
    fn register_write_waker(&mut self, waker: &Waker);
}

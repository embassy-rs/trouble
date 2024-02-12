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

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl Error for std::io::Error {
    fn kind(&self) -> ErrorKind {
        self.kind().into()
    }
}

#[repr(u8)]
pub enum HciMessageType {
    Command = 0x01,
    Data = 0x02,
    Event = 0x04,
}

/// Interface to a driver for a HCI adapter
pub trait HciDriver {
    type Error: Error;

    /// Reads an entire HCI packet into the provided buffer.
    ///
    /// If successful, returns the message type of the received HCI packet.
    async fn read(&mut self, buf: &mut [u8]) -> Result<HciMessageType, Self::Error>;

    /// Write the provided data as a single HCI packet.
    async fn write(&mut self, kind: HciMessageType, data: &[u8]) -> Result<(), Self::Error>;
}

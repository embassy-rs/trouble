//! BTP error types.

use core::fmt;

use super::types::{Opcode, ServiceId};

/// Errors that can occur in the BTP protocol handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Transport I/O error.
    Transport(embedded_io::ErrorKind),
    /// Invalid packet format.
    InvalidPacket,
    /// Packet data too short for expected content.
    BufferTooShort,
    /// Unknown service ID.
    UnknownService(ServiceId),
    /// Unknown command opcode for the given service.
    UnknownCommand {
        /// The service ID.
        service: ServiceId,
        /// The opcode.
        opcode: Opcode,
    },
    /// Invalid controller index.
    InvalidIndex,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Transport(kind) => write!(f, "transport error: {:?}", kind),
            Error::InvalidPacket => write!(f, "invalid packet format"),
            Error::BufferTooShort => write!(f, "buffer too short"),
            Error::UnknownService(id) => write!(f, "unknown service: 0x{:02x}", id.0),
            Error::UnknownCommand { service, opcode } => {
                write!(
                    f,
                    "unknown command: service=0x{:02x} opcode=0x{:02x}",
                    service.0, opcode.0
                )
            }
            Error::InvalidIndex => write!(f, "invalid controller index"),
        }
    }
}

impl<E: embedded_io::Error> From<E> for Error {
    fn from(value: E) -> Self {
        Error::Transport(value.kind())
    }
}

/// Convert a ReadExactError to Error.
///
/// This is provided as a function rather than a From impl due to potential
/// forward-compatibility issues with trait implementations.
pub fn from_read_exact_error<E: embedded_io::Error>(e: embedded_io::ReadExactError<E>) -> Error {
    match e {
        embedded_io::ReadExactError::UnexpectedEof => Error::Transport(embedded_io::ErrorKind::Other),
        embedded_io::ReadExactError::Other(e) => Error::Transport(e.kind()),
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Error {
    fn format(&self, f: defmt::Formatter) {
        match self {
            Error::Transport(kind) => {
                defmt::write!(f, "transport error: {:?}", kind)
            }
            Error::InvalidPacket => defmt::write!(f, "invalid packet format"),
            Error::BufferTooShort => defmt::write!(f, "buffer too short"),
            Error::UnknownService(id) => defmt::write!(f, "unknown service: {=u8:#04x}", id.0),
            Error::UnknownCommand { service, opcode } => {
                defmt::write!(
                    f,
                    "unknown command: service={=u8:#04x} opcode={=u8:#04x}",
                    service.0,
                    opcode.0
                )
            }
            Error::InvalidIndex => defmt::write!(f, "invalid controller index"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

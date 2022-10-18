use core::fmt;

/// Errors returned by the BLE stack.
#[derive(Debug, PartialEq, Eq, defmt::Format)]
#[non_exhaustive]
pub enum Error {
    /// Packet specified an invalid length value or was too short.
    ///
    /// This indicates a protocol violation, so the connection should
    /// considered lost (if one is currently established).
    InvalidLength,

    /// Invalid value supplied for field.
    InvalidValue,

    /// Unexpectedly reached EOF while reading or writing data.
    ///
    /// This is returned when the application tries to fit too much data into a
    /// PDU or other fixed-size buffer, and also when reaching EOF prematurely
    /// while reading data from a buffer.
    Eof,

    /// Parsing didn't consume the entire buffer.
    IncompleteParse,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::InvalidLength => "invalid length value specified",
            Error::InvalidValue => "invalid value for field",
            Error::Eof => "end of buffer",
            Error::IncompleteParse => "excess data in buffer",
        })
    }
}

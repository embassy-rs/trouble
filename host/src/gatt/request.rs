//! GATT request types for callback-based characteristic handlers

/// Request passed to characteristic handler methods
///
/// This enum represents the different types of requests that can be made
/// to a GATT characteristic. Handler methods pattern match on this to
/// implement their read/write logic.
///
/// # Example
///
/// ```rust,ignore
/// #[characteristic(uuid = characteristic::BATTERY_LEVEL, read, notify)]
/// async fn level(&self, req: GattRequest) -> Result<(), AttErrorCode> {
///     match req {
///         GattRequest::Read { offset, output } => {
///             if offset > 0 {
///                 return Ok(());
///             }
///             output[0] = self.battery_level;
///             Ok(())
///         }
///         GattRequest::Write { .. } => {
///             Err(AttErrorCode::WRITE_NOT_PERMITTED)
///         }
///     }
/// }
/// ```
pub enum GattRequest<'a> {
    /// Read request
    ///
    /// The handler should write data into the `output` buffer starting
    /// at the given `offset`. The number of bytes written will be determined
    /// by how much of the output buffer is filled.
    Read {
        /// Offset within the characteristic value
        offset: u16,
        /// Output buffer to write data into
        output: &'a mut [u8],
    },

    /// Write request
    ///
    /// The handler should process the data in `input`, writing it to
    /// the characteristic value at the given `offset`.
    Write {
        /// Offset within the characteristic value
        offset: u16,
        /// Input data to write
        input: &'a [u8],
    },
}

/// Response builder for read requests
///
/// This provides a more ergonomic API for responding to read requests
pub struct ReadResponse<'a> {
    output: &'a mut [u8],
    offset: u16,
}

impl<'a> ReadResponse<'a> {
    /// Create a new read response
    pub fn new(offset: u16, output: &'a mut [u8]) -> Self {
        Self { output, offset }
    }

    /// Write data to the response, handling offset automatically
    ///
    /// Returns the number of bytes written
    pub fn write(&mut self, data: &[u8]) -> usize {
        let offset = self.offset as usize;
        if offset >= data.len() {
            return 0;
        }
        let len = (data.len() - offset).min(self.output.len());
        self.output[..len].copy_from_slice(&data[offset..offset + len]);
        len
    }

    /// Write a single byte value
    pub fn write_u8(&mut self, value: u8) -> usize {
        self.write(&[value])
    }

    /// Write a u16 value in little-endian format
    pub fn write_u16(&mut self, value: u16) -> usize {
        self.write(&value.to_le_bytes())
    }

    /// Write a u32 value in little-endian format
    pub fn write_u32(&mut self, value: u32) -> usize {
        self.write(&value.to_le_bytes())
    }

    /// Write a string (UTF-8 bytes)
    pub fn write_str(&mut self, s: &str) -> usize {
        self.write(s.as_bytes())
    }
}

/// Extension trait for GattRequest to provide helper methods
pub trait GattRequestExt<'a> {
    /// Get a ReadResponse for easier response building
    fn read_response(self) -> Option<ReadResponse<'a>>;

    /// Check if this is a read request
    fn is_read(&self) -> bool;

    /// Check if this is a write request
    fn is_write(&self) -> bool;
}

impl<'a> GattRequestExt<'a> for GattRequest<'a> {
    fn read_response(self) -> Option<ReadResponse<'a>> {
        match self {
            GattRequest::Read { offset, output } => Some(ReadResponse::new(offset, output)),
            _ => None,
        }
    }

    fn is_read(&self) -> bool {
        matches!(self, GattRequest::Read { .. })
    }

    fn is_write(&self) -> bool {
        matches!(self, GattRequest::Write { .. })
    }
}

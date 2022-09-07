use core::fmt;

/// Specifies whether a device address is randomly generated or a LAN MAC address.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum AddressKind {
    /// Publicly registered IEEE 802-2001 LAN MAC address.
    Public,
    /// Randomly generated address.
    Random,
}

/// A Bluetooth device address.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct DeviceAddress {
    bytes: [u8; 6],
    kind: AddressKind,
}

impl DeviceAddress {
    /// Create a new device address from 6 raw Bytes and an address kind specifier.
    ///
    /// The `bytes` array contains the address Bytes as they are sent over the air (LSB first).
    pub fn new(bytes: [u8; 6], kind: AddressKind) -> Self {
        DeviceAddress { bytes, kind }
    }

    /// Returns the address kind.
    pub fn kind(&self) -> AddressKind {
        self.kind
    }

    /// Returns whether this address is randomly generated.
    pub fn is_random(&self) -> bool {
        self.kind == AddressKind::Random
    }

    /// Returns the raw bytes making up this address (LSB first).
    pub fn raw(&self) -> &[u8; 6] {
        &self.bytes
    }
}

impl fmt::Debug for DeviceAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceAddress({}, {:?})", self, self.kind)?;
        Ok(())
    }
}

impl fmt::Display for DeviceAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Note: Bluetooth device addresses are usually displayed with MSB
        // first, so that the OUI (Organizationally Unique Identifier) is at
        // the start of the address and thus acts as a prefix, not as a suffix.
        for (i, b) in self.bytes.iter().rev().enumerate() {
            if i != 0 {
                f.write_str(":")?;
            }
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_representation() {
        // Logitech device with OUI prefix 88:C6:26
        // https://macaddresschanger.com/bluetooth-mac-lookup/88%3AC6%3A26
        let addr = DeviceAddress::new([0x5A, 0x92, 0x04, 0x26, 0xC6, 0x88], AddressKind::Public);
        assert_eq!(
            format!("{:?}", addr),
            "DeviceAddress(88:c6:26:04:92:5a, Public)"
        );
    }

    #[test]
    fn display_representation() {
        // Logitech device with OUI prefix 88:C6:26
        // https://macaddresschanger.com/bluetooth-mac-lookup/88%3AC6%3A26
        let addr = DeviceAddress::new([0x5A, 0x92, 0x04, 0x26, 0xC6, 0x88], AddressKind::Public);
        assert_eq!(format!("{}", addr), "88:c6:26:04:92:5a");
    }
}

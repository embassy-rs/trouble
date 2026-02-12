//! Common BTP types.

// Re-export standard Bluetooth types from bt_hci
pub use bt_hci::param::{AddrKind, BdAddr};
// Re-export types from trouble_host
pub use trouble_host::Address;

/// BTP opcode.
///
/// Commands use opcodes 0x01-0x7F, events use 0x80-0xFF, error response is 0x00.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(transparent)]
pub struct Opcode(pub u8);

impl Opcode {
    /// Error response opcode.
    pub const ERROR: Self = Self(0x00);

    /// Check if this is a command opcode (0x01-0x7F).
    pub const fn is_command(&self) -> bool {
        self.0 >= 0x01 && self.0 <= 0x7F
    }
}

impl From<u8> for Opcode {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

/// BTP Service ID newtype.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(transparent)]
pub struct ServiceId(pub u8);

impl ServiceId {
    /// Core Service (mandatory).
    pub const CORE: Self = Self(0x00);
    /// GAP Service.
    pub const GAP: Self = Self(0x01);
    /// GATT Server Service.
    pub const GATT: Self = Self(0x02);
    /// L2CAP Service.
    pub const L2CAP: Self = Self(0x03);
}

impl From<u8> for ServiceId {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addr_kind() {
        assert_eq!(AddrKind::PUBLIC.as_raw(), 0x00);
        assert_eq!(AddrKind::RANDOM.as_raw(), 0x01);
        assert_eq!(AddrKind::new(0x02).as_raw(), 0x02);
    }

    #[test]
    fn test_address() {
        let addr = Address {
            kind: AddrKind::RANDOM,
            addr: BdAddr::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
        };
        assert_eq!(addr.kind, AddrKind::RANDOM);
        assert_eq!(addr.addr.raw(), &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    }
}

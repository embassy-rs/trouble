use bt_hci::param::AddrKind;

use crate::Address;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SecurityMode {
    NoAccess,
    Open,
    JustWorks,
    Mitm,
    LescMitm,
    Signed,
    SignedMitm,
}

impl Default for SecurityMode {
    fn default() -> Self {
        Self::Open
    }
}

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MasterId {
    /// Encrypted diversifier
    pub ediv: u16,
    /// Random number
    pub rand: [u8; 8],
}

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EncryptionInfo {
    /// Long term key
    pub ltk: [u8; 16],
    pub flags: u8,
}

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct IdentityResolutionKey {
    irk: [u8; 16],
}

#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct IdentityKey {
    /// Identity resolution key
    pub irk: IdentityResolutionKey,
    /// Address
    pub addr: Address,
}


impl IdentityKey {
    pub fn is_match(&self, addr: Address) -> bool {
        match addr.kind {
            AddrKind::PUBLIC | AddrKind::RANDOM => {
                if self.addr.kind == addr.kind && self.addr.addr == addr.addr {
                    true 
                } else {
                    false
                }
            },
            AddrKind::RESOLVABLE_PRIVATE_OR_RANDOM => {
                todo!("Random address resolution")
            }
            AddrKind::RESOLVABLE_PRIVATE_OR_PUBLIC | AddrKind::ANONYMOUS_ADV => false,
            _ => panic!("Invalid address kind"),
        }
    }

    pub fn from_addr(addr: Address) -> Self {
        Self {
            irk: Default::default(),
            addr,
        }
    }
}

fn random_address_hash(key: IdentityResolutionKey) -> [u8; 6] {
    todo!()
}


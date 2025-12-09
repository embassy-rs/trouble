use core::cell::RefCell;
use core::marker::PhantomData;

use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::RawMutex;

use crate::att::{self, AttClient, AttCmd, AttErrorCode, AttReq};
use crate::attribute::{Attribute, AttributeData, AttributeTable, CCCD};
use crate::cursor::WriteCursor;
use crate::prelude::Connection;
use crate::types::uuid::Uuid;
use crate::{Error, Identity, PacketPool, codec};

#[derive(Default)]
struct Client {
    identity: Identity,
    is_connected: bool,
}

impl Client {
    fn set_identity(&mut self, identity: Identity) {
        self.identity = identity;
    }
}

/// A table of CCCD values.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Clone, Debug)]
pub struct CccdTable<const ENTRIES: usize> {
    inner: [(u16, CCCD); ENTRIES],
}

impl<const ENTRIES: usize> Default for CccdTable<ENTRIES> {
    fn default() -> Self {
        Self {
            inner: [(0, CCCD(0)); ENTRIES],
        }
    }
}

impl<const ENTRIES: usize> CccdTable<ENTRIES> {
    /// Create a new CCCD table from an array of (handle, cccd) pairs.
    pub fn new(cccd_values: [(u16, CCCD); ENTRIES]) -> Self {
        Self { inner: cccd_values }
    }

    /// Get the inner array of (handle, cccd) pairs.
    pub fn inner(&self) -> &[(u16, CCCD); ENTRIES] {
        &self.inner
    }

    fn add_handle(&mut self, cccd_handle: u16) {
        for (handle, _) in self.inner.iter_mut() {
            if *handle == 0 {
                *handle = cccd_handle;
                break;
            }
        }
    }

    fn disable_all(&mut self) {
        for (_, value) in self.inner.iter_mut() {
            value.disable();
        }
    }

    fn get_raw(&self, cccd_handle: u16) -> Option<[u8; 2]> {
        for (handle, value) in self.inner.iter() {
            if *handle == cccd_handle {
                return Some(value.raw().to_le_bytes());
            }
        }
        None
    }

    fn set_notify(&mut self, cccd_handle: u16, is_enabled: bool) {
        for (handle, value) in self.inner.iter_mut() {
            if *handle == cccd_handle {
                trace!("[cccd] set_notify({}) = {}", cccd_handle, is_enabled);
                value.set_notify(is_enabled);
                break;
            }
        }
    }

    fn should_notify(&self, cccd_handle: u16) -> bool {
        for (handle, value) in self.inner.iter() {
            if *handle == cccd_handle {
                return value.should_notify();
            }
        }
        false
    }

    fn set_indicate(&mut self, cccd_handle: u16, is_enabled: bool) {
        for (handle, value) in self.inner.iter_mut() {
            if *handle == cccd_handle {
                trace!("\n\n\n[cccd] set_indicate({}) = {}", cccd_handle, is_enabled);
                value.set_indicate(is_enabled);
                break;
            }
        }
    }
    fn should_indicate(&self, cccd_handle: u16) -> bool {
        for (handle, value) in self.inner.iter() {
            if *handle == cccd_handle {
                return value.should_indicate();
            }
        }
        false
    }
}

/// A table of CCCD values for each connected client.
struct CccdTables<M: RawMutex, const CCCD_MAX: usize, const CONN_MAX: usize> {
    state: Mutex<M, RefCell<[(Client, CccdTable<CCCD_MAX>); CONN_MAX]>>,
}

impl<M: RawMutex, const CCCD_MAX: usize, const CONN_MAX: usize> CccdTables<M, CCCD_MAX, CONN_MAX> {
    fn new<const ATT_MAX: usize>(att_table: &AttributeTable<'_, M, ATT_MAX>) -> Self {
        let mut values: [(Client, CccdTable<CCCD_MAX>); CONN_MAX] =
            core::array::from_fn(|_| (Client::default(), CccdTable::default()));
        let mut base_cccd_table = CccdTable::default();
        att_table.iterate(|mut at| {
            while let Some(att) = at.next() {
                if let AttributeData::Cccd { .. } = att.data {
                    base_cccd_table.add_handle(att.handle);
                }
            }
        });
        // add the base CCCD table for each potential connected client
        for (_, table) in values.iter_mut() {
            *table = base_cccd_table.clone();
        }
        Self {
            state: Mutex::new(RefCell::new(values)),
        }
    }

    fn connect(&self, peer_identity: &Identity) -> Result<(), Error> {
        self.state.lock(|n| {
            trace!("[server] searching for peer {:?}", peer_identity);
            let mut n = n.borrow_mut();
            let empty_slot = Identity::default();
            for (client, table) in n.iter_mut() {
                if client.identity.match_identity(peer_identity) {
                    // trace!("[server] found! table = {:?}", *table);
                    client.is_connected = true;
                    return Ok(());
                } else if client.identity == empty_slot {
                    //  trace!("[server] empty slot: connecting");
                    client.is_connected = true;
                    client.set_identity(*peer_identity);
                    return Ok(());
                }
            }
            trace!("[server] all slots full...");
            // if we got here all slots are full; replace the first disconnected client
            for (client, table) in n.iter_mut() {
                if !client.is_connected {
                    trace!("[server] booting disconnected peer {:?}", client.identity);
                    client.is_connected = true;
                    client.set_identity(*peer_identity);
                    // erase the previous client's config
                    table.disable_all();
                    return Ok(());
                }
            }
            // Should be unreachable if the max connections (CONN_MAX) matches that defined
            // in HostResources...
            warn!("[server] unable to obtain CCCD slot");
            Err(Error::ConnectionLimitReached)
        })
    }

    fn disconnect(&self, peer_identity: &Identity) {
        self.state.lock(|n| {
            let mut n = n.borrow_mut();
            for (client, _) in n.iter_mut() {
                if client.identity.match_identity(peer_identity) {
                    client.is_connected = false;
                    break;
                }
            }
        })
    }

    fn get_value(&self, peer_identity: &Identity, cccd_handle: u16) -> Option<[u8; 2]> {
        self.state.lock(|n| {
            let n = n.borrow();
            for (client, table) in n.iter() {
                if client.identity.match_identity(peer_identity) {
                    return table.get_raw(cccd_handle);
                }
            }
            None
        })
    }

    fn set_notify(&self, peer_identity: &Identity, cccd_handle: u16, is_enabled: bool) {
        self.state.lock(|n| {
            let mut n = n.borrow_mut();
            for (client, table) in n.iter_mut() {
                if client.identity.match_identity(peer_identity) {
                    table.set_notify(cccd_handle, is_enabled);
                    break;
                }
            }
        })
    }

    fn should_notify(&self, peer_identity: &Identity, cccd_handle: u16) -> bool {
        self.state.lock(|n| {
            let n = n.borrow();
            for (client, table) in n.iter() {
                if client.identity.match_identity(peer_identity) {
                    return table.should_notify(cccd_handle);
                }
            }
            false
        })
    }

    fn set_indicate(&self, peer_identity: &Identity, cccd_handle: u16, is_enabled: bool) {
        self.state.lock(|n| {
            let mut n = n.borrow_mut();
            for (client, table) in n.iter_mut() {
                if client.identity.match_identity(peer_identity) {
                    table.set_indicate(cccd_handle, is_enabled);
                    break;
                }
            }
        })
    }

    fn should_indicate(&self, peer_identity: &Identity, cccd_handle: u16) -> bool {
        self.state.lock(|n| {
            let n = n.borrow();
            for (client, table) in n.iter() {
                if client.identity.match_identity(peer_identity) {
                    return table.should_indicate(cccd_handle);
                }
            }
            false
        })
    }

    fn get_cccd_table(&self, peer_identity: &Identity) -> Option<CccdTable<CCCD_MAX>> {
        self.state.lock(|n| {
            let n = n.borrow();
            for (client, table) in n.iter() {
                if client.identity.match_identity(peer_identity) {
                    return Some(table.clone());
                }
            }
            None
        })
    }

    fn set_cccd_table(&self, peer_identity: &Identity, table: CccdTable<CCCD_MAX>) {
        self.state.lock(|n| {
            let mut n = n.borrow_mut();
            for (client, t) in n.iter_mut() {
                if client.identity.match_identity(peer_identity) {
                    trace!("Setting cccd table {:?} for {:?}", table, peer_identity);
                    *t = table;
                    break;
                }
            }
        })
    }

    fn update_identity(&self, identity: Identity) -> Result<(), Error> {
        self.state.lock(|n| {
            let mut n = n.borrow_mut();
            for (client, _) in n.iter_mut() {
                if identity.match_identity(&client.identity) {
                    client.set_identity(identity);
                    return Ok(());
                }
            }
            Err(Error::NotFound)
        })
    }
}

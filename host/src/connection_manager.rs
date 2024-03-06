use core::cell::RefCell;

use bt_hci::param::{BdAddr, ConnHandle, LeConnRole, Status};
use embassy_sync::blocking_mutex::{raw::RawMutex, Mutex};

pub struct ConnectionManager<'d, M: RawMutex> {
    connections: Mutex<M, RefCell<&'d mut [ConnectionStorage]>>,
}

impl<'d, M: RawMutex> ConnectionManager<'d, M> {
    pub fn new(connections: &'d mut [ConnectionStorage]) -> Self {
        Self {
            connections: Mutex::new(RefCell::new(connections)),
        }
    }

    pub fn update<F: FnOnce(&mut ConnectionState)>(&self, handle: ConnHandle, f: F) -> Result<(), ()> {
        self.connections.lock(|connections| {
            let mut connections = connections.borrow_mut();
            for storage in connections.iter_mut() {
                if let Some(stored) = storage.state.as_mut() {
                    if stored.handle == handle {
                        f(stored);
                        break;
                    }
                }
            }
            Ok(())
        })
    }

    pub fn delete(&self, handle: ConnHandle) -> Result<(), ()> {
        self.connections.lock(|connections| {
            let mut connections = connections.borrow_mut();
            for storage in connections.iter_mut() {
                if let Some(stored) = &storage.state {
                    if stored.handle == handle {
                        storage.state.take();
                        break;
                    }
                }
            }
            Ok(())
        })
    }

    pub fn create(&self, handle: ConnHandle, state: ConnectionState) -> Result<(), ()> {
        self.connections.lock(|connections| {
            let mut connections = connections.borrow_mut();
            for storage in connections.iter_mut() {
                if storage.state.is_none() {
                    storage.state.replace(state);
                    return Ok(());
                }
            }
            Err(())
        })
    }
}

pub struct ConnectionStorage {
    state: Option<ConnectionState>,
}

impl ConnectionStorage {
    pub const UNUSED: Self = Self { state: None };
}

#[derive(Clone)]
pub struct ConnectionState {
    pub(crate) handle: ConnHandle,
    pub(crate) status: Status,
    pub(crate) role: LeConnRole,
    pub(crate) peer_address: BdAddr,
    pub(crate) interval: u16,
    pub(crate) latency: u16,
    pub(crate) timeout: u16,
}

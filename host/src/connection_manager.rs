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

    pub fn update<F: FnOnce(&mut ConnectionState)>(&self, f: F) {
        todo!()
    }

    pub fn create(&self, handle: ConnHandle, state: &ConnectionState) -> Result<(), ()> {
        todo!()
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
    handle: ConnHandle,
    status: Status,
    role: LeConnRole,
    peer_address: BdAddr,
    interval: u16,
    latency: u16,
    timeout: u16,
}

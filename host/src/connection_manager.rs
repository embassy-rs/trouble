use core::cell::RefCell;

use bt_hci::param::{BdAddr, ConnHandle, LeConnRole, Status};
use embassy_sync::{
    blocking_mutex::{raw::RawMutex, Mutex},
    channel::{Channel, DynamicReceiver},
};

use crate::connection::ConnEvent;

pub struct ConnectionManager<'d, M: RawMutex> {
    // Connection states
    connections: Mutex<M, RefCell<&'d mut [ConnectionStorage]>>,
    // Connection events.
    events: &'d [Channel<M, ConnEvent, 1>],
}

impl<'d, M: RawMutex> ConnectionManager<'d, M> {
    pub fn new(connections: &'d mut [ConnectionStorage], events: &'d [Channel<M, ConnEvent, 1>]) -> Self {
        Self {
            connections: Mutex::new(RefCell::new(connections)),
            events,
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

    pub fn create(&self, handle: ConnHandle, state: ConnectionState) -> Result<DynamicReceiver<'_, ConnEvent>, ()> {
        self.connections.lock(|connections| {
            let mut connections = connections.borrow_mut();
            for (storage, chan) in connections.iter_mut().zip(self.events) {
                if storage.state.is_none() {
                    storage.state.replace(state);
                    return Ok(chan.receiver().into());
                }
            }
            Err(())
        })
    }

    pub async fn notify(&self, handle: ConnHandle, event: ConnEvent) -> Result<(), ()> {
        let chan = self.connections.lock(|connections| {
            let mut connections = connections.borrow_mut();
            for (storage, chan) in connections.iter_mut().zip(self.events) {
                if let Some(state) = &storage.state {
                    if state.handle == handle {
                        return Ok(chan.sender());
                    }
                }
            }
            Err(())
        })?;
        chan.send(event).await;
        Ok(())
    }
}

pub struct ConnectionStorage {
    state: Option<ConnectionState>,
}

impl ConnectionStorage {
    pub const UNUSED: Self = Self { state: None };
}

pub struct ConnectionState {
    pub(crate) handle: ConnHandle,
    pub(crate) status: Status,
    pub(crate) role: LeConnRole,
    pub(crate) peer_address: BdAddr,
    pub(crate) interval: u16,
    pub(crate) latency: u16,
    pub(crate) timeout: u16,
}

impl ConnectionState {
    pub fn new(
        handle: ConnHandle,
        status: Status,
        role: LeConnRole,
        peer_address: BdAddr,
        interval: u16,
        latency: u16,
        timeout: u16,
    ) -> Self {
        Self {
            handle,
            status,
            role,
            peer_address,
            interval,
            latency,
            timeout,
        }
    }
}

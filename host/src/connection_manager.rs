use core::{
    cell::RefCell,
    future::poll_fn,
    task::{Context, Poll},
};

use bt_hci::param::{BdAddr, ConnHandle, LeConnRole, Status};
use embassy_sync::{
    blocking_mutex::{raw::RawMutex, Mutex},
    waitqueue::WakerRegistration,
};

use crate::Error;

struct State<const CONNS: usize> {
    connections: [ConnectionState; CONNS],
    waker: WakerRegistration,
}

pub struct ConnectionManager<M: RawMutex, const CONNS: usize> {
    state: Mutex<M, RefCell<State<CONNS>>>,
}

impl<M: RawMutex, const CONNS: usize> ConnectionManager<M, CONNS> {
    const DISCONNECTED: ConnectionState = ConnectionState::Disconnected;
    pub fn new() -> Self {
        Self {
            state: Mutex::new(RefCell::new(State {
                connections: [Self::DISCONNECTED; CONNS],
                waker: WakerRegistration::new(),
            })),
        }
    }

    pub fn disconnect(&self, h: ConnHandle) -> Result<(), Error> {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            for storage in state.connections.iter_mut() {
                match storage {
                    ConnectionState::Connecting(handle, _) if *handle == h => {
                        *storage = ConnectionState::Disconnected;
                    }
                    ConnectionState::Connected(handle, _) if *handle == h => {
                        *storage = ConnectionState::Disconnected;
                    }
                    _ => {}
                }
            }
            Ok(())
        })
    }

    pub fn connect(&self, handle: ConnHandle, info: ConnectionInfo) -> Result<(), Error> {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            for storage in state.connections.iter_mut() {
                match storage {
                    ConnectionState::Disconnected => {
                        *storage = ConnectionState::Connecting(handle, info);
                        state.waker.wake();
                        return Ok(());
                    }
                    _ => {}
                }
            }
            Err(Error::NotFound)
        })
    }

    pub fn poll_accept(&self, peer: Option<BdAddr>, cx: &mut Context<'_>) -> Poll<ConnHandle> {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            for storage in state.connections.iter_mut() {
                match storage {
                    ConnectionState::Connecting(handle, info) => {
                        if let Some(peer) = peer {
                            if info.peer_address == peer {
                                let handle = handle.clone();
                                *storage = ConnectionState::Connected(handle.clone(), info.clone());
                                return Poll::Ready(handle);
                            }
                        } else {
                            let handle = handle.clone();
                            *storage = ConnectionState::Connected(handle.clone(), info.clone());
                            return Poll::Ready(handle);
                        }
                    }
                    _ => {}
                }
            }
            state.waker.register(cx.waker());
            Poll::Pending
        })
    }

    pub async fn accept(&self, peer: Option<BdAddr>) -> ConnHandle {
        poll_fn(move |cx| self.poll_accept(peer, cx)).await
    }
}

pub enum ConnectionState {
    Disconnected,
    Connecting(ConnHandle, ConnectionInfo),
    Connected(ConnHandle, ConnectionInfo),
}

pub trait DynamicConnectionManager {
    fn get_att_mtu(&self, conn: ConnHandle) -> u16;
    fn exchange_att_mtu(&self, conn: ConnHandle, mtu: u16) -> u16;
}

impl<M: RawMutex, const CONNS: usize> DynamicConnectionManager for ConnectionManager<M, CONNS> {
    fn get_att_mtu(&self, conn: ConnHandle) -> u16 {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            for storage in state.connections.iter_mut() {
                match storage {
                    ConnectionState::Connected(handle, info) if *handle == conn => {
                        return info.att_mtu;
                    }
                    _ => {}
                }
            }
            23 // Minimum value
        })
    }
    fn exchange_att_mtu(&self, conn: ConnHandle, mtu: u16) -> u16 {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            for storage in state.connections.iter_mut() {
                match storage {
                    ConnectionState::Connected(handle, info) if *handle == conn => {
                        info.att_mtu = info.att_mtu.min(mtu);
                        return info.att_mtu;
                    }
                    _ => {}
                }
            }
            mtu
        })
    }
}

#[derive(Clone, Copy)]
pub struct ConnectionInfo {
    pub handle: ConnHandle,
    pub status: Status,
    pub role: LeConnRole,
    pub peer_address: BdAddr,
    pub interval: u16,
    pub latency: u16,
    pub timeout: u16,
    pub att_mtu: u16,
}

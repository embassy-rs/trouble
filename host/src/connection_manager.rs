use core::{
    cell::RefCell,
    future::poll_fn,
    task::{Context, Poll},
};

use bt_hci::param::{AddrKind, BdAddr, ConnHandle, LeConnRole, Status};
use embassy_sync::{
    blocking_mutex::{raw::RawMutex, Mutex},
    signal::Signal,
    waitqueue::WakerRegistration,
};

use crate::Error;

struct State<const CONNS: usize> {
    connections: [ConnectionState; CONNS],
    waker: WakerRegistration,
}

pub struct ConnectionManager<M: RawMutex, const CONNS: usize> {
    state: Mutex<M, RefCell<State<CONNS>>>,
    canceled: Signal<M, ()>,
}

impl<M: RawMutex, const CONNS: usize> ConnectionManager<M, CONNS> {
    const DISCONNECTED: ConnectionState = ConnectionState::Disconnected;
    pub fn new() -> Self {
        Self {
            state: Mutex::new(RefCell::new(State {
                connections: [Self::DISCONNECTED; CONNS],
                waker: WakerRegistration::new(),
            })),
            canceled: Signal::new(),
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

    pub(crate) fn with_connection<F: FnOnce(&ConnectionInfo) -> R, R>(
        &self,
        handle: ConnHandle,
        f: F,
    ) -> Result<R, Error> {
        self.state.lock(|state| {
            let state = state.borrow();
            for storage in state.connections.iter() {
                match storage {
                    ConnectionState::Connected(h, info) if *h == handle => return Ok(f(info)),
                    _ => {}
                }
            }
            Err(Error::NotFound)
        })
    }

    pub fn connect(&self, handle: ConnHandle, info: ConnectionInfo) -> Result<(), Error> {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            for storage in state.connections.iter_mut() {
                if let ConnectionState::Disconnected = storage {
                    *storage = ConnectionState::Connecting(handle, Some(info));
                    state.waker.wake();
                    return Ok(());
                }
            }
            Err(Error::NotFound)
        })
    }

    pub async fn wait_canceled(&self) {
        self.canceled.wait().await;
        self.canceled.reset();
    }

    pub fn canceled(&self) {
        self.canceled.signal(());
    }

    pub fn poll_accept(&self, peers: &[(AddrKind, &BdAddr)], cx: &mut Context<'_>) -> Poll<ConnHandle> {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            for storage in state.connections.iter_mut() {
                if let ConnectionState::Connecting(handle, info) = storage {
                    let handle = *handle;
                    if !peers.is_empty() {
                        for peer in peers.iter() {
                            if info.as_ref().unwrap().peer_addr_kind == peer.0
                                && &info.as_ref().unwrap().peer_address == peer.1
                            {
                                *storage = ConnectionState::Connected(handle, info.take().unwrap());
                                return Poll::Ready(handle);
                            }
                        }
                    } else {
                        *storage = ConnectionState::Connected(handle, info.take().unwrap());
                        return Poll::Ready(handle);
                    }
                }
            }
            state.waker.register(cx.waker());
            Poll::Pending
        })
    }

    pub async fn accept(&self, peers: &[(AddrKind, &BdAddr)]) -> ConnHandle {
        poll_fn(move |cx| self.poll_accept(peers, cx)).await
    }
}

pub enum ConnectionState {
    Disconnected,
    Connecting(ConnHandle, Option<ConnectionInfo>),
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

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConnectionInfo {
    pub handle: ConnHandle,
    pub status: Status,
    pub role: LeConnRole,
    pub peer_addr_kind: AddrKind,
    pub peer_address: BdAddr,
    pub interval: u16,
    pub latency: u16,
    pub timeout: u16,
    pub att_mtu: u16,
}

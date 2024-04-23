use core::cell::RefCell;
use core::future::poll_fn;
use core::task::{Context, Poll};

use bt_hci::event::le::LeConnectionComplete;
use bt_hci::param::{AddrKind, BdAddr, ConnHandle, LeConnRole};
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::signal::Signal;
use embassy_sync::waitqueue::WakerRegistration;

use crate::Error;

struct State<const CONNS: usize> {
    connections: [ConnectionStorage; CONNS],
    waker: WakerRegistration,
}

pub(crate) struct ConnectionManager<M: RawMutex, const CONNS: usize> {
    state: Mutex<M, RefCell<State<CONNS>>>,
    canceled: Signal<M, ()>,
}

impl<M: RawMutex, const CONNS: usize> ConnectionManager<M, CONNS> {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(RefCell::new(State {
                connections: [ConnectionStorage::DISCONNECTED; CONNS],
                waker: WakerRegistration::new(),
            })),
            canceled: Signal::new(),
        }
    }

    pub(crate) fn role(&self, h: ConnHandle) -> Result<LeConnRole, Error> {
        self.state.lock(|state| {
            let state = state.borrow();
            for storage in state.connections.iter() {
                if storage.state == ConnectionState::Connected && storage.handle.unwrap() == h {
                    return Ok(storage.role.unwrap());
                }
            }
            Err(Error::NotFound)
        })
    }

    pub(crate) fn peer_address(&self, h: ConnHandle) -> Result<BdAddr, Error> {
        self.state.lock(|state| {
            let state = state.borrow();
            for storage in state.connections.iter() {
                if storage.state == ConnectionState::Connected && storage.handle.unwrap() == h {
                    return Ok(storage.peer_addr.unwrap());
                }
            }
            Err(Error::NotFound)
        })
    }

    pub(crate) fn disconnect(&self, h: ConnHandle) -> Result<(), Error> {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            for storage in state.connections.iter_mut() {
                match storage.state {
                    ConnectionState::Connecting if storage.handle.unwrap() == h => {
                        storage.state = ConnectionState::Disconnected;
                    }
                    ConnectionState::Connected if storage.handle.unwrap() == h => {
                        storage.state = ConnectionState::Disconnected;
                    }
                    _ => {}
                }
            }
            Ok(())
        })
    }

    pub(crate) fn connect(&self, handle: ConnHandle, info: &LeConnectionComplete) -> Result<(), Error> {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            for storage in state.connections.iter_mut() {
                if let ConnectionState::Disconnected = storage.state {
                    storage.state = ConnectionState::Connecting;
                    storage.handle.replace(handle);
                    storage.peer_addr_kind.replace(info.peer_addr_kind);
                    storage.peer_addr.replace(info.peer_addr);
                    storage.role.replace(info.role);
                    state.waker.wake();
                    return Ok(());
                }
            }
            Err(Error::NotFound)
        })
    }

    pub(crate) async fn wait_canceled(&self) {
        self.canceled.wait().await;
        self.canceled.reset();
    }

    pub(crate) fn canceled(&self) {
        self.canceled.signal(());
    }

    pub(crate) fn poll_accept(&self, peers: &[(AddrKind, &BdAddr)], cx: &mut Context<'_>) -> Poll<ConnHandle> {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            for storage in state.connections.iter_mut() {
                if let ConnectionState::Connecting = storage.state {
                    let handle = storage.handle.unwrap();
                    if !peers.is_empty() {
                        for peer in peers.iter() {
                            if storage.peer_addr_kind.unwrap() == peer.0 && &storage.peer_addr.unwrap() == peer.1 {
                                storage.state = ConnectionState::Connected;
                                return Poll::Ready(handle);
                            }
                        }
                    } else {
                        storage.state = ConnectionState::Connected;
                        return Poll::Ready(handle);
                    }
                }
            }
            state.waker.register(cx.waker());
            Poll::Pending
        })
    }

    pub(crate) async fn accept(&self, peers: &[(AddrKind, &BdAddr)]) -> ConnHandle {
        poll_fn(move |cx| self.poll_accept(peers, cx)).await
    }
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
                match storage.state {
                    ConnectionState::Connected if storage.handle.unwrap() == conn => {
                        return storage.att_mtu;
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
                match storage.state {
                    ConnectionState::Connected if storage.handle.unwrap() == conn => {
                        storage.att_mtu = storage.att_mtu.min(mtu);
                        return storage.att_mtu;
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
pub struct ConnectionStorage {
    pub state: ConnectionState,
    pub handle: Option<ConnHandle>,
    pub role: Option<LeConnRole>,
    pub peer_addr_kind: Option<AddrKind>,
    pub peer_addr: Option<BdAddr>,
    pub att_mtu: u16,
}

impl ConnectionStorage {
    const DISCONNECTED: ConnectionStorage = ConnectionStorage {
        state: ConnectionState::Disconnected,
        handle: None,
        role: None,
        peer_addr_kind: None,
        peer_addr: None,
        att_mtu: 23,
    };
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
}

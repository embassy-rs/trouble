use core::cell::RefCell;
use core::future::poll_fn;
use core::task::{Context, Poll};

use bt_hci::param::{AddrKind, BdAddr, ConnHandle, DisconnectReason, LeConnRole};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::signal::Signal;
use embassy_sync::waitqueue::WakerRegistration;

use crate::Error;

struct State<'d> {
    connections: &'d mut [ConnectionStorage],
    accept_waker: WakerRegistration,
    disconnect_waker: WakerRegistration,
    default_link_credits: usize,
}

impl<'d> State<'d> {
    fn print(&self) {
        for (idx, storage) in self.connections.iter().enumerate() {
            if storage.state != ConnectionState::Disconnected {
                debug!("[link][idx = {}] state = {:?}", idx, storage);
            }
        }
    }
}

pub(crate) struct ConnectionManager<'d> {
    state: RefCell<State<'d>>,
    canceled: Signal<NoopRawMutex, ()>,
}

impl<'d> ConnectionManager<'d> {
    pub(crate) fn new(connections: &'d mut [ConnectionStorage]) -> Self {
        Self {
            state: RefCell::new(State {
                connections,
                accept_waker: WakerRegistration::new(),
                disconnect_waker: WakerRegistration::new(),
                default_link_credits: 0,
            }),
            canceled: Signal::new(),
        }
    }

    pub(crate) fn role(&self, index: u8) -> LeConnRole {
        self.with_mut(|state| {
            let state = &mut state.connections[index as usize];
            assert_eq!(state.state, ConnectionState::Connected);
            state.role.unwrap()
        })
    }

    pub(crate) fn handle(&self, index: u8) -> ConnHandle {
        self.with_mut(|state| {
            let state = &mut state.connections[index as usize];
            assert_eq!(state.state, ConnectionState::Connected);
            state.handle.unwrap()
        })
    }

    pub(crate) fn peer_address(&self, index: u8) -> BdAddr {
        self.with_mut(|state| {
            let state = &mut state.connections[index as usize];
            assert_eq!(state.state, ConnectionState::Connected);
            state.peer_addr.unwrap()
        })
    }

    pub(crate) fn request_disconnect(&self, index: u8, reason: DisconnectReason) {
        self.with_mut(|state| {
            let state = &mut state.connections[index as usize];
            if state.state == ConnectionState::Connected {
                state.state = ConnectionState::Disconnecting(reason);
            }
        })
    }

    pub(crate) fn poll_disconnecting<'m>(&'m self, cx: &mut Context<'_>) -> Poll<DisconnectIter<'m, 'd>> {
        let mut state = self.state.borrow_mut();
        state.disconnect_waker.register(cx.waker());
        for storage in state.connections.iter() {
            if let ConnectionState::Disconnecting(_) = storage.state {
                return Poll::Ready(DisconnectIter {
                    idx: 0,
                    state: &self.state,
                });
            }
        }
        Poll::Pending
    }

    pub(crate) fn disconnect(&self, h: ConnHandle) -> Result<(), Error> {
        let mut state = self.state.borrow_mut();
        for storage in state.connections.iter_mut() {
            match storage.state {
                ConnectionState::Connecting if storage.handle.unwrap() == h => {
                    storage.state = ConnectionState::Disconnected;
                    state.disconnect_waker.wake();
                    return Ok(());
                }
                ConnectionState::Connected if storage.handle.unwrap() == h => {
                    storage.state = ConnectionState::Disconnected;
                    state.disconnect_waker.wake();
                    return Ok(());
                }
                _ => {}
            }
        }
        Err(Error::NotFound)
    }

    pub(crate) fn connect(
        &self,
        handle: ConnHandle,
        peer_addr_kind: AddrKind,
        peer_addr: BdAddr,
        role: LeConnRole,
    ) -> Result<(), Error> {
        let mut state = self.state.borrow_mut();
        let default_credits = state.default_link_credits;
        for storage in state.connections.iter_mut() {
            if ConnectionState::Disconnected == storage.state && storage.refcount == 0 {
                storage.state = ConnectionState::Connecting;
                storage.link_credits = default_credits;
                storage.handle.replace(handle);
                storage.peer_addr_kind.replace(peer_addr_kind);
                storage.peer_addr.replace(peer_addr);
                storage.role.replace(role);
                state.accept_waker.wake();
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    pub(crate) async fn wait_canceled(&self) {
        self.canceled.wait().await;
        self.canceled.reset();
    }

    pub(crate) fn canceled(&self) {
        self.canceled.signal(());
    }

    pub(crate) fn poll_accept(&self, peers: &[(AddrKind, &BdAddr)], cx: &mut Context<'_>) -> Poll<u8> {
        let mut state = self.state.borrow_mut();
        state.accept_waker.register(cx.waker());
        for (idx, storage) in state.connections.iter_mut().enumerate() {
            if let ConnectionState::Connecting = storage.state {
                let handle = storage.handle.unwrap();
                if !peers.is_empty() {
                    for peer in peers.iter() {
                        if storage.peer_addr_kind.unwrap() == peer.0 && &storage.peer_addr.unwrap() == peer.1 {
                            storage.state = ConnectionState::Connected;
                            return Poll::Ready(idx as u8);
                        }
                    }
                } else {
                    storage.state = ConnectionState::Connected;
                    return Poll::Ready(idx as u8);
                }
            }
        }
        Poll::Pending
    }

    fn with_mut<F: FnOnce(&mut State<'d>) -> R, R>(&self, f: F) -> R {
        let mut state = self.state.borrow_mut();
        f(&mut state)
    }

    pub(crate) fn log_status(&self) {
        let state = self.state.borrow();
        state.print();
    }

    pub(crate) fn inc_ref(&self, index: u8) {
        self.with_mut(|state| {
            let state = &mut state.connections[index as usize];
            state.refcount = unwrap!(
                state.refcount.checked_add(1),
                "Too many references to the same connection"
            );
        });
    }

    pub(crate) fn dec_ref(&self, index: u8) {
        self.with_mut(|state| {
            let state = &mut state.connections[index as usize];
            state.refcount = unwrap!(
                state.refcount.checked_sub(1),
                "bug: dropping a connection with refcount 0"
            );
            if state.refcount == 0 {
                if state.state == ConnectionState::Connected {
                    state.state = ConnectionState::Disconnecting(DisconnectReason::RemoteUserTerminatedConn);
                }
            }
        });
    }

    pub(crate) async fn accept(&self, peers: &[(AddrKind, &BdAddr)]) -> u8 {
        poll_fn(move |cx| self.poll_accept(peers, cx)).await
    }

    pub(crate) fn set_link_credits(&self, credits: usize) {
        let mut state = self.state.borrow_mut();
        state.default_link_credits = credits;
        for storage in state.connections.iter_mut() {
            storage.link_credits = credits;
        }
    }

    pub(crate) fn confirm_sent(&self, handle: ConnHandle, packets: usize) -> Result<(), Error> {
        let mut state = self.state.borrow_mut();
        for storage in state.connections.iter_mut() {
            match storage.state {
                ConnectionState::Connected if handle == storage.handle.unwrap() => {
                    storage.link_credits += packets;
                    storage.link_credit_waker.wake();
                    return Ok(());
                }
                _ => {}
            }
        }
        warn!("[link][confirm_sent] connection {:?} not found", handle);
        Err(Error::NotFound)
    }

    pub(crate) fn poll_request_to_send(
        &self,
        handle: ConnHandle,
        packets: usize,
        cx: Option<&mut Context<'_>>,
    ) -> Poll<Result<PacketGrant<'_, 'd>, Error>> {
        let mut state = self.state.borrow_mut();
        for storage in state.connections.iter_mut() {
            match storage.state {
                ConnectionState::Connected if storage.handle.unwrap() == handle => {
                    if packets <= storage.link_credits {
                        storage.link_credits -= packets;

                        return Poll::Ready(Ok(PacketGrant::new(&self.state, handle, packets)));
                    } else {
                        if let Some(cx) = cx {
                            storage.link_credit_waker.register(cx.waker());
                        }
                        debug!(
                            "[link][poll_request_to_send][conn = {}] requested {} available {}",
                            handle.raw(),
                            packets,
                            storage.link_credits
                        );
                        return Poll::Pending;
                    }
                }
                _ => {}
            }
        }
        warn!("[link][pool_request_to_send] connection {:?} not found", handle);
        Poll::Ready(Err(Error::NotFound))
    }
}

pub(crate) trait DynamicConnectionManager {
    fn role(&self, index: u8) -> LeConnRole;
    fn handle(&self, index: u8) -> ConnHandle;
    fn peer_address(&self, index: u8) -> BdAddr;
    fn inc_ref(&self, index: u8);
    fn dec_ref(&self, index: u8);
    fn disconnect(&self, index: u8, reason: DisconnectReason);
    fn get_att_mtu(&self, conn: ConnHandle) -> u16;
    fn exchange_att_mtu(&self, conn: ConnHandle, mtu: u16) -> u16;
}

impl<'d> DynamicConnectionManager for ConnectionManager<'d> {
    fn role(&self, index: u8) -> LeConnRole {
        ConnectionManager::role(self, index)
    }
    fn handle(&self, index: u8) -> ConnHandle {
        ConnectionManager::handle(self, index)
    }
    fn peer_address(&self, index: u8) -> BdAddr {
        ConnectionManager::peer_address(self, index)
    }
    fn inc_ref(&self, index: u8) {
        ConnectionManager::inc_ref(self, index)
    }
    fn dec_ref(&self, index: u8) {
        ConnectionManager::dec_ref(self, index)
    }
    fn disconnect(&self, index: u8, reason: DisconnectReason) {
        ConnectionManager::request_disconnect(self, index, reason)
    }
    fn get_att_mtu(&self, conn: ConnHandle) -> u16 {
        let mut state = self.state.borrow_mut();
        for storage in state.connections.iter_mut() {
            match storage.state {
                ConnectionState::Connected if storage.handle.unwrap() == conn => {
                    return storage.att_mtu;
                }
                _ => {}
            }
        }
        23 // Minimum value
    }
    fn exchange_att_mtu(&self, conn: ConnHandle, mtu: u16) -> u16 {
        let mut state = self.state.borrow_mut();
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
    }
}

pub struct DisconnectIter<'a, 'd> {
    state: &'a RefCell<State<'d>>,
    idx: usize,
}

impl<'a, 'd> Iterator for DisconnectIter<'a, 'd> {
    type Item = (ConnHandle, DisconnectReason);
    fn next(&mut self) -> Option<Self::Item> {
        let state = self.state.borrow();
        for idx in self.idx..state.connections.len() {
            if let ConnectionState::Disconnecting(reason) = state.connections[idx].state {
                self.idx = idx;
                return state.connections[idx].handle.map(|h| (h, reason));
            }
        }
        self.idx = state.connections.len();
        None
    }
}

#[derive(Debug)]
pub struct ConnectionStorage {
    pub state: ConnectionState,
    pub handle: Option<ConnHandle>,
    pub role: Option<LeConnRole>,
    pub peer_addr_kind: Option<AddrKind>,
    pub peer_addr: Option<BdAddr>,
    pub att_mtu: u16,
    pub link_credits: usize,
    pub link_credit_waker: WakerRegistration,
    pub refcount: u8,
}

impl ConnectionStorage {
    pub(crate) const DISCONNECTED: ConnectionStorage = ConnectionStorage {
        state: ConnectionState::Disconnected,
        handle: None,
        role: None,
        peer_addr_kind: None,
        peer_addr: None,
        att_mtu: 23,
        link_credits: 0,
        link_credit_waker: WakerRegistration::new(),
        refcount: 0,
    };
}

#[cfg(feature = "defmt")]
impl defmt::Format for ConnectionStorage {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(
            f,
            "state = {}, conn = {}, credits = {}, peer = {:?}",
            self.state,
            self.handle,
            self.link_credits,
            self.peer_addr,
        );
    }
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ConnectionState {
    Disconnecting(DisconnectReason),
    Disconnected,
    Connecting,
    Connected,
}

pub struct PacketGrant<'a, 'd> {
    state: &'a RefCell<State<'d>>,
    handle: ConnHandle,
    packets: usize,
}

impl<'a, 'd> PacketGrant<'a, 'd> {
    fn new(state: &'a RefCell<State<'d>>, handle: ConnHandle, packets: usize) -> Self {
        Self { state, handle, packets }
    }

    pub(crate) fn confirm(&mut self, sent: usize) {
        self.packets = self.packets.saturating_sub(sent);
    }
}

impl<'a, 'd> Drop for PacketGrant<'a, 'd> {
    fn drop(&mut self) {
        if self.packets > 0 {
            let mut state = self.state.borrow_mut();
            for storage in state.connections.iter_mut() {
                match storage.state {
                    ConnectionState::Connected if self.handle == storage.handle.unwrap() => {
                        storage.link_credits += self.packets;
                        storage.link_credit_waker.wake();
                        break;
                    }
                    _ => {}
                }
            }
            // make it an assert?
            warn!("[link] connection {:?} not found", self.handle);
        }
    }
}

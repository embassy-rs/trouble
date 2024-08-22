use core::cell::RefCell;
use core::future::poll_fn;
use core::task::{Context, Poll};

use bt_hci::param::{AddrKind, BdAddr, ConnHandle, DisconnectReason, LeConnRole};
use embassy_sync::waitqueue::WakerRegistration;

use crate::connection::Connection;
use crate::Error;

struct State<'d> {
    connections: &'d mut [ConnectionStorage],
    accept_waker: WakerRegistration,
    disconnect_waker: WakerRegistration,
    default_link_credits: usize,
}

impl<'d> State<'d> {
    fn print(&self, verbose: bool) {
        for (idx, storage) in self.connections.iter().enumerate() {
            if verbose || storage.state != ConnectionState::Disconnected {
                debug!("[link][idx = {}] state = {:?}", idx, storage);
            }
        }
    }

    fn inc_ref(&mut self, index: u8) {
        let state = &mut self.connections[index as usize];
        state.refcount = unwrap!(
            state.refcount.checked_add(1),
            "Too many references to the same connection"
        );
    }
}

pub(crate) struct ConnectionManager<'d> {
    state: RefCell<State<'d>>,
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
        }
    }

    pub(crate) fn role(&self, index: u8) -> LeConnRole {
        self.with_mut(|state| {
            let state = &mut state.connections[index as usize];
            state.role.unwrap()
        })
    }

    pub(crate) fn handle(&self, index: u8) -> ConnHandle {
        self.with_mut(|state| {
            let state = &mut state.connections[index as usize];
            state.handle.unwrap()
        })
    }

    pub(crate) fn is_connected(&self, index: u8) -> bool {
        self.with_mut(|state| {
            let state = &mut state.connections[index as usize];
            state.state == ConnectionState::Connected
        })
    }

    pub(crate) fn peer_address(&self, index: u8) -> BdAddr {
        self.with_mut(|state| {
            let state = &mut state.connections[index as usize];
            state.peer_addr.unwrap()
        })
    }

    pub(crate) fn set_att_mtu(&self, index: u8, mtu: u16) {
        self.with_mut(|state| {
            state.connections[index as usize].att_mtu = mtu;
        })
    }

    pub(crate) fn request_disconnect(&self, index: u8, reason: DisconnectReason) {
        self.with_mut(|state| {
            let entry = &mut state.connections[index as usize];
            if entry.state == ConnectionState::Connected {
                entry.state = ConnectionState::DisconnectRequest(reason);
                state.disconnect_waker.wake();
            }
        })
    }

    pub(crate) fn request_handle_disconnect(&self, handle: ConnHandle, reason: DisconnectReason) {
        self.with_mut(|state| {
            for entry in state.connections.iter_mut() {
                if entry.state == ConnectionState::Connected && Some(handle) == entry.handle {
                    entry.state = ConnectionState::DisconnectRequest(reason);
                    state.disconnect_waker.wake();
                    break;
                }
            }
        })
    }

    pub(crate) fn poll_disconnecting<'m>(&'m self, cx: Option<&mut Context<'_>>) -> Poll<DisconnectRequest<'m, 'd>> {
        let mut state = self.state.borrow_mut();
        if let Some(cx) = cx {
            state.disconnect_waker.register(cx.waker());
        }
        for (idx, storage) in state.connections.iter().enumerate() {
            if let ConnectionState::DisconnectRequest(reason) = storage.state {
                return Poll::Ready(DisconnectRequest {
                    index: idx,
                    handle: storage.handle.unwrap(),
                    reason,
                    state: &self.state,
                });
            }
        }
        Poll::Pending
    }

    pub(crate) fn get_connected_handle(&self, h: ConnHandle) -> Option<Connection<'_>> {
        let mut state = self.state.borrow_mut();
        for (index, storage) in state.connections.iter().enumerate() {
            match (storage.handle, &storage.state) {
                (Some(handle), ConnectionState::Connected) if handle == h => {
                    state.inc_ref(index as u8);
                    return Some(Connection::new(index as u8, self));
                }
                _ => {}
            }
        }
        None
    }

    pub(crate) fn is_handle_disconnected(&self, h: ConnHandle) -> bool {
        let mut state = self.state.borrow_mut();
        for storage in state.connections.iter_mut() {
            match (storage.handle, &storage.state) {
                (Some(handle), ConnectionState::Disconnected) if handle == h => {
                    return true;
                }
                _ => {}
            }
        }
        false
    }

    pub(crate) fn disconnected(&self, h: ConnHandle) -> Result<(), Error> {
        let mut state = self.state.borrow_mut();
        for (idx, storage) in state.connections.iter_mut().enumerate() {
            if let Some(handle) = storage.handle {
                if handle == h && storage.state != ConnectionState::Disconnected {
                    storage.state = ConnectionState::Disconnected;
                    return Ok(());
                }
            }
        }
        trace!("[link][disconnect] connection handle {:?} not found", h);
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
                storage.att_mtu = 23;
                storage.handle.replace(handle);
                storage.peer_addr_kind.replace(peer_addr_kind);
                storage.peer_addr.replace(peer_addr);
                storage.role.replace(role);
                state.accept_waker.wake();
                return Ok(());
            }
        }
        trace!("[link][connect] no available slot found for handle {:?}", handle);
        Err(Error::NotFound)
    }

    pub(crate) fn poll_accept(
        &self,
        role: LeConnRole,
        peers: &[(AddrKind, &BdAddr)],
        cx: Option<&mut Context<'_>>,
    ) -> Poll<Connection<'_>> {
        let mut state = self.state.borrow_mut();
        if let Some(cx) = cx {
            state.accept_waker.register(cx.waker());
        }
        for (idx, storage) in state.connections.iter_mut().enumerate() {
            if let ConnectionState::Connecting = storage.state {
                let handle = storage.handle.unwrap();
                let r = storage.role.unwrap();
                if r == role {
                    if !peers.is_empty() {
                        for peer in peers.iter() {
                            if storage.peer_addr_kind.unwrap() == peer.0 && &storage.peer_addr.unwrap() == peer.1 {
                                storage.state = ConnectionState::Connected;
                                trace!(
                                    "[link][poll_accept] connection handle {:?} in role {:?} accepted",
                                    handle,
                                    role
                                );
                                assert_eq!(storage.refcount, 0);
                                state.inc_ref(idx as u8);
                                return Poll::Ready(Connection::new(idx as u8, self));
                            }
                        }
                    } else {
                        storage.state = ConnectionState::Connected;
                        assert_eq!(storage.refcount, 0);
                        trace!(
                            "[link][poll_accept] connection handle {:?} in role {:?} accepted",
                            handle,
                            role
                        );

                        assert_eq!(storage.refcount, 0);
                        state.inc_ref(idx as u8);
                        return Poll::Ready(Connection::new(idx as u8, self));
                    }
                }
            }
        }
        Poll::Pending
    }

    fn with_mut<F: FnOnce(&mut State<'d>) -> R, R>(&self, f: F) -> R {
        let mut state = self.state.borrow_mut();
        f(&mut state)
    }

    pub(crate) fn log_status(&self, verbose: bool) {
        let state = self.state.borrow();
        state.print(verbose);
    }

    pub(crate) fn inc_ref(&self, index: u8) {
        self.with_mut(|state| {
            state.inc_ref(index);
        });
    }

    pub(crate) fn dec_ref(&self, index: u8) {
        self.with_mut(|state| {
            let state = &mut state.connections[index as usize];
            state.refcount = unwrap!(
                state.refcount.checked_sub(1),
                "bug: dropping a connection with refcount 0"
            );
            if state.refcount == 0 && state.state == ConnectionState::Connected {
                state.state = ConnectionState::DisconnectRequest(DisconnectReason::RemoteUserTerminatedConn);
            }
        });
    }

    pub(crate) async fn accept(&self, role: LeConnRole, peers: &[(AddrKind, &BdAddr)]) -> Connection<'_> {
        poll_fn(move |cx| self.poll_accept(role, peers, Some(cx))).await
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
        trace!("[link][pool_request_to_send] connection {:?} not found", handle);
        Poll::Ready(Err(Error::NotFound))
    }
}

pub(crate) trait DynamicConnectionManager {
    fn role(&self, index: u8) -> LeConnRole;
    fn is_connected(&self, index: u8) -> bool;
    fn handle(&self, index: u8) -> ConnHandle;
    fn peer_address(&self, index: u8) -> BdAddr;
    fn set_att_mtu(&self, index: u8, mtu: u16);
    fn inc_ref(&self, index: u8);
    fn dec_ref(&self, index: u8);
    fn disconnect(&self, index: u8, reason: DisconnectReason);
    fn get_att_mtu(&self, conn: ConnHandle) -> u16;
    fn exchange_att_mtu(&self, conn: ConnHandle, mtu: u16) -> u16;
    fn get_connected_handle(&self, h: ConnHandle) -> Option<Connection<'_>>;
}

impl<'d> DynamicConnectionManager for ConnectionManager<'d> {
    fn role(&self, index: u8) -> LeConnRole {
        ConnectionManager::role(self, index)
    }
    fn handle(&self, index: u8) -> ConnHandle {
        ConnectionManager::handle(self, index)
    }
    fn is_connected(&self, index: u8) -> bool {
        ConnectionManager::is_connected(self, index)
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
    fn set_att_mtu(&self, index: u8, mtu: u16) {
        ConnectionManager::set_att_mtu(self, index, mtu);
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

    fn get_connected_handle(&self, h: ConnHandle) -> Option<Connection<'_>> {
        ConnectionManager::get_connected_handle(self, h)
    }
}

pub struct DisconnectRequest<'a, 'd> {
    index: usize,
    handle: ConnHandle,
    reason: DisconnectReason,
    state: &'a RefCell<State<'d>>,
}

impl<'a, 'd> DisconnectRequest<'a, 'd> {
    pub fn handle(&self) -> ConnHandle {
        self.handle
    }

    pub fn reason(&self) -> DisconnectReason {
        self.reason
    }

    pub fn confirm(self) {
        let mut state = self.state.borrow_mut();
        state.connections[self.index].state = ConnectionState::Disconnecting(self.reason);
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
            "state = {}, conn = {}, flow = {}, role = {}, peer = {:02x}, ref = {}",
            self.state,
            self.handle,
            self.link_credits,
            self.role,
            self.peer_addr,
            self.refcount,
        );
    }
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ConnectionState {
    DisconnectRequest(DisconnectReason),
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
                        return;
                    }
                    _ => {}
                }
            }
            // make it an assert?
            warn!("[link] connection {:?} not found", self.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDR_1: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    const ADDR_2: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    #[test]
    fn peripheral_connection_established() {
        let mut storage = [ConnectionStorage::DISCONNECTED; 3];
        let mgr = ConnectionManager::new(&mut storage[..]);

        assert!(mgr.poll_accept(LeConnRole::Peripheral, &[], None).is_pending());

        unwrap!(mgr.connect(
            ConnHandle::new(0),
            AddrKind::RANDOM,
            BdAddr::new(ADDR_1),
            LeConnRole::Peripheral
        ));

        let Poll::Ready(handle) = mgr.poll_accept(LeConnRole::Peripheral, &[], None) else {
            panic!("expected connection to be accepted");
        };
        assert_eq!(handle.role(), LeConnRole::Peripheral);
        assert_eq!(handle.peer_address(), BdAddr::new(ADDR_1));

        handle.disconnect();
    }

    #[test]
    fn central_connection_established() {
        let mut storage = [ConnectionStorage::DISCONNECTED; 3];
        let mgr = ConnectionManager::new(&mut storage[..]);

        assert!(mgr.poll_accept(LeConnRole::Central, &[], None).is_pending());

        unwrap!(mgr.connect(
            ConnHandle::new(0),
            AddrKind::RANDOM,
            BdAddr::new(ADDR_2),
            LeConnRole::Central
        ));

        let Poll::Ready(handle) = mgr.poll_accept(LeConnRole::Central, &[], None) else {
            panic!("expected connection to be accepted");
        };
        assert_eq!(handle.role(), LeConnRole::Central);
        assert_eq!(handle.peer_address(), BdAddr::new(ADDR_2));
    }

    #[test]
    fn controller_disconnects_before_host() {
        let mut storage = [ConnectionStorage::DISCONNECTED; 3];
        let mgr = ConnectionManager::new(&mut storage[..]);

        unwrap!(mgr.connect(
            ConnHandle::new(3),
            AddrKind::RANDOM,
            BdAddr::new(ADDR_1),
            LeConnRole::Central
        ));

        unwrap!(mgr.connect(
            ConnHandle::new(2),
            AddrKind::RANDOM,
            BdAddr::new(ADDR_2),
            LeConnRole::Peripheral
        ));

        let Poll::Ready(central) = mgr.poll_accept(LeConnRole::Central, &[], None) else {
            panic!("expected connection to be accepted");
        };

        let Poll::Ready(peripheral) = mgr.poll_accept(LeConnRole::Peripheral, &[], None) else {
            panic!("expected connection to be accepted");
        };

        assert_eq!(ConnHandle::new(3), central.handle());
        assert_eq!(ConnHandle::new(2), peripheral.handle());

        // Disconnect request from us
        peripheral.disconnect();

        // Polling should return the disconnecting handle
        let Poll::Ready(req) = mgr.poll_disconnecting(None) else {
            panic!("expected connection to be accepted");
        };

        // If nothing happens, polling should behave the same way
        let Poll::Ready(req) = mgr.poll_disconnecting(None) else {
            panic!("expected connection to be accepted");
        };

        // Disconnection event from host arrives before we confirm
        unwrap!(mgr.disconnected(ConnHandle::new(2)));

        // This should be a noop
        req.confirm();

        // Polling should not return anything
        assert!(mgr.poll_disconnecting(None).is_pending());
    }

    #[test]
    fn controller_disconnects_after_host() {
        let mut storage = [ConnectionStorage::DISCONNECTED; 3];
        let mgr = ConnectionManager::new(&mut storage[..]);

        unwrap!(mgr.connect(
            ConnHandle::new(3),
            AddrKind::RANDOM,
            BdAddr::new(ADDR_1),
            LeConnRole::Central
        ));

        unwrap!(mgr.connect(
            ConnHandle::new(2),
            AddrKind::RANDOM,
            BdAddr::new(ADDR_2),
            LeConnRole::Peripheral
        ));

        let Poll::Ready(central) = mgr.poll_accept(LeConnRole::Central, &[], None) else {
            panic!("expected connection to be accepted");
        };

        let Poll::Ready(peripheral) = mgr.poll_accept(LeConnRole::Peripheral, &[], None) else {
            panic!("expected connection to be accepted");
        };

        assert_eq!(ConnHandle::new(3), central.handle());
        assert_eq!(ConnHandle::new(2), peripheral.handle());

        // Disconnect request from us
        peripheral.disconnect();

        // Polling should return the disconnecting handle
        let Poll::Ready(req) = mgr.poll_disconnecting(None) else {
            panic!("expected connection to be accepted");
        };

        // This should remove it from the list
        req.confirm();

        // Polling should not return anything
        assert!(mgr.poll_disconnecting(None).is_pending());

        // Disconnection event from host arrives before we confirm
        unwrap!(mgr.disconnected(ConnHandle::new(2)));

        // Polling should not return anything
        assert!(mgr.poll_disconnecting(None).is_pending());
    }

    #[test]
    fn referenced_handle_not_reused() {
        let mut storage = [ConnectionStorage::DISCONNECTED; 3];
        let mgr = ConnectionManager::new(&mut storage[..]);

        assert!(mgr.poll_accept(LeConnRole::Peripheral, &[], None).is_pending());

        let handle = ConnHandle::new(42);
        unwrap!(mgr.connect(handle, AddrKind::RANDOM, BdAddr::new(ADDR_1), LeConnRole::Peripheral));

        let Poll::Ready(conn) = mgr.poll_accept(LeConnRole::Peripheral, &[], None) else {
            panic!("expected connection to be accepted");
        };
        assert_eq!(conn.role(), LeConnRole::Peripheral);
        assert_eq!(conn.peer_address(), BdAddr::new(ADDR_1));

        unwrap!(mgr.disconnected(handle));

        // New incoming connection reusing handle
        let handle = ConnHandle::new(42);
        unwrap!(mgr.connect(handle, AddrKind::RANDOM, BdAddr::new(ADDR_2), LeConnRole::Peripheral));

        let Poll::Ready(conn2) = mgr.poll_accept(LeConnRole::Peripheral, &[], None) else {
            panic!("expected connection to be accepted");
        };

        // Ensure existing connection doesnt panic things
        assert_eq!(conn.handle(), ConnHandle::new(42));
        assert_eq!(conn.role(), LeConnRole::Peripheral);
        assert_eq!(conn.peer_address(), BdAddr::new(ADDR_1));
        assert!(!conn.is_connected());

        assert_eq!(conn2.handle(), ConnHandle::new(42));
        assert_eq!(conn2.role(), LeConnRole::Peripheral);
        assert_eq!(conn2.peer_address(), BdAddr::new(ADDR_2));
        assert!(conn2.is_connected());
    }

    #[test]
    fn disconnect_correct_handle() {
        let mut storage = [ConnectionStorage::DISCONNECTED; 3];
        let mgr = ConnectionManager::new(&mut storage[..]);

        assert!(mgr.poll_accept(LeConnRole::Peripheral, &[], None).is_pending());

        let handle = ConnHandle::new(42);
        unwrap!(mgr.connect(handle, AddrKind::RANDOM, BdAddr::new(ADDR_1), LeConnRole::Peripheral));

        let Poll::Ready(conn) = mgr.poll_accept(LeConnRole::Peripheral, &[], None) else {
            panic!("expected connection to be accepted");
        };
        assert_eq!(conn.role(), LeConnRole::Peripheral);
        assert_eq!(conn.peer_address(), BdAddr::new(ADDR_1));

        unwrap!(mgr.disconnected(handle));

        // New incoming connection reusing handle
        let handle = ConnHandle::new(42);
        unwrap!(mgr.connect(handle, AddrKind::RANDOM, BdAddr::new(ADDR_2), LeConnRole::Peripheral));

        let Poll::Ready(conn2) = mgr.poll_accept(LeConnRole::Peripheral, &[], None) else {
            panic!("expected connection to be accepted");
        };

        assert_eq!(conn2.handle(), ConnHandle::new(42));
        assert_eq!(conn2.role(), LeConnRole::Peripheral);
        assert_eq!(conn2.peer_address(), BdAddr::new(ADDR_2));
        assert!(conn2.is_connected());

        unwrap!(mgr.disconnected(handle));

        assert!(!conn2.is_connected());
    }

    #[test]
    fn disconnecting_iterator_invalid() {
        let mut storage = [ConnectionStorage::DISCONNECTED; 3];
        let mgr = ConnectionManager::new(&mut storage[..]);

        assert!(mgr.poll_accept(LeConnRole::Peripheral, &[], None).is_pending());

        unwrap!(mgr.connect(
            ConnHandle::new(3),
            AddrKind::RANDOM,
            BdAddr::new(ADDR_1),
            LeConnRole::Peripheral
        ));

        let Poll::Ready(handle) = mgr.poll_accept(LeConnRole::Peripheral, &[], None) else {
            panic!("expected connection to be accepted");
        };
        assert_eq!(handle.role(), LeConnRole::Peripheral);
        assert_eq!(handle.peer_address(), BdAddr::new(ADDR_1));

        assert!(mgr.poll_disconnecting(None).is_pending());

        // Disconnect request from us
        drop(handle);

        // Polling should return the disconnecting handle
        let Poll::Ready(req) = mgr.poll_disconnecting(None) else {
            panic!("expected connection to be accepted");
        };

        //        unwrap!(mgr.disconnected(ConnHandle::new(3)));

        req.confirm();

        assert!(mgr.poll_disconnecting(None).is_pending());
    }
}

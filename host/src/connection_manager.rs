use core::cell::RefCell;
use core::future::poll_fn;
use core::task::{Context, Poll};

use bt_hci::param::{AddrKind, BdAddr, ConnHandle, DisconnectReason, LeConnRole, Status};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::waitqueue::WakerRegistration;

use crate::connection::{Connection, ConnectionEvent};
use crate::packet_pool::GlobalPacketPool;
use crate::packet_pool::Packet;
use crate::packet_pool::ATT_ID;
use crate::pdu::Pdu;
use crate::{config, Error};

struct State<'d> {
    connections: &'d mut [ConnectionStorage],
    central_waker: WakerRegistration,
    peripheral_waker: WakerRegistration,
    disconnect_waker: WakerRegistration,
    default_link_credits: usize,
    default_att_mtu: u16,
}

impl State<'_> {
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

pub(crate) type EventChannel<'d> = Channel<NoopRawMutex, ConnectionEvent<'d>, { config::CONNECTION_EVENT_QUEUE_SIZE }>;

pub(crate) struct ConnectionManager<'d> {
    state: RefCell<State<'d>>,
    events: &'d mut [EventChannel<'d>],
    outbound: Channel<NoopRawMutex, (ConnHandle, Pdu<'d>), { config::L2CAP_TX_QUEUE_SIZE }>,
    #[cfg(feature = "gatt")]
    tx_pool: &'d dyn GlobalPacketPool<'d>,
}

impl<'d> ConnectionManager<'d> {
    pub(crate) fn new(
        connections: &'d mut [ConnectionStorage],
        events: &'d mut [EventChannel<'d>],
        #[cfg(feature = "gatt")] tx_pool: &'d dyn GlobalPacketPool<'d>,
    ) -> Self {
        Self {
            state: RefCell::new(State {
                connections,
                central_waker: WakerRegistration::new(),
                peripheral_waker: WakerRegistration::new(),
                disconnect_waker: WakerRegistration::new(),
                default_link_credits: 0,
                default_att_mtu: 23,
            }),
            events,
            outbound: Channel::new(),
            #[cfg(feature = "gatt")]
            tx_pool,
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

    pub(crate) async fn next(&self, index: u8) -> ConnectionEvent<'d> {
        self.events[index as usize].receive().await
    }

    pub(crate) async fn post_event(&self, index: u8, event: ConnectionEvent<'d>) {
        self.events[index as usize].send(event).await
    }

    pub(crate) fn post_handle_event(&self, handle: ConnHandle, event: ConnectionEvent<'d>) -> Result<(), Error> {
        self.with_mut(|state| {
            for (index, entry) in state.connections.iter().enumerate() {
                if entry.state == ConnectionState::Connected && Some(handle) == entry.handle {
                    return self.events[index as usize]
                        .try_send(event)
                        .map_err(|_| Error::OutOfMemory);
                }
            }
            Err(Error::NotFound)
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

    pub(crate) fn get_connected_handle(&'d self, h: ConnHandle) -> Option<Connection<'d>> {
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

    pub(crate) fn with_connected_handle<F: FnOnce(&mut ConnectionStorage) -> Result<(), Error>>(
        &self,
        h: ConnHandle,
        f: F,
    ) -> Result<(), Error> {
        let mut state = self.state.borrow_mut();
        for storage in state.connections.iter_mut() {
            match (storage.handle, &storage.state) {
                (Some(handle), ConnectionState::Connected) if handle == h => {
                    return f(storage);
                }
                (Some(handle), ConnectionState::Connecting) if handle == h => {
                    return f(storage);
                }
                _ => {}
            }
        }
        Err(Error::Disconnected)
    }

    pub(crate) fn received(&self, h: ConnHandle) -> Result<(), Error> {
        self.with_connected_handle(h, |storage| {
            #[cfg(feature = "connection-metrics")]
            storage.metrics.received(1);
            Ok(())
        })
    }

    pub(crate) fn is_handle_connected(&self, h: ConnHandle) -> bool {
        self.with_connected_handle(h, |_storage| Ok(())).is_ok()
    }

    pub(crate) fn disconnected(&self, h: ConnHandle, reason: Status) -> Result<(), Error> {
        let mut state = self.state.borrow_mut();
        for (idx, storage) in state.connections.iter_mut().enumerate() {
            if Some(h) == storage.handle && storage.state != ConnectionState::Disconnected {
                storage.state = ConnectionState::Disconnected;
                let _ = self.events[idx].try_send(ConnectionEvent::Disconnected { reason });
                #[cfg(feature = "connection-metrics")]
                storage.metrics.reset();
                return Ok(());
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
        let default_att_mtu = state.default_att_mtu;
        for (idx, storage) in state.connections.iter_mut().enumerate() {
            if ConnectionState::Disconnected == storage.state && storage.refcount == 0 {
                self.events[idx].clear();
                storage.state = ConnectionState::Connecting;
                storage.link_credits = default_credits;
                storage.att_mtu = default_att_mtu;
                storage.handle.replace(handle);
                storage.peer_addr_kind.replace(peer_addr_kind);
                storage.peer_addr.replace(peer_addr);
                storage.role.replace(role);
                match role {
                    LeConnRole::Central => {
                        state.central_waker.wake();
                    }
                    LeConnRole::Peripheral => {
                        state.peripheral_waker.wake();
                    }
                }
                return Ok(());
            }
        }
        trace!("[link][connect] no available slot found for handle {:?}", handle);
        Err(Error::NotFound)
    }

    pub(crate) fn poll_accept(
        &'d self,
        role: LeConnRole,
        peers: &[(AddrKind, &BdAddr)],
        cx: Option<&mut Context<'_>>,
    ) -> Poll<Connection<'d>> {
        let mut state = self.state.borrow_mut();
        if let Some(cx) = cx {
            match role {
                LeConnRole::Central => {
                    state.central_waker.register(cx.waker());
                }
                LeConnRole::Peripheral => {
                    state.peripheral_waker.register(cx.waker());
                }
            }
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

    pub(crate) async fn accept(&'d self, role: LeConnRole, peers: &[(AddrKind, &BdAddr)]) -> Connection<'d> {
        poll_fn(|cx| self.poll_accept(role, peers, Some(cx))).await
    }

    pub(crate) fn set_link_credits(&self, credits: usize) {
        let mut state = self.state.borrow_mut();
        state.default_link_credits = credits;
        for storage in state.connections.iter_mut() {
            storage.link_credits = credits;
        }
    }

    pub(crate) fn set_default_att_mtu(&self, att_mtu: u16) {
        let mut state = self.state.borrow_mut();
        state.default_att_mtu = att_mtu;
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

    pub(crate) fn get_att_mtu(&self, index: u8) -> u16 {
        self.with_mut(|state| state.connections[index as usize].att_mtu)
    }

    pub(crate) async fn send(&self, index: u8, pdu: Pdu<'d>) {
        let handle = self.with_mut(|state| state.connections[index as usize].handle.unwrap());
        self.outbound.send((handle, pdu)).await
    }

    #[cfg(feature = "gatt")]
    pub(crate) fn alloc_tx(&self) -> Result<Packet<'d>, Error> {
        self.tx_pool.alloc(ATT_ID).ok_or(Error::OutOfMemory)
    }

    pub(crate) fn try_send(&self, index: u8, pdu: Pdu<'d>) -> Result<(), Error> {
        let handle = self.with_mut(|state| state.connections[index as usize].handle.unwrap());
        self.outbound.try_send((handle, pdu)).map_err(|_| Error::OutOfMemory)
    }

    pub(crate) fn try_outbound(&self, handle: ConnHandle, pdu: Pdu<'d>) -> Result<(), Error> {
        self.outbound.try_send((handle, pdu)).map_err(|_| Error::OutOfMemory)
    }

    pub(crate) async fn outbound(&self) -> (ConnHandle, Pdu<'d>) {
        self.outbound.receive().await
    }

    pub(crate) fn get_att_mtu_handle(&self, conn: ConnHandle) -> u16 {
        let mut state = self.state.borrow_mut();
        for storage in state.connections.iter_mut() {
            match storage.state {
                ConnectionState::Connected if storage.handle.unwrap() == conn => {
                    return storage.att_mtu;
                }
                _ => {}
            }
        }
        state.default_att_mtu
    }

    pub(crate) fn exchange_att_mtu(&self, conn: ConnHandle, mtu: u16) -> u16 {
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

pub struct DisconnectRequest<'a, 'd> {
    index: usize,
    handle: ConnHandle,
    reason: DisconnectReason,
    state: &'a RefCell<State<'d>>,
}

impl DisconnectRequest<'_, '_> {
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
    #[cfg(feature = "connection-metrics")]
    pub metrics: Metrics,
}

#[cfg(feature = "connection-metrics")]
#[derive(Debug)]
pub struct Metrics {
    pub num_sent: usize,
    pub num_received: usize,
    pub last_sent: embassy_time::Instant,
    pub last_received: embassy_time::Instant,
}

#[cfg(feature = "connection-metrics")]
impl Metrics {
    pub const fn new() -> Self {
        Self {
            num_sent: 0,
            num_received: 0,
            last_sent: embassy_time::Instant::MIN,
            last_received: embassy_time::Instant::MIN,
        }
    }
    pub fn sent(&mut self, num: usize) {
        self.num_sent = self.num_sent.wrapping_add(num);
        self.last_sent = embassy_time::Instant::now();
    }

    pub fn received(&mut self, num: usize) {
        self.num_received = self.num_received.wrapping_add(num);
        self.last_received = embassy_time::Instant::now();
    }

    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

#[cfg(feature = "connection-metrics")]
#[cfg(feature = "defmt")]
impl defmt::Format for Metrics {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(
            f,
            "sent = {}, since_sent = {} ms, recvd = {}, since_recvd = {} ms",
            self.num_sent,
            self.last_sent.elapsed().as_millis(),
            self.num_received,
            self.last_received.elapsed().as_millis(),
        );
    }
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
        #[cfg(feature = "connection-metrics")]
        metrics: Metrics::new(),
    };
}

#[cfg(feature = "defmt")]
impl defmt::Format for ConnectionStorage {
    fn format(&self, f: defmt::Formatter<'_>) {
        #[cfg(feature = "connection-metrics")]
        defmt::write!(
            f,
            "state = {}, conn = {}, flow = {}, role = {}, peer = {:02x}, ref = {}, {}",
            self.state,
            self.handle,
            self.link_credits,
            self.role,
            self.peer_addr,
            self.refcount,
            self.metrics
        );

        #[cfg(not(feature = "connection-metrics"))]
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
        #[cfg(feature = "connection-metrics")]
        {
            let mut state = self.state.borrow_mut();
            for storage in state.connections.iter_mut() {
                match storage.state {
                    ConnectionState::Connected if self.handle == storage.handle.unwrap() => {
                        storage.metrics.sent(sent);
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
}

impl Drop for PacketGrant<'_, '_> {
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
    use crate::{prelude::PacketPool, PacketQos};

    use super::*;
    extern crate std;
    use std::boxed::Box;

    use embassy_futures::block_on;

    const ADDR_1: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    const ADDR_2: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    fn setup() -> &'static ConnectionManager<'static> {
        let storage = Box::leak(Box::new([ConnectionStorage::DISCONNECTED; 3]));
        let events = Box::leak(Box::new([const { EventChannel::new() }; 3]));
        let pool = Box::leak(Box::new(PacketPool::<NoopRawMutex, 27, 8, 1>::new(PacketQos::None)));
        let mgr = ConnectionManager::new(&mut storage[..], &mut events[..], pool);
        Box::leak(Box::new(mgr))
    }

    #[test]
    fn peripheral_connection_established() {
        let mgr = setup();
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
        let mgr = setup();

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
        let mgr = setup();

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
        unwrap!(mgr.disconnected(ConnHandle::new(2), Status::UNSPECIFIED));

        // This should be a noop
        req.confirm();

        // Polling should not return anything
        assert!(mgr.poll_disconnecting(None).is_pending());
    }

    #[test]
    fn controller_disconnects_after_host() {
        let mgr = setup();

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
        unwrap!(mgr.disconnected(ConnHandle::new(2), Status::UNSPECIFIED));

        // Check that we get an event
        assert!(matches!(
            block_on(peripheral.next()),
            ConnectionEvent::Disconnected {
                reason: Status::UNSPECIFIED
            }
        ));

        // Polling should not return anything
        assert!(mgr.poll_disconnecting(None).is_pending());
    }

    #[test]
    fn referenced_handle_not_reused() {
        let mgr = setup();

        assert!(mgr.poll_accept(LeConnRole::Peripheral, &[], None).is_pending());

        let handle = ConnHandle::new(42);
        unwrap!(mgr.connect(handle, AddrKind::RANDOM, BdAddr::new(ADDR_1), LeConnRole::Peripheral));

        let Poll::Ready(conn) = mgr.poll_accept(LeConnRole::Peripheral, &[], None) else {
            panic!("expected connection to be accepted");
        };
        assert_eq!(conn.role(), LeConnRole::Peripheral);
        assert_eq!(conn.peer_address(), BdAddr::new(ADDR_1));

        unwrap!(mgr.disconnected(handle, Status::UNSPECIFIED));

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
        let mgr = setup();

        assert!(mgr.poll_accept(LeConnRole::Peripheral, &[], None).is_pending());

        let handle = ConnHandle::new(42);
        unwrap!(mgr.connect(handle, AddrKind::RANDOM, BdAddr::new(ADDR_1), LeConnRole::Peripheral));

        let Poll::Ready(conn) = mgr.poll_accept(LeConnRole::Peripheral, &[], None) else {
            panic!("expected connection to be accepted");
        };
        assert_eq!(conn.role(), LeConnRole::Peripheral);
        assert_eq!(conn.peer_address(), BdAddr::new(ADDR_1));

        unwrap!(mgr.disconnected(handle, Status::UNSPECIFIED));

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

        unwrap!(mgr.disconnected(handle, Status::UNSPECIFIED));

        assert!(!conn2.is_connected());
    }

    #[test]
    fn disconnecting_iterator_invalid() {
        let mgr = setup();

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

    #[test]
    fn nonexisting_handle_is_disconnected() {
        let mgr = setup();

        assert!(!mgr.is_handle_connected(ConnHandle::new(5)));

        unwrap!(mgr.connect(
            ConnHandle::new(3),
            AddrKind::RANDOM,
            BdAddr::new(ADDR_1),
            LeConnRole::Peripheral
        ));

        assert!(mgr.is_handle_connected(ConnHandle::new(3)));

        let Poll::Ready(handle) = mgr.poll_accept(LeConnRole::Peripheral, &[], None) else {
            panic!("expected connection to be accepted");
        };

        assert!(mgr.is_handle_connected(ConnHandle::new(3)));

        handle.disconnect();

        assert!(!mgr.is_handle_connected(ConnHandle::new(3)));
    }
}

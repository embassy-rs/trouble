use core::cell::RefCell;
use core::future::poll_fn;
#[cfg(feature = "security")]
use core::future::Future;
use core::task::{Context, Poll};

use bt_hci::param::{AddrKind, BdAddr, ConnHandle, DisconnectReason, LeConnRole, Status};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::waitqueue::WakerRegistration;
#[cfg(feature = "security")]
use embassy_time::TimeoutError;

use crate::connection::{Connection, ConnectionEventData};
#[cfg(feature = "gatt")]
use crate::packet_pool::{Packet, Pool};
use crate::pdu::Pdu;
#[cfg(feature = "security")]
use crate::security_manager::{SecurityEventData, SecurityManager};
use crate::{config, Error};

struct State<'d> {
    connections: &'d mut [ConnectionStorage],
    central_waker: WakerRegistration,
    peripheral_waker: WakerRegistration,
    disconnect_waker: WakerRegistration,
    #[cfg(feature = "controller-host-flow-control")]
    completed_packets_waker: WakerRegistration,
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

pub(crate) struct EventChannel {
    chan: Channel<NoopRawMutex, ConnectionEventData, { config::CONNECTION_EVENT_QUEUE_SIZE }>,
}

impl EventChannel {
    #[allow(clippy::declare_interior_mutable_const)]
    pub(crate) const NEW: EventChannel = EventChannel { chan: Channel::new() };

    pub async fn receive(&self) -> ConnectionEventData {
        self.chan.receive().await
    }

    pub async fn send(&self, event: ConnectionEventData) {
        self.chan.send(event).await;
    }

    pub fn try_send(&self, event: ConnectionEventData) -> Result<(), Error> {
        self.chan.try_send(event).map_err(|_| Error::OutOfMemory)
    }

    pub fn clear(&self) {
        self.chan.clear();
    }
}

pub(crate) struct ConnectionManager<'d> {
    state: RefCell<State<'d>>,
    events: &'d mut [EventChannel],
    outbound: Channel<NoopRawMutex, (ConnHandle, Pdu), { config::L2CAP_TX_QUEUE_SIZE }>,
    #[cfg(feature = "gatt")]
    tx_pool: &'d dyn Pool,
    #[cfg(feature = "security")]
    pub(crate) security_manager: SecurityManager<{ crate::BI_COUNT }>,
}

impl<'d> ConnectionManager<'d> {
    pub(crate) fn new(
        connections: &'d mut [ConnectionStorage],
        events: &'d mut [EventChannel],
        default_att_mtu: u16,
        #[cfg(feature = "gatt")] tx_pool: &'d dyn Pool,
    ) -> Self {
        Self {
            state: RefCell::new(State {
                connections,
                central_waker: WakerRegistration::new(),
                peripheral_waker: WakerRegistration::new(),
                disconnect_waker: WakerRegistration::new(),
                #[cfg(feature = "controller-host-flow-control")]
                completed_packets_waker: WakerRegistration::new(),
                default_link_credits: 0,
                default_att_mtu,
            }),
            events,
            outbound: Channel::new(),
            #[cfg(feature = "gatt")]
            tx_pool,
            #[cfg(feature = "security")]
            security_manager: SecurityManager::new(),
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

    pub(crate) async fn next(&self, index: u8) -> ConnectionEventData {
        self.events[index as usize].receive().await
    }

    pub(crate) async fn post_event(&self, index: u8, event: ConnectionEventData) {
        self.events[index as usize].send(event).await
    }

    pub(crate) fn post_handle_event(&self, handle: ConnHandle, event: ConnectionEventData) -> Result<(), Error> {
        let index = self.with_mut(|state| {
            for (index, entry) in state.connections.iter().enumerate() {
                if entry.state == ConnectionState::Connected && Some(handle) == entry.handle {
                    return Ok(index);
                }
            }
            Err(Error::NotFound)
        })?;
        self.events[index].try_send(event).map_err(|_| Error::OutOfMemory)
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

    pub(crate) fn completed_packets(&self, _handle: ConnHandle, _amount: u16) {
        #[cfg(feature = "controller-host-flow-control")]
        self.with_mut(|state| {
            let handle = _handle;
            let amount = _amount;
            for entry in state.connections.iter_mut() {
                if entry.state == ConnectionState::Connected && Some(handle) == entry.handle {
                    entry.completed_packets += amount;
                    state.completed_packets_waker.wake();
                    break;
                }
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

    pub(crate) fn poll_completed_packets<'m>(
        &'m self,
        _cursor: usize,
        _cx: Option<&mut Context<'_>>,
    ) -> Poll<CompletedPackets<'m, 'd>> {
        #[cfg(feature = "controller-host-flow-control")]
        {
            let cursor = _cursor;
            let cx = _cx;
            let mut state = self.state.borrow_mut();
            if let Some(cx) = cx {
                state.completed_packets_waker.register(cx.waker());
            }
            let mut pos = cursor;
            let end = if pos > 0 { pos - 1 } else { state.connections.len() - 1 };

            loop {
                let next = (pos + 1) % state.connections.len();
                let storage = &state.connections[pos];
                if let ConnectionState::Connected = storage.state {
                    if storage.completed_packets > 0 {
                        return Poll::Ready(CompletedPackets {
                            index: pos,
                            handle: storage.handle.unwrap(),
                            amount: storage.completed_packets,
                            state: &self.state,
                        });
                    }
                }
                if pos == end {
                    break;
                }
                pos = next;
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
                let _ = self.events[idx].try_send(ConnectionEventData::Disconnected { reason });
                #[cfg(feature = "connection-metrics")]
                storage.metrics.reset();
                #[cfg(feature = "security")]
                {
                    storage.encrypted = false;
                    let _ = self.security_manager.disconnect(h);
                }
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
                #[cfg(feature = "controller-host-flow-control")]
                {
                    storage.completed_packets = 0;
                }
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
                        #[cfg(feature = "connection-metrics")]
                        storage.metrics.blocked_send();

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

    pub(crate) async fn send(&self, index: u8, pdu: Pdu) {
        let handle = self.with_mut(|state| state.connections[index as usize].handle.unwrap());
        self.outbound.send((handle, pdu)).await
    }

    #[cfg(feature = "gatt")]
    pub(crate) fn alloc_tx(&self) -> Result<Packet, Error> {
        self.tx_pool.alloc().ok_or(Error::OutOfMemory)
    }

    pub(crate) fn try_send(&self, index: u8, pdu: Pdu) -> Result<(), Error> {
        let handle = self.with_mut(|state| state.connections[index as usize].handle.unwrap());
        self.outbound.try_send((handle, pdu)).map_err(|_| Error::OutOfMemory)
    }

    pub(crate) fn try_outbound(&self, handle: ConnHandle, pdu: Pdu) -> Result<(), Error> {
        self.outbound.try_send((handle, pdu)).map_err(|_| Error::OutOfMemory)
    }

    pub(crate) async fn outbound(&self) -> (ConnHandle, Pdu) {
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

    pub(crate) fn get_encrypted(&self, index: u8) -> bool {
        #[cfg(feature = "security")]
        {
            self.state.borrow().connections[index as usize].encrypted
        }
        #[cfg(not(feature = "security"))]
        false
    }

    pub(crate) fn handle_security_channel(
        &self,
        handle: ConnHandle,
        packet: &crate::packet_pool::Packet,
        payload_size: usize,
    ) -> Result<(), Error> {
        #[cfg(feature = "security")]
        {
            let state = self.state.borrow();
            for storage in state.connections.iter() {
                match storage.state {
                    ConnectionState::Connected if storage.handle.unwrap() == handle => {
                        if let Err(error) = self.security_manager.handle(packet, payload_size, self, storage) {
                            error!("Failed to handle security manager packet, {:?}", error);
                            return Err(error);
                        }
                    }
                    _ => (),
                }
            }
        }
        Ok(())
    }

    pub(crate) fn handle_security_hci_event(&self, event: bt_hci::event::Event) -> Result<(), Error> {
        #[cfg(feature = "security")]
        {
            self.security_manager.handle_event(&event)?;

            if let bt_hci::event::Event::EncryptionChangeV1(event_data) = event {
                self.with_connected_handle(event_data.handle, |storage| {
                    storage.encrypted = event_data.enabled;
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    #[cfg(feature = "security")]
    pub(crate) async fn handle_security_event<'h, C>(
        &self,
        host: &crate::host::BleHost<'h, C>,
        _event: crate::security_manager::SecurityEventData,
    ) -> Result<(), crate::BleHostError<C::Error>>
    where
        C: crate::ControllerCmdSync<bt_hci::cmd::le::LeLongTermKeyRequestReply>
            + crate::ControllerCmdAsync<bt_hci::cmd::le::LeEnableEncryption>
            + crate::ControllerCmdSync<bt_hci::cmd::link_control::Disconnect>,
    {
        use bt_hci::cmd::le::{LeEnableEncryption, LeLongTermKeyRequestReply};
        use bt_hci::cmd::link_control::Disconnect;

        match _event {
            crate::security_manager::SecurityEventData::SendLongTermKey(handle) => {
                let conn_info = self.state.borrow().connections.iter().find_map(|connection| {
                    match (connection.handle, connection.peer_addr, connection.peer_addr_kind) {
                        (Some(connection_handle), Some(addr), Some(kind)) => {
                            if handle == connection_handle {
                                Some((connection_handle, crate::Address { addr, kind }))
                            } else {
                                None
                            }
                        }
                        (_, _, _) => None,
                    }
                });

                if let Some((conn, address)) = conn_info {
                    if let Some(ltk) = self.security_manager.get_peer_long_term_key(address) {
                        let _ = host
                            .command(LeLongTermKeyRequestReply::new(handle, ltk.to_le_bytes()))
                            .await?;
                    } else {
                        warn!("[host] Long term key request reply failed, no long term key");
                        // Send disconnect event to the controller
                        host.command(Disconnect::new(conn, DisconnectReason::AuthenticationFailure))
                            .await?;
                        unwrap!(self.disconnected(conn, Status::AUTHENTICATION_FAILURE));
                    }
                } else {
                    warn!("[host] Long term key request reply failed, unknown peer")
                }
            }
            crate::security_manager::SecurityEventData::EnableEncryption(handle, bond_info) => {
                let connection_data =
                    self.state
                        .borrow()
                        .connections
                        .iter()
                        .enumerate()
                        .find_map(|(index, connection)| {
                            match (connection.handle, connection.peer_addr, connection.peer_addr_kind) {
                                (Some(connection_handle), Some(addr), Some(kind)) => {
                                    if handle == connection_handle {
                                        Some((index, connection.role, crate::Address { addr, kind }))
                                    } else {
                                        None
                                    }
                                }
                                (_, _, _) => None,
                            }
                        });
                if let Some((index, role, address)) = connection_data {
                    if let Some(ltk) = self.security_manager.get_peer_long_term_key(address) {
                        if let Some(LeConnRole::Central) = role {
                            host.async_command(LeEnableEncryption::new(handle, [0; 8], 0, ltk.to_le_bytes()))
                                .await?;
                        }
                        // Emit the bonded event after enabling encryption
                        self.post_event(index as u8, ConnectionEventData::Bonded { bond_info })
                            .await;
                    } else {
                        warn!("[host] Enable encryption failed, no long term key")
                    }
                } else {
                    warn!("[host] Enable encryption failed, unknown peer")
                }
            }
            crate::security_manager::SecurityEventData::Timeout => {
                warn!("[host] Pairing timeout");
                self.security_manager.cancel_timeout()?;
            }
            crate::security_manager::SecurityEventData::TimerChange => (),
        }
        Ok(())
    }

    #[cfg(feature = "security")]
    pub(crate) fn poll_security_events(
        &self,
    ) -> impl Future<Output = Result<SecurityEventData, TimeoutError>> + use<'_> {
        self.security_manager.poll_events()
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

pub(crate) struct CompletedPackets<'a, 'd> {
    state: &'a RefCell<State<'d>>,
    handle: ConnHandle,
    amount: u16,
    index: usize,
}

#[cfg(feature = "controller-host-flow-control")]
impl CompletedPackets<'_, '_> {
    pub(crate) fn amount(&self) -> u16 {
        self.amount
    }

    pub(crate) fn handle(&self) -> ConnHandle {
        self.handle
    }

    pub(crate) fn confirm(self) -> usize {
        let mut state = self.state.borrow_mut();
        let connection = &mut state.connections[self.index];
        if connection.state == ConnectionState::Connected && connection.handle == Some(self.handle) {
            connection.completed_packets = connection.completed_packets.saturating_sub(self.amount);
        }

        (self.index + 1) % state.connections.len()
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
    #[cfg(feature = "controller-host-flow-control")]
    pub completed_packets: u16,
    pub refcount: u8,
    #[cfg(feature = "connection-metrics")]
    pub metrics: Metrics,
    #[cfg(feature = "security")]
    pub encrypted: bool,
}

#[cfg(feature = "connection-metrics")]
#[derive(Debug)]
pub struct Metrics {
    pub num_sent: usize,
    pub num_received: usize,
    pub last_sent: embassy_time::Instant,
    pub last_received: embassy_time::Instant,
    pub blocked_sends: usize,
}

#[cfg(feature = "connection-metrics")]
impl Metrics {
    pub const fn new() -> Self {
        Self {
            num_sent: 0,
            num_received: 0,
            last_sent: embassy_time::Instant::MIN,
            last_received: embassy_time::Instant::MIN,
            blocked_sends: 0,
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

    pub fn blocked_send(&mut self) {
        self.blocked_sends = self.blocked_sends.wrapping_add(1);
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
            "sent = {}, since_sent = {} ms, recvd = {}, since_recvd = {} ms, blocked sends = {}",
            self.num_sent,
            self.last_sent.elapsed().as_millis(),
            self.num_received,
            self.last_received.elapsed().as_millis(),
            self.blocked_sends,
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
        #[cfg(feature = "controller-host-flow-control")]
        completed_packets: 0,
        link_credit_waker: WakerRegistration::new(),
        refcount: 0,
        #[cfg(feature = "connection-metrics")]
        metrics: Metrics::new(),
        #[cfg(feature = "security")]
        encrypted: false,
    };
}

#[cfg(feature = "defmt")]
impl defmt::Format for ConnectionStorage {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(
            f,
            "state = {}, conn = {}, flow = {}",
            self.state,
            self.handle,
            self.link_credits,
        );

        #[cfg(feature = "controller-host-flow-control")]
        defmt::write!(f, ", completed = {}", self.completed_packets);
        defmt::write!(
            f,
            ", role = {}, peer = {:02x}, ref = {}",
            self.role,
            self.peer_addr,
            self.refcount
        );

        #[cfg(feature = "connection-metrics")]
        defmt::write!(", {}", self.metrics);
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
    use super::*;
    use crate::prelude::PacketPool;
    extern crate std;
    use std::boxed::Box;

    use embassy_futures::block_on;

    const ADDR_1: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    const ADDR_2: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    fn setup() -> &'static ConnectionManager<'static> {
        let storage = Box::leak(Box::new([ConnectionStorage::DISCONNECTED; 3]));
        let events = Box::leak(Box::new([EventChannel::NEW; 3]));
        let pool = Box::leak(Box::new(PacketPool::<27, 8>::new()));
        let mgr = ConnectionManager::new(&mut storage[..], &mut events[..], 23, pool);
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
        use crate::connection::ConnectionEvent;
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

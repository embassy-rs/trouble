use core::cell::{Ref, RefCell, RefMut};
use core::future::poll_fn;
#[cfg(feature = "security")]
use core::future::Future;
use core::task::{Context, Poll};

#[cfg(feature = "security")]
use bt_hci::param::BdAddr;
use bt_hci::param::{ConnHandle, DisconnectReason, LeConnRole, Status};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::waitqueue::WakerRegistration;
#[cfg(feature = "security")]
use embassy_time::TimeoutError;

use crate::connection::{ConnParams, Connection, ConnectionEvent, SecurityLevel};
use crate::host::EventHandler;
use crate::pdu::Pdu;
use crate::prelude::sar::PacketReassembly;
#[cfg(feature = "security")]
use crate::security_manager::{SecurityEventData, SecurityManager};
use crate::{config, Address, Error, Identity, PacketPool};

/// Resolvable private addresses used on a connection.
///
/// Holds the Resolvable Private Addresses (RPAs) for a connection that were
/// resolved by the controller.
#[cfg(feature = "security")]
#[derive(Debug, Default, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct ResolvablePrivateAddrs {
    /// The local resolvable private address used on this connection, if any.
    pub(crate) local: Option<BdAddr>,
    /// The peer's resolvable private address used on this connection, if any.
    pub(crate) peer: Option<BdAddr>,
}

#[cfg(feature = "security")]
impl ResolvablePrivateAddrs {
    /// Create an empty `ResolvablePrivateAddrs` with no addresses set.
    pub(crate) const fn none() -> Self {
        Self {
            local: None,
            peer: None,
        }
    }
}

#[cfg(feature = "att-queued-writes")]
pub(crate) struct PrepareWriteState {
    pub(crate) handle: u16,
    pub(crate) offset: u16,
    pub(crate) len: u16,
    pub(crate) buf: [u8; config::PREPARE_WRITE_BUFFER_SIZE],
}

#[cfg(feature = "att-queued-writes")]
impl PrepareWriteState {
    const fn new() -> Self {
        Self {
            handle: 0,
            offset: 0,
            len: 0,
            buf: [0; config::PREPARE_WRITE_BUFFER_SIZE],
        }
    }

    fn queue(&mut self, handle: u16, offset: u16, value: &[u8]) -> Result<(), crate::att::AttErrorCode> {
        if self.handle == 0 {
            // Empty: start a new queued write
            self.handle = handle;
            self.offset = offset;
            self.len = 0;
        } else if self.handle != handle || self.offset + self.len != offset {
            return Err(crate::att::AttErrorCode::PREPARE_QUEUE_FULL);
        }

        let buf_offset = (offset - self.offset) as usize;
        let end = buf_offset + value.len();
        if end > self.buf.len() {
            return Err(crate::att::AttErrorCode::PREPARE_QUEUE_FULL);
        }

        self.buf[buf_offset..end].copy_from_slice(value);
        self.len = end as u16;
        Ok(())
    }

    fn clear(&mut self) {
        self.handle = 0;
        self.len = 0;
    }
}

struct State {
    central_waker: WakerRegistration,
    peripheral_waker: WakerRegistration,
    disconnect_waker: WakerRegistration,
    default_link_credits: usize,
    default_att_mtu: u16,
}

type EventChannel = Channel<NoopRawMutex, ConnectionEvent, { config::CONNECTION_EVENT_QUEUE_SIZE }>;
type GattChannel<P> = Channel<NoopRawMutex, Pdu<P>, { config::L2CAP_RX_QUEUE_SIZE }>;

pub(crate) struct ConnectionManager<'d, P: PacketPool> {
    state: RefCell<State>,
    connections: &'d RefCell<[ConnectionStorage<P::Packet>]>,
    outbound: Channel<NoopRawMutex, (ConnHandle, Pdu<P::Packet>), { config::L2CAP_TX_QUEUE_SIZE }>,
    #[cfg(feature = "security")]
    pub(crate) security_manager: SecurityManager<'d>,
}

impl<'d, P: PacketPool> ConnectionManager<'d, P> {
    pub(crate) fn new(
        connections: &'d RefCell<[ConnectionStorage<P::Packet>]>,
        default_att_mtu: u16,
        #[cfg(feature = "security")] bond_storage: &'d RefCell<heapless::VecView<crate::BondInformation>>,
    ) -> Self {
        Self {
            state: RefCell::new(State {
                central_waker: WakerRegistration::new(),
                peripheral_waker: WakerRegistration::new(),
                disconnect_waker: WakerRegistration::new(),
                default_link_credits: 0,
                default_att_mtu,
            }),
            connections,
            outbound: Channel::new(),
            #[cfg(feature = "security")]
            security_manager: SecurityManager::new(bond_storage),
        }
    }

    fn connection(&self, index: u8) -> Ref<'_, ConnectionStorage<P::Packet>> {
        Ref::map(self.connections.borrow(), |x| &x[index as usize])
    }

    fn connection_mut(&self, index: u8) -> RefMut<'_, ConnectionStorage<P::Packet>> {
        RefMut::map(self.connections.borrow_mut(), |x| &mut x[index as usize])
    }

    fn connection_by_handle(&self, handle: ConnHandle) -> Option<Ref<'_, ConnectionStorage<P::Packet>>> {
        Ref::filter_map(self.connections.borrow(), |connections| {
            for storage in connections.iter() {
                if storage.handle == Some(handle)
                    && matches!(storage.state, ConnectionState::Connected | ConnectionState::Connecting)
                {
                    return Some(storage);
                }
            }
            None
        })
        .ok()
    }

    fn connection_by_handle_mut(&self, handle: ConnHandle) -> Option<RefMut<'_, ConnectionStorage<P::Packet>>> {
        RefMut::filter_map(self.connections.borrow_mut(), |connections| {
            for storage in connections.iter_mut() {
                if storage.handle == Some(handle)
                    && matches!(storage.state, ConnectionState::Connected | ConnectionState::Connecting)
                {
                    return Some(storage);
                }
            }
            None
        })
        .ok()
    }

    pub(crate) fn role(&self, index: u8) -> LeConnRole {
        self.connection(index).role.unwrap()
    }

    pub(crate) fn role_by_handle(&self, handle: ConnHandle) -> Option<LeConnRole> {
        self.connection_by_handle(handle).and_then(|connection| connection.role)
    }

    pub(crate) fn handle(&self, index: u8) -> ConnHandle {
        self.connection(index).handle.unwrap()
    }

    pub(crate) fn is_connected(&self, index: u8) -> bool {
        self.connection(index).state == ConnectionState::Connected
    }

    pub(crate) async fn next(&self, index: u8) -> ConnectionEvent {
        poll_fn(|cx| self.connection(index).events.poll_receive(cx)).await
    }

    #[cfg(feature = "gatt")]
    pub(crate) async fn next_gatt(&self, index: u8) -> Pdu<P::Packet> {
        poll_fn(|cx| self.connection(index).gatt.poll_receive(cx)).await
    }

    pub(crate) async fn post_event(&self, index: u8, event: ConnectionEvent) {
        poll_fn(|cx| self.connection(index).events.poll_ready_to_send(cx)).await;
        self.connection(index).events.try_send(event).unwrap();
    }

    pub(crate) fn post_handle_event(&self, handle: ConnHandle, event: ConnectionEvent) -> Result<(), Error> {
        for entry in self.connections.borrow_mut().iter_mut() {
            if entry.state == ConnectionState::Connected && Some(handle) == entry.handle {
                if let ConnectionEvent::ConnectionParamsUpdated {
                    conn_interval,
                    peripheral_latency,
                    supervision_timeout,
                } = event
                {
                    entry.params = ConnParams {
                        conn_interval,
                        peripheral_latency,
                        supervision_timeout,
                    }
                }

                entry.events.try_send(event).map_err(|_| Error::OutOfMemory)?;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    #[cfg(feature = "gatt")]
    pub(crate) fn post_gatt(&self, handle: ConnHandle, pdu: Pdu<P::Packet>) -> Result<(), Error> {
        for entry in self.connections.borrow().iter() {
            if entry.state == ConnectionState::Connected && Some(handle) == entry.handle {
                entry.gatt.try_send(pdu).map_err(|_| Error::OutOfMemory)?;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    #[cfg(feature = "gatt")]
    pub(crate) fn post_gatt_client(&self, handle: ConnHandle, pdu: Pdu<P::Packet>) -> Result<(), Error> {
        for entry in self.connections.borrow().iter() {
            if entry.state == ConnectionState::Connected && Some(handle) == entry.handle {
                entry.gatt_client.try_send(pdu).map_err(|_| Error::OutOfMemory)?;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    #[cfg(feature = "gatt")]
    pub(crate) async fn next_gatt_client(&self, index: u8) -> Option<Pdu<P::Packet>> {
        poll_fn(|cx| {
            let mut connections = self.connections.borrow_mut();
            let storage = &mut connections[index as usize];
            storage.gatt_client_waker.register(cx.waker());
            match storage.gatt_client.poll_receive(cx) {
                core::task::Poll::Ready(pdu) => core::task::Poll::Ready(Some(pdu)),
                core::task::Poll::Pending if storage.state == ConnectionState::Disconnected => {
                    core::task::Poll::Ready(None)
                }
                core::task::Poll::Pending => core::task::Poll::Pending,
            }
        })
        .await
    }

    pub(crate) fn peer_address(&self, index: u8) -> Address {
        self.connection(index).peer_identity.map(|i| i.addr).unwrap_or_default()
    }

    pub(crate) fn peer_identity(&self, index: u8) -> Identity {
        self.connection(index).peer_identity.unwrap()
    }

    pub(crate) fn params(&self, index: u8) -> ConnParams {
        self.connection(index).params
    }

    pub(crate) fn set_att_mtu(&self, index: u8, mtu: u16) {
        self.connection_mut(index).att_mtu = mtu;
    }

    pub(crate) fn set_l2cap_listening(&self, index: u8, listening: bool) {
        self.connection_mut(index).l2cap_listening = listening;
    }

    pub(crate) fn request_disconnect(&self, index: u8, reason: DisconnectReason) {
        let entry = &mut self.connection_mut(index);
        if entry.state == ConnectionState::Connected {
            entry.state = ConnectionState::DisconnectRequest(reason);
            self.state.borrow_mut().disconnect_waker.wake();
        }
    }

    pub(crate) fn request_handle_disconnect(&self, handle: ConnHandle, reason: DisconnectReason) {
        if let Some(mut entry) = self.connection_by_handle_mut(handle) {
            if entry.state == ConnectionState::Connected && Some(handle) == entry.handle {
                entry.state = ConnectionState::DisconnectRequest(reason);
                self.state.borrow_mut().disconnect_waker.wake();
            }
        }
    }

    pub(crate) fn poll_disconnecting<'m>(
        &'m self,
        cx: Option<&mut Context<'_>>,
    ) -> Poll<DisconnectRequest<'m, P::Packet>> {
        let mut state = self.state.borrow_mut();
        if let Some(cx) = cx {
            state.disconnect_waker.register(cx.waker());
        }
        core::mem::drop(state);
        for (idx, storage) in self.connections.borrow().iter().enumerate() {
            if let ConnectionState::DisconnectRequest(reason) = storage.state {
                return Poll::Ready(DisconnectRequest {
                    index: idx,
                    handle: storage.handle.unwrap(),
                    reason,
                    connections: self.connections,
                });
            }
        }
        Poll::Pending
    }

    pub(crate) fn get_connected_handle(&'d self, h: ConnHandle) -> Option<Connection<'d, P>> {
        for (index, storage) in self.connections.borrow_mut().iter_mut().enumerate() {
            match (storage.handle, &storage.state) {
                (Some(handle), ConnectionState::Connected) if handle == h => {
                    storage.inc_ref();
                    return Some(Connection::new(index as u8, self));
                }
                _ => {}
            }
        }
        None
    }

    pub(crate) fn connections(&'d self) -> ConnectedIter<'d, P> {
        ConnectedIter {
            manager: self,
            index: 0,
            len: self.connections.as_ptr().len(),
        }
    }

    pub(crate) fn get_connection_by_peer_address(&'d self, peer_address: Address) -> Option<Connection<'d, P>> {
        for (index, storage) in self.connections.borrow_mut().iter_mut().enumerate() {
            if storage.state == ConnectionState::Connected {
                if let Some(peer) = &storage.peer_identity {
                    if peer.match_address(&peer_address) {
                        storage.inc_ref();
                        return Some(Connection::new(index as u8, self));
                    }
                }
            }
        }
        None
    }

    pub(crate) fn with_connected_handle<F: FnOnce(&mut ConnectionStorage<P::Packet>) -> Result<R, Error>, R>(
        &self,
        h: ConnHandle,
        f: F,
    ) -> Result<R, Error> {
        self.connection_by_handle_mut(h)
            .map(|mut c| f(&mut *c))
            .unwrap_or(Err(Error::Disconnected))
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

    pub(crate) fn is_l2cap_listening(&self, h: ConnHandle) -> bool {
        self.with_connected_handle(h, |storage| Ok(storage.l2cap_listening))
            .unwrap_or(false)
    }

    pub(crate) fn reassembly<F: FnOnce(&mut PacketReassembly<P::Packet>) -> Result<R, Error>, R>(
        &self,
        h: ConnHandle,
        f: F,
    ) -> Result<R, Error> {
        self.with_connected_handle(h, |storage| f(&mut storage.reassembly))
    }

    pub(crate) fn disconnected(&self, h: ConnHandle, reason: Status) -> Result<(), Error> {
        for (idx, storage) in self.connections.borrow_mut().iter_mut().enumerate() {
            if Some(h) == storage.handle && storage.state != ConnectionState::Disconnected {
                storage.state = ConnectionState::Disconnected;
                storage.reassembly.clear();
                let _ = storage.events.try_send(ConnectionEvent::Disconnected { reason });
                #[cfg(feature = "gatt")]
                {
                    storage.gatt.clear();
                    storage.gatt_client_waker.wake();
                }
                #[cfg(feature = "connection-metrics")]
                storage.metrics.reset();
                #[cfg(feature = "security")]
                {
                    storage.security_level = SecurityLevel::NoEncryption;
                    storage.bondable = false;
                    if let Some(identity) = storage.peer_identity.as_ref() {
                        self.security_manager.disconnect(identity);
                    }
                }
                #[cfg(feature = "att-queued-writes")]
                storage.prepare_write.clear();
                storage.l2cap_listening = false;
                return Ok(());
            }
        }
        warn!("[link][disconnect] connection handle {:?} not found", h);
        Err(Error::NotFound)
    }

    pub(crate) fn connect(
        &self,
        handle: ConnHandle,
        peer_addr: Address,
        role: LeConnRole,
        params: ConnParams,
    ) -> Result<(), Error> {
        self.connect_with_rpas(
            handle,
            peer_addr,
            role,
            params,
            #[cfg(feature = "security")]
            ResolvablePrivateAddrs::none(),
        )
    }

    pub(crate) fn connect_with_rpas(
        &self,
        handle: ConnHandle,
        peer_addr: Address,
        role: LeConnRole,
        params: ConnParams,
        #[cfg(feature = "security")] resolvable_addrs: ResolvablePrivateAddrs,
    ) -> Result<(), Error> {
        let mut state = self.state.borrow_mut();
        let default_credits = state.default_link_credits;
        let default_att_mtu = state.default_att_mtu;
        for (idx, storage) in self.connections.borrow_mut().iter_mut().enumerate() {
            if ConnectionState::Disconnected == storage.state && storage.refcount == 0 {
                storage.events.clear();
                storage.reassembly.clear();
                storage.state = ConnectionState::Connecting;
                storage.link_credits = default_credits;
                // Default ATT MTU is 23
                storage.att_mtu = 23;
                storage.handle.replace(handle);
                #[cfg(feature = "security")]
                let identity = self
                    .security_manager
                    .get_peer_bond_information(&peer_addr.into())
                    .map(|bond| bond.identity)
                    .unwrap_or(peer_addr.into());
                #[cfg(not(feature = "security"))]
                let identity = Identity::from(peer_addr);
                storage.peer_identity.replace(identity);
                storage.role.replace(role);
                storage.params = params;
                #[cfg(feature = "security")]
                {
                    storage.bond_rejected = false;
                    storage.smp_timeout = false;
                }
                #[cfg(feature = "security")]
                {
                    storage.resolvable_addrs = resolvable_addrs;
                }

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
        warn!("[link][connect] no available slot found for handle {:?}", handle);
        Err(Error::NotFound)
    }

    pub(crate) fn poll_accept(
        &'d self,
        role: LeConnRole,
        peers: &[Address],
        cx: Option<&mut Context<'_>>,
    ) -> Poll<Connection<'d, P>> {
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
        core::mem::drop(state);
        for (idx, storage) in self.connections.borrow_mut().iter_mut().enumerate() {
            if let ConnectionState::Connecting = storage.state {
                let handle = storage.handle.unwrap();
                let r = storage.role.unwrap();
                if r == role {
                    if !peers.is_empty() {
                        for peer in peers.iter() {
                            if storage.peer_identity.unwrap().match_address(peer) {
                                storage.state = ConnectionState::Connected;
                                debug!("[link][poll_accept] connection accepted: state: {:?}", storage);
                                assert_eq!(storage.refcount, 0);
                                storage.inc_ref();
                                return Poll::Ready(Connection::new(idx as u8, self));
                            }
                        }
                    } else {
                        storage.state = ConnectionState::Connected;
                        assert_eq!(storage.refcount, 0);
                        debug!("[link][poll_accept] connection accepted: state: {:?}", storage);

                        assert_eq!(storage.refcount, 0);
                        storage.inc_ref();
                        return Poll::Ready(Connection::new(idx as u8, self));
                    }
                }
            }
        }
        Poll::Pending
    }

    pub(crate) fn log_status(&self, verbose: bool) {
        for (idx, storage) in self.connections.borrow().iter().enumerate() {
            if verbose || storage.state != ConnectionState::Disconnected {
                debug!("[link][idx = {}] state = {:?}", idx, storage);
            }
        }
    }

    pub(crate) fn inc_ref(&self, index: u8) {
        self.connection_mut(index).inc_ref();
    }

    pub(crate) fn dec_ref(&self, index: u8) {
        self.connection_mut(index)
            .dec_ref(&mut self.state.borrow_mut().disconnect_waker);
    }

    pub(crate) async fn accept(&'d self, role: LeConnRole, peers: &[Address]) -> Connection<'d, P> {
        poll_fn(|cx| self.poll_accept(role, peers, Some(cx))).await
    }

    pub(crate) fn set_link_credits(&self, credits: usize) {
        let mut state = self.state.borrow_mut();
        state.default_link_credits = credits;
        core::mem::drop(state);
        for storage in self.connections.borrow_mut().iter_mut() {
            storage.link_credits = credits;
        }
    }

    pub(crate) fn set_default_att_mtu(&self, att_mtu: u16) {
        let mut state = self.state.borrow_mut();
        state.default_att_mtu = att_mtu;
    }

    pub(crate) fn confirm_sent(&self, handle: ConnHandle, packets: usize) -> Result<(), Error> {
        for storage in self.connections.borrow_mut().iter_mut() {
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
    ) -> Poll<Result<PacketGrant<'_, P::Packet>, Error>> {
        for storage in self.connections.borrow_mut().iter_mut() {
            match storage.state {
                ConnectionState::Connected if storage.handle.unwrap() == handle => {
                    if packets <= storage.link_credits {
                        storage.link_credits -= packets;

                        return Poll::Ready(Ok(PacketGrant::new(self.connections, handle, packets)));
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
        warn!("[link][pool_request_to_send] connection {:?} not found", handle);
        Poll::Ready(Err(Error::NotFound))
    }

    pub(crate) fn get_att_mtu(&self, index: u8) -> u16 {
        self.connection(index).att_mtu
    }

    pub(crate) async fn send(&self, index: u8, pdu: Pdu<P::Packet>) {
        let handle = self.connection(index).handle.unwrap();
        self.outbound.send((handle, pdu)).await
    }

    pub(crate) fn try_send(&self, index: u8, pdu: Pdu<P::Packet>) -> Result<(), Error> {
        let handle = self.connection(index).handle.unwrap();
        self.outbound.try_send((handle, pdu)).map_err(|_| Error::OutOfMemory)
    }

    pub(crate) fn try_outbound(&self, handle: ConnHandle, pdu: Pdu<P::Packet>) -> Result<(), Error> {
        self.outbound.try_send((handle, pdu)).map_err(|_| Error::OutOfMemory)
    }

    pub(crate) async fn outbound(&self) -> (ConnHandle, Pdu<P::Packet>) {
        self.outbound.receive().await
    }

    pub(crate) fn get_att_mtu_handle(&self, conn: ConnHandle) -> u16 {
        for storage in self.connections.borrow_mut().iter_mut() {
            match storage.state {
                ConnectionState::Connected if storage.handle.unwrap() == conn => {
                    return storage.att_mtu;
                }
                _ => {}
            }
        }
        self.state.borrow().default_att_mtu
    }

    pub(crate) fn exchange_att_mtu(&self, conn: ConnHandle, mtu: u16) -> u16 {
        let state = self.state.borrow();
        debug!("exchange_att_mtu: {}, current default: {}", mtu, state.default_att_mtu);
        let default_att_mtu = state.default_att_mtu;
        core::mem::drop(state);
        for storage in self.connections.borrow_mut().iter_mut() {
            match storage.state {
                ConnectionState::Connected if storage.handle.unwrap() == conn => {
                    storage.att_mtu = default_att_mtu.min(mtu);
                    return storage.att_mtu;
                }
                _ => {}
            }
        }
        mtu
    }

    pub(crate) fn pass_key_confirm(&self, index: u8, confirm: bool) -> Result<(), Error> {
        #[cfg(feature = "security")]
        {
            let connection = self.connection(index);
            if connection.state == ConnectionState::Connected {
                self.security_manager
                    .handle_pass_key_confirm(confirm, self, &connection)
            } else {
                Err(Error::Disconnected)
            }
        }
        #[cfg(not(feature = "security"))]
        Err(Error::NotSupported)
    }

    pub(crate) fn pass_key_input(&self, index: u8, pass_key: u32) -> Result<(), Error> {
        #[cfg(feature = "security")]
        {
            let connection = self.connection(index);
            if connection.state == ConnectionState::Connected {
                self.security_manager.handle_pass_key_input(pass_key, self, &connection)
            } else {
                Err(Error::Disconnected)
            }
        }
        #[cfg(not(feature = "security"))]
        Err(Error::NotSupported)
    }

    pub(crate) fn request_security(&self, index: u8, user_initiated: bool) -> Result<(), Error> {
        #[cfg(feature = "security")]
        {
            let current_level = self.get_security_level(index)?;
            if current_level != SecurityLevel::NoEncryption {
                return Ok(());
            }
            self.security_manager
                .initiate(self, &self.connection(index), user_initiated)
        }
        #[cfg(not(feature = "security"))]
        Err(Error::NotSupported)
    }

    #[cfg(feature = "security")]
    pub(crate) fn is_bonded_peer(&self, index: u8) -> bool {
        let storage = self.connection(index);
        if let Some(identity) = storage.peer_identity.as_ref() {
            self.security_manager
                .get_peer_bond_information(identity)
                .is_some_and(|b| b.is_bonded)
        } else {
            false
        }
    }

    #[cfg(feature = "security")]
    pub(crate) async fn try_enable_encryption(&self, index: u8) -> Result<(), Error> {
        let address = {
            let storage = self.connection(index);
            if storage.state != ConnectionState::Connected {
                return Err(Error::Disconnected);
            } else if storage.security_level != SecurityLevel::NoEncryption {
                return Ok(());
            }
            match storage.peer_identity.as_ref() {
                Some(identity) => identity.addr,
                _ => return Err(Error::InvalidValue),
            }
        };

        if !self.security_manager.is_pairing_in_progress(address) {
            self.request_security(index, false)?;
        }
        match self.security_manager.wait_finished(address).await {
            Ok(()) => Ok(()),
            Err(Error::Busy) => {
                // Another connection is now pairing. Check if pairing succeeded first.
                if self.get_security_level(index)? != SecurityLevel::NoEncryption {
                    Ok(())
                } else {
                    Err(Error::Busy)
                }
            }
            Err(e) => Err(e),
        }
    }

    pub(crate) fn get_security_level(&self, index: u8) -> Result<SecurityLevel, Error> {
        let storage = self.connection(index);
        match storage.state {
            ConnectionState::Connected => {
                #[cfg(feature = "security")]
                {
                    Ok(storage.security_level)
                }
                #[cfg(not(feature = "security"))]
                Ok(SecurityLevel::NoEncryption)
            }
            _ => Err(Error::Disconnected),
        }
    }

    #[cfg(feature = "legacy-pairing")]
    pub(crate) fn get_encryption_key_len(&self, index: u8) -> Result<u8, Error> {
        let storage = self.connection(index);
        match storage.state {
            ConnectionState::Connected => Ok(storage.encryption_key_len),
            _ => Err(Error::Disconnected),
        }
    }

    pub(crate) fn get_bondable(&self, index: u8) -> Result<bool, Error> {
        let storage = self.connection(index);
        match storage.state {
            ConnectionState::Connected => {
                #[cfg(feature = "security")]
                {
                    Ok(storage.bondable)
                }
                #[cfg(not(feature = "security"))]
                Ok(false)
            }
            _ => Err(Error::Disconnected),
        }
    }

    pub(crate) fn set_bondable(&self, index: u8, bondable: bool) -> Result<(), Error> {
        #[cfg(feature = "security")]
        {
            let mut storage = self.connection_mut(index);
            match storage.state {
                ConnectionState::Connected => {
                    storage.bondable = bondable;
                    Ok(())
                }
                _ => Err(Error::Disconnected),
            }
        }
        #[cfg(not(feature = "security"))]
        Err(Error::NotSupported)
    }

    #[cfg(feature = "security")]
    pub(crate) fn set_oob_available(&self, index: u8, available: bool) -> Result<(), Error> {
        let mut storage = self.connection_mut(index);
        match storage.state {
            ConnectionState::Connected => {
                storage.oob_available = available;
                Ok(())
            }
            _ => Err(Error::Disconnected),
        }
    }

    #[cfg(feature = "security")]
    pub(crate) fn provide_oob_data(
        &self,
        index: u8,
        local_oob: crate::security_manager::OobData,
        peer_oob: crate::security_manager::OobData,
    ) -> Result<(), Error> {
        let storage = self.connection(index);
        if storage.state == ConnectionState::Connected {
            self.security_manager
                .handle_oob_data_received(local_oob, peer_oob, self, &storage)
        } else {
            Err(Error::Disconnected)
        }
    }

    pub(crate) fn handle_security_channel(
        &self,
        handle: ConnHandle,
        pdu: Pdu<P::Packet>,
        event_handler: &dyn EventHandler,
    ) -> Result<(), Error> {
        #[cfg(feature = "security")]
        {
            for storage in self.connections.borrow().iter() {
                match storage.state {
                    ConnectionState::Connected if storage.handle.unwrap() == handle => {
                        if storage.smp_timeout {
                            warn!("Ignoring security channel packet after SMP timeout");
                            return Ok(());
                        } else if let Err(error) = self.security_manager.handle_l2cap_command(pdu, self, storage) {
                            error!("Failed to handle security manager packet, {:?}", error);
                            return Err(error);
                        }
                        break;
                    }
                    _ => (),
                }
            }
        }
        Ok(())
    }

    pub(crate) fn handle_security_hci_event(&self, event: bt_hci::event::EventPacket) -> Result<(), Error> {
        #[cfg(feature = "security")]
        {
            self.security_manager.handle_hci_event(event, self)?;
        }
        Ok(())
    }

    pub(crate) fn handle_security_hci_le_event(&self, event: bt_hci::event::le::LeEventPacket) -> Result<(), Error> {
        #[cfg(feature = "security")]
        {
            self.security_manager.handle_hci_le_event(event, self)?;
        }
        Ok(())
    }

    #[cfg(feature = "security")]
    pub(crate) async fn handle_security_event<'h, C>(
        &self,
        host: &crate::host::BleHost<'h, C, P>,
        _event: crate::security_manager::SecurityEventData,
    ) -> Result<(), crate::BleHostError<C::Error>>
    where
        C: crate::ControllerCmdSync<bt_hci::cmd::le::LeLongTermKeyRequestReply>
            + crate::ControllerCmdAsync<bt_hci::cmd::le::LeEnableEncryption>,
    {
        use bt_hci::cmd::le::{LeEnableEncryption, LeLongTermKeyRequestReply};

        match _event {
            crate::security_manager::SecurityEventData::SendLongTermKey(handle, ediv, rand) => {
                let identity = self.connection_by_handle(handle).and_then(|x| x.peer_identity);
                if let Some(identity) = identity {
                    // Match EDIV/Rand against stored bonds to find the correct LTK.
                    // During active legacy pairing (STK phase), the STK is stored with EDIV=0, Rand=0.
                    let bond = self.security_manager.get_peer_bond_information(&identity);
                    #[cfg(not(feature = "legacy-pairing"))]
                    let ltk = bond.map(|b| b.ltk);
                    #[cfg(feature = "legacy-pairing")]
                    let ltk = bond.and_then(|b| {
                        if b.ediv == ediv && b.rand == rand {
                            Some(b.ltk)
                        } else {
                            None
                        }
                    });
                    if let Some(ltk) = ltk {
                        let _ = host
                            .command(LeLongTermKeyRequestReply::new(handle, ltk.to_le_bytes()))
                            .await?;
                    } else {
                        warn!("[host] Long term key request reply failed, no long term key");
                        // Send disconnect event to the controller
                        self.request_handle_disconnect(handle, DisconnectReason::AuthenticationFailure);
                    }
                } else {
                    warn!("[host] Long term key request reply failed, unknown peer")
                }
            }
            crate::security_manager::SecurityEventData::EnableEncryption(handle, bond_info) => {
                let role = self.connection_by_handle(handle).and_then(|x| x.role);
                if let Some(role) = role {
                    if LeConnRole::Central == role {
                        #[cfg(feature = "legacy-pairing")]
                        let (ediv, rand) = (bond_info.ediv, bond_info.rand);
                        #[cfg(not(feature = "legacy-pairing"))]
                        let (ediv, rand) = (0, [0; 8]);
                        host.async_command(LeEnableEncryption::new(handle, rand, ediv, bond_info.ltk.to_le_bytes()))
                            .await?;
                    }
                } else {
                    warn!("[host] Enable encryption failed, unknown peer")
                }
            }
            crate::security_manager::SecurityEventData::Timeout => {
                warn!("[host] Pairing timeout");
                if let Some(peer_address) = self.security_manager.peer_address() {
                    for (index, storage) in self.connections.borrow_mut().iter_mut().enumerate() {
                        if storage.state == ConnectionState::Connected {
                            if let Some(peer) = &storage.peer_identity {
                                if peer.match_address(&peer_address) {
                                    storage.smp_timeout = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                self.security_manager.cancel_timeout();
            }
            crate::security_manager::SecurityEventData::TimerChange => (),
            #[cfg(feature = "security")]
            crate::security_manager::SecurityEventData::BondAdded(identity) => {
                host.resolving_list_state
                    .borrow_mut()
                    .push(crate::host::ResolvingListUpdate::Add(identity));
            }
        }
        Ok(())
    }

    #[cfg(feature = "security")]
    pub(crate) fn poll_security_events(
        &self,
    ) -> impl Future<Output = Result<SecurityEventData, TimeoutError>> + use<'_, P> {
        self.security_manager.poll_events()
    }

    #[cfg(feature = "connection-metrics")]
    pub(crate) fn metrics<F: FnOnce(&Metrics) -> R, R>(&self, index: u8, f: F) -> R {
        f(&self.connection(index).metrics)
    }

    #[cfg(feature = "att-queued-writes")]
    pub(crate) fn prepare_write(
        &self,
        index: u8,
        handle: u16,
        offset: u16,
        value: &[u8],
    ) -> Result<(), crate::att::AttErrorCode> {
        self.connection_mut(index).prepare_write.queue(handle, offset, value)
    }

    #[cfg(feature = "att-queued-writes")]
    pub(crate) fn with_prepare_write<F, R>(&self, index: u8, f: F) -> R
    where
        F: FnOnce(&PrepareWriteState) -> R,
    {
        f(&self.connection(index).prepare_write)
    }

    #[cfg(feature = "att-queued-writes")]
    pub(crate) fn clear_prepare_write(&self, index: u8) {
        self.connection_mut(index).prepare_write.clear();
    }
}

/// Iterator over currently connected connections.
pub struct ConnectedIter<'d, P: PacketPool> {
    manager: &'d ConnectionManager<'d, P>,
    index: usize,
    len: usize,
}

impl<'d, P: PacketPool> Iterator for ConnectedIter<'d, P> {
    type Item = Connection<'d, P>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < self.len {
            let idx = self.index;
            self.index += 1;
            if self.manager.is_connected(idx as u8) {
                self.manager.inc_ref(idx as u8);
                return Some(Connection::new(idx as u8, self.manager));
            }
        }
        None
    }
}

pub struct DisconnectRequest<'a, P> {
    index: usize,
    handle: ConnHandle,
    reason: DisconnectReason,
    connections: &'a RefCell<[ConnectionStorage<P>]>,
}

impl<P> DisconnectRequest<'_, P> {
    pub fn handle(&self) -> ConnHandle {
        self.handle
    }

    pub fn reason(&self) -> DisconnectReason {
        self.reason
    }

    pub fn confirm(self) {
        let mut connections = self.connections.borrow_mut();
        let storage = &mut connections[self.index];
        // Only transition if still in DisconnectRequest. The HCI
        // disconnect_complete handler (`disconnected()`) may race ahead and
        // set state = Disconnected; in that case we must NOT overwrite it
        // back to Disconnecting, or the slot becomes unreusable
        // (`state == Disconnected && refcount == 0` is the reuse check).
        if !matches!(storage.state, ConnectionState::DisconnectRequest(_)) {
            return;
        }
        storage.state = ConnectionState::Disconnecting(self.reason);
    }
}
pub struct ConnectionStorage<P> {
    pub state: ConnectionState,
    pub handle: Option<ConnHandle>,
    pub role: Option<LeConnRole>,
    pub peer_identity: Option<Identity>,
    pub params: ConnParams,
    pub att_mtu: u16,
    pub link_credits: usize,
    pub link_credit_waker: WakerRegistration,
    pub refcount: u8,
    #[cfg(feature = "connection-metrics")]
    pub metrics: Metrics,
    #[cfg(feature = "security")]
    pub security_level: SecurityLevel,
    #[cfg(feature = "security")]
    pub bondable: bool,
    #[cfg(feature = "security")]
    pub oob_available: bool,
    #[cfg(feature = "security")]
    pub bond_rejected: bool,
    #[cfg(feature = "security")]
    pub smp_timeout: bool,
    #[cfg(feature = "security")]
    pub resolvable_addrs: ResolvablePrivateAddrs,
    #[cfg(feature = "legacy-pairing")]
    pub encryption_key_len: u8,
    pub l2cap_listening: bool,
    pub events: EventChannel,
    pub reassembly: PacketReassembly<P>,
    #[cfg(feature = "gatt")]
    pub gatt: GattChannel<P>,
    #[cfg(feature = "gatt")]
    pub(crate) gatt_client: GattChannel<P>,
    #[cfg(feature = "gatt")]
    pub(crate) gatt_client_waker: WakerRegistration,
    #[cfg(feature = "att-queued-writes")]
    pub(crate) prepare_write: PrepareWriteState,
}

/// Connection metrics
#[cfg(feature = "connection-metrics")]
#[derive(Debug)]
pub struct Metrics {
    /// Number of ACL packets sent for this connection.
    pub num_sent: usize,
    /// Number of ACL packets received on this connection.
    pub num_received: usize,
    /// Time of last sent packet.
    pub last_sent: embassy_time::Instant,
    /// Time of last received packet.
    pub last_received: embassy_time::Instant,
    /// Number of times a sender was blocked from sending.
    pub blocked_sends: usize,
}

#[cfg(feature = "connection-metrics")]
impl Metrics {
    pub(crate) const fn new() -> Self {
        Self {
            num_sent: 0,
            num_received: 0,
            last_sent: embassy_time::Instant::MIN,
            last_received: embassy_time::Instant::MIN,
            blocked_sends: 0,
        }
    }
    pub(crate) fn sent(&mut self, num: usize) {
        self.num_sent = self.num_sent.wrapping_add(num);
        self.last_sent = embassy_time::Instant::now();
    }

    pub(crate) fn received(&mut self, num: usize) {
        self.num_received = self.num_received.wrapping_add(num);
        self.last_received = embassy_time::Instant::now();
    }

    pub(crate) fn blocked_send(&mut self) {
        self.blocked_sends = self.blocked_sends.wrapping_add(1);
    }

    pub(crate) fn reset(&mut self) {
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

impl<P> ConnectionStorage<P> {
    pub(crate) const fn new() -> ConnectionStorage<P> {
        ConnectionStorage {
            state: ConnectionState::Disconnected,
            handle: None,
            role: None,
            peer_identity: None,
            params: ConnParams::new(),
            att_mtu: 23,
            link_credits: 0,
            link_credit_waker: WakerRegistration::new(),
            refcount: 0,
            #[cfg(feature = "connection-metrics")]
            metrics: Metrics::new(),
            #[cfg(feature = "security")]
            security_level: SecurityLevel::NoEncryption,
            #[cfg(feature = "security")]
            bond_rejected: false,
            #[cfg(feature = "security")]
            smp_timeout: false,
            #[cfg(feature = "security")]
            resolvable_addrs: ResolvablePrivateAddrs::none(),
            #[cfg(feature = "legacy-pairing")]
            encryption_key_len: 0,
            l2cap_listening: false,
            events: EventChannel::new(),
            #[cfg(feature = "gatt")]
            gatt: GattChannel::new(),
            #[cfg(feature = "gatt")]
            gatt_client: GattChannel::new(),
            #[cfg(feature = "gatt")]
            gatt_client_waker: WakerRegistration::new(),
            reassembly: PacketReassembly::new(),
            #[cfg(feature = "security")]
            bondable: false,
            #[cfg(feature = "security")]
            oob_available: false,
            #[cfg(feature = "att-queued-writes")]
            prepare_write: PrepareWriteState::new(),
        }
    }

    fn inc_ref(&mut self) {
        self.refcount = unwrap!(
            self.refcount.checked_add(1),
            "Too many references to the same connection"
        );
    }

    fn dec_ref(&mut self, waker: &mut WakerRegistration) {
        self.refcount = unwrap!(
            self.refcount.checked_sub(1),
            "bug: dropping a connection with refcount 0"
        );
        if self.refcount == 0 && self.state == ConnectionState::Connected {
            self.state = ConnectionState::DisconnectRequest(DisconnectReason::RemoteUserTerminatedConn);
            waker.wake();
        }
    }
}

impl<P> core::fmt::Debug for ConnectionStorage<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut d = f.debug_struct("ConnectionStorage");
        let d = d
            .field("state", &self.state)
            .field("handle", &self.handle)
            .field("role", &self.role)
            .field("peer_identity", &self.peer_identity)
            .field("refcount", &self.refcount);
        #[cfg(feature = "connection-metrics")]
        let d = d.field("metrics", &self.metrics);
        d.finish()
    }
}

#[cfg(feature = "defmt")]
impl<P> defmt::Format for ConnectionStorage<P> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(
            f,
            "state = {}, conn = {}, flow = {}",
            self.state,
            self.handle,
            self.link_credits,
        );

        defmt::write!(
            f,
            ", role = {}, peer = {}, ref = {}, sar = {}",
            self.role,
            self.peer_identity,
            self.refcount,
            self.reassembly,
        );

        #[cfg(feature = "connection-metrics")]
        defmt::write!(f, ", {}", self.metrics);
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

pub struct PacketGrant<'a, P> {
    connections: &'a RefCell<[ConnectionStorage<P>]>,
    handle: ConnHandle,
    packets: usize,
}

impl<'a, P> PacketGrant<'a, P> {
    fn new(connections: &'a RefCell<[ConnectionStorage<P>]>, handle: ConnHandle, packets: usize) -> Self {
        Self {
            connections,
            handle,
            packets,
        }
    }

    pub(crate) fn confirm(&mut self, sent: usize) {
        self.packets = self.packets.saturating_sub(sent);
        #[cfg(feature = "connection-metrics")]
        {
            for storage in self.connections.borrow_mut().iter_mut() {
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

impl<P> Drop for PacketGrant<'_, P> {
    fn drop(&mut self) {
        if self.packets > 0 {
            for storage in self.connections.borrow_mut().iter_mut() {
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
pub(crate) mod tests {
    use super::*;
    extern crate std;

    use std::boxed::Box;

    use bt_hci::param::{AddrKind, BdAddr};
    use embassy_futures::block_on;

    use crate::prelude::*;

    pub const ADDR_1: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    pub const ADDR_2: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    pub fn setup() -> &'static ConnectionManager<'static, DefaultPacketPool> {
        let storage: &RefCell<[_]> = Box::leak(Box::new(RefCell::new([const { ConnectionStorage::new() }; 3])));
        #[cfg(feature = "security")]
        let bond_storage: &RefCell<heapless::VecView<_>> = Box::leak(Box::new(RefCell::new(heapless::Vec::<
            crate::security_manager::BondInformation,
            10,
        >::new())));
        let mgr = ConnectionManager::new(
            storage,
            23,
            #[cfg(feature = "security")]
            bond_storage,
        );
        Box::leak(Box::new(mgr))
    }

    #[test]
    fn peripheral_connection_established() {
        let mgr = setup();
        assert!(mgr.poll_accept(LeConnRole::Peripheral, &[], None).is_pending());

        unwrap!(mgr.connect(
            ConnHandle::new(0),
            Address::new(AddrKind::RANDOM, BdAddr::new(ADDR_1)),
            LeConnRole::Peripheral,
            ConnParams::new(),
        ));

        let Poll::Ready(handle) = mgr.poll_accept(LeConnRole::Peripheral, &[], None) else {
            panic!("expected connection to be accepted");
        };
        assert_eq!(handle.role(), LeConnRole::Peripheral);
        assert_eq!(
            handle.peer_address(),
            Address::new(AddrKind::RANDOM, BdAddr::new(ADDR_1))
        );

        handle.disconnect();
    }

    #[test]
    fn central_connection_established() {
        let mgr = setup();

        assert!(mgr.poll_accept(LeConnRole::Central, &[], None).is_pending());

        unwrap!(mgr.connect(
            ConnHandle::new(0),
            Address::new(AddrKind::RANDOM, BdAddr::new(ADDR_2)),
            LeConnRole::Central,
            ConnParams::new(),
        ));

        let Poll::Ready(handle) = mgr.poll_accept(LeConnRole::Central, &[], None) else {
            panic!("expected connection to be accepted");
        };
        assert_eq!(handle.role(), LeConnRole::Central);
        assert_eq!(
            handle.peer_address(),
            Address::new(AddrKind::RANDOM, BdAddr::new(ADDR_2))
        );
    }

    #[test]
    fn controller_disconnects_before_host() {
        let mgr = setup();

        unwrap!(mgr.connect(
            ConnHandle::new(3),
            Address::new(AddrKind::RANDOM, BdAddr::new(ADDR_1)),
            LeConnRole::Central,
            ConnParams::new(),
        ));

        unwrap!(mgr.connect(
            ConnHandle::new(2),
            Address::new(AddrKind::RANDOM, BdAddr::new(ADDR_2)),
            LeConnRole::Peripheral,
            ConnParams::new(),
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
            Address::new(AddrKind::RANDOM, BdAddr::new(ADDR_1)),
            LeConnRole::Central,
            ConnParams::new(),
        ));

        unwrap!(mgr.connect(
            ConnHandle::new(2),
            Address::new(AddrKind::RANDOM, BdAddr::new(ADDR_2)),
            LeConnRole::Peripheral,
            ConnParams::new(),
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
        unwrap!(mgr.connect(
            handle,
            Address::new(AddrKind::RANDOM, BdAddr::new(ADDR_1)),
            LeConnRole::Peripheral,
            ConnParams::new()
        ));

        let Poll::Ready(conn) = mgr.poll_accept(LeConnRole::Peripheral, &[], None) else {
            panic!("expected connection to be accepted");
        };
        assert_eq!(conn.role(), LeConnRole::Peripheral);
        assert_eq!(conn.peer_address(), Address::new(AddrKind::RANDOM, BdAddr::new(ADDR_1)));

        unwrap!(mgr.disconnected(handle, Status::UNSPECIFIED));

        // New incoming connection reusing handle
        let handle = ConnHandle::new(42);
        unwrap!(mgr.connect(
            handle,
            Address::new(AddrKind::RANDOM, BdAddr::new(ADDR_2)),
            LeConnRole::Peripheral,
            ConnParams::new()
        ));

        let Poll::Ready(conn2) = mgr.poll_accept(LeConnRole::Peripheral, &[], None) else {
            panic!("expected connection to be accepted");
        };

        // Ensure existing connection doesnt panic things
        assert_eq!(conn.handle(), ConnHandle::new(42));
        assert_eq!(conn.role(), LeConnRole::Peripheral);
        assert_eq!(conn.peer_address(), Address::new(AddrKind::RANDOM, BdAddr::new(ADDR_1)));
        assert!(!conn.is_connected());

        assert_eq!(conn2.handle(), ConnHandle::new(42));
        assert_eq!(conn2.role(), LeConnRole::Peripheral);
        assert_eq!(
            conn2.peer_address(),
            Address::new(AddrKind::RANDOM, BdAddr::new(ADDR_2))
        );
        assert!(conn2.is_connected());
    }

    #[test]
    fn disconnect_correct_handle() {
        let mgr = setup();

        assert!(mgr.poll_accept(LeConnRole::Peripheral, &[], None).is_pending());

        let handle = ConnHandle::new(42);
        unwrap!(mgr.connect(
            handle,
            Address::new(AddrKind::RANDOM, BdAddr::new(ADDR_1)),
            LeConnRole::Peripheral,
            ConnParams::new()
        ));

        let Poll::Ready(conn) = mgr.poll_accept(LeConnRole::Peripheral, &[], None) else {
            panic!("expected connection to be accepted");
        };
        assert_eq!(conn.role(), LeConnRole::Peripheral);
        assert_eq!(conn.peer_address(), Address::new(AddrKind::RANDOM, BdAddr::new(ADDR_1)));

        unwrap!(mgr.disconnected(handle, Status::UNSPECIFIED));

        // New incoming connection reusing handle
        let handle = ConnHandle::new(42);
        unwrap!(mgr.connect(
            handle,
            Address::new(AddrKind::RANDOM, BdAddr::new(ADDR_2)),
            LeConnRole::Peripheral,
            ConnParams::new()
        ));

        let Poll::Ready(conn2) = mgr.poll_accept(LeConnRole::Peripheral, &[], None) else {
            panic!("expected connection to be accepted");
        };

        assert_eq!(conn2.handle(), ConnHandle::new(42));
        assert_eq!(conn2.role(), LeConnRole::Peripheral);
        assert_eq!(
            conn2.peer_address(),
            Address::new(AddrKind::RANDOM, BdAddr::new(ADDR_2))
        );
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
            Address::new(AddrKind::RANDOM, BdAddr::new(ADDR_1)),
            LeConnRole::Peripheral,
            ConnParams::new()
        ));

        let Poll::Ready(handle) = mgr.poll_accept(LeConnRole::Peripheral, &[], None) else {
            panic!("expected connection to be accepted");
        };
        assert_eq!(handle.role(), LeConnRole::Peripheral);
        assert_eq!(
            handle.peer_address(),
            Address::new(AddrKind::RANDOM, BdAddr::new(ADDR_1))
        );

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
            Address::new(AddrKind::RANDOM, BdAddr::new(ADDR_1)),
            LeConnRole::Peripheral,
            ConnParams::new()
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

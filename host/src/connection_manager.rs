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

use crate::connection::{Connection, ConnectionEvent, SecurityLevel};
use crate::host::EventHandler;
use crate::pdu::Pdu;
use crate::prelude::sar::PacketReassembly;
#[cfg(feature = "security")]
use crate::security_manager::{SecurityEventData, SecurityManager};
use crate::{config, Error, Identity, PacketPool};

struct State<'d, P> {
    connections: &'d mut [ConnectionStorage<P>],
    central_waker: WakerRegistration,
    peripheral_waker: WakerRegistration,
    disconnect_waker: WakerRegistration,
    default_link_credits: usize,
    default_att_mtu: u16,
}

impl<P> State<'_, P> {
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

type EventChannel = Channel<NoopRawMutex, ConnectionEvent, { config::CONNECTION_EVENT_QUEUE_SIZE }>;
type GattChannel<P> = Channel<NoopRawMutex, Pdu<P>, { config::L2CAP_RX_QUEUE_SIZE }>;

pub(crate) struct ConnectionManager<'d, P: PacketPool> {
    state: RefCell<State<'d, P::Packet>>,
    outbound: Channel<NoopRawMutex, (ConnHandle, Pdu<P::Packet>), { config::L2CAP_TX_QUEUE_SIZE }>,
    #[cfg(feature = "security")]
    pub(crate) security_manager: SecurityManager<{ crate::BI_COUNT }>,
}

impl<'d, P: PacketPool> ConnectionManager<'d, P> {
    pub(crate) fn new(connections: &'d mut [ConnectionStorage<P::Packet>], default_att_mtu: u16) -> Self {
        Self {
            state: RefCell::new(State {
                connections,
                central_waker: WakerRegistration::new(),
                peripheral_waker: WakerRegistration::new(),
                disconnect_waker: WakerRegistration::new(),
                default_link_credits: 0,
                default_att_mtu,
            }),
            outbound: Channel::new(),
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

    pub(crate) async fn next(&self, index: u8) -> ConnectionEvent {
        poll_fn(|cx| self.with_mut(|state| state.connections[index as usize].events.poll_receive(cx))).await
    }

    #[cfg(feature = "gatt")]
    pub(crate) async fn next_gatt(&self, index: u8) -> Pdu<P::Packet> {
        poll_fn(|cx| self.with_mut(|state| state.connections[index as usize].gatt.poll_receive(cx))).await
    }

    pub(crate) async fn post_event(&self, index: u8, event: ConnectionEvent) {
        poll_fn(|cx| self.with_mut(|state| state.connections[index as usize].events.poll_ready_to_send(cx))).await;
        self.with_mut(|state| state.connections[index as usize].events.try_send(event).unwrap());
    }

    pub(crate) fn post_handle_event(&self, handle: ConnHandle, event: ConnectionEvent) -> Result<(), Error> {
        self.with_mut(|state| {
            for entry in state.connections.iter() {
                if entry.state == ConnectionState::Connected && Some(handle) == entry.handle {
                    entry.events.try_send(event).map_err(|_| Error::OutOfMemory)?;
                    return Ok(());
                }
            }
            Err(Error::NotFound)
        })
    }

    #[cfg(feature = "gatt")]
    pub(crate) fn post_gatt(&self, handle: ConnHandle, pdu: Pdu<P::Packet>) -> Result<(), Error> {
        self.with_mut(|state| {
            for entry in state.connections.iter() {
                if entry.state == ConnectionState::Connected && Some(handle) == entry.handle {
                    entry.gatt.try_send(pdu).map_err(|_| Error::OutOfMemory)?;
                    return Ok(());
                }
            }
            Err(Error::NotFound)
        })
    }

    pub(crate) fn peer_address(&self, index: u8) -> BdAddr {
        self.with_mut(|state| {
            let state = &mut state.connections[index as usize];
            match state.peer_identity {
                Some(identity) => identity.bd_addr, // TODO: If irk is used, this addr might be outdated.
                _ => BdAddr::default(),
            }
        })
    }

    pub(crate) fn peer_identity(&self, index: u8) -> Identity {
        self.with_mut(|state| {
            let state = &mut state.connections[index as usize];
            state.peer_identity.unwrap()
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

    pub(crate) fn poll_disconnecting<'m>(
        &'m self,
        cx: Option<&mut Context<'_>>,
    ) -> Poll<DisconnectRequest<'m, 'd, P::Packet>> {
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

    pub(crate) fn get_connected_handle(&'d self, h: ConnHandle) -> Option<Connection<'d, P>> {
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

    pub(crate) fn with_connected_handle<F: FnOnce(&mut ConnectionStorage<P::Packet>) -> Result<R, Error>, R>(
        &self,
        h: ConnHandle,
        f: F,
    ) -> Result<R, Error> {
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

    pub(crate) fn reassembly<F: FnOnce(&mut PacketReassembly<P::Packet>) -> Result<R, Error>, R>(
        &self,
        h: ConnHandle,
        f: F,
    ) -> Result<R, Error> {
        self.with_connected_handle(h, |storage| f(&mut storage.reassembly))
    }

    pub(crate) fn disconnected(&self, h: ConnHandle, reason: Status) -> Result<(), Error> {
        let mut state = self.state.borrow_mut();
        for (idx, storage) in state.connections.iter_mut().enumerate() {
            if Some(h) == storage.handle && storage.state != ConnectionState::Disconnected {
                storage.state = ConnectionState::Disconnected;
                storage.reassembly.clear();
                let _ = storage.events.try_send(ConnectionEvent::Disconnected { reason });
                #[cfg(feature = "gatt")]
                storage.gatt.clear();
                #[cfg(feature = "connection-metrics")]
                storage.metrics.reset();
                #[cfg(feature = "security")]
                {
                    storage.security_level = SecurityLevel::NoEncryption;
                    storage.bondable = false;
                    let _ = self.security_manager.disconnect(h, storage.peer_identity);
                }
                return Ok(());
            }
        }
        warn!("[link][disconnect] connection handle {:?} not found", h);
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
                storage.events.clear();
                storage.reassembly.clear();
                storage.state = ConnectionState::Connecting;
                storage.link_credits = default_credits;
                // Default ATT MTU is 23
                storage.att_mtu = 23;
                storage.handle.replace(handle);
                storage.peer_addr_kind.replace(peer_addr_kind);
                storage.peer_identity.replace(Identity {
                    bd_addr: peer_addr,
                    #[cfg(feature = "security")]
                    irk: None,
                });
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
        warn!("[link][connect] no available slot found for handle {:?}", handle);
        Err(Error::NotFound)
    }

    pub(crate) fn poll_accept(
        &'d self,
        role: LeConnRole,
        peers: &[(AddrKind, &BdAddr)],
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
        for (idx, storage) in state.connections.iter_mut().enumerate() {
            if let ConnectionState::Connecting = storage.state {
                let handle = storage.handle.unwrap();
                let r = storage.role.unwrap();
                if r == role {
                    if !peers.is_empty() {
                        for peer in peers.iter() {
                            // TODO: Accept advertising peers which use IRK
                            if storage.peer_addr_kind.unwrap() == peer.0
                                && storage.peer_identity.unwrap().bd_addr == *peer.1
                            {
                                storage.state = ConnectionState::Connected;
                                debug!("[link][poll_accept] connection accepted: state: {:?}", storage);
                                assert_eq!(storage.refcount, 0);
                                state.inc_ref(idx as u8);
                                return Poll::Ready(Connection::new(idx as u8, self));
                            }
                        }
                    } else {
                        storage.state = ConnectionState::Connected;
                        assert_eq!(storage.refcount, 0);
                        debug!("[link][poll_accept] connection accepted: state: {:?}", storage);

                        assert_eq!(storage.refcount, 0);
                        state.inc_ref(idx as u8);
                        return Poll::Ready(Connection::new(idx as u8, self));
                    }
                }
            }
        }
        Poll::Pending
    }

    fn with_mut<F: FnOnce(&mut State<'d, P::Packet>) -> R, R>(&self, f: F) -> R {
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
            let conn = &mut state.connections[index as usize];
            conn.refcount = unwrap!(
                conn.refcount.checked_sub(1),
                "bug: dropping a connection with refcount 0"
            );
            if conn.refcount == 0 && conn.state == ConnectionState::Connected {
                conn.state = ConnectionState::DisconnectRequest(DisconnectReason::RemoteUserTerminatedConn);
                state.disconnect_waker.wake();
            }
        });
    }

    pub(crate) async fn accept(&'d self, role: LeConnRole, peers: &[(AddrKind, &BdAddr)]) -> Connection<'d, P> {
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
    ) -> Poll<Result<PacketGrant<'_, 'd, P::Packet>, Error>> {
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
        warn!("[link][pool_request_to_send] connection {:?} not found", handle);
        Poll::Ready(Err(Error::NotFound))
    }

    pub(crate) fn get_att_mtu(&self, index: u8) -> u16 {
        self.with_mut(|state| state.connections[index as usize].att_mtu)
    }

    pub(crate) async fn send(&self, index: u8, pdu: Pdu<P::Packet>) {
        let handle = self.with_mut(|state| state.connections[index as usize].handle.unwrap());
        self.outbound.send((handle, pdu)).await
    }

    pub(crate) fn try_send(&self, index: u8, pdu: Pdu<P::Packet>) -> Result<(), Error> {
        let handle = self.with_mut(|state| state.connections[index as usize].handle.unwrap());
        self.outbound.try_send((handle, pdu)).map_err(|_| Error::OutOfMemory)
    }

    pub(crate) fn try_outbound(&self, handle: ConnHandle, pdu: Pdu<P::Packet>) -> Result<(), Error> {
        self.outbound.try_send((handle, pdu)).map_err(|_| Error::OutOfMemory)
    }

    pub(crate) async fn outbound(&self) -> (ConnHandle, Pdu<P::Packet>) {
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
        debug!("exchange_att_mtu: {}, current default: {}", mtu, state.default_att_mtu);
        let default_att_mtu = state.default_att_mtu;
        for storage in state.connections.iter_mut() {
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
            if self.state.borrow_mut().connections[index as usize].state == ConnectionState::Connected {
                self.security_manager.handle_pass_key_confirm(
                    confirm,
                    self,
                    &self.state.borrow().connections[index as usize],
                )
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
            if self.state.borrow_mut().connections[index as usize].state == ConnectionState::Connected {
                self.security_manager.handle_pass_key_input(
                    pass_key,
                    self,
                    &self.state.borrow().connections[index as usize],
                )
            } else {
                Err(Error::Disconnected)
            }
        }
        #[cfg(not(feature = "security"))]
        Err(Error::NotSupported)
    }

    pub(crate) fn request_security(&self, index: u8) -> Result<(), Error> {
        #[cfg(feature = "security")]
        {
            let current_level = self.get_security_level(index)?;
            if current_level != SecurityLevel::NoEncryption {
                return Err(Error::NotSupported);
            }
            self.security_manager
                .initiate(self, &self.state.borrow().connections[index as usize])
        }
        #[cfg(not(feature = "security"))]
        Err(Error::NotSupported)
    }

    pub(crate) fn get_security_level(&self, index: u8) -> Result<SecurityLevel, Error> {
        let state = self.state.borrow();
        match state.connections[index as usize].state {
            ConnectionState::Connected => {
                #[cfg(feature = "security")]
                {
                    Ok(state.connections[index as usize].security_level)
                }
                #[cfg(not(feature = "security"))]
                Ok(SecurityLevel::NoEncryption)
            }
            _ => Err(Error::Disconnected),
        }
    }

    pub(crate) fn get_bondable(&self, index: u8) -> Result<bool, Error> {
        let state = self.state.borrow();
        match state.connections[index as usize].state {
            ConnectionState::Connected => {
                #[cfg(feature = "security")]
                {
                    Ok(state.connections[index as usize].bondable)
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
            let mut state = self.state.borrow_mut();
            match state.connections[index as usize].state {
                ConnectionState::Connected => {
                    state.connections[index as usize].bondable = bondable;
                    Ok(())
                }
                _ => Err(Error::Disconnected),
            }
        }
        #[cfg(not(feature = "security"))]
        Err(Error::NotSupported)
    }

    pub(crate) fn handle_security_channel(
        &self,
        handle: ConnHandle,
        pdu: Pdu<P::Packet>,
        event_handler: &dyn EventHandler,
    ) -> Result<(), Error> {
        #[cfg(feature = "security")]
        {
            let state = self.state.borrow();
            for storage in state.connections.iter() {
                match storage.state {
                    ConnectionState::Connected if storage.handle.unwrap() == handle => {
                        if let Err(error) = self.security_manager.handle_l2cap_command(pdu, self, storage) {
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
            + crate::ControllerCmdAsync<bt_hci::cmd::le::LeEnableEncryption>
            + crate::ControllerCmdSync<bt_hci::cmd::link_control::Disconnect>,
    {
        use bt_hci::cmd::le::{LeEnableEncryption, LeLongTermKeyRequestReply};
        use bt_hci::cmd::link_control::Disconnect;

        match _event {
            crate::security_manager::SecurityEventData::SendLongTermKey(handle) => {
                let conn_info = self.state.borrow().connections.iter().find_map(|connection| {
                    match (connection.handle, connection.peer_identity) {
                        (Some(connection_handle), Some(identity)) => {
                            if handle == connection_handle {
                                Some((connection_handle, identity))
                            } else {
                                None
                            }
                        }
                        (_, _) => None,
                    }
                });

                if let Some((conn, identity)) = conn_info {
                    if let Some(ltk) = self.security_manager.get_peer_long_term_key(&identity) {
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
                        .find_map(
                            |(index, connection)| match (connection.handle, connection.peer_identity) {
                                (Some(connection_handle), Some(identity)) => {
                                    if handle == connection_handle {
                                        Some((index, connection.role, identity))
                                    } else {
                                        None
                                    }
                                }
                                (_, _) => None,
                            },
                        );
                if let Some((index, role, identity)) = connection_data {
                    if let Some(ltk) = self.security_manager.get_peer_long_term_key(&identity) {
                        if let Some(LeConnRole::Central) = role {
                            host.async_command(LeEnableEncryption::new(handle, [0; 8], 0, ltk.to_le_bytes()))
                                .await?;
                        }
                    } else {
                        warn!("[host] Enable encryption failed, no long term key")
                    }
                } else {
                    warn!("[host] Enable encryption failed, unknown peer")
                }
            }
            crate::security_manager::SecurityEventData::Timeout => {
                warn!("[host] Pairing timeout");
                self.security_manager.cancel_timeout();
            }
            crate::security_manager::SecurityEventData::TimerChange => (),
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
        self.with_mut(|state| {
            let state = &state.connections[index as usize];
            f(&state.metrics)
        })
    }
}

pub struct DisconnectRequest<'a, 'd, P> {
    index: usize,
    handle: ConnHandle,
    reason: DisconnectReason,
    state: &'a RefCell<State<'d, P>>,
}

impl<P> DisconnectRequest<'_, '_, P> {
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
pub struct ConnectionStorage<P> {
    pub state: ConnectionState,
    pub handle: Option<ConnHandle>,
    pub role: Option<LeConnRole>,
    pub peer_addr_kind: Option<AddrKind>,
    pub peer_identity: Option<Identity>,
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
    pub events: EventChannel,
    pub reassembly: PacketReassembly<P>,
    #[cfg(feature = "gatt")]
    pub gatt: GattChannel<P>,
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
            peer_addr_kind: None,
            peer_identity: None,
            att_mtu: 23,
            link_credits: 0,
            link_credit_waker: WakerRegistration::new(),
            refcount: 0,
            #[cfg(feature = "connection-metrics")]
            metrics: Metrics::new(),
            #[cfg(feature = "security")]
            security_level: SecurityLevel::NoEncryption,
            events: EventChannel::new(),
            #[cfg(feature = "gatt")]
            gatt: GattChannel::new(),
            reassembly: PacketReassembly::new(),
            #[cfg(feature = "security")]
            bondable: false,
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

pub struct PacketGrant<'a, 'd, P> {
    state: &'a RefCell<State<'d, P>>,
    handle: ConnHandle,
    packets: usize,
}

impl<'a, 'd, P> PacketGrant<'a, 'd, P> {
    fn new(state: &'a RefCell<State<'d, P>>, handle: ConnHandle, packets: usize) -> Self {
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

impl<P> Drop for PacketGrant<'_, '_, P> {
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
pub(crate) mod tests {
    use super::*;
    extern crate std;

    use std::boxed::Box;

    use embassy_futures::block_on;

    use crate::prelude::*;

    pub const ADDR_1: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    pub const ADDR_2: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    pub fn setup() -> &'static ConnectionManager<'static, DefaultPacketPool> {
        let storage = Box::leak(Box::new([const { ConnectionStorage::new() }; 3]));
        let mgr = ConnectionManager::new(&mut storage[..], 23);
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

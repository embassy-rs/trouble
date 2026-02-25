#![warn(missing_docs)]
//! # Bluetooth Security Manager
// ([Vol 3] Part H, Section 3.5.5)

mod constants;
pub(crate) mod crypto;
mod pairing;
mod types;
#[cfg(feature = "legacy-pairing")]
use core::cell::Cell;
use core::cell::RefCell;
use core::future::{poll_fn, Future};
use core::ops::DerefMut;
use core::task::Poll;

use bt_hci::event::le::{LeEventKind, LeEventPacket, LeLongTermKeyRequest};
use bt_hci::event::{EncryptionChangeV1, EncryptionKeyRefreshComplete, EventKind, EventPacket};
use bt_hci::param::{ConnHandle, EncryptionEnabledLevel, LeConnRole};
use bt_hci::FromHciBytes;
pub use crypto::{IdentityResolvingKey, LongTermKey};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::waitqueue::WakerRegistration;
use embassy_time::{Instant, TimeoutError, WithTimeout};
use heapless::Vec;
use rand_chacha::ChaCha12Rng;
use rand_core::SeedableRng;
use types::Command;
pub use types::{PassKey, Reason};

use crate::connection::SecurityLevel;
use crate::connection_manager::{ConnectionManager, ConnectionStorage};
use crate::pdu::Pdu;
use crate::prelude::ConnectionEvent;
use crate::security_manager::pairing::{Pairing, PairingOps};
#[cfg(feature = "legacy-pairing")]
use crate::security_manager::types::AuthReq;
use crate::security_manager::types::BondingFlag;
use crate::types::l2cap::L2CAP_CID_LE_U_SECURITY_MANAGER;
use crate::{Address, Error, Identity, IoCapabilities, PacketPool};

/// Events of interest to the security manager
pub(crate) enum SecurityEventData {
    /// A long term key request has been issued (handle, ediv, rand)
    SendLongTermKey(ConnHandle, u16, [u8; 8]),
    /// Enable encryption on channel
    EnableEncryption(ConnHandle, BondInformation),
    /// Pairing timeout
    Timeout,
    /// Pairing timer changed
    TimerChange,
}

/// Bond Information
#[derive(Clone, Debug, PartialEq)]
pub struct BondInformation {
    /// Long Term Key (LTK)
    pub ltk: LongTermKey,
    /// Peer identity
    pub identity: Identity,
    /// True if this bond information is from a bonded pairing
    pub is_bonded: bool,
    /// Security level of this long term key.
    pub security_level: SecurityLevel,
    #[cfg(feature = "legacy-pairing")]
    /// Encrypted Diversifier (0 for LESC, non-zero for legacy)
    pub ediv: u16,
    #[cfg(feature = "legacy-pairing")]
    /// Random Number (all zeros for LESC, non-zero for legacy)
    pub rand: [u8; 8],
}

impl BondInformation {
    /// Create a BondInformation
    pub fn new(identity: Identity, ltk: LongTermKey, security_level: SecurityLevel, is_bonded: bool) -> Self {
        Self {
            ltk,
            identity,
            is_bonded,
            security_level,
            #[cfg(feature = "legacy-pairing")]
            ediv: 0,
            #[cfg(feature = "legacy-pairing")]
            rand: [0; 8],
        }
    }
}

impl core::fmt::Display for BondInformation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Identity {:?} LTK {}", self.identity, self.ltk)
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for BondInformation {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "Identity {:?} LTK {}", self.identity, self.ltk);
    }
}

/// Security manager data
struct SecurityManagerData<const BOND_COUNT: usize> {
    /// Local device address
    local_address: Option<Address>,
    /// Current bonds with other devices
    bond: Vec<BondInformation, BOND_COUNT>,
    /// Random generator seeded
    random_generator_seeded: bool,
}

impl<const BOND_COUNT: usize> SecurityManagerData<BOND_COUNT> {
    /// Create a new security manager data structure
    pub(crate) fn new() -> Self {
        Self {
            local_address: None,
            bond: Vec::new(),
            random_generator_seeded: false,
        }
    }
}

/// Packet structure for sending security manager protocol (SMP) commands
struct TxPacket<P: PacketPool> {
    /// Underlying packet
    packet: P::Packet,
    /// Command to send
    command: Command,
}

impl<P: PacketPool> TxPacket<P> {
    /// Size of L2CAP header and command
    const HEADER_SIZE: usize = 5;

    /// Get a packet from the pool
    pub fn new(mut packet: P::Packet, command: Command) -> Result<Self, Error> {
        let packet_data = packet.as_mut();
        let smp_size = command.payload_size() + 1;
        packet_data[..2].copy_from_slice(&(smp_size).to_le_bytes());
        packet_data[2..4].copy_from_slice(&L2CAP_CID_LE_U_SECURITY_MANAGER.to_le_bytes());
        packet_data[4] = command.into();
        Ok(Self { packet, command })
    }
    /// Packet command
    pub fn command(&self) -> Command {
        self.command
    }

    /// Packet payload
    pub fn payload(&self) -> &[u8] {
        &self.packet.as_ref()[Self::HEADER_SIZE..Self::HEADER_SIZE + usize::from(self.command.payload_size())]
    }
    /// Package mutable payload
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.packet.as_mut()[Self::HEADER_SIZE..Self::HEADER_SIZE + usize::from(self.command.payload_size())]
    }
    /// Package size
    pub fn total_size(&self) -> usize {
        usize::from(self.command.payload_size()) + Self::HEADER_SIZE
    }
    /// Create a PDU from the packet
    pub fn into_pdu(self) -> Pdu<P::Packet> {
        let len = self.total_size();
        Pdu::new(self.packet, len)
    }
}

// TODO: IRK exchange, HCI_LE_­Add_­Device_­To_­Resolving_­List

/// Security manager that handles SM packet
pub struct SecurityManager<const BOND_COUNT: usize> {
    /// Random generator
    rng: RefCell<ChaCha12Rng>,
    /// Security manager data
    state: RefCell<SecurityManagerData<BOND_COUNT>>,
    /// State of an ongoing pairing as a peripheral
    pairing_sm: RefCell<Option<Pairing>>,
    /// Waker for pairing finished
    finished_waker: RefCell<WakerRegistration>,
    /// Received events
    events: Channel<NoopRawMutex, SecurityEventData, 2>,
    /// Io capabilities
    io_capabilities: RefCell<IoCapabilities>,
    /// When true, reject legacy pairing even if the feature is compiled in
    #[cfg(feature = "legacy-pairing")]
    secure_connections_only: Cell<bool>,
}

impl<const BOND_COUNT: usize> SecurityManager<BOND_COUNT> {
    /// Create a new SecurityManager
    pub(crate) fn new() -> Self {
        let random_seed = [0u8; 32];
        Self {
            rng: RefCell::new(ChaCha12Rng::from_seed(random_seed)),
            state: RefCell::new(SecurityManagerData::new()),
            events: Channel::new(),
            pairing_sm: RefCell::new(None),
            finished_waker: RefCell::new(WakerRegistration::new()),
            io_capabilities: RefCell::new(IoCapabilities::NoInputNoOutput),
            #[cfg(feature = "legacy-pairing")]
            secure_connections_only: Cell::new(false),
        }
    }

    /// Set the IO capabilities
    pub(crate) fn set_io_capabilities(&self, io_capabilities: IoCapabilities) {
        self.io_capabilities.replace(io_capabilities);
    }

    /// Enable or disable secure connections only mode.
    /// When enabled, legacy pairing is rejected even if the feature is compiled in.
    #[cfg(feature = "legacy-pairing")]
    pub(crate) fn set_secure_connections_only(&self, enabled: bool) {
        self.secure_connections_only.set(enabled);
    }

    #[cfg(feature = "legacy-pairing")]
    fn is_secure_connections_only(&self) -> bool {
        self.secure_connections_only.get()
    }

    /// Set the current local address
    pub(crate) fn set_random_generator_seed(&self, random_seed: [u8; 32]) {
        self.rng.replace(ChaCha12Rng::from_seed(random_seed));
        self.state.borrow_mut().random_generator_seeded = true;
    }

    /// Set the current local address
    pub(crate) fn set_local_address(&self, address: Address) {
        self.state.borrow_mut().local_address = Some(address);
    }

    /// Returns true if no pairing is currently in progress.
    fn is_idle(&self) -> bool {
        self.pairing_sm
            .borrow()
            .as_ref()
            .map(|sm| sm.result().is_some())
            .unwrap_or(true)
    }

    pub(crate) fn is_pairing_in_progress(&self, address: Address) -> bool {
        let sm = self.pairing_sm.borrow();
        match &*sm {
            Some(sm) => sm.peer_address() == address && sm.result().is_none(),
            None => false,
        }
    }

    pub(crate) async fn wait_finished(&self, address: Address) -> Result<(), Error> {
        poll_fn(|cx| {
            self.finished_waker.borrow_mut().register(cx.waker());
            match &*self.pairing_sm.borrow() {
                Some(sm) => {
                    if sm.peer_address() != address {
                        return Poll::Ready(Err(Error::Busy));
                    }
                    match sm.result() {
                        Some(result) => Poll::Ready(result),
                        None => Poll::Pending,
                    }
                }
                None => Poll::Ready(Err(Error::Disconnected)),
            }
        })
        .await
    }

    pub(crate) fn get_peer_bond_information(&self, identity: &Identity) -> Option<BondInformation> {
        trace!("[security manager] Find long term key for {:?}", identity);
        self.state.borrow().bond.iter().find_map(|bond| {
            if bond.identity.match_identity(identity) {
                Some(bond.clone())
            } else {
                None
            }
        })
    }

    /// Has the random generator been seeded?
    pub(crate) fn get_random_generator_seeded(&self) -> bool {
        self.state.borrow().random_generator_seeded
    }

    /// Add a bonded device
    pub(crate) fn add_bond_information(&self, bond_information: BondInformation) -> Result<(), Error> {
        trace!("[security manager] Add bond for {:?}", bond_information.identity);
        let index = self
            .state
            .borrow()
            .bond
            .iter()
            .position(|bond| bond_information.identity.match_identity(&bond.identity));
        match index {
            Some(index) => {
                // Replace existing bond if it exists
                self.state.borrow_mut().bond[index] = bond_information;
                Ok(())
            }
            None => self
                .state
                .borrow_mut()
                .bond
                .push(bond_information)
                .map_err(|_| Error::OutOfMemory),
        }
    }

    /// Remove a bonded device
    pub(crate) fn remove_bond_information(&self, identity: Identity) -> Result<(), Error> {
        trace!("[security manager] Remove bond for {:?}", identity);
        let index = self
            .state
            .borrow_mut()
            .bond
            .iter()
            .position(|bond| bond.identity.match_identity(&identity));
        match index {
            Some(index) => {
                self.state.borrow_mut().bond.remove(index);
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Get bonded devices
    pub(crate) fn get_bond_information(&self) -> Vec<BondInformation, BOND_COUNT> {
        Vec::from_slice(self.state.borrow().bond.as_slice()).unwrap()
    }

    fn handle_peripheral<P: PacketPool>(
        &self,
        pdu: Pdu<P::Packet>,
        connections: &ConnectionManager<'_, P>,
        storage: &ConnectionStorage<P::Packet>,
    ) -> Result<(), Error> {
        let handle = storage.handle.ok_or(Error::InvalidValue)?;
        let peer_address_kind = storage.peer_addr_kind.ok_or(Error::InvalidValue)?;
        let peer_identity = storage.peer_identity.ok_or(Error::InvalidValue)?;
        let peer_address = Address {
            kind: peer_address_kind,
            addr: peer_identity.bd_addr,
        };
        let mut buffer = [0u8; 72];
        let size = {
            let size = pdu.len().min(buffer.len());
            buffer[..size].copy_from_slice(&pdu.as_ref()[..size]);
            size
        };
        if size < 2 {
            error!("[security manager] Payload size too small {}", size);
            return Err(Error::Security(Reason::InvalidParameters));
        }
        let payload = &buffer[1..size];
        let command = buffer[0];

        let command = match Command::try_from(command) {
            Ok(command) => {
                if usize::from(command.payload_size()) != payload.len() {
                    error!("[security manager] Payload size mismatch for command {}", command);
                    return Err(Error::Security(Reason::InvalidParameters));
                }
                command
            }
            Err(_) => return Err(Error::Security(Reason::CommandNotSupported)),
        };

        let address = {
            let idle = self.is_idle();
            let mut state_machine = self.pairing_sm.borrow_mut();
            if idle {
                let local_address = self.state.borrow().local_address.unwrap();
                let local_io = *self.io_capabilities.borrow();

                #[cfg(feature = "legacy-pairing")]
                {
                    // Check if peer supports SC by peeking at PairingRequest AuthReq byte
                    let use_legacy = command == Command::PairingRequest
                        && payload.len() >= 3
                        && !AuthReq::from(payload[2]).secure_connection();

                    if use_legacy && self.is_secure_connections_only() {
                        return Err(Error::Security(Reason::AuthenticationRequirements));
                    }

                    if use_legacy {
                        *state_machine = Some(Pairing::new_legacy_peripheral(local_address, peer_address, local_io));
                    } else {
                        *state_machine = Some(Pairing::new_peripheral(local_address, peer_address, local_io));
                    }
                }
                #[cfg(not(feature = "legacy-pairing"))]
                {
                    *state_machine = Some(Pairing::new_peripheral(local_address, peer_address, local_io));
                }
            }

            // Check if we need to switch from LESC to legacy peripheral
            // when receiving a PairingRequest without SC flag
            #[cfg(feature = "legacy-pairing")]
            if command == Command::PairingRequest
                && payload.len() >= 3
                && !AuthReq::from(payload[2]).secure_connection()
                && matches!(state_machine.as_ref(), Some(Pairing::Peripheral(_)))
            {
                if self.is_secure_connections_only() {
                    return Err(Error::Security(Reason::AuthenticationRequirements));
                }
                let old = state_machine.take().unwrap();
                *state_machine = Some(old.switch_to_legacy_peripheral()?);
            }

            let state_machine = state_machine.as_ref().unwrap();
            if state_machine.is_central() {
                return Err(Error::InvalidState);
            }
            state_machine.peer_address()
        };

        if address != peer_address {
            // TODO Is this correct?
            self.pairing_sm.replace(None);
            return Err(Error::InvalidValue);
        }

        let sm = self.pairing_sm.borrow();
        let mut ops = PairingOpsImpl {
            security_manager: self,
            conn_handle: handle,
            connections,
            storage,
            peer_identity,
        };
        let mut rng_borrow = self.rng.borrow_mut();
        sm.as_ref()
            .unwrap()
            .handle_l2cap_command(command, payload, &mut ops, rng_borrow.deref_mut())
    }

    fn handle_central<P: PacketPool>(
        &self,
        pdu: Pdu<P::Packet>,
        connections: &ConnectionManager<'_, P>,
        storage: &ConnectionStorage<P::Packet>,
    ) -> Result<(), Error> {
        let handle = storage.handle.ok_or(Error::InvalidValue)?;
        let peer_address_kind = storage.peer_addr_kind.ok_or(Error::InvalidValue)?;
        let peer_identity = storage.peer_identity.ok_or(Error::InvalidValue)?;
        let peer_address = Address {
            kind: peer_address_kind,
            addr: peer_identity.bd_addr,
        };
        let mut buffer = [0u8; 72];
        let size = {
            let size = pdu.len().min(buffer.len());
            buffer[..size].copy_from_slice(&pdu.as_ref()[..size]);
            size
        };
        if size < 2 {
            error!("[security manager] Payload size too small {}", size);
            return Err(Error::Security(Reason::InvalidParameters));
        }
        let payload = &buffer[1..size];
        let command = buffer[0];

        let command = match Command::try_from(command) {
            Ok(command) => {
                if usize::from(command.payload_size()) != payload.len() {
                    error!("[security manager] Payload size mismatch for command {}", command);
                    return Err(Error::Security(Reason::InvalidParameters));
                }
                command
            }
            Err(_) => return Err(Error::Security(Reason::CommandNotSupported)),
        };

        let address = {
            let idle = self.is_idle();
            let mut state_machine = self.pairing_sm.borrow_mut();
            if idle {
                *state_machine = Some(Pairing::new_central(
                    self.state.borrow().local_address.unwrap(),
                    peer_address,
                    *self.io_capabilities.borrow(),
                ));
            }

            // Check if we need to switch from LESC to legacy central
            // when receiving a PairingResponse without SC flag
            #[cfg(feature = "legacy-pairing")]
            if command == Command::PairingResponse
                && payload.len() >= 3
                && !AuthReq::from(payload[2]).secure_connection()
                && matches!(state_machine.as_ref(), Some(Pairing::Central(_)))
            {
                if self.is_secure_connections_only() {
                    return Err(Error::Security(Reason::AuthenticationRequirements));
                }
                let old = state_machine.take().unwrap();
                *state_machine = Some(old.switch_to_legacy_central()?);
            }

            let state_machine = state_machine.as_ref().unwrap();
            if !state_machine.is_central() {
                return Err(Error::InvalidState);
            }
            state_machine.peer_address()
        };

        if address != peer_address {
            // TODO Is this correct?
            self.pairing_sm.replace(None);
            return Err(Error::InvalidValue);
        }

        let sm = { self.pairing_sm.borrow() };
        let mut ops = PairingOpsImpl {
            security_manager: self,
            conn_handle: handle,
            connections,
            storage,
            peer_identity,
        };
        let mut rng_borrow = self.rng.borrow_mut();
        sm.as_ref()
            .unwrap()
            .handle_l2cap_command(command, payload, &mut ops, rng_borrow.deref_mut())
    }

    /// Handle packet
    pub(crate) fn handle_l2cap_command<P: PacketPool>(
        &self,
        pdu: Pdu<P::Packet>,
        connections: &ConnectionManager<P>,
        storage: &ConnectionStorage<P::Packet>,
    ) -> Result<(), Error> {
        let role = storage.role.ok_or(Error::InvalidValue)?;

        let result = if role == LeConnRole::Peripheral {
            self.handle_peripheral(pdu, connections, storage)
        } else {
            self.handle_central(pdu, connections, storage)
        };

        if self.is_idle() {
            self.finished_waker.borrow_mut().wake();
        }

        if result.is_ok() {
            if let Some(sm) = self.pairing_sm.borrow().as_ref() {
                sm.reset_timeout();
                let _ = self.events.try_send(SecurityEventData::TimerChange);
            }
        } else if let Err(e) = self.handle_security_error(connections, storage, &result) {
            error!("[security manager] Failed sending pairing failed message! {:?}", e);
        }
        result
    }

    fn handle_security_error<P: PacketPool>(
        &self,
        connections: &ConnectionManager<P>,
        storage: &ConnectionStorage<<P as PacketPool>::Packet>,
        result: &Result<(), Error>,
    ) -> Result<(), Error> {
        if let Err(error) = result {
            let reason = if let Error::Security(secuity_error) = error {
                *secuity_error
            } else {
                Reason::UnspecifiedReason
            };

            error!("Handling of command failed {:?}", error);

            // Cease sending security manager messages on timeout
            if *error != Error::Timeout {
                let handle = storage.handle.ok_or(Error::InvalidValue)?;
                let mut packet = self.prepare_packet(Command::PairingFailed, connections)?;
                let payload = packet.payload_mut();
                payload[0] = u8::from(reason);

                match self.try_send_packet(packet, connections, handle) {
                    Ok(()) => (),
                    Err(error) => {
                        error!("[security manager] Failed to send pairing failed {:?}", error);
                        return Err(error);
                    }
                }
            }
        }

        Ok(())
    }

    /// Initiate pairing
    pub fn initiate<P: PacketPool>(
        &self,
        connections: &ConnectionManager<'_, P>,
        storage: &ConnectionStorage<<P as PacketPool>::Packet>,
        user_initiated: bool,
    ) -> Result<(), Error> {
        if storage.security_level != SecurityLevel::NoEncryption {
            return Err(Error::Security(Reason::UnspecifiedReason));
        }

        let role = storage.role.ok_or(Error::InvalidValue)?;
        if !self.is_idle() {
            // If pairing is already in progress for this peer, consider the request fulfilled.
            let peer_address_kind = storage.peer_addr_kind.ok_or(Error::InvalidValue)?;
            let peer_identity = storage.peer_identity.ok_or(Error::InvalidValue)?;
            let peer_address = Address {
                kind: peer_address_kind,
                addr: peer_identity.bd_addr,
            };
            if self.is_pairing_in_progress(peer_address) {
                return Ok(());
            }
            return Err(Error::InvalidState);
        }
        let mut pairing_sm = self.pairing_sm.borrow_mut();

        let handle = storage.handle.ok_or(Error::InvalidValue)?;
        let local_address = self.state.borrow().local_address.ok_or(Error::InvalidValue)?;
        let peer_address_kind = storage.peer_addr_kind.ok_or(Error::InvalidValue)?;
        let peer_identity = storage.peer_identity.ok_or(Error::InvalidValue)?;
        let peer_address = Address {
            kind: peer_address_kind,
            addr: peer_identity.bd_addr,
        };
        let mut ops = PairingOpsImpl {
            security_manager: self,
            conn_handle: handle,
            connections,
            storage,
            peer_identity,
        };
        if role == LeConnRole::Peripheral {
            *pairing_sm = Some(Pairing::initiate_peripheral(
                local_address,
                peer_address,
                &mut ops,
                *self.io_capabilities.borrow(),
            )?);
            Ok(())
        } else {
            *pairing_sm = Some(Pairing::initiate_central(
                local_address,
                peer_address,
                &mut ops,
                *self.io_capabilities.borrow(),
                user_initiated,
            )?);
            Ok(())
        }
    }

    /// Cancel pairing after timeout
    pub(crate) fn cancel_timeout(&self) {
        if let Some(pairing) = self.pairing_sm.borrow().as_ref() {
            pairing.mark_timeout();
            self.finished_waker.borrow_mut().wake();
        }
    }

    /// Channel disconnected
    pub(crate) fn disconnect(&self, identity: &Identity) {
        if self
            .pairing_sm
            .borrow()
            .as_ref()
            .is_some_and(|sm| sm.peer_address().addr == identity.bd_addr)
        {
            self.pairing_sm.replace(None);
            self.finished_waker.borrow_mut().wake();
        }
        self.state
            .borrow_mut()
            .bond
            .retain(|x| x.is_bonded || x.identity != *identity);
    }

    /// Handle recevied events from HCI
    pub(crate) fn handle_hci_le_event<P: PacketPool>(
        &self,
        event: LeEventPacket,
        connections: &ConnectionManager<'_, P>,
    ) -> Result<(), Error> {
        #[allow(clippy::single_match)]
        match event.kind {
            LeEventKind::LeLongTermKeyRequest => {
                let event_data = LeLongTermKeyRequest::from_hci_bytes_complete(event.data)?;
                self.try_send_event(SecurityEventData::SendLongTermKey(
                    event_data.handle,
                    event_data.encrypted_diversifier,
                    event_data.random_number,
                ))?;
            }
            _ => (),
        }
        Ok(())
    }

    /// Handle recevied events from HCI
    pub(crate) fn handle_hci_event<P: PacketPool>(
        &self,
        event: EventPacket,
        connections: &ConnectionManager<'_, P>,
    ) -> Result<(), Error> {
        // Extract (handle, status, encrypted) from either encryption event type
        let encryption_event = match event.kind {
            EventKind::EncryptionChangeV1 => {
                let e = EncryptionChangeV1::from_hci_bytes_complete(event.data)?;
                Some((e.handle, e.status, e.enabled != EncryptionEnabledLevel::Off))
            }
            EventKind::EncryptionKeyRefreshComplete => {
                let e = EncryptionKeyRefreshComplete::from_hci_bytes_complete(event.data)?;
                // Key refresh implies encryption is still on
                Some((e.handle, e.status, true))
            }
            _ => None,
        };

        if let Some((handle, status, encrypted)) = encryption_event {
            match status.to_result() {
                Ok(()) => {
                    trace!("[smp] Encryption event (encrypted={})", encrypted);
                    connections.with_connected_handle(handle, |storage| {
                        let sm = self.pairing_sm.borrow();
                        if let Some(sm) = &*sm {
                            let mut rng = self.rng.borrow_mut();
                            let res = sm.handle_event(
                                pairing::Event::LinkEncryptedResult(encrypted),
                                &mut PairingOpsImpl {
                                    security_manager: self,
                                    peer_identity: storage.peer_identity.ok_or(Error::InvalidValue)?,
                                    connections,
                                    storage,
                                    conn_handle: storage.handle.ok_or(Error::InvalidValue)?,
                                },
                                rng.deref_mut(),
                            );
                            let _ = self.handle_security_error(connections, storage, &res);
                            if res.is_ok() {
                                storage.security_level = sm.security_level();
                                storage.bond_rejected = false;
                            }
                            if sm.result().is_some() {
                                self.finished_waker.borrow_mut().wake();
                                let _ = self.events.try_send(SecurityEventData::TimerChange);
                            }
                            res?;
                        } else if let Some(identity) = storage.peer_identity.as_ref() {
                            match self.get_peer_bond_information(identity) {
                                Some(bond) if encrypted => {
                                    info!("[smp] Encrypted using bond {:?}", bond.identity);
                                    storage.security_level = bond.security_level;
                                }
                                _ => {
                                    warn!(
                                        "[smp] Either encryption failed to enable or bond not found for {:?}",
                                        identity
                                    );
                                    storage.security_level = SecurityLevel::NoEncryption;
                                }
                            }
                        }
                        Ok(())
                    })?;
                }
                Err(error) => {
                    error!("[security manager] Encryption event error {:?}", error);
                    connections.with_connected_handle(handle, |storage| {
                        let sm = self.pairing_sm.borrow();
                        if let Some(sm) = &*sm {
                            // If we were waiting for bonded encryption, mark the bond as
                            // rejected on this connection so the next pairing attempt will
                            // skip bonded encryption and initiate fresh pairing instead.
                            if sm.is_waiting_bonded_encryption() {
                                storage.bond_rejected = true;
                            }
                            let mut rng = self.rng.borrow_mut();
                            let _res = sm.handle_event(
                                pairing::Event::LinkEncryptedResult(false),
                                &mut PairingOpsImpl {
                                    security_manager: self,
                                    peer_identity: storage.peer_identity.ok_or(Error::InvalidValue)?,
                                    connections,
                                    storage,
                                    conn_handle: storage.handle.ok_or(Error::InvalidValue)?,
                                },
                                rng.deref_mut(),
                            );
                            // Don't call handle_security_error here: sending SMP PairingFailed
                            // for an HCI-level encryption failure would cause the peer to
                            // delete its bond information, preventing future re-encryption.
                            if sm.result().is_some() {
                                self.finished_waker.borrow_mut().wake();
                                let _ = self.events.try_send(SecurityEventData::TimerChange);
                            }
                        }
                        Ok(())
                    })?;
                }
            }
        }
        Ok(())
    }

    fn handle_event<P: PacketPool>(
        &self,
        pairing_event: pairing::Event,
        connections: &ConnectionManager<'_, P>,
        storage: &ConnectionStorage<P::Packet>,
    ) -> Result<(), Error> {
        let sm = self.pairing_sm.borrow();
        if let Some(sm) = &*sm {
            let mut ops = PairingOpsImpl {
                peer_identity: storage.peer_identity.ok_or(Error::InvalidValue)?,
                security_manager: self,
                conn_handle: storage.handle.ok_or(Error::InvalidValue)?,
                connections,
                storage,
            };
            let mut rng = self.rng.borrow_mut();
            let res = sm.handle_event(pairing_event, &mut ops, rng.deref_mut());
            if res.is_ok() {
                sm.reset_timeout();
                let _ = self.events.try_send(SecurityEventData::TimerChange);
            } else if let Err(e) = self.handle_security_error(connections, storage, &res) {
                error!("[security manager] Failed sending pairing failed message! {:?}", e);
            }
            res?;
        }
        Ok(())
    }

    pub(crate) fn handle_pass_key_input<P: PacketPool>(
        &self,
        input: u32,
        connections: &ConnectionManager<'_, P>,
        storage: &ConnectionStorage<P::Packet>,
    ) -> Result<(), Error> {
        self.handle_event(pairing::Event::PassKeyInput(input), connections, storage)
    }

    pub(crate) fn handle_pass_key_confirm<P: PacketPool>(
        &self,
        confirmed: bool,
        connections: &ConnectionManager<'_, P>,
        storage: &ConnectionStorage<<P as PacketPool>::Packet>,
    ) -> Result<(), Error> {
        let pairing_event = match confirmed {
            true => pairing::Event::PassKeyConfirm,
            false => pairing::Event::PassKeyCancel,
        };
        self.handle_event(pairing_event, connections, storage)
    }

    /// Prepare a packet for sending
    fn prepare_packet<P: PacketPool>(
        &self,
        command: Command,
        connections: &ConnectionManager<P>,
    ) -> Result<TxPacket<P>, Error> {
        let packet = P::allocate().ok_or(Error::OutOfMemory)?;
        TxPacket::new(packet, command)
    }

    /// Send a packet
    fn try_send_packet<P: PacketPool>(
        &self,
        packet: TxPacket<P>,
        connections: &ConnectionManager<P>,
        handle: ConnHandle,
    ) -> Result<(), Error> {
        let len = packet.total_size();
        trace!("[security manager] Send {} {}", packet.command, len);
        connections.try_outbound(handle, packet.into_pdu())
    }

    /// Send a packet
    fn try_send_event(&self, event: SecurityEventData) -> Result<(), Error> {
        self.events.try_send(event).map_err(|_| Error::OutOfMemory)
    }

    /// Poll for security manager work
    pub(crate) fn poll_events(
        &self,
    ) -> impl Future<Output = Result<SecurityEventData, TimeoutError>> + use<'_, BOND_COUNT> {
        let deadline = self
            .pairing_sm
            .borrow()
            .as_ref()
            .map(|x| x.timeout_at())
            .unwrap_or(Instant::now() + constants::TIMEOUT_DISABLE);
        // try to pop an event from the channel
        poll_fn(|cx| self.events.poll_receive(cx)).with_deadline(deadline)
    }
}

struct PairingOpsImpl<'sm, 'cm, 'cm2, 'cs, const B: usize, P: PacketPool> {
    security_manager: &'sm SecurityManager<B>,
    connections: &'cm ConnectionManager<'cm2, P>,
    storage: &'cs ConnectionStorage<P::Packet>,
    conn_handle: ConnHandle,
    peer_identity: Identity,
}

impl<'sm, 'cm, 'cm2, 'cs, const B: usize, P: PacketPool> PairingOps<P> for PairingOpsImpl<'sm, 'cm, 'cm2, 'cs, B, P> {
    fn try_send_packet(&mut self, packet: TxPacket<P>) -> Result<(), Error> {
        self.security_manager
            .try_send_packet(packet, self.connections, self.connection_handle())?;
        let _ = self.security_manager.events.try_send(SecurityEventData::TimerChange);
        Ok(())
    }

    fn try_update_bond_information(&mut self, bond: &BondInformation) -> Result<(), Error> {
        self.security_manager.add_bond_information(bond.clone())
    }

    fn find_bond(&self) -> Option<BondInformation> {
        self.security_manager
            .state
            .borrow()
            .bond
            .iter()
            .find(|x| x.identity.match_identity(&self.peer_identity))
            .cloned()
    }

    fn try_enable_encryption(
        &mut self,
        ltk: &LongTermKey,
        security_level: SecurityLevel,
        is_bonded: bool,
        #[cfg(feature = "legacy-pairing")] ediv: u16,
        #[cfg(feature = "legacy-pairing")] rand: [u8; 8],
    ) -> Result<BondInformation, Error> {
        info!("Enabling encryption for {:?}", self.peer_identity);
        let bond_info = BondInformation {
            ltk: *ltk,
            identity: self.peer_identity,
            is_bonded,
            security_level,
            #[cfg(feature = "legacy-pairing")]
            ediv,
            #[cfg(feature = "legacy-pairing")]
            rand,
        };
        self.try_update_bond_information(&bond_info)?;
        self.security_manager
            .try_send_event(SecurityEventData::EnableEncryption(self.conn_handle, bond_info.clone()))?;
        Ok(bond_info)
    }

    fn try_enable_bonded_encryption(&mut self) -> Result<Option<BondInformation>, Error> {
        if self.storage.bond_rejected {
            return Ok(None);
        }
        if let Some(bond) = self.find_bond() {
            self.security_manager
                .try_send_event(SecurityEventData::EnableEncryption(self.conn_handle, bond.clone()))?;
            Ok(Some(bond))
        } else {
            Ok(None)
        }
    }

    fn bonding_flag(&self) -> BondingFlag {
        if self.storage.bondable {
            BondingFlag::Bonding
        } else {
            BondingFlag::NoBonding
        }
    }

    fn connection_handle(&mut self) -> ConnHandle {
        self.conn_handle
    }

    fn try_send_connection_event(&mut self, event: ConnectionEvent) -> Result<(), Error> {
        let timer_changed = matches!(
            event,
            ConnectionEvent::PairingComplete { .. } | ConnectionEvent::PairingFailed(_)
        );
        self.storage.events.try_send(event).map_err(|_| Error::OutOfMemory)?;
        if timer_changed {
            let _ = self.security_manager.events.try_send(SecurityEventData::TimerChange);
        }
        Ok(())
    }
}

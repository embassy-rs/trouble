#![warn(missing_docs)]
//! # Bluetooth Security Manager
// ([Vol 3] Part H, Section 3.5.5)

mod constants;
mod crypto;
mod pairing;
mod types;
use core::cell::RefCell;
use core::future::{poll_fn, Future};
use core::ops::DerefMut;

use bt_hci::event::le::{LeEventKind, LeEventPacket, LeLongTermKeyRequest};
use bt_hci::event::{EncryptionChangeV1, EventKind, EventPacket};
use bt_hci::param::{ConnHandle, EncryptionEnabledLevel, LeConnRole};
use bt_hci::FromHciBytes;
pub use crypto::{IdentityResolvingKey, LongTermKey};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
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
use crate::security_manager::types::BondingFlag;
use crate::types::l2cap::L2CAP_CID_LE_U_SECURITY_MANAGER;
use crate::{Address, Error, Identity, IoCapabilities, PacketPool};

/// Events of interest to the security manager
pub(crate) enum SecurityEventData {
    /// A long term key request has been issued
    SendLongTermKey(ConnHandle),
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
}

impl BondInformation {
    /// Create a BondInformation
    pub fn new(identity: Identity, ltk: LongTermKey, security_level: SecurityLevel, is_bonded: bool) -> Self {
        Self {
            ltk,
            identity,
            is_bonded,
            security_level,
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

/// Pairing methods
#[derive(Debug, Clone, Copy, PartialEq)]
enum PairingMethod {
    /// Uninitialized pairing
    None,
    /// Numeric Comparison
    LeSecureConnectionNumericComparison,
    /// Passkey entry
    LeSecureConnectionPasskey,
    /// Out-of-band
    LeSecureConnectionOob,
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
    /// Received events
    events: Channel<NoopRawMutex, SecurityEventData, 2>,
    /// Io capabilities
    io_capabilities: RefCell<IoCapabilities>,
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
            io_capabilities: RefCell::new(IoCapabilities::NoInputNoOutput),
        }
    }

    /// Set the IO capabilities
    pub(crate) fn set_io_capabilities(&self, io_capabilities: IoCapabilities) {
        self.io_capabilities.replace(io_capabilities);
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

    fn get_peer_bond_information(&self, identity: &Identity) -> Option<BondInformation> {
        trace!("[security manager] Find long term key for {:?}", identity);
        self.state.borrow().bond.iter().find_map(|bond| {
            if bond.identity.match_identity(identity) {
                Some(bond.clone())
            } else {
                None
            }
        })
    }

    /// Get the long term key for peer
    pub(crate) fn get_peer_long_term_key(&self, identity: &Identity) -> Option<LongTermKey> {
        trace!("[security manager] Find long term key for {:?}", identity);
        self.state.borrow().bond.iter().find_map(|bond| {
            if bond.identity.match_identity(identity) {
                Some(bond.ltk)
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
            let mut state_machine = self.pairing_sm.borrow_mut();
            if state_machine.is_none() {
                *state_machine = Some(Pairing::new_peripheral(
                    self.state.borrow().local_address.unwrap(),
                    peer_address,
                    *self.io_capabilities.borrow(),
                ));
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
            let mut state_machine = self.pairing_sm.borrow_mut();
            if state_machine.is_none() {
                *state_machine = Some(Pairing::new_central(
                    self.state.borrow().local_address.unwrap(),
                    peer_address,
                    *self.io_capabilities.borrow(),
                ));
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
            let reason = if let Error::Security(security_error) = error {
                *security_error
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
    ) -> Result<(), Error> {
        if storage.security_level != SecurityLevel::NoEncryption {
            return Err(Error::Security(Reason::UnspecifiedReason));
        }

        let role = storage.role.ok_or(Error::InvalidValue)?;
        let mut pairing_sm = self.pairing_sm.borrow_mut();
        if pairing_sm.is_none() {
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
                )?);
                Ok(())
            }
        } else {
            Err(Error::InvalidState)
        }
    }

    /// Cancel pairing after timeout
    pub(crate) fn cancel_timeout(&self) {
        if let Some(pairing) = self.pairing_sm.borrow().as_ref() {
            pairing.mark_timeout();
        }
    }

    /// Channel disconnected
    pub(crate) fn disconnect(&self, handle: ConnHandle, identity: Option<Identity>) -> Result<(), Error> {
        self.pairing_sm.replace(None);
        if let Some(identity) = identity {
            self.state
                .borrow_mut()
                .bond
                .retain(|x| x.is_bonded || x.identity != identity);
        }

        Ok(())
    }

    /// Handle received events from HCI
    pub(crate) fn handle_hci_le_event<P: PacketPool>(
        &self,
        event: LeEventPacket,
        connections: &ConnectionManager<'_, P>,
    ) -> Result<(), Error> {
        #[allow(clippy::single_match)]
        match event.kind {
            LeEventKind::LeLongTermKeyRequest => {
                let event_data = LeLongTermKeyRequest::from_hci_bytes_complete(event.data)?;
                self.try_send_event(SecurityEventData::SendLongTermKey(event_data.handle))?;
            }
            _ => (),
        }
        Ok(())
    }

    /// Handle received events from HCI
    pub(crate) fn handle_hci_event<P: PacketPool>(
        &self,
        event: EventPacket,
        connections: &ConnectionManager<'_, P>,
    ) -> Result<(), Error> {
        #[allow(clippy::single_match)]
        match event.kind {
            EventKind::EncryptionChangeV1 => {
                let event_data = EncryptionChangeV1::from_hci_bytes_complete(event.data)?;
                match event_data.status.to_result() {
                    Ok(()) => {
                        trace!("[smp] Encryption Changed event {:?}", event_data.enabled);
                        connections.with_connected_handle(event_data.handle, |storage| {
                            let sm = self.pairing_sm.borrow();
                            if let Some(sm) = &*sm {
                                let mut rng = self.rng.borrow_mut();
                                let res = sm.handle_event(
                                    pairing::Event::LinkEncryptedResult(
                                        event_data.enabled != EncryptionEnabledLevel::Off,
                                    ),
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
                                match res {
                                    Ok(_) => {
                                        storage.security_level = sm.security_level();
                                        Ok(())
                                    }
                                    x => x,
                                }?
                            } else if let Some(identity) = storage.peer_identity.as_ref() {
                                match self.get_peer_bond_information(identity) {
                                    Some(bond) if event_data.enabled != EncryptionEnabledLevel::Off => {
                                        info!("[smp] Encryption changed to true using bond {:?}", bond.identity);
                                        storage.security_level = bond.security_level;
                                    }
                                    _ => {
                                        warn!(
                                            "[smp] Either encryption failed to enable or bond not found for {:?}",
                                            identity
                                        );
                                        storage.security_level = SecurityLevel::NoEncryption
                                    }
                                }
                            }
                            Ok(())
                        })?;
                    }
                    Err(error) => {
                        error!("[security manager] Encryption Changed Handle Error {:?}", error);
                    }
                }
            }
            _ => (),
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
            .unwrap_or(Instant::MAX /*no timeout*/);
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

    fn try_enable_encryption(
        &mut self,
        ltk: &LongTermKey,
        security_level: SecurityLevel,
        is_bonded: bool,
    ) -> Result<BondInformation, Error> {
        info!("Enabling encryption for {:?}", self.peer_identity);
        //let bond_info = self.store_pairing()?;
        let bond_info = BondInformation {
            ltk: *ltk,
            identity: self.peer_identity,
            is_bonded,
            security_level,
        };
        self.security_manager.add_bond_information(bond_info.clone())?;
        self.security_manager
            .try_send_event(SecurityEventData::EnableEncryption(self.conn_handle, bond_info.clone()))?;
        Ok(bond_info)
    }

    fn try_enable_bonded_encryption(&mut self) -> Result<Option<BondInformation>, Error> {
        if let Some(bond) = self
            .security_manager
            .state
            .borrow()
            .bond
            .iter()
            .find(|x| x.identity.match_identity(&self.peer_identity))
        {
            self.security_manager
                .try_send_event(SecurityEventData::EnableEncryption(self.conn_handle, bond.clone()))?;
            Ok(Some(bond.clone()))
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

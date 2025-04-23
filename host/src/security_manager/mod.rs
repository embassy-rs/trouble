#![warn(missing_docs)]
//! # Bluetooth Security Manager
// ([Vol 3] Part H, Section 3.5.5)

mod constants;
mod crypto;
mod types;

use core::cell::RefCell;
use core::future::{poll_fn, Future};
use core::ops::DerefMut;

use bt_hci::event::le::LeEvent;
use bt_hci::event::Event;
use bt_hci::param::{AddrKind, BdAddr, ConnHandle, LeConnRole};
use constants::ENCRYPTION_KEY_SIZE_128_BITS;
pub use crypto::IdentityResolvingKey;
pub use crypto::LongTermKey;
use crypto::{Check, Confirm, DHKey, MacKey, Nonce, PublicKey, SecretKey};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Instant, TimeoutError, WithTimeout};
use heapless::Vec;
use rand_chacha::ChaCha12Rng;
use rand_core::SeedableRng;
pub use types::Reason;
use types::{AuthReq, BondingFlag, Command, IoCapabilities, PairingFeatures};

use crate::codec::{Decode, Encode};
use crate::connection_manager::{ConnectionManager, ConnectionStorage};
use crate::pdu::Pdu;
use crate::prelude::Connection;
use crate::security_manager::types::UseOutOfBand;
use crate::types::l2cap::L2CAP_CID_LE_U_SECURITY_MANAGER;
use crate::{Address, Error};
use crate::{Identity, PacketPool};

/// Events of interest to the security manager
pub(crate) enum SecurityEventData {
    /// A long term key request has been issued
    SendLongTermKey(ConnHandle),
    /// Enable encryption on channel
    EnableEncryption(ConnHandle, BondInformation),
    /// Pairing timeout
    Timeout,
    /// Oairing timer changed
    TimerChange,
}

/// Bond Information
#[derive(Clone, Debug, PartialEq)]
pub struct BondInformation {
    /// Long Term Key (LTK)
    pub ltk: LongTermKey,
    /// Peer identity
    pub identity: Identity,
    // Connection Signature Resolving Key (CSRK)?
}

impl BondInformation {
    /// Create a BondInformation
    pub fn new(identity: Identity, ltk: LongTermKey) -> Self {
        Self { ltk, identity }
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

/// Pairing states
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum PairingState {
    /// No pairing initialized
    Idle,
    /// Security request from peripheral
    SecurityRequest,
    /// Pairing requested by central
    Request,
    /// Pairing received by peripheral
    Response,
    /// Central public key exchange
    CentralPublicKey,
    /// Peripheral public key exchange
    PeripheralPublicKey,
    /// Peripheral confirm
    PeripheralConfirm,
    /// Central random
    CentralRandom,
    /// Peripheral random
    PeripheralRandom,
    /// Central key check
    CentralKeyCheck,
    /// Peripheral key check
    PeripheralKeyCheck,
    /// Security change event
    SecurityChangeEvent,
    /// Pairing failed
    Failed,
    /// Pairing complete
    Complete,
}

/// Pairing stateful data
struct PairingData {
    /// Connection role, Central or Peripheral
    role: LeConnRole,
    /// Pairing method used
    method: PairingMethod,
    /// Pairing state
    state: PairingState,
    /// Connection handle used in pairing
    handle: Option<ConnHandle>,
    /// Local security features
    local_features: Option<PairingFeatures>,
    /// Peer security features
    peer_features: Option<PairingFeatures>,
    /// Local secret key
    secret_key: Option<SecretKey>,
    /// Local public key
    public_key: Option<PublicKey>,
    /// Peer public key
    public_key_peer: Option<PublicKey>,
    /// Peer random
    peer_nonce: Option<Nonce>,
    /// Local random
    local_nonce: Option<Nonce>,
    /// DH key
    dh_key: Option<DHKey>,
    /// Received confirm
    confirm: Option<Confirm>,
    /// MAC key
    mac_key: Option<MacKey>,
    /// Local check value
    local_check: Option<Check>,
    /// Long term key
    ltk: Option<u128>,
    /// Peer device address
    peer_address: Option<Address>,
    /// Identity Resolving Key
    irk: Option<IdentityResolvingKey>,
}

impl PairingData {
    /// Create new pairing data
    pub(crate) fn new() -> Self {
        Self {
            state: PairingState::Idle,
            method: PairingMethod::None,
            role: LeConnRole::Peripheral,
            handle: None,
            local_features: None,
            peer_features: None,
            secret_key: None,
            public_key: None,
            public_key_peer: None,
            peer_nonce: None,
            local_nonce: None,
            dh_key: None,
            confirm: None,
            mac_key: None,
            local_check: None,
            ltk: None,
            peer_address: None,
            irk: None,
        }
    }
    /// Clear pairing data
    pub(crate) fn clear(&mut self) {
        self.state = PairingState::Idle;
        self.method = PairingMethod::None;
        self.role = LeConnRole::Peripheral;
        self.handle = None;
        self.local_features = None;
        self.peer_features = None;
        self.secret_key = None;
        self.public_key = None;
        self.public_key_peer = None;
        self.peer_nonce = None;
        self.local_nonce = None;
        self.dh_key = None;
        self.confirm = None;
        self.mac_key = None;
        self.local_check = None;
        self.ltk = None;
        self.peer_address = None;
    }
}

// TODO: IRK exchange, HCI_LE_­Add_­Device_­To_­Resolving_­List

// LESC LE Security Connections Pairing over L2CAP
// Central               Peripheral
// ------ Phase 1 ------
// Optional Security Request <----
// Pairing Request ---->
// Pairing Response <---
// ------ Phase 2 -------
// Pairing Public Key ---->
// Pairing Public Key <----
// ----- Numeric Comparison -----
// Pairing Confirm <----
// Pairing Random ---->
// Pairing Random <----
// ----- Passkey -----
// Keypress notification <----
// Pairing Confirm ---->
// Pairing Confirm <----
// Pairing Random ---->
// Pairing Random <----
// ----- Out-of-band -----
//  --- OOB Confirm ---
// Pairing Random ---->
// Pairing Random <----
// ------ Phase 3 ------
// Pairing DH key check ---->
// Pairing DH key check <----
// ----- Key Distribution (HCI) -----

/// Security manager that handles SM packet
pub struct SecurityManager<const BOND_COUNT: usize> {
    /// Random generator
    rng: RefCell<ChaCha12Rng>,
    /// Security manager data
    state: RefCell<SecurityManagerData<BOND_COUNT>>,
    /// Current state of the pairing
    pairing_state: RefCell<PairingData>,
    /// Received events
    events: Channel<NoopRawMutex, SecurityEventData, 2>,
    result_signal: Signal<NoopRawMutex, Reason>,
    /// Timer
    timer_expires: RefCell<Instant>,
}

enum TimerCommand {
    Stop,
    Start,
}

impl<const BOND_COUNT: usize> SecurityManager<BOND_COUNT> {
    /// Create a new SecurityManager
    pub(crate) fn new() -> Self {
        let random_seed = [0u8; 32];
        Self {
            rng: RefCell::new(ChaCha12Rng::from_seed(random_seed)),
            state: RefCell::new(SecurityManagerData::new()),
            events: Channel::new(),
            pairing_state: RefCell::new(PairingData::new()),
            result_signal: Signal::new(),
            timer_expires: RefCell::new(Instant::now() + Self::TIMEOUT_DISABLE),
        }
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

    /// Get the long term key for peer
    pub(crate) fn get_peer_long_term_key(&self, identity: &Identity) -> Option<LongTermKey> {
        trace!("[security manager] Find long term key for {:?}", identity);
        self.state.borrow().bond.iter().find_map(|bond| {
            info!("Matching address: {}", bond);
            if bond.identity.match_identity(identity) {
                Some(bond.ltk)
            } else {
                None
            }
        })
    }

    /// Get the result of the pairing
    pub(crate) async fn get_result(&self) -> Reason {
        self.result_signal.wait().await
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

    /// Handle packet
    pub(crate) fn handle<P: PacketPool>(
        &self,
        pdu: Pdu<P::Packet>,
        connections: &ConnectionManager<P>,
        storage: &ConnectionStorage<P::Packet>,
    ) -> Result<(), Error> {
        // Should it be possible to handle multiple concurrent pairings?
        let role = storage.role.ok_or(Error::InvalidValue)?;
        let handle = storage.handle.ok_or(Error::InvalidValue)?;
        let peer_address_kind = storage.peer_addr_kind.ok_or(Error::InvalidValue)?;
        let peer_identity = storage.peer_identity.ok_or(Error::InvalidValue)?;
        let peer_address = Address {
            kind: peer_address_kind,
            addr: peer_identity.bd_addr,
        };

        let result = {
            let mut buffer = [0u8; 72];
            let size = {
                let size = pdu.len.min(buffer.len());
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
            let pairing_peer_address = {
                let pairing_state = self.pairing_state.borrow();
                if role != pairing_state.role {
                    return Err(Error::InvalidValue);
                }

                if let Some(pairing_handle) = pairing_state.handle {
                    if pairing_handle != handle {
                        error!(
                            "Mismatching connection handle {} != {}",
                            pairing_handle.raw(),
                            handle.raw()
                        );
                        return Err(Error::InvalidValue);
                    }
                }

                pairing_state.peer_address
            };

            if let Some(address) = pairing_peer_address {
                if address != peer_address {
                    return Err(Error::InvalidValue);
                }
            } else {
                self.pairing_state.borrow_mut().peer_address = Some(peer_address);
            }

            {
                match command {
                    Command::PairingRequest
                    | Command::PairingResponse
                    | Command::PairingPublicKey
                    | Command::PairingConfirm
                    | Command::PairingRandom
                    | Command::PairingDhKeyCheck => {
                        self.timer_reset()?;
                    }
                    _ => (),
                }
            }

            trace!("Security Manager Protocol command {}", command);

            match command {
                Command::PairingRequest => self.handle_pairing_request(payload, connections, handle),
                Command::PairingResponse => self.handle_pairing_response(payload, connections, handle),
                Command::PairingPublicKey => self.handle_pairing_public_key(payload, connections, handle),
                Command::PairingConfirm => self.handle_pairing_confirm(payload, connections, handle),
                Command::PairingRandom => self.handle_pairing_random(payload, connections, handle, storage),
                Command::PairingDhKeyCheck => self.handle_pairing_dhkey_check(payload, connections, handle, storage),
                Command::PairingFailed => self.handle_pairing_failed(payload),
                Command::IdentityInformation => self.handle_identity_information(payload, handle),
                Command::IdentityAddressInformation => self.handle_identity_address_information(payload),
                _ => {
                    warn!("Unhandled Security Manager Protocol command {}", command);
                    Ok(())
                }
            }
        };
        if let Err(ref error) = result {
            let reason = if let Error::Security(secuity_error) = error {
                *secuity_error
            } else {
                Reason::UnspecifiedReason
            };

            error!("Handling of command failed {:?}", error);

            // Cease sending security manager messages on timeout
            if *error != Error::Timeout {
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
            self.pairing_result(reason)?;
        }
        result
    }

    /// Initiate pairing
    pub fn initiate<P: PacketPool>(&self, connection: &Connection<P>) -> Result<(), Error> {
        if connection.role() == LeConnRole::Central {
            let peer_identity = connection.peer_identity();
            if let Some(ltk) = self.get_peer_long_term_key(&peer_identity) {
                self.try_send_event(SecurityEventData::EnableEncryption(
                    connection.handle(),
                    BondInformation::new(peer_identity, ltk),
                ))?;
                {
                    let mut pairing_state = self.pairing_state.borrow_mut();
                    pairing_state.role = connection.role();
                    pairing_state.handle = Some(connection.handle());
                    pairing_state.state = PairingState::SecurityChangeEvent;
                }
                self.timer_reset()?;
            } else {
                // Send pairing request
                let local_features = PairingFeatures {
                    io_capabilities: IoCapabilities::NoInputNoOutput,
                    security_properties: AuthReq::new(BondingFlag::Bonding),
                    ..Default::default()
                };

                let mut packet: TxPacket<P> =
                    TxPacket::new(P::allocate().ok_or(Error::OutOfMemory)?, Command::PairingRequest)?;

                let payload = packet.payload_mut();

                local_features.encode(payload).map_err(|_| Error::InvalidValue)?;

                match connection.try_send(packet.into_pdu()) {
                    Ok(()) => (),
                    Err(error) => {
                        error!("[security manager] Failed to respond to request {:?}", error);
                        return Err(error);
                    }
                }

                {
                    let mut pairing_state = self.pairing_state.borrow_mut();
                    pairing_state.role = connection.role();
                    pairing_state.handle = Some(connection.handle());
                    pairing_state.state = PairingState::Request;
                    pairing_state.local_features = Some(local_features);
                    pairing_state.method =
                        self.choose_pairing_method(&pairing_state.local_features, &pairing_state.peer_features);
                    self.timer_reset()?;
                }
            }
        } else {
            // Send sequrity request to central
            let auth_req = AuthReq::new(BondingFlag::Bonding);

            let mut packet: TxPacket<P> =
                TxPacket::new(P::allocate().ok_or(Error::OutOfMemory)?, Command::SecurityRequest)?;

            let response = packet.payload_mut();

            response[0] = auth_req.into();

            match connection.try_send(packet.into_pdu()) {
                Ok(()) => (),
                Err(error) => {
                    error!("[security manager] Failed to send security request {:?}", error);
                    return Err(error);
                }
            }

            {
                let mut pairing_state = self.pairing_state.borrow_mut();
                pairing_state.state = PairingState::SecurityRequest;
                self.timer_reset()?;
            }
        }

        Ok(())
    }

    /// Cancel pairing after timeout
    pub(crate) fn cancel_timeout(&self) -> Result<(), Error> {
        self.timer_disable()?;
        // Stop responding to security manager protocol after time-out,
        // New pairing requires a new link
        {
            let mut pairing_state = self.pairing_state.borrow_mut();
            pairing_state.state = PairingState::Failed;
        }
        Ok(())
    }

    /// Channel disconnected
    pub(crate) fn disconnect(&self, handle: ConnHandle) -> Result<(), Error> {
        let mut pairing_state = self.pairing_state.borrow_mut();
        if let Some(pairing_handle) = pairing_state.handle {
            if pairing_handle != handle {
                error!(
                    "Mismatching connection handle {} != {}",
                    pairing_handle.raw(),
                    handle.raw()
                );
                return Err(Error::InvalidValue);
            } else {
                pairing_state.clear();
            }
        } else {
            pairing_state.clear();
        }
        Ok(())
    }

    /// Handle pairing response command
    fn handle_pairing_failed(&self, payload: &[u8]) -> Result<(), Error> {
        let reason = if let Ok(r) = Reason::try_from(payload[0]) {
            r
        } else {
            Reason::UnspecifiedReason
        };
        error!("[security manager] Pairing failed {}", reason);
        self.pairing_result(reason)
    }

    /// Handle pairing request command
    fn handle_pairing_request<P: PacketPool>(
        &self,
        payload: &[u8],
        connections: &ConnectionManager<P>,
        handle: ConnHandle,
    ) -> Result<(), Error> {
        let peer_features = PairingFeatures::decode(payload).map_err(|_| Error::Security(Reason::InvalidParameters))?;
        {
            let pairing_state = self.pairing_state.borrow();
            if pairing_state.role == LeConnRole::Central {
                return Err(Error::Security(Reason::CommandNotSupported));
            }
        }
        if peer_features.maximum_encryption_key_size < ENCRYPTION_KEY_SIZE_128_BITS {
            return Err(Error::Security(Reason::EncryptionKeySize));
        }
        if !peer_features.security_properties.secure_connection() {
            return Err(Error::Security(Reason::UnspecifiedReason));
        }
        let mut local_features = PairingFeatures {
            io_capabilities: IoCapabilities::NoInputNoOutput,
            security_properties: AuthReq::new(BondingFlag::Bonding),
            ..Default::default()
        };

        // Set identity key flag
        if peer_features.initiator_key_distribution.identity_key() {
            local_features.initiator_key_distribution.set_identity_key();
        }

        {
            let pairing_state = self.pairing_state.borrow();

            if pairing_state.state != PairingState::Idle {
                return Err(Error::InvalidState);
            }

            let mut packet = self.prepare_packet(Command::PairingResponse, connections)?;

            let response = packet.payload_mut();
            local_features.encode(response).map_err(|_| Error::InvalidValue)?;

            match self.try_send_packet(packet, connections, handle) {
                Ok(()) => (),
                Err(error) => {
                    error!("[security manager] Failed to respond to request {:?}", error);
                    return Err(error);
                }
            }
        }

        {
            let mut pairing_state = self.pairing_state.borrow_mut();
            pairing_state.local_features = Some(local_features);
            pairing_state.peer_features = Some(peer_features);
            pairing_state.handle = Some(handle);
            pairing_state.state = PairingState::Response;
            pairing_state.method =
                self.choose_pairing_method(&pairing_state.local_features, &pairing_state.peer_features);
        }

        Ok(())
    }

    /// Handle pairing response command
    fn handle_pairing_response<P: PacketPool>(
        &self,
        payload: &[u8],
        connections: &ConnectionManager<P>,
        handle: ConnHandle,
    ) -> Result<(), Error> {
        let peer_features = PairingFeatures::decode(payload).map_err(|_| Error::Security(Reason::InvalidParameters))?;
        {
            let pairing_state = self.pairing_state.borrow();
            if pairing_state.state != PairingState::Request {
                return Err(Error::InvalidState);
            }
        }

        let mut rng_borrow = self.rng.borrow_mut();
        let rng = rng_borrow.deref_mut();

        let secret_key = SecretKey::new(rng);
        let public_key = secret_key.public_key();

        let mut packet = self.prepare_packet(Command::PairingPublicKey, connections)?;

        let response = packet.payload_mut();

        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(public_key.x.as_be_bytes());
        y.copy_from_slice(public_key.y.as_be_bytes());
        x.reverse();
        y.reverse();

        response[..x.len()].copy_from_slice(&x);
        response[x.len()..y.len() + x.len()].copy_from_slice(&y);

        match self.try_send_packet(packet, connections, handle) {
            Ok(()) => (),
            Err(error) => {
                error!("[security manager] Failed to respond to request {:?}", error);
                return Err(error);
            }
        }

        {
            let mut pairing_state = self.pairing_state.borrow_mut();
            pairing_state.peer_features = Some(peer_features);
            pairing_state.public_key = Some(public_key);
            pairing_state.secret_key = Some(secret_key);
            pairing_state.state = PairingState::CentralPublicKey;
        }

        Ok(())
    }

    /// Handle pairing public key command
    fn handle_pairing_public_key<P: PacketPool>(
        &self,
        payload: &[u8],
        connections: &ConnectionManager<P>,
        handle: ConnHandle,
    ) -> Result<(), Error> {
        let role = {
            let pairing_state = self.pairing_state.borrow();
            if (pairing_state.role == LeConnRole::Central && pairing_state.state == PairingState::CentralPublicKey)
                || (pairing_state.role == LeConnRole::Peripheral && pairing_state.state == PairingState::Response)
            {
                pairing_state.role
            } else {
                return Err(Error::InvalidValue);
            }
        };

        let peer_public_key = PublicKey::from_bytes(payload);
        let mut rng_borrow = self.rng.borrow_mut();
        let rng = rng_borrow.deref_mut();

        if role == LeConnRole::Central {
            let (dh_key, local_nonce, method) = {
                let pairing_state = self.pairing_state.borrow();

                if pairing_state.state != PairingState::CentralPublicKey {
                    return Err(Error::InvalidState);
                }

                let secret_key = pairing_state.secret_key.as_ref().ok_or(Error::InvalidValue)?;

                let dh_key = match secret_key.dh_key(peer_public_key) {
                    Some(dh_key) => Ok(dh_key),
                    None => Err(Error::Security(Reason::InvalidParameters)),
                }?;
                let local_nonce = Nonce::new(rng);
                (dh_key, local_nonce, pairing_state.method)
            };
            if method != PairingMethod::LeSecureConnectionNumericComparison {
                return Err(Error::InvalidValue);
            }
            {
                let mut pairing_state = self.pairing_state.borrow_mut();
                pairing_state.public_key_peer = Some(peer_public_key);
                pairing_state.local_nonce = Some(local_nonce);
                pairing_state.dh_key = Some(dh_key);
                pairing_state.state = PairingState::PeripheralPublicKey;
            }
        } else {
            let secret_key = SecretKey::new(rng);
            let public_key = secret_key.public_key();

            let mut x = [0u8; 32];
            let mut y = [0u8; 32];
            x.copy_from_slice(public_key.x.as_be_bytes());
            y.copy_from_slice(public_key.y.as_be_bytes());
            x.reverse();
            y.reverse();

            let mut packet = self.prepare_packet(Command::PairingPublicKey, connections)?;

            let response = packet.payload_mut();

            response[..x.len()].copy_from_slice(&x);
            response[x.len()..y.len() + x.len()].copy_from_slice(&y);

            match self.try_send_packet(packet, connections, handle) {
                Ok(()) => (),
                Err(error) => {
                    error!("[security manager] Failed to send public key {:?}", error);
                    return Err(error);
                }
            }

            let dh_key = match secret_key.dh_key(peer_public_key) {
                Some(dh_key) => Ok(dh_key),
                None => Err(Error::Security(Reason::InvalidParameters)),
            }?;

            // SUBTLE: The order of these send/recv ops is important. See last
            // paragraph of Section 2.3.5.6.2.
            let local_nonce = Nonce::new(rng);
            let confirm = local_nonce.f4(public_key.x(), peer_public_key.x(), 0);

            let mut packet = self.prepare_packet(Command::PairingConfirm, connections)?;

            let response = packet.payload_mut();

            response.copy_from_slice(&confirm.0.to_le_bytes());

            match self.try_send_packet(packet, connections, handle) {
                Ok(()) => (),
                Err(error) => {
                    error!("[security manager] Failed to send confirm {:?}", error);
                    return Err(error);
                }
            }
            {
                let mut pairing_state = self.pairing_state.borrow_mut();
                pairing_state.state = PairingState::PeripheralConfirm;
                pairing_state.public_key_peer = Some(peer_public_key);
                pairing_state.public_key = Some(public_key);
                pairing_state.secret_key = Some(secret_key);
                pairing_state.local_nonce = Some(local_nonce);
                pairing_state.dh_key = Some(dh_key);
            }
        }

        Ok(())
    }

    /// Handle pairing confirm command
    fn handle_pairing_confirm<P: PacketPool>(
        &self,
        payload: &[u8],
        connections: &ConnectionManager<P>,
        handle: ConnHandle,
    ) -> Result<(), Error> {
        let confirm = Confirm(u128::from_le_bytes(
            payload.try_into().map_err(|_| Error::InvalidValue)?,
        ));
        {
            let pairing_state = self.pairing_state.borrow();

            let local_nonce = match pairing_state.local_nonce {
                Some(n) => Ok(n),
                None => {
                    error!("[security manager] Uninitialized nonce");
                    Err(Error::InvalidValue)
                }
            }?;

            let mut packet = self.prepare_packet(Command::PairingRandom, connections)?;

            let response = packet.payload_mut();

            response.copy_from_slice(&local_nonce.0.to_le_bytes());

            match self.try_send_packet(packet, connections, handle) {
                Ok(()) => (),
                Err(error) => {
                    error!("[security manager] Failed to send random {:?}", error);
                    return Err(error);
                }
            }
        }

        {
            let mut pairing_state = self.pairing_state.borrow_mut();
            pairing_state.state = PairingState::CentralRandom;
            pairing_state.confirm = Some(confirm);
        }

        Ok(())
    }

    /// Handle pairing random command
    fn handle_pairing_random<P: PacketPool>(
        &self,
        payload: &[u8],
        connections: &ConnectionManager<P>,
        handle: ConnHandle,
        storage: &ConnectionStorage<P::Packet>,
    ) -> Result<(), Error> {
        let peer_nonce = Nonce(u128::from_le_bytes(
            payload
                .try_into()
                .map_err(|_| Error::Security(Reason::InvalidParameters))?,
        ));
        let (role, local_nonce, local_public_key, peer_public_key) = {
            let pairing_state = self.pairing_state.borrow();
            let local_nonce = pairing_state.local_nonce.ok_or(Error::InvalidValue)?;
            let local_public_key = pairing_state.public_key.ok_or(Error::InvalidValue)?;
            let peer_public_key = pairing_state.public_key_peer.ok_or(Error::InvalidValue)?;
            (pairing_state.role, local_nonce, local_public_key, peer_public_key)
        };
        if role == LeConnRole::Central {
            let pairing_state = self.pairing_state.borrow();
            let peer_confirm = pairing_state.confirm.ok_or(Error::InvalidValue)?;
            // Calculate and check confirm
            let local_confirm = peer_nonce.f4(peer_public_key.x(), local_public_key.x(), 0);
            if local_confirm != peer_confirm {
                return Err(Error::Security(Reason::ConfirmValueFailed));
            }
        } else {
            let mut packet = self.prepare_packet(Command::PairingRandom, connections)?;

            let response = packet.payload_mut();

            response.copy_from_slice(&local_nonce.0.to_le_bytes());

            match self.try_send_packet(packet, connections, handle) {
                Ok(()) => (),
                Err(error) => {
                    error!("[security manager] Failed to send random {:?}", error);
                    return Err(error);
                }
            }
        }
        let (peer_nonce, mac_key, ltk, local_check) = {
            let pairing_state = self.pairing_state.borrow();
            let peer_address_kind = storage.peer_addr_kind.ok_or(Error::InvalidValue)?;
            let peer_identity = storage.peer_identity.ok_or(Error::InvalidValue)?;
            let peer_address = Address {
                kind: peer_address_kind,
                addr: peer_identity.bd_addr,
            };
            let local_address = self.state.borrow().local_address.ok_or(Error::InvalidValue)?;
            let dh_key = pairing_state.dh_key.as_ref().ok_or(Error::InvalidValue)?;
            let local_features = pairing_state.local_features.ok_or(Error::InvalidValue)?;

            let vb = if role == LeConnRole::Peripheral {
                peer_nonce.g2(peer_public_key.x(), local_public_key.x(), &local_nonce)
            } else {
                local_nonce.g2(local_public_key.x(), peer_public_key.x(), &peer_nonce)
            };

            // should display the code and get confirmation from user (pin ok or not) - if not okay send a pairing-failed
            // assume it's correct or the user will cancel on central
            info!("Display code is ** {} **", vb.0);

            // Authentication stage 2 and long term key calculation
            // ([Vol 3] Part H, Section 2.3.5.6.5 and C.2.2.4).

            let ra = 0;

            let (mac_key, ltk, local_check) = if role == LeConnRole::Peripheral {
                let (mac_key, ltk) = dh_key.f5(peer_nonce, local_nonce, peer_address, local_address);
                let local_check = mac_key.f6(
                    local_nonce,
                    peer_nonce,
                    ra,
                    local_features.as_io_cap(),
                    local_address,
                    peer_address,
                );
                (mac_key, ltk, local_check)
            } else {
                let (mac_key, ltk) = dh_key.f5(local_nonce, peer_nonce, local_address, peer_address);
                let local_check = mac_key.f6(
                    local_nonce,
                    peer_nonce,
                    ra,
                    local_features.as_io_cap(),
                    local_address,
                    peer_address,
                );
                (mac_key, ltk, local_check)
            };
            (peer_nonce, mac_key, ltk, local_check)
        };
        {
            let mut pairing_state = self.pairing_state.borrow_mut();
            pairing_state.peer_nonce = Some(peer_nonce);
            pairing_state.mac_key = Some(mac_key);
            pairing_state.ltk = Some(ltk.0);
            pairing_state.local_check = Some(local_check);
            pairing_state.state = if role == LeConnRole::Central {
                PairingState::CentralKeyCheck
            } else {
                PairingState::PeripheralRandom
            }
        }
        if role == LeConnRole::Central {
            // Send DH check
            let mut packet = self.prepare_packet(Command::PairingDhKeyCheck, connections)?;

            let response = packet.payload_mut();

            response.copy_from_slice(&local_check.0.to_le_bytes());

            match self.try_send_packet(packet, connections, handle) {
                Ok(()) => (),
                Err(error) => {
                    error!("[security manager] Failed to send DH check {:?}", error);
                    return Err(error);
                }
            }
        }

        Ok(())
    }

    /// Handle pairing DH key check
    fn handle_pairing_dhkey_check<P: PacketPool>(
        &self,
        payload: &[u8],
        connections: &ConnectionManager<P>,
        handle: ConnHandle,
        storage: &ConnectionStorage<P::Packet>,
    ) -> Result<(), Error> {
        let (role, local_check) = {
            let pairing_state = self.pairing_state.borrow();

            let local_nonce = pairing_state.local_nonce.ok_or(Error::InvalidValue)?;
            let peer_nonce = pairing_state.peer_nonce.ok_or(Error::InvalidValue)?;
            let peer_public_key = pairing_state.public_key_peer.ok_or(Error::InvalidValue)?;
            let local_public_key = pairing_state.public_key.ok_or(Error::InvalidValue)?;
            let peer_address_kind = storage.peer_addr_kind.ok_or(Error::InvalidValue)?;
            let peer_identity = storage.peer_identity.ok_or(Error::InvalidValue)?;
            let peer_address = Address {
                kind: peer_address_kind,
                addr: peer_identity.bd_addr,
            };
            let local_address = self.state.borrow().local_address.ok_or(Error::InvalidValue)?;
            let mac_key = pairing_state.mac_key.as_ref().ok_or(Error::InvalidValue)?;
            let peer_features = pairing_state.peer_features.ok_or(Error::InvalidValue)?;
            let local_check = pairing_state.local_check.ok_or(Error::InvalidValue)?;

            let expected_check = mac_key
                .f6(
                    peer_nonce,
                    local_nonce,
                    0,
                    peer_features.as_io_cap(),
                    peer_address,
                    local_address,
                )
                .0
                .to_le_bytes();

            if payload != expected_check {
                error!(
                    "[security manager] DH check failed {:?} != {:?}",
                    payload, expected_check
                );
                return Err(Error::Security(Reason::DHKeyCheckFailed));
            }
            (pairing_state.role, local_check)
        };
        if role == LeConnRole::Central {
            let bond_info = self.store_pairing()?;
            self.try_send_event(SecurityEventData::EnableEncryption(handle, bond_info))?;
        } else {
            let mut packet = self.prepare_packet(Command::PairingDhKeyCheck, connections)?;

            let response = packet.payload_mut();

            response.copy_from_slice(&local_check.0.to_le_bytes());

            match self.try_send_packet(packet, connections, handle) {
                Ok(()) => (),
                Err(error) => {
                    error!("[security manager] Failed to send DH check {:?}", error);
                    return Err(error);
                }
            }
            let bond_info = self.store_pairing()?;
            self.try_send_event(SecurityEventData::EnableEncryption(handle, bond_info))?;
        }
        {
            let mut pairing_state = self.pairing_state.borrow_mut();
            pairing_state.state = if role == LeConnRole::Central {
                PairingState::SecurityChangeEvent
            } else {
                PairingState::PeripheralKeyCheck
            }
        }

        Ok(())
    }

    fn handle_identity_information(&self, payload: &[u8], handle: ConnHandle) -> Result<(), Error> {
        let irk = IdentityResolvingKey::new(u128::from_le_bytes(
            payload.try_into().map_err(|_| Error::InvalidValue)?,
        ));
        self.pairing_state.borrow_mut().irk = Some(irk);
        let bond_info = self.store_pairing()?;
        self.try_send_event(SecurityEventData::EnableEncryption(handle, bond_info))?;
        info!("Identity information: IRK: {:?}", irk);
        Ok(())
    }

    fn handle_identity_address_information(&self, payload: &[u8]) -> Result<(), Error> {
        let addr_type = payload[0];
        let kind = if addr_type == 0 {
            AddrKind::PUBLIC
        } else if addr_type == 1 {
            AddrKind::RANDOM
        } else {
            // Impossible
            error!("[security manager] Invalid address type: {:?}", addr_type);
            return Err(Error::InvalidValue);
        };
        let addr = BdAddr::new(payload[1..7].try_into().map_err(|_| Error::InvalidValue)?);
        self.pairing_state.borrow_mut().peer_address = Some(Address { kind, addr });
        // TODO: Check if the bond info is correctly updated
        let bond_info = self.store_pairing()?;
        // How to process the public device address when ​​Resolvable Private Address is used?
        // TODO: If bond info is updated, send EnableEncryption event
        // self.try_send_event(SecurityEventData::EnableEncryption(handle, bond_info))?;
        debug!(
            "Identity address information: addr_type: {:?}, addr: {:?}",
            addr_type, addr
        );
        Ok(())
    }

    /// Handle recevied events from HCI
    pub(crate) fn handle_event(&self, event: &Event) -> Result<(), Error> {
        match event {
            Event::EncryptionChangeV1(event_data) => match event_data.status.to_result() {
                Ok(()) => {
                    let checks_ok = {
                        let pairing_state = self.pairing_state.borrow();
                        match pairing_state.state {
                            PairingState::Idle => true,
                            PairingState::SecurityChangeEvent => {
                                pairing_state.role == LeConnRole::Central
                                    && pairing_state.handle == Some(event_data.handle)
                            }
                            PairingState::PeripheralKeyCheck => {
                                pairing_state.role == LeConnRole::Peripheral
                                    && pairing_state.handle == Some(event_data.handle)
                            }
                            _ => false,
                        }
                    };
                    if checks_ok {
                        if event_data.enabled {
                            self.pairing_result(Reason::Success)?;
                        }
                    } else {
                        warn!("[security manager] Encryption Changed, invalid pairing state");
                    }
                }
                Err(error) => {
                    error!("[security manager] Encryption Changed Handle Error {}", error);
                }
            },
            Event::Le(LeEvent::LeLongTermKeyRequest(event_data)) => {
                self.try_send_event(SecurityEventData::SendLongTermKey(event_data.handle))?;
            }
            _ => (),
        }
        Ok(())
    }

    fn store_pairing(&self) -> Result<BondInformation, Error> {
        let pairing_state = self.pairing_state.borrow();
        let irk = pairing_state.irk;
        if let (Some(ltk), Some(peer_address)) = (pairing_state.ltk, pairing_state.peer_address) {
            let ltk = LongTermKey(ltk);
            // Use IRK in bond information if available
            let bond = BondInformation {
                ltk,
                identity: Identity {
                    bd_addr: peer_address.addr,
                    irk,
                },
            };

            let bonds = &mut self.state.borrow_mut().bond;

            let mut replaced = false;
            for bond in bonds.iter_mut() {
                if bond.identity.match_address(&peer_address.addr) {
                    bond.ltk = ltk;
                    replaced = true;
                    trace!("[security manager] Replaced bond for {}", peer_address);
                    break;
                }
            }
            if !replaced {
                match bonds.push(bond.clone()) {
                    Ok(_) => {
                        trace!("[security manager] Added bond {} for {}", bond, peer_address);
                        Ok(bond)
                    }
                    Err(e) => {
                        error!("[security manager] Failed to store bond");
                        Err(Error::OutOfMemory)
                    }
                }
            } else {
                Ok(bond)
            }
        } else {
            error!("[security manager] Failed to store bond, no pairing information");
            Err(Error::InvalidState)
        }
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
        // try to pop an event from the channel
        poll_fn(|cx| self.events.poll_receive(cx)).with_deadline(*self.timer_expires.borrow())
    }

    /// Long duration, to disable the timer
    const TIMEOUT_DISABLE: Duration = Duration::from_secs(31556926); // ~1 year
                                                                     // Workaround for Duration multiplication not being const
    const TIMEOUT_SECS: u64 = 30;
    /// Pairing time-out
    const TIMEOUT: Duration = Duration::from_secs(Self::TIMEOUT_SECS);
    /// Pairing time-out treshold, used to register wakeup
    const TIMER_WAKE_THRESHOLD: Duration = Duration::from_secs(Self::TIMEOUT_SECS * 2);

    /// Reset timeout timer
    #[inline]
    fn timer_reset(&self) -> Result<(), Error> {
        self.timer_expires.replace(Instant::now() + Self::TIMEOUT);
        self.try_send_event(SecurityEventData::TimerChange)
    }

    /// "disable" timeout timer
    #[inline]
    fn timer_disable(&self) -> Result<(), Error> {
        self.timer_expires.replace(Instant::now() + Self::TIMEOUT_DISABLE);
        self.try_send_event(SecurityEventData::TimerChange)
    }

    /// Update pairing result
    fn pairing_result(&self, reason: Reason) -> Result<(), Error> {
        self.timer_disable()?;
        self.result_signal.signal(reason);
        Ok(())
    }

    /// Choose pairing method
    ///
    /// https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-60/out/en/host/generic-access-profile.html#UUID-9bec8715-4a79-31bd-f551-37336e9ff099_N1680553287676
    fn choose_pairing_method(
        &self,
        local_features: &Option<PairingFeatures>,
        peer_features: &Option<PairingFeatures>,
    ) -> PairingMethod {
        let local_features = local_features.unwrap_or_default();
        let peer_features = peer_features.unwrap_or_default();

        // Check if OOB data is present
        if local_features.use_oob == UseOutOfBand::Present && peer_features.use_oob == UseOutOfBand::Present {
            return PairingMethod::LeSecureConnectionOob;
        }

        // If both sides do not support secure connection, return None(JustWorks)
        if !local_features.security_properties.secure_connection()
            || !peer_features.security_properties.secure_connection()
        {
            return PairingMethod::None;
        }

        // Check IO capabilities and determine appropriate pairing method
        match (local_features.io_capabilities, peer_features.io_capabilities) {
            // When one device has only keyboard and the other has display capability, use Passkey Entry
            (IoCapabilities::KeyboardOnly, IoCapabilities::DisplayOnly)
            | (IoCapabilities::KeyboardOnly, IoCapabilities::DisplayYesNo)
            | (IoCapabilities::KeyboardOnly, IoCapabilities::KeyboardOnly)
            | (IoCapabilities::DisplayOnly, IoCapabilities::KeyboardOnly)
            | (IoCapabilities::DisplayYesNo, IoCapabilities::KeyboardOnly) => PairingMethod::LeSecureConnectionPasskey,

            _ => PairingMethod::LeSecureConnectionNumericComparison,
        }
    }
}

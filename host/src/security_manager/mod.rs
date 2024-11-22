#![warn(missing_docs)]
//! # Bluetooth Security Manager
// ([Vol 3] Part H, Section 3.5.5)

mod constants;
mod crypto;
mod types;

use core::task::{Context, Poll};
use core::{cell::RefCell, ops::DerefMut};

use bt_hci::event::le::LeEvent;
use bt_hci::event::Event;
use bt_hci::param::{ConnHandle, LeConnRole};
use constants::ENCRYPTION_KEY_SIZE_128_BITS;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use heapless::Vec;
use rand_chacha::ChaCha12Rng;
use rand_core::SeedableRng;

use crate::codec::{Decode, Encode};
use crate::{
    connection::Connection,
    packet_pool::{PacketPool, Pool},
    pdu::Pdu,
    types::l2cap::L2CAP_CID_LE_U_SECURITY_MANAGER,
    Address, Error,
};

pub use types::Reason;

use crypto::{Check, Confirm, DHKey, MacKey, Nonce, PublicKey, SecretKey};
use types::{AuthReq, BondingFlag, Command, IoCapabilities, PairingFeatures};

/// Events of interest to the security manager
pub(crate) enum SecurityEventData {
    /// A long term key request has been issued
    SendLongTermKey(ConnHandle),
    /// Enable encryption on channel
    EnableEncryption(ConnHandle),
}

/// Bonding data
struct BondData {
    /// Long term key
    ltk: [u8; 16],
    /// Device address
    address: Address,
}

/// Security manager data
struct SecurityManagerData {
    /// Current bonds with other devices
    bond: Vec<BondData, 10>,
}

impl SecurityManagerData {
    /// Create a new security manager data structure
    pub(crate) fn new() -> Self {
        Self { bond: Vec::new() }
    }
}

/// Packet structure for sending security manager protocol (SMP) commands
struct TxPacket {
    /// Underlying packet
    pub(crate) packet: crate::packet_pool::Packet,
    /// Command to send
    command: Command,
}

impl TxPacket {
    /// Size of L2CAP header and command
    const HEADER_SIZE: usize = 5;

    /// Get a packet from the pool
    pub fn new<const MTU: usize, const N: usize>(pool: &PacketPool<MTU, N>, command: Command) -> Result<Self, Error> {
        let mut packet = match pool.alloc() {
            Some(p) => p,
            None => {
                return Err(Error::OutOfMemory);
            }
        };
        let packet_data = packet.as_mut();
        let smp_size = command.payload_size() + 1;
        packet_data[..2].copy_from_slice(&(smp_size).to_le_bytes());
        packet_data[2..4].copy_from_slice(&L2CAP_CID_LE_U_SECURITY_MANAGER.to_le_bytes());
        packet_data[4] = command.into();
        Ok(Self { packet, command })
    }
    /// Package payload
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
enum PairingState {
    /// No pairing initialized
    Idle,
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
    /// Local device address
    local_address: Option<Address>,
    /// Peer device address
    peer_address: Option<Address>,
    /// Long term key
    ltk: Option<u128>,
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
            local_address: None,
            peer_address: None,
            ltk: None,
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
        self.peer_address = None;
        self.ltk = None;
        // local_address is not cleared
    }
}

// TODO: 30 second timer for pairing timeout
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
pub struct SecurityManager {
    /// Random generator
    rng: RefCell<ChaCha12Rng>,
    // Maximum SMP package size is 69 bytes, align to 8 bytes
    /// Packet pool for transmitting SMP packets
    tx_pool: PacketPool<72, 2>,
    /// Security manager data
    state: RefCell<SecurityManagerData>,
    /// Current state of the pairing
    pairing_state: RefCell<PairingData>,
    /// Received events
    events: Channel<NoopRawMutex, SecurityEventData, 2>,
}

impl SecurityManager {
    /// Create a new SecurityManager
    pub(crate) fn new() -> Self {
        let random_seed = [0; 32];
        Self {
            rng: RefCell::new(ChaCha12Rng::from_seed(random_seed)),
            tx_pool: PacketPool::new(),
            state: RefCell::new(SecurityManagerData::new()),
            events: Channel::new(),
            pairing_state: RefCell::new(PairingData::new()),
        }
    }

    /// Set the current local address
    pub(crate) fn set_local_address(&self, address: Address) {
        {
            let mut pairing_state = self.pairing_state.borrow_mut();
            pairing_state.local_address = Some(address);
        }
    }

    /// Set the current peer address
    pub(crate) fn set_peer_address(&self, address: Address) {
        {
            let mut pairing_state = self.pairing_state.borrow_mut();
            pairing_state.peer_address = Some(address);
        }
    }

    /// Set random seed
    pub(crate) fn set_random_seed(&self, random_seed: &[u8; 32]) {
        self.rng.replace(ChaCha12Rng::from_seed(*random_seed));
    }

    /// Get the long term key from the latests pairing
    pub(crate) fn get_long_term_key(&self) -> Option<[u8; 16]> {
        self.pairing_state.borrow().ltk.map(|ltk| ltk.to_le_bytes())
    }

    /// Handle packet
    pub(crate) fn handle(
        &self,
        packet: &crate::packet_pool::Packet,
        length: usize,
        connection: &Connection,
    ) -> Result<(), Error> {
        let result = {
            let mut buffer = [0u8; 128];
            let size = {
                let packet_payload = packet.as_ref();
                let size = length.min(buffer.len());
                buffer[..size].copy_from_slice(&packet_payload[..size]);
                size
            };
            if size < 2 {
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

            let role = connection.role();

            {
                let pairing_state = self.pairing_state.borrow();
                if role != pairing_state.role {
                    return Err(Error::InvalidValue);
                }

                if let Some(handle) = pairing_state.handle {
                    if handle != connection.handle() {
                        error!(
                            "Mismatching connection handle {} != {}",
                            handle.raw(),
                            connection.handle().raw()
                        );
                        return Err(Error::InvalidValue);
                    }
                }
            }

            match command {
                Command::PairingRequest => self.handle_pairing_request(payload, connection),
                Command::PairingResponse => self.handle_pairing_response(payload, connection),
                Command::PairingPublicKey => self.handle_pairing_public_key(payload, connection),
                Command::PairingConfirm => self.handle_pairing_confirm(payload, connection),
                Command::PairingRandom => self.handle_pairing_random(payload, connection),
                Command::PairingDhKeyCheck => self.handle_pairing_dhkey_check(payload, connection),
                Command::PairingFailed => self.handle_pairing_failed(payload, connection),
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

            let mut packet = self.prepare_packet(Command::PairingFailed)?;
            let payload = packet.payload_mut();
            payload[0] = u8::from(reason);

            match self.try_send_packet(packet, connection) {
                Ok(()) => {
                    self.pairing_state.borrow_mut().clear();
                }
                Err(error) => {
                    error!("[security manager] Failed to send pairing failed {:?}", error);
                    return Err(error);
                }
            }
        }
        result
    }

    /// Initiate pairing
    pub fn initiate(&self, connection: &Connection<'_>) -> Result<(), Error> {
        if connection.role() == LeConnRole::Central {
            // Send pairing request
            let local_features = PairingFeatures {
                io_capabilities: IoCapabilities::DisplayYesNo,
                security_properties: AuthReq::new(BondingFlag::Bonding),
                ..Default::default()
            };

            let mut packet = self.prepare_packet(Command::PairingRequest)?;

            let payload = packet.payload_mut();

            local_features.encode(payload).map_err(|_| Error::InvalidValue)?;

            match self.try_send_packet(packet, connection) {
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
                pairing_state.method = PairingMethod::LeSecureConnectionNumericComparison;
            }
        } else {
            // Send sequrity request to central

            let mut tx_packet = match self.tx_pool.alloc() {
                Some(p) => p,
                None => {
                    return Err(Error::OutOfMemory);
                }
            };
            let packet_data = tx_packet.as_mut();

            let auth_req = AuthReq::new(BondingFlag::Bonding);

            let mut packet = self.prepare_packet(Command::SecurityRequest)?;

            let response = packet.payload_mut();

            response[0] = auth_req.into();

            match self.try_send_packet(packet, connection) {
                Ok(()) => (),
                Err(error) => {
                    error!("[security manager] Failed to send security request {:?}", error);
                    return Err(error);
                }
            }
        }

        Ok(())
    }

    /// Handle pairing response command
    fn handle_pairing_failed(&self, payload: &[u8], connection: &Connection<'_>) -> Result<(), Error> {
        let reason = if let Ok(r) = Reason::try_from(payload[0]) {
            r
        } else {
            Reason::UnspecifiedReason
        };
        error!("[security manager] Pairing failed {}", reason);

        self.pairing_state.borrow_mut().clear();

        Ok(())
    }

    /// Handle pairing request command
    fn handle_pairing_request(&self, payload: &[u8], connection: &Connection<'_>) -> Result<(), Error> {
        let peer_features = PairingFeatures::decode(payload).map_err(|_| Error::Security(Reason::InvalidParameters))?;
        if connection.role() == LeConnRole::Central {
            return Err(Error::InvalidValue);
        }
        if peer_features.maximum_encryption_key_size < ENCRYPTION_KEY_SIZE_128_BITS {
            return Err(Error::Security(Reason::EncryptionKeySize));
        }
        if !peer_features.security_properties.secure_connection() {
            return Err(Error::Security(Reason::UnspecifiedReason));
        }
        let local_features = PairingFeatures {
            io_capabilities: IoCapabilities::DisplayYesNo,
            security_properties: AuthReq::new(BondingFlag::Bonding),
            ..Default::default()
        };

        {
            let pairing_state = self.pairing_state.borrow();

            if pairing_state.state != PairingState::Idle {
                return Err(Error::InvalidState);
            }

            let mut packet = self.prepare_packet(Command::PairingResponse)?;

            let response = packet.payload_mut();
            local_features.encode(response).map_err(|_| Error::InvalidValue)?;

            match self.try_send_packet(packet, connection) {
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
            pairing_state.role = connection.role();
            pairing_state.handle = Some(connection.handle());
            pairing_state.state = PairingState::Response;
            pairing_state.method = PairingMethod::LeSecureConnectionNumericComparison;
        }

        Ok(())
    }

    /// Handle pairing response command
    fn handle_pairing_response(&self, payload: &[u8], connection: &Connection<'_>) -> Result<(), Error> {
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

        let mut packet = self.prepare_packet(Command::PairingPublicKey)?;

        let response = packet.payload_mut();

        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(public_key.x.as_be_bytes());
        y.copy_from_slice(public_key.y.as_be_bytes());
        x.reverse();
        y.reverse();

        response[..x.len()].copy_from_slice(&x);
        response[x.len()..y.len() + x.len()].copy_from_slice(&y);

        match self.try_send_packet(packet, connection) {
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
    fn handle_pairing_public_key(&self, payload: &[u8], connection: &Connection<'_>) -> Result<(), Error> {
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

            let mut packet = self.prepare_packet(Command::PairingPublicKey)?;

            let response = packet.payload_mut();

            response[..x.len()].copy_from_slice(&x);
            response[x.len()..y.len() + x.len()].copy_from_slice(&y);

            match self.try_send_packet(packet, connection) {
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

            let mut packet = self.prepare_packet(Command::PairingConfirm)?;

            let response = packet.payload_mut();

            response.copy_from_slice(&confirm.0.to_le_bytes());

            match self.try_send_packet(packet, connection) {
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
    fn handle_pairing_confirm(&self, payload: &[u8], connection: &Connection<'_>) -> Result<(), Error> {
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

            let mut packet = self.prepare_packet(Command::PairingRandom)?;

            let response = packet.payload_mut();

            response.copy_from_slice(&local_nonce.0.to_le_bytes());

            match self.try_send_packet(packet, connection) {
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
    fn handle_pairing_random(&self, payload: &[u8], connection: &Connection<'_>) -> Result<(), Error> {
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
            } else {
                info!("[security manager] Pairing confirm OK");
            }
        } else {
            let mut packet = self.prepare_packet(Command::PairingRandom)?;

            let response = packet.payload_mut();

            response.copy_from_slice(&local_nonce.0.to_le_bytes());

            match self.try_send_packet(packet, connection) {
                Ok(()) => (),
                Err(error) => {
                    error!("[security manager] Failed to send random {:?}", error);
                    return Err(error);
                }
            }
        }
        let (peer_nonce, mac_key, ltk, local_check) = {
            let pairing_state = self.pairing_state.borrow();

            let peer_address = pairing_state.peer_address.ok_or(Error::InvalidValue)?;
            let local_address = pairing_state.local_address.ok_or(Error::InvalidValue)?;
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
            let mut packet = self.prepare_packet(Command::PairingDhKeyCheck)?;

            let response = packet.payload_mut();

            response.copy_from_slice(&local_check.0.to_le_bytes());

            match self.try_send_packet(packet, connection) {
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
    fn handle_pairing_dhkey_check(&self, payload: &[u8], connection: &Connection<'_>) -> Result<(), Error> {
        let (role, local_check) = {
            let pairing_state = self.pairing_state.borrow();

            let local_nonce = pairing_state.local_nonce.ok_or(Error::InvalidValue)?;
            let peer_nonce = pairing_state.peer_nonce.ok_or(Error::InvalidValue)?;
            let peer_public_key = pairing_state.public_key_peer.ok_or(Error::InvalidValue)?;
            let local_public_key = pairing_state.public_key.ok_or(Error::InvalidValue)?;
            let peer_address = pairing_state.peer_address.ok_or(Error::InvalidValue)?;
            let local_address = pairing_state.local_address.ok_or(Error::InvalidValue)?;
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
            self.events
                .try_send(SecurityEventData::EnableEncryption(connection.handle()))
                .map_err(|_| Error::OutOfMemory)?;
        } else {
            let mut packet = self.prepare_packet(Command::PairingDhKeyCheck)?;

            let response = packet.payload_mut();

            response.copy_from_slice(&local_check.0.to_le_bytes());

            match self.try_send_packet(packet, connection) {
                Ok(()) => (),
                Err(error) => {
                    error!("[security manager] Failed to send DH check {:?}", error);
                    return Err(error);
                }
            }
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

    /// Handle recevied events from HCI
    pub(crate) fn handle_event(&self, event: Event) -> Result<(), Error> {
        if let Event::EncryptionChangeV1(event_data) = event {
            {
                let pairing_state = self.pairing_state.borrow();
                if pairing_state.handle == Some(event_data.handle) {
                    match event_data.status.to_result() {
                        Ok(()) => {
                            info!(
                                "[security manager] Pairing complete Handle {} {}",
                                event_data.handle.raw(),
                                if event_data.enabled {
                                    "encrypted"
                                } else {
                                    "non-encrypted"
                                }
                            );
                        }
                        Err(error) => {
                            error!("[security manager] Encryption Changed Handle Error {}", error);
                        }
                    }
                } else {
                    error!(
                        "[security manager] Pairing complete? {:?} Handle {} {}",
                        event_data.status,
                        event_data.handle.raw(),
                        if event_data.enabled {
                            "encrypted"
                        } else {
                            "non-encrypted"
                        }
                    );
                }
            }
            {
                let mut pairing_state = self.pairing_state.borrow_mut();
                let ltk_bytes = pairing_state.ltk.map(|ltk| ltk.to_le_bytes()).unwrap();
                let bond = BondData {
                    address: pairing_state.peer_address.unwrap(),
                    ltk: ltk_bytes,
                };
                match self.state.borrow_mut().bond.push(bond) {
                    Ok(_) => (),
                    Err(_) => error!("[security manager] Failed to store bond"),
                }
                pairing_state.clear();
            }
        }
        Ok(())
    }

    /// Prepare a packet for sending
    fn prepare_packet(&self, command: Command) -> Result<TxPacket, Error> {
        TxPacket::new(&self.tx_pool, command)
    }

    /// Send a packet
    fn try_send_packet(&self, packet: TxPacket, connection: &Connection<'_>) -> Result<(), Error> {
        let size = packet.total_size();
        info!("[security manager] Try send {} ({})", packet.command, size);
        connection.try_send(Pdu::new(packet.packet, size))
    }

    /// Handle recevied LE events from HCI
    pub(crate) fn handle_le_event(&self, event: LeEvent) -> Result<(), Error> {
        if let LeEvent::LeLongTermKeyRequest(data) = event {
            self.events
                .try_send(SecurityEventData::SendLongTermKey(data.handle))
                .map_err(|_| Error::OutOfMemory)?;
        }
        Ok(())
    }

    /// Poll for security manager work
    pub(crate) fn poll_work(&self, cx: &mut Context<'_>) -> Poll<SecurityEventData> {
        self.events.poll_receive(cx)
    }
}

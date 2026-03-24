#![warn(missing_docs)]
//! # Bluetooth Security Manager
// ([Vol 3] Part H, Section 3.5.5)

mod constants;
pub(crate) mod crypto;
mod pairing;
mod types;
use core::cell::{Ref, RefCell};
use core::future::{poll_fn, Future};
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
use heapless::VecView;
pub use pairing::OobData;
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[cfg(feature = "legacy-pairing")]
    /// Negotiated encryption key length in bytes (16 for LESC)
    pub encryption_key_len: u8,
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
            #[cfg(feature = "legacy-pairing")]
            encryption_key_len: 16,
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
struct SecurityManagerData {
    /// Local device address
    local_address: Option<Address>,
    /// Random generator seeded
    random_generator_seeded: bool,
}

impl SecurityManagerData {
    /// Create a new security manager data structure
    fn new() -> Self {
        Self {
            local_address: None,
            random_generator_seeded: false,
        }
    }
}

/// Add or replace a bond in the given bond storage.
fn add_bond(bond: &mut VecView<BondInformation>, bond_information: BondInformation) -> Result<(), Error> {
    trace!("[security manager] Add bond for {:?}", bond_information.identity);
    if let Some(idx) = bond
        .iter()
        .position(|b| bond_information.identity.match_identity(&b.identity))
    {
        bond[idx] = bond_information;
    } else {
        bond.push(bond_information).map_err(|_| Error::OutOfMemory)?;
    }
    Ok(())
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

/// Inner mutable state of the security manager
struct Inner {
    /// Random generator
    rng: ChaCha12Rng,
    /// Persistent LESC keypair (generated once when RNG is seeded)
    secret_key: crypto::SecretKey,
    /// Corresponding public key
    public_key: crypto::PublicKey,
    /// Security manager data
    state: SecurityManagerData,
    /// State of an ongoing pairing
    pairing_sm: Option<Pairing>,
    /// Waker for pairing finished
    finished_waker: WakerRegistration,
    /// Io capabilities
    io_capabilities: IoCapabilities,
    /// When true, reject legacy pairing even if the feature is compiled in
    #[cfg(feature = "legacy-pairing")]
    secure_connections_only: bool,
}

/// Parsed SMP command data extracted from an L2CAP PDU
struct SmpCommand<'a> {
    command: Command,
    payload: &'a [u8],
    peer_address: Address,
    handle: ConnHandle,
    peer_identity: Identity,
}

impl Inner {
    fn is_idle(&self) -> bool {
        self.pairing_sm.as_ref().map(|sm| sm.result().is_some()).unwrap_or(true)
    }

    fn handle_peripheral<P: PacketPool>(
        &mut self,
        bonds: &mut VecView<BondInformation>,
        events: &Channel<NoopRawMutex, SecurityEventData, 2>,
        cmd: &SmpCommand<'_>,
        connections: &ConnectionManager<'_, P>,
        storage: &ConnectionStorage<P::Packet>,
    ) -> Result<(), Error> {
        let SmpCommand {
            command,
            payload,
            peer_address,
            handle,
            peer_identity,
        } = *cmd;
        if self.is_idle() {
            let local_address = self.state.local_address.unwrap();
            let local_io = self.io_capabilities;

            #[cfg(feature = "legacy-pairing")]
            {
                // Check if peer supports SC by peeking at PairingRequest AuthReq byte,
                // or if peer requests a key size smaller than LESC requires
                let use_legacy = command == Command::PairingRequest
                    && payload.len() >= 4
                    && (!AuthReq::from(payload[2]).secure_connection()
                        || payload[3] < crate::security_manager::constants::ENCRYPTION_KEY_SIZE_128_BITS);

                if use_legacy && self.secure_connections_only {
                    if payload[3] < crate::security_manager::constants::ENCRYPTION_KEY_SIZE_128_BITS {
                        return Err(Error::Security(Reason::EncryptionKeySize));
                    }
                    return Err(Error::Security(Reason::AuthenticationRequirements));
                }

                if use_legacy {
                    self.pairing_sm = Some(Pairing::new_legacy_peripheral(local_address, peer_address, local_io));
                } else {
                    self.pairing_sm = Some(Pairing::new_peripheral(local_address, peer_address, local_io));
                }
            }
            #[cfg(not(feature = "legacy-pairing"))]
            {
                self.pairing_sm = Some(Pairing::new_peripheral(local_address, peer_address, local_io));
            }
        }

        // Check if we need to switch from LESC to legacy peripheral
        // when receiving a PairingRequest without SC flag or with insufficient key size
        #[cfg(feature = "legacy-pairing")]
        if command == Command::PairingRequest
            && payload.len() >= 4
            && (!AuthReq::from(payload[2]).secure_connection()
                || payload[3] < crate::security_manager::constants::ENCRYPTION_KEY_SIZE_128_BITS)
            && self.pairing_sm.as_ref().is_some_and(|p| p.is_lesc_peripheral())
        {
            if self.secure_connections_only {
                if payload[3] < crate::security_manager::constants::ENCRYPTION_KEY_SIZE_128_BITS {
                    return Err(Error::Security(Reason::EncryptionKeySize));
                }
                return Err(Error::Security(Reason::AuthenticationRequirements));
            }
            let old = self.pairing_sm.take().unwrap();
            self.pairing_sm = Some(old.switch_to_legacy_peripheral()?);
        }

        if self.pairing_sm.as_ref().unwrap().is_central() {
            return Err(Error::InvalidState);
        }
        let address = self.pairing_sm.as_ref().unwrap().peer_address();

        if address != peer_address {
            // TODO Is this correct?
            self.pairing_sm = None;
            return Err(Error::InvalidValue);
        }

        let mut ops = PairingOpsImpl {
            bonds,
            events,
            secret_key: &self.secret_key,
            public_key: &self.public_key,
            conn_handle: handle,
            connections,
            storage,
            peer_identity,
        };
        self.pairing_sm
            .as_mut()
            .unwrap()
            .handle_l2cap_command(command, payload, &mut ops, &mut self.rng)
    }

    fn handle_central<P: PacketPool>(
        &mut self,
        bonds: &mut VecView<BondInformation>,
        events: &Channel<NoopRawMutex, SecurityEventData, 2>,
        cmd: &SmpCommand<'_>,
        connections: &ConnectionManager<'_, P>,
        storage: &ConnectionStorage<P::Packet>,
    ) -> Result<(), Error> {
        let SmpCommand {
            command,
            payload,
            peer_address,
            handle,
            peer_identity,
        } = *cmd;
        if self.is_idle() {
            self.pairing_sm = Some(Pairing::new_central(
                self.state.local_address.unwrap(),
                peer_address,
                self.io_capabilities,
            ));
        }

        // Check if we need to switch from LESC to legacy central
        // when receiving a PairingResponse without SC flag or with insufficient key size
        #[cfg(feature = "legacy-pairing")]
        if command == Command::PairingResponse
            && payload.len() >= 4
            && (!AuthReq::from(payload[2]).secure_connection()
                || payload[3] < crate::security_manager::constants::ENCRYPTION_KEY_SIZE_128_BITS)
            && self.pairing_sm.as_ref().is_some_and(|p| p.is_lesc_central())
        {
            if self.secure_connections_only {
                if payload[3] < crate::security_manager::constants::ENCRYPTION_KEY_SIZE_128_BITS {
                    return Err(Error::Security(Reason::EncryptionKeySize));
                }
                return Err(Error::Security(Reason::AuthenticationRequirements));
            }
            let old = self.pairing_sm.take().unwrap();
            self.pairing_sm = Some(old.switch_to_legacy_central()?);
        }

        if !self.pairing_sm.as_ref().unwrap().is_central() {
            return Err(Error::InvalidState);
        }
        let address = self.pairing_sm.as_ref().unwrap().peer_address();

        if address != peer_address {
            // TODO Is this correct?
            self.pairing_sm = None;
            return Err(Error::InvalidValue);
        }

        let mut ops = PairingOpsImpl {
            bonds,
            events,
            secret_key: &self.secret_key,
            public_key: &self.public_key,
            conn_handle: handle,
            connections,
            storage,
            peer_identity,
        };
        self.pairing_sm
            .as_mut()
            .unwrap()
            .handle_l2cap_command(command, payload, &mut ops, &mut self.rng)
    }

    fn handle_pairing_event<P: PacketPool>(
        &mut self,
        bonds: &mut VecView<BondInformation>,
        events: &Channel<NoopRawMutex, SecurityEventData, 2>,
        pairing_event: pairing::Event,
        connections: &ConnectionManager<'_, P>,
        storage: &ConnectionStorage<P::Packet>,
    ) -> Result<(), Error> {
        if let Some(sm) = self.pairing_sm.as_mut() {
            let mut ops = PairingOpsImpl {
                bonds,
                events,
                secret_key: &self.secret_key,
                public_key: &self.public_key,
                peer_identity: storage.peer_identity.ok_or(Error::InvalidValue)?,
                conn_handle: storage.handle.ok_or(Error::InvalidValue)?,
                connections,
                storage,
            };
            let res = sm.handle_event(pairing_event, &mut ops, &mut self.rng);
            if res.is_ok() {
                sm.reset_timeout();
                let _ = events.try_send(SecurityEventData::TimerChange);
            }
            return res;
        }
        Ok(())
    }

    fn handle_encryption_success<P: PacketPool>(
        &mut self,
        bonds: &mut VecView<BondInformation>,
        events: &Channel<NoopRawMutex, SecurityEventData, 2>,
        encrypted: bool,
        connections: &ConnectionManager<'_, P>,
        storage: &mut ConnectionStorage<P::Packet>,
    ) -> Result<(), Error> {
        if let Some(sm) = self.pairing_sm.as_mut() {
            let mut ops = PairingOpsImpl {
                bonds,
                events,
                secret_key: &self.secret_key,
                public_key: &self.public_key,
                peer_identity: storage.peer_identity.ok_or(Error::InvalidValue)?,
                connections,
                storage,
                conn_handle: storage.handle.ok_or(Error::InvalidValue)?,
            };
            let res = sm.handle_event(pairing::Event::LinkEncryptedResult(encrypted), &mut ops, &mut self.rng);
            if res.is_ok() {
                storage.security_level = sm.security_level();
                storage.bond_rejected = false;
                #[cfg(feature = "legacy-pairing")]
                if let Some(bond) = sm.bond_information() {
                    storage.encryption_key_len = bond.encryption_key_len;
                }
            }
            if sm.result().is_some() {
                self.finished_waker.wake();
                let _ = events.try_send(SecurityEventData::TimerChange);
            }
            return res;
        } else if let Some(identity) = storage.peer_identity.as_ref() {
            match bonds
                .iter()
                .find(|bond| bond.identity.match_identity(identity))
                .cloned()
            {
                Some(bond) if encrypted => {
                    info!("[smp] Encrypted using bond {:?}", bond.identity);
                    storage.security_level = bond.security_level;
                    #[cfg(feature = "legacy-pairing")]
                    {
                        storage.encryption_key_len = bond.encryption_key_len;
                    }
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
    }

    fn handle_encryption_failure<P: PacketPool>(
        &mut self,
        bonds: &mut VecView<BondInformation>,
        events: &Channel<NoopRawMutex, SecurityEventData, 2>,
        connections: &ConnectionManager<'_, P>,
        storage: &mut ConnectionStorage<P::Packet>,
    ) {
        if let Some(sm) = self.pairing_sm.as_mut() {
            // If we were waiting for bonded encryption, mark the bond as
            // rejected on this connection so the next pairing attempt will
            // skip bonded encryption and initiate fresh pairing instead.
            if sm.is_waiting_bonded_encryption() {
                storage.bond_rejected = true;
            }
            let _res = sm.handle_event(
                pairing::Event::LinkEncryptedResult(false),
                &mut PairingOpsImpl {
                    bonds,
                    events,
                    secret_key: &self.secret_key,
                    public_key: &self.public_key,
                    peer_identity: storage.peer_identity.unwrap_or_default(),
                    connections,
                    storage,
                    conn_handle: storage.handle.unwrap_or(ConnHandle::new(0)),
                },
                &mut self.rng,
            );
            // Don't call handle_security_error here: sending SMP PairingFailed
            // for an HCI-level encryption failure would cause the peer to
            // delete its bond information, preventing future re-encryption.
            if sm.result().is_some() {
                self.finished_waker.wake();
                let _ = events.try_send(SecurityEventData::TimerChange);
            }
        }
    }

    fn initiate<P: PacketPool>(
        &mut self,
        bonds: &mut VecView<BondInformation>,
        events: &Channel<NoopRawMutex, SecurityEventData, 2>,
        connections: &ConnectionManager<'_, P>,
        storage: &ConnectionStorage<<P as PacketPool>::Packet>,
        user_initiated: bool,
    ) -> Result<(), Error> {
        let role = storage.role.ok_or(Error::InvalidValue)?;

        if !self.is_idle() {
            // If pairing is already in progress for this peer, consider the request fulfilled.
            let peer_identity = storage.peer_identity.ok_or(Error::InvalidValue)?;
            let peer_address = peer_identity.addr;
            if self
                .pairing_sm
                .as_ref()
                .is_some_and(|sm| sm.peer_address() == peer_address && sm.result().is_none())
            {
                return Ok(());
            }
            return Err(Error::InvalidState);
        }

        let handle = storage.handle.ok_or(Error::InvalidValue)?;
        let local_address = self.state.local_address.ok_or(Error::InvalidValue)?;
        let peer_identity = storage.peer_identity.ok_or(Error::InvalidValue)?;
        let peer_address = peer_identity.addr;
        let local_io = self.io_capabilities;
        let mut ops = PairingOpsImpl {
            bonds,
            events,
            secret_key: &self.secret_key,
            public_key: &self.public_key,
            conn_handle: handle,
            connections,
            storage,
            peer_identity,
        };
        if role == LeConnRole::Peripheral {
            self.pairing_sm = Some(Pairing::initiate_peripheral(
                local_address,
                peer_address,
                &mut ops,
                local_io,
                user_initiated,
            )?);
        } else {
            self.pairing_sm = Some(Pairing::initiate_central(
                local_address,
                peer_address,
                &mut ops,
                local_io,
                user_initiated,
            )?);
        }
        Ok(())
    }
}

/// Security manager that handles SM packet
pub struct SecurityManager<'d> {
    /// Inner mutable state
    inner: RefCell<Inner>,
    /// Bond storage (externally owned by HostResources)
    bonds: &'d RefCell<VecView<BondInformation>>,
    /// Received events
    events: Channel<NoopRawMutex, SecurityEventData, 2>,
}

impl<'d> SecurityManager<'d> {
    /// Create a new SecurityManager
    pub(crate) fn new(bonds: &'d RefCell<VecView<BondInformation>>) -> Self {
        let mut rng = ChaCha12Rng::from_seed([0u8; 32]);
        let secret_key = crypto::SecretKey::new(&mut rng);
        let public_key = secret_key.public_key();
        Self {
            inner: RefCell::new(Inner {
                rng,
                secret_key,
                public_key,
                state: SecurityManagerData::new(),
                pairing_sm: None,
                finished_waker: WakerRegistration::new(),
                io_capabilities: IoCapabilities::NoInputNoOutput,
                #[cfg(feature = "legacy-pairing")]
                secure_connections_only: false,
            }),
            bonds,
            events: Channel::new(),
        }
    }

    /// Set the IO capabilities
    pub(crate) fn set_io_capabilities(&self, io_capabilities: IoCapabilities) {
        self.inner.borrow_mut().io_capabilities = io_capabilities;
    }

    /// Enable or disable secure connections only mode.
    /// When enabled, legacy pairing is rejected even if the feature is compiled in.
    #[cfg(feature = "legacy-pairing")]
    pub(crate) fn set_secure_connections_only(&self, enabled: bool) {
        self.inner.borrow_mut().secure_connections_only = enabled;
    }

    /// Set the current local address
    pub(crate) fn set_random_generator_seed(&self, random_seed: [u8; 32]) {
        let mut inner = self.inner.borrow_mut();
        inner.rng = ChaCha12Rng::from_seed(random_seed);
        inner.secret_key = crypto::SecretKey::new(&mut inner.rng);
        inner.public_key = inner.secret_key.public_key();
        inner.state.random_generator_seeded = true;
    }

    /// Set the current local address
    pub(crate) fn set_local_address(&self, address: Address) {
        self.inner.borrow_mut().state.local_address = Some(address);
    }

    /// Returns true if no pairing is currently in progress.
    fn is_idle(&self) -> bool {
        self.inner.borrow().is_idle()
    }

    pub(crate) fn is_pairing_in_progress(&self, address: Address) -> bool {
        let inner = self.inner.borrow();
        match &inner.pairing_sm {
            Some(sm) => sm.peer_address() == address && sm.result().is_none(),
            None => false,
        }
    }

    /// The address of the peer that is currently being paired with.
    pub(crate) fn peer_address(&self) -> Option<Address> {
        self.inner
            .borrow()
            .pairing_sm
            .as_ref()
            .and_then(|sm| sm.result().is_none().then_some(sm.peer_address()))
    }

    pub(crate) async fn wait_finished(&self, address: Address) -> Result<(), Error> {
        poll_fn(|cx| {
            let mut inner = self.inner.borrow_mut();
            inner.finished_waker.register(cx.waker());
            match &inner.pairing_sm {
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
        self.bonds.borrow().iter().find_map(|bond| {
            if bond.identity.match_identity(identity) {
                Some(bond.clone())
            } else {
                None
            }
        })
    }

    /// Has the random generator been seeded?
    pub(crate) fn get_random_generator_seeded(&self) -> bool {
        self.inner.borrow().state.random_generator_seeded
    }

    /// Generate local OOB data for LESC pairing.
    ///
    /// The returned data should be exchanged with the peer via an out-of-band channel.
    /// The persistent keypair is used so the confirm value matches the public key
    /// that will be sent during pairing.
    pub(crate) fn get_local_oob_data(&self) -> pairing::OobData {
        let mut inner = self.inner.borrow_mut();
        let r = crypto::Nonce::new(&mut inner.rng);
        let c = r.f4(inner.public_key.x(), inner.public_key.x(), 0);
        pairing::OobData {
            random: r.0.to_le_bytes(),
            confirm: c.0.to_le_bytes(),
        }
    }

    /// Get the current local address.
    pub(crate) fn get_local_address(&self) -> Option<Address> {
        self.inner.borrow().state.local_address
    }

    /// Add a bonded device
    pub(crate) fn add_bond_information(&self, bond_information: BondInformation) -> Result<(), Error> {
        add_bond(&mut self.bonds.borrow_mut(), bond_information)
    }

    /// Remove a bonded device
    pub(crate) fn remove_bond_information(&self, identity: Identity) -> Result<(), Error> {
        trace!("[security manager] Remove bond for {:?}", identity);
        let mut bonds = self.bonds.borrow_mut();
        let index = bonds.iter().position(|bond| bond.identity.match_identity(&identity));
        match index {
            Some(index) => {
                bonds.remove(index);
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Get bonded devices
    pub(crate) fn get_bond_information(&self) -> Ref<'_, VecView<BondInformation>> {
        self.bonds.borrow()
    }

    /// Get the number of bonded devices
    pub(crate) fn bond_count(&self) -> usize {
        self.bonds.borrow().len()
    }

    /// Get the identity of a bonded device by index
    pub(crate) fn get_bond_identity(&self, index: usize) -> Option<Identity> {
        self.bonds.borrow().get(index).map(|b| b.identity)
    }

    fn parse_smp_command<P: PacketPool>(pdu: Pdu<P::Packet>) -> Result<(Command, [u8; 72], usize), Error> {
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
        let payload_len = size - 1;
        let command = match Command::try_from(buffer[0]) {
            Ok(command) => {
                if usize::from(command.payload_size()) != payload_len {
                    error!("[security manager] Payload size mismatch for command {}", command);
                    return Err(Error::Security(Reason::InvalidParameters));
                }
                command
            }
            Err(_) => return Err(Error::Security(Reason::CommandNotSupported)),
        };
        Ok((command, buffer, size))
    }

    fn handle_peripheral<P: PacketPool>(
        &self,
        pdu: Pdu<P::Packet>,
        connections: &ConnectionManager<'_, P>,
        storage: &ConnectionStorage<P::Packet>,
    ) -> Result<(), Error> {
        let (command, buffer, size) = Self::parse_smp_command::<P>(pdu)?;
        let cmd = SmpCommand {
            command,
            payload: &buffer[1..size],
            peer_address: storage.peer_identity.ok_or(Error::InvalidValue)?.addr,
            handle: storage.handle.ok_or(Error::InvalidValue)?,
            peer_identity: storage.peer_identity.ok_or(Error::InvalidValue)?,
        };
        self.inner.borrow_mut().handle_peripheral(
            &mut self.bonds.borrow_mut(),
            &self.events,
            &cmd,
            connections,
            storage,
        )
    }

    fn handle_central<P: PacketPool>(
        &self,
        pdu: Pdu<P::Packet>,
        connections: &ConnectionManager<'_, P>,
        storage: &ConnectionStorage<P::Packet>,
    ) -> Result<(), Error> {
        let (command, buffer, size) = Self::parse_smp_command::<P>(pdu)?;
        let cmd = SmpCommand {
            command,
            payload: &buffer[1..size],
            peer_address: storage.peer_identity.ok_or(Error::InvalidValue)?.addr,
            handle: storage.handle.ok_or(Error::InvalidValue)?,
            peer_identity: storage.peer_identity.ok_or(Error::InvalidValue)?,
        };
        self.inner
            .borrow_mut()
            .handle_central(&mut self.bonds.borrow_mut(), &self.events, &cmd, connections, storage)
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

        {
            let mut inner = self.inner.borrow_mut();
            if inner.is_idle() {
                inner.finished_waker.wake();
            }
            if result.is_ok() {
                if let Some(sm) = inner.pairing_sm.as_mut() {
                    sm.reset_timeout();
                    let _ = self.events.try_send(SecurityEventData::TimerChange);
                }
            }
        }

        if result.is_err() {
            if let Err(e) = self.handle_security_error(connections, storage, &result) {
                error!("[security manager] Failed sending pairing failed message! {:?}", e);
            }
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
        self.inner.borrow_mut().initiate(
            &mut self.bonds.borrow_mut(),
            &self.events,
            connections,
            storage,
            user_initiated,
        )
    }

    /// Cancel pairing after timeout
    pub(crate) fn cancel_timeout(&self) {
        let mut inner = self.inner.borrow_mut();
        if let Some(pairing) = inner.pairing_sm.as_mut() {
            pairing.mark_timeout();
            inner.finished_waker.wake();
        }
    }

    /// Channel disconnected
    pub(crate) fn disconnect(&self, identity: &Identity) {
        {
            let mut inner = self.inner.borrow_mut();
            if inner
                .pairing_sm
                .as_ref()
                .is_some_and(|sm| sm.peer_address() == identity.addr)
            {
                inner.pairing_sm = None;
                inner.finished_waker.wake();
            }
        }
        self.bonds
            .borrow_mut()
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
                        let res = self.inner.borrow_mut().handle_encryption_success(
                            &mut self.bonds.borrow_mut(),
                            &self.events,
                            encrypted,
                            connections,
                            storage,
                        );
                        let _ = self.handle_security_error(connections, storage, &res);
                        res
                    })?;
                }
                Err(error) => {
                    error!("[security manager] Encryption event error {:?}", error);
                    connections.with_connected_handle(handle, |storage| {
                        self.inner.borrow_mut().handle_encryption_failure(
                            &mut self.bonds.borrow_mut(),
                            &self.events,
                            connections,
                            storage,
                        );
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
        let res = self.inner.borrow_mut().handle_pairing_event(
            &mut self.bonds.borrow_mut(),
            &self.events,
            pairing_event,
            connections,
            storage,
        );
        if res.is_err() {
            if let Err(e) = self.handle_security_error(connections, storage, &res) {
                error!("[security manager] Failed sending pairing failed message! {:?}", e);
            }
        }
        res
    }

    pub(crate) fn handle_pass_key_input<P: PacketPool>(
        &self,
        input: u32,
        connections: &ConnectionManager<'_, P>,
        storage: &ConnectionStorage<P::Packet>,
    ) -> Result<(), Error> {
        self.handle_event(pairing::Event::PassKeyInput(input), connections, storage)
    }

    pub(crate) fn handle_oob_data_received<P: PacketPool>(
        &self,
        local_oob: pairing::OobData,
        peer_oob: pairing::OobData,
        connections: &ConnectionManager<'_, P>,
        storage: &ConnectionStorage<P::Packet>,
    ) -> Result<(), Error> {
        self.handle_event(
            pairing::Event::OobDataReceived {
                local: local_oob,
                peer: peer_oob,
            },
            connections,
            storage,
        )
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
    pub(crate) fn poll_events(&self) -> impl Future<Output = Result<SecurityEventData, TimeoutError>> + use<'_, 'd> {
        let deadline = self
            .inner
            .borrow()
            .pairing_sm
            .as_ref()
            .map(|x| x.timeout_at())
            .unwrap_or(Instant::now() + constants::TIMEOUT_DISABLE);
        // try to pop an event from the channel
        poll_fn(|cx| self.events.poll_receive(cx)).with_deadline(deadline)
    }
}

struct PairingOpsImpl<'sm, 'cm, 'cm2, 'cs, P: PacketPool> {
    bonds: &'sm mut VecView<BondInformation>,
    events: &'sm Channel<NoopRawMutex, SecurityEventData, 2>,
    secret_key: &'sm crypto::SecretKey,
    public_key: &'sm crypto::PublicKey,
    connections: &'cm ConnectionManager<'cm2, P>,
    storage: &'cs ConnectionStorage<P::Packet>,
    conn_handle: ConnHandle,
    peer_identity: Identity,
}

impl<'sm, 'cm, 'cm2, 'cs, P: PacketPool> PairingOps<P> for PairingOpsImpl<'sm, 'cm, 'cm2, 'cs, P> {
    fn try_send_packet(&mut self, packet: TxPacket<P>) -> Result<(), Error> {
        let len = packet.total_size();
        trace!("[security manager] Send {} {}", packet.command, len);
        self.connections.try_outbound(self.conn_handle, packet.into_pdu())?;
        let _ = self.events.try_send(SecurityEventData::TimerChange);
        Ok(())
    }

    fn try_update_bond_information(&mut self, bond: &BondInformation) -> Result<(), Error> {
        add_bond(self.bonds, bond.clone())
    }

    fn find_bond(&self) -> Option<BondInformation> {
        self.bonds
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
        #[cfg(feature = "legacy-pairing")] encryption_key_len: u8,
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
            #[cfg(feature = "legacy-pairing")]
            encryption_key_len,
        };
        self.try_update_bond_information(&bond_info)?;
        self.events
            .try_send(SecurityEventData::EnableEncryption(self.conn_handle, bond_info.clone()))
            .map_err(|_| Error::OutOfMemory)?;
        Ok(bond_info)
    }

    fn try_enable_bonded_encryption(&mut self) -> Result<Option<BondInformation>, Error> {
        if self.storage.bond_rejected {
            return Ok(None);
        }
        if let Some(bond) = self.find_bond() {
            self.events
                .try_send(SecurityEventData::EnableEncryption(self.conn_handle, bond.clone()))
                .map_err(|_| Error::OutOfMemory)?;
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
            let _ = self.events.try_send(SecurityEventData::TimerChange);
        }
        Ok(())
    }

    fn oob_available(&self) -> bool {
        self.storage.oob_available
    }

    fn secret_key(&self) -> &crypto::SecretKey {
        self.secret_key
    }

    fn public_key(&self) -> &crypto::PublicKey {
        self.public_key
    }
}

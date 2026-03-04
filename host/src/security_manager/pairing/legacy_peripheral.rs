use core::cell::RefCell;
use core::ops::{Deref, DerefMut};

use bt_hci::param::{AddrKind, BdAddr};
use embassy_time::Instant;
use rand::Rng;
use rand_core::{CryptoRng, RngCore};

use crate::codec::{Decode, Encode};
use crate::connection::SecurityLevel;
use crate::prelude::ConnectionEvent;
use crate::security_manager::pairing::util::{
    choose_legacy_pairing_method, make_central_identification_packet, make_encryption_information_packet,
    make_identity_address_information_packet, make_identity_information_packet, make_pairing_random, prepare_packet,
    CommandAndPayload, PairingMethod, PassKeyEntryAction,
};
use crate::security_manager::pairing::{Event, PairingData, PairingOps};
use crate::security_manager::types::{AuthReq, Command, PairingFeatures, PassKey};
use crate::security_manager::{crypto, Reason};
use crate::{Address, Error, IdentityResolvingKey, IoCapabilities, LongTermKey, PacketPool};

/// Data needed during the confirm/random exchange phase of legacy pairing.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct ConfirmPhaseData {
    /// TK: 0 for JustWorks, passkey value for PassKey Entry
    tk: u128,
    /// Pairing Request command bytes (opcode + 6 feature bytes)
    preq: [u8; 7],
    /// Pairing Response command bytes (opcode + 6 feature bytes)
    pres: [u8; 7],
    /// Peripheral's random (Srand)
    local_nonce: u128,
}

/// Key distribution data generated for bonding.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct KeyDistData {
    long_term_key: LongTermKey,
    ediv: u16,
    rand: [u8; 8],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum Step {
    WaitingPairingRequest,
    WaitingPassKeyInput {
        confirm_bytes: Option<[u8; size_of::<u128>()]>,
        preq: [u8; 7],
        pres: [u8; 7],
    },
    WaitingPairingConfirm(ConfirmPhaseData),
    WaitingPairingRandom {
        confirm_data: ConfirmPhaseData,
        peer_confirm: u128,
    },
    WaitingLinkEncrypted,
    WaitingIdentitityInformation,
    WaitingIdentitityAddressInformation,
    SendingKeys {
        phase: u8,
        keys: KeyDistData,
    },
    ReceivingKeys {
        phase: u8,
        received_ltk: LongTermKey,
    },
    Success,
    Error(Error),
}

/// Get address type flag for c1 (0=public, 1=random)
fn addr_type_flag(addr: &Address) -> u8 {
    if addr.kind == AddrKind::PUBLIC {
        0
    } else {
        1
    }
}

/// Get address bytes in MSO order for c1
fn addr_bytes_mso(addr: &Address) -> [u8; 6] {
    let mut bytes = addr.addr.into_inner();
    bytes.reverse();
    bytes
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Pairing {
    current_step: RefCell<Step>,
    pairing_data: RefCell<PairingData>,
}

impl Pairing {
    pub fn result(&self) -> Option<Result<(), Error>> {
        let step = self.current_step.borrow();
        match step.deref() {
            Step::Success => Some(Ok(())),
            Step::Error(e) => Some(Err(e.clone())),
            _ => None,
        }
    }

    pub fn timeout_at(&self) -> Instant {
        let step = self.current_step.borrow();
        if matches!(step.deref(), Step::Success | Step::Error(_)) {
            Instant::now() + crate::security_manager::constants::TIMEOUT_DISABLE
        } else {
            self.pairing_data.borrow().timeout_at
        }
    }

    pub fn reset_timeout(&self) {
        let mut pairing_data = self.pairing_data.borrow_mut();
        pairing_data.timeout_at = Instant::now() + crate::security_manager::constants::TIMEOUT;
    }

    pub(crate) fn mark_timeout(&self) {
        let mut current_step = self.current_step.borrow_mut();
        if matches!(current_step.deref(), Step::Success | Step::Error(_)) {
            return;
        }
        *current_step = Step::Error(Error::Timeout);
    }

    pub fn peer_address(&self) -> Address {
        self.pairing_data.borrow().peer_address
    }

    pub fn new(local_address: Address, peer_address: Address, local_io: IoCapabilities) -> Self {
        Self {
            current_step: RefCell::new(Step::WaitingPairingRequest),
            pairing_data: RefCell::new(PairingData {
                local_address,
                peer_address,
                local_features: PairingFeatures {
                    io_capabilities: local_io,
                    ..Default::default()
                },
                pairing_method: PairingMethod::JustWorks,
                peer_features: PairingFeatures::default(),
                timeout_at: Instant::now() + crate::security_manager::constants::TIMEOUT,
                bond_information: None,
            }),
        }
    }

    pub fn handle_l2cap_command<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        &self,
        command: Command,
        payload: &[u8],
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        match self.handle_impl(CommandAndPayload { payload, command }, ops, rng) {
            Ok(()) => Ok(()),
            Err(error) => {
                error!("[smp legacy] Failed to handle command {:?}, {:?}", command, error);
                self.current_step.replace(Step::Error(error.clone()));
                Err(error)
            }
        }
    }

    pub fn handle_event<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        &self,
        event: Event,
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let current_state = self.current_step.borrow().clone();
        let next_step = match (current_state, event) {
            (x @ (Step::WaitingPairingRequest | Step::WaitingLinkEncrypted), Event::LinkEncryptedResult(res)) => {
                if res {
                    info!("[smp legacy] Link encrypted!");
                    if matches!(x, Step::WaitingPairingRequest) {
                        self.pairing_data.borrow_mut().bond_information = ops.try_enable_bonded_encryption()?;
                    }
                    let pairing_data = self.pairing_data.borrow();
                    if matches!(x, Step::WaitingLinkEncrypted) && pairing_data.want_bonding() {
                        // Send our keys first, then receive theirs
                        if pairing_data.local_features.responder_key_distribution.encryption_key() {
                            Self::make_sending_keys_step(0, rng)
                        } else if pairing_data.local_features.responder_key_distribution.identity_key() {
                            Self::make_sending_keys_step(2, rng)
                        } else if pairing_data.peer_features.initiator_key_distribution.encryption_key() {
                            Step::ReceivingKeys {
                                phase: 0,
                                received_ltk: LongTermKey(0),
                            }
                        } else if pairing_data.peer_features.initiator_key_distribution.identity_key() {
                            Step::WaitingIdentitityInformation
                        } else {
                            Step::Success
                        }
                    } else if pairing_data.peer_features.initiator_key_distribution.identity_key() {
                        Step::WaitingIdentitityInformation
                    } else {
                        Step::Success
                    }
                } else {
                    error!("[smp legacy] Failed to enable encryption!");
                    Step::Error(Error::Security(Reason::KeyRejected))
                }
            }
            (
                Step::WaitingPassKeyInput {
                    confirm_bytes,
                    preq,
                    pres,
                },
                Event::PassKeyInput(input),
            ) => {
                let tk = input as u128;
                match confirm_bytes {
                    Some(payload) => {
                        let pairing_data = self.pairing_data.borrow();
                        let peer_confirm = u128::from_le_bytes(payload);
                        let mut confirm_data = ConfirmPhaseData {
                            tk,
                            preq,
                            pres,
                            local_nonce: 0,
                        };
                        Self::send_sconfirm(ops, &pairing_data, &mut confirm_data, rng)?;
                        Step::WaitingPairingRandom {
                            confirm_data,
                            peer_confirm,
                        }
                    }
                    None => Step::WaitingPairingConfirm(ConfirmPhaseData {
                        tk,
                        preq,
                        pres,
                        local_nonce: 0,
                    }),
                }
            }
            (x, Event::PassKeyConfirm | Event::PassKeyCancel | Event::PassKeyInput(_)) => x,
            _ => Step::Error(Error::InvalidState),
        };

        self.handle_step_result(next_step, ops)
    }

    pub fn security_level(&self) -> SecurityLevel {
        let step = self.current_step.borrow();
        match step.deref() {
            Step::WaitingIdentitityInformation
            | Step::WaitingIdentitityAddressInformation
            | Step::SendingKeys { .. }
            | Step::ReceivingKeys { .. }
            | Step::Success => self
                .pairing_data
                .borrow()
                .bond_information
                .as_ref()
                .map(|x| x.security_level)
                .unwrap_or(SecurityLevel::NoEncryption),
            _ => SecurityLevel::NoEncryption,
        }
    }

    fn generate_key_dist_data<RNG: RngCore>(rng: &mut RNG) -> KeyDistData {
        let mut ltk_bytes = [0u8; 16];
        rng.fill_bytes(&mut ltk_bytes);
        let ediv = rng.gen();
        let mut rand = [0u8; 8];
        rng.fill_bytes(&mut rand);
        KeyDistData {
            long_term_key: LongTermKey::from_le_bytes(ltk_bytes),
            ediv,
            rand,
        }
    }

    fn make_sending_keys_step<RNG: RngCore>(phase: u8, rng: &mut RNG) -> Step {
        let keys = if phase == 0 {
            Self::generate_key_dist_data(rng)
        } else {
            // Identity-only phases don't use encryption key fields
            KeyDistData {
                long_term_key: LongTermKey(0),
                ediv: 0,
                rand: [0; 8],
            }
        };
        Step::SendingKeys { phase, keys }
    }

    fn handle_step_result<P: PacketPool, OPS: PairingOps<P>>(
        &self,
        next_step: Step,
        ops: &mut OPS,
    ) -> Result<(), Error> {
        match next_step {
            Step::Error(x) => {
                self.current_step.replace(Step::Error(x.clone()));
                ops.try_send_connection_event(ConnectionEvent::PairingFailed(x.clone()))?;
                Err(x)
            }
            Step::SendingKeys { phase, keys } => {
                self.current_step.replace(Step::SendingKeys { phase, keys });
                self.send_keys(ops, phase, keys)
            }
            x => {
                let is_success = matches!(x, Step::Success);
                self.current_step.replace(x);
                if is_success {
                    let pairing_data = self.pairing_data.borrow();
                    if let Some(bond) = pairing_data.bond_information.as_ref() {
                        let pairing_bond = if pairing_data.want_bonding() {
                            ops.try_update_bond_information(bond)?;
                            Some(bond.clone())
                        } else {
                            None
                        };
                        ops.try_send_connection_event(ConnectionEvent::PairingComplete {
                            security_level: bond.security_level,
                            bond: pairing_bond,
                        })?;
                    }
                }
                Ok(())
            }
        }
    }

    fn send_keys<P: PacketPool, OPS: PairingOps<P>>(
        &self,
        ops: &mut OPS,
        phase: u8,
        keys: KeyDistData,
    ) -> Result<(), Error> {
        let pairing_data = self.pairing_data.borrow();

        let next = match phase {
            // Phase 0: send EncryptionInformation (LTK)
            0 => {
                let packet = make_encryption_information_packet(&keys.long_term_key)?;
                ops.try_send_packet(packet)?;
                Step::SendingKeys { phase: 1, keys }
            }
            // Phase 1: send CentralIdentification (EDIV + Rand)
            1 => {
                let packet = make_central_identification_packet(keys.ediv, &keys.rand)?;
                ops.try_send_packet(packet)?;
                if pairing_data.local_features.responder_key_distribution.identity_key() {
                    Step::SendingKeys { phase: 2, keys }
                } else if pairing_data.peer_features.initiator_key_distribution.encryption_key() {
                    Step::ReceivingKeys {
                        phase: 0,
                        received_ltk: LongTermKey(0),
                    }
                } else if pairing_data.peer_features.initiator_key_distribution.identity_key() {
                    Step::WaitingIdentitityInformation
                } else {
                    Step::Success
                }
            }
            // Phase 2: send IdentityInformation (IRK) - use zero IRK for now
            2 => {
                let irk = IdentityResolvingKey::new(0);
                let packet = make_identity_information_packet(&irk)?;
                ops.try_send_packet(packet)?;
                Step::SendingKeys { phase: 3, keys }
            }
            // Phase 3: send IdentityAddressInformation
            3 => {
                let packet = make_identity_address_information_packet(&pairing_data.local_address)?;
                ops.try_send_packet(packet)?;
                if pairing_data.peer_features.initiator_key_distribution.encryption_key() {
                    Step::ReceivingKeys {
                        phase: 0,
                        received_ltk: LongTermKey(0),
                    }
                } else if pairing_data.peer_features.initiator_key_distribution.identity_key() {
                    Step::WaitingIdentitityInformation
                } else {
                    Step::Success
                }
            }
            _ => Step::Success,
        };

        // After distributing our encryption keys, update the bond with our own
        // LTK (masked to negotiated key size per BT Core Spec Vol 3, Part H, Section 2.4.4),
        // EDIV, and Rand so the central can use them for re-encryption.
        if phase == 1 {
            drop(pairing_data);
            let mut pairing_data = self.pairing_data.borrow_mut();
            let negotiated_key_size = core::cmp::min(
                pairing_data.peer_features.maximum_encryption_key_size,
                pairing_data.local_features.maximum_encryption_key_size,
            );
            let want_bonding = pairing_data.want_bonding();
            if let Some(ref mut bond) = pairing_data.bond_information {
                bond.ltk = if negotiated_key_size >= 16 {
                    keys.long_term_key
                } else {
                    LongTermKey(keys.long_term_key.0 & ((1u128 << (negotiated_key_size as u32 * 8)) - 1))
                };
                bond.ediv = keys.ediv;
                bond.rand = keys.rand;
                bond.is_bonded = want_bonding;
            }
        } else {
            drop(pairing_data);
        }

        self.handle_step_result(next, ops)
    }

    fn handle_impl<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        &self,
        command: CommandAndPayload,
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let current_step = self.current_step.borrow().clone();
        let next_step = {
            let mut pairing_data = self.pairing_data.borrow_mut();
            let pairing_data = pairing_data.deref_mut();
            trace!("[smp legacy] Handling {:?}, step {:?}", command.command, current_step);
            match (current_step, command.command) {
                (Step::WaitingPairingRequest, Command::PairingRequest) => {
                    if ops.find_bond().is_some() {
                        ops.try_send_connection_event(ConnectionEvent::BondLost)?;
                    }
                    Self::handle_pairing_request(command.payload, ops, pairing_data, rng)?
                }
                (Step::WaitingPassKeyInput { preq, pres, .. }, Command::PairingConfirm) => {
                    let confirm_bytes: [u8; size_of::<u128>()] =
                        command.payload.try_into().map_err(|_| Error::InvalidValue)?;
                    Step::WaitingPassKeyInput {
                        confirm_bytes: Some(confirm_bytes),
                        preq,
                        pres,
                    }
                }
                (Step::WaitingPairingConfirm(mut confirm_data), Command::PairingConfirm) => {
                    let peer_confirm = u128::from_le_bytes(
                        command
                            .payload
                            .try_into()
                            .map_err(|_| Error::Security(Reason::InvalidParameters))?,
                    );
                    Self::send_sconfirm(ops, pairing_data, &mut confirm_data, rng)?;
                    Step::WaitingPairingRandom {
                        confirm_data,
                        peer_confirm,
                    }
                }
                (
                    Step::WaitingPairingRandom {
                        confirm_data,
                        peer_confirm,
                    },
                    Command::PairingRandom,
                ) => Self::handle_pairing_random(command.payload, ops, pairing_data, &confirm_data, peer_confirm, rng)?,
                (Step::WaitingIdentitityInformation, Command::IdentityInformation) => {
                    Self::handle_identity_information(command.payload, pairing_data)?
                }
                (Step::WaitingIdentitityAddressInformation, Command::IdentityAddressInformation) => {
                    Self::handle_identity_address_information(command.payload, pairing_data)?
                }
                (Step::ReceivingKeys { phase: 0, .. }, Command::EncryptionInformation) => {
                    Self::handle_encryption_information(command.payload)?
                }
                (
                    Step::ReceivingKeys {
                        phase: 1,
                        received_ltk: _,
                    },
                    Command::CentralIdentification,
                ) => Self::handle_central_identification(command.payload, pairing_data)?,
                (x, Command::KeypressNotification) => x,
                _ => return Err(Error::InvalidState),
            }
        };

        self.handle_step_result(next_step, ops)
    }

    fn handle_pairing_request<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        payload: &[u8],
        ops: &mut OPS,
        pairing_data: &mut PairingData,
        rng: &mut RNG,
    ) -> Result<Step, Error> {
        let peer_features = PairingFeatures::decode(payload).map_err(|_| Error::Security(Reason::InvalidParameters))?;
        // Key size validation (7-16 range) is done in PairingFeatures::decode

        // Store the PairingRequest command bytes for c1
        let mut preq = [0u8; 7];
        preq[0] = u8::from(Command::PairingRequest);
        preq[1..7].copy_from_slice(payload);

        // Negotiate key distribution
        if peer_features.initiator_key_distribution.identity_key() {
            pairing_data
                .local_features
                .initiator_key_distribution
                .set_identity_key();
        }
        if peer_features.initiator_key_distribution.encryption_key() {
            pairing_data
                .local_features
                .initiator_key_distribution
                .set_encryption_key();
        }
        if peer_features.responder_key_distribution.identity_key() {
            pairing_data
                .local_features
                .responder_key_distribution
                .set_identity_key();
        }
        if peer_features.responder_key_distribution.encryption_key() {
            pairing_data
                .local_features
                .responder_key_distribution
                .set_encryption_key();
        }

        pairing_data.peer_features = peer_features;
        let mut auth_req = AuthReq::new_legacy(ops.bonding_flag());
        if pairing_data.local_features.io_capabilities != IoCapabilities::NoInputNoOutput {
            auth_req = auth_req.with_mitm();
        }
        pairing_data.local_features.security_properties = auth_req;
        pairing_data.pairing_method =
            choose_legacy_pairing_method(pairing_data.peer_features, pairing_data.local_features);
        info!("[smp legacy] Pairing method {:?}", pairing_data.pairing_method);

        // Send PairingResponse and store the command bytes for c1
        let mut packet = prepare_packet::<P>(Command::PairingResponse)?;
        let response = packet.payload_mut();
        pairing_data
            .local_features
            .encode(response)
            .map_err(|_| Error::InvalidValue)?;
        let mut pres = [0u8; 7];
        pres[0] = u8::from(Command::PairingResponse);
        pres[1..7].copy_from_slice(response);
        ops.try_send_packet(packet)?;

        match pairing_data.pairing_method {
            PairingMethod::OutOfBand => Err(Error::Security(Reason::OobNotAvailable)),
            PairingMethod::PassKeyEntry { peripheral, .. } => {
                if peripheral == PassKeyEntryAction::Display {
                    let tk = rng.sample(rand::distributions::Uniform::new_inclusive(0u32, 999999)) as u128;
                    ops.try_send_connection_event(ConnectionEvent::PassKeyDisplay(PassKey(tk as u32)))?;
                    Ok(Step::WaitingPairingConfirm(ConfirmPhaseData {
                        tk,
                        preq,
                        pres,
                        local_nonce: 0,
                    }))
                } else {
                    ops.try_send_connection_event(ConnectionEvent::PassKeyInput)?;
                    Ok(Step::WaitingPassKeyInput {
                        confirm_bytes: None,
                        preq,
                        pres,
                    })
                }
            }
            PairingMethod::JustWorks => Ok(Step::WaitingPairingConfirm(ConfirmPhaseData {
                tk: 0,
                preq,
                pres,
                local_nonce: 0,
            })),
            PairingMethod::NumericComparison => {
                // Should not happen in legacy pairing
                Err(Error::Security(Reason::AuthenticationRequirements))
            }
        }
    }

    fn send_sconfirm<P: PacketPool, OPS: PairingOps<P>, RNG: RngCore>(
        ops: &mut OPS,
        pairing_data: &PairingData,
        confirm_data: &mut ConfirmPhaseData,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        // Generate Srand
        let mut srand_bytes = [0u8; 16];
        rng.fill_bytes(&mut srand_bytes);
        confirm_data.local_nonce = u128::from_be_bytes(srand_bytes);
        if confirm_data.local_nonce == 0 {
            confirm_data.local_nonce = 1;
        }

        // Compute Sconfirm = c1(TK, Srand, preq, pres, iat, ia, rat, ra)
        let sconfirm = crypto::c1(
            confirm_data.tk,
            confirm_data.local_nonce,
            &confirm_data.preq,
            &confirm_data.pres,
            addr_type_flag(&pairing_data.peer_address),
            &addr_bytes_mso(&pairing_data.peer_address),
            addr_type_flag(&pairing_data.local_address),
            &addr_bytes_mso(&pairing_data.local_address),
        );

        let mut packet = prepare_packet(Command::PairingConfirm)?;
        packet.payload_mut().copy_from_slice(&sconfirm.to_le_bytes());
        ops.try_send_packet(packet)?;
        Ok(())
    }

    fn handle_pairing_random<P: PacketPool, OPS: PairingOps<P>, RNG: RngCore>(
        payload: &[u8],
        ops: &mut OPS,
        pairing_data: &mut PairingData,
        confirm_data: &ConfirmPhaseData,
        peer_confirm: u128,
        rng: &mut RNG,
    ) -> Result<Step, Error> {
        // Parse Mrand from central
        let mrand_le: [u8; 16] = payload
            .try_into()
            .map_err(|_| Error::Security(Reason::InvalidParameters))?;
        let peer_nonce = u128::from_le_bytes(mrand_le);

        // Verify: c1(TK, Mrand, preq, pres, iat, ia, rat, ra) == stored Mconfirm
        let expected_mconfirm = crypto::c1(
            confirm_data.tk,
            peer_nonce,
            &confirm_data.preq,
            &confirm_data.pres,
            addr_type_flag(&pairing_data.peer_address),
            &addr_bytes_mso(&pairing_data.peer_address),
            addr_type_flag(&pairing_data.local_address),
            &addr_bytes_mso(&pairing_data.local_address),
        );

        if expected_mconfirm != peer_confirm {
            error!("[smp legacy] Confirm value mismatch");
            return Err(Error::Security(Reason::ConfirmValueFailed));
        }

        // Send Srand
        let packet = make_pairing_random(&crypto::Nonce(confirm_data.local_nonce))?;
        ops.try_send_packet(packet)?;

        // Compute STK = s1(TK, Srand, Mrand)
        let stk = crypto::s1(confirm_data.tk, confirm_data.local_nonce, peer_nonce);

        // Mask STK to negotiated key size (Bluetooth Core Spec Vol 3, Part H, Section 2.4.4):
        // Zero out the most significant (16 - key_size) bytes.
        let negotiated_key_size = core::cmp::min(
            pairing_data.peer_features.maximum_encryption_key_size,
            pairing_data.local_features.maximum_encryption_key_size,
        );
        let masked_stk = if negotiated_key_size >= 16 {
            stk
        } else {
            stk & ((1u128 << (negotiated_key_size as u32 * 8)) - 1)
        };
        let stk = LongTermKey(masked_stk);

        // Enable encryption with STK (not yet bonded — real LTK comes via key distribution)
        let bond = ops.try_enable_encryption(&stk, pairing_data.pairing_method.security_level(), false, 0, [0; 8])?;
        pairing_data.bond_information = Some(bond);

        Ok(Step::WaitingLinkEncrypted)
    }

    fn handle_encryption_information(payload: &[u8]) -> Result<Step, Error> {
        let ltk = LongTermKey::from_le_bytes(payload.try_into().map_err(|_| Error::InvalidValue)?);
        trace!("[smp legacy] Received LTK from central");
        Ok(Step::ReceivingKeys {
            phase: 1,
            received_ltk: ltk,
        })
    }

    fn handle_central_identification(payload: &[u8], pairing_data: &mut PairingData) -> Result<Step, Error> {
        if payload.len() < 10 {
            return Err(Error::Security(Reason::InvalidParameters));
        }
        // Central's EDIV/Rand received but not stored in bond — the bond retains the
        // peripheral's own LTK/EDIV/Rand (set in send_keys phase 1) for re-encryption.
        trace!("[smp legacy] Received EDIV/Rand from central");
        if pairing_data.peer_features.initiator_key_distribution.identity_key() {
            Ok(Step::WaitingIdentitityInformation)
        } else {
            Ok(Step::Success)
        }
    }

    fn handle_identity_information(payload: &[u8], pairing_data: &mut PairingData) -> Result<Step, Error> {
        let irk = IdentityResolvingKey::new(u128::from_le_bytes(
            payload.try_into().map_err(|_| Error::InvalidValue)?,
        ));
        if let Some(ref mut bond) = &mut pairing_data.bond_information {
            bond.identity.irk = Some(irk);
        }
        trace!("[smp legacy] Received IRK");
        Ok(Step::WaitingIdentitityAddressInformation)
    }

    fn handle_identity_address_information(payload: &[u8], pairing_data: &mut PairingData) -> Result<Step, Error> {
        let addr_type = payload[0];
        let kind = if addr_type == 0 {
            AddrKind::PUBLIC
        } else if addr_type == 1 {
            AddrKind::RANDOM
        } else {
            return Err(Error::InvalidValue);
        };
        let addr = BdAddr::new(payload[1..7].try_into().map_err(|_| Error::InvalidValue)?);
        pairing_data.peer_address = Address { kind, addr };

        if let Some(ref mut bond) = &mut pairing_data.bond_information {
            bond.identity.bd_addr = addr;
        }

        trace!("[smp legacy] Received identity address {:?}", addr);
        Ok(Step::Success)
    }
}

#[cfg(test)]
mod tests {
    use core::ops::Deref;

    use rand_chacha::{ChaCha12Core, ChaCha12Rng};
    use rand_core::SeedableRng;

    use super::{Pairing, Step};
    use crate::security_manager::pairing::tests::{HeaplessPool, TestOps};
    use crate::security_manager::types::Command;
    use crate::{Address, IoCapabilities};

    #[test]
    fn just_works() {
        let mut ops: TestOps<10> = TestOps::default();
        let pairing = Pairing::new(
            Address::random([1, 2, 3, 4, 5, 6]),
            Address::random([7, 8, 9, 10, 11, 12]),
            IoCapabilities::NoInputNoOutput,
        );
        let mut rng: ChaCha12Rng = ChaCha12Core::seed_from_u64(42).into();

        // Central sends PairingRequest (without SC flag)
        // AuthReq = 0x05 (MITM + Bonding, no SC)
        pairing
            .handle_l2cap_command::<HeaplessPool, _, _>(
                Command::PairingRequest,
                &[0x03, 0, 0x04, 16, 0, 0],
                &mut ops,
                &mut rng,
            )
            .unwrap();

        assert_eq!(ops.sent_packets.len(), 1);
        assert_eq!(ops.sent_packets[0].command(), Command::PairingResponse);

        // Verify it's JustWorks (NoInputNoOutput)
        assert!(matches!(
            pairing.current_step.borrow().deref(),
            Step::WaitingPairingConfirm(_)
        ));
    }
}

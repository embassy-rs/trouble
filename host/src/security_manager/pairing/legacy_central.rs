use core::cell::RefCell;
use core::ops::{Deref, DerefMut};

use bt_hci::param::{AddrKind, BdAddr};
use embassy_time::Instant;
use rand::Rng;
use rand_core::{CryptoRng, RngCore};

use crate::codec::Decode;
use crate::connection::{ConnectionEvent, SecurityLevel};
use crate::security_manager::pairing::util::{
    choose_legacy_pairing_method, make_central_identification_packet, make_encryption_information_packet,
    make_identity_address_information_packet, make_identity_information_packet, make_pairing_random, prepare_packet,
    CommandAndPayload, PairingMethod, PassKeyEntryAction,
};
use crate::security_manager::pairing::{Event, PairingOps};
use crate::security_manager::types::{BondingFlag, Command, PairingFeatures, PassKey};
use crate::security_manager::{crypto, Reason};
use crate::{Address, BondInformation, Error, IdentityResolvingKey, LongTermKey, PacketPool};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum Step {
    WaitingPairingResponse,
    WaitingPassKeyInput(Option<[u8; size_of::<u128>()]>),
    WaitingPairingConfirm,
    WaitingPairingRandom,
    WaitingLinkEncrypted,
    WaitingIdentitityInformation,
    WaitingIdentitityAddressInformation,
    ReceivingKeys(u8),
    SendingKeys(u8),
    Success,
    Error(Error),
}

struct PairingData {
    local_address: Address,
    peer_address: Address,
    local_features: PairingFeatures,
    peer_features: PairingFeatures,
    pairing_method: PairingMethod,
    /// TK: 0 for JustWorks, passkey value for PassKey Entry
    tk: u128,
    /// Pairing Request command bytes (opcode + 6 feature bytes)
    preq: [u8; 7],
    /// Pairing Response command bytes (opcode + 6 feature bytes)
    pres: [u8; 7],
    /// Peripheral's confirm value (Sconfirm)
    peer_confirm: u128,
    /// Central's random (Mrand)
    local_nonce: u128,
    /// Peripheral's random (Srand)
    peer_nonce: u128,
    /// Short-Term Key computed from s1
    stk: LongTermKey,
    /// Received LTK from peripheral (key distribution)
    long_term_key: LongTermKey,
    /// Received EDIV from peripheral
    ediv: u16,
    /// Received Rand from peripheral
    rand: [u8; 8],
    timeout_at: Instant,
    bond_information: Option<BondInformation>,
}

impl PairingData {
    fn want_bonding(&self) -> bool {
        matches!(self.local_features.security_properties.bond(), BondingFlag::Bonding)
            && matches!(self.peer_features.security_properties.bond(), BondingFlag::Bonding)
    }

    /// Get initiator (central) address type for c1
    fn iat(&self) -> u8 {
        if self.local_address.kind == AddrKind::PUBLIC {
            0
        } else {
            1
        }
    }

    /// Get responder (peripheral) address type for c1
    fn rat(&self) -> u8 {
        if self.peer_address.kind == AddrKind::PUBLIC {
            0
        } else {
            1
        }
    }

    /// Get initiator (central) address bytes in MSO order for c1
    fn ia(&self) -> [u8; 6] {
        let mut addr = self.local_address.addr.into_inner();
        addr.reverse();
        addr
    }

    /// Get responder (peripheral) address bytes in MSO order for c1
    fn ra(&self) -> [u8; 6] {
        let mut addr = self.peer_address.addr.into_inner();
        addr.reverse();
        addr
    }
}

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

    /// Create a legacy central state machine from an already-sent PairingRequest.
    /// The LESC central already sent the PairingRequest before discovering the peer doesn't support SC.
    pub(crate) fn from_lesc_switch(
        local_address: Address,
        peer_address: Address,
        local_features: PairingFeatures,
        preq: [u8; 7],
    ) -> Self {
        Self {
            current_step: RefCell::new(Step::WaitingPairingResponse),
            pairing_data: RefCell::new(PairingData {
                local_address,
                peer_address,
                local_features,
                peer_features: PairingFeatures::default(),
                pairing_method: PairingMethod::JustWorks,
                tk: 0,
                preq,
                pres: [0; 7],
                peer_confirm: 0,
                local_nonce: 0,
                peer_nonce: 0,
                stk: LongTermKey(0),
                long_term_key: LongTermKey(0),
                ediv: 0,
                rand: [0; 8],
                timeout_at: Instant::now() + crate::security_manager::constants::TIMEOUT,
                bond_information: None,
            }),
        }
    }

    pub fn peer_address(&self) -> Address {
        self.pairing_data.borrow().peer_address
    }

    pub fn security_level(&self) -> SecurityLevel {
        let step = self.current_step.borrow();
        match step.deref() {
            Step::SendingKeys(_) | Step::ReceivingKeys(_) | Step::Success => self
                .pairing_data
                .borrow()
                .bond_information
                .as_ref()
                .map(|x| x.security_level)
                .unwrap_or(SecurityLevel::NoEncryption),
            _ => SecurityLevel::NoEncryption,
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
                error!(
                    "[smp legacy central] Failed to handle command {:?}, {:?}",
                    command, error
                );
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
        let next_state = match (current_state, event) {
            (Step::WaitingLinkEncrypted, Event::LinkEncryptedResult(res)) => {
                if res {
                    info!("[smp legacy central] Link encrypted!");
                    let pairing_data = self.pairing_data.borrow();
                    if pairing_data.want_bonding() {
                        // Receive keys from peripheral first, then send ours
                        if pairing_data.peer_features.responder_key_distribution.encryption_key() {
                            Step::ReceivingKeys(0)
                        } else if pairing_data.peer_features.responder_key_distribution.identity_key() {
                            Step::WaitingIdentitityInformation
                        } else if pairing_data.local_features.initiator_key_distribution.encryption_key() {
                            Step::SendingKeys(0)
                        } else if pairing_data.local_features.initiator_key_distribution.identity_key() {
                            Step::SendingKeys(2)
                        } else {
                            Step::Success
                        }
                    } else {
                        Step::Success
                    }
                } else {
                    error!("[smp legacy central] Link encryption failed!");
                    Step::Error(Error::Security(Reason::KeyRejected))
                }
            }
            (Step::WaitingPassKeyInput(confirm), Event::PassKeyInput(input)) => {
                let mut pairing_data = self.pairing_data.borrow_mut();
                pairing_data.tk = input as u128;
                Self::send_mconfirm(ops, pairing_data.deref_mut(), rng)?;
                match confirm {
                    Some(payload) => {
                        // We already received Sconfirm
                        pairing_data.peer_confirm = u128::from_le_bytes(payload);
                        Self::send_mrand(ops, pairing_data.deref_mut())?;
                        Step::WaitingPairingRandom
                    }
                    None => Step::WaitingPairingConfirm,
                }
            }
            (Step::WaitingPassKeyInput(confirm), Event::PassKeyCancel) => {
                Step::Error(Error::Security(Reason::PasskeyEntryFailed))
            }
            (x, Event::PassKeyConfirm | Event::PassKeyCancel | Event::PassKeyInput(_)) => x,
            _ => Step::Error(Error::InvalidState),
        };

        self.handle_step_result(next_state, ops)
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
            Step::SendingKeys(phase) => {
                self.current_step.replace(Step::SendingKeys(phase));
                self.send_keys(ops)
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
                    } else {
                        error!("[smp legacy central] No bond information stored");
                    }
                }
                Ok(())
            }
        }
    }

    fn send_keys<P: PacketPool, OPS: PairingOps<P>>(&self, ops: &mut OPS) -> Result<(), Error> {
        let pairing_data = self.pairing_data.borrow();
        let step = self.current_step.borrow().clone();
        let phase = match step {
            Step::SendingKeys(p) => p,
            _ => return Ok(()),
        };

        let next = match phase {
            // Phase 0: send EncryptionInformation (LTK)
            0 => {
                let packet = make_encryption_information_packet(&pairing_data.long_term_key)?;
                ops.try_send_packet(packet)?;
                Step::SendingKeys(1)
            }
            // Phase 1: send CentralIdentification (EDIV + Rand)
            1 => {
                let packet = make_central_identification_packet(pairing_data.ediv, &pairing_data.rand)?;
                ops.try_send_packet(packet)?;
                if pairing_data.local_features.initiator_key_distribution.identity_key() {
                    Step::SendingKeys(2)
                } else {
                    Step::Success
                }
            }
            // Phase 2: send IdentityInformation (IRK)
            2 => {
                let irk = IdentityResolvingKey::new(0);
                let packet = make_identity_information_packet(&irk)?;
                ops.try_send_packet(packet)?;
                Step::SendingKeys(3)
            }
            // Phase 3: send IdentityAddressInformation
            3 => {
                let packet = make_identity_address_information_packet(&pairing_data.local_address)?;
                ops.try_send_packet(packet)?;
                Step::Success
            }
            _ => Step::Success,
        };
        drop(pairing_data);
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
            trace!(
                "[smp legacy central] Handling {:?}, step {:?}",
                command.command,
                current_step
            );
            match (current_step, command.command) {
                (Step::WaitingPairingResponse, Command::PairingResponse) => {
                    Self::handle_pairing_response(command.payload, ops, pairing_data, rng)?
                }
                (Step::WaitingPassKeyInput(_), Command::PairingConfirm) => {
                    let confirm: [u8; size_of::<u128>()] =
                        command.payload.try_into().map_err(|_| Error::InvalidValue)?;
                    Step::WaitingPassKeyInput(Some(confirm))
                }
                (Step::WaitingPairingConfirm, Command::PairingConfirm) => {
                    pairing_data.peer_confirm = u128::from_le_bytes(
                        command
                            .payload
                            .try_into()
                            .map_err(|_| Error::Security(Reason::InvalidParameters))?,
                    );
                    // Send Mrand after receiving Sconfirm
                    Self::send_mrand(ops, pairing_data)?;
                    Step::WaitingPairingRandom
                }
                (Step::WaitingPairingRandom, Command::PairingRandom) => {
                    Self::handle_pairing_random(command.payload, ops, pairing_data)?
                }
                (Step::ReceivingKeys(0), Command::EncryptionInformation) => {
                    Self::handle_encryption_information(command.payload, pairing_data)?
                }
                (Step::ReceivingKeys(1), Command::CentralIdentification) => {
                    Self::handle_central_identification(command.payload, pairing_data)?
                }
                (Step::WaitingIdentitityInformation, Command::IdentityInformation) => {
                    Self::handle_identity_information(command.payload, pairing_data)?
                }
                (Step::WaitingIdentitityAddressInformation, Command::IdentityAddressInformation) => {
                    Self::handle_identity_address_information(command.payload, pairing_data)?
                }
                (x, Command::KeypressNotification) => x,
                _ => return Err(Error::InvalidState),
            }
        };

        self.handle_step_result(next_step, ops)
    }

    fn handle_pairing_response<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        payload: &[u8],
        ops: &mut OPS,
        pairing_data: &mut PairingData,
        rng: &mut RNG,
    ) -> Result<Step, Error> {
        let peer_features = PairingFeatures::decode(payload).map_err(|_| Error::Security(Reason::InvalidParameters))?;
        // Key size validation (7-16 range) is done in PairingFeatures::decode

        // Store the PairingResponse command bytes for c1
        pairing_data.pres[0] = u8::from(Command::PairingResponse);
        pairing_data.pres[1..7].copy_from_slice(payload);

        pairing_data.peer_features = peer_features;
        pairing_data.pairing_method =
            choose_legacy_pairing_method(pairing_data.local_features, pairing_data.peer_features);
        info!("[smp legacy central] Pairing method {:?}", pairing_data.pairing_method);

        // If bonding, generate LTK, EDIV, Rand for central's key distribution
        if pairing_data.want_bonding() && pairing_data.local_features.initiator_key_distribution.encryption_key() {
            let mut ltk_bytes = [0u8; 16];
            rng.fill_bytes(&mut ltk_bytes);
            pairing_data.long_term_key = LongTermKey::from_le_bytes(ltk_bytes);
            pairing_data.ediv = rng.gen();
            rng.fill_bytes(&mut pairing_data.rand);
        }

        match pairing_data.pairing_method {
            PairingMethod::OutOfBand => Err(Error::Security(Reason::OobNotAvailable)),
            PairingMethod::PassKeyEntry { central, .. } => {
                if central == PassKeyEntryAction::Display {
                    pairing_data.tk = rng.sample(rand::distributions::Uniform::new_inclusive(0u32, 999999)) as u128;
                    ops.try_send_connection_event(ConnectionEvent::PassKeyDisplay(PassKey(pairing_data.tk as u32)))?;
                    Self::send_mconfirm(ops, pairing_data, rng)?;
                    Ok(Step::WaitingPairingConfirm)
                } else {
                    ops.try_send_connection_event(ConnectionEvent::PassKeyInput)?;
                    Ok(Step::WaitingPassKeyInput(None))
                }
            }
            PairingMethod::JustWorks => {
                pairing_data.tk = 0;
                Self::send_mconfirm(ops, pairing_data, rng)?;
                Ok(Step::WaitingPairingConfirm)
            }
            PairingMethod::NumericComparison => {
                // Should not happen in legacy pairing
                Err(Error::Security(Reason::AuthenticationRequirements))
            }
        }
    }

    fn send_mconfirm<P: PacketPool, OPS: PairingOps<P>, RNG: RngCore>(
        ops: &mut OPS,
        pairing_data: &mut PairingData,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        // Generate Mrand
        let mut mrand_bytes = [0u8; 16];
        rng.fill_bytes(&mut mrand_bytes);
        pairing_data.local_nonce = u128::from_be_bytes(mrand_bytes);
        if pairing_data.local_nonce == 0 {
            pairing_data.local_nonce = 1;
        }

        // Compute Mconfirm = c1(TK, Mrand, preq, pres, iat, ia, rat, ra)
        let mconfirm = crypto::c1(
            pairing_data.tk,
            pairing_data.local_nonce,
            &pairing_data.preq,
            &pairing_data.pres,
            pairing_data.iat(),
            &pairing_data.ia(),
            pairing_data.rat(),
            &pairing_data.ra(),
        );

        let mut packet = prepare_packet(Command::PairingConfirm)?;
        packet.payload_mut().copy_from_slice(&mconfirm.to_le_bytes());
        ops.try_send_packet(packet)?;
        Ok(())
    }

    fn send_mrand<P: PacketPool, OPS: PairingOps<P>>(
        ops: &mut OPS,
        pairing_data: &mut PairingData,
    ) -> Result<(), Error> {
        let packet = make_pairing_random(&crypto::Nonce(pairing_data.local_nonce))?;
        ops.try_send_packet(packet)?;
        Ok(())
    }

    fn handle_pairing_random<P: PacketPool, OPS: PairingOps<P>>(
        payload: &[u8],
        ops: &mut OPS,
        pairing_data: &mut PairingData,
    ) -> Result<Step, Error> {
        // Parse Srand from peripheral
        let srand_le: [u8; 16] = payload
            .try_into()
            .map_err(|_| Error::Security(Reason::InvalidParameters))?;
        pairing_data.peer_nonce = u128::from_le_bytes(srand_le);

        // Verify: c1(TK, Srand, preq, pres, iat, ia, rat, ra) == stored Sconfirm
        let expected_sconfirm = crypto::c1(
            pairing_data.tk,
            pairing_data.peer_nonce,
            &pairing_data.preq,
            &pairing_data.pres,
            pairing_data.iat(),
            &pairing_data.ia(),
            pairing_data.rat(),
            &pairing_data.ra(),
        );

        if expected_sconfirm != pairing_data.peer_confirm {
            error!("[smp legacy central] Confirm value mismatch");
            return Err(Error::Security(Reason::ConfirmValueFailed));
        }

        // Compute STK = s1(TK, Srand, Mrand)
        let stk = crypto::s1(pairing_data.tk, pairing_data.peer_nonce, pairing_data.local_nonce);

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
        pairing_data.stk = LongTermKey(masked_stk);

        // Central enables encryption with STK (not yet bonded — real LTK comes via key distribution)
        let bond = ops.try_enable_encryption(
            &pairing_data.stk,
            pairing_data.pairing_method.security_level(),
            false,
            0,
            [0; 8],
        )?;
        pairing_data.bond_information = Some(bond);

        Ok(Step::WaitingLinkEncrypted)
    }

    fn handle_encryption_information(payload: &[u8], pairing_data: &mut PairingData) -> Result<Step, Error> {
        let ltk = LongTermKey::from_le_bytes(payload.try_into().map_err(|_| Error::InvalidValue)?);
        pairing_data.long_term_key = ltk;
        trace!("[smp legacy central] Received LTK from peripheral");
        Ok(Step::ReceivingKeys(1))
    }

    fn handle_central_identification(payload: &[u8], pairing_data: &mut PairingData) -> Result<Step, Error> {
        if payload.len() < 10 {
            return Err(Error::Security(Reason::InvalidParameters));
        }
        let ediv = u16::from_le_bytes(payload[0..2].try_into().unwrap());
        let mut rand = [0u8; 8];
        rand.copy_from_slice(&payload[2..10]);

        // Update bond with the peripheral's distributed keys, masking LTK to negotiated
        // key size per BT Core Spec Vol 3, Part H, Section 2.4.4.
        let want_bonding = pairing_data.want_bonding();
        if let Some(ref mut bond) = pairing_data.bond_information {
            let negotiated_key_size = core::cmp::min(
                pairing_data.peer_features.maximum_encryption_key_size,
                pairing_data.local_features.maximum_encryption_key_size,
            );
            bond.ltk = if negotiated_key_size >= 16 {
                pairing_data.long_term_key
            } else {
                LongTermKey(pairing_data.long_term_key.0 & ((1u128 << (negotiated_key_size as u32 * 8)) - 1))
            };
            bond.ediv = ediv;
            bond.rand = rand;
            bond.is_bonded = want_bonding;
        }

        trace!("[smp legacy central] Received EDIV/Rand from peripheral");
        if pairing_data.peer_features.responder_key_distribution.identity_key() {
            Ok(Step::WaitingIdentitityInformation)
        } else if pairing_data.local_features.initiator_key_distribution.encryption_key() {
            Ok(Step::SendingKeys(0))
        } else if pairing_data.local_features.initiator_key_distribution.identity_key() {
            Ok(Step::SendingKeys(2))
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
        trace!("[smp legacy central] Received IRK");
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

        trace!("[smp legacy central] Received identity address {:?}", addr);

        // After receiving peripheral keys, send central keys
        if pairing_data.want_bonding() {
            if pairing_data.local_features.initiator_key_distribution.encryption_key() {
                Ok(Step::SendingKeys(0))
            } else if pairing_data.local_features.initiator_key_distribution.identity_key() {
                Ok(Step::SendingKeys(2))
            } else {
                Ok(Step::Success)
            }
        } else {
            Ok(Step::Success)
        }
    }
}

#[cfg(test)]
mod tests {
    use core::ops::Deref;

    use super::{Pairing, Step};
    use crate::codec::Encode;
    use crate::security_manager::types::{AuthReq, BondingFlag, Command, PairingFeatures};
    use crate::{Address, IoCapabilities};

    #[test]
    fn from_lesc_switch() {
        let central = Address::random([0xff, 2, 2, 3, 4, 5]);
        let peripheral = Address::random([0xff, 1, 2, 3, 4, 5]);

        let local_features = PairingFeatures {
            io_capabilities: IoCapabilities::NoInputNoOutput,
            security_properties: AuthReq::new_legacy(BondingFlag::NoBonding),
            ..Default::default()
        };
        let mut preq = [0u8; 7];
        preq[0] = u8::from(Command::PairingRequest);
        local_features.encode(&mut preq[1..]).unwrap();

        let pairing = Pairing::from_lesc_switch(central, peripheral, local_features, preq);
        assert!(matches!(
            pairing.current_step.borrow().deref(),
            Step::WaitingPairingResponse
        ));
    }
}

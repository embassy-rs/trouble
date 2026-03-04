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
use crate::security_manager::pairing::{Event, PairingData, PairingOps};
use crate::security_manager::types::{Command, PairingFeatures, PassKey};
use crate::security_manager::{crypto, Reason};
use crate::{Address, Error, IdentityResolvingKey, LongTermKey, PacketPool};

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
    /// Central's random (Mrand)
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
    WaitingPairingResponse {
        preq: [u8; 7],
    },
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
    ReceivingKeys {
        phase: u8,
        received_ltk: LongTermKey,
    },
    SendingKeys {
        phase: u8,
        keys: KeyDistData,
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
    current_step: Step,
    pairing_data: PairingData,
}

impl Pairing {
    pub fn result(&self) -> Option<Result<(), Error>> {
        match &self.current_step {
            Step::Success => Some(Ok(())),
            Step::Error(e) => Some(Err(e.clone())),
            _ => None,
        }
    }

    pub fn timeout_at(&self) -> Instant {
        if matches!(&self.current_step, Step::Success | Step::Error(_)) {
            Instant::now() + crate::security_manager::constants::TIMEOUT_DISABLE
        } else {
            self.pairing_data.timeout_at
        }
    }

    pub fn reset_timeout(&mut self) {
        self.pairing_data.timeout_at = Instant::now() + crate::security_manager::constants::TIMEOUT;
    }

    pub(crate) fn mark_timeout(&mut self) {
        if matches!(&self.current_step, Step::Success | Step::Error(_)) {
            return;
        }
        self.current_step = Step::Error(Error::Timeout);
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
            current_step: Step::WaitingPairingResponse { preq },
            pairing_data: PairingData {
                local_address,
                peer_address,
                local_features,
                peer_features: PairingFeatures::default(),
                pairing_method: PairingMethod::JustWorks,
                timeout_at: Instant::now() + crate::security_manager::constants::TIMEOUT,
                bond_information: None,
            },
        }
    }

    pub fn peer_address(&self) -> Address {
        self.pairing_data.peer_address
    }

    pub fn security_level(&self) -> SecurityLevel {
        match &self.current_step {
            Step::SendingKeys { .. } | Step::ReceivingKeys { .. } | Step::Success => self
                .pairing_data
                .bond_information
                .as_ref()
                .map(|x| x.security_level)
                .unwrap_or(SecurityLevel::NoEncryption),
            _ => SecurityLevel::NoEncryption,
        }
    }

    pub fn handle_l2cap_command<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        &mut self,
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
                self.current_step = Step::Error(error.clone());
                Err(error)
            }
        }
    }

    pub fn handle_event<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        &mut self,
        event: Event,
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let current_state = core::mem::replace(&mut self.current_step, Step::Error(Error::InvalidState));
        let next_state = match (current_state, event) {
            (Step::WaitingLinkEncrypted, Event::LinkEncryptedResult(res)) => {
                if res {
                    info!("[smp legacy central] Link encrypted!");
                    let pairing_data = &self.pairing_data;
                    if pairing_data.want_bonding() {
                        // Receive keys from peripheral first, then send ours
                        if pairing_data.peer_features.responder_key_distribution.encryption_key() {
                            Step::ReceivingKeys {
                                phase: 0,
                                received_ltk: LongTermKey(0),
                            }
                        } else if pairing_data.peer_features.responder_key_distribution.identity_key() {
                            Step::WaitingIdentitityInformation
                        } else if pairing_data.local_features.initiator_key_distribution.encryption_key() {
                            Self::make_sending_keys_step(0, rng)
                        } else if pairing_data.local_features.initiator_key_distribution.identity_key() {
                            Self::make_sending_keys_step(2, rng)
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
            (
                Step::WaitingPassKeyInput {
                    confirm_bytes,
                    preq,
                    pres,
                },
                Event::PassKeyInput(input),
            ) => {
                let pairing_data = &self.pairing_data;
                let tk = input as u128;
                let mut confirm_data = ConfirmPhaseData {
                    tk,
                    preq,
                    pres,
                    local_nonce: 0,
                };
                Self::send_mconfirm(ops, pairing_data, &mut confirm_data, rng)?;
                match confirm_bytes {
                    Some(payload) => {
                        let peer_confirm = u128::from_le_bytes(payload);
                        Self::send_mrand(ops, &confirm_data)?;
                        Step::WaitingPairingRandom {
                            confirm_data,
                            peer_confirm,
                        }
                    }
                    None => Step::WaitingPairingConfirm(confirm_data),
                }
            }
            (Step::WaitingPassKeyInput { .. }, Event::PassKeyCancel) => {
                Step::Error(Error::Security(Reason::PasskeyEntryFailed))
            }
            (x, Event::PassKeyConfirm | Event::PassKeyCancel | Event::PassKeyInput(_)) => x,
            _ => Step::Error(Error::InvalidState),
        };

        self.handle_step_result(next_state, ops)
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
        &mut self,
        next_step: Step,
        ops: &mut OPS,
    ) -> Result<(), Error> {
        match next_step {
            Step::Error(x) => {
                self.current_step = Step::Error(x.clone());
                ops.try_send_connection_event(ConnectionEvent::PairingFailed(x.clone()))?;
                Err(x)
            }
            Step::SendingKeys { phase, keys } => {
                self.current_step = Step::SendingKeys { phase, keys };
                self.send_keys(ops, phase, keys)
            }
            x => {
                let is_success = matches!(x, Step::Success);
                self.current_step = x;
                if is_success {
                    let pairing_data = &self.pairing_data;
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

    fn send_keys<P: PacketPool, OPS: PairingOps<P>>(
        &mut self,
        ops: &mut OPS,
        phase: u8,
        keys: KeyDistData,
    ) -> Result<(), Error> {
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
                if self
                    .pairing_data
                    .local_features
                    .initiator_key_distribution
                    .identity_key()
                {
                    Step::SendingKeys { phase: 2, keys }
                } else {
                    Step::Success
                }
            }
            // Phase 2: send IdentityInformation (IRK)
            2 => {
                let irk = IdentityResolvingKey::new(0);
                let packet = make_identity_information_packet(&irk)?;
                ops.try_send_packet(packet)?;
                Step::SendingKeys { phase: 3, keys }
            }
            // Phase 3: send IdentityAddressInformation
            3 => {
                let packet = make_identity_address_information_packet(&self.pairing_data.local_address)?;
                ops.try_send_packet(packet)?;
                Step::Success
            }
            _ => Step::Success,
        };
        self.handle_step_result(next, ops)
    }

    fn handle_impl<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        &mut self,
        command: CommandAndPayload,
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let current_step = core::mem::replace(&mut self.current_step, Step::Error(Error::InvalidState));
        let next_step = {
            let pairing_data = &mut self.pairing_data;
            trace!(
                "[smp legacy central] Handling {:?}, step {:?}",
                command.command,
                current_step
            );
            match (current_step, command.command) {
                (Step::WaitingPairingResponse { preq }, Command::PairingResponse) => {
                    Self::handle_pairing_response(command.payload, ops, pairing_data, rng, preq)?
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
                (Step::WaitingPairingConfirm(confirm_data), Command::PairingConfirm) => {
                    let peer_confirm = u128::from_le_bytes(
                        command
                            .payload
                            .try_into()
                            .map_err(|_| Error::Security(Reason::InvalidParameters))?,
                    );
                    // Send Mrand after receiving Sconfirm
                    Self::send_mrand(ops, &confirm_data)?;
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
                ) => Self::handle_pairing_random(command.payload, ops, pairing_data, &confirm_data, peer_confirm)?,
                (Step::ReceivingKeys { phase: 0, .. }, Command::EncryptionInformation) => {
                    Self::handle_encryption_information(command.payload)?
                }
                (Step::ReceivingKeys { phase: 1, received_ltk }, Command::CentralIdentification) => {
                    Self::handle_central_identification(command.payload, pairing_data, received_ltk, rng)?
                }
                (Step::WaitingIdentitityInformation, Command::IdentityInformation) => {
                    Self::handle_identity_information(command.payload, pairing_data)?
                }
                (Step::WaitingIdentitityAddressInformation, Command::IdentityAddressInformation) => {
                    Self::handle_identity_address_information(command.payload, pairing_data, rng)?
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
        preq: [u8; 7],
    ) -> Result<Step, Error> {
        let peer_features = PairingFeatures::decode(payload).map_err(|_| Error::Security(Reason::InvalidParameters))?;
        // Key size validation (7-16 range) is done in PairingFeatures::decode

        // Store the PairingResponse command bytes for c1
        let mut pres = [0u8; 7];
        pres[0] = u8::from(Command::PairingResponse);
        pres[1..7].copy_from_slice(payload);

        pairing_data.peer_features = peer_features;
        pairing_data.pairing_method =
            choose_legacy_pairing_method(pairing_data.local_features, pairing_data.peer_features);
        info!("[smp legacy central] Pairing method {:?}", pairing_data.pairing_method);

        match pairing_data.pairing_method {
            PairingMethod::OutOfBand => Err(Error::Security(Reason::OobNotAvailable)),
            PairingMethod::PassKeyEntry { central, .. } => {
                if central == PassKeyEntryAction::Display {
                    let tk = rng.sample(rand::distributions::Uniform::new_inclusive(0u32, 999999)) as u128;
                    ops.try_send_connection_event(ConnectionEvent::PassKeyDisplay(PassKey(tk as u32)))?;
                    let mut confirm_data = ConfirmPhaseData {
                        tk,
                        preq,
                        pres,
                        local_nonce: 0,
                    };
                    Self::send_mconfirm(ops, pairing_data, &mut confirm_data, rng)?;
                    Ok(Step::WaitingPairingConfirm(confirm_data))
                } else {
                    ops.try_send_connection_event(ConnectionEvent::PassKeyInput)?;
                    Ok(Step::WaitingPassKeyInput {
                        confirm_bytes: None,
                        preq,
                        pres,
                    })
                }
            }
            PairingMethod::JustWorks => {
                let mut confirm_data = ConfirmPhaseData {
                    tk: 0,
                    preq,
                    pres,
                    local_nonce: 0,
                };
                Self::send_mconfirm(ops, pairing_data, &mut confirm_data, rng)?;
                Ok(Step::WaitingPairingConfirm(confirm_data))
            }
            PairingMethod::NumericComparison => {
                // Should not happen in legacy pairing
                Err(Error::Security(Reason::AuthenticationRequirements))
            }
        }
    }

    fn send_mconfirm<P: PacketPool, OPS: PairingOps<P>, RNG: RngCore>(
        ops: &mut OPS,
        pairing_data: &PairingData,
        confirm_data: &mut ConfirmPhaseData,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        // Generate Mrand
        let mut mrand_bytes = [0u8; 16];
        rng.fill_bytes(&mut mrand_bytes);
        confirm_data.local_nonce = u128::from_be_bytes(mrand_bytes);
        if confirm_data.local_nonce == 0 {
            confirm_data.local_nonce = 1;
        }

        // Compute Mconfirm = c1(TK, Mrand, preq, pres, iat, ia, rat, ra)
        let mconfirm = crypto::c1(
            confirm_data.tk,
            confirm_data.local_nonce,
            &confirm_data.preq,
            &confirm_data.pres,
            addr_type_flag(&pairing_data.local_address),
            &addr_bytes_mso(&pairing_data.local_address),
            addr_type_flag(&pairing_data.peer_address),
            &addr_bytes_mso(&pairing_data.peer_address),
        );

        let mut packet = prepare_packet(Command::PairingConfirm)?;
        packet.payload_mut().copy_from_slice(&mconfirm.to_le_bytes());
        ops.try_send_packet(packet)?;
        Ok(())
    }

    fn send_mrand<P: PacketPool, OPS: PairingOps<P>>(
        ops: &mut OPS,
        confirm_data: &ConfirmPhaseData,
    ) -> Result<(), Error> {
        let packet = make_pairing_random(&crypto::Nonce(confirm_data.local_nonce))?;
        ops.try_send_packet(packet)?;
        Ok(())
    }

    fn handle_pairing_random<P: PacketPool, OPS: PairingOps<P>>(
        payload: &[u8],
        ops: &mut OPS,
        pairing_data: &mut PairingData,
        confirm_data: &ConfirmPhaseData,
        peer_confirm: u128,
    ) -> Result<Step, Error> {
        // Parse Srand from peripheral
        let srand_le: [u8; 16] = payload
            .try_into()
            .map_err(|_| Error::Security(Reason::InvalidParameters))?;
        let peer_nonce = u128::from_le_bytes(srand_le);

        // Verify: c1(TK, Srand, preq, pres, iat, ia, rat, ra) == stored Sconfirm
        let expected_sconfirm = crypto::c1(
            confirm_data.tk,
            peer_nonce,
            &confirm_data.preq,
            &confirm_data.pres,
            addr_type_flag(&pairing_data.local_address),
            &addr_bytes_mso(&pairing_data.local_address),
            addr_type_flag(&pairing_data.peer_address),
            &addr_bytes_mso(&pairing_data.peer_address),
        );

        if expected_sconfirm != peer_confirm {
            error!("[smp legacy central] Confirm value mismatch");
            return Err(Error::Security(Reason::ConfirmValueFailed));
        }

        // Compute STK = s1(TK, Srand, Mrand)
        let stk = crypto::s1(confirm_data.tk, peer_nonce, confirm_data.local_nonce);

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

        // Central enables encryption with STK (not yet bonded — real LTK comes via key distribution)
        let bond = ops.try_enable_encryption(&stk, pairing_data.pairing_method.security_level(), false, 0, [0; 8])?;
        pairing_data.bond_information = Some(bond);

        Ok(Step::WaitingLinkEncrypted)
    }

    fn handle_encryption_information(payload: &[u8]) -> Result<Step, Error> {
        let ltk = LongTermKey::from_le_bytes(payload.try_into().map_err(|_| Error::InvalidValue)?);
        trace!("[smp legacy central] Received LTK from peripheral");
        Ok(Step::ReceivingKeys {
            phase: 1,
            received_ltk: ltk,
        })
    }

    fn handle_central_identification<RNG: RngCore>(
        payload: &[u8],
        pairing_data: &mut PairingData,
        received_ltk: LongTermKey,
        rng: &mut RNG,
    ) -> Result<Step, Error> {
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
                received_ltk
            } else {
                LongTermKey(received_ltk.0 & ((1u128 << (negotiated_key_size as u32 * 8)) - 1))
            };
            bond.ediv = ediv;
            bond.rand = rand;
            bond.is_bonded = want_bonding;
        }

        trace!("[smp legacy central] Received EDIV/Rand from peripheral");
        if pairing_data.peer_features.responder_key_distribution.identity_key() {
            Ok(Step::WaitingIdentitityInformation)
        } else if pairing_data.local_features.initiator_key_distribution.encryption_key() {
            Ok(Self::make_sending_keys_step(0, rng))
        } else if pairing_data.local_features.initiator_key_distribution.identity_key() {
            Ok(Self::make_sending_keys_step(2, rng))
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

    fn handle_identity_address_information<RNG: RngCore>(
        payload: &[u8],
        pairing_data: &mut PairingData,
        rng: &mut RNG,
    ) -> Result<Step, Error> {
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
                Ok(Self::make_sending_keys_step(0, rng))
            } else if pairing_data.local_features.initiator_key_distribution.identity_key() {
                Ok(Self::make_sending_keys_step(2, rng))
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
        assert!(matches!(&pairing.current_step, Step::WaitingPairingResponse { .. }));
    }
}

use bt_hci::param::{AddrKind, BdAddr};
use rand::Rng;
use rand_core::{CryptoRng, RngCore};

use crate::codec::{Decode, Encode};
use crate::connection::ConnectionEvent;
use crate::security_manager::pairing::util::{
    choose_legacy_pairing_method, make_central_identification_packet, make_encryption_information_packet,
    make_identity_address_information_packet, make_identity_information_packet, make_pairing_random, prepare_packet,
    PairingMethod, PassKeyEntryAction,
};
use crate::security_manager::pairing::{Event, Input, PairingData, PairingOps};
use crate::security_manager::types::{AuthReq, Command, PairingFeatures, PassKey};
use crate::security_manager::{crypto, Reason};
use crate::{Address, Error, IdentityResolvingKey, IoCapabilities, LongTermKey, PacketPool};

/// Data needed during the confirm/random exchange phase of legacy pairing.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(super) struct ConfirmPhaseData {
    /// TK: 0 for JustWorks, passkey value for PassKey Entry
    tk: u128,
    /// Pairing Request command bytes (opcode + 6 feature bytes)
    preq: [u8; 7],
    /// Pairing Response command bytes (opcode + 6 feature bytes)
    pres: [u8; 7],
    /// Peripheral's random (Srand)
    local_nonce: u128,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(super) enum Pairing {
    WaitingPairingRequest,
    WaitingPassKeyInput {
        confirm_bytes: Option<[u8; size_of::<u128>()]>,
        preq: [u8; 7],
        pres: [u8; 7],
    },
    WaitingOobData {
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

impl Pairing {
    pub fn result(&self) -> Option<Result<(), Error>> {
        match self {
            Self::Success => Some(Ok(())),
            Self::Error(e) => Some(Err(e.clone())),
            _ => None,
        }
    }

    pub(crate) fn mark_timeout(&mut self) {
        if matches!(self, Self::Success | Self::Error(_)) {
            return;
        }
        *self = Self::Error(Error::Timeout);
    }

    pub fn new() -> Self {
        Self::WaitingPairingRequest
    }

    pub(crate) fn is_encrypted(&self) -> bool {
        matches!(
            self,
            Self::WaitingIdentitityInformation
                | Self::WaitingIdentitityAddressInformation
                | Self::ReceivingKeys { .. }
                | Self::Success
        )
    }

    // --- FSM core ---

    pub(super) fn handle_input<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        &mut self,
        input: Input<'_>,
        pairing_data: &mut PairingData,
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let current = core::mem::replace(self, Self::Error(Error::InvalidState));
        let next = Self::transition::<P, OPS, RNG>(current, input, pairing_data, ops, rng).unwrap_or_else(Self::Error);
        self.enter(next, pairing_data, ops);
        self.result().unwrap_or(Ok(()))
    }

    fn transition<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        current: Self,
        input: Input<'_>,
        pairing_data: &mut PairingData,
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        match (current, input) {
            // --- Command transitions ---
            (Self::WaitingPairingRequest, Input::Command(Command::PairingRequest, payload)) => {
                Self::handle_pairing_request(payload, ops, pairing_data, rng)
            }
            (Self::WaitingOobData { preq, pres }, Input::Event(Event::OobDataReceived { local, .. })) => {
                let tk = u128::from_le_bytes(local.random);
                Ok(Self::WaitingPairingConfirm(ConfirmPhaseData {
                    tk,
                    preq,
                    pres,
                    local_nonce: 0,
                }))
            }
            (Self::WaitingPassKeyInput { preq, pres, .. }, Input::Command(Command::PairingConfirm, payload)) => {
                Self::store_confirm_bytes(payload, preq, pres)
            }
            (Self::WaitingPairingConfirm(confirm_data), Input::Command(Command::PairingConfirm, payload)) => {
                Self::handle_peer_confirm(payload, ops, pairing_data, confirm_data, rng)
            }
            (
                Self::WaitingPairingRandom {
                    confirm_data,
                    peer_confirm,
                },
                Input::Command(Command::PairingRandom, payload),
            ) => Self::handle_pairing_random(payload, ops, pairing_data, &confirm_data, peer_confirm, rng),
            (Self::WaitingIdentitityInformation, Input::Command(Command::IdentityInformation, payload)) => {
                Self::handle_identity_information(payload, pairing_data)
            }
            (
                Self::WaitingIdentitityAddressInformation,
                Input::Command(Command::IdentityAddressInformation, payload),
            ) => Self::handle_identity_address_information(payload, pairing_data),
            (Self::ReceivingKeys { phase: 0, .. }, Input::Command(Command::EncryptionInformation, payload)) => {
                Self::handle_encryption_information(payload)
            }
            (
                Self::ReceivingKeys {
                    phase: 1,
                    received_ltk: _,
                },
                Input::Command(Command::CentralIdentification, payload),
            ) => Self::handle_central_identification(payload, pairing_data),
            (current, Input::Command(Command::KeypressNotification, _)) => Ok(current),

            // --- Event transitions ---
            (
                x @ (Self::WaitingPairingRequest | Self::WaitingLinkEncrypted),
                Input::Event(Event::LinkEncryptedResult(true)),
            ) => Self::handle_link_encrypted_success(x, pairing_data, ops, rng),
            (
                Self::WaitingPairingRequest | Self::WaitingLinkEncrypted,
                Input::Event(Event::LinkEncryptedResult(false)),
            ) => {
                error!("[smp legacy peripheral] Link encryption failed!");
                Err(Error::Security(Reason::KeyRejected))
            }
            (
                Self::WaitingPassKeyInput {
                    confirm_bytes,
                    preq,
                    pres,
                },
                Input::Event(Event::PassKeyInput(input)),
            ) => Self::handle_pass_key_input(input, confirm_bytes, preq, pres, ops, pairing_data, rng),
            (Self::WaitingPassKeyInput { .. }, Input::Event(Event::PassKeyCancel)) => {
                Err(Error::Security(Reason::PasskeyEntryFailed))
            }
            (current, Input::Event(Event::PassKeyConfirm | Event::PassKeyCancel | Event::PassKeyInput(_))) => {
                Ok(current)
            }

            // --- Catch-all ---
            _ => Err(Error::InvalidState),
        }
    }

    fn enter<P: PacketPool, OPS: PairingOps<P>>(&mut self, next: Self, pairing_data: &PairingData, ops: &mut OPS) {
        match &next {
            Self::Error(e) => {
                if let Err(e) = ops.try_send_connection_event(ConnectionEvent::PairingFailed(e.clone())) {
                    error!("[smp] Failed to send PairingFailed event: {:?}", e);
                }
            }
            Self::Success => {
                if let Some(bond) = pairing_data.bond_information.as_ref() {
                    let pairing_bond = if pairing_data.want_bonding() {
                        if let Err(e) = ops.try_update_bond_information(bond) {
                            error!("[smp] Failed to update bond information: {:?}", e);
                        }
                        Some(bond.clone())
                    } else {
                        None
                    };
                    if let Err(e) = ops.try_send_connection_event(ConnectionEvent::PairingComplete {
                        security_level: bond.security_level,
                        bond: pairing_bond,
                    }) {
                        error!("[smp] Failed to send PairingComplete event: {:?}", e);
                    }
                } else {
                    error!("[smp legacy peripheral] No bond information stored");
                }
            }
            _ => {}
        }
        *self = next;
    }

    // --- Transition helpers ---

    fn handle_link_encrypted_success<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        previous: Self,
        pairing_data: &mut PairingData,
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        info!("[smp legacy peripheral] Link encrypted!");
        if matches!(previous, Self::WaitingPairingRequest) {
            pairing_data.bond_information = ops.try_enable_bonded_encryption()?;
        }
        if matches!(previous, Self::WaitingLinkEncrypted) && pairing_data.want_bonding() {
            // Peripheral sends its keys first, then receives central's
            Self::send_all_keys(pairing_data, ops, rng)
        } else if pairing_data.peer_features.initiator_key_distribution.identity_key() {
            Ok(Self::WaitingIdentitityInformation)
        } else {
            Ok(Self::Success)
        }
    }

    fn store_confirm_bytes(payload: &[u8], preq: [u8; 7], pres: [u8; 7]) -> Result<Self, Error> {
        let confirm_bytes: [u8; size_of::<u128>()] = payload.try_into().map_err(|_| Error::InvalidValue)?;
        Ok(Self::WaitingPassKeyInput {
            confirm_bytes: Some(confirm_bytes),
            preq,
            pres,
        })
    }

    #[inline]
    fn handle_peer_confirm<P: PacketPool, OPS: PairingOps<P>, RNG: RngCore>(
        payload: &[u8],
        ops: &mut OPS,
        pairing_data: &PairingData,
        mut confirm_data: ConfirmPhaseData,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let peer_confirm = u128::from_le_bytes(
            payload
                .try_into()
                .map_err(|_| Error::Security(Reason::InvalidParameters))?,
        );
        Self::send_sconfirm(ops, pairing_data, &mut confirm_data, rng)?;
        Ok(Self::WaitingPairingRandom {
            confirm_data,
            peer_confirm,
        })
    }

    #[inline]
    fn handle_pass_key_input<P: PacketPool, OPS: PairingOps<P>, RNG: RngCore>(
        input: u32,
        confirm_bytes: Option<[u8; size_of::<u128>()]>,
        preq: [u8; 7],
        pres: [u8; 7],
        ops: &mut OPS,
        pairing_data: &PairingData,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let tk = input as u128;
        match confirm_bytes {
            Some(payload) => {
                let peer_confirm = u128::from_le_bytes(payload);
                let mut confirm_data = ConfirmPhaseData {
                    tk,
                    preq,
                    pres,
                    local_nonce: 0,
                };
                Self::send_sconfirm(ops, pairing_data, &mut confirm_data, rng)?;
                Ok(Self::WaitingPairingRandom {
                    confirm_data,
                    peer_confirm,
                })
            }
            None => Ok(Self::WaitingPairingConfirm(ConfirmPhaseData {
                tk,
                preq,
                pres,
                local_nonce: 0,
            })),
        }
    }

    /// Send all responder key distribution packets at once.
    fn send_all_keys<P: PacketPool, OPS: PairingOps<P>, RNG: RngCore>(
        pairing_data: &mut PairingData,
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        if pairing_data.local_features.responder_key_distribution.encryption_key() {
            let mut ltk_bytes = [0u8; 16];
            rng.fill_bytes(&mut ltk_bytes);
            let long_term_key = LongTermKey::from_le_bytes(ltk_bytes);
            let ediv: u16 = rng.gen();
            let mut rand = [0u8; 8];
            rng.fill_bytes(&mut rand);

            let packet = make_encryption_information_packet(&long_term_key)?;
            ops.try_send_packet(packet)?;
            let packet = make_central_identification_packet(ediv, &rand)?;
            ops.try_send_packet(packet)?;

            // Update bond with our own distributed LTK (masked to negotiated key size
            // per BT Core Spec Vol 3, Part H, Section 2.4.4), EDIV, and Rand so the
            // central can use them for re-encryption.
            let negotiated_key_size = core::cmp::min(
                pairing_data.peer_features.maximum_encryption_key_size,
                pairing_data.local_features.maximum_encryption_key_size,
            );
            let want_bonding = pairing_data.want_bonding();
            if let Some(ref mut bond) = pairing_data.bond_information {
                bond.ltk = if negotiated_key_size >= 16 {
                    long_term_key
                } else {
                    LongTermKey(long_term_key.0 & ((1u128 << (negotiated_key_size as u32 * 8)) - 1))
                };
                bond.ediv = ediv;
                bond.rand = rand;
                bond.is_bonded = want_bonding;
            }
        }
        if pairing_data.local_features.responder_key_distribution.identity_key() {
            let irk = IdentityResolvingKey::new(0);
            let packet = make_identity_information_packet(&irk)?;
            ops.try_send_packet(packet)?;
            let packet = make_identity_address_information_packet(&pairing_data.local_address)?;
            ops.try_send_packet(packet)?;
        }

        // After sending our keys, receive central's keys
        if pairing_data.peer_features.initiator_key_distribution.encryption_key() {
            Ok(Self::ReceivingKeys {
                phase: 0,
                received_ltk: LongTermKey(0),
            })
        } else if pairing_data.peer_features.initiator_key_distribution.identity_key() {
            Ok(Self::WaitingIdentitityInformation)
        } else {
            Ok(Self::Success)
        }
    }

    // --- Protocol helpers ---

    fn handle_pairing_request<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        payload: &[u8],
        ops: &mut OPS,
        pairing_data: &mut PairingData,
        rng: &mut RNG,
    ) -> Result<Pairing, Error> {
        if ops.find_bond().is_some() {
            if let Err(e) = ops.try_send_connection_event(ConnectionEvent::BondLost) {
                error!("[smp] Failed to send BondLost event: {:?}", e);
            }
        }

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
        if ops.oob_available() {
            pairing_data.local_features.use_oob = crate::security_manager::types::UseOutOfBand::Present;
        }
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
            PairingMethod::OutOfBand => {
                ops.try_send_connection_event(ConnectionEvent::OobRequest)?;
                Ok(Self::WaitingOobData { preq, pres })
            }
            PairingMethod::PassKeyEntry { peripheral, .. } => {
                if peripheral == PassKeyEntryAction::Display {
                    let tk = rng.sample(rand::distributions::Uniform::new_inclusive(0u32, 999999)) as u128;
                    ops.try_send_connection_event(ConnectionEvent::PassKeyDisplay(PassKey(tk as u32)))?;
                    Ok(Self::WaitingPairingConfirm(ConfirmPhaseData {
                        tk,
                        preq,
                        pres,
                        local_nonce: 0,
                    }))
                } else {
                    ops.try_send_connection_event(ConnectionEvent::PassKeyInput)?;
                    Ok(Self::WaitingPassKeyInput {
                        confirm_bytes: None,
                        preq,
                        pres,
                    })
                }
            }
            PairingMethod::JustWorks => Ok(Self::WaitingPairingConfirm(ConfirmPhaseData {
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

    #[inline]
    fn handle_pairing_random<P: PacketPool, OPS: PairingOps<P>, RNG: RngCore>(
        payload: &[u8],
        ops: &mut OPS,
        pairing_data: &mut PairingData,
        confirm_data: &ConfirmPhaseData,
        peer_confirm: u128,
        rng: &mut RNG,
    ) -> Result<Pairing, Error> {
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
        let bond = ops.try_enable_encryption(
            &stk,
            pairing_data.pairing_method.security_level(),
            false,
            0,
            [0; 8],
            negotiated_key_size,
        )?;
        pairing_data.bond_information = Some(bond);

        Ok(Self::WaitingLinkEncrypted)
    }

    fn handle_encryption_information(payload: &[u8]) -> Result<Pairing, Error> {
        let ltk = LongTermKey::from_le_bytes(payload.try_into().map_err(|_| Error::InvalidValue)?);
        trace!("[smp legacy] Received LTK from central");
        Ok(Self::ReceivingKeys {
            phase: 1,
            received_ltk: ltk,
        })
    }

    fn handle_central_identification(payload: &[u8], pairing_data: &mut PairingData) -> Result<Pairing, Error> {
        if payload.len() < 10 {
            return Err(Error::Security(Reason::InvalidParameters));
        }
        // Central's EDIV/Rand received but not stored in bond — the bond retains the
        // peripheral's own LTK/EDIV/Rand (set in send_all_keys) for re-encryption.
        trace!("[smp legacy] Received EDIV/Rand from central");
        if pairing_data.peer_features.initiator_key_distribution.identity_key() {
            Ok(Self::WaitingIdentitityInformation)
        } else {
            Ok(Self::Success)
        }
    }

    fn handle_identity_information(payload: &[u8], pairing_data: &mut PairingData) -> Result<Pairing, Error> {
        let irk = IdentityResolvingKey::new(u128::from_le_bytes(
            payload.try_into().map_err(|_| Error::InvalidValue)?,
        ));
        if let Some(ref mut bond) = &mut pairing_data.bond_information {
            bond.identity.irk = Some(irk);
        }
        trace!("[smp legacy] Received IRK");
        Ok(Self::WaitingIdentitityAddressInformation)
    }

    fn handle_identity_address_information(payload: &[u8], pairing_data: &mut PairingData) -> Result<Pairing, Error> {
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
            bond.identity.addr = Address { kind, addr };
        }

        trace!("[smp legacy] Received identity address {:?}", addr);
        Ok(Self::Success)
    }
}

#[cfg(test)]
mod tests {
    use embassy_time::Instant;
    use rand_chacha::{ChaCha12Core, ChaCha12Rng};
    use rand_core::SeedableRng;

    use super::Pairing;
    use crate::security_manager::pairing::tests::{HeaplessPool, TestOps};
    use crate::security_manager::pairing::util::PairingMethod;
    use crate::security_manager::pairing::{Input, PairingData};
    use crate::security_manager::types::{Command, PairingFeatures};
    use crate::{Address, IoCapabilities};

    fn make_default_pairing_data(
        local_address: Address,
        peer_address: Address,
        local_io: IoCapabilities,
    ) -> PairingData {
        PairingData {
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
        }
    }

    #[test]
    fn just_works() {
        let mut ops: TestOps<10> = TestOps::new(0xDEAD);
        let mut pairing_data = make_default_pairing_data(
            Address::random([1, 2, 3, 4, 5, 6]),
            Address::random([7, 8, 9, 10, 11, 12]),
            IoCapabilities::NoInputNoOutput,
        );
        let mut pairing = Pairing::new();
        let mut rng: ChaCha12Rng = ChaCha12Core::seed_from_u64(42).into();

        // Central sends PairingRequest (without SC flag)
        // AuthReq = 0x05 (MITM + Bonding, no SC)
        pairing
            .handle_input::<HeaplessPool, _, _>(
                Input::Command(Command::PairingRequest, &[0x03, 0, 0x04, 16, 0, 0]),
                &mut pairing_data,
                &mut ops,
                &mut rng,
            )
            .unwrap();

        assert_eq!(ops.sent_packets.len(), 1);
        assert_eq!(ops.sent_packets[0].command(), Command::PairingResponse);

        // Verify it's JustWorks (NoInputNoOutput)
        assert!(matches!(pairing, Pairing::WaitingPairingConfirm(_)));
    }
}

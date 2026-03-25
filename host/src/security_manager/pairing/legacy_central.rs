use bt_hci::param::{AddrKind, BdAddr};
use rand::Rng;
use rand_core::{CryptoRng, RngCore};

use crate::codec::Decode;
use crate::connection::ConnectionEvent;
use crate::security_manager::pairing::util::{
    choose_legacy_pairing_method, make_central_identification_packet, make_encryption_information_packet,
    make_identity_address_information_packet, make_identity_information_packet, make_pairing_random, prepare_packet,
    PairingMethod, PassKeyEntryAction,
};
use crate::security_manager::pairing::{Event, Input, PairingData, PairingOps};
use crate::security_manager::types::{Command, PairingFeatures, PassKey};
use crate::security_manager::{crypto, Reason};
use crate::{Address, Error, IdentityResolvingKey, LongTermKey, PacketPool};

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
    /// Central's random (Mrand)
    local_nonce: u128,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(super) enum Pairing {
    WaitingPairingResponse {
        preq: [u8; 7],
    },
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

    /// Create a legacy central state machine from an already-sent PairingRequest.
    /// The LESC central already sent the PairingRequest before discovering the peer doesn't support SC.
    pub(crate) fn from_lesc_switch(preq: [u8; 7]) -> Self {
        Self::WaitingPairingResponse { preq }
    }

    pub(crate) fn is_encrypted(&self) -> bool {
        matches!(self, Self::ReceivingKeys { .. } | Self::Success)
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
            (Self::WaitingPairingResponse { preq }, Input::Command(Command::PairingResponse, payload)) => {
                Self::handle_pairing_response(payload, ops, pairing_data, rng, preq)
            }
            (Self::WaitingOobData { preq, pres }, Input::Event(Event::OobDataReceived { local, peer })) => {
                let tk = u128::from_le_bytes(local.random);
                let mut confirm_data = ConfirmPhaseData {
                    tk,
                    preq,
                    pres,
                    local_nonce: 0,
                };
                Self::send_mconfirm(ops, pairing_data, &mut confirm_data, rng)?;
                Ok(Self::WaitingPairingConfirm(confirm_data))
            }
            (Self::WaitingPassKeyInput { preq, pres, .. }, Input::Command(Command::PairingConfirm, payload)) => {
                Self::store_confirm_bytes(payload, preq, pres)
            }
            (Self::WaitingPairingConfirm(confirm_data), Input::Command(Command::PairingConfirm, payload)) => {
                Self::handle_peer_confirm(payload, ops, confirm_data)
            }
            (
                Self::WaitingPairingRandom {
                    confirm_data,
                    peer_confirm,
                },
                Input::Command(Command::PairingRandom, payload),
            ) => Self::handle_pairing_random(payload, ops, pairing_data, &confirm_data, peer_confirm),
            (Self::ReceivingKeys { phase: 0, .. }, Input::Command(Command::EncryptionInformation, payload)) => {
                Self::handle_encryption_information(payload)
            }
            (
                Self::ReceivingKeys { phase: 1, received_ltk },
                Input::Command(Command::CentralIdentification, payload),
            ) => Self::handle_central_identification(payload, pairing_data, received_ltk, ops, rng),
            (Self::WaitingIdentitityInformation, Input::Command(Command::IdentityInformation, payload)) => {
                Self::handle_identity_information(payload, pairing_data)
            }
            (
                Self::WaitingIdentitityAddressInformation,
                Input::Command(Command::IdentityAddressInformation, payload),
            ) => Self::handle_identity_address_information(payload, pairing_data, ops, rng),
            (current, Input::Command(Command::KeypressNotification, _)) => Ok(current),

            // --- Event transitions ---
            (Self::WaitingLinkEncrypted, Input::Event(Event::LinkEncryptedResult(true))) => {
                Self::handle_link_encrypted_success(pairing_data, ops, rng)
            }
            (Self::WaitingLinkEncrypted, Input::Event(Event::LinkEncryptedResult(false))) => {
                error!("[smp legacy central] Link encryption failed!");
                Err(Error::Security(Reason::ConfirmValueFailed))
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
                    error!("[smp legacy central] No bond information stored");
                }
            }
            _ => {}
        }
        *self = next;
    }

    // --- Transition helpers ---

    fn handle_link_encrypted_success<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        pairing_data: &mut PairingData,
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        info!("[smp legacy central] Link encrypted!");
        if pairing_data.want_bonding() {
            // Receive keys from peripheral first, then send ours
            if pairing_data.peer_features.responder_key_distribution.encryption_key() {
                Ok(Self::ReceivingKeys {
                    phase: 0,
                    received_ltk: LongTermKey(0),
                })
            } else if pairing_data.peer_features.responder_key_distribution.identity_key() {
                Ok(Self::WaitingIdentitityInformation)
            } else {
                Self::send_all_keys(pairing_data, ops, rng)
            }
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
    fn handle_peer_confirm<P: PacketPool, OPS: PairingOps<P>>(
        payload: &[u8],
        ops: &mut OPS,
        confirm_data: ConfirmPhaseData,
    ) -> Result<Self, Error> {
        let peer_confirm = u128::from_le_bytes(
            payload
                .try_into()
                .map_err(|_| Error::Security(Reason::InvalidParameters))?,
        );
        Self::send_mrand(ops, &confirm_data)?;
        Ok(Self::WaitingPairingRandom {
            confirm_data,
            peer_confirm,
        })
    }

    #[inline]
    fn handle_pass_key_input<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        input: u32,
        confirm_bytes: Option<[u8; size_of::<u128>()]>,
        preq: [u8; 7],
        pres: [u8; 7],
        ops: &mut OPS,
        pairing_data: &PairingData,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
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
                Ok(Self::WaitingPairingRandom {
                    confirm_data,
                    peer_confirm,
                })
            }
            None => Ok(Self::WaitingPairingConfirm(confirm_data)),
        }
    }

    /// Send all initiator key distribution packets at once.
    fn send_all_keys<P: PacketPool, OPS: PairingOps<P>, RNG: RngCore>(
        pairing_data: &mut PairingData,
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        if pairing_data.local_features.initiator_key_distribution.encryption_key() {
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
        }
        if pairing_data.local_features.initiator_key_distribution.identity_key() {
            let irk = IdentityResolvingKey::new(0);
            let packet = make_identity_information_packet(&irk)?;
            ops.try_send_packet(packet)?;
            let packet = make_identity_address_information_packet(&pairing_data.local_address)?;
            ops.try_send_packet(packet)?;
        }
        Ok(Self::Success)
    }

    // --- Protocol helpers ---

    fn handle_pairing_response<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        payload: &[u8],
        ops: &mut OPS,
        pairing_data: &mut PairingData,
        rng: &mut RNG,
        preq: [u8; 7],
    ) -> Result<Self, Error> {
        let peer_features = PairingFeatures::decode(payload).map_err(|_| Error::Security(Reason::InvalidParameters))?;

        // Store the PairingResponse command bytes for c1
        let mut pres = [0u8; 7];
        pres[0] = u8::from(Command::PairingResponse);
        pres[1..7].copy_from_slice(payload);

        pairing_data.peer_features = peer_features;
        pairing_data.pairing_method =
            choose_legacy_pairing_method(pairing_data.local_features, pairing_data.peer_features);
        info!("[smp legacy central] Pairing method {:?}", pairing_data.pairing_method);

        match pairing_data.pairing_method {
            PairingMethod::OutOfBand => {
                ops.try_send_connection_event(ConnectionEvent::OobRequest)?;
                Ok(Self::WaitingOobData { preq, pres })
            }
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
                    Ok(Self::WaitingPairingConfirm(confirm_data))
                } else {
                    ops.try_send_connection_event(ConnectionEvent::PassKeyInput)?;
                    Ok(Self::WaitingPassKeyInput {
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
                Ok(Self::WaitingPairingConfirm(confirm_data))
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
        let mut mrand_bytes = [0u8; 16];
        rng.fill_bytes(&mut mrand_bytes);
        confirm_data.local_nonce = u128::from_be_bytes(mrand_bytes);
        if confirm_data.local_nonce == 0 {
            confirm_data.local_nonce = 1;
        }

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

    #[inline]
    fn handle_pairing_random<P: PacketPool, OPS: PairingOps<P>>(
        payload: &[u8],
        ops: &mut OPS,
        pairing_data: &mut PairingData,
        confirm_data: &ConfirmPhaseData,
        peer_confirm: u128,
    ) -> Result<Self, Error> {
        let srand_le: [u8; 16] = payload
            .try_into()
            .map_err(|_| Error::Security(Reason::InvalidParameters))?;
        let peer_nonce = u128::from_le_bytes(srand_le);

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

        let stk = crypto::s1(confirm_data.tk, peer_nonce, confirm_data.local_nonce);

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

    fn handle_encryption_information(payload: &[u8]) -> Result<Self, Error> {
        let ltk = LongTermKey::from_le_bytes(payload.try_into().map_err(|_| Error::InvalidValue)?);
        trace!("[smp legacy central] Received LTK from peripheral");
        Ok(Self::ReceivingKeys {
            phase: 1,
            received_ltk: ltk,
        })
    }

    fn handle_central_identification<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        payload: &[u8],
        pairing_data: &mut PairingData,
        received_ltk: LongTermKey,
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        if payload.len() < 10 {
            return Err(Error::Security(Reason::InvalidParameters));
        }
        let ediv = u16::from_le_bytes(payload[0..2].try_into().unwrap());
        let mut rand = [0u8; 8];
        rand.copy_from_slice(&payload[2..10]);

        // Update bond with the peripheral's distributed keys
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
            Ok(Self::WaitingIdentitityInformation)
        } else {
            Self::send_all_keys(pairing_data, ops, rng)
        }
    }

    fn handle_identity_information(payload: &[u8], pairing_data: &mut PairingData) -> Result<Self, Error> {
        let irk = IdentityResolvingKey::new(u128::from_le_bytes(
            payload.try_into().map_err(|_| Error::InvalidValue)?,
        ));
        if let Some(ref mut bond) = &mut pairing_data.bond_information {
            bond.identity.irk = Some(irk);
        }
        trace!("[smp legacy central] Received IRK");
        Ok(Self::WaitingIdentitityAddressInformation)
    }

    fn handle_identity_address_information<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        payload: &[u8],
        pairing_data: &mut PairingData,
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let addr_type = payload[0];
        let kind = if addr_type == 0 {
            AddrKind::PUBLIC
        } else if addr_type == 1 {
            AddrKind::RANDOM
        } else {
            return Err(Error::InvalidValue);
        };
        let addr = BdAddr::new(payload[1..7].try_into().map_err(|_| Error::InvalidValue)?);
        pairing_data.peer_address = Address::new(kind, addr);

        if let Some(ref mut bond) = &mut pairing_data.bond_information {
            bond.identity.addr = Address::new(kind, addr);
        }

        trace!("[smp legacy central] Received identity address {:?}", addr);

        if pairing_data.want_bonding() {
            Self::send_all_keys(pairing_data, ops, rng)
        } else {
            Ok(Self::Success)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Pairing;
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

        let pairing = Pairing::from_lesc_switch(preq);
        assert!(matches!(pairing, Pairing::WaitingPairingResponse { .. }));
    }
}

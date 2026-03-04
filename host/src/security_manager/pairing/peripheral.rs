use bt_hci::param::{AddrKind, BdAddr};
use rand::Rng;
use rand_core::{CryptoRng, RngCore};

use crate::codec::{Decode, Encode};
use crate::prelude::ConnectionEvent;
use crate::security_manager::crypto::{Confirm, DHKey, Nonce, PublicKey, PublicKeyX, SecretKey};
use crate::security_manager::pairing::util::{
    choose_pairing_method, make_confirm_packet, make_dhkey_check_packet, make_pairing_random, make_public_key_packet,
    prepare_packet, CommandAndPayload, PairingMethod, PassKeyEntryAction,
};
use crate::security_manager::pairing::{Event, PairingData, PairingOps};
use crate::security_manager::types::{AuthReq, Command, PairingFeatures, PassKey};
use crate::security_manager::Reason;
use crate::{Address, Error, IdentityResolvingKey, IoCapabilities, PacketPool};

/// EC key and comparison phase data carried through LESC step variants.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(super) struct LescPhaseData {
    local_public_key_x: PublicKeyX,
    peer_public_key_x: PublicKeyX,
    dh_key: DHKey,
    confirm: Confirm,
    local_nonce: Nonce,
    peer_nonce: Nonce,
    local_secret_rb: u128,
    peer_secret_ra: u128,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(super) enum Pairing {
    WaitingPairingRequest,
    WaitingPublicKey,
    // Numeric comparison
    WaitingNumericComparisonRandom(LescPhaseData),
    WaitingNumericComparisonResult {
        phase_data: LescPhaseData,
        ea: Option<[u8; size_of::<u128>()]>,
    },
    // Pass key entry
    WaitingPassKeyInput {
        phase_data: LescPhaseData,
        confirm_bytes: Option<[u8; size_of::<u128>()]>,
    },
    WaitingPassKeyEntryConfirm {
        phase_data: LescPhaseData,
        round: i32,
    },
    WaitingPassKeyEntryRandom {
        phase_data: LescPhaseData,
        round: i32,
    },
    // TODO add OOB
    WaitingDHKeyEa(LescPhaseData),
    WaitingLinkEncrypted,
    // TODO: WaitingIdentitity is actually a subset of `ReceivingKeys(i32)`,
    // they can be removed after implementing the full receiving keys procedure.
    WaitingIdentitityInformation,
    WaitingIdentitityAddressInformation,
    SendingKeys(i32),
    ReceivingKeys(i32),
    Success,
    Error(Error),
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
                | Self::SendingKeys(_)
                | Self::ReceivingKeys(_)
                | Self::Success
        )
    }

    pub(crate) fn initiate<P: PacketPool, OPS: PairingOps<P>>(
        pairing_data: &PairingData,
        ops: &mut OPS,
    ) -> Result<Self, Error> {
        let ret = Self::new();
        {
            let mut security_request = prepare_packet(Command::SecurityRequest)?;
            let payload = security_request.payload_mut();
            let mut auth_req = AuthReq::new(ops.bonding_flag());
            if pairing_data.local_features.io_capabilities != IoCapabilities::NoInputNoOutput {
                auth_req = auth_req.with_mitm();
            }
            payload[0] = auth_req.into();
            ops.try_send_packet(security_request)?;
        }
        Ok(ret)
    }

    pub fn handle_l2cap_command<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        &mut self,
        command: Command,
        payload: &[u8],
        pairing_data: &mut PairingData,
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        match self.handle_impl(CommandAndPayload { payload, command }, pairing_data, ops, rng) {
            Ok(()) => Ok(()),
            Err(error) => {
                error!("[smp] Failed to handle command {:?}, {:?}", command, error);
                *self = Self::Error(error.clone());
                Err(error)
            }
        }
    }

    pub fn handle_event<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        &mut self,
        event: Event,
        pairing_data: &mut PairingData,
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let current_state = core::mem::replace(self, Self::Error(Error::InvalidState));
        let next_step = (|| -> Result<Pairing, Error> {
            Ok(match (current_state, event) {
                x @ (Self::WaitingPairingRequest | Self::WaitingLinkEncrypted, Event::LinkEncryptedResult(res)) => {
                    if res {
                        info!("Link encrypted!");
                        if matches!(x.0, Self::WaitingLinkEncrypted) {
                            // TODO send key data
                        } else {
                            pairing_data.bond_information = ops.try_enable_bonded_encryption()?;
                        }

                        if pairing_data.peer_features.initiator_key_distribution.identity_key() {
                            // Remote will share identity key
                            Self::WaitingIdentitityInformation
                        } else {
                            Self::Success
                        }
                    } else {
                        error!("Failed to enable encryption!");
                        Self::Error(Error::Security(Reason::KeyRejected))
                    }
                }
                (
                    Self::WaitingNumericComparisonResult {
                        phase_data,
                        ea: Some(ea),
                    },
                    Event::PassKeyConfirm,
                ) => Self::handle_dhkey_ea(&ea, ops, pairing_data, &phase_data)?,
                (Self::WaitingNumericComparisonResult { phase_data, ea: None }, Event::PassKeyConfirm) => {
                    Self::WaitingDHKeyEa(phase_data)
                }
                (Self::WaitingNumericComparisonResult { .. }, Event::PassKeyCancel) => {
                    Self::Error(Error::Security(Reason::NumericComparisonFailed))
                }
                (
                    Self::WaitingPassKeyInput {
                        mut phase_data,
                        confirm_bytes,
                    },
                    Event::PassKeyInput(input),
                ) => {
                    phase_data.local_secret_rb = input as u128;
                    phase_data.peer_secret_ra = phase_data.local_secret_rb;
                    match confirm_bytes {
                        Some(payload) => {
                            Self::handle_pass_key_confirm(0, &payload, ops, pairing_data, phase_data, rng)?
                        }
                        None => Self::WaitingPassKeyEntryConfirm { phase_data, round: 0 },
                    }
                }
                (x, Event::PassKeyConfirm | Event::PassKeyCancel | Event::PassKeyInput(_)) => x,
                _ => Self::Error(Error::InvalidState),
            })
        })()
        .unwrap_or_else(Self::Error);

        match next_step {
            Self::Error(x) => {
                *self = Self::Error(x.clone());
                ops.try_send_connection_event(ConnectionEvent::PairingFailed(x.clone()))?;
                Err(x)
            }
            x => {
                let is_success = matches!(x, Self::Success);
                *self = x;
                if is_success {
                    if let Some(bond) = pairing_data.bond_information.as_ref() {
                        debug!("bond info: {:?}", bond);
                        let pairing_bond = if pairing_data.want_bonding() {
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

    fn handle_impl<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        &mut self,
        command: CommandAndPayload,
        pairing_data: &mut PairingData,
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let current_step = core::mem::replace(self, Self::Error(Error::InvalidState));
        let next_step = {
            trace!("Handling {:?}, step {:?}", command.command, current_step);
            match (current_step, command.command) {
                (Self::WaitingPairingRequest, Command::PairingRequest) => {
                    if ops.find_bond().is_some() {
                        ops.try_send_connection_event(ConnectionEvent::BondLost)?;
                    }
                    Self::handle_pairing_request(command.payload, ops, pairing_data)?;
                    Self::send_pairing_response(ops, pairing_data)?;
                    Self::WaitingPublicKey
                }
                (Self::WaitingPublicKey, Command::PairingPublicKey) => {
                    let peer_public_key = PublicKey::from_bytes(command.payload);
                    let secret_key = SecretKey::new(rng);
                    let local_public_key = secret_key.public_key();
                    let dh_key = secret_key
                        .dh_key(peer_public_key)
                        .ok_or(Error::Security(Reason::DHKeyCheckFailed))?;

                    Self::send_public_key(ops, &local_public_key)?;

                    let mut phase_data = LescPhaseData {
                        local_public_key_x: *local_public_key.x(),
                        peer_public_key_x: *peer_public_key.x(),
                        dh_key,
                        confirm: Confirm(0),
                        local_nonce: Nonce(0),
                        peer_nonce: Nonce(0),
                        local_secret_rb: 0,
                        peer_secret_ra: 0,
                    };

                    match pairing_data.pairing_method {
                        PairingMethod::OutOfBand => todo!("OOB not implemented"),
                        PairingMethod::PassKeyEntry { peripheral, .. } => {
                            if peripheral == PassKeyEntryAction::Display {
                                phase_data.local_secret_rb =
                                    rng.sample(rand::distributions::Uniform::new_inclusive(0, 999999));
                                phase_data.peer_secret_ra = phase_data.local_secret_rb;
                                ops.try_send_connection_event(ConnectionEvent::PassKeyDisplay(PassKey(
                                    phase_data.local_secret_rb as u32,
                                )))?;
                                Self::WaitingPassKeyEntryConfirm { phase_data, round: 0 }
                            } else {
                                ops.try_send_connection_event(ConnectionEvent::PassKeyInput)?;
                                Self::WaitingPassKeyInput {
                                    phase_data,
                                    confirm_bytes: None,
                                }
                            }
                        }
                        _ => {
                            // Numeric comparison / Just Works: send confirm
                            Self::send_numeric_compare_confirm(&mut phase_data, ops, rng)?;
                            Self::WaitingNumericComparisonRandom(phase_data)
                        }
                    }
                }
                (Self::WaitingNumericComparisonRandom(mut phase_data), Command::PairingRandom) => {
                    Self::handle_numeric_compare_random(command.payload, &mut phase_data)?;
                    Self::send_nonce(ops, &phase_data.local_nonce)?;
                    Self::numeric_compare_confirm(ops, pairing_data, phase_data)?
                }
                (Self::WaitingNumericComparisonResult { phase_data, ea: None }, Command::PairingDhKeyCheck) => {
                    let ea: [u8; size_of::<u128>()] = command.payload.try_into().map_err(|_| Error::InvalidValue)?;
                    Self::WaitingNumericComparisonResult {
                        phase_data,
                        ea: Some(ea),
                    }
                }

                (
                    Self::WaitingPassKeyInput {
                        phase_data,
                        confirm_bytes: _,
                    },
                    Command::PairingConfirm,
                ) => {
                    let confirm: [u8; size_of::<u128>()] =
                        command.payload.try_into().map_err(|_| Error::InvalidValue)?;
                    Self::WaitingPassKeyInput {
                        phase_data,
                        confirm_bytes: Some(confirm),
                    }
                }
                (Self::WaitingPassKeyEntryConfirm { phase_data, round }, Command::PairingConfirm) => {
                    Self::handle_pass_key_confirm(round, command.payload, ops, pairing_data, phase_data, rng)?
                }

                (Self::WaitingPassKeyEntryRandom { phase_data, round }, Command::PairingRandom) => {
                    Self::handle_pass_key_random(round, command.payload, ops, pairing_data, phase_data)?
                }

                (Self::WaitingDHKeyEa(phase_data), Command::PairingDhKeyCheck) => {
                    Self::handle_dhkey_ea(command.payload, ops, pairing_data, &phase_data)?
                }

                (x, Command::KeypressNotification) => x,

                (Self::WaitingIdentitityInformation, Command::IdentityInformation) => {
                    Self::handle_identity_information(command.payload, pairing_data)?
                }

                (Self::WaitingIdentitityAddressInformation, Command::IdentityAddressInformation) => {
                    Self::handle_identity_address_information(command.payload, pairing_data)?
                }

                _ => return Err(Error::InvalidState),
            }
        };

        match next_step {
            Self::Error(x) => {
                *self = Self::Error(x.clone());
                ops.try_send_connection_event(ConnectionEvent::PairingFailed(x.clone()))?;
                Err(x)
            }
            x => {
                let is_success = matches!(x, Self::Success);
                *self = x;
                if is_success {
                    debug!("Pairing::Success");
                    if let Some(bond) = pairing_data.bond_information.as_ref() {
                        debug!("bond info: {:?}", bond);
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

    fn handle_pairing_request<P: PacketPool, OPS: PairingOps<P>>(
        payload: &[u8],
        ops: &mut OPS,
        pairing_data: &mut PairingData,
    ) -> Result<(), Error> {
        let peer_features = PairingFeatures::decode(payload).map_err(|_| Error::Security(Reason::InvalidParameters))?;

        #[cfg(not(feature = "legacy-pairing"))]
        if !peer_features.security_properties.secure_connection() {
            return Err(Error::Security(Reason::AuthenticationRequirements));
        }

        if peer_features.maximum_encryption_key_size < crate::security_manager::constants::ENCRYPTION_KEY_SIZE_128_BITS
        {
            return Err(Error::Security(Reason::EncryptionKeySize));
        }

        if peer_features.initiator_key_distribution.identity_key() {
            pairing_data
                .local_features
                .initiator_key_distribution
                .set_identity_key();
        }

        pairing_data.peer_features = peer_features;
        let mut auth_req = AuthReq::new(ops.bonding_flag());
        if pairing_data.local_features.io_capabilities != IoCapabilities::NoInputNoOutput {
            auth_req = auth_req.with_mitm();
        }
        pairing_data.local_features.security_properties = auth_req;
        pairing_data.pairing_method = choose_pairing_method(pairing_data.peer_features, pairing_data.local_features);
        info!("[smp] Pairing method {:?}", pairing_data.pairing_method);
        Ok(())
    }

    fn send_pairing_response<P: PacketPool, OPS: PairingOps<P>>(
        ops: &mut OPS,
        pairing_data: &mut PairingData,
    ) -> Result<(), Error> {
        let mut packet = prepare_packet::<P>(Command::PairingResponse)?;

        let response = packet.payload_mut();
        pairing_data
            .local_features
            .encode(response)
            .map_err(|_| Error::InvalidValue)?;

        match ops.try_send_packet(packet) {
            Ok(_) => (),
            Err(error) => {
                error!("[smp] Failed to respond to request {:?}", error);
                return Err(error);
            }
        }

        Ok(())
    }

    fn handle_identity_information(payload: &[u8], pairing_data: &mut PairingData) -> Result<Pairing, Error> {
        let irk = IdentityResolvingKey::new(u128::from_le_bytes(
            payload.try_into().map_err(|_| Error::InvalidValue)?,
        ));
        if let Some(ref mut bond) = &mut pairing_data.bond_information {
            bond.identity.irk = Some(irk);
        }

        trace!("Identity information: IRK: {:?}", irk);
        Ok(Self::WaitingIdentitityAddressInformation)
    }

    fn handle_identity_address_information(payload: &[u8], pairing_data: &mut PairingData) -> Result<Pairing, Error> {
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
        pairing_data.peer_address = Address { kind, addr };

        if let Some(ref mut bond) = &mut pairing_data.bond_information {
            bond.identity.bd_addr = addr;
        }

        trace!(
            "Identity address information: addr_type: {:?}, addr: {:?}",
            addr_type,
            addr
        );
        Ok(Self::Success)
    }

    fn send_public_key<P: PacketPool, OPS: PairingOps<P>>(ops: &mut OPS, public_key: &PublicKey) -> Result<(), Error> {
        let packet = make_public_key_packet::<P>(public_key).map_err(|_| Error::Security(Reason::InvalidParameters))?;

        match ops.try_send_packet(packet) {
            Ok(_) => (),
            Err(error) => {
                error!("[smp] Failed to send public key {:?}", error);
                return Err(error);
            }
        }

        Ok(())
    }

    fn send_nonce<P: PacketPool, OPS: PairingOps<P>>(ops: &mut OPS, nonce: &Nonce) -> Result<(), Error> {
        let packet = make_pairing_random::<P>(nonce).map_err(|_| Error::Security(Reason::InvalidParameters))?;

        match ops.try_send_packet(packet) {
            Ok(_) => (),
            Err(error) => {
                error!("[smp] Failed to send pairing random {:?}", error);
                return Err(error);
            }
        }

        Ok(())
    }

    /// Send numeric comparison confirm (peripheral sends first in LESC).
    fn send_numeric_compare_confirm<P: PacketPool, OPS: PairingOps<P>, RNG: RngCore>(
        phase_data: &mut LescPhaseData,
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        phase_data.local_nonce = Nonce::new(rng);
        phase_data.confirm =
            phase_data
                .local_nonce
                .f4(&phase_data.local_public_key_x, &phase_data.peer_public_key_x, 0);
        let packet = make_confirm_packet(&phase_data.confirm)?;
        match ops.try_send_packet(packet) {
            Ok(_) => (),
            Err(error) => {
                error!("[smp] Failed to send confirm {:?}", error);
                return Err(error);
            }
        }
        Ok(())
    }

    fn handle_numeric_compare_random(payload: &[u8], phase_data: &mut LescPhaseData) -> Result<(), Error> {
        phase_data.peer_nonce = Nonce(u128::from_le_bytes(
            payload
                .try_into()
                .map_err(|_| Error::Security(Reason::InvalidParameters))?,
        ));

        Ok(())
    }

    #[inline]
    fn numeric_compare_confirm<P: PacketPool, OPS: PairingOps<P>>(
        ops: &mut OPS,
        pairing_data: &PairingData,
        phase_data: LescPhaseData,
    ) -> Result<Pairing, Error> {
        let vb = phase_data.peer_nonce.g2(
            &phase_data.peer_public_key_x,
            &phase_data.local_public_key_x,
            &phase_data.local_nonce,
        );

        if pairing_data.pairing_method == PairingMethod::JustWorks {
            info!("[smp] Just works pairing with compare {}", vb.0);
            Ok(Self::WaitingDHKeyEa(phase_data))
        } else {
            info!("[smp] Numeric comparison pairing with compare {}", vb.0);
            ops.try_send_connection_event(ConnectionEvent::PassKeyConfirm(PassKey(vb.0)))?;
            Ok(Self::WaitingNumericComparisonResult { phase_data, ea: None })
        }
    }

    fn handle_dhkey_ea<P: PacketPool, OPS: PairingOps<P>>(
        payload: &[u8],
        ops: &mut OPS,
        pairing_data: &mut PairingData,
        phase_data: &LescPhaseData,
    ) -> Result<Pairing, Error> {
        // Compute LTK and MAC key using f5
        let (mac_key, ltk) = phase_data.dh_key.f5(
            phase_data.peer_nonce,
            phase_data.local_nonce,
            pairing_data.peer_address,
            pairing_data.local_address,
        );

        // Verify Ea from central
        let expected_ea = mac_key
            .f6(
                phase_data.peer_nonce,
                phase_data.local_nonce,
                phase_data.local_secret_rb,
                pairing_data.peer_features.as_io_cap(),
                pairing_data.peer_address,
                pairing_data.local_address,
            )
            .0
            .to_le_bytes();

        if expected_ea != payload {
            return Err(Error::Security(Reason::DHKeyCheckFailed));
        }

        // Send Eb to central
        let eb = mac_key.f6(
            phase_data.local_nonce,
            phase_data.peer_nonce,
            phase_data.peer_secret_ra,
            pairing_data.local_features.as_io_cap(),
            pairing_data.local_address,
            pairing_data.peer_address,
        );
        let check = make_dhkey_check_packet(&eb)?;
        ops.try_send_packet(check)?;

        // Enable encryption
        let bond = ops.try_enable_encryption(
            &ltk,
            pairing_data.pairing_method.security_level(),
            pairing_data.want_bonding(),
            #[cfg(feature = "legacy-pairing")]
            0,
            #[cfg(feature = "legacy-pairing")]
            [0; 8],
        )?;
        pairing_data.bond_information = Some(bond);
        Ok(Self::WaitingLinkEncrypted)
    }

    #[inline]
    fn handle_pass_key_confirm<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        round: i32,
        payload: &[u8],
        ops: &mut OPS,
        _pairing_data: &mut PairingData,
        mut phase_data: LescPhaseData,
        rng: &mut RNG,
    ) -> Result<Pairing, Error> {
        phase_data.confirm = Confirm(u128::from_le_bytes(
            payload
                .try_into()
                .map_err(|_| Error::Security(Reason::InvalidParameters))?,
        ));
        phase_data.local_nonce = Nonce::new(rng);
        let z = 0x80 | ((phase_data.local_secret_rb & (1 << round)) >> round);
        let confirm_to_send =
            phase_data
                .local_nonce
                .f4(&phase_data.local_public_key_x, &phase_data.peer_public_key_x, z as u8);
        let packet = make_confirm_packet(&confirm_to_send)?;
        ops.try_send_packet(packet)?;
        Ok(Self::WaitingPassKeyEntryRandom { phase_data, round })
    }

    #[inline]
    fn handle_pass_key_random<P: PacketPool, OPS: PairingOps<P>>(
        round: i32,
        payload: &[u8],
        ops: &mut OPS,
        pairing_data: &mut PairingData,
        mut phase_data: LescPhaseData,
    ) -> Result<Pairing, Error> {
        phase_data.peer_nonce = Nonce(u128::from_le_bytes(
            payload
                .try_into()
                .map_err(|_| Error::Security(Reason::InvalidParameters))?,
        ));
        let round_u128 = round as u128;
        let z = 0x80 | ((phase_data.local_secret_rb & (1 << round_u128)) >> round_u128);
        let expected_confirm =
            phase_data
                .peer_nonce
                .f4(&phase_data.peer_public_key_x, &phase_data.local_public_key_x, z as u8);

        if phase_data.confirm != expected_confirm {
            error!(
                "Confirm and computed confirm mismatch: {:?} != {:?}",
                phase_data.confirm.0, expected_confirm.0
            );
            Err(Error::Security(Reason::ConfirmValueFailed))
        } else {
            let nonce_packet = make_pairing_random(&phase_data.local_nonce)?;
            ops.try_send_packet(nonce_packet)?;
            if round == 19 {
                Ok(Self::WaitingDHKeyEa(phase_data))
            } else {
                Ok(Self::WaitingPassKeyEntryConfirm {
                    phase_data,
                    round: round + 1,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bt_hci::param::{AddrKind, BdAddr};
    use rand_chacha::{ChaCha12Core, ChaCha12Rng};
    use rand_core::SeedableRng;

    use super::Pairing;
    use crate::prelude::{ConnectionEvent, SecurityLevel};
    use crate::security_manager::crypto::SecretKey;
    use crate::security_manager::pairing::tests::{HeaplessPool, TestOps};
    use crate::security_manager::pairing::util::make_public_key_packet;
    use crate::security_manager::pairing::{Event, PairingData};
    use crate::security_manager::types::{Command, PairingFeatures};
    use crate::{Address, IoCapabilities, LongTermKey};

    fn make_default_pairing_data(
        local_address: Address,
        peer_address: Address,
        local_io: IoCapabilities,
    ) -> PairingData {
        use embassy_time::Instant;

        use crate::security_manager::pairing::util::PairingMethod;

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
        let mut pairing_ops: TestOps<10> = TestOps::default();
        let mut pairing_data = make_default_pairing_data(
            Address::random([1, 2, 3, 4, 5, 6]),
            Address::random([7, 8, 9, 10, 11, 12]),
            IoCapabilities::NoInputNoOutput,
        );
        let mut pairing = Pairing::new();
        let mut rng: ChaCha12Rng = ChaCha12Core::seed_from_u64(1).into();
        // Central sends pairing request, expects pairing response from peripheral
        pairing
            .handle_l2cap_command::<HeaplessPool, _, _>(
                Command::PairingRequest,
                &[0x03, 0, 0x08, 16, 0, 0],
                &mut pairing_data,
                &mut pairing_ops,
                &mut rng,
            )
            .unwrap();
        {
            let sent_packets = &pairing_ops.sent_packets;
            assert_eq!(
                pairing_data.peer_features,
                PairingFeatures {
                    io_capabilities: IoCapabilities::NoInputNoOutput,
                    security_properties: 8.into(),
                    ..Default::default()
                }
            );
            assert_eq!(sent_packets.len(), 1);
            let pairing_response = &sent_packets[0];
            assert_eq!(pairing_response.command, Command::PairingResponse);
            assert_eq!(pairing_response.payload(), &[0x03, 0, 8, 16, 0, 0]);
            assert_eq!(
                pairing_data.local_features,
                PairingFeatures {
                    io_capabilities: IoCapabilities::NoInputNoOutput,
                    security_properties: 8.into(),
                    ..Default::default()
                }
            );
        }
        // Pairing method expected to be just works (numeric comparison)
        // Central sends public key, expects peripheral public key followed by peripheral confirm
        let secret_key = SecretKey::new(&mut rng);
        let packet = make_public_key_packet::<HeaplessPool>(&secret_key.public_key()).unwrap();
        pairing
            .handle_l2cap_command::<HeaplessPool, _, _>(
                Command::PairingPublicKey,
                packet.payload(),
                &mut pairing_data,
                &mut pairing_ops,
                &mut rng,
            )
            .unwrap();

        {
            let sent_packets = &pairing_ops.sent_packets;
            assert_eq!(sent_packets.len(), 3);

            // Verify public key was sent
            assert_eq!(sent_packets[1].command, Command::PairingPublicKey);
            // These magic values depends on the random number generator and the seed.
            assert_eq!(
                sent_packets[1].payload(),
                &[
                    83, 171, 46, 254, 4, 90, 134, 154, 166, 92, 149, 210, 40, 29, 13, 105, 204, 111, 93, 54, 48, 113,
                    67, 56, 159, 46, 229, 216, 65, 17, 185, 147, 105, 13, 253, 69, 206, 82, 83, 1, 1, 141, 124, 108,
                    221, 90, 7, 60, 250, 66, 190, 186, 121, 211, 140, 7, 80, 110, 58, 174, 243, 47, 255, 61
                ]
            );

            assert_eq!(sent_packets[2].command, Command::PairingConfirm);
            assert_eq!(
                sent_packets[2].payload(),
                &[27, 253, 56, 56, 116, 220, 121, 84, 160, 189, 222, 40, 163, 99, 44, 214]
            );
        }

        // Central sends Nonce, expects Nonce
        pairing
            .handle_l2cap_command::<HeaplessPool, _, _>(
                Command::PairingRandom,
                &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                &mut pairing_data,
                &mut pairing_ops,
                &mut rng,
            )
            .unwrap();

        {
            let sent_packets = &pairing_ops.sent_packets;
            assert_eq!(sent_packets.len(), 4);
            assert_eq!(sent_packets[3].command, Command::PairingRandom);
            assert_eq!(pairing_ops.encryptions.len(), 0);
        }
        pairing
            .handle_l2cap_command::<HeaplessPool, _, _>(
                Command::PairingDhKeyCheck,
                &[
                    0x70, 0xa9, 0xf1, 0xd0, 0xcf, 0x52, 0x84, 0xe9, 0xfc, 0x36, 0x9b, 0x84, 0x35, 0x13, 0xc5, 0xed,
                ],
                &mut pairing_data,
                &mut pairing_ops,
                &mut rng,
            )
            .unwrap();

        {
            let sent_packets = &pairing_ops.sent_packets;
            assert_eq!(sent_packets.len(), 5);
            assert_eq!(sent_packets[4].command, Command::PairingDhKeyCheck);
            assert_eq!(
                sent_packets[4].payload(),
                [161, 50, 135, 68, 154, 19, 105, 76, 55, 97, 207, 61, 193, 29, 234, 92]
            );
            assert_eq!(pairing_ops.encryptions.len(), 1);
            assert!(matches!(pairing_ops.encryptions[0], LongTermKey(_)));
        }
    }

    #[test]
    fn just_works_with_irk_distribution() {
        let mut pairing_ops: TestOps<10> = TestOps {
            bondable: true,
            ..Default::default()
        };
        let mut pairing_data = make_default_pairing_data(
            Address::random([1, 2, 3, 4, 5, 6]),
            Address::random([7, 8, 9, 10, 11, 12]),
            IoCapabilities::NoInputNoOutput,
        );
        let mut pairing = Pairing::new();
        let mut rng: ChaCha12Rng = ChaCha12Core::seed_from_u64(1).into();

        // Central sends pairing request with identity_key bit set, expects pairing response from peripheral
        let pairing_request = [
            0x03, // IO Capabilities
            0x00, // OOB data flag
            0x09, // Auth Req(Secure Connection + Bonding)
            16,   // Maximum Encryption Key Size
            0x02, // Initiator Key Distribution(identity_key = true)
            0x00, // Responder Key Distribution
        ];

        pairing
            .handle_l2cap_command::<HeaplessPool, _, _>(
                Command::PairingRequest,
                &pairing_request,
                &mut pairing_data,
                &mut pairing_ops,
                &mut rng,
            )
            .unwrap();

        {
            let sent_packets = &pairing_ops.sent_packets;

            assert!(pairing_data.local_features.initiator_key_distribution.identity_key());
            assert!(pairing_data.peer_features.initiator_key_distribution.identity_key());

            assert_eq!(sent_packets.len(), 1);
            assert_eq!(sent_packets[0].command, Command::PairingResponse);
            let response_payload = sent_packets[0].payload();
            // Check AuthReq and identity key bit in response
            assert_eq!(response_payload[2] & 0x09, 0x09);
            assert_eq!(response_payload[4] & 0x02, 0x02);
        }

        // Central sends public key, expects peripheral public key followed by peripheral confirm
        let secret_key = SecretKey::new(&mut rng);
        let packet = make_public_key_packet::<HeaplessPool>(&secret_key.public_key()).unwrap();
        pairing
            .handle_l2cap_command::<HeaplessPool, _, _>(
                Command::PairingPublicKey,
                packet.payload(),
                &mut pairing_data,
                &mut pairing_ops,
                &mut rng,
            )
            .unwrap();

        // Central sends Nonce, expects Nonce
        pairing
            .handle_l2cap_command::<HeaplessPool, _, _>(
                Command::PairingRandom,
                &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                &mut pairing_data,
                &mut pairing_ops,
                &mut rng,
            )
            .unwrap();

        // Central sends DHKey Check, expects encrypted link
        pairing
            .handle_l2cap_command::<HeaplessPool, _, _>(
                Command::PairingDhKeyCheck,
                &[
                    0x06, 0x32, 0x9c, 0x2c, 0x99, 0xc2, 0xb1, 0x62, 0x6a, 0x02, 0x0e, 0x56, 0x46, 0xf6, 0x0e, 0x97,
                ],
                &mut pairing_data,
                &mut pairing_ops,
                &mut rng,
            )
            .unwrap();

        pairing
            .handle_event(
                Event::LinkEncryptedResult(true),
                &mut pairing_data,
                &mut pairing_ops,
                &mut rng,
            )
            .unwrap();

        // Waiting identity information check
        assert!(pairing.is_encrypted());

        // Central sends identity information(IRK)
        let irk_data: [u8; 16] = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        ];
        pairing
            .handle_l2cap_command::<HeaplessPool, _, _>(
                Command::IdentityInformation,
                &irk_data,
                &mut pairing_data,
                &mut pairing_ops,
                &mut rng,
            )
            .unwrap();

        // Central sends identity address information
        let addr_data: [u8; 7] = [
            0x00, // Public address type
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, // Address
        ];
        pairing
            .handle_l2cap_command::<HeaplessPool, _, _>(
                Command::IdentityAddressInformation,
                &addr_data,
                &mut pairing_data,
                &mut pairing_ops,
                &mut rng,
            )
            .unwrap();

        // The step should be `Success` after `IdentityAddressInformation` command
        assert!(pairing.result().is_some());

        // Verify identity and address
        {
            let bond = pairing_data.bond_information.as_ref().unwrap();

            assert!(bond.identity.irk.is_some());
            let stored_irk = bond.identity.irk.unwrap();
            assert_eq!(stored_irk.0, u128::from_le_bytes(irk_data));

            assert_eq!(bond.identity.bd_addr, BdAddr::new([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]));
            assert_eq!(pairing_data.peer_address.kind, AddrKind::PUBLIC);
            assert_eq!(
                pairing_data.peer_address.addr,
                BdAddr::new([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC])
            );
        }

        // Verify completeness
        assert_eq!(pairing_ops.connection_events.len(), 1);
        match &pairing_ops.connection_events[0] {
            ConnectionEvent::PairingComplete { security_level, bond } => {
                assert_eq!(*security_level, SecurityLevel::Encrypted);
                assert!(bond.is_some());
                let bond_info = bond.as_ref().unwrap();
                assert!(bond_info.identity.irk.is_some());
                assert_eq!(bond_info.identity.irk.unwrap().0, u128::from_le_bytes(irk_data));
            }
            _ => panic!("Unexpected connection event"),
        }
    }
}

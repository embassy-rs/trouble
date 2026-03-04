use embassy_time::Instant;
use rand::Rng;
use rand_core::{CryptoRng, RngCore};

use crate::codec::{Decode, Encode};
use crate::connection::{ConnectionEvent, SecurityLevel};
use crate::security_manager::crypto::{Confirm, DHKey, MacKey, Nonce, PublicKey, PublicKeyX, SecretKey};
use crate::security_manager::pairing::util::{
    choose_pairing_method, make_confirm_packet, make_dhkey_check_packet, make_pairing_random, make_public_key_packet,
    prepare_packet, CommandAndPayload, PairingMethod, PassKeyEntryAction,
};
use crate::security_manager::pairing::{Event, PairingData, PairingOps};
use crate::security_manager::types::{AuthReq, BondingFlag, Command, PairingFeatures};
use crate::security_manager::{PassKey, Reason};
use crate::{Address, Error, IoCapabilities, LongTermKey, PacketPool};

/// EC key and comparison phase data carried through LESC step variants.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct LescPhaseData {
    local_public_key_x: PublicKeyX,
    peer_public_key_x: PublicKeyX,
    dh_key: DHKey,
    confirm: Confirm,
    local_nonce: Nonce,
    peer_nonce: Nonce,
    local_secret_ra: u128,
    peer_secret_rb: u128,
}

/// Data carried through the DH key check phase.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct DhKeyCheckData {
    mac_key: MacKey,
    ltk: LongTermKey,
    local_nonce: Nonce,
    peer_nonce: Nonce,
    local_secret_ra: u128,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum Step {
    Idle,
    WaitingPairingResponse,
    WaitingPublicKey {
        private_key: SecretKey,
        local_public_key: PublicKey,
    },
    // Numeric comparison
    WaitingNumericComparisonConfirm(LescPhaseData),
    WaitingNumericComparisonRandom(LescPhaseData),
    WaitingNumericComparisonResult(LescPhaseData),
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
    WaitingDHKeyEb(DhKeyCheckData),
    WaitingLinkEncrypted,
    WaitingBondedLinkEncryption,
    ReceivingKeys(i32),
    SendingKeys(i32),
    Success,
    Error(Error),
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Pairing {
    current_step: Step,
    pairing_data: PairingData,
    user_initiated: bool,
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
        if matches!(&self.current_step, Step::Idle | Step::Success | Step::Error(_)) {
            return;
        }
        self.current_step = Step::Error(Error::Timeout);
    }

    pub(crate) fn new_idle(local_address: Address, peer_address: Address, local_io: IoCapabilities) -> Pairing {
        let pairing_data = PairingData {
            pairing_method: PairingMethod::JustWorks,
            local_address,
            peer_address,
            peer_features: PairingFeatures::default(),
            local_features: PairingFeatures {
                io_capabilities: local_io,
                ..Default::default()
            },
            timeout_at: Instant::now() + crate::security_manager::constants::TIMEOUT_DISABLE,
            bond_information: None,
        };
        Self {
            pairing_data,
            current_step: Step::Idle,
            user_initiated: false,
        }
    }

    fn send_pairing_request<P: PacketPool, OPS: PairingOps<P>>(
        pairing_data: &PairingData,
        ops: &mut OPS,
    ) -> Result<(), Error> {
        let mut packet = prepare_packet::<P>(Command::PairingRequest)?;
        pairing_data
            .local_features
            .encode(packet.payload_mut())
            .map_err(|_| Error::InvalidValue)?;
        ops.try_send_packet(packet)?;
        Ok(())
    }

    pub(crate) fn initiate<P: PacketPool, OPS: PairingOps<P>>(
        local_address: Address,
        peer_address: Address,
        ops: &mut OPS,
        local_io: IoCapabilities,
        user_initiated: bool,
    ) -> Result<Pairing, Error> {
        let mut ret = Self::new_idle(local_address, peer_address, local_io);
        ret.user_initiated = user_initiated;
        {
            let mut auth_req = AuthReq::new(ops.bonding_flag());
            if local_io != IoCapabilities::NoInputNoOutput {
                auth_req = auth_req.with_mitm();
            }
            ret.pairing_data.local_features.security_properties = auth_req;
            if matches!(ops.bonding_flag(), BondingFlag::Bonding) {
                ret.pairing_data
                    .local_features
                    .initiator_key_distribution
                    .set_encryption_key();
                ret.pairing_data
                    .local_features
                    .responder_key_distribution
                    .set_encryption_key();
            }
            ret.current_step = if let Some(bond) = ops.try_enable_bonded_encryption()? {
                ret.pairing_data.bond_information = Some(bond);
                Step::WaitingBondedLinkEncryption
            } else {
                Self::send_pairing_request(&ret.pairing_data, ops)?;
                Step::WaitingPairingResponse
            };
        }
        ret.reset_timeout();
        Ok(ret)
    }

    pub fn peer_address(&self) -> Address {
        self.pairing_data.peer_address
    }

    pub(crate) fn is_waiting_bonded_encryption(&self) -> bool {
        matches!(self.current_step, Step::WaitingBondedLinkEncryption)
    }

    #[cfg(feature = "legacy-pairing")]
    pub(crate) fn into_legacy(self) -> super::legacy_central::Pairing {
        let PairingData {
            local_address,
            local_features,
            peer_address,
            ..
        } = self.pairing_data;

        let mut preq = [0u8; 7];
        preq[0] = u8::from(Command::PairingRequest);
        local_features.encode(&mut preq[1..]).unwrap();

        super::legacy_central::Pairing::from_lesc_switch(local_address, peer_address, local_features, preq)
    }

    pub fn security_level(&self) -> SecurityLevel {
        match &self.current_step {
            Step::SendingKeys(_) | Step::ReceivingKeys(_) | Step::Success => self
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
                error!("[smp] Failed to handle command {:?}, {:?}", command, error);
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
        let mut bond_lost = false;
        let next_state = (|| -> Result<Step, Error> {
            Ok(match (current_state, event) {
                (Step::WaitingLinkEncrypted, Event::LinkEncryptedResult(res)) => {
                    if res {
                        info!("Link encrypted!");
                        // TODO wait for keys
                        Step::Success
                    } else {
                        error!("Link encryption failed!");
                        Step::Error(Error::Security(Reason::KeyRejected))
                    }
                }
                (Step::WaitingBondedLinkEncryption, Event::LinkEncryptedResult(res)) => {
                    if res {
                        info!("Link encrypted using bonded key!");
                        Step::Success
                    } else if self.user_initiated {
                        warn!("Link encryption with bonded key failed, initiating fresh pairing");
                        ops.try_send_connection_event(ConnectionEvent::BondLost)?;
                        Self::send_pairing_request(&self.pairing_data, ops)?;
                        Step::WaitingPairingResponse
                    } else {
                        error!("Link encryption with bonded key failed!");
                        bond_lost = true;
                        Step::Error(Error::Security(Reason::KeyRejected))
                    }
                }
                (Step::WaitingNumericComparisonResult(phase_data), Event::PassKeyConfirm) => {
                    Self::send_dhkey_ea_and_transition(ops, &self.pairing_data, &phase_data)?
                }
                (Step::WaitingNumericComparisonResult(_), Event::PassKeyCancel) => {
                    Step::Error(Error::Security(Reason::NumericComparisonFailed))
                }
                (
                    Step::WaitingPassKeyInput {
                        mut phase_data,
                        confirm_bytes,
                    },
                    Event::PassKeyInput(input),
                ) => {
                    phase_data.local_secret_ra = input as u128;
                    phase_data.peer_secret_rb = phase_data.local_secret_ra;
                    Self::send_pass_key_confirm(0, &mut phase_data, ops, rng)?;
                    match confirm_bytes {
                        Some(payload) => {
                            Self::store_pass_key_confirm(&payload, &mut phase_data)?;
                            Self::send_nonce(ops, &phase_data.local_nonce)?;
                            Step::WaitingPassKeyEntryRandom { phase_data, round: 0 }
                        }
                        None => Step::WaitingPassKeyEntryConfirm { phase_data, round: 0 },
                    }
                }
                (x, Event::PassKeyConfirm | Event::PassKeyCancel) => x,
                _ => Step::Error(Error::InvalidState),
            })
        })()
        .unwrap_or_else(Step::Error);

        match next_state {
            Step::Error(x) => {
                self.current_step = Step::Error(x.clone());
                let event = if bond_lost {
                    ConnectionEvent::BondLost
                } else {
                    ConnectionEvent::PairingFailed(x.clone())
                };
                ops.try_send_connection_event(event)?;
                Err(x)
            }
            x => {
                let is_success = matches!(x, Step::Success);
                self.current_step = x;
                if is_success {
                    if let Some(bond) = self.pairing_data.bond_information.as_ref() {
                        let pairing_bond = if self.pairing_data.want_bonding() {
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
                        error!("[smp] No bond information stored");
                    }
                }
                Ok(())
            }
        }
    }

    fn handle_impl<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        &mut self,
        command: CommandAndPayload,
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let current_step = core::mem::replace(&mut self.current_step, Step::Error(Error::InvalidState));
        let pairing_data = &mut self.pairing_data;
        let next_step = {
            trace!("Handling {:?}, step {:?}", command.command, current_step);
            match (current_step, command.command) {
                (Step::Idle, Command::SecurityRequest) => {
                    // Parse the peer's AuthReq from the SecurityRequest payload
                    let peer_auth_req = AuthReq::from(command.payload[0]);
                    let peer_requests_mitm = peer_auth_req.man_in_the_middle();

                    let mut auth_req = AuthReq::new(ops.bonding_flag());
                    if pairing_data.local_features.io_capabilities != IoCapabilities::NoInputNoOutput {
                        auth_req = auth_req.with_mitm();
                    }
                    pairing_data.local_features.security_properties = auth_req;

                    // Per Core Spec Vol 3, Part H, Section 3.6.7: if the existing bond
                    // meets the peer's security requirements, re-encrypt with it;
                    // otherwise initiate new pairing.
                    let bond = ops.find_bond();
                    let bond_sufficient = bond.as_ref().is_some_and(|b| {
                        !peer_requests_mitm || b.security_level == SecurityLevel::EncryptedAuthenticated
                    });
                    if bond_sufficient {
                        let bond = ops.try_enable_bonded_encryption()?.unwrap();
                        pairing_data.bond_information = Some(bond);
                        Step::WaitingBondedLinkEncryption
                    } else {
                        Self::send_pairing_request(pairing_data, ops)?;
                        Step::WaitingPairingResponse
                    }
                }
                (Step::WaitingPairingResponse, Command::SecurityRequest) => {
                    // SM test spec SM/CEN/PIS/BV-03-C, security requests while waiting for pairing response shall be ignored
                    Step::WaitingPairingResponse
                }
                (Step::WaitingPairingResponse, Command::PairingResponse) => {
                    Self::handle_pairing_response(command.payload, ops, pairing_data)?;
                    let secret_key = SecretKey::new(rng);
                    let public_key = secret_key.public_key();
                    Self::send_public_key(ops, &public_key)?;
                    Step::WaitingPublicKey {
                        private_key: secret_key,
                        local_public_key: public_key,
                    }
                }
                (
                    Step::WaitingPublicKey {
                        private_key,
                        local_public_key,
                    },
                    Command::PairingPublicKey,
                ) => {
                    let peer_public_key = PublicKey::from_bytes(command.payload);
                    let dh_key = private_key
                        .dh_key(peer_public_key)
                        .ok_or(Error::Security(Reason::DHKeyCheckFailed))?;

                    let mut phase_data = LescPhaseData {
                        local_public_key_x: *local_public_key.x(),
                        peer_public_key_x: *peer_public_key.x(),
                        dh_key,
                        confirm: Confirm(0),
                        local_nonce: Nonce(0),
                        peer_nonce: Nonce(0),
                        local_secret_ra: 0,
                        peer_secret_rb: 0,
                    };

                    match pairing_data.pairing_method {
                        PairingMethod::OutOfBand => todo!("OOB not implemented"),
                        PairingMethod::PassKeyEntry { central, .. } => {
                            if central == PassKeyEntryAction::Display {
                                phase_data.local_secret_ra =
                                    rng.sample(rand::distributions::Uniform::new_inclusive(0, 999999));
                                phase_data.peer_secret_rb = phase_data.local_secret_ra;
                                ops.try_send_connection_event(ConnectionEvent::PassKeyDisplay(PassKey(
                                    phase_data.local_secret_ra as u32,
                                )))?;
                                Self::send_pass_key_confirm(0, &mut phase_data, ops, rng)?;
                                Step::WaitingPassKeyEntryConfirm { phase_data, round: 0 }
                            } else {
                                ops.try_send_connection_event(ConnectionEvent::PassKeyInput)?;
                                Step::WaitingPassKeyInput {
                                    phase_data,
                                    confirm_bytes: None,
                                }
                            }
                        }
                        _ => Step::WaitingNumericComparisonConfirm(phase_data),
                    }
                }
                (Step::WaitingNumericComparisonConfirm(mut phase_data), Command::PairingConfirm) => {
                    Self::handle_numeric_compare_confirm(command.payload, &mut phase_data, rng)?;
                    Self::send_nonce(ops, &phase_data.local_nonce)?;
                    Step::WaitingNumericComparisonRandom(phase_data)
                }
                (Step::WaitingNumericComparisonRandom(phase_data), Command::PairingRandom) => {
                    Self::handle_numeric_compare_random(command.payload, phase_data, pairing_data, ops)?
                }
                (
                    Step::WaitingPassKeyInput {
                        phase_data,
                        confirm_bytes: _,
                    },
                    Command::PairingConfirm,
                ) => {
                    let confirm_bytes: [u8; size_of::<u128>()] =
                        command.payload.try_into().map_err(|_| Error::InvalidValue)?;
                    Step::WaitingPassKeyInput {
                        phase_data,
                        confirm_bytes: Some(confirm_bytes),
                    }
                }
                (Step::WaitingPassKeyEntryConfirm { mut phase_data, round }, Command::PairingConfirm) => {
                    Self::store_pass_key_confirm(command.payload, &mut phase_data)?;
                    Self::send_nonce(ops, &phase_data.local_nonce)?;
                    Step::WaitingPassKeyEntryRandom { phase_data, round }
                }
                (Step::WaitingPassKeyEntryRandom { mut phase_data, round }, Command::PairingRandom) => {
                    Self::handle_pass_key_random(round, command.payload, ops, &mut phase_data)?;
                    if round == 19 {
                        Self::send_dhkey_ea_and_transition(ops, pairing_data, &phase_data)?
                    } else {
                        Self::send_pass_key_confirm(round + 1, &mut phase_data, ops, rng)?;
                        Step::WaitingPassKeyEntryConfirm {
                            phase_data,
                            round: round + 1,
                        }
                    }
                }
                (Step::WaitingDHKeyEb(check_data), Command::PairingDhKeyCheck) => {
                    Self::handle_dhkey_eb(command.payload, ops, pairing_data, &check_data)?;
                    Step::WaitingLinkEncrypted
                }
                (x, Command::KeypressNotification) => x,

                _ => return Err(Error::InvalidState),
            }
        };

        self.current_step = next_step;

        Ok(())
    }

    fn handle_pairing_response<P: PacketPool, OPS: PairingOps<P>>(
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

        pairing_data.peer_features = peer_features;
        pairing_data.pairing_method = choose_pairing_method(pairing_data.local_features, pairing_data.peer_features);
        info!("[smp] Pairing method {:?}", pairing_data.pairing_method);

        Ok(())
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

    fn handle_numeric_compare_confirm<RNG: CryptoRng + RngCore>(
        payload: &[u8],
        phase_data: &mut LescPhaseData,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        phase_data.confirm = Confirm(u128::from_le_bytes(
            payload.try_into().map_err(|_| Error::InvalidValue)?,
        ));
        phase_data.local_nonce = Nonce::new(rng);
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

    #[inline]
    fn handle_numeric_compare_random<P: PacketPool, OPS: PairingOps<P>>(
        payload: &[u8],
        mut phase_data: LescPhaseData,
        pairing_data: &PairingData,
        ops: &mut OPS,
    ) -> Result<Step, Error> {
        let peer_nonce = Nonce(u128::from_le_bytes(
            payload.try_into().map_err(|_| Error::InvalidValue)?,
        ));
        let expected_cb = peer_nonce.f4(&phase_data.peer_public_key_x, &phase_data.local_public_key_x, 0);
        if phase_data.confirm != expected_cb {
            return Err(Error::Security(Reason::NumericComparisonFailed));
        }
        phase_data.peer_nonce = peer_nonce;
        let va = phase_data.local_nonce.g2(
            &phase_data.local_public_key_x,
            &phase_data.peer_public_key_x,
            &phase_data.peer_nonce,
        );

        if pairing_data.pairing_method == PairingMethod::JustWorks {
            info!("[smp] Just works pairing with compare {}", va.0);
            Self::send_dhkey_ea_and_transition(ops, pairing_data, &phase_data)
        } else {
            info!("[smp] Numeric comparison pairing with compare {}", va.0);
            ops.try_send_connection_event(ConnectionEvent::PassKeyConfirm(PassKey(va.0)))?;
            Ok(Step::WaitingNumericComparisonResult(phase_data))
        }
    }

    /// Compute f5/f6, send DHKey check Ea, and transition to WaitingDHKeyEb.
    fn send_dhkey_ea_and_transition<P: PacketPool, OPS: PairingOps<P>>(
        ops: &mut OPS,
        pairing_data: &PairingData,
        phase_data: &LescPhaseData,
    ) -> Result<Step, Error> {
        let (mac_key, ltk) = phase_data.dh_key.f5(
            phase_data.local_nonce,
            phase_data.peer_nonce,
            pairing_data.local_address,
            pairing_data.peer_address,
        );

        let ea = mac_key.f6(
            phase_data.local_nonce,
            phase_data.peer_nonce,
            phase_data.peer_secret_rb,
            pairing_data.local_features.as_io_cap(),
            pairing_data.local_address,
            pairing_data.peer_address,
        );

        let check = make_dhkey_check_packet(&ea)?;
        ops.try_send_packet(check)?;

        Ok(Step::WaitingDHKeyEb(DhKeyCheckData {
            mac_key,
            ltk,
            local_nonce: phase_data.local_nonce,
            peer_nonce: phase_data.peer_nonce,
            local_secret_ra: phase_data.local_secret_ra,
        }))
    }

    fn handle_dhkey_eb<P: PacketPool, OPS: PairingOps<P>>(
        payload: &[u8],
        ops: &mut OPS,
        pairing_data: &mut PairingData,
        check_data: &DhKeyCheckData,
    ) -> Result<(), Error> {
        let expected_eb = check_data
            .mac_key
            .f6(
                check_data.peer_nonce,
                check_data.local_nonce,
                check_data.local_secret_ra,
                pairing_data.peer_features.as_io_cap(),
                pairing_data.peer_address,
                pairing_data.local_address,
            )
            .0
            .to_le_bytes();
        if payload != expected_eb {
            return Err(Error::Security(Reason::DHKeyCheckFailed));
        }

        let bond = ops.try_enable_encryption(
            &check_data.ltk,
            pairing_data.pairing_method.security_level(),
            pairing_data.want_bonding(),
            #[cfg(feature = "legacy-pairing")]
            0,
            #[cfg(feature = "legacy-pairing")]
            [0; 8],
        )?;
        pairing_data.bond_information = Some(bond);
        Ok(())
    }

    /// Send a passkey entry confirm for the given round.
    fn send_pass_key_confirm<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        round: i32,
        phase_data: &mut LescPhaseData,
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        phase_data.local_nonce = Nonce::new(rng);
        let rai = 0x80u8 | (((phase_data.local_secret_ra & (1 << round as u128)) >> (round as u128)) as u8);
        let cai = phase_data
            .local_nonce
            .f4(&phase_data.local_public_key_x, &phase_data.peer_public_key_x, rai);
        let confirm = make_confirm_packet(&cai)?;
        ops.try_send_packet(confirm)?;
        Ok(())
    }

    fn store_pass_key_confirm(payload: &[u8], phase_data: &mut LescPhaseData) -> Result<(), Error> {
        phase_data.confirm = Confirm(u128::from_le_bytes(
            payload.try_into().map_err(|_| Error::InvalidValue)?,
        ));
        Ok(())
    }

    fn handle_pass_key_random<P: PacketPool, OPS: PairingOps<P>>(
        round: i32,
        payload: &[u8],
        ops: &mut OPS,
        phase_data: &mut LescPhaseData,
    ) -> Result<(), Error> {
        let peer_nonce = Nonce(u128::from_le_bytes(
            payload.try_into().map_err(|_| Error::InvalidValue)?,
        ));
        let rai = 0x80u8 | (((phase_data.local_secret_ra & (1 << round as u128)) >> (round as u128)) as u8);
        let cbi = peer_nonce.f4(&phase_data.peer_public_key_x, &phase_data.local_public_key_x, rai);
        if cbi != phase_data.confirm {
            return Err(Error::Security(Reason::ConfirmValueFailed));
        }
        phase_data.peer_nonce = peer_nonce;
        Ok(())
    }
}

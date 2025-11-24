use core::cell::RefCell;
use core::ops::{Deref, DerefMut};

use embassy_time::Instant;
use rand::Rng;
use rand_core::{CryptoRng, RngCore};

use crate::codec::{Decode, Encode};
use crate::connection::{ConnectionEvent, SecurityLevel};
use crate::security_manager::constants::ENCRYPTION_KEY_SIZE_128_BITS;
use crate::security_manager::crypto::{Confirm, DHKey, MacKey, Nonce, PublicKey, SecretKey};
use crate::security_manager::pairing::util::{
    choose_pairing_method, make_confirm_packet, make_dhkey_check_packet, make_pairing_random, make_public_key_packet,
    prepare_packet, CommandAndPayload, PairingMethod, PassKeyEntryAction,
};
use crate::security_manager::pairing::{Event, PairingOps};
use crate::security_manager::types::{AuthReq, BondingFlag, Command, PairingFeatures};
use crate::security_manager::{PassKey, Reason};
use crate::{Address, BondInformation, Error, IoCapabilities, LongTermKey, PacketPool};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum Step {
    Idle,
    WaitingPairingResponse(PairingRequestSentTag),
    WaitingPublicKey,
    // Numeric comparison
    WaitingNumericComparisonConfirm,
    WaitingNumericComparisonRandom,
    WaitingNumericComparisonResult,
    // Pass key entry
    WaitingPassKeyInput,
    WaitingPassKeyEntryConfirm(PassKeyEntryConfirmSentTag),
    WaitingPassKeyEntryRandom(i32),
    // TODO add OOB
    WaitingDHKeyEb(DHKeyEaSentTag),
    WaitingLinkEncrypted,
    WaitingBondedLinkEncryption,
    ReceivingKeys(i32),
    SendingKeys(i32),
    Success,
    Error(Error),
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct PairingRequestSentTag {}

impl PairingRequestSentTag {
    fn new<P: PacketPool, OPS: PairingOps<P>>(pairing_data: &mut PairingData, ops: &mut OPS) -> Result<Self, Error> {
        let mut packet = prepare_packet::<P>(Command::PairingRequest)?;

        let payload = packet.payload_mut();
        pairing_data
            .local_features
            .encode(payload)
            .map_err(|_| Error::InvalidValue)?;

        match ops.try_send_packet(packet) {
            Ok(_) => {}
            Err(error) => {
                error!("[smp] Failed to respond to request {:?}", error);
                return Err(error);
            }
        }

        Ok(Self {})
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct PassKeyEntryConfirmSentTag(i32);

impl PassKeyEntryConfirmSentTag {
    fn new<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        round: i32,
        pairing_data: &mut PairingData,
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<PassKeyEntryConfirmSentTag, Error> {
        pairing_data.local_nonce = Nonce::new(rng);
        let rai = 0x80u8 | (((pairing_data.local_secret_ra & (1 << round as u128)) >> (round as u128)) as u8);
        let cai = pairing_data.local_nonce.f4(
            pairing_data.local_public_key.as_ref().ok_or(Error::InvalidValue)?.x(),
            pairing_data.peer_public_key.as_ref().ok_or(Error::InvalidValue)?.x(),
            rai,
        );
        let confirm = make_confirm_packet(&cai)?;
        ops.try_send_packet(confirm)?;
        Ok(PassKeyEntryConfirmSentTag(round))
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct DHKeyEaSentTag {}

impl DHKeyEaSentTag {
    fn new<P: PacketPool, OPS: PairingOps<P>>(
        pairing_data: &mut PairingData,
        ops: &mut OPS,
    ) -> Result<DHKeyEaSentTag, Error> {
        let (mac, ltk) = {
            let dh_key = pairing_data.dh_key.as_ref().ok_or(Error::InvalidValue)?;
            dh_key.f5(
                pairing_data.local_nonce,
                pairing_data.peer_nonce,
                pairing_data.local_address,
                pairing_data.peer_address,
            )
        };

        let ea = mac.f6(
            pairing_data.local_nonce,
            pairing_data.peer_nonce,
            pairing_data.peer_secret_rb,
            pairing_data.local_features.as_io_cap(),
            pairing_data.local_address,
            pairing_data.peer_address,
        );

        let check = make_dhkey_check_packet(&ea)?;
        ops.try_send_packet(check)?;
        pairing_data.mac_key = Some(mac);
        pairing_data.ltk = Some(ltk);
        Ok(DHKeyEaSentTag {})
    }
}

struct PairingData {
    local_address: Address,
    peer_address: Address,
    local_features: PairingFeatures,
    peer_features: PairingFeatures,
    pairing_method: PairingMethod,
    local_public_key: Option<PublicKey>,
    private_key: Option<SecretKey>,
    peer_public_key: Option<PublicKey>,
    dh_key: Option<DHKey>,
    local_secret_ra: u128,
    peer_secret_rb: u128,
    confirm: Confirm,
    local_nonce: Nonce,
    peer_nonce: Nonce,
    mac_key: Option<MacKey>,
    ltk: Option<LongTermKey>,
    timeout_at: Instant,
    bond_information: Option<BondInformation>,
}

impl PairingData {
    fn want_bonding(&self) -> bool {
        matches!(self.local_features.security_properties.bond(), BondingFlag::Bonding)
            && matches!(self.peer_features.security_properties.bond(), BondingFlag::Bonding)
    }
}

pub struct Pairing {
    current_step: RefCell<Step>,
    pairing_data: RefCell<PairingData>,
}

impl Pairing {
    pub fn timeout_at(&self) -> Instant {
        let step = self.current_step.borrow();
        if matches!(step.deref(), Step::Success | Step::Error(_)) {
            Instant::MAX // timeout disabled
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
        if matches!(current_step.deref(), Step::Idle | Step::Success | Step::Error(_)) {
            return;
        }
        *current_step = Step::Error(Error::Timeout);
    }

    pub(crate) fn new_idle(local_address: Address, peer_address: Address, local_io: IoCapabilities) -> Pairing {
        let pairing_data = PairingData {
            pairing_method: PairingMethod::JustWorks,
            local_address,
            peer_address,
            peer_public_key: None,
            local_public_key: None,
            local_secret_ra: 0,
            peer_secret_rb: 0,
            peer_features: PairingFeatures::default(),
            mac_key: None,
            local_features: PairingFeatures {
                io_capabilities: local_io,
                ..Default::default()
            },
            peer_nonce: Nonce(0),
            local_nonce: Nonce(0),
            dh_key: None,
            confirm: Confirm(0),
            ltk: None,
            private_key: None,
            timeout_at: Instant::MAX,
            bond_information: None,
        };
        Self {
            pairing_data: RefCell::new(pairing_data),
            current_step: RefCell::new(Step::Idle),
        }
    }

    pub(crate) fn initiate<P: PacketPool, OPS: PairingOps<P>>(
        local_address: Address,
        peer_address: Address,
        ops: &mut OPS,
        local_io: IoCapabilities,
    ) -> Result<Pairing, Error> {
        let ret = Self::new_idle(local_address, peer_address, local_io);
        {
            let mut pairing_data = ret.pairing_data.borrow_mut();
            pairing_data.local_features.security_properties = AuthReq::new(ops.bonding_flag());
            let next_step = if let Some(bond) = ops.try_enable_bonded_encryption()? {
                pairing_data.bond_information = Some(bond);
                Step::WaitingBondedLinkEncryption
            } else {
                Step::WaitingPairingResponse(PairingRequestSentTag::new(pairing_data.deref_mut(), ops)?)
            };
            ret.current_step.replace(next_step);
        }
        ret.reset_timeout();
        Ok(ret)
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
                error!("[smp] Failed to handle command {:?}, {:?}", command, error);
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
                } else {
                    error!("Link encryption with bonded key failed!");
                    Step::Error(Error::Security(Reason::KeyRejected))
                }
            }
            (Step::WaitingNumericComparisonResult, Event::PassKeyConfirm) => {
                Step::WaitingDHKeyEb(DHKeyEaSentTag::new(self.pairing_data.borrow_mut().deref_mut(), ops)?)
            }
            (Step::WaitingNumericComparisonResult, Event::PassKeyCancel) => {
                Step::Error(Error::Security(Reason::NumericComparisonFailed))
            }
            (Step::WaitingPassKeyInput, Event::PassKeyInput(input)) => {
                let mut pairing_data = self.pairing_data.borrow_mut();
                pairing_data.local_secret_ra = input as u128;
                pairing_data.peer_secret_rb = pairing_data.local_secret_ra;
                Step::WaitingPassKeyEntryConfirm(PassKeyEntryConfirmSentTag::new(
                    0,
                    pairing_data.deref_mut(),
                    ops,
                    rng,
                )?)
            }
            (x, Event::PassKeyConfirm | Event::PassKeyCancel) => x,
            _ => Step::Error(Error::InvalidState),
        };

        match next_state {
            Step::Error(x) => {
                self.current_step.replace(Step::Error(x.clone()));
                ops.try_send_connection_event(ConnectionEvent::PairingFailed(x.clone()))?;
                Err(x)
            }
            x => {
                let is_success = matches!(x, Step::Success);
                self.current_step.replace(x);
                if is_success {
                    let pairing_data = self.pairing_data.borrow();
                    if let Some(bond) = pairing_data.bond_information.as_ref() {
                        let pairing_bond = if pairing_data.want_bonding() {
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
        &self,
        command: CommandAndPayload,
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let current_step = self.current_step.borrow().clone();
        let mut pairing_data = self.pairing_data.borrow_mut();
        let pairing_data = pairing_data.deref_mut();
        let next_step = {
            trace!("Handling {:?}, step {:?}", command.command, current_step);
            match (current_step, command.command) {
                (Step::Idle, Command::SecurityRequest) => {
                    pairing_data.local_features.security_properties = AuthReq::new(ops.bonding_flag());
                    if let Some(bond) = ops.try_enable_bonded_encryption()? {
                        pairing_data.bond_information = Some(bond);
                        Step::WaitingBondedLinkEncryption
                    } else {
                        Step::WaitingPairingResponse(PairingRequestSentTag::new(pairing_data, ops)?)
                    }
                }
                (Step::WaitingPairingResponse(x), Command::SecurityRequest) => {
                    // SM test spec SM/CEN/PIS/BV-03-C, security requests while waiting for pairing response shall be ignored
                    Step::WaitingPairingResponse(x)
                }
                (Step::WaitingPairingResponse(_), Command::PairingResponse) => {
                    Self::handle_pairing_response(command.payload, ops, pairing_data)?;
                    Self::generate_private_public_key_pair(pairing_data, rng)?;
                    Self::send_public_key(ops, pairing_data.local_public_key.as_ref().unwrap())?;
                    Step::WaitingPublicKey
                }
                (Step::WaitingPublicKey, Command::PairingPublicKey) => {
                    Self::handle_public_key(command.payload, pairing_data)?;
                    match pairing_data.pairing_method {
                        PairingMethod::OutOfBand => todo!("OOB not implemented"),
                        PairingMethod::PassKeyEntry { central, .. } => {
                            if central == PassKeyEntryAction::Display {
                                pairing_data.local_secret_ra =
                                    rng.sample(rand::distributions::Uniform::new_inclusive(0, 999999));
                                pairing_data.peer_secret_rb = pairing_data.local_secret_ra;
                                ops.try_send_connection_event(ConnectionEvent::PassKeyDisplay(PassKey(
                                    pairing_data.local_secret_ra as u32,
                                )))?;
                                Step::WaitingPassKeyEntryConfirm(PassKeyEntryConfirmSentTag::new(
                                    0,
                                    pairing_data,
                                    ops,
                                    rng,
                                )?)
                            } else {
                                ops.try_send_connection_event(ConnectionEvent::PassKeyInput)?;
                                Step::WaitingPassKeyInput
                            }
                        }
                        _ => Step::WaitingNumericComparisonConfirm,
                    }
                }
                (Step::WaitingNumericComparisonConfirm, Command::PairingConfirm) => {
                    Self::handle_numeric_compare_confirm(command.payload, pairing_data, rng)?;
                    Self::send_nonce(ops, &pairing_data.local_nonce)?;
                    Step::WaitingNumericComparisonRandom
                }
                (Step::WaitingNumericComparisonRandom, Command::PairingRandom) => {
                    Self::handle_numeric_compare_random(command.payload, pairing_data, ops)?
                }
                (Step::WaitingPassKeyEntryConfirm(round), Command::PairingConfirm) => {
                    Self::handle_pass_key_confirm(command.payload, pairing_data)?;
                    Self::send_nonce(ops, &pairing_data.local_nonce)?;
                    Step::WaitingPassKeyEntryRandom(round.0)
                }

                (Step::WaitingPassKeyEntryRandom(round), Command::PairingRandom) => {
                    Self::handle_pass_key_random(round, command.payload, ops, pairing_data)?;
                    if round == 19 {
                        Step::WaitingDHKeyEb(DHKeyEaSentTag::new(pairing_data, ops)?)
                    } else {
                        Step::WaitingPassKeyEntryConfirm(PassKeyEntryConfirmSentTag::new(
                            round + 1,
                            pairing_data,
                            ops,
                            rng,
                        )?)
                    }
                }
                (Step::WaitingDHKeyEb(_), Command::PairingDhKeyCheck) => {
                    Self::handle_dhkey_eb(command.payload, ops, pairing_data)?;
                    Step::WaitingLinkEncrypted
                }
                (x, Command::KeypressNotification) => x,

                _ => return Err(Error::InvalidState),
            }
        };

        self.current_step.replace(next_step);

        Ok(())
    }

    fn handle_pairing_response<P: PacketPool, OPS: PairingOps<P>>(
        payload: &[u8],
        ops: &mut OPS,
        pairing_data: &mut PairingData,
    ) -> Result<(), Error> {
        let peer_features = PairingFeatures::decode(payload).map_err(|_| Error::Security(Reason::InvalidParameters))?;
        if peer_features.maximum_encryption_key_size < ENCRYPTION_KEY_SIZE_128_BITS {
            return Err(Error::Security(Reason::EncryptionKeySize));
        }
        if !peer_features.security_properties.secure_connection() {
            return Err(Error::Security(Reason::UnspecifiedReason));
        }

        pairing_data.peer_features = peer_features;
        pairing_data.pairing_method = choose_pairing_method(pairing_data.local_features, pairing_data.peer_features);
        info!("[smp] Pairing method {:?}", pairing_data.pairing_method);

        Ok(())
    }

    fn generate_private_public_key_pair<RNG: CryptoRng + RngCore>(
        pairing_data: &mut PairingData,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let secret_key = SecretKey::new(rng);
        let public_key = secret_key.public_key();
        pairing_data.local_public_key = Some(public_key);
        pairing_data.private_key = Some(secret_key);

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

    fn handle_public_key(payload: &[u8], pairing_data: &mut PairingData) -> Result<(), Error> {
        let peer_public_key = PublicKey::from_bytes(payload);
        let secret_key = pairing_data.private_key.as_ref().ok_or(Error::InvalidValue)?;
        pairing_data.dh_key = Some(
            secret_key
                .dh_key(peer_public_key)
                .ok_or(Error::Security(Reason::InvalidParameters))?,
        );

        pairing_data.peer_public_key = Some(peer_public_key);

        Ok(())
    }

    fn handle_numeric_compare_confirm<RNG: CryptoRng + RngCore>(
        payload: &[u8],
        pairing_data: &mut PairingData,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        pairing_data.confirm = Confirm(u128::from_le_bytes(
            payload.try_into().map_err(|_| Error::InvalidValue)?,
        ));
        pairing_data.local_nonce = Nonce::new(rng);
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

    fn handle_numeric_compare_random<P: PacketPool, OPS: PairingOps<P>>(
        payload: &[u8],
        pairing_data: &mut PairingData,
        ops: &mut OPS,
    ) -> Result<Step, Error> {
        let peer_nonce = Nonce(u128::from_le_bytes(
            payload.try_into().map_err(|_| Error::InvalidValue)?,
        ));
        let expected_cb = peer_nonce.f4(
            pairing_data.peer_public_key.ok_or(Error::InvalidValue)?.x(),
            pairing_data.local_public_key.ok_or(Error::InvalidValue)?.x(),
            0,
        );
        if pairing_data.confirm != expected_cb {
            return Err(Error::Security(Reason::NumericComparisonFailed));
        }
        pairing_data.peer_nonce = peer_nonce;
        let va = pairing_data.local_nonce.g2(
            pairing_data.local_public_key.ok_or(Error::InvalidValue)?.x(),
            pairing_data.peer_public_key.ok_or(Error::InvalidValue)?.x(),
            &pairing_data.peer_nonce,
        );

        if pairing_data.pairing_method == PairingMethod::JustWorks {
            info!("[smp] Just works pairing with compare {}", va.0);
            Ok(Step::WaitingDHKeyEb(DHKeyEaSentTag::new(pairing_data, ops)?))
        } else {
            info!("[smp] Numeric comparison pairing with compare {}", va.0);
            ops.try_send_connection_event(ConnectionEvent::PassKeyConfirm(PassKey(va.0)))?;
            Ok(Step::WaitingNumericComparisonResult)
        }
    }

    fn handle_dhkey_eb<P: PacketPool, OPS: PairingOps<P>>(
        payload: &[u8],
        ops: &mut OPS,
        pairing_data: &mut PairingData,
    ) -> Result<(), Error> {
        let expected_eb = {
            let mac_key = pairing_data.mac_key.as_ref().ok_or(Error::InvalidValue)?;
            mac_key
                .f6(
                    pairing_data.peer_nonce,
                    pairing_data.local_nonce,
                    pairing_data.local_secret_ra,
                    pairing_data.peer_features.as_io_cap(),
                    pairing_data.peer_address,
                    pairing_data.local_address,
                )
                .0
                .to_le_bytes()
        };
        if payload != expected_eb {
            return Err(Error::Security(Reason::DHKeyCheckFailed));
        }

        let bond = ops.try_enable_encryption(
            &pairing_data.ltk.ok_or(Error::InvalidValue)?,
            pairing_data.pairing_method.security_level(),
            pairing_data.want_bonding(),
        )?;
        pairing_data.bond_information = Some(bond);
        Ok(())
    }

    fn handle_pass_key_confirm(payload: &[u8], pairing_data: &mut PairingData) -> Result<(), Error> {
        let confirm = Confirm(u128::from_le_bytes(
            payload.try_into().map_err(|_| Error::InvalidValue)?,
        ));
        pairing_data.confirm = confirm;
        Ok(())
    }

    fn handle_pass_key_random<P: PacketPool, OPS: PairingOps<P>>(
        round: i32,
        payload: &[u8],
        ops: &mut OPS,
        pairing_data: &mut PairingData,
    ) -> Result<(), Error> {
        let peer_nonce = Nonce(u128::from_le_bytes(
            payload.try_into().map_err(|_| Error::InvalidValue)?,
        ));
        let rai = 0x80u8 | (((pairing_data.local_secret_ra & (1 << round as u128)) >> (round as u128)) as u8);
        let cbi = peer_nonce.f4(
            pairing_data.peer_public_key.as_ref().ok_or(Error::InvalidValue)?.x(),
            pairing_data.local_public_key.as_ref().ok_or(Error::InvalidValue)?.x(),
            rai,
        );
        if cbi != pairing_data.confirm {
            return Err(Error::Security(Reason::NumericComparisonFailed));
        }
        pairing_data.peer_nonce = peer_nonce;
        Ok(())
    }
}

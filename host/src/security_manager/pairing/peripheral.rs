use core::cell::RefCell;
use core::ops::{Deref, DerefMut};

use embassy_time::Instant;
use rand::Rng;
use rand_core::{CryptoRng, RngCore};

use crate::codec::{Decode, Encode};
use crate::connection::SecurityLevel;
use crate::prelude::ConnectionEvent;
use crate::security_manager::constants::ENCRYPTION_KEY_SIZE_128_BITS;
use crate::security_manager::crypto::{Confirm, DHKey, MacKey, Nonce, PublicKey, SecretKey};
use crate::security_manager::pairing::util::{
    choose_pairing_method, make_confirm_packet, make_dhkey_check_packet, make_pairing_random, make_public_key_packet,
    prepare_packet, CommandAndPayload, PairingMethod, PassKeyEntryAction,
};
use crate::security_manager::pairing::{Event, PairingOps};
use crate::security_manager::types::{AuthReq, BondingFlag, Command, PairingFeatures, PassKey};
use crate::security_manager::Reason;
use crate::{Address, BondInformation, Error, IoCapabilities, LongTermKey, PacketPool};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum Step {
    WaitingPairingRequest,
    WaitingPublicKey,
    // Numeric comparison
    WaitingNumericComparisonRandom(NumericCompareConfirmSentTag),
    WaitingNumericComparisonResult(Option<[u8; size_of::<u128>()]>),
    // Associated data is which round currently being processed.
    WaitingPassKeyInput(Option<[u8; size_of::<u128>()]>),
    WaitingPassKeyEntryConfirm(i32),
    WaitingPassKeyEntryRandom(i32),
    // TODO add OOB
    WaitingDHKeyEa,
    WaitingLinkEncrypted,
    SendingKeys(i32),
    ReceivingKeys(i32),
    Success,
    Error(Error),
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct NumericCompareConfirmSentTag {}

impl NumericCompareConfirmSentTag {
    fn new<P: PacketPool, OPS: PairingOps<P>, RNG: RngCore>(
        ops: &mut OPS,
        pairing_data: &mut PairingData,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        pairing_data.local_nonce = Nonce::new(rng);
        pairing_data.confirm = Self::compute_confirm(pairing_data)?;
        let packet = make_confirm_packet(&pairing_data.confirm)?;
        match ops.try_send_packet(packet) {
            Ok(_) => (),
            Err(error) => {
                error!("[smp] Failed to send confirm {:?}", error);
                return Err(error);
            }
        }

        Ok(Self {})
    }
    fn compute_confirm(pairing_data: &PairingData) -> Result<Confirm, Error> {
        let local_public_key = pairing_data.local_public_key.as_ref().ok_or(Error::InvalidValue)?;
        let peer_public_key = pairing_data.peer_public_key.as_ref().ok_or(Error::InvalidValue)?;
        Ok(pairing_data
            .local_nonce
            .f4(local_public_key.x(), peer_public_key.x(), 0))
    }
}

pub struct Pairing {
    current_step: RefCell<Step>,
    pairing_data: RefCell<PairingData>,
}

struct PairingData {
    local_address: Address,
    peer_address: Address,
    peer_features: PairingFeatures,
    local_features: PairingFeatures,
    pairing_method: PairingMethod,
    peer_public_key: Option<PublicKey>,
    local_public_key: Option<PublicKey>,
    private_key: Option<SecretKey>,
    dh_key: Option<DHKey>,
    confirm: Confirm,
    local_secret_rb: u128,
    peer_secret_ra: u128,
    local_nonce: Nonce,
    peer_nonce: Nonce,
    mac_key: Option<MacKey>,
    long_term_key: LongTermKey,
    timeout_at: Instant,
    bond_information: Option<BondInformation>,
}

impl PairingData {
    fn want_bonding(&self) -> bool {
        matches!(self.local_features.security_properties.bond(), BondingFlag::Bonding)
            && matches!(self.peer_features.security_properties.bond(), BondingFlag::Bonding)
    }
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
                peer_public_key: None,
                local_public_key: None,
                private_key: None,
                dh_key: None,
                confirm: Confirm(0),
                local_secret_rb: 0,
                peer_secret_ra: 0,
                local_nonce: Nonce(0),
                peer_nonce: Nonce(0),
                mac_key: None,
                long_term_key: LongTermKey(0),
                timeout_at: Instant::now() + crate::security_manager::constants::TIMEOUT,
                bond_information: None,
            }),
        }
    }

    pub(crate) fn initiate<P: PacketPool, OPS: PairingOps<P>>(
        local_address: Address,
        peer_address: Address,
        ops: &mut OPS,
        local_io: IoCapabilities,
    ) -> Result<Self, Error> {
        let ret = Self::new(local_address, peer_address, local_io);
        {
            let mut security_request = prepare_packet(Command::SecurityRequest)?;
            let payload = security_request.payload_mut();
            payload[0] = AuthReq::new(ops.bonding_flag()).into();
            ops.try_send_packet(security_request)?;
        }
        Ok(ret)
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
            x @ (Step::WaitingPairingRequest | Step::WaitingLinkEncrypted, Event::LinkEncryptedResult(res)) => {
                if res {
                    info!("Link encrypted!");
                    if matches!(x.0, Step::WaitingLinkEncrypted) {
                        // TODO send key data
                    } else {
                        self.pairing_data.borrow_mut().bond_information = ops.try_enable_bonded_encryption()?;
                    }
                    Step::Success
                } else {
                    error!("Failed to enable encryption!");
                    Step::Error(Error::Security(Reason::KeyRejected))
                }
            }
            (Step::WaitingNumericComparisonResult(ea), Event::PassKeyConfirm) => {
                if let Some(ea) = ea {
                    let mut pairing_data = self.pairing_data.borrow_mut();
                    Self::handle_dhkey_ea(&ea, ops, pairing_data.deref_mut())?
                } else {
                    Step::WaitingDHKeyEa
                }
            }
            (Step::WaitingNumericComparisonResult(_), Event::PassKeyCancel) => {
                Step::Error(Error::Security(Reason::NumericComparisonFailed))
            }
            (Step::WaitingPassKeyInput(confirm), Event::PassKeyInput(input)) => {
                let mut pairing_data = self.pairing_data.borrow_mut();
                pairing_data.local_secret_rb = input as u128;
                pairing_data.peer_secret_ra = pairing_data.local_secret_rb;
                match confirm {
                    Some(payload) => Self::handle_pass_key_confirm(0, &payload, ops, pairing_data.deref_mut(), rng)?,
                    None => Step::WaitingPassKeyEntryConfirm(0),
                }
            }
            (x, Event::PassKeyConfirm | Event::PassKeyCancel | Event::PassKeyInput(_)) => x,
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
                    }
                }
                Ok(())
            }
        }
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
                (Step::WaitingPairingRequest, Command::PairingRequest) => {
                    Self::handle_pairing_request(command.payload, ops, pairing_data)?;
                    Self::send_pairing_response(ops, pairing_data)?;
                    Step::WaitingPublicKey
                }
                (Step::WaitingPublicKey, Command::PairingPublicKey) => {
                    Self::handle_public_key(command.payload, pairing_data);
                    Self::generate_private_public_key_pair(pairing_data, rng)?;
                    Self::send_public_key(ops, pairing_data.local_public_key.as_ref().unwrap())?;
                    match pairing_data.pairing_method {
                        PairingMethod::OutOfBand => todo!("OOB not implemented"),
                        PairingMethod::PassKeyEntry { peripheral, .. } => {
                            if peripheral == PassKeyEntryAction::Display {
                                pairing_data.local_secret_rb =
                                    rng.sample(rand::distributions::Uniform::new_inclusive(0, 999999));
                                pairing_data.peer_secret_ra = pairing_data.local_secret_rb;
                                ops.try_send_connection_event(ConnectionEvent::PassKeyDisplay(PassKey(
                                    pairing_data.local_secret_rb as u32,
                                )))?;
                                Step::WaitingPassKeyEntryConfirm(0)
                            } else {
                                ops.try_send_connection_event(ConnectionEvent::PassKeyInput)?;
                                Step::WaitingPassKeyInput(None)
                            }
                        }
                        _ => Step::WaitingNumericComparisonRandom(NumericCompareConfirmSentTag::new(
                            ops,
                            pairing_data,
                            rng,
                        )?),
                    }
                }
                (Step::WaitingNumericComparisonRandom(_), Command::PairingRandom) => {
                    Self::handle_numeric_compare_random(command.payload, pairing_data)?;
                    Self::send_nonce(ops, &pairing_data.local_nonce)?;
                    Self::numeric_compare_confirm(ops, pairing_data)?
                }
                (Step::WaitingNumericComparisonResult(None), Command::PairingDhKeyCheck) => {
                    let ea: [u8; size_of::<u128>()] = command.payload.try_into().map_err(|_| Error::InvalidValue)?;
                    Step::WaitingNumericComparisonResult(Some(ea))
                }

                (Step::WaitingPassKeyInput(_), Command::PairingConfirm) => {
                    let confirm: [u8; size_of::<u128>()] =
                        command.payload.try_into().map_err(|_| Error::InvalidValue)?;
                    Step::WaitingPassKeyInput(Some(confirm))
                }
                (Step::WaitingPassKeyEntryConfirm(round), Command::PairingConfirm) => {
                    Self::handle_pass_key_confirm(round, command.payload, ops, pairing_data, rng)?
                }

                (Step::WaitingPassKeyEntryRandom(round), Command::PairingRandom) => {
                    Self::handle_pass_key_random(round, command.payload, ops, pairing_data)?
                }

                (Step::WaitingDHKeyEa, Command::PairingDhKeyCheck) => {
                    Self::handle_dhkey_ea(command.payload, ops, pairing_data)?
                }

                (x, Command::KeypressNotification) => x,

                _ => return Err(Error::InvalidState),
            }
        };

        self.current_step.replace(next_step);

        Ok(())
    }

    fn handle_pairing_request<P: PacketPool, OPS: PairingOps<P>>(
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
        pairing_data.local_features.security_properties = AuthReq::new(ops.bonding_flag());
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

    fn handle_public_key(payload: &[u8], pairing_data: &mut PairingData) {
        let peer_public_key = PublicKey::from_bytes(payload);
        pairing_data.peer_public_key = Some(peer_public_key);
    }

    fn generate_private_public_key_pair<RNG: CryptoRng + RngCore>(
        pairing_data: &mut PairingData,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        let secret_key = SecretKey::new(rng);
        let public_key = secret_key.public_key();
        let peer_public_key = pairing_data
            .peer_public_key
            .ok_or(Error::Security(Reason::InvalidParameters))?;
        pairing_data.dh_key = Some(
            secret_key
                .dh_key(peer_public_key)
                .ok_or(Error::Security(Reason::InvalidParameters))?,
        );
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

    fn handle_numeric_compare_random(payload: &[u8], pairing_data: &mut PairingData) -> Result<(), Error> {
        pairing_data.peer_nonce = Nonce(u128::from_le_bytes(
            payload
                .try_into()
                .map_err(|_| Error::Security(Reason::InvalidParameters))?,
        ));

        Ok(())
    }

    fn compute_ltk(pairing_data: &mut PairingData) -> Result<(), Error> {
        let (mac, ltk) = pairing_data.dh_key.as_ref().ok_or(Error::InvalidValue)?.f5(
            pairing_data.peer_nonce,
            pairing_data.local_nonce,
            pairing_data.peer_address,
            pairing_data.local_address,
        );

        pairing_data.mac_key = Some(mac);
        pairing_data.long_term_key = ltk;
        Ok(())
    }

    fn handle_dhkey_ea<P: PacketPool, OPS: PairingOps<P>>(
        payload: &[u8],
        ops: &mut OPS,
        pairing_data: &mut PairingData,
    ) -> Result<Step, Error> {
        Self::compute_ltk(pairing_data)?;
        let expected_payload = pairing_data
            .mac_key
            .as_ref()
            .ok_or(Error::InvalidValue)?
            .f6(
                pairing_data.peer_nonce,
                pairing_data.local_nonce,
                pairing_data.local_secret_rb,
                pairing_data.peer_features.as_io_cap(),
                pairing_data.peer_address,
                pairing_data.local_address,
            )
            .0
            .to_le_bytes();

        if expected_payload != payload {
            Err(Error::Security(Reason::DHKeyCheckFailed))
        } else {
            Self::send_dhkey_eb(ops, pairing_data)?;
            let bond = ops.try_enable_encryption(
                &pairing_data.long_term_key,
                pairing_data.pairing_method.security_level(),
                pairing_data.want_bonding(),
            )?;
            pairing_data.bond_information = Some(bond);
            Ok(Step::WaitingLinkEncrypted)
        }
    }

    fn send_dhkey_eb<P: PacketPool, OPS: PairingOps<P>>(
        ops: &mut OPS,
        pairing_data: &mut PairingData,
    ) -> Result<(), Error> {
        let check = pairing_data.mac_key.as_ref().ok_or(Error::InvalidValue)?.f6(
            pairing_data.local_nonce,
            pairing_data.peer_nonce,
            pairing_data.peer_secret_ra,
            pairing_data.local_features.as_io_cap(),
            pairing_data.local_address,
            pairing_data.peer_address,
        );

        let check = make_dhkey_check_packet(&check)?;
        ops.try_send_packet(check)?;
        Ok(())
    }

    fn numeric_compare_confirm<P: PacketPool, OPS: PairingOps<P>>(
        ops: &mut OPS,
        pairing_data: &PairingData,
    ) -> Result<Step, Error> {
        let peer_public_key = pairing_data.peer_public_key.ok_or(Error::InvalidValue)?;
        let local_public_key = pairing_data.local_public_key.ok_or(Error::InvalidValue)?;
        let vb = pairing_data
            .peer_nonce
            .g2(peer_public_key.x(), local_public_key.x(), &pairing_data.local_nonce);

        if pairing_data.pairing_method == PairingMethod::JustWorks {
            info!("[smp] Just works pairing with compare {}", vb.0);
            Ok(Step::WaitingDHKeyEa)
        } else {
            info!("[smp] Numeric comparison pairing with compare {}", vb.0);
            ops.try_send_connection_event(ConnectionEvent::PassKeyConfirm(PassKey(vb.0)))?;
            Ok(Step::WaitingNumericComparisonResult(None))
        }
    }

    fn handle_pass_key_confirm<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        round: i32,
        payload: &[u8],
        ops: &mut OPS,
        pairing_data: &mut PairingData,
        rng: &mut RNG,
    ) -> Result<Step, Error> {
        pairing_data.confirm = Confirm(u128::from_le_bytes(
            payload
                .try_into()
                .map_err(|_| Error::Security(Reason::InvalidParameters))?,
        ));
        pairing_data.local_nonce = Nonce::new(rng);
        let z = 0x80 | ((pairing_data.local_secret_rb & (1 << round)) >> round);
        let confirm_to_send = pairing_data.local_nonce.f4(
            pairing_data.local_public_key.ok_or(Error::InvalidValue)?.x(),
            pairing_data.peer_public_key.ok_or(Error::InvalidValue)?.x(),
            z as u8,
        );
        let packet = make_confirm_packet(&confirm_to_send)?;
        ops.try_send_packet(packet)?;
        Ok(Step::WaitingPassKeyEntryRandom(round))
    }

    fn handle_pass_key_random<P: PacketPool, OPS: PairingOps<P>>(
        round: i32,
        payload: &[u8],
        ops: &mut OPS,
        pairing_data: &mut PairingData,
    ) -> Result<Step, Error> {
        pairing_data.peer_nonce = Nonce(u128::from_le_bytes(
            payload
                .try_into()
                .map_err(|_| Error::Security(Reason::InvalidParameters))?,
        ));
        let round = round as u128;
        let z = 0x80 | ((pairing_data.local_secret_rb & (1 << round)) >> round);
        let expected_confirm = pairing_data.peer_nonce.f4(
            pairing_data.peer_public_key.ok_or(Error::InvalidValue)?.x(),
            pairing_data.local_public_key.ok_or(Error::InvalidValue)?.x(),
            z as u8,
        );

        if pairing_data.confirm != expected_confirm {
            error!(
                "Confirm and computed confirm mismatch: {:?} != {:?}",
                pairing_data.confirm.0, expected_confirm.0
            );
            Err(Error::Security(Reason::PasskeyEntryFailed))
        } else {
            let nonce_packet = make_pairing_random(&pairing_data.local_nonce)?;
            ops.try_send_packet(nonce_packet)?;
            if round == 19 {
                Ok(Step::WaitingDHKeyEa)
            } else {
                Ok(Step::WaitingPassKeyEntryConfirm((round + 1) as i32))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::{ChaCha12Core, ChaCha12Rng};
    use rand_core::SeedableRng;

    use crate::security_manager::crypto::{Nonce, PublicKey, SecretKey};
    use crate::security_manager::pairing::peripheral::Pairing;
    use crate::security_manager::pairing::tests::{HeaplessPool, TestOps};
    use crate::security_manager::pairing::util::make_public_key_packet;
    use crate::security_manager::types::{Command, PairingFeatures};
    use crate::{Address, IoCapabilities, LongTermKey};

    #[test]
    fn just_works() {
        let mut pairing_ops: TestOps<10> = TestOps::default();
        let pairing = Pairing::new(
            Address::random([1, 2, 3, 4, 5, 6]),
            Address::random([7, 8, 9, 10, 11, 12]),
            IoCapabilities::NoInputNoOutput,
        );
        let mut rng: ChaCha12Rng = ChaCha12Core::seed_from_u64(1).into();
        // Central sends pairing request, expects pairing response from peripheral
        pairing
            .handle_l2cap_command::<HeaplessPool, _, _>(
                Command::PairingRequest,
                &[0x03, 0, 0x08, 16, 0, 0],
                &mut pairing_ops,
                &mut rng,
            )
            .unwrap();
        {
            let pairing_data = pairing.pairing_data.borrow();
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
            assert_eq!(pairing_response.payload(), &[0x03, 0, 12, 16, 0, 0]);
            assert_eq!(
                pairing_data.local_features,
                PairingFeatures {
                    io_capabilities: IoCapabilities::NoInputNoOutput,
                    security_properties: 12.into(),
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
                &mut pairing_ops,
                &mut rng,
            )
            .unwrap();

        {
            let sent_packets = &pairing_ops.sent_packets;
            let pairing_data = pairing.pairing_data.borrow();
            assert_eq!(sent_packets.len(), 3);

            let peer_public = pairing_data.peer_public_key.unwrap();
            assert_eq!(peer_public, secret_key.public_key());

            let local_public = pairing_data.local_public_key.unwrap();
            assert_eq!(local_public, PublicKey::from_bytes(sent_packets[1].payload()));
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
            let confirm = pairing_data.confirm;
            assert_eq!(
                confirm.0,
                u128::from_le_bytes(sent_packets[2].payload().try_into().unwrap())
            );
        }

        // Central sends Nonce, expects Nonce
        pairing
            .handle_l2cap_command::<HeaplessPool, _, _>(
                Command::PairingRandom,
                &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                &mut pairing_ops,
                &mut rng,
            )
            .unwrap();

        {
            let pairing_data = pairing.pairing_data.borrow();
            let sent_packets = &pairing_ops.sent_packets;
            let peer_nonce = Nonce(u128::from_le_bytes([
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            ]));
            let local_nonce = pairing_data.local_nonce.0.to_le_bytes();
            assert_eq!(sent_packets.len(), 4);
            assert_eq!(sent_packets[3].command, Command::PairingRandom);
            assert_eq!(sent_packets[3].payload(), &local_nonce);
            assert_eq!(pairing_data.peer_nonce, peer_nonce);
            assert_eq!(pairing_ops.encryptions.len(), 0);
        }
        pairing
            .handle_l2cap_command::<HeaplessPool, _, _>(
                Command::PairingDhKeyCheck,
                &[
                    0x70, 0xa9, 0xf1, 0xd0, 0xcf, 0x52, 0x84, 0xe9, 0xfc, 0x36, 0x9b, 0x84, 0x35, 0x13, 0xc5, 0xed,
                ],
                &mut pairing_ops,
                &mut rng,
            )
            .unwrap();

        {
            let pairing_data = pairing.pairing_data.borrow();
            let sent_packets = &pairing_ops.sent_packets;
            let local_nonce = pairing_data.local_nonce.0.to_le_bytes();
            assert!(pairing_data.mac_key.is_some());
            assert_eq!(sent_packets.len(), 5);
            assert_eq!(sent_packets[4].command, Command::PairingDhKeyCheck);
            assert_eq!(
                sent_packets[4].payload(),
                [22, 123, 0, 74, 239, 81, 163, 188, 71, 111, 251, 117, 54, 186, 205, 3]
            );
            assert_eq!(pairing_ops.encryptions.len(), 1);
            assert!(matches!(pairing_ops.encryptions[0], LongTermKey(_)));
        }
    }
}

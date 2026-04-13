use bt_hci::param::{AddrKind, BdAddr};
use rand::Rng;
use rand_core::{CryptoRng, RngCore};

use crate::codec::{Decode, Encode};
use crate::prelude::ConnectionEvent;
use crate::security_manager::crypto::{Confirm, DHKey, Nonce, PublicKey, PublicKeyX};
use crate::security_manager::pairing::util::{
    choose_pairing_method, make_confirm_packet, make_dhkey_check_packet, make_pairing_random, make_public_key_packet,
    prepare_packet, PairingMethod, PassKeyEntryAction,
};
use crate::security_manager::pairing::{Event, Input, PairingData, PairingOps};
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
    // OOB
    WaitingOobData(LescPhaseData),
    WaitingOobRandom(LescPhaseData),
    WaitingDHKeyEa(LescPhaseData),
    WaitingLinkEncrypted,
    WaitingIdentitityInformation,
    WaitingIdentitityAddressInformation,
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
            Self::WaitingIdentitityInformation | Self::WaitingIdentitityAddressInformation | Self::Success
        )
    }

    pub(crate) fn initiate<P: PacketPool, OPS: PairingOps<P>>(
        pairing_data: &PairingData,
        ops: &mut OPS,
        user_initiated: bool,
    ) -> Result<Self, Error> {
        let ret = Self::new();
        {
            let mut security_request = prepare_packet(Command::SecurityRequest)?;
            let payload = security_request.payload_mut();
            let mut auth_req = AuthReq::new(ops.bonding_flag());
            let mut request_mitm = pairing_data.local_features.io_capabilities != IoCapabilities::NoInputNoOutput;
            if !user_initiated {
                if let Some(bond) = ops.find_bond() {
                    request_mitm = bond.security_level == crate::connection::SecurityLevel::EncryptedAuthenticated;
                }
            }
            if request_mitm {
                auth_req = auth_req.with_mitm();
            }
            payload[0] = auth_req.into();
            ops.try_send_packet(security_request)?;
        }
        Ok(ret)
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
                Self::handle_pairing_request_command(payload, pairing_data, ops, rng)
            }
            (Self::WaitingPublicKey, Input::Command(Command::PairingPublicKey, payload)) => {
                Self::handle_public_key_and_choose_method(payload, pairing_data, ops, rng)
            }
            (Self::WaitingNumericComparisonRandom(phase_data), Input::Command(Command::PairingRandom, payload)) => {
                Self::handle_numeric_compare_random_and_confirm(payload, phase_data, pairing_data, ops)
            }
            (
                Self::WaitingNumericComparisonResult { phase_data, ea: None },
                Input::Command(Command::PairingDhKeyCheck, payload),
            ) => Self::store_dhkey_ea(payload, phase_data),
            (
                Self::WaitingPassKeyInput {
                    phase_data,
                    confirm_bytes: _,
                },
                Input::Command(Command::PairingConfirm, payload),
            ) => Self::store_pass_key_confirm_bytes(payload, phase_data),
            (
                Self::WaitingPassKeyEntryConfirm { phase_data, round },
                Input::Command(Command::PairingConfirm, payload),
            ) => Self::handle_pass_key_confirm(round, payload, ops, pairing_data, phase_data, rng),
            (
                Self::WaitingPassKeyEntryRandom { phase_data, round },
                Input::Command(Command::PairingRandom, payload),
            ) => Self::handle_pass_key_random(round, payload, ops, pairing_data, phase_data),
            (Self::WaitingOobRandom(phase_data), Input::Command(Command::PairingRandom, payload)) => {
                Self::handle_oob_random(payload, phase_data, pairing_data, ops, rng)
            }
            (Self::WaitingDHKeyEa(phase_data), Input::Command(Command::PairingDhKeyCheck, payload)) => {
                Self::handle_dhkey_ea(payload, ops, pairing_data, &phase_data)
            }
            (Self::WaitingIdentitityInformation, Input::Command(Command::IdentityInformation, payload)) => {
                Self::handle_identity_information(payload, pairing_data)
            }
            (
                Self::WaitingIdentitityAddressInformation,
                Input::Command(Command::IdentityAddressInformation, payload),
            ) => Self::handle_identity_address_information(payload, pairing_data),
            (current, Input::Command(Command::KeypressNotification, _)) => Ok(current),
            // Handle PairingFailed from peer in any state
            (_, Input::Command(Command::PairingFailed, payload)) => {
                let reason = Reason::try_from(payload[0]).unwrap_or(Reason::UnspecifiedReason);
                warn!("[smp peripheral] Peer sent PairingFailed: {:?}", reason);
                Err(Error::Security(reason))
            }

            // --- Event transitions ---
            (Self::WaitingOobData(phase_data), Input::Event(Event::OobDataReceived { local, peer })) => {
                Self::handle_oob_data_received(local, peer, phase_data, pairing_data)
            }
            (
                current @ (Self::WaitingPairingRequest | Self::WaitingLinkEncrypted),
                Input::Event(Event::LinkEncryptedResult(res)),
            ) => Self::handle_link_encrypted(current, res, pairing_data, ops),
            (
                Self::WaitingNumericComparisonResult {
                    phase_data,
                    ea: Some(ea),
                },
                Input::Event(Event::PassKeyConfirm),
            ) => Self::handle_dhkey_ea(&ea, ops, pairing_data, &phase_data),
            (Self::WaitingNumericComparisonResult { phase_data, ea: None }, Input::Event(Event::PassKeyConfirm)) => {
                Ok(Self::WaitingDHKeyEa(phase_data))
            }
            (Self::WaitingNumericComparisonResult { .. }, Input::Event(Event::PassKeyCancel)) => {
                Err(Error::Security(Reason::NumericComparisonFailed))
            }
            (
                Self::WaitingPassKeyInput {
                    phase_data,
                    confirm_bytes,
                },
                Input::Event(Event::PassKeyInput(input)),
            ) => Self::handle_pass_key_input(input, phase_data, confirm_bytes, ops, pairing_data, rng),
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
                }
            }
            _ => {}
        }
        *self = next;
    }

    // --- Transition helpers ---

    fn handle_pairing_request_command<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        payload: &[u8],
        pairing_data: &mut PairingData,
        ops: &mut OPS,
        _rng: &mut RNG,
    ) -> Result<Self, Error> {
        if ops.find_bond().is_some() {
            if let Err(e) = ops.try_send_connection_event(ConnectionEvent::BondLost) {
                error!("[smp] Failed to send BondLost event: {:?}", e);
            }
        }
        Self::handle_pairing_request(payload, ops, pairing_data)?;
        Self::send_pairing_response(ops, pairing_data)?;
        Ok(Self::WaitingPublicKey)
    }

    fn handle_public_key_and_choose_method<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        payload: &[u8],
        pairing_data: &mut PairingData,
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let peer_public_key = PublicKey::from_bytes(payload);
        let secret_key = ops.secret_key().clone();
        let local_public_key = *ops.public_key();
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
            PairingMethod::OutOfBand => {
                ops.try_send_connection_event(crate::prelude::ConnectionEvent::OobRequest)?;
                Ok(Self::WaitingOobData(phase_data))
            }
            PairingMethod::PassKeyEntry { peripheral, .. } => {
                if peripheral == PassKeyEntryAction::Display {
                    phase_data.local_secret_rb = rng.sample(rand::distributions::Uniform::new_inclusive(0, 999999));
                    phase_data.peer_secret_ra = phase_data.local_secret_rb;
                    ops.try_send_connection_event(ConnectionEvent::PassKeyDisplay(PassKey(
                        phase_data.local_secret_rb as u32,
                    )))?;
                    Ok(Self::WaitingPassKeyEntryConfirm { phase_data, round: 0 })
                } else {
                    ops.try_send_connection_event(ConnectionEvent::PassKeyInput)?;
                    Ok(Self::WaitingPassKeyInput {
                        phase_data,
                        confirm_bytes: None,
                    })
                }
            }
            _ => {
                // Numeric comparison / Just Works: send confirm
                Self::send_numeric_compare_confirm(&mut phase_data, ops, rng)?;
                Ok(Self::WaitingNumericComparisonRandom(phase_data))
            }
        }
    }

    #[inline]
    fn handle_numeric_compare_random_and_confirm<P: PacketPool, OPS: PairingOps<P>>(
        payload: &[u8],
        mut phase_data: LescPhaseData,
        pairing_data: &PairingData,
        ops: &mut OPS,
    ) -> Result<Self, Error> {
        Self::handle_numeric_compare_random(payload, &mut phase_data)?;
        Self::send_nonce(ops, &phase_data.local_nonce)?;
        Self::numeric_compare_confirm(ops, pairing_data, phase_data)
    }

    #[inline]
    fn store_dhkey_ea(payload: &[u8], phase_data: LescPhaseData) -> Result<Self, Error> {
        let ea: [u8; size_of::<u128>()] = payload.try_into().map_err(|_| Error::InvalidValue)?;
        Ok(Self::WaitingNumericComparisonResult {
            phase_data,
            ea: Some(ea),
        })
    }

    #[inline]
    fn store_pass_key_confirm_bytes(payload: &[u8], phase_data: LescPhaseData) -> Result<Self, Error> {
        let confirm: [u8; size_of::<u128>()] = payload.try_into().map_err(|_| Error::InvalidValue)?;
        Ok(Self::WaitingPassKeyInput {
            phase_data,
            confirm_bytes: Some(confirm),
        })
    }

    fn handle_link_encrypted<P: PacketPool, OPS: PairingOps<P>>(
        current: Self,
        res: bool,
        pairing_data: &mut PairingData,
        ops: &mut OPS,
    ) -> Result<Self, Error> {
        if res {
            info!("Link encrypted!");
            if matches!(current, Self::WaitingPairingRequest) {
                pairing_data.bond_information = ops.try_enable_bonded_encryption()?;
            }

            // Send our keys first (responder distributes first in LESC)
            if pairing_data.local_features.responder_key_distribution.identity_key() {
                let irk = ops.local_irk();
                Self::send_irk_distribution(ops, &irk)?;
            }

            if pairing_data.peer_features.initiator_key_distribution.identity_key() {
                Ok(Self::WaitingIdentitityInformation)
            } else {
                Ok(Self::Success)
            }
        } else {
            error!("Failed to enable encryption!");
            Err(Error::Security(Reason::KeyRejected))
        }
    }

    /// Send local IRK and identity address to the peer.
    fn send_irk_distribution<P: PacketPool, OPS: PairingOps<P>>(ops: &mut OPS, irk: &[u8; 16]) -> Result<(), Error> {
        use crate::security_manager::pairing::util::{
            make_identity_address_information_packet, make_identity_information_packet,
        };
        let packet = make_identity_information_packet(irk)?;
        ops.try_send_packet(packet)?;
        // Send the identity address (public or static random), not the RPA used for pairing.
        let identity_address = ops.local_identity_address()?;
        let packet = make_identity_address_information_packet(&identity_address)?;
        ops.try_send_packet(packet)?;
        Ok(())
    }

    #[inline]
    fn handle_pass_key_input<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        input: u32,
        mut phase_data: LescPhaseData,
        confirm_bytes: Option<[u8; size_of::<u128>()]>,
        ops: &mut OPS,
        pairing_data: &mut PairingData,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        phase_data.local_secret_rb = input as u128;
        phase_data.peer_secret_ra = phase_data.local_secret_rb;
        match confirm_bytes {
            Some(payload) => Self::handle_pass_key_confirm(0, &payload, ops, pairing_data, phase_data, rng),
            None => Ok(Self::WaitingPassKeyEntryConfirm { phase_data, round: 0 }),
        }
    }

    fn handle_oob_data_received(
        local: super::OobData,
        peer: super::OobData,
        mut phase_data: LescPhaseData,
        pairing_data: &PairingData,
    ) -> Result<Self, Error> {
        // Verify peer's confirm value if peer OOB data was received.
        // Per spec 2.3.5.6.3: if a device has not received the peer's OOB data,
        // the peer's random is set to zero and the confirm check is skipped.
        let peer_has_oob = peer.random != [0; 16] || peer.confirm != [0; 16];
        if peer_has_oob {
            let peer_r = Nonce(u128::from_le_bytes(peer.random));
            let expected_c = peer_r.f4(&phase_data.peer_public_key_x, &phase_data.peer_public_key_x, 0);
            if expected_c.0.to_le_bytes() != peer.confirm {
                return Err(crate::Error::Security(
                    crate::security_manager::Reason::ConfirmValueFailed,
                ));
            }
        }

        // Peripheral: rb = local random, ra = peer's (central's) random.
        // Per spec 2.3.5.6.4: if the peer (central) did not receive our OOB data
        // (peer's OOB flag = NotPresent), rb must be 0 so both sides agree.
        phase_data.local_secret_rb = if matches!(
            pairing_data.peer_features.use_oob,
            crate::security_manager::types::UseOutOfBand::Present
        ) {
            u128::from_le_bytes(local.random)
        } else {
            0
        };
        phase_data.peer_secret_ra = u128::from_le_bytes(peer.random);

        Ok(Self::WaitingOobRandom(phase_data))
    }

    fn handle_oob_random<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        payload: &[u8],
        mut phase_data: LescPhaseData,
        pairing_data: &mut PairingData,
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        // Receive Na from central
        phase_data.peer_nonce = Nonce(u128::from_le_bytes(
            payload.try_into().map_err(|_| crate::Error::InvalidValue)?,
        ));
        // Generate and send Nb
        phase_data.local_nonce = Nonce::new(rng);
        Self::send_nonce(ops, &phase_data.local_nonce)?;
        // Wait for DHKey check from central
        Ok(Self::WaitingDHKeyEa(phase_data))
    }

    // --- Protocol helpers ---

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

        // Always agree to distribute identity key when the peer requests it,
        // even without a local IRK — we'll send a zero IRK with our identity address.
        if peer_features.responder_key_distribution.identity_key() {
            pairing_data
                .local_features
                .responder_key_distribution
                .set_identity_key();
        }

        pairing_data.peer_features = peer_features;
        let mut auth_req = AuthReq::new(ops.bonding_flag());
        if pairing_data.local_features.io_capabilities != IoCapabilities::NoInputNoOutput {
            auth_req = auth_req.with_mitm();
        }
        pairing_data.local_features.security_properties = auth_req;
        if ops.oob_available() {
            pairing_data.local_features.use_oob = crate::security_manager::types::UseOutOfBand::Present;
        }
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
            bond.identity.irk = irk;
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
        pairing_data.peer_address = Address::new(kind, addr);

        if let Some(ref mut bond) = &mut pairing_data.bond_information {
            bond.identity.addr = Address::new(kind, addr);
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
            #[cfg(feature = "legacy-pairing")]
            16,
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
    use crate::security_manager::pairing::{Event, Input, PairingData};
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
        let mut pairing_ops: TestOps<10> = TestOps::new(0xDEAD);
        let mut pairing_data = make_default_pairing_data(
            Address::random([1, 2, 3, 4, 5, 6]),
            Address::random([7, 8, 9, 10, 11, 12]),
            IoCapabilities::NoInputNoOutput,
        );
        let mut pairing = Pairing::new();
        let mut rng: ChaCha12Rng = ChaCha12Core::seed_from_u64(1).into();
        // Central sends pairing request, expects pairing response from peripheral
        pairing
            .handle_input::<HeaplessPool, _, _>(
                Input::Command(Command::PairingRequest, &[0x03, 0, 0x08, 16, 0, 0]),
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
            .handle_input::<HeaplessPool, _, _>(
                Input::Command(Command::PairingPublicKey, packet.payload()),
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
                    21, 196, 108, 202, 69, 188, 69, 135, 69, 42, 164, 53, 225, 21, 133, 89, 26, 48, 111, 199, 227, 174,
                    133, 111, 21, 207, 26, 116, 100, 190, 159, 168, 98, 251, 173, 190, 122, 175, 196, 246, 214, 0, 91,
                    37, 138, 57, 110, 237, 171, 123, 98, 152, 198, 0, 252, 222, 53, 242, 184, 135, 125, 232, 8, 102
                ]
            );

            assert_eq!(sent_packets[2].command, Command::PairingConfirm);
            assert_eq!(
                sent_packets[2].payload(),
                &[60, 131, 200, 162, 116, 60, 118, 168, 186, 178, 89, 159, 38, 122, 197, 173]
            );
        }

        // Central sends Nonce, expects Nonce
        pairing
            .handle_input::<HeaplessPool, _, _>(
                Input::Command(
                    Command::PairingRandom,
                    &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                ),
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
            .handle_input::<HeaplessPool, _, _>(
                Input::Command(
                    Command::PairingDhKeyCheck,
                    &[
                        221, 215, 144, 142, 100, 9, 130, 242, 165, 163, 136, 234, 41, 58, 197, 162,
                    ],
                ),
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
                [33, 152, 76, 163, 246, 225, 149, 237, 16, 164, 28, 82, 252, 35, 196, 40]
            );
            assert_eq!(pairing_ops.encryptions.len(), 1);
            assert!(matches!(pairing_ops.encryptions[0], LongTermKey(_)));
        }
    }

    #[test]
    fn just_works_with_irk_distribution() {
        let mut pairing_ops: TestOps<10> = {
            let mut ops = TestOps::new(0xDEAD);
            ops.bondable = true;
            ops
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
            .handle_input::<HeaplessPool, _, _>(
                Input::Command(Command::PairingRequest, &pairing_request),
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
            .handle_input::<HeaplessPool, _, _>(
                Input::Command(Command::PairingPublicKey, packet.payload()),
                &mut pairing_data,
                &mut pairing_ops,
                &mut rng,
            )
            .unwrap();

        // Central sends Nonce, expects Nonce
        pairing
            .handle_input::<HeaplessPool, _, _>(
                Input::Command(
                    Command::PairingRandom,
                    &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                ),
                &mut pairing_data,
                &mut pairing_ops,
                &mut rng,
            )
            .unwrap();

        // Central sends DHKey Check, expects encrypted link
        pairing
            .handle_input::<HeaplessPool, _, _>(
                Input::Command(
                    Command::PairingDhKeyCheck,
                    &[
                        70, 123, 121, 123, 91, 126, 242, 102, 238, 164, 153, 99, 69, 175, 183, 215,
                    ],
                ),
                &mut pairing_data,
                &mut pairing_ops,
                &mut rng,
            )
            .unwrap();

        pairing
            .handle_input::<HeaplessPool, _, _>(
                Input::Event(Event::LinkEncryptedResult(true)),
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
            .handle_input::<HeaplessPool, _, _>(
                Input::Command(Command::IdentityInformation, &irk_data),
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
            .handle_input::<HeaplessPool, _, _>(
                Input::Command(Command::IdentityAddressInformation, &addr_data),
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
            assert_eq!(stored_irk.0.get(), u128::from_le_bytes(irk_data));

            assert_eq!(
                bond.identity.addr.addr,
                BdAddr::new([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC])
            );
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
                assert_eq!(bond_info.identity.irk.unwrap().0.get(), u128::from_le_bytes(irk_data));
            }
            _ => panic!("Unexpected connection event"),
        }
    }
}

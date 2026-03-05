use bt_hci::param::ConnHandle;
use embassy_time::Instant;
use rand_core::{CryptoRng, RngCore};

use self::util::PairingMethod;
use crate::connection::{ConnectionEvent, SecurityLevel};
use crate::security_manager::types::{BondingFlag, Command, PairingFeatures};
use crate::security_manager::TxPacket;
use crate::{Address, BondInformation, Error, IoCapabilities, LongTermKey, PacketPool};

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct PairingData {
    local_address: Address,
    peer_address: Address,
    local_features: PairingFeatures,
    peer_features: PairingFeatures,
    pairing_method: PairingMethod,
    timeout_at: Instant,
    bond_information: Option<BondInformation>,
}

impl PairingData {
    fn new(
        local_address: Address,
        peer_address: Address,
        local_io: IoCapabilities,
        timeout: embassy_time::Duration,
    ) -> PairingData {
        PairingData {
            local_address,
            peer_address,
            local_features: PairingFeatures {
                io_capabilities: local_io,
                ..Default::default()
            },
            peer_features: PairingFeatures::default(),
            pairing_method: PairingMethod::JustWorks,
            timeout_at: Instant::now() + timeout,
            bond_information: None,
        }
    }

    fn want_bonding(&self) -> bool {
        matches!(self.local_features.security_properties.bond(), BondingFlag::Bonding)
            && matches!(self.peer_features.security_properties.bond(), BondingFlag::Bonding)
    }
}

pub mod central;
#[cfg(feature = "legacy-pairing")]
pub mod legacy_central;
#[cfg(feature = "legacy-pairing")]
pub mod legacy_peripheral;
pub mod peripheral;
mod util;

pub(super) enum Input<'a> {
    Command(Command, &'a [u8]),
    Event(Event),
}

pub trait PairingOps<P: PacketPool> {
    fn try_send_packet(&mut self, packet: TxPacket<P>) -> Result<(), Error>;
    fn find_bond(&self) -> Option<BondInformation>;
    fn try_enable_bonded_encryption(&mut self) -> Result<Option<BondInformation>, Error>;
    fn try_enable_encryption(
        &mut self,
        ltk: &LongTermKey,
        security_level: SecurityLevel,
        is_bonded: bool,
        #[cfg(feature = "legacy-pairing")] ediv: u16,
        #[cfg(feature = "legacy-pairing")] rand: [u8; 8],
    ) -> Result<BondInformation, Error>;
    fn try_update_bond_information(&mut self, bond: &BondInformation) -> Result<(), Error>;
    fn connection_handle(&mut self) -> ConnHandle;
    fn try_send_connection_event(&mut self, event: ConnectionEvent) -> Result<(), Error>;
    fn bonding_flag(&self) -> BondingFlag;
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum State {
    Central(central::Pairing),
    Peripheral(peripheral::Pairing),
    #[cfg(feature = "legacy-pairing")]
    LegacyCentral(legacy_central::Pairing),
    #[cfg(feature = "legacy-pairing")]
    LegacyPeripheral(legacy_peripheral::Pairing),
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Pairing {
    pairing_data: PairingData,
    state: State,
}

impl Pairing {
    pub(crate) fn is_central(&self) -> bool {
        match &self.state {
            State::Central(_) => true,
            #[cfg(feature = "legacy-pairing")]
            State::LegacyCentral(_) => true,
            _ => false,
        }
    }

    #[cfg(feature = "legacy-pairing")]
    pub(crate) fn is_lesc_central(&self) -> bool {
        matches!(&self.state, State::Central(_))
    }

    #[cfg(feature = "legacy-pairing")]
    pub(crate) fn is_lesc_peripheral(&self) -> bool {
        matches!(&self.state, State::Peripheral(_))
    }

    pub(crate) fn result(&self) -> Option<Result<(), Error>> {
        match &self.state {
            State::Central(c) => c.result(),
            State::Peripheral(p) => p.result(),
            #[cfg(feature = "legacy-pairing")]
            State::LegacyCentral(c) => c.result(),
            #[cfg(feature = "legacy-pairing")]
            State::LegacyPeripheral(p) => p.result(),
        }
    }

    pub(crate) fn handle_l2cap_command<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        &mut self,
        command: Command,
        payload: &[u8],
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        self.handle_input(Input::Command(command, payload), ops, rng)
    }

    pub(crate) fn handle_event<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        &mut self,
        event: Event,
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        self.handle_input(Input::Event(event), ops, rng)
    }

    fn handle_input<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(
        &mut self,
        input: Input<'_>,
        ops: &mut OPS,
        rng: &mut RNG,
    ) -> Result<(), Error> {
        match &mut self.state {
            State::Central(central) => central.handle_input(input, &mut self.pairing_data, ops, rng),
            State::Peripheral(peripheral) => peripheral.handle_input(input, &mut self.pairing_data, ops, rng),
            #[cfg(feature = "legacy-pairing")]
            State::LegacyCentral(central) => central.handle_input(input, &mut self.pairing_data, ops, rng),
            #[cfg(feature = "legacy-pairing")]
            State::LegacyPeripheral(peripheral) => peripheral.handle_input(input, &mut self.pairing_data, ops, rng),
        }
    }

    pub(crate) fn security_level(&self) -> SecurityLevel {
        let is_encrypted = match &self.state {
            State::Central(c) => c.is_encrypted(),
            State::Peripheral(p) => p.is_encrypted(),
            #[cfg(feature = "legacy-pairing")]
            State::LegacyCentral(c) => c.is_encrypted(),
            #[cfg(feature = "legacy-pairing")]
            State::LegacyPeripheral(p) => p.is_encrypted(),
        };
        if is_encrypted {
            self.pairing_data
                .bond_information
                .as_ref()
                .map(|x| x.security_level)
                .unwrap_or(SecurityLevel::NoEncryption)
        } else {
            SecurityLevel::NoEncryption
        }
    }

    pub(crate) fn new_central(local_address: Address, peer_address: Address, local_io: IoCapabilities) -> Pairing {
        Pairing {
            pairing_data: PairingData::new(
                local_address,
                peer_address,
                local_io,
                crate::security_manager::constants::TIMEOUT_DISABLE,
            ),
            state: State::Central(central::Pairing::new_idle()),
        }
    }

    pub(crate) fn initiate_central<P: PacketPool, OPS: PairingOps<P>>(
        local_address: Address,
        peer_address: Address,
        ops: &mut OPS,
        local_io: IoCapabilities,
        user_initiated: bool,
    ) -> Result<Self, Error> {
        let mut pairing_data = PairingData::new(
            local_address,
            peer_address,
            local_io,
            crate::security_manager::constants::TIMEOUT_DISABLE,
        );
        let state = central::Pairing::initiate(&mut pairing_data, ops, user_initiated)?;
        pairing_data.timeout_at = Instant::now() + crate::security_manager::constants::TIMEOUT;
        Ok(Pairing {
            pairing_data,
            state: State::Central(state),
        })
    }

    pub(crate) fn new_peripheral(local_address: Address, peer_address: Address, local_io: IoCapabilities) -> Pairing {
        Pairing {
            pairing_data: PairingData::new(
                local_address,
                peer_address,
                local_io,
                crate::security_manager::constants::TIMEOUT,
            ),
            state: State::Peripheral(peripheral::Pairing::new()),
        }
    }

    #[cfg(feature = "legacy-pairing")]
    pub(crate) fn new_legacy_peripheral(
        local_address: Address,
        peer_address: Address,
        local_io: IoCapabilities,
    ) -> Pairing {
        Pairing {
            pairing_data: PairingData::new(
                local_address,
                peer_address,
                local_io,
                crate::security_manager::constants::TIMEOUT,
            ),
            state: State::LegacyPeripheral(legacy_peripheral::Pairing::new()),
        }
    }

    pub(crate) fn initiate_peripheral<P: PacketPool, OPS: PairingOps<P>>(
        local_address: Address,
        peer_address: Address,
        ops: &mut OPS,
        local_io: IoCapabilities,
        user_initiated: bool,
    ) -> Result<Self, Error> {
        let pairing_data = PairingData::new(
            local_address,
            peer_address,
            local_io,
            crate::security_manager::constants::TIMEOUT,
        );
        let state = peripheral::Pairing::initiate(&pairing_data, ops, user_initiated)?;
        Ok(Pairing {
            pairing_data,
            state: State::Peripheral(state),
        })
    }

    /// Switch from a LESC Central to a Legacy Central when the peer doesn't support SC.
    #[cfg(feature = "legacy-pairing")]
    pub(crate) fn switch_to_legacy_central(self) -> Result<Pairing, Error> {
        use crate::codec::Encode;

        let Pairing { pairing_data, state } = self;
        match state {
            State::Central(_) => {
                let mut preq = [0u8; 7];
                preq[0] = u8::from(Command::PairingRequest);
                pairing_data.local_features.encode(&mut preq[1..]).unwrap();
                Ok(Pairing {
                    pairing_data,
                    state: State::LegacyCentral(legacy_central::Pairing::from_lesc_switch(preq)),
                })
            }
            _ => Err(Error::InvalidState),
        }
    }

    /// Switch from a LESC Peripheral to a Legacy Peripheral when the peer doesn't support SC.
    #[cfg(feature = "legacy-pairing")]
    pub(crate) fn switch_to_legacy_peripheral(self) -> Result<Pairing, Error> {
        let Pairing { pairing_data, state } = self;
        match state {
            State::Peripheral(_) => Ok(Pairing {
                pairing_data,
                state: State::LegacyPeripheral(legacy_peripheral::Pairing::new()),
            }),
            _ => Err(Error::InvalidState),
        }
    }

    pub(crate) fn is_waiting_bonded_encryption(&self) -> bool {
        match &self.state {
            State::Central(c) => c.is_waiting_bonded_encryption(),
            _ => false,
        }
    }

    pub(crate) fn peer_address(&self) -> Address {
        self.pairing_data.peer_address
    }

    pub(crate) fn timeout_at(&self) -> Instant {
        if self.result().is_some() {
            Instant::now() + crate::security_manager::constants::TIMEOUT_DISABLE
        } else {
            self.pairing_data.timeout_at
        }
    }

    pub(crate) fn reset_timeout(&mut self) {
        self.pairing_data.timeout_at = Instant::now() + crate::security_manager::constants::TIMEOUT;
    }

    pub(crate) fn mark_timeout(&mut self) {
        match &mut self.state {
            State::Central(c) => c.mark_timeout(),
            State::Peripheral(p) => p.mark_timeout(),
            #[cfg(feature = "legacy-pairing")]
            State::LegacyCentral(c) => c.mark_timeout(),
            #[cfg(feature = "legacy-pairing")]
            State::LegacyPeripheral(p) => p.mark_timeout(),
        }
    }
}

pub enum Event {
    LinkEncryptedResult(bool),
    PassKeyConfirm,
    PassKeyCancel,
    PassKeyInput(u32),
}

#[cfg(test)]
mod tests {
    use rand_chacha::{ChaCha12Core, ChaCha12Rng};
    use rand_core::SeedableRng;

    use super::*;
    use crate::{Identity, Packet};

    #[derive(Debug)]
    pub(crate) struct TestPacket(pub(crate) heapless::Vec<u8, 128>);

    impl AsRef<[u8]> for TestPacket {
        fn as_ref(&self) -> &[u8] {
            self.0.as_slice()
        }
    }

    impl AsMut<[u8]> for TestPacket {
        fn as_mut(&mut self) -> &mut [u8] {
            self.0.as_mut_slice()
        }
    }

    impl Packet for TestPacket {}

    #[derive(Debug)]
    pub(crate) struct HeaplessPool;

    impl PacketPool for HeaplessPool {
        type Packet = TestPacket;
        const MTU: usize = 128;

        fn allocate() -> Option<Self::Packet> {
            let mut ret = TestPacket(heapless::Vec::new());
            ret.0.resize(Self::MTU, 0).unwrap();
            Some(ret)
        }

        fn capacity() -> usize {
            isize::MAX as usize
        }
    }

    #[derive(Default)]
    pub(crate) struct TestOps<const N: usize> {
        pub(crate) sent_packets: heapless::Vec<TxPacket<HeaplessPool>, N>,
        pub(crate) encryptions: heapless::Vec<LongTermKey, 10>,
        pub(crate) connection_events: heapless::Vec<ConnectionEvent, 10>,
        pub(crate) bond_information: Option<BondInformation>,
        pub(crate) bondable: bool,
    }

    impl<const N: usize> PairingOps<HeaplessPool> for TestOps<N> {
        fn try_send_packet(&mut self, packet: TxPacket<HeaplessPool>) -> Result<(), Error> {
            self.sent_packets.push(packet).map_err(|_| Error::OutOfMemory)
        }

        fn try_enable_encryption(
            &mut self,
            ltk: &LongTermKey,
            security_level: SecurityLevel,
            is_bonded: bool,
            #[cfg(feature = "legacy-pairing")] ediv: u16,
            #[cfg(feature = "legacy-pairing")] rand: [u8; 8],
        ) -> Result<BondInformation, Error> {
            self.encryptions.push(ltk.clone()).unwrap();
            Ok(BondInformation {
                security_level,
                identity: Identity::default(),
                ltk: ltk.clone(),
                is_bonded,
                #[cfg(feature = "legacy-pairing")]
                ediv,
                #[cfg(feature = "legacy-pairing")]
                rand,
            })
        }

        fn find_bond(&self) -> Option<BondInformation> {
            self.bond_information.clone()
        }

        fn try_enable_bonded_encryption(&mut self) -> Result<Option<BondInformation>, Error> {
            if let Some(bond) = &self.bond_information {
                self.encryptions.push(bond.ltk.clone()).unwrap();
                Ok(Some(bond.clone()))
            } else {
                Ok(None)
            }
        }

        fn try_update_bond_information(&mut self, bond: &BondInformation) -> Result<(), Error> {
            Ok(())
        }

        fn connection_handle(&mut self) -> ConnHandle {
            ConnHandle::new(2)
        }

        fn try_send_connection_event(&mut self, event: ConnectionEvent) -> Result<(), Error> {
            self.connection_events.push(event).unwrap();
            Ok(())
        }

        fn bonding_flag(&self) -> BondingFlag {
            if self.bondable {
                BondingFlag::Bonding
            } else {
                BondingFlag::NoBonding
            }
        }
    }

    #[test]
    fn just_works() {
        let peripheral = Address::random([0xff, 1, 2, 3, 4, 5]);
        let central = Address::random([0xff, 2, 2, 3, 4, 5]);

        let mut peripheral_ops = TestOps::<10>::default();
        let mut central_ops = TestOps::<10>::default();

        let mut peripheral_pairing = Pairing::new_peripheral(peripheral, central, IoCapabilities::NoInputNoOutput);
        let mut central_pairing = Pairing::initiate_central(
            central,
            peripheral,
            &mut central_ops,
            IoCapabilities::NoInputNoOutput,
            true,
        )
        .unwrap();

        let mut num_central_data_sent = 0;
        let mut num_peripheral_data_sent = 0;
        let mut rng: ChaCha12Rng = ChaCha12Core::seed_from_u64(1).into();
        transmit_packets(
            &mut peripheral_ops,
            &mut central_ops,
            &mut rng,
            &mut peripheral_pairing,
            &mut central_pairing,
            &mut num_central_data_sent,
            &mut num_peripheral_data_sent,
        );

        assert_eq!(central_ops.encryptions[0], peripheral_ops.encryptions[0]);
        central_pairing
            .handle_event(Event::LinkEncryptedResult(true), &mut central_ops, &mut rng)
            .unwrap();
        peripheral_pairing
            .handle_event(Event::LinkEncryptedResult(true), &mut peripheral_ops, &mut rng)
            .unwrap();

        assert!(matches!(
            central_ops.connection_events[0],
            ConnectionEvent::PairingComplete {
                security_level: SecurityLevel::Encrypted,
                bond: None
            }
        ));
        assert!(matches!(
            peripheral_ops.connection_events[0],
            ConnectionEvent::PairingComplete {
                security_level: SecurityLevel::Encrypted,
                bond: None
            }
        ));
        assert_eq!(central_pairing.security_level(), SecurityLevel::Encrypted);
        assert_eq!(peripheral_pairing.security_level(), SecurityLevel::Encrypted);
    }

    #[test]
    fn numeric_compare() {
        let peripheral = Address::random([0xff, 1, 2, 3, 4, 5]);
        let central = Address::random([0xff, 2, 2, 3, 4, 5]);

        let mut peripheral_ops = TestOps::<10>::default();
        let mut central_ops = TestOps::<10>::default();

        let mut peripheral_pairing = Pairing::new_peripheral(peripheral, central, IoCapabilities::DisplayYesNo);
        let mut central_pairing = Pairing::initiate_central(
            central,
            peripheral,
            &mut central_ops,
            IoCapabilities::DisplayYesNo,
            true,
        )
        .unwrap();

        let mut num_central_data_sent = 0;
        let mut num_peripheral_data_sent = 0;
        let mut rng: ChaCha12Rng = ChaCha12Core::seed_from_u64(1).into();
        transmit_packets(
            &mut peripheral_ops,
            &mut central_ops,
            &mut rng,
            &mut peripheral_pairing,
            &mut central_pairing,
            &mut num_central_data_sent,
            &mut num_peripheral_data_sent,
        );

        let (central_numeric, peripheral_numeric) = {
            let central = match &central_ops.connection_events[0] {
                ConnectionEvent::PassKeyConfirm(n) => n,
                _ => panic!("Unexpected connection event"),
            };

            let peripheral = match &peripheral_ops.connection_events[0] {
                ConnectionEvent::PassKeyConfirm(n) => n,
                _ => panic!("Unexpected connection event"),
            };

            (*central, *peripheral)
        };

        assert_eq!(central_numeric, peripheral_numeric);
        central_pairing
            .handle_event(Event::PassKeyConfirm, &mut central_ops, &mut rng)
            .unwrap();
        peripheral_pairing
            .handle_event(Event::PassKeyConfirm, &mut peripheral_ops, &mut rng)
            .unwrap();

        transmit_packets(
            &mut peripheral_ops,
            &mut central_ops,
            &mut rng,
            &mut peripheral_pairing,
            &mut central_pairing,
            &mut num_central_data_sent,
            &mut num_peripheral_data_sent,
        );

        assert_eq!(central_ops.encryptions[0], peripheral_ops.encryptions[0]);
        central_pairing
            .handle_event(Event::LinkEncryptedResult(true), &mut central_ops, &mut rng)
            .unwrap();
        peripheral_pairing
            .handle_event(Event::LinkEncryptedResult(true), &mut peripheral_ops, &mut rng)
            .unwrap();

        assert!(matches!(
            central_ops.connection_events[1],
            ConnectionEvent::PairingComplete {
                security_level: SecurityLevel::EncryptedAuthenticated,
                bond: None
            }
        ));
        assert!(matches!(
            peripheral_ops.connection_events[1],
            ConnectionEvent::PairingComplete {
                security_level: SecurityLevel::EncryptedAuthenticated,
                bond: None
            }
        ));
        assert_eq!(central_pairing.security_level(), SecurityLevel::EncryptedAuthenticated);
        assert_eq!(
            peripheral_pairing.security_level(),
            SecurityLevel::EncryptedAuthenticated
        );
    }

    #[test]
    fn pass_key_entry_keyboard_only() {
        let peripheral = Address::random([0xff, 1, 2, 3, 4, 5]);
        let central = Address::random([0xff, 2, 2, 3, 4, 5]);

        let mut peripheral_ops = TestOps::<80>::default();
        let mut central_ops = TestOps::<80>::default();

        let mut peripheral_pairing = Pairing::new_peripheral(peripheral, central, IoCapabilities::KeyboardOnly);
        let mut central_pairing = Pairing::initiate_central(
            central,
            peripheral,
            &mut central_ops,
            IoCapabilities::KeyboardOnly,
            true,
        )
        .unwrap();

        let mut num_central_data_sent = 0;
        let mut num_peripheral_data_sent = 0;
        let mut rng: ChaCha12Rng = ChaCha12Core::seed_from_u64(1).into();
        transmit_packets(
            &mut peripheral_ops,
            &mut central_ops,
            &mut rng,
            &mut peripheral_pairing,
            &mut central_pairing,
            &mut num_central_data_sent,
            &mut num_peripheral_data_sent,
        );

        assert!(matches!(
            central_ops.connection_events[0],
            ConnectionEvent::PassKeyInput
        ));
        assert!(matches!(
            peripheral_ops.connection_events[0],
            ConnectionEvent::PassKeyInput
        ));

        central_pairing
            .handle_event(Event::PassKeyInput(123456), &mut central_ops, &mut rng)
            .unwrap();
        peripheral_pairing
            .handle_event(Event::PassKeyInput(123456), &mut peripheral_ops, &mut rng)
            .unwrap();

        transmit_packets(
            &mut peripheral_ops,
            &mut central_ops,
            &mut rng,
            &mut peripheral_pairing,
            &mut central_pairing,
            &mut num_central_data_sent,
            &mut num_peripheral_data_sent,
        );

        assert_eq!(central_ops.encryptions[0], peripheral_ops.encryptions[0]);
        central_pairing
            .handle_event(Event::LinkEncryptedResult(true), &mut central_ops, &mut rng)
            .unwrap();
        peripheral_pairing
            .handle_event(Event::LinkEncryptedResult(true), &mut peripheral_ops, &mut rng)
            .unwrap();

        assert!(matches!(
            central_ops.connection_events[1],
            ConnectionEvent::PairingComplete {
                security_level: SecurityLevel::EncryptedAuthenticated,
                bond: None
            }
        ));
        assert!(matches!(
            peripheral_ops.connection_events[1],
            ConnectionEvent::PairingComplete {
                security_level: SecurityLevel::EncryptedAuthenticated,
                bond: None
            }
        ));
        assert_eq!(central_pairing.security_level(), SecurityLevel::EncryptedAuthenticated);
        assert_eq!(
            peripheral_pairing.security_level(),
            SecurityLevel::EncryptedAuthenticated
        );
    }

    #[test]
    fn pass_key_entry_peripheral_display() {
        let peripheral = Address::random([0xff, 1, 2, 3, 4, 5]);
        let central = Address::random([0xff, 2, 2, 3, 4, 5]);

        let mut peripheral_ops = TestOps::<80>::default();
        let mut central_ops = TestOps::<80>::default();

        let mut peripheral_pairing = Pairing::new_peripheral(peripheral, central, IoCapabilities::DisplayOnly);
        let mut central_pairing = Pairing::initiate_central(
            central,
            peripheral,
            &mut central_ops,
            IoCapabilities::KeyboardOnly,
            true,
        )
        .unwrap();

        let mut num_central_data_sent = 0;
        let mut num_peripheral_data_sent = 0;
        let mut rng: ChaCha12Rng = ChaCha12Core::seed_from_u64(1).into();
        transmit_packets(
            &mut peripheral_ops,
            &mut central_ops,
            &mut rng,
            &mut peripheral_pairing,
            &mut central_pairing,
            &mut num_central_data_sent,
            &mut num_peripheral_data_sent,
        );

        let pass_key = match &peripheral_ops.connection_events[0] {
            ConnectionEvent::PassKeyDisplay(pk) => *pk,
            _ => panic!("Unexpected connection event"),
        };

        assert!(matches!(
            central_ops.connection_events[0],
            ConnectionEvent::PassKeyInput
        ));

        central_pairing
            .handle_event(Event::PassKeyInput(pass_key.value()), &mut central_ops, &mut rng)
            .unwrap();

        transmit_packets(
            &mut peripheral_ops,
            &mut central_ops,
            &mut rng,
            &mut peripheral_pairing,
            &mut central_pairing,
            &mut num_central_data_sent,
            &mut num_peripheral_data_sent,
        );

        assert_eq!(central_ops.encryptions[0], peripheral_ops.encryptions[0]);
        central_pairing
            .handle_event(Event::LinkEncryptedResult(true), &mut central_ops, &mut rng)
            .unwrap();
        peripheral_pairing
            .handle_event(Event::LinkEncryptedResult(true), &mut peripheral_ops, &mut rng)
            .unwrap();

        assert!(matches!(
            central_ops.connection_events[1],
            ConnectionEvent::PairingComplete {
                security_level: SecurityLevel::EncryptedAuthenticated,
                bond: None
            }
        ));
        assert!(matches!(
            peripheral_ops.connection_events[1],
            ConnectionEvent::PairingComplete {
                security_level: SecurityLevel::EncryptedAuthenticated,
                bond: None
            }
        ));
        assert_eq!(central_pairing.security_level(), SecurityLevel::EncryptedAuthenticated);
        assert_eq!(
            peripheral_pairing.security_level(),
            SecurityLevel::EncryptedAuthenticated
        );
    }

    #[test]
    fn pass_key_entry_central_display() {
        let peripheral = Address::random([0xff, 1, 2, 3, 4, 5]);
        let central = Address::random([0xff, 2, 2, 3, 4, 5]);

        let mut peripheral_ops = TestOps::<80>::default();
        let mut central_ops = TestOps::<80>::default();

        let mut peripheral_pairing = Pairing::new_peripheral(peripheral, central, IoCapabilities::KeyboardOnly);
        let mut central_pairing =
            Pairing::initiate_central(central, peripheral, &mut central_ops, IoCapabilities::DisplayOnly, true)
                .unwrap();

        let mut num_central_data_sent = 0;
        let mut num_peripheral_data_sent = 0;
        let mut rng: ChaCha12Rng = ChaCha12Core::seed_from_u64(1).into();
        transmit_packets(
            &mut peripheral_ops,
            &mut central_ops,
            &mut rng,
            &mut peripheral_pairing,
            &mut central_pairing,
            &mut num_central_data_sent,
            &mut num_peripheral_data_sent,
        );

        let pass_key = match &central_ops.connection_events[0] {
            ConnectionEvent::PassKeyDisplay(pk) => *pk,
            _ => panic!("Unexpected connection event"),
        };

        assert!(matches!(
            peripheral_ops.connection_events[0],
            ConnectionEvent::PassKeyInput
        ));

        peripheral_pairing
            .handle_event(Event::PassKeyInput(pass_key.value()), &mut peripheral_ops, &mut rng)
            .unwrap();

        transmit_packets(
            &mut peripheral_ops,
            &mut central_ops,
            &mut rng,
            &mut peripheral_pairing,
            &mut central_pairing,
            &mut num_central_data_sent,
            &mut num_peripheral_data_sent,
        );

        assert_eq!(central_ops.encryptions[0], peripheral_ops.encryptions[0]);
        central_pairing
            .handle_event(Event::LinkEncryptedResult(true), &mut central_ops, &mut rng)
            .unwrap();
        peripheral_pairing
            .handle_event(Event::LinkEncryptedResult(true), &mut peripheral_ops, &mut rng)
            .unwrap();

        assert!(matches!(
            central_ops.connection_events[1],
            ConnectionEvent::PairingComplete {
                security_level: SecurityLevel::EncryptedAuthenticated,
                bond: None
            }
        ));
        assert!(matches!(
            peripheral_ops.connection_events[1],
            ConnectionEvent::PairingComplete {
                security_level: SecurityLevel::EncryptedAuthenticated,
                bond: None
            }
        ));
        assert_eq!(central_pairing.security_level(), SecurityLevel::EncryptedAuthenticated);
        assert_eq!(
            peripheral_pairing.security_level(),
            SecurityLevel::EncryptedAuthenticated
        );
    }

    #[test]
    fn bondable_just_works() {
        let peripheral = Address::random([0xff, 1, 2, 3, 4, 5]);
        let central = Address::random([0xff, 2, 2, 3, 4, 5]);

        let mut peripheral_ops = TestOps::<80>::default();
        let mut central_ops = TestOps::<80>::default();
        peripheral_ops.bondable = true;
        central_ops.bondable = true;

        let mut peripheral_pairing = Pairing::new_peripheral(peripheral, central, IoCapabilities::NoInputNoOutput);
        let mut central_pairing = Pairing::initiate_central(
            central,
            peripheral,
            &mut central_ops,
            IoCapabilities::NoInputNoOutput,
            true,
        )
        .unwrap();

        let mut num_central_data_sent = 0;
        let mut num_peripheral_data_sent = 0;
        let mut rng: ChaCha12Rng = ChaCha12Core::seed_from_u64(1).into();
        transmit_packets(
            &mut peripheral_ops,
            &mut central_ops,
            &mut rng,
            &mut peripheral_pairing,
            &mut central_pairing,
            &mut num_central_data_sent,
            &mut num_peripheral_data_sent,
        );

        assert_eq!(central_ops.encryptions[0], peripheral_ops.encryptions[0]);
        central_pairing
            .handle_event(Event::LinkEncryptedResult(true), &mut central_ops, &mut rng)
            .unwrap();
        peripheral_pairing
            .handle_event(Event::LinkEncryptedResult(true), &mut peripheral_ops, &mut rng)
            .unwrap();

        assert!(matches!(
            central_ops.connection_events[0],
            ConnectionEvent::PairingComplete {
                security_level: SecurityLevel::Encrypted,
                bond: Some(BondInformation {
                    is_bonded: true,
                    security_level: SecurityLevel::Encrypted,
                    ..
                })
            }
        ));
        assert!(matches!(
            peripheral_ops.connection_events[0],
            ConnectionEvent::PairingComplete {
                security_level: SecurityLevel::Encrypted,
                bond: Some(BondInformation {
                    is_bonded: true,
                    security_level: SecurityLevel::Encrypted,
                    ..
                })
            }
        ));
        assert_eq!(central_pairing.security_level(), SecurityLevel::Encrypted);
        assert_eq!(peripheral_pairing.security_level(), SecurityLevel::Encrypted);
    }

    #[test]
    fn bonded_central_initiates() {
        let peripheral = Address::random([0xff, 1, 2, 3, 4, 5]);
        let central = Address::random([0xff, 2, 2, 3, 4, 5]);

        let mut peripheral_ops = TestOps::<80>::default();
        let mut central_ops = TestOps::<80>::default();
        central_ops.bond_information = Some(BondInformation {
            security_level: SecurityLevel::EncryptedAuthenticated,
            is_bonded: true,
            ltk: LongTermKey(1),
            identity: Identity {
                irk: None,
                bd_addr: peripheral.addr,
            },
            #[cfg(feature = "legacy-pairing")]
            ediv: 0,
            #[cfg(feature = "legacy-pairing")]
            rand: [0; 8],
        });

        peripheral_ops.bond_information = Some(BondInformation {
            security_level: SecurityLevel::EncryptedAuthenticated,
            is_bonded: true,
            ltk: LongTermKey(1),
            identity: Identity {
                irk: None,
                bd_addr: central.addr,
            },
            #[cfg(feature = "legacy-pairing")]
            ediv: 0,
            #[cfg(feature = "legacy-pairing")]
            rand: [0; 8],
        });

        let mut rng: ChaCha12Rng = ChaCha12Core::seed_from_u64(1).into();

        let mut peripheral_pairing = Pairing::new_peripheral(peripheral, central, IoCapabilities::NoInputNoOutput);
        let mut central_pairing = Pairing::initiate_central(
            central,
            peripheral,
            &mut central_ops,
            IoCapabilities::NoInputNoOutput,
            true,
        )
        .unwrap();
        assert_eq!(central_ops.sent_packets.len(), 0);
        assert_eq!(peripheral_ops.sent_packets.len(), 0);
        assert_eq!(central_ops.encryptions.len(), 1);
        assert_eq!(central_ops.encryptions[0], LongTermKey(1));

        central_pairing
            .handle_event(Event::LinkEncryptedResult(true), &mut central_ops, &mut rng)
            .unwrap();
        peripheral_pairing
            .handle_event(Event::LinkEncryptedResult(true), &mut peripheral_ops, &mut rng)
            .unwrap();

        assert!(matches!(
            central_ops.connection_events[0],
            ConnectionEvent::PairingComplete {
                security_level: SecurityLevel::EncryptedAuthenticated,
                bond: None
            }
        ));
        assert!(matches!(
            peripheral_ops.connection_events[0],
            ConnectionEvent::PairingComplete {
                security_level: SecurityLevel::EncryptedAuthenticated,
                bond: None
            }
        ));
        assert_eq!(central_ops.connection_events.len(), 1);
        assert_eq!(peripheral_ops.connection_events.len(), 1);
        assert_eq!(central_pairing.security_level(), SecurityLevel::EncryptedAuthenticated);
        assert_eq!(
            peripheral_pairing.security_level(),
            SecurityLevel::EncryptedAuthenticated
        );
    }

    #[test]
    fn bonded_peripheral_initiates() {
        let peripheral = Address::random([0xff, 1, 2, 3, 4, 5]);
        let central = Address::random([0xff, 2, 2, 3, 4, 5]);

        let mut peripheral_ops = TestOps::<80>::default();
        let mut central_ops = TestOps::<80>::default();
        central_ops.bond_information = Some(BondInformation {
            security_level: SecurityLevel::EncryptedAuthenticated,
            is_bonded: true,
            ltk: LongTermKey(1),
            identity: Identity {
                irk: None,
                bd_addr: peripheral.addr,
            },
            #[cfg(feature = "legacy-pairing")]
            ediv: 0,
            #[cfg(feature = "legacy-pairing")]
            rand: [0; 8],
        });

        peripheral_ops.bond_information = Some(BondInformation {
            security_level: SecurityLevel::EncryptedAuthenticated,
            is_bonded: true,
            ltk: LongTermKey(1),
            identity: Identity {
                irk: None,
                bd_addr: central.addr,
            },
            #[cfg(feature = "legacy-pairing")]
            ediv: 0,
            #[cfg(feature = "legacy-pairing")]
            rand: [0; 8],
        });

        let mut rng: ChaCha12Rng = ChaCha12Core::seed_from_u64(1).into();

        let mut peripheral_pairing = Pairing::initiate_peripheral(
            peripheral,
            central,
            &mut peripheral_ops,
            IoCapabilities::NoInputNoOutput,
            false,
        )
        .unwrap();
        let mut central_pairing = Pairing::new_central(central, peripheral, IoCapabilities::NoInputNoOutput);

        let mut num_central_data_sent = 0;
        let mut num_peripheral_data_sent = 0;
        transmit_packets(
            &mut peripheral_ops,
            &mut central_ops,
            &mut rng,
            &mut peripheral_pairing,
            &mut central_pairing,
            &mut num_central_data_sent,
            &mut num_peripheral_data_sent,
        );

        assert_eq!(central_ops.sent_packets.len(), 0);
        assert_eq!(peripheral_ops.sent_packets.len(), 1);
        assert_eq!(central_ops.encryptions.len(), 1);
        assert_eq!(central_ops.encryptions[0], LongTermKey(1));

        central_pairing
            .handle_event(Event::LinkEncryptedResult(true), &mut central_ops, &mut rng)
            .unwrap();
        peripheral_pairing
            .handle_event(Event::LinkEncryptedResult(true), &mut peripheral_ops, &mut rng)
            .unwrap();

        assert!(matches!(
            central_ops.connection_events[0],
            ConnectionEvent::PairingComplete {
                security_level: SecurityLevel::EncryptedAuthenticated,
                bond: None
            }
        ));
        assert!(matches!(
            peripheral_ops.connection_events[0],
            ConnectionEvent::PairingComplete {
                security_level: SecurityLevel::EncryptedAuthenticated,
                bond: None
            }
        ));
        assert_eq!(central_ops.connection_events.len(), 1);
        assert_eq!(peripheral_ops.connection_events.len(), 1);
        assert_eq!(central_pairing.security_level(), SecurityLevel::EncryptedAuthenticated);
        assert_eq!(
            peripheral_pairing.security_level(),
            SecurityLevel::EncryptedAuthenticated
        );
    }

    fn transmit_packets<const N: usize>(
        peripheral_ops: &mut TestOps<N>,
        central_ops: &mut TestOps<N>,
        rng: &mut ChaCha12Rng,
        peripheral_pairing: &mut Pairing,
        central_pairing: &mut Pairing,
        num_central_data_sent: &mut usize,
        num_peripheral_data_sent: &mut usize,
    ) {
        let mut loop_count = 0;
        loop {
            let saved_num_central_data_sent = *num_central_data_sent;
            let saved_num_peripheral_data_sent = *num_peripheral_data_sent;

            while *num_central_data_sent < central_ops.sent_packets.len() {
                peripheral_pairing
                    .handle_l2cap_command(
                        central_ops.sent_packets[*num_central_data_sent].command,
                        central_ops.sent_packets[*num_central_data_sent].payload(),
                        peripheral_ops,
                        rng,
                    )
                    .unwrap();
                *num_central_data_sent += 1;
            }

            while *num_peripheral_data_sent < peripheral_ops.sent_packets.len() {
                central_pairing
                    .handle_l2cap_command(
                        peripheral_ops.sent_packets[*num_peripheral_data_sent].command,
                        peripheral_ops.sent_packets[*num_peripheral_data_sent].payload(),
                        central_ops,
                        rng,
                    )
                    .unwrap();
                *num_peripheral_data_sent += 1;
            }

            if saved_num_central_data_sent == *num_central_data_sent
                && saved_num_peripheral_data_sent == *num_peripheral_data_sent
            {
                break;
            }

            loop_count += 1;
            if loop_count > 10000 {
                panic!("Too many loops");
            }
        }
    }
}

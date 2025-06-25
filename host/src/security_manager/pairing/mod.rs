use bt_hci::param::ConnHandle;
use embassy_time::Instant;
use rand_core::{CryptoRng, RngCore};
use crate::{Address, Error, IoCapabilities, LongTermKey, PacketPool};
use crate::connection::{ConnectionEvent, SecurityLevel};
use crate::security_manager::{TxPacket};
use crate::security_manager::types::Command;

pub mod peripheral;
pub mod central;
// pub mod central;
mod util;

pub trait PairingOps<P: PacketPool> {
    fn try_send_packet(&mut self, packet: TxPacket<P>) -> Result<(), Error>;
    fn try_enable_encryption(&mut self, ltk: &LongTermKey) -> Result<(), Error>;
    fn connection_handle(&mut self) -> ConnHandle;
    fn try_send_connection_event(&mut self, event: ConnectionEvent) -> Result<(), Error>;
}

pub enum Pairing {
    Central(central::Pairing),
    Peripheral(peripheral::Pairing),
}

impl Pairing {
    pub(crate) fn is_central(&self) -> bool {
        matches!(self, Pairing::Central(_))
    }
    pub(crate) fn handle_l2cap_command<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(&self, command: Command, payload: &[u8], ops: &mut OPS, rng: &mut RNG) -> Result<(), Error> {
        match self {
            Pairing::Central(central) => central.handle_l2cap_command(command, payload, ops, rng),
            Pairing::Peripheral(peripheral) => peripheral.handle_l2cap_command(command, payload, ops, rng),
        }
    }

    pub(crate) fn handle_event<P: PacketPool, OPS: PairingOps<P>, RNG: CryptoRng + RngCore>(&self, event: Event, ops: &mut OPS, rng: &mut RNG) -> Result<(), Error> {
        match self {
            Pairing::Central(central) => central.handle_event(event, ops, rng),
            Pairing::Peripheral(peripheral) => peripheral.handle_event(event, ops, rng),
        }
    }

    pub(crate) fn security_level(&self) -> SecurityLevel {
        match self {
            Pairing::Central(c) => c.security_level(),
            Pairing::Peripheral(p) => p.security_level(),
        }
    }
    pub(crate) fn new_central(local_address: Address, peer_address: Address, local_io: IoCapabilities) -> Pairing {
        Pairing::Central(central::Pairing::new_idle(local_address, peer_address, local_io))
    }

    pub(crate) fn initiate_central<P: PacketPool, OPS: PairingOps<P>>(local_address: Address, peer_address: Address,
                                                                      ops: &mut OPS, local_io: IoCapabilities) -> Result<Self, Error> {
        Ok(Pairing::Central(central::Pairing::initiate(local_address, peer_address, ops, local_io)?))
    }

    pub(crate) fn new_peripheral(local_address: Address, peer_address: Address, local_io: IoCapabilities) -> Pairing {
        Pairing::Peripheral(peripheral::Pairing::new(local_address, peer_address, local_io))
    }

    pub(crate) fn initiate_peripheral<P: PacketPool, OPS: PairingOps<P>>(local_address: Address, peer_address: Address,
                                                                      ops: &mut OPS, local_io: IoCapabilities) -> Result<Self, Error> {
        Ok(Pairing::Peripheral(peripheral::Pairing::initiate(local_address, peer_address, ops, local_io)?))
    }

    pub(crate) fn peer_address(&self) -> Address {
        match self {
            Pairing::Central(central) => central.peer_address(),
            Pairing::Peripheral(per) => per.peer_address(),
        }
    }

    pub(crate) fn timeout_at(&self) -> Instant {
        match self {
            Pairing::Central(c) => c.timeout_at(),
            Pairing::Peripheral(p) => p.timeout_at(),
        }
    }

    pub(crate) fn reset_timeout(&self) {
        match self {
            Pairing::Central(c) => c.reset_timeout(),
            Pairing::Peripheral(p) => p.reset_timeout(),
        }
    }

    pub(crate) fn mark_timeout(&self) {
        match self {
            Pairing::Central(c) => c.mark_timeout(),
            Pairing::Peripheral(p) => p.mark_timeout(),
        }
    }
}

pub enum Event {
    LinkEncrypted,
    PassKeyConfirm,
    PassKeyCancel,
    PassKeyInput(u32),
}

#[cfg(test)]
mod tests {
    use rand_chacha::{ChaCha12Core, ChaCha12Rng};
    use rand_core::SeedableRng;
    use crate::Packet;
    use super::*;

    #[derive(Debug)]
    pub(crate) struct TestPacket(pub(crate)heapless::Vec<u8, 128>);

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
    }

    impl<const N: usize> PairingOps<HeaplessPool> for TestOps<N> {
        fn try_send_packet(&mut self, packet: TxPacket<HeaplessPool>) -> Result<(), Error> {
            self.sent_packets.push(packet).map_err(|_| Error::OutOfMemory)
        }

        fn try_enable_encryption(&mut self, ltk: &LongTermKey) -> Result<(), Error> {
            self.encryptions.push(ltk.clone()).unwrap();
            Ok(())
        }

        fn connection_handle(&mut self) -> ConnHandle {
            ConnHandle::new(2)
        }

        fn try_send_connection_event(&mut self, event: ConnectionEvent) -> Result<(), Error> {
            self.connection_events.push(event).unwrap();
            Ok(())
        }
    }

    #[test]
    fn just_works() {
        let peripheral = Address::random([0xff, 1, 2, 3, 4, 5]);
        let central = Address::random([0xff, 2, 2, 3, 4, 5]);

        let mut peripheral_ops = TestOps::<10>::default();
        let mut central_ops = TestOps::<10>::default();

        let peripheral_pairing = peripheral::Pairing::new(peripheral, central, IoCapabilities::NoInputNoOutput);
        let central_pairing = central::Pairing::initiate(central, peripheral, &mut central_ops, IoCapabilities::NoInputNoOutput).unwrap();

        let mut num_central_data_sent = 0;
        let mut num_peripheral_data_sent = 0;
        let mut rng: ChaCha12Rng = ChaCha12Core::seed_from_u64(1).into();
        let mut loop_cnt = 0;
        while peripheral_ops.encryptions.is_empty() || central_ops.encryptions.is_empty() {
            while num_central_data_sent < central_ops.sent_packets.len() {
                peripheral_pairing.handle_l2cap_command(central_ops.sent_packets[num_central_data_sent].command, central_ops.sent_packets[num_central_data_sent].payload(), &mut peripheral_ops, &mut rng).unwrap();
                num_central_data_sent += 1;
            }

            while num_peripheral_data_sent < peripheral_ops.sent_packets.len() {
                central_pairing.handle_l2cap_command(peripheral_ops.sent_packets[num_peripheral_data_sent].command, peripheral_ops.sent_packets[num_peripheral_data_sent].payload(), &mut central_ops, &mut rng).unwrap();
                num_peripheral_data_sent += 1;
            }

            loop_cnt += 1;
            if loop_cnt > 10000 {
                break;
            }
        }

        assert_eq!(central_ops.encryptions[0], peripheral_ops.encryptions[0]);
        central_pairing.handle_event(Event::LinkEncrypted, &mut central_ops, &mut rng).unwrap();
        peripheral_pairing.handle_event(Event::LinkEncrypted, &mut peripheral_ops, &mut rng).unwrap();

        assert!(matches!(central_ops.connection_events[0], ConnectionEvent::PairingComplete(_)));
        assert!(matches!(peripheral_ops.connection_events[0], ConnectionEvent::PairingComplete(_)));
    }

    #[test]
    fn numeric_compare() {
        let peripheral = Address::random([0xff, 1, 2, 3, 4, 5]);
        let central = Address::random([0xff, 2, 2, 3, 4, 5]);

        let mut peripheral_ops = TestOps::<10>::default();
        let mut central_ops = TestOps::<10>::default();

        let peripheral_pairing = peripheral::Pairing::new(peripheral, central, IoCapabilities::DisplayYesNo);
        let central_pairing = central::Pairing::initiate(central, peripheral, &mut central_ops, IoCapabilities::DisplayYesNo).unwrap();

        let mut num_central_data_sent = 0;
        let mut num_peripheral_data_sent = 0;
        let mut rng: ChaCha12Rng = ChaCha12Core::seed_from_u64(1).into();
        let mut loop_cnt = 0;
        while peripheral_ops.connection_events.is_empty() || central_ops.connection_events.is_empty() {
            while num_central_data_sent < central_ops.sent_packets.len() {
                peripheral_pairing.handle_l2cap_command(central_ops.sent_packets[num_central_data_sent].command, central_ops.sent_packets[num_central_data_sent].payload(), &mut peripheral_ops, &mut rng).unwrap();
                num_central_data_sent += 1;
            }

            while num_peripheral_data_sent < peripheral_ops.sent_packets.len() {
                central_pairing.handle_l2cap_command(peripheral_ops.sent_packets[num_peripheral_data_sent].command, peripheral_ops.sent_packets[num_peripheral_data_sent].payload(), &mut central_ops, &mut rng).unwrap();
                num_peripheral_data_sent += 1;
            }

            loop_cnt += 1;
            if loop_cnt > 10000 {
                panic!("Too many loops");
            }
        }

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
        central_pairing.handle_event(Event::PassKeyConfirm, &mut central_ops, &mut rng).unwrap();
        peripheral_pairing.handle_event(Event::PassKeyConfirm, &mut peripheral_ops, &mut rng).unwrap();

        while peripheral_ops.encryptions.is_empty() || central_ops.encryptions.is_empty() {
            while num_central_data_sent < central_ops.sent_packets.len() {
                peripheral_pairing.handle_l2cap_command(central_ops.sent_packets[num_central_data_sent].command, central_ops.sent_packets[num_central_data_sent].payload(), &mut peripheral_ops, &mut rng).unwrap();
                num_central_data_sent += 1;
            }

            while num_peripheral_data_sent < peripheral_ops.sent_packets.len() {
                central_pairing.handle_l2cap_command(peripheral_ops.sent_packets[num_peripheral_data_sent].command, peripheral_ops.sent_packets[num_peripheral_data_sent].payload(), &mut central_ops, &mut rng).unwrap();
                num_peripheral_data_sent += 1;
            }

            loop_cnt += 1;
            if loop_cnt > 10000 {
                panic!("Too many loops");
            }
        }

        assert_eq!(central_ops.encryptions[0], peripheral_ops.encryptions[0]);
        central_pairing.handle_event(Event::LinkEncrypted, &mut central_ops, &mut rng).unwrap();
        peripheral_pairing.handle_event(Event::LinkEncrypted, &mut peripheral_ops, &mut rng).unwrap();

        assert!(matches!(central_ops.connection_events[1], ConnectionEvent::PairingComplete(_)));
        assert!(matches!(peripheral_ops.connection_events[1], ConnectionEvent::PairingComplete(_)));
    }

    #[test]
    fn pass_key_entry_keyboard_only() {
        let peripheral = Address::random([0xff, 1, 2, 3, 4, 5]);
        let central = Address::random([0xff, 2, 2, 3, 4, 5]);

        let mut peripheral_ops = TestOps::<80>::default();
        let mut central_ops = TestOps::<80>::default();

        let peripheral_pairing = peripheral::Pairing::new(peripheral, central, IoCapabilities::KeyboardOnly);
        let central_pairing = central::Pairing::initiate(central, peripheral, &mut central_ops, IoCapabilities::KeyboardOnly).unwrap();

        let mut num_central_data_sent = 0;
        let mut num_peripheral_data_sent = 0;
        let mut rng: ChaCha12Rng = ChaCha12Core::seed_from_u64(1).into();
        let mut loop_cnt = 0;
        while peripheral_ops.connection_events.is_empty() || central_ops.connection_events.is_empty() {
            while num_central_data_sent < central_ops.sent_packets.len() {
                peripheral_pairing.handle_l2cap_command(central_ops.sent_packets[num_central_data_sent].command, central_ops.sent_packets[num_central_data_sent].payload(), &mut peripheral_ops, &mut rng).unwrap();
                num_central_data_sent += 1;
            }

            while num_peripheral_data_sent < peripheral_ops.sent_packets.len() {
                central_pairing.handle_l2cap_command(peripheral_ops.sent_packets[num_peripheral_data_sent].command, peripheral_ops.sent_packets[num_peripheral_data_sent].payload(), &mut central_ops, &mut rng).unwrap();
                num_peripheral_data_sent += 1;
            }

            loop_cnt += 1;
            if loop_cnt > 10000 {
                panic!("Too many loops in first loop");
            }
        }

        assert!(matches!(central_ops.connection_events[0], ConnectionEvent::PassKeyInput));
        assert!(matches!(peripheral_ops.connection_events[0], ConnectionEvent::PassKeyInput));

        central_pairing.handle_event(Event::PassKeyInput(123456), &mut central_ops, &mut rng).unwrap();
        peripheral_pairing.handle_event(Event::PassKeyInput(123456), &mut peripheral_ops, &mut rng).unwrap();

        while peripheral_ops.encryptions.is_empty() || central_ops.encryptions.is_empty() {
            while num_central_data_sent < central_ops.sent_packets.len() {
                peripheral_pairing.handle_l2cap_command(central_ops.sent_packets[num_central_data_sent].command, central_ops.sent_packets[num_central_data_sent].payload(), &mut peripheral_ops, &mut rng).unwrap();
                num_central_data_sent += 1;
            }

            while num_peripheral_data_sent < peripheral_ops.sent_packets.len() {
                central_pairing.handle_l2cap_command(peripheral_ops.sent_packets[num_peripheral_data_sent].command, peripheral_ops.sent_packets[num_peripheral_data_sent].payload(), &mut central_ops, &mut rng).unwrap();
                num_peripheral_data_sent += 1;
            }

            loop_cnt += 1;
            if loop_cnt > 20000 {
                panic!("Too many loops in second loop");
            }
        }

        assert_eq!(central_ops.encryptions[0], peripheral_ops.encryptions[0]);
        central_pairing.handle_event(Event::LinkEncrypted, &mut central_ops, &mut rng).unwrap();
        peripheral_pairing.handle_event(Event::LinkEncrypted, &mut peripheral_ops, &mut rng).unwrap();

        assert!(matches!(central_ops.connection_events[1], ConnectionEvent::PairingComplete(_)));
        assert!(matches!(peripheral_ops.connection_events[1], ConnectionEvent::PairingComplete(_)));
    }

    #[test]
    fn pass_key_entry_peripheral_display() {
        let peripheral = Address::random([0xff, 1, 2, 3, 4, 5]);
        let central = Address::random([0xff, 2, 2, 3, 4, 5]);

        let mut peripheral_ops = TestOps::<80>::default();
        let mut central_ops = TestOps::<80>::default();

        let peripheral_pairing = peripheral::Pairing::new(peripheral, central, IoCapabilities::DisplayOnly);
        let central_pairing = central::Pairing::initiate(central, peripheral, &mut central_ops, IoCapabilities::KeyboardOnly).unwrap();

        let mut num_central_data_sent = 0;
        let mut num_peripheral_data_sent = 0;
        let mut rng: ChaCha12Rng = ChaCha12Core::seed_from_u64(1).into();
        let mut loop_cnt = 0;
        while peripheral_ops.connection_events.is_empty() || central_ops.connection_events.is_empty() {
            while num_central_data_sent < central_ops.sent_packets.len() {
                peripheral_pairing.handle_l2cap_command(central_ops.sent_packets[num_central_data_sent].command, central_ops.sent_packets[num_central_data_sent].payload(), &mut peripheral_ops, &mut rng).unwrap();
                num_central_data_sent += 1;
            }

            while num_peripheral_data_sent < peripheral_ops.sent_packets.len() {
                central_pairing.handle_l2cap_command(peripheral_ops.sent_packets[num_peripheral_data_sent].command, peripheral_ops.sent_packets[num_peripheral_data_sent].payload(), &mut central_ops, &mut rng).unwrap();
                num_peripheral_data_sent += 1;
            }

            loop_cnt += 1;
            if loop_cnt > 10000 {
                panic!("Too many loops in first loop");
            }
        }

        let pass_key = match &peripheral_ops.connection_events[0] {
            ConnectionEvent::PassKeyDisplay(pk) => *pk,
            _ => panic!("Unexpected connection event"),
        };

        assert!(matches!(central_ops.connection_events[0], ConnectionEvent::PassKeyInput));

        central_pairing.handle_event(Event::PassKeyInput(pass_key.value()), &mut central_ops, &mut rng).unwrap();

        while peripheral_ops.encryptions.is_empty() || central_ops.encryptions.is_empty() {
            while num_central_data_sent < central_ops.sent_packets.len() {
                peripheral_pairing.handle_l2cap_command(central_ops.sent_packets[num_central_data_sent].command, central_ops.sent_packets[num_central_data_sent].payload(), &mut peripheral_ops, &mut rng).unwrap();
                num_central_data_sent += 1;
            }

            while num_peripheral_data_sent < peripheral_ops.sent_packets.len() {
                central_pairing.handle_l2cap_command(peripheral_ops.sent_packets[num_peripheral_data_sent].command, peripheral_ops.sent_packets[num_peripheral_data_sent].payload(), &mut central_ops, &mut rng).unwrap();
                num_peripheral_data_sent += 1;
            }

            loop_cnt += 1;
            if loop_cnt > 20000 {
                panic!("Too many loops in second loop");
            }
        }

        assert_eq!(central_ops.encryptions[0], peripheral_ops.encryptions[0]);
        central_pairing.handle_event(Event::LinkEncrypted, &mut central_ops, &mut rng).unwrap();
        peripheral_pairing.handle_event(Event::LinkEncrypted, &mut peripheral_ops, &mut rng).unwrap();

        assert!(matches!(central_ops.connection_events[1], ConnectionEvent::PairingComplete(_)));
        assert!(matches!(peripheral_ops.connection_events[1], ConnectionEvent::PairingComplete(_)));
    }

    #[test]
    fn pass_key_entry_central_display() {
        let peripheral = Address::random([0xff, 1, 2, 3, 4, 5]);
        let central = Address::random([0xff, 2, 2, 3, 4, 5]);

        let mut peripheral_ops = TestOps::<80>::default();
        let mut central_ops = TestOps::<80>::default();

        let peripheral_pairing = peripheral::Pairing::new(peripheral, central, IoCapabilities::KeyboardOnly);
        let central_pairing = central::Pairing::initiate(central, peripheral, &mut central_ops, IoCapabilities::DisplayOnly).unwrap();

        let mut num_central_data_sent = 0;
        let mut num_peripheral_data_sent = 0;
        let mut rng: ChaCha12Rng = ChaCha12Core::seed_from_u64(1).into();
        let mut loop_cnt = 0;
        while peripheral_ops.connection_events.is_empty() || central_ops.connection_events.is_empty() {
            while num_central_data_sent < central_ops.sent_packets.len() {
                peripheral_pairing.handle_l2cap_command(central_ops.sent_packets[num_central_data_sent].command, central_ops.sent_packets[num_central_data_sent].payload(), &mut peripheral_ops, &mut rng).unwrap();
                num_central_data_sent += 1;
            }

            while num_peripheral_data_sent < peripheral_ops.sent_packets.len() {
                central_pairing.handle_l2cap_command(peripheral_ops.sent_packets[num_peripheral_data_sent].command, peripheral_ops.sent_packets[num_peripheral_data_sent].payload(), &mut central_ops, &mut rng).unwrap();
                num_peripheral_data_sent += 1;
            }

            loop_cnt += 1;
            if loop_cnt > 10000 {
                panic!("Too many loops in first loop");
            }
        }

        let pass_key = match &central_ops.connection_events[0] {
            ConnectionEvent::PassKeyDisplay(pk) => *pk,
            _ => panic!("Unexpected connection event"),
        };

        assert!(matches!(peripheral_ops.connection_events[0], ConnectionEvent::PassKeyInput));

        peripheral_pairing.handle_event(Event::PassKeyInput(pass_key.value()), &mut peripheral_ops, &mut rng).unwrap();

        while peripheral_ops.encryptions.is_empty() || central_ops.encryptions.is_empty() {
            while num_central_data_sent < central_ops.sent_packets.len() {
                peripheral_pairing.handle_l2cap_command(central_ops.sent_packets[num_central_data_sent].command, central_ops.sent_packets[num_central_data_sent].payload(), &mut peripheral_ops, &mut rng).unwrap();
                num_central_data_sent += 1;
            }

            while num_peripheral_data_sent < peripheral_ops.sent_packets.len() {
                central_pairing.handle_l2cap_command(peripheral_ops.sent_packets[num_peripheral_data_sent].command, peripheral_ops.sent_packets[num_peripheral_data_sent].payload(), &mut central_ops, &mut rng).unwrap();
                num_peripheral_data_sent += 1;
            }

            loop_cnt += 1;
            if loop_cnt > 20000 {
                panic!("Too many loops in second loop");
            }
        }

        assert_eq!(central_ops.encryptions[0], peripheral_ops.encryptions[0]);
        central_pairing.handle_event(Event::LinkEncrypted, &mut central_ops, &mut rng).unwrap();
        peripheral_pairing.handle_event(Event::LinkEncrypted, &mut peripheral_ops, &mut rng).unwrap();

        assert!(matches!(central_ops.connection_events[1], ConnectionEvent::PairingComplete(_)));
        assert!(matches!(peripheral_ops.connection_events[1], ConnectionEvent::PairingComplete(_)));
    }
}

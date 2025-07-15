use crate::pdu::Pdu;
use crate::security_manager::crypto::{Check, Confirm, DHKey, MacKey, Nonce, PublicKey};
use crate::security_manager::types::{Command, PairingFeatures, UseOutOfBand};
use crate::security_manager::{Reason, TxPacket};
use crate::{Address, Error, IoCapabilities, LongTermKey, PacketPool};
use crate::prelude::SecurityLevel;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PassKeyEntryAction {
    Display,
    Input,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PairingMethod {
    JustWorks,
    NumericComparison,
    PassKeyEntry {
        central: PassKeyEntryAction,
        peripheral: PassKeyEntryAction,
    },
    OutOfBand,
}

impl PairingMethod {
    pub fn security_level(&self) -> SecurityLevel {
        match self {
            PairingMethod::JustWorks => SecurityLevel::Encrypted,
            _ => SecurityLevel::EncryptedAuthenticated
        }
    }
}

pub fn choose_pairing_method(central: PairingFeatures, peripheral: PairingFeatures) -> PairingMethod {
    if !central.security_properties.man_in_the_middle() && !peripheral.security_properties.man_in_the_middle() {
        PairingMethod::JustWorks
    } else if matches!(central.use_oob, UseOutOfBand::Present) || matches!(peripheral.use_oob, UseOutOfBand::Present) {
        PairingMethod::OutOfBand
    } else if peripheral.io_capabilities == IoCapabilities::DisplayOnly {
        match central.io_capabilities {
            IoCapabilities::KeyboardOnly | IoCapabilities::KeyboardDisplay => PairingMethod::PassKeyEntry {
                central: PassKeyEntryAction::Input,
                peripheral: PassKeyEntryAction::Display,
            },
            _ => PairingMethod::JustWorks,
        }
    } else if peripheral.io_capabilities == IoCapabilities::DisplayYesNo {
        match central.io_capabilities {
            IoCapabilities::DisplayYesNo | IoCapabilities::KeyboardDisplay => PairingMethod::NumericComparison,
            IoCapabilities::KeyboardOnly => PairingMethod::PassKeyEntry {
                central: PassKeyEntryAction::Input,
                peripheral: PassKeyEntryAction::Display,
            },
            _ => PairingMethod::JustWorks,
        }
    } else if peripheral.io_capabilities == IoCapabilities::KeyboardOnly {
        match central.io_capabilities {
            IoCapabilities::NoInputNoOutput => PairingMethod::JustWorks,
            IoCapabilities::KeyboardOnly => PairingMethod::PassKeyEntry {
                central: PassKeyEntryAction::Input,
                peripheral: PassKeyEntryAction::Input,
            },
            _ => PairingMethod::PassKeyEntry {
                central: PassKeyEntryAction::Display,
                peripheral: PassKeyEntryAction::Input,
            },
        }
    } else if peripheral.io_capabilities == IoCapabilities::NoInputNoOutput {
        PairingMethod::JustWorks
    } else {
        // Local io == keyboard display
        match central.io_capabilities {
            IoCapabilities::DisplayOnly => PairingMethod::PassKeyEntry {
                central: PassKeyEntryAction::Display,
                peripheral: PassKeyEntryAction::Input,
            },
            IoCapabilities::KeyboardDisplay => PairingMethod::PassKeyEntry {
                central: PassKeyEntryAction::Input,
                peripheral: PassKeyEntryAction::Display,
            },
            IoCapabilities::NoInputNoOutput => PairingMethod::JustWorks,
            _ => PairingMethod::NumericComparison,
        }
    }
}


pub fn prepare_packet<P: PacketPool>(command: Command) -> Result<TxPacket<P>, Error> {
    let packet = P::allocate().ok_or(Error::OutOfMemory)?;
    TxPacket::new(packet, command)
}

pub fn make_pairing_random<P: PacketPool>(nonce: &Nonce) -> Result<TxPacket<P>, Error> {
    let mut packet = prepare_packet::<P>(Command::PairingRandom)?;
    let response = packet.payload_mut();
    response.copy_from_slice(&nonce.0.to_le_bytes());
    Ok(packet)
}

pub fn make_public_key_packet<P: PacketPool>(public_key: &PublicKey) -> Result<TxPacket<P>, Error> {
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(public_key.x.as_be_bytes());
    y.copy_from_slice(public_key.y.as_be_bytes());
    x.reverse();
    y.reverse();
    let mut packet = prepare_packet(Command::PairingPublicKey)?;

    let response = packet.payload_mut();

    response[..x.len()].copy_from_slice(&x);
    response[x.len()..y.len() + x.len()].copy_from_slice(&y);
    Ok(packet)
}

pub fn make_dhkey_check_packet<P: PacketPool>(check: &Check) -> Result<TxPacket<P>, Error> {
    let mut packet = prepare_packet(Command::PairingDhKeyCheck)?;
    let response = packet.payload_mut();
    let bytes = check.0.to_le_bytes();
    response[..bytes.len()].copy_from_slice(&bytes);
    Ok(packet)
}

pub fn make_mac_and_ltk(
    dh_key: &DHKey,
    central_nonce: &Nonce,
    peripheral_nonce: &Nonce,
    central_address: Address,
    peripheral_address: Address,
) -> (MacKey, LongTermKey) {
    dh_key.f5(*central_nonce, *peripheral_nonce, central_address, peripheral_address)
}

pub fn make_confirm_packet<P: PacketPool>(confirm: &Confirm) -> Result<TxPacket<P>, Error> {
    let mut packet = prepare_packet::<P>(Command::PairingConfirm)?;
    let response = packet.payload_mut();
    response.copy_from_slice(&confirm.0.to_le_bytes());
    Ok(packet)
}

#[derive(Debug, Clone)]
pub struct CommandAndPayload<'a> {
    pub command: Command,
    pub payload: &'a [u8],
}

impl<'a> CommandAndPayload<'a> {
    pub fn try_parse<P: PacketPool>(pdu: Pdu<P::Packet>, buffer: &'a mut [u8]) -> Result<Self, Error> {
        let size = {
            let size = pdu.len().min(buffer.len());
            buffer[..size].copy_from_slice(&pdu.as_ref()[..size]);
            size
        };
        if size < 2 {
            error!("[security manager] Payload size too small {}", size);
            return Err(Error::Security(Reason::InvalidParameters));
        }
        let payload = &buffer[1..size];
        let command = buffer[0];

        let command = match Command::try_from(command) {
            Ok(command) => {
                if usize::from(command.payload_size()) != payload.len() {
                    error!("[security manager] Payload size mismatch for command {}", command);
                    return Err(Error::Security(Reason::InvalidParameters));
                }
                command
            }
            Err(_) => return Err(Error::Security(Reason::CommandNotSupported)),
        };

        Ok(Self { command, payload })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_manager::types::{AuthReq, BondingFlag};

    #[test]
    fn oob_used() {
        for p_oob in 0..1 {
            for c_oob in 0..1 {
                let p_oob = if p_oob == 1 {
                    UseOutOfBand::Present
                } else {
                    UseOutOfBand::NotPresent
                };
                let c_oob = if c_oob == 1 {
                    UseOutOfBand::Present
                } else {
                    UseOutOfBand::NotPresent
                };
                for p in 0u8..5 {
                    for c in 0u8..5 {
                        let peripheral = PairingFeatures {
                            io_capabilities: p.try_into().unwrap(),
                            use_oob: p_oob,
                            security_properties: AuthReq::new(BondingFlag::NoBonding),
                            initiator_key_distribution: 0.into(),
                            responder_key_distribution: 0.into(),
                            maximum_encryption_key_size: 16,
                        };
                        let mut central = peripheral.clone();
                        central.use_oob = c_oob;
                        central.io_capabilities = c.try_into().unwrap();
                        if p_oob == UseOutOfBand::NotPresent && c_oob == UseOutOfBand::NotPresent {
                            assert_ne!(choose_pairing_method(central, peripheral), PairingMethod::OutOfBand);
                        } else {
                            assert_eq!(choose_pairing_method(central, peripheral), PairingMethod::OutOfBand);
                        }
                    }
                }
            }
        }
    }
}

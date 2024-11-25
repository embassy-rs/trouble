use bitfield_struct::bitfield;
use bt_hci::controller::Controller;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum IoCapabilities {
    DisplayOnly = 0,
    DisplayYesNo = 1,
    KeyboardOnly = 2,
    NoInputNoOutput = 3,
    KeyboardDisplay = 4,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum SecurityManagerError {
    PasskeyEntryFailed = 1,
    OobNotAvailable,
    AuthenticationRequirements,
    ConfirmValueFailed,
    PairingNotSupported,
    EncryptionKeySize,
    CommandNotSupported,
    UnspecifiedReason,
    RepeatedAttempts,
    InvalidParameters,
    DHKeyCheckFailed,
    NumericComparisonFailed,
    BrEdrPairingInProgress,
    GenerationNotAllowed,
    KeyRejected,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum OobDataFlag {
    NotPresent = 0,
    Present = 1,
}

#[bitfield(u8)]
pub struct AuthReq {
    #[bits(2)]
    bonding_flags: u8,
    #[bits(1)]
    mitm: bool,
    #[bits(1)]
    sc: bool,
    #[bits(1)]
    keypress: bool,
    #[bits(1)]
    ct2: bool,
    #[bits(2)]
    rfu: u8,
}

const SM_PAIRING_REQUEST: u8 = 0x01;
const SM_PAIRING_RESPONSE: u8 = 0x02;
const SM_PAIRING_CONFIRM: u8 = 0x03;
const SM_PAIRING_RANDOM: u8 = 0x04;
const SM_PAIRING_FAILED: u8 = 0x05;
const SM_PAIRING_PUBLIC_KEY: u8 = 0x0c;
const SM_PAIRING_DHKEY_CHECK: u8 = 0x0d;

/// Security manager that handles SM packet
pub struct SecurityManager<'d, C: Controller> {
    controller: &'d C,
}

impl<C: Controller> SecurityManager<'_, C> {
    /// Handle packet
    pub(crate) async fn handle(&mut self, payload: &[u8]) {
        let data = &payload[1..];
        let command = payload[0];

        match command {
            SM_PAIRING_REQUEST => {
                todo!()
            }
            SM_PAIRING_PUBLIC_KEY => {
                todo!()
            }
            SM_PAIRING_RANDOM => {
                todo!()
            }
            SM_PAIRING_DHKEY_CHECK => {
                todo!()
            }
            _ => {
                // handle FAILURE
                error!("Unknown SM command {}", command);
                todo!()
            }
        }
    }
}

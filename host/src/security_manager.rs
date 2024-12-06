use bitfield_struct::bitfield;
use bt_hci::{
    controller::Controller,
    data::{AclBroadcastFlag, AclPacket, AclPacketBoundary},
    param::ConnHandle,
};

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

fn make_auth_req() -> AuthReq {
    AuthReq::new()
        .with_bonding_flags(1)
        .with_mitm(true)
        .with_sc(true)
        .with_keypress(false)
        .with_ct2(true)
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
    pub(crate) async fn handle(&mut self, src_handle: u16, payload: &[u8]) {
        let data = &payload[1..];
        let command = payload[0];

        match command {
            SM_PAIRING_REQUEST => {
                self.handle_pairing_request(src_handle, data).await.unwrap();
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

    fn encode_sm_data<'a>(&self, data: &[u8], target: &'a mut [u8]) -> &'a [u8] {
        target.copy_from_slice(&[
            0x0, 0x0, // len set later
            0x6, 0x0, // channel
        ]);
        target[4..data.len() + 4].copy_from_slice(data);
        let len = data.len() - 4;
        target[0] = (len & 0xff) as u8;
        target[1] = ((len >> 8) & 0xff) as u8;
        &target[..data.len() + 4]
    }

    async fn write_sm_data(&self, handle: u16, data: &[u8]) -> Result<(), C::Error> {
        let mut sm_data_buf = [0u8; 256];
        let encoded_data = self.encode_sm_data(data, &mut sm_data_buf);

        let packet = AclPacket::new(
            ConnHandle::new(handle),
            AclPacketBoundary::FirstNonFlushable,
            AclBroadcastFlag::PointToPoint,
            encoded_data,
        );
        self.controller.write_acl_data(&packet).await
    }

    async fn handle_pairing_request(&mut self, src_handle: u16, data: &[u8]) -> Result<(), C::Error> {
        // TODO: save A/O/I
        debug!("[security manager] Handle pairing request");
        let auth_req = data[2];
        let oob_data = data[1] != 0;
        let io_cap = data[0];

        let req_data = [
            SM_PAIRING_RESPONSE,
            IoCapabilities::DisplayYesNo as u8,
            OobDataFlag::NotPresent as u8,
            make_auth_req().0,
            0x10,
            0,
            0,
        ];
        self.write_sm_data(src_handle, &req_data).await
    }

    async fn handle_pairing_public_key(&mut self, src_handle: u16, pka: &[u8]) -> Result<(), C::Error> {
        debug!("[security manager] Handle pairing public key");
        debug!("[security manager] key len = {} {:02x?}", pka.len(), pka);
        todo!()
    }
}

use bitfield_struct::bitfield;
use bt_hci::{
    controller::Controller,
    data::{AclBroadcastFlag, AclPacket, AclPacketBoundary},
    param::ConnHandle,
};
use rand_core::{CryptoRng, RngCore};

use crate::{
    crypto::{Nonce, PublicKey, SecretKey},
    BleHostError, Error,
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
pub struct SecurityManager<'a, 'd, C: Controller, R: CryptoRng + RngCore> {
    controller: &'d C,
    rng: &'a mut R,
}

impl<C: Controller, R: CryptoRng + RngCore> SecurityManager<'_, '_, C, R> {
    /// Handle packet
    pub(crate) async fn handle(&mut self, src_handle: u16, payload: &[u8]) -> Result<(), BleHostError<C::Error>> {
        let data = &payload[1..];
        let command = payload[0];

        match command {
            SM_PAIRING_REQUEST => self.handle_pairing_request(src_handle, data).await,
            SM_PAIRING_PUBLIC_KEY => self.handle_pairing_public_key(src_handle, data).await,
            SM_PAIRING_RANDOM => self.handle_pairing_random(src_handle, data).await,
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

    async fn write_sm_data(&self, handle: u16, data: &[u8]) -> Result<(), BleHostError<C::Error>> {
        let mut sm_data_buf = [0u8; 256];
        let encoded_data = self.encode_sm_data(data, &mut sm_data_buf);

        let packet = AclPacket::new(
            ConnHandle::new(handle),
            AclPacketBoundary::FirstNonFlushable,
            AclBroadcastFlag::PointToPoint,
            encoded_data,
        );
        self.controller
            .write_acl_data(&packet)
            .await
            .map_err(|e| BleHostError::Controller(e))
    }

    async fn handle_pairing_request(&mut self, src_handle: u16, data: &[u8]) -> Result<(), BleHostError<C::Error>> {
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

    async fn handle_pairing_public_key(&mut self, src_handle: u16, pka: &[u8]) -> Result<(), BleHostError<C::Error>> {
        debug!("[security manager] Handle pairing public key");
        debug!("[security manager] key len = {} {:02x?}", pka.len(), pka);
        let pka = PublicKey::from_bytes(pka);

        // Send the local public key before validating the remote key to allow
        // parallel computation of DHKey. No security risk in doing so.

        let skb = SecretKey::new(self.rng);
        let pkb = skb.public_key();

        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(pkb.x.as_be_bytes());
        y.copy_from_slice(pkb.y.as_be_bytes());
        x.reverse();
        y.reverse();

        let mut data = [0u8; 65];
        data[0] = SM_PAIRING_PUBLIC_KEY;
        data[1..33].copy_from_slice(&x);
        data[33..65].copy_from_slice(&y);

        self.write_sm_data(src_handle, &data).await?;

        let dh_key = match skb.dh_key(pka) {
            Some(dh_key) => Ok(dh_key),
            None => Err(BleHostError::BleHost(Error::Security(
                SecurityManagerError::DHKeyCheckFailed,
            ))),
        }?;

        // SUBTLE: The order of these send/recv ops is important. See last
        // paragraph of Section 2.3.5.6.2.
        let nb = Nonce::new(self.rng);
        let cb = nb.f4(pkb.x(), pka.x(), 0);

        let mut data = [0u8; 17];
        data[0] = SM_PAIRING_CONFIRM;
        data[1..17].copy_from_slice(&cb.0.to_le_bytes());

        self.write_sm_data(src_handle, &data).await?;

        // TODO: update keys
        // self.pka = Some(pka);
        // self.pkb = Some(pkb);
        // self.skb = Some(skb);
        // self.confirm = Some(cb);
        // self.nb = Some(nb);
        // self.dh_key = Some(dh_key);

        Ok(())
    }

    async fn handle_pairing_random(&mut self, src_handle: u16, random: &[u8]) -> Result<(), BleHostError<C::Error>> {
        debug!("[security manager] Handle pairing random");
        debug!("[security manager] Got pairing random: {:02x?}", random);

        // TODO: Do checking

        // Write nb data
        let mut data = [0u8; 17];
        data[0] = SM_PAIRING_RANDOM;
        // TODO: add nb
        // data[1..17].copy_from_slice(self.nb.unwrap().0.to_le_bytes());
        self.write_sm_data(src_handle, &data).await?;

        let na = Nonce(u128::from_le_bytes(random.try_into().unwrap()));
        // TODO: calculation
        // self.na = Some(na);
        // let nb = self.nb.unwrap();
        // let vb = na.g2(self.pka.as_ref().unwrap().x(), self.pkb.as_ref().unwrap().x(), &nb);

        // should display the code and get confirmation from user (pin ok or not) - if not okay send a pairing-failed
        // assume it's correct or the user will cancel on central
        // TODO: What is pin_callback used for?
        // info!("Display code is {}", vb.0);
        // if let Some(pin_callback) = pin_callback {
        // pin_callback(vb.0);
        // }

        // Authentication stage 2 and long term key calculation
        // ([Vol 3] Part H, Section 2.3.5.6.5 and C.2.2.4).

        // let a = self.peer_address.unwrap();
        // let b = self.local_address.unwrap();
        let ra = 0;
        // trace!("peer_address = {:02x?}", a.0);
        // trace!("local_address = {:02x?}", b.0);

        // TODO: more calculations!
        // let iob = IoCap::new(make_auth_req().0, false, io_cap);
        let auth_req = make_auth_req();
        let oob_data = false;
        let io_cap = IoCapabilities::DisplayYesNo as u8;
        // let dh_key = self.dh_key.as_ref().unwrap();

        // let (mac_key, ltk) = dh_key.f5(na, nb, a, b);
        // let eb = mac_key.f6(nb, na, ra, iob, b, a);

        // self.mac_key = Some(mac_key);
        // self.ltk = Some(ltk.0);
        // self.eb = Some(eb);

        Ok(())
    }

    async fn handle_pairing_dhkey_check(&mut self, src_handle: u16, ea: &[u8]) -> Result<(), BleHostError<C::Error>> {
        debug!("[security manager] Handle pairing dhkey check");
        debug!("[security manager] Got ea: {:02x?}", ea);

        // TODO: Do checking

        // TODO: Check dhkey
        // let expected_ea = self
        //     .mac_key
        //     .as_ref()
        //     .unwrap()
        //     .f6(
        //         self.na.unwrap(),
        //         self.nb.unwrap(),
        //         0,
        //         self.ioa.unwrap(),
        //         self.peer_address.unwrap(),
        //         self.local_address.unwrap(),
        //     )
        //     .0
        //     .to_le_bytes();

        // if ea != expected {
        // warn!("DH check failed");
        // }

        let mut data = [0u8; 17];
        data[0] = SM_PAIRING_DHKEY_CHECK;
        // data[1..17].copy_from_slice(self.eb.as_ref().unwrap().0.to_le_bytes());

        self.write_sm_data(src_handle, &data).await?;
        Ok(())
    }
}

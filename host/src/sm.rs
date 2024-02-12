use core::marker::PhantomData;

use bitfield::bitfield;
use p256::elliptic_curve::rand_core::{CryptoRng, RngCore};

use crate::{
    acl::{AclPacket, BoundaryFlag, HostBroadcastFlag},
    attribute_server::AttributeServerError,
    crypto::{Check, Confirm, DHKey, IoCap, MacKey, Nonce, PublicKey, SecretKey},
    l2cap::L2capPacket,
    Addr, Ble, Data,
};

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
pub enum IoCapability {
    DisplayOnly = 0,
    DisplayYesNo = 1,
    KeyboardOnly = 2,
    NoInputNoOutput = 3,
    KeyboardDisplay = 4,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum OobDataFlag {
    NotPresent = 0,
    Present = 1,
}

bitfield! {
    pub struct AuthReq(u8);
    impl Debug;

    pub bonding_flags, set_bonding_flags: 1, 0;
    pub mitm, set_mitm: 2, 2;
    pub sc, set_sc: 3, 3;
    pub keypress, set_keypress: 4, 4;
    pub ct2, set_ct2: 5, 5;
    pub rfu, set_rfu: 7, 6;
}

const SM_PAIRING_REQUEST: u8 = 0x01;
const SM_PAIRING_RESPONSE: u8 = 0x02;
const SM_PAIRING_CONFIRM: u8 = 0x03;
const SM_PAIRING_RANDOM: u8 = 0x04;
const SM_PAIRING_FAILED: u8 = 0x05;
const SM_PAIRING_PUBLIC_KEY: u8 = 0x0c;
const SM_PAIRING_DHKEY_CHECK: u8 = 0x0d;

pub struct SecurityManager<'a, B, R: CryptoRng> {
    ioa: Option<IoCap>,

    skb: Option<SecretKey>,
    pkb: Option<PublicKey>,

    pka: Option<PublicKey>,

    confirm: Option<Confirm>,

    na: Option<Nonce>,
    nb: Option<Nonce>,

    dh_key: Option<DHKey>,

    mac_key: Option<MacKey>,

    eb: Option<Check>,

    pub local_address: Option<Addr>,
    pub peer_address: Option<Addr>,
    pub ltk: Option<u128>,

    rng: &'a mut R,
    phantom: PhantomData<B>,
}

pub trait BleWriter {
    fn write_bytes(&mut self, bytes: &[u8]);
}

impl<'a> BleWriter for Ble<'a> {
    fn write_bytes(&mut self, bytes: &[u8]) {
        self.write_bytes(bytes);
    }
}

impl<'a, B, R: CryptoRng> SecurityManager<'a, B, R> {
    pub fn new(rng: &'a mut R) -> Self {
        Self {
            ioa: None,
            skb: None,
            pkb: None,
            pka: None,
            confirm: None,
            na: None,
            nb: None,
            dh_key: None,
            mac_key: None,
            eb: None,
            local_address: None,
            peer_address: None,
            ltk: None,
            rng,
            phantom: PhantomData::default(),
        }
    }
}

#[cfg(feature = "async")]
pub struct AsyncSecurityManager<'a, B, R: CryptoRng> {
    ioa: Option<IoCap>,

    skb: Option<SecretKey>,
    pkb: Option<PublicKey>,

    pka: Option<PublicKey>,

    confirm: Option<Confirm>,

    na: Option<Nonce>,
    nb: Option<Nonce>,

    dh_key: Option<DHKey>,

    mac_key: Option<MacKey>,
    eb: Option<Check>,

    pub local_address: Option<Addr>,
    pub peer_address: Option<Addr>,
    pub ltk: Option<u128>,

    rng: &'a mut R,
    phantom: PhantomData<B>,
}

#[cfg(feature = "async")]
pub trait AsyncBleWriter {
    async fn write_bytes(&mut self, bytes: &[u8]);
}

#[cfg(feature = "async")]
impl<T> AsyncBleWriter for crate::asynch::Ble<T>
where
    T: embedded_io_async::Read + embedded_io_async::Write,
{
    async fn write_bytes(&mut self, bytes: &[u8]) {
        self.write_bytes(bytes).await
    }
}

#[cfg(feature = "async")]
impl<'a, B, R: CryptoRng> AsyncSecurityManager<'a, B, R> {
    pub fn new(rng: &'a mut R) -> Self {
        Self {
            ioa: None,
            skb: None,
            pkb: None,
            pka: None,
            confirm: None,
            na: None,
            nb: None,
            dh_key: None,
            mac_key: None,
            eb: None,
            local_address: None,
            peer_address: None,
            ltk: None,
            rng,
            phantom: PhantomData::default(),
        }
    }
}

fn make_auth_req() -> AuthReq {
    let mut auth_req = AuthReq(0);
    auth_req.set_bonding_flags(1);
    auth_req.set_mitm(1);
    auth_req.set_sc(1);
    auth_req.set_keypress(0);
    auth_req.set_ct2(1);
    auth_req
}

bleps_dedup::dedup! {
impl<'a, B, R> SYNC SecurityManager<'a, B, R> where B: BleWriter, R: CryptoRng + RngCore
impl<'a, B, R> ASYNC AsyncSecurityManager<'a, B, R> where B: AsyncBleWriter, R: CryptoRng + RngCore
 {
    pub(crate) async fn handle(&mut self, ble: &mut B, src_handle: u16, payload: crate::Data, pin_callback: &mut Option<&mut dyn FnMut(u32)>) -> Result<(), AttributeServerError> {
        log::info!("SM packet {:02x?}", payload.as_slice());

        let data = &payload.as_slice()[1..];
        let command = payload.as_slice()[0];

        match command {
            SM_PAIRING_REQUEST => {
                self.handle_pairing_request(ble, src_handle, data).await;
            }
            SM_PAIRING_PUBLIC_KEY => {
                self.handle_pairing_public_key(ble, src_handle, data).await?;
            }
            SM_PAIRING_RANDOM => {
                self.handle_pairing_random(ble, src_handle, data, pin_callback).await?;
            }
            SM_PAIRING_DHKEY_CHECK => {
                self.handle_pairing_dhkey_check(ble, src_handle, data).await?;
            }
            _ => {
                // handle FAILURE
                log::error!("Unknown SM command {}", command);
                self.report_error(ble, src_handle, SecurityManagerError::CommandNotSupported).await;
                return Err(AttributeServerError::SecurityManagerError);
            }
        }

        Ok(())
    }

    async fn handle_pairing_request(&mut self, ble: &mut B, src_handle: u16, data: &[u8]) {
        self.ioa = Some(IoCap::new(data[2], data[1] != 0, data[0]));
        log::info!("got pairing request");

        let mut data = Data::new(&[SM_PAIRING_RESPONSE]);
        data.append_value(IoCapability::DisplayYesNo as u8);
        data.append_value(OobDataFlag::NotPresent as u8);
        data.append_value(make_auth_req().0);
        data.append_value(0x10u8);
        data.append_value(0u8); // 3
        data.append_value(0u8); // 3

        self.write_sm(ble, src_handle, data).await;
    }

    async fn handle_pairing_public_key(&mut self, ble: &mut B, src_handle: u16, pka: &[u8]) -> Result<(), AttributeServerError> {
        log::info!("got public key");

        log::info!("key len = {} {:02x?}", pka.len(), pka);
        let pka = PublicKey::from_bytes(pka);

        // Send the local public key before validating the remote key to allow
        // parallel computation of DHKey. No security risk in doing so.

        let mut data = Data::new(&[SM_PAIRING_PUBLIC_KEY]);

        let skb = SecretKey::new(self.rng);
        let pkb = skb.public_key();

        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(pkb.x.as_be_bytes());
        y.copy_from_slice(pkb.y.as_be_bytes());
        x.reverse();
        y.reverse();

        data.append(&x);
        data.append(&y);
        self.write_sm(ble, src_handle, data).await;

        let dh_key = match skb.dh_key(pka) {
            Some(dh_key) => Ok(dh_key),
            None => Err(AttributeServerError::SecurityManagerError),
        }?;

        // SUBTLE: The order of these send/recv ops is important. See last
        // paragraph of Section 2.3.5.6.2.
        let nb = Nonce::new(self.rng);
        let cb = nb.f4(pkb.x(), pka.x(), 0);

        let mut data = Data::new(&[SM_PAIRING_CONFIRM]);
        let confirm_value = cb.0.to_le_bytes();
        data.append(&confirm_value);
        self.write_sm(ble, src_handle, data).await;

        self.pka = Some(pka);
        self.pkb = Some(pkb);
        self.skb = Some(skb);
        self.confirm = Some(cb);
        self.nb = Some(nb);
        self.dh_key = Some(dh_key);

        Ok(())
    }

    async fn handle_pairing_random(&mut self, ble: &mut B, src_handle: u16, random: &[u8], pin_callback: &mut Option<&mut dyn FnMut(u32)>) -> Result<(), AttributeServerError> {
        log::info!("got pairing random {:02x?}", random);

        if *&(self.nb).is_none() {
            self.report_error(ble, src_handle, SecurityManagerError::UnspecifiedReason).await;
            return Err(AttributeServerError::SecurityManagerError);
        }

        if *&(self.pka).is_none() {
            self.report_error(ble, src_handle, SecurityManagerError::UnspecifiedReason).await;
            return Err(AttributeServerError::SecurityManagerError);
        }

        if *&(self.pkb).is_none() {
            self.report_error(ble, src_handle, SecurityManagerError::UnspecifiedReason).await;
            return Err(AttributeServerError::SecurityManagerError);
        }

        if *&(self.peer_address).is_none() {
            self.report_error(ble, src_handle, SecurityManagerError::UnspecifiedReason).await;
            return Err(AttributeServerError::SecurityManagerError);
        }

        if *&(self.local_address).is_none() {
            self.report_error(ble, src_handle, SecurityManagerError::UnspecifiedReason).await;
            return Err(AttributeServerError::SecurityManagerError);
        }

        let mut data = Data::new(&[SM_PAIRING_RANDOM]);
        data.append(&self.nb.unwrap().0.to_le_bytes());
        self.write_sm(ble, src_handle, data).await;

        let na = Nonce(u128::from_le_bytes(random.try_into().unwrap()));
        self.na = Some(na);
        let nb = self.nb.unwrap();
        let vb = na.g2(
            self.pka.as_ref().unwrap().x(),
            self.pkb.as_ref().unwrap().x(),
            &nb,
        );

        // should display the code and get confirmation from user (pin ok or not) - if not okay send a pairing-failed
        // assume it's correct or the user will cancel on central
        log::info!("Display code is {}", vb.0);
        if let Some(pin_callback) = pin_callback {
            pin_callback(vb.0);
        }

        // Authentication stage 2 and long term key calculation
        // ([Vol 3] Part H, Section 2.3.5.6.5 and C.2.2.4).

        let a = self.peer_address.unwrap();
        let b = self.local_address.unwrap();
        let ra = 0;
        log::info!("a = {:02x?}", a.0);
        log::info!("b = {:02x?}", b.0);

        let io_cap = IoCapability::DisplayYesNo as u8;
        let iob = IoCap::new(make_auth_req().0, false, io_cap);
        let dh_key = self.dh_key.as_ref().unwrap();

        let (mac_key, ltk) = dh_key.f5(na, nb, a, b);
        let eb = mac_key.f6(nb, na, ra, iob, b, a);

        self.mac_key = Some(mac_key);
        self.ltk = Some(ltk.0);
        self.eb = Some(eb);

        Ok(())
    }

    async fn handle_pairing_dhkey_check(&mut self, ble: &mut B, src_handle: u16, ea: &[u8]) -> Result<(), AttributeServerError> {
        log::info!("got dhkey_check {:02x?}", ea);

        if *&(self.na).is_none() {
            self.report_error(ble, src_handle, SecurityManagerError::UnspecifiedReason).await;
            return Err(AttributeServerError::SecurityManagerError);
        }

        if *&(self.nb).is_none() {
            self.report_error(ble, src_handle, SecurityManagerError::UnspecifiedReason).await;
            return Err(AttributeServerError::SecurityManagerError);
        }

        if *&(self.ioa).is_none() {
            self.report_error(ble, src_handle, SecurityManagerError::UnspecifiedReason).await;
            return Err(AttributeServerError::SecurityManagerError);
        }

        if *&(self.peer_address).is_none() {
            self.report_error(ble, src_handle, SecurityManagerError::UnspecifiedReason).await;
            return Err(AttributeServerError::SecurityManagerError);
        }

        if *&(self.local_address).is_none() {
            self.report_error(ble, src_handle, SecurityManagerError::UnspecifiedReason).await;
            return Err(AttributeServerError::SecurityManagerError);
        }

        let expected = self
            .mac_key
            .as_ref()
            .unwrap()
            .f6(
                self.na.unwrap(),
                self.nb.unwrap(),
                0,
                self.ioa.unwrap(),
                self.peer_address.unwrap(),
                self.local_address.unwrap(),
            )
            .0
            .to_le_bytes();
        if ea != expected {
            log::warn!("DH check failed");
        }

        let mut data = Data::new(&[SM_PAIRING_DHKEY_CHECK]);
        data.append(&self.eb.as_ref().unwrap().0.to_le_bytes());
        self.write_sm(ble, src_handle, data).await;

        Ok(())
    }

    async fn write_sm(&self, ble: &mut B, handle: u16, data: Data) {
        // Workaround! For unknown reasons this is currently necessary
        // Needs to get solved in the underlying esp-wifi implementation
        static mut DUMMY: u32 = 0;
        unsafe {
            for _ in 0..1_000_000 {
                (&mut DUMMY as *mut u32).write_volatile(0);
            }
        }

        log::debug!("data {:x?}", data.as_slice());

        let res = L2capPacket::encode_sm(data);
        log::info!("encoded_l2cap {:x?}", res.as_slice());

        let res = AclPacket::encode(
            handle,
            BoundaryFlag::FirstAutoFlushable,
            HostBroadcastFlag::NoBroadcast,
            res,
        );

        log::info!("writing {:02x?}", res.as_slice());
        ble.write_bytes(res.as_slice()).await;
    }

    async fn report_error(&self, ble: &mut B, src_handle: u16, error: SecurityManagerError) {
        let mut data = Data::new(&[SM_PAIRING_FAILED]);
        data.append(&[error as u8]);
        self.write_sm(ble, src_handle, data).await;
    }
}
}

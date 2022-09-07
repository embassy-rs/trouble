//! The LE Security Manager protocol.
//!
//! The Security Manager is a mandatory part of BLE and is connected to L2CAP channel `0x0006` when
//! the Link-Layer connection is established.
//!
//! # BLE Security
//!
//! As is tradition, BLE security is a complexity nightmare. This section hopes to clear up a few
//! things and tries to define terms used throughout the code and specficiation.
//!
//! ## Pairing and Bonding
//!
//! * **Pairing** is the process of generating and exchanging connection-specific keys in order to
//!   accomplish an encrypted Link-Layer connection.
//!
//!   This is done by having the *Security Managers* of the devices talk to each other to perform
//!   the key exchange, and then using *LL Control PDUs* to enable the negotiated encryption
//!   parameters.
//!
//! * **Bonding** means permanently storing the shared keys derived by *Pairing* in order to reuse
//!   them for later connections.
//!
//!   The way keys are stored is inherently platform- and application-dependent, we just have to
//!   provide interfaces to export and import key sets.
//!
//! Most times, when talking about *pairing*, the *bonding* part is implied. If it were not, you
//! would constantly have to re-pair devices when reconnecting them.
//!
//! ## LE Legacy Pairing vs. LE Secure Connections
//!
//! Bluetooth's security track record is an actual record in that it is so atrociously bad that this
//! protocol should have never seen the light of the day. Alas, here we are.
//!
//! LE security is generally able to utilize *AES-128-CCM* for encryption, which isn't broken by
//! itself (unlike the "export-grade" encryption used by earlier Bluetooth versions). However, the
//! way the AES key is exchanged differs between *LE Legacy Pairing* and *LE Secure Connections*
//! pairing, which hugely impacts actual security.
//!
//! ### LE Legacy Pairing
//!
//! For BLE 4.0 and 4.1, only the *LE Legacy Pairing* (as it is now known as) was available. Like
//! every awfully designed protocol, they've rolled their own crypto and use their own key exchange
//! procedure (with the usual catastrophic consequences). First, a shared 128-bit **T**emporary
//! **K**ey (TK) is obtained, which is then used to generate the 128-bit **S**hort-**T**erm **K**ey
//! (STK) that is used to initially encrypt the connection while other keys are exchanged.
//!
//! The STK is generated from the TK by mixing in random values from master (`Mrand`) and slave
//! (`Srand`), which are exchanged in plain text. If a passive eavesdropper manages to obtain TK,
//! they only need to listen for the `Mrand` and `Srand` value and can then compute the STK and
//! decrypt the connection.
//!
//! There are 3 methods of determining the TK:
//! * *"Just Works"*: TK=0
//! * *Passkey Entry*: A 6-digit number is displayed on one device and input on the other device.
//!   The number is directly used as the TK (after zero-padding it to 128 bits).
//! * *Out-of-Band* (OOB): The 128-bit TK is provided by an external mechanism (eg. NFC).
//!
//! "Just Works" obviously is broken without any effort other than listening for the exchanged
//! `Mrand` and `Srand` values.
//!
//! The Passkey Entry method only allows 1000000 different TKs (equivalent to using 20-bit keys)
//! and does not do any key derivation. This makes it trivial to brute-force the TK by running the
//! STK derivation up to a million times.
//!
//! **The only way to perform *LE Legacy Pairing* with meaningful protection against passive
//! eavesdropping is by using a secure Out-of-Band channel for agreeing on the TK.**
//!
//! ### LE Secure Connections pairing
//!
//! Added with BLE 4.2, this finally uses established cryptography to do everything. It uses ECDH on
//! the P-256 curve (aka "secp256r1" or "prime256v1").
//!
//! Using ECDH immediately protects against passive eavesdropping. MITM-protection works similarly
//! to what *LE Legacy Pairing* attempted to do, but is actually relevant here since the base key
//! exchange isn't broken to begin with. There are several user confirmation processes that can
//! offer MITM-protection:
//!
//! * *"Just Works"*: No MITM-protection. Uses the *Numeric Comparison* protocol internally, with
//!   automatic confirmation.
//! * *Numeric Comparison*: Both devices display a 6-digit confirmation value and the user is
//!   required to compare them and confirm on each device if they're equal.
//! * *Passkey Entry*: Either a generated passkey is displayed on one device and input on the other,
//!   or the user inputs the same passkey into both devices.
//! * *Out-of-Band* (OOB): An Out-of-Band mechanism is used to exchange random nonces and confirm
//!   values. The mechanism has to be secure against MITM.
//!
//! ## LE Privacy
//!
//! BLE devices are normally extremely easy to track. Since many people use BLE devices, and device
//! addresses are device-unique, they can be very easily used to identify and track people just by
//! recording BLE advertisements.
//!
//! The LE privacy feature can prevent this by changing the device address over time. Bonded devices
//! can still *resolve* this address by using a shared **I**dentity **R**esolving **K**ey (IRK).
//!
//! This feature is not related to encryption or authentication of connections.

use crate::l2cap::{Protocol, ProtocolObj, Sender};
use crate::{bytes::*, utils::HexSlice, Error};
use bitflags::bitflags;
use core::fmt;
use zerocopy::Unaligned;

/// Supported security levels.
pub trait SecurityLevel {
    /// The L2CAP MTU required by this security level.
    const MTU: u8;
}

/// *LE Secure Connections* are not supported and will not be established.
#[derive(Debug)]
pub struct NoSecurity;
impl SecurityLevel for NoSecurity {
    /// 23 Bytes when *LE Secure Connections* are unsupported
    const MTU: u8 = 23;
}

/// Indicates support for *LE Secure Connections*.
#[derive(Debug)]
pub struct SecureConnections;
impl SecurityLevel for SecureConnections {
    /// 65 Bytes when *LE Secure Connections* are supported
    const MTU: u8 = 65;
}

/// The LE Security Manager.
///
/// Manages pairing and key generation and exchange.
#[derive(Debug)]
pub struct SecurityManager<S: SecurityLevel> {
    _security: S,
}

impl SecurityManager<NoSecurity> {
    pub fn no_security() -> Self {
        Self {
            _security: NoSecurity,
        }
    }
}

impl<S: SecurityLevel> ProtocolObj for SecurityManager<S> {
    fn process_message(&mut self, message: &[u8], _responder: Sender<'_>) -> Result<(), Error> {
        let cmd = Command::from_bytes(&mut ByteReader::new(message))?;
        trace!("SMP cmd {:?}, {:?}", cmd, HexSlice(message));
        match cmd {
            Command::PairingRequest(_req) => {
                warn!("pairing request NYI");
            }
            Command::Unknown {
                code: CommandCode::Unknown(code),
                data,
            } => warn!(
                "unknown security manager cmd: 0x{:02X} {:?}",
                code,
                HexSlice(data)
            ),
            Command::Unknown { code, data } => {
                warn!("[NYI] SMP cmd {:?}: {:?}", code, HexSlice(data));
            }
        }

        Ok(())
    }
}

impl<S: SecurityLevel> Protocol for SecurityManager<S> {
    const RSP_PDU_SIZE: u8 = S::MTU;
}

#[derive(Debug, Copy, Clone, Unaligned, zerocopy::FromBytes)]
#[repr(C)]
struct PairingRequest {
    /// The I/O capabilities of the initiator.
    io: Field<u8, IoCapabilities>,
    /// Whether the initiator has OOB pairing data available.
    oob: Field<u8, Oob>,
    /// Initiator authentication requirements.
    auth_req: Field<u8, AuthReq>,
    /// Maximum supported encryption key size in range 7..=16 Bytes.
    ///
    /// For BLE, this is always 16, since it always uses AES-128-CCM (even with the broken
    /// *LE Legacy Pairing*). We consider anything smaller than 16 to be as insecure as a plain
    /// text connection.
    max_keysize: u8,
    /// Set of keys the initiator (the device sending this request) wants to distribute to the
    /// responder (the device receiving this request).
    initiator_dist: Field<u8, KeyDistribution>,
    /// Set of keys the initiator requests the responder to generate and distribute.
    responder_dist: Field<u8, KeyDistribution>,
}

/// An SMP command.
#[derive(Debug, Copy, Clone)]
enum Command<'a> {
    PairingRequest(&'a PairingRequest),
    Unknown { code: CommandCode, data: &'a [u8] },
}

impl<'a> FromBytes<'a> for Command<'a> {
    fn from_bytes(bytes: &mut ByteReader<'a>) -> Result<Self, Error> {
        let code = CommandCode::from(bytes.read_u8()?);
        Ok(match code {
            CommandCode::PairingRequest => Command::PairingRequest(bytes.read_obj()?),
            _ => Command::Unknown {
                code,
                data: bytes.read_rest(),
            },
        })
    }
}

enum_with_unknown! {
    #[derive(Debug, Copy, Clone)]
    enum CommandCode(u8) {
        PairingRequest = 0x01,
        PairingResponse = 0x02,
        PairingConfirm = 0x03,
        PairingRandom = 0x04,
        PairingFailed = 0x05,
        EncryptionInformation = 0x06,
        MasterIdentification = 0x07,
        IdentityInformation = 0x08,
        IdentityAddressInformation = 0x09,
        SigningInformation = 0x0A,
        SecurityRequest = 0x0B,
        PairingPublicKey = 0x0C,
        PairingDhKeyCheck = 0x0D,
        PairingKeypressNotification = 0x0E,
    }
}

enum_with_unknown! {
    /// Describes the I/O capabilities of a device that can be used for the pairing process.
    #[derive(Debug, Copy, Clone, defmt::Format)]
    pub enum IoCapabilities(u8) {
        /// Device can display a 6-digit number, but has no input capabilities.
        DisplayOnly = 0x00,

        /// Device can display a 6-digit number and the user can input "Yes" or "No".
        DisplayYesNo = 0x01,

        /// Device does not have output capability, but the user can input a passcode.
        KeyboardOnly = 0x02,

        /// Device has no meaningful input and output capabilities.
        NoInputNoOutput = 0x03,

        /// Device can display a 6-digit passcode and allows passcode entry via a keyboard.
        KeyboardDisplay = 0x04,
    }
}

enum_with_unknown! {
    #[derive(Debug, Copy, Clone, defmt::Format)]
    pub enum Oob(u8) {
        NotPresent = 0x00,
        Present = 0x01,
    }
}

/// Authentication requirements exchanged during pairing requests.
#[derive(Copy, Clone)]
pub struct AuthReq(u8);

impl AuthReq {
    const BITS_BONDING: u8 = 0b0000_0011;
    const BITS_MITM: u8 = 0b0000_0100;
    const BITS_SC: u8 = 0b0000_1000;
    const BITS_KEYPRESS: u8 = 0b0001_0000;

    /// Returns the requested bonding.
    pub fn bonding_type(&self) -> BondingType {
        BondingType::from(self.0 & Self::BITS_BONDING)
    }

    pub fn set_bonding_type(&mut self, ty: BondingType) {
        self.0 = (self.0 & !Self::BITS_BONDING) | u8::from(ty);
    }

    /// Returns whether MITM protection is requested.
    pub fn mitm(&self) -> bool {
        self.0 & Self::BITS_MITM != 0
    }

    pub fn set_mitm(&mut self, mitm: bool) {
        self.0 = (self.0 & !Self::BITS_MITM) | if mitm { Self::BITS_MITM } else { 0 };
    }

    /// Returns whether *LE Secure Connection* pairing is supported and requested.
    ///
    /// If this returns `false`, *LE Legacy Pairing* will be used. Note that Rubble does not support
    /// *LE Legacy Pairing* at the moment since it has serious security problems (refer to the
    /// module docs for more info).
    pub fn secure_connection(&self) -> bool {
        self.0 & Self::BITS_SC != 0
    }

    /// Sets whether *LE Secure Connection* pairing is supported and requested.
    pub fn set_secure_connection(&mut self, sc: bool) {
        self.0 = (self.0 & !Self::BITS_SC) | if sc { Self::BITS_SC } else { 0 };
    }

    pub fn keypress(&self) -> bool {
        self.0 & Self::BITS_KEYPRESS != 0
    }

    pub fn set_keypress(&mut self, keypress: bool) {
        self.0 = (self.0 & !Self::BITS_KEYPRESS) | if keypress { Self::BITS_KEYPRESS } else { 0 };
    }
}

impl fmt::Debug for AuthReq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthReq")
            .field("bonding_type", &self.bonding_type())
            .field("mitm", &self.mitm())
            .field("secure_connection", &self.secure_connection())
            .field("keypress", &self.keypress())
            .finish()
    }
}

impl RawRepr<u8> for AuthReq {
    fn from_raw(raw: u8) -> Self {
        Self(raw)
    }

    fn as_raw(&self) -> u8 {
        self.0
    }
}

enum_with_unknown! {
    /// Whether to perform bonding in addition to pairing.
    ///
    /// If `Bonding` is selected, the exchanged keys are permanently stored on both devices. This
    /// is usually what you want.
    #[derive(Debug, Copy, Clone, defmt::Format)]
    pub enum BondingType(u8) {
        /// No bonding should be performed; the exchanged keys should not be permanently stored.
        ///
        /// This is usually not what you want since it requires the user to perform pairing every
        /// time the devices connect again.
        NoBonding = 0b00,

        /// Permanently store the exchanged keys to allow resuming encryption on future connections.
        Bonding = 0b01,
    }
}

bitflags! {
    /// Indicates which types of keys a device requests for distribution.
    struct KeyDistribution: u8 {
        const ENC_KEY = 1 << 0;
        const ID_KEY = 1 << 1;
        const SIGN_KEY = 1 << 2;
        const LINK_KEY = 1 << 3;
    }
}

impl RawRepr<u8> for KeyDistribution {
    fn from_raw(raw: u8) -> Self {
        Self::from_bits_truncate(raw)
    }

    fn as_raw(&self) -> u8 {
        self.bits()
    }
}

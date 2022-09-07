//! Elliptic Curve Diffie-Hellman (ECDH) on P-256.
//!
//! BLE uses ECDH on P-256 for pairing. This module provides an interface for plugging in different
//! implementations of the P-256 operations. The main consumer of this module is the [`security`]
//! module; refer to that for more info about pairing and encryption in BLE.
//!
//! The primary trait in this module is [`EcdhProvider`]. Rubble comes with 2 built-in
//! implementations of that trait:
//!
//! * [`P256Provider`] and [`P256SecretKey`]: These use the pure-Rust [`p256`] crate and are always
//!   available.
//! * [`RingProvider`] and [`RingSecretKey`] (behind the **`ring`** Cargo feature): These use the
//!   [*ring*][ring] library to provide the operations. Note that *ring* does not support
//!   `#![no_std]` operation, so this is mostly useful for tests and other non-embedded usage.
//!
//! [`security`]: crate::security
//! [ring]: https://github.com/briansmith/ring
//! [`p256`]: https://docs.rs/p256

mod p256;

pub use self::p256::*;

#[cfg(feature = "ring")]
mod ring;

#[cfg(feature = "ring")]
pub use self::ring::*;

use core::fmt;
use rand_core::{CryptoRng, RngCore};

/// A P-256 public key (point on the curve) in uncompressed format.
///
/// The encoding is as specified in *[SEC 1: Elliptic Curve Cryptography]*, but without the leading
/// `0x04` byte: The first 32 Bytes are the big-endian encoding of the point's X coordinate, and the
/// remaining 32 Bytes are the Y coordinate, encoded the same way.
///
/// Note that this type does not provide any validity guarantees (unlike [`PrivateKey`]
/// implementors): It is possible to represent invalid public P-256 keys, such as the point at
/// infinity, with this type. The other APIs in this module are designed to take that into account.
///
/// [SEC 1: Elliptic Curve Cryptography]: http://www.secg.org/sec1-v2.pdf
/// [`PrivateKey`]: trait.PrivateKey.html
pub struct PublicKey(pub [u8; 64]);

/// A shared secret resulting from an ECDH key agreement.
///
/// This is returned by implementations of [`SecretKey::agree`].
///
/// [`SecretKey::agree`]: trait.SecretKey.html#tymethod.agree
pub struct SharedSecret(pub [u8; 32]);

/// Error returned by [`SecretKey::agree`] when the public key of the other party is invalid.
///
/// [`SecretKey::agree`]: trait.SecretKey.html#tymethod.agree
#[derive(Debug)]
pub struct InvalidPublicKey {}

impl InvalidPublicKey {
    /// Creates a new `InvalidPublicKey` error.
    pub fn new() -> Self {
        Self {}
    }
}

impl fmt::Display for InvalidPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid public key")
    }
}

/// Trait for ECDH providers.
pub trait EcdhProvider {
    /// Provider-defined secret key type.
    type SecretKey: SecretKey;

    /// Generates a P-256 key pair using cryptographically strong randomness.
    ///
    /// Implementors must ensure that they only return valid private/public key pairs from this
    /// method.
    ///
    /// Rubble will pass a cryptographically secure random number generator `rng` to this function
    /// that may be used to obtain entropy for key generation. Implementations may also use their
    /// own RNG if they so choose.
    fn generate_keypair<R>(&mut self, rng: &mut R) -> (Self::SecretKey, PublicKey)
    where
        R: RngCore + CryptoRng;
}

/// Secret key operations required by Rubble.
///
/// This API imposes no requirements on the representation or location of secret keys. This means
/// that it should be possible to implement this trait even for keys stored in some secure key
/// storage like a smartcard.
pub trait SecretKey: Sized {
    /// Performs ECDH key agreement using an ephemeral secret key `self` and the public key of the
    /// other party.
    ///
    /// Here, "ephemeral" just means that this method takes `self` by value. This allows
    /// implementing `SecretKey` for providers that enforce single-use keys using Rust ownership
    /// (like *ring*).
    ///
    /// # Errors
    ///
    /// If `foreign_key` is an invalid public key, implementors must return an error.
    fn agree(self, foreign_key: &PublicKey) -> Result<SharedSecret, InvalidPublicKey>;
}

/// Runs Rubble's P-256 provider testsuite against `provider`.
///
/// Note that this is just a quick smoke test that does not provide any assurance about security
/// properties. The P-256 provider should have a dedicated test suite.
pub fn run_tests(mut provider: impl EcdhProvider) {
    static RNG: &[u8] = &[
        0x1e, 0x66, 0x81, 0xb6, 0xa3, 0x4e, 0x06, 0x97, 0x75, 0xbe, 0xd4, 0x5c, 0xf9, 0x52, 0x3f,
        0xf1, 0x5b, 0x6a, 0x72, 0xe2, 0xb8, 0x35, 0xb3, 0x29, 0x5e, 0xe0, 0xbb, 0x92, 0x35, 0xa5,
        0xb9, 0x60, 0xc9, 0xaf, 0xe2, 0x72, 0x12, 0xf1, 0xc4, 0xfc, 0x10, 0x2d, 0x63, 0x2f, 0x05,
        0xd6, 0xe5, 0x0a, 0xbf, 0x2c, 0xb9, 0x02, 0x3a, 0x67, 0x23, 0x63, 0x36, 0x7a, 0x62, 0xe6,
        0x63, 0xce, 0x28, 0x98,
    ];

    // Pretend-RNG that returns a fixed sequence of pregenerated numbers. Do not do this outside of
    // tests.
    struct Rng(&'static [u8]);

    impl RngCore for Rng {
        fn next_u32(&mut self) -> u32 {
            rand_core::impls::next_u32_via_fill(self)
        }
        fn next_u64(&mut self) -> u64 {
            rand_core::impls::next_u64_via_fill(self)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            if self.0.len() < dest.len() {
                panic!("p256::run_tests: ran out of pregenerated entropy");
            }

            for chunk in dest.chunks_mut(self.0.len()) {
                chunk.copy_from_slice(&self.0[..chunk.len()]);
                self.0 = &self.0[chunk.len()..];
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for Rng {}

    // Test that different key pairs will be generated:
    let mut rng = Rng(RNG);
    let (secret1, public1) = provider.generate_keypair(&mut rng);
    let (secret2, public2) = provider.generate_keypair(&mut rng);
    assert_ne!(&public1.0[..], &public2.0[..]);

    // Test that ECDH agreement results in the same shared secret:
    let shared1 = secret1.agree(&public2).unwrap();
    let shared2 = secret2.agree(&public1).unwrap();
    assert_eq!(shared1.0, shared2.0);

    // Now, test that ECDH agreement with invalid public keys fails correctly.

    // Point at infinity is an invalid public key:
    let infty = PublicKey([0; 64]);
    let (secret, _) = provider.generate_keypair(&mut Rng(RNG));
    assert!(secret.agree(&infty).is_err());

    // Malicious public key not on the curve:
    // (taken from https://web-in-security.blogspot.com/2015/09/practical-invalid-curve-attacks.html)
    let x = [
        0xb7, 0x0b, 0xf0, 0x43, 0xc1, 0x44, 0x93, 0x57, 0x56, 0xf8, 0xf4, 0x57, 0x8c, 0x36, 0x9c,
        0xf9, 0x60, 0xee, 0x51, 0x0a, 0x5a, 0x0f, 0x90, 0xe9, 0x3a, 0x37, 0x3a, 0x21, 0xf0, 0xd1,
        0x39, 0x7f,
    ];
    let y = [
        0x4a, 0x2e, 0x0d, 0xed, 0x57, 0xa5, 0x15, 0x6b, 0xb8, 0x2e, 0xb4, 0x31, 0x4c, 0x37, 0xfd,
        0x41, 0x55, 0x39, 0x5a, 0x7e, 0x51, 0x98, 0x8a, 0xf2, 0x89, 0xcc, 0xe5, 0x31, 0xb9, 0xc1,
        0x71, 0x92,
    ];
    let mut key = [0; 64];
    key[..32].copy_from_slice(&x);
    key[32..].copy_from_slice(&y);

    let (secret, _) = provider.generate_keypair(&mut Rng(RNG));
    assert!(secret.agree(&PublicKey(key)).is_err());
}

//! ChaCha12 CSPRNG registered as the `embassy-crypto` RNG driver, seeded from
//! a hardware entropy source at startup.

use core::cell::RefCell;

use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use rand_chacha::ChaCha12Rng;
use rand_chacha::rand_core::{RngCore as _, SeedableRng as _};

static RNG: Mutex<CriticalSectionRawMutex, RefCell<Option<ChaCha12Rng>>> = Mutex::new(RefCell::new(None));

/// Seed the CSPRNG. Must be called before the BLE stack is created.
pub fn seed(seed: [u8; 32]) {
    RNG.lock(|rng| rng.replace(Some(ChaCha12Rng::from_seed(seed))));
}

struct Driver;

impl embassy_crypto::driver::Rng for Driver {
    fn fill_bytes(buf: &mut [u8]) {
        RNG.lock(|rng| {
            let mut rng = rng.borrow_mut();
            let rng = rng.as_mut().expect("CSPRNG used before it was seeded");
            rng.fill_bytes(buf);
        })
    }
}

embassy_crypto::rng_impl!(Driver);

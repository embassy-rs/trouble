#![no_std]
#![cfg(feature = "security")]

use {
    chacha20::ChaCha12Rng,
    core::default::Default,
    embassy_nrf::mode::Async,
    rand_core::SeedableRng
};

// Needed until 'embassy_nrf' supports 'rand_core' 0.10.
pub fn chacha_from_nrf_rng(rng: &mut embassy_nrf::rng::Rng<Async>) -> ChaCha12Rng {
    let mut seed = <ChaCha12Rng as SeedableRng>::Seed::default();
    rng.blocking_fill_bytes(seed.as_mut());
    ChaCha12Rng::from_seed(seed)
}

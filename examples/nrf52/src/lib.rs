#![no_std]
#![cfg(feature = "security")]

use {
    core::default::Default,
    embassy_nrf::mode::Async,
    rand::rand_core::SeedableRng,
    rand::rngs::ChaCha12Rng,
};

// Needed until 'embassy_nrf' supports 'rand_core' 0.10.
//  -> https://github.com/embassy-rs/embassy/blob/main/embassy-nrf/Cargo.toml
pub fn chacha_from_nrf_rng(rng: &mut embassy_nrf::rng::Rng<Async>) -> ChaCha12Rng {
    let mut seed = <ChaCha12Rng as SeedableRng>::Seed::default();
    rng.blocking_fill_bytes(seed.as_mut());
    ChaCha12Rng::from_seed(seed)
}

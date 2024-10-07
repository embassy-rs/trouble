#!/bin/bash

set -eo pipefail

if ! command -v cargo-batch &> /dev/null; then
    cargo install --git https://github.com/embassy-rs/cargo-batch cargo --bin cargo-batch --locked
fi

export RUSTFLAGS=-Dwarnings
export DEFMT_LOG=trace
export CARGO_NET_GIT_FETCH_WITH_CLI=true
if [[ -z "${CARGO_TARGET_DIR}" ]]; then
    export CARGO_TARGET_DIR=target_ci
fi

cargo batch \
    --- build --release -p trouble-nrf-sdc-examples --target thumbv7em-none-eabihf --features nrf52840 \
    --- build --release -p trouble-nrf-sdc-examples --target thumbv7em-none-eabihf --features nrf52832 \
    --- build --release -p trouble-esp32-examples --target riscv32imc-unknown-none-elf \
    --- build --release -p serial-hci \
    --- build --release -p trouble-rp-examples --target thumbv6m-none-eabi --features skip-cyw43-firmware \
    --- build --release -p trouble-host --features peripheral \
    --- build --release -p trouble-host --features central \
    --- build --release -p trouble-host --features gatt,peripheral \
    --- build --release -p trouble-host --features gatt,central \
    --- build --release -p trouble-host --features gatt,peripheral,central,scan
#   --- build --release --manifest-path examples/apache-nimble/Cargo.toml --target thumbv7em-none-eabihf

cargo fmt --check
cargo clippy --features gatt,peripheral,central
cargo test -- --nocapture

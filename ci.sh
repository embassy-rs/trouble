#!/bin/bash

set -eo pipefail

# Check formatting before anything else; it's a fast check.
#
cargo +nightly fmt --check --manifest-path ./host/Cargo.toml
cargo +nightly fmt --check --manifest-path ./host-macros/Cargo.toml

cargo clippy --manifest-path ./host/Cargo.toml --features central,gatt,peripheral,scan,security

if ! command -v cargo-batch &> /dev/null; then
    mkdir -p $HOME/.cargo/bin
    curl -L https://github.com/embassy-rs/cargo-batch/releases/download/batch-0.6.0/cargo-batch > $HOME/.cargo/bin/cargo-batch
    chmod +x $HOME/.cargo/bin/cargo-batch
fi

export RUSTFLAGS=-Dwarnings
export DEFMT_LOG=trace
export CARGO_NET_GIT_FETCH_WITH_CLI=true
if [[ -z "${CARGO_TARGET_DIR}" ]]; then
    export CARGO_TARGET_DIR=target_ci
fi

cargo batch \
    --- build --release --manifest-path host/Cargo.toml --no-default-features --features peripheral \
    --- build --release --manifest-path host/Cargo.toml --no-default-features --features central \
    --- build --release --manifest-path host/Cargo.toml --no-default-features --features central,scan \
    --- build --release --manifest-path host/Cargo.toml --no-default-features --features central,peripheral \
    --- build --release --manifest-path host/Cargo.toml --no-default-features --features central,peripheral,defmt \
    --- build --release --manifest-path host/Cargo.toml --no-default-features --features gatt,peripheral \
    --- build --release --manifest-path host/Cargo.toml --no-default-features --features gatt,central \
    --- build --release --manifest-path host/Cargo.toml --no-default-features --features gatt,peripheral,central,scan \
    --- build --release --manifest-path host/Cargo.toml --no-default-features --features gatt,peripheral,central,scan,security \
    --- build --release --manifest-path host/Cargo.toml --no-default-features --features gatt,peripheral,central,scan,controller-host-flow-control \
    --- build --release --manifest-path host/Cargo.toml --no-default-features --features gatt,peripheral,central,scan,controller-host-flow-control,connection-metrics,channel-metrics \
    --- build --release --manifest-path host/Cargo.toml --no-default-features --features gatt,peripheral,central,scan,controller-host-flow-control,connection-metrics,channel-metrics,l2cap-sdu-reassembly-optimization \
    --- build --release --manifest-path bt-hci-linux/Cargo.toml \
    --- build --release --manifest-path examples/nrf-sdc/Cargo.toml --target thumbv7em-none-eabihf --features nrf52840 \
    --- build --release --manifest-path examples/nrf-sdc/Cargo.toml --target thumbv7em-none-eabihf --features nrf52840,security \
    --- build --release --manifest-path examples/nrf-sdc/Cargo.toml --target thumbv7em-none-eabihf --features nrf52833 --artifact-dir tests/nrf-sdc \
    --- build --release --manifest-path examples/nrf-sdc/Cargo.toml --target thumbv7em-none-eabihf --features nrf52832 \
    --- build --release --manifest-path examples/esp32/Cargo.toml --features esp32c3 --target riscv32imc-unknown-none-elf --artifact-dir tests/esp32 \
    --- build --release --manifest-path examples/serial-hci/Cargo.toml \
    --- build --release --manifest-path examples/linux/Cargo.toml \
    --- build --release --manifest-path examples/linux/Cargo.toml --features security \
    --- build --release --manifest-path examples/tests/Cargo.toml \
    --- build --release --manifest-path benchmarks/nrf-sdc/Cargo.toml --target thumbv7em-none-eabihf --features nrf52840 \
    --- build --release --manifest-path examples/rp-pico-w/Cargo.toml --target thumbv6m-none-eabi --features skip-cyw43-firmware \
    --- build --release --manifest-path examples/rp-pico-2-w/Cargo.toml --target thumbv8m.main-none-eabihf --features skip-cyw43-firmware
#    --- build --release --manifest-path examples/apache-nimble/Cargo.toml --target thumbv7em-none-eabihf

cargo test --manifest-path ./host/Cargo.toml --features central,gatt,peripheral,scan,security --lib -- --nocapture

# Running tests requires some hardware, so we just check they compile.
cargo test --manifest-path ./host/Cargo.toml --features central,gatt,peripheral,scan,security --no-run
cargo test --manifest-path ./examples/tests/Cargo.toml --no-run

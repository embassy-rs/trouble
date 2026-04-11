#!/bin/bash
## on push branch=main
## on pull_request
## priority 5
## dedup kill
## cooldown 30s
## device /dev/serial/by-id/usb-ZEPHYR_Zephyr_HCI_UART_sample_265650C6A0739A40-if00 /dev/serial/by-id/usb-ZEPHYR_Zephyr_HCI_UART_sample_265650C6A0739A40-if00 
## device /dev/serial/by-id/usb-ZEPHYR_Zephyr_HCI_UART_sample_CBBC59EDA8BA738E-if00 /dev/serial/by-id/usb-ZEPHYR_Zephyr_HCI_UART_sample_CBBC59EDA8BA738E-if00
## cooldown 1m

set -euxo pipefail


export CARGO_TARGET_DIR=/ci/cache/target
export RUST_LOG=trace
export DEFMT_LOG=trace
export RUST_TEST_THREADS=1

echo "Integration tests"
cargo test --manifest-path host/Cargo.toml --features log --test '*' -- --nocapture

if ! command -v cargo-batch &> /dev/null; then
    mkdir -p $HOME/.cargo/bin
    curl -L https://github.com/embassy-rs/cargo-batch/releases/download/batch-0.6.0/cargo-batch > $HOME/.cargo/bin/cargo-batch
    chmod +x $HOME/.cargo/bin/cargo-batch
fi

cargo install probe-rs-tools --git https://github.com/probe-rs/probe-rs --locked --features remote

if [ -f /ci/cache/lockfiles.tar ]; then
    echo Restoring lockfiles...
    tar xf /ci/cache/lockfiles.tar
fi

# Build firmware for targets
cargo batch \
    --- build --release --manifest-path examples/nrf52/Cargo.toml --target thumbv7em-none-eabihf --features nrf52833 --artifact-dir examples/tests/bins/nrf52 \
    --- build --release --manifest-path examples/esp32/Cargo.toml --features esp32c3 --target riscv32imc-unknown-none-elf --artifact-dir examples/tests/bins/esp32

# Read probe-rs token from bender's mounted secrets directory
if [[ ! -f /ci/secrets/probe-rs-token ]]; then
    echo "ERROR: /ci/secrets/probe-rs-token not found (this job must run as trusted)"
    exit 1
fi
PROBE_RS_TOKEN=$(cat /ci/secrets/probe-rs-token)

# Run example tests against real hardware via probe-rs (client mode)
export PROBE_CONFIG=$(jq --arg token "$PROBE_RS_TOKEN" '.server.token = $token' .ci/config.json)

echo "Example tests"
cargo test --manifest-path examples/tests/Cargo.toml -- --nocapture

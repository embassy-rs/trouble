#!/bin/bash

set -eo pipefail

if ! command -v cargo-batch &> /dev/null; then
    echo "cargo-batch could not be found. Install it with the following command:"
    echo ""
    echo "    cargo install --git https://github.com/embassy-rs/cargo-batch cargo --bin cargo-batch --locked"
    echo ""
    exit 1
fi

export RUSTFLAGS=-Dwarnings
export DEFMT_LOG=trace
export RUST_LOG=info


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
    --- build --release --manifest-path host/Cargo.toml --no-default-features --features gatt,peripheral,central,scan,legacy-pairing \
    --- build --release --manifest-path host/Cargo.toml --no-default-features --features gatt,peripheral,central,scan,controller-host-flow-control \
    --- build --release --manifest-path host/Cargo.toml --no-default-features --features gatt,peripheral,central,scan,controller-host-flow-control,connection-metrics,channel-metrics \
    --- build --release --manifest-path host/Cargo.toml --no-default-features --features gatt,peripheral,central,scan,controller-host-flow-control,connection-metrics,channel-metrics,l2cap-sdu-reassembly-optimization \
    --- build --release --manifest-path host/Cargo.toml --no-default-features --features gatt,peripheral,central,scan,controller-host-flow-control,connection-metrics,channel-metrics,l2cap-sdu-reassembly-optimization,connection-params-update \
    --- build --release --manifest-path bt-hci-linux/Cargo.toml \
    --- build --release --manifest-path bt-hci-usb/Cargo.toml \
    --- build --release --manifest-path examples/nrf52/Cargo.toml --target thumbv7em-none-eabihf --features nrf52840 \
    --- build --release --manifest-path examples/nrf52/Cargo.toml --target thumbv7em-none-eabihf --features nrf52840,security \
    --- build --release --manifest-path examples/nrf52/Cargo.toml --target thumbv7em-none-eabihf --features nrf52833 \
    --- build --release --manifest-path examples/nrf52/Cargo.toml --target thumbv7em-none-eabihf --features nrf52832 --artifact-dir examples/tests/bins/nrf52 \
    --- build --release --manifest-path examples/nrf54/Cargo.toml --target thumbv8m.main-none-eabihf --features nrf54l15 \
    --- build --release --manifest-path examples/esp32/Cargo.toml --features esp32c3 --target riscv32imc-unknown-none-elf --artifact-dir examples/tests/bins/esp32 \
    --- build --release --manifest-path examples/serial-hci/Cargo.toml \
    --- build --release --manifest-path examples/linux/Cargo.toml \
    --- build --release --manifest-path examples/linux/Cargo.toml --features security \
    --- build --release --manifest-path examples/usb-hci/Cargo.toml \
    --- build --release --manifest-path examples/usb-hci/Cargo.toml --features security \
    --- build --release --manifest-path examples/tests/Cargo.toml \
    --- build --release --manifest-path benchmarks/nrf-sdc/Cargo.toml --target thumbv7em-none-eabihf --features nrf52840 \
    --- build --release --manifest-path examples/rp-pico-w/Cargo.toml --target thumbv6m-none-eabi --features skip-cyw43-firmware \
    --- build --release --manifest-path examples/rp-pico-2-w/Cargo.toml --target thumbv8m.main-none-eabihf --features skip-cyw43-firmware \
    --- build --release --manifest-path tester/nrf52/Cargo.toml --target thumbv7em-none-eabihf --features nrf52840
#    --- build --release --manifest-path examples/apache-nimble/Cargo.toml --target thumbv7em-none-eabihf

cargo fmt --check --manifest-path ./host/Cargo.toml
cargo fmt --check --manifest-path ./tester/app/Cargo.toml
cargo fmt --check --manifest-path ./tester/nrf52/Cargo.toml
cargo clippy --manifest-path ./host/Cargo.toml --features gatt,peripheral,central,legacy-pairing
cargo test --manifest-path ./host/Cargo.toml --lib -- --nocapture
cargo test --manifest-path ./host/Cargo.toml --features central,gatt,peripheral,scan,security --lib -- --nocapture
cargo test --manifest-path ./host/Cargo.toml --features central,gatt,peripheral,scan,legacy-pairing --lib -- --nocapture
cargo test --manifest-path ./host/Cargo.toml --no-run -- --nocapture
cargo test --manifest-path ./examples/tests/Cargo.toml --no-run -- --nocapture
cargo test --manifest-path ./tester/app/Cargo.toml --lib -- --nocapture


if [[ -z "${HIL_TOKEN}" ]]; then
    echo "No HIL token found, skipping running HIL tests"
    exit
fi

export RUST_TEST_THREADS=1

echo "Integration tests"
cargo test --manifest-path host/Cargo.toml --features log --test '*' -- --nocapture

# echo "Example tests"
# 
# export PROBE_CONFIG=$(jq --arg token "$HIL_TOKEN" '.server.token = $token' .ci/config.json)
# 
# echo "Example tests"
# cargo test --manifest-path examples/tests/Cargo.toml -- --nocapture

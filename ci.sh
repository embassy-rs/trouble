#!/bin/bash

set -eo pipefail

if ! command -v cargo-batch &>/dev/null; then
	mkdir -p "$HOME"/.cargo/bin
	curl -L https://github.com/embassy-rs/cargo-batch/releases/download/batch-0.6.0/cargo-batch >"$HOME"/.cargo/bin/cargo-batch
	chmod +x "$HOME"/.cargo/bin/cargo-batch
fi


export RUSTFLAGS=-Dwarnings
export DEFMT_LOG=trace
export CARGO_NET_GIT_FETCH_WITH_CLI=true
if [[ -z "${CARGO_TARGET_DIR}" ]]; then
	export CARGO_TARGET_DIR=target_ci
fi
echo "Running Cargo Build"
cargo batch \
	--- build --release --manifest-path host/Cargo.toml --no-default-features --features peripheral \
	--- build --release --manifest-path host/Cargo.toml --no-default-features --features central \
	--- build --release --manifest-path host/Cargo.toml --no-default-features --features central,scan \
	--- build --release --manifest-path host/Cargo.toml --no-default-features --features central,peripheral \
	--- build --release --manifest-path host/Cargo.toml --no-default-features --features central,peripheral,defmt \
	--- build --release --manifest-path host/Cargo.toml --no-default-features --features gatt,peripheral \
	--- build --release --manifest-path host/Cargo.toml --no-default-features --features gatt,central \
	--- build --release --manifest-path host/Cargo.toml --no-default-features --features gatt,peripheral,central,scan \
	--- build --release --manifest-path examples/nrf-sdc/Cargo.toml --target thumbv7em-none-eabihf --features nrf52840 \
	--- build --release --manifest-path examples/nrf-sdc/Cargo.toml --target thumbv7em-none-eabihf --features nrf52833 --artifact-dir tests/nrf-sdc \
	--- build --release --manifest-path examples/nrf-sdc/Cargo.toml --target thumbv7em-none-eabihf --features nrf52832 \
	--- build --release --manifest-path examples/esp32/Cargo.toml --features esp32c3 --target riscv32imc-unknown-none-elf --artifact-dir tests/esp32 \
	--- build --release --manifest-path examples/serial-hci/Cargo.toml \
	--- build --release --manifest-path examples/tests/Cargo.toml \
	--- build --release --manifest-path examples/rp-pico-w/Cargo.toml --target thumbv6m-none-eabi --features skip-cyw43-firmware \
	--- build --release --manifest-path examples/rp-pico-2-w/Cargo.toml --target thumbv8m.main-none-eabihf --features skip-cyw43-firmware \
    --- build --release --manifest-path host/Cargo.toml --no-default-features --features peripheral \
    --- build --release --manifest-path host/Cargo.toml --no-default-features --features central \
    --- build --release --manifest-path host/Cargo.toml --no-default-features --features central,scan \
    --- build --release --manifest-path host/Cargo.toml --no-default-features --features central,peripheral \
    --- build --release --manifest-path host/Cargo.toml --no-default-features --features central,peripheral,defmt \
    --- build --release --manifest-path host/Cargo.toml --no-default-features --features gatt,peripheral \
    --- build --release --manifest-path host/Cargo.toml --no-default-features --features gatt,central \
    --- build --release --manifest-path host/Cargo.toml --no-default-features --features gatt,peripheral,central,scan \
    --- build --release --manifest-path host/Cargo.toml --no-default-features --features gatt,peripheral,central,scan,controller-host-flow-control \
    --- build --release --manifest-path examples/nrf-sdc/Cargo.toml --target thumbv7em-none-eabihf --features nrf52840 \
    --- build --release --manifest-path examples/nrf-sdc/Cargo.toml --target thumbv7em-none-eabihf --features nrf52833 --artifact-dir tests/nrf-sdc \
    --- build --release --manifest-path examples/nrf-sdc/Cargo.toml --target thumbv7em-none-eabihf --features nrf52832 \
    --- build --release --manifest-path examples/esp32/Cargo.toml --features esp32c3 --target riscv32imc-unknown-none-elf --artifact-dir tests/esp32 \
    --- build --release --manifest-path examples/serial-hci/Cargo.toml \
    --- build --release --manifest-path examples/tests/Cargo.toml \
    --- build --release --manifest-path benchmarks/nrf-sdc/Cargo.toml --target thumbv7em-none-eabihf --features nrf52840 \
    --- build --release --manifest-path examples/rp-pico-w/Cargo.toml --target thumbv6m-none-eabi --features skip-cyw43-firmware \
    --- build --release --manifest-path examples/rp-pico-2-w/Cargo.toml --target thumbv8m.main-none-eabihf --features skip-cyw43-firmware
#    --- build --release --manifest-path examples/apache-nimble/Cargo.toml --target thumbv7em-none-eabihf

# Run Cargo fmt
echo "Running Cargo fmt"
cargo batch  \
	--- fmt --manifest-path host/Cargo.toml -- --check \
	--- fmt --manifest-path host-macros/Cargo.toml -- --check \
	--- fmt --manifest-path examples/apache-nimble/Cargo.toml -- --check \
	--- fmt --manifest-path examples/apps/Cargo.toml -- --check \
	--- fmt --manifest-path examples/esp32/Cargo.toml -- --check \
	--- fmt --manifest-path examples/nrf-sdc/Cargo.toml -- --check \
	--- fmt --manifest-path examples/rp-pico-2-w/Cargo.toml -- --check \
	--- fmt --manifest-path examples/rp-pico-w/Cargo.toml -- --check \
	--- fmt --manifest-path examples/serial-hci/Cargo.toml -- --check \
	--- fmt --manifest-path examples/tests/Cargo.toml -- --check \


# Clippy Main Library
echo "Running Cargo Clippy"
cd host && cargo clippy -- -D warnings && cd ..
cd host-macros && cargo clippy -- -D warnings  && cd ..

# Clippy Examples
cd examples
cd apache-nimble && cargo clippy -- -D warnings  && cd ..
cd apps && cargo clippy -- -D warnings  && cd ..
# ESP32 Examples
cd esp32 && cargo clippy --no-default-features --features=esp32 --target=xtensa-esp32-none-elf -- -D warnings  && cd ..
cd esp32c2 && cargo clippy --no-default-features --features=esp32c2 --target=riscv32imc-unknown-none-elf -- -D warnings && cd ..
cd esp32c3 && cargo clippy --no-default-features --features=esp32c3 --target=riscv32imc-unknown-none-elf -- -D warnings && cd..
cd esp32c6 && cargo clippy --no-default-features --features=esp32c6 --target=riscv32imac-unknown-none-elf -- -D warnings && cd..
cd esp32h2 && cargo clippy  --no-default-features --features=esp32h2 --target=riscv32imac-unknown-none-elf -- -D warnings && cd..
cd esp32s3 && cargo clippy --no-default-features --features=esp32s3 --target=xtensa-esp32s3-none-elf -- -D warnings && cd..
# nrf-sdc
cd nrf-sdc
cargo clippy --features=nrf52832  -- -D warnings
cargo clippy --features=nrf52833  -- -D warnings
cargo clippy --features=nrf52840  -- -D warnings
cd..
# rp-pico-2-w
cd rp-pico-2-w && cargo clippy -- --D warnings && cd..
# rp-pico-w
cd rp-pico-w && cargo clippy -- --D warnings && cd..
# serial-hci
cd serial-hci && cargo clippy -- --D warnings && cd..
# tests
cd tests && cargo clippy -- --D warnings && cd..
# Leave examples folder
cd..

# Run and install MegaLinter (if enabled)


# Run tests
echo "Running Cargo Clippy"
cargo test --manifest-path ./host/Cargo.toml --lib -- --nocapture
cargo test --manifest-path ./host/Cargo.toml --no-run -- --nocapture
cargo test --manifest-path ./examples/tests/Cargo.toml --no-run -- --nocapture

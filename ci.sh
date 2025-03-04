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
# cargo batch \
# 	--- build --release --manifest-path host/Cargo.toml --no-default-features --features peripheral \
# 	--- build --release --manifest-path host/Cargo.toml --no-default-features --features central \
# 	--- build --release --manifest-path host/Cargo.toml --no-default-features --features central,scan \
# 	--- build --release --manifest-path host/Cargo.toml --no-default-features --features central,peripheral \
# 	--- build --release --manifest-path host/Cargo.toml --no-default-features --features central,peripheral,defmt \
# 	--- build --release --manifest-path host/Cargo.toml --no-default-features --features gatt,peripheral \
# 	--- build --release --manifest-path host/Cargo.toml --no-default-features --features gatt,central \
# 	--- build --release --manifest-path host/Cargo.toml --no-default-features --features gatt,peripheral,central,scan \
# 	--- build --release --manifest-path examples/nrf-sdc/Cargo.toml --target thumbv7em-none-eabihf --features nrf52840 \
# 	--- build --release --manifest-path examples/nrf-sdc/Cargo.toml --target thumbv7em-none-eabihf --features nrf52833 --artifact-dir tests/nrf-sdc \
# 	--- build --release --manifest-path examples/nrf-sdc/Cargo.toml --target thumbv7em-none-eabihf --features nrf52832 \
# 	--- build --release --manifest-path examples/esp32/Cargo.toml --features esp32c3 --target riscv32imc-unknown-none-elf --artifact-dir tests/esp32 \
# 	--- build --release --manifest-path examples/serial-hci/Cargo.toml \
# 	--- build --release --manifest-path examples/tests/Cargo.toml \
# 	--- build --release --manifest-path examples/rp-pico-w/Cargo.toml --target thumbv6m-none-eabi --features skip-cyw43-firmware \
# 	--- build --release --manifest-path examples/rp-pico-2-w/Cargo.toml --target thumbv8m.main-none-eabihf --features skip-cyw43-firmware \
#     --- build --release --manifest-path host/Cargo.toml --no-default-features --features peripheral \
#     --- build --release --manifest-path host/Cargo.toml --no-default-features --features central \
#     --- build --release --manifest-path host/Cargo.toml --no-default-features --features central,scan \
#     --- build --release --manifest-path host/Cargo.toml --no-default-features --features central,peripheral \
#     --- build --release --manifest-path host/Cargo.toml --no-default-features --features central,peripheral,defmt \
#     --- build --release --manifest-path host/Cargo.toml --no-default-features --features gatt,peripheral \
#     --- build --release --manifest-path host/Cargo.toml --no-default-features --features gatt,central \
#     --- build --release --manifest-path host/Cargo.toml --no-default-features --features gatt,peripheral,central,scan \
#     --- build --release --manifest-path host/Cargo.toml --no-default-features --features gatt,peripheral,central,scan,controller-host-flow-control \
#     --- build --release --manifest-path examples/nrf-sdc/Cargo.toml --target thumbv7em-none-eabihf --features nrf52840 \
#     --- build --release --manifest-path examples/nrf-sdc/Cargo.toml --target thumbv7em-none-eabihf --features nrf52833 --artifact-dir tests/nrf-sdc \
#     --- build --release --manifest-path examples/nrf-sdc/Cargo.toml --target thumbv7em-none-eabihf --features nrf52832 \
#     --- build --release --manifest-path examples/esp32/Cargo.toml --features esp32c3 --target riscv32imc-unknown-none-elf --artifact-dir tests/esp32 \
#     --- build --release --manifest-path examples/serial-hci/Cargo.toml \
#     --- build --release --manifest-path examples/tests/Cargo.toml \
#     --- build --release --manifest-path benchmarks/nrf-sdc/Cargo.toml --target thumbv7em-none-eabihf --features nrf52840 \
#     --- build --release --manifest-path examples/rp-pico-w/Cargo.toml --target thumbv6m-none-eabi --features skip-cyw43-firmware \
#     --- build --release --manifest-path examples/rp-pico-2-w/Cargo.toml --target thumbv8m.main-none-eabihf --features skip-cyw43-firmware
# #    --- build --release --manifest-path examples/apache-nimble/Cargo.toml --target thumbv7em-none-eabihf

# Run Cargo fmt
echo "Running Cargo fmt"
# cargo batch  \
# 	--- fmt --manifest-path host/Cargo.toml -- --check \
# 	--- fmt --manifest-path host-macros/Cargo.toml -- --check \
# 	--- fmt --manifest-path examples/apache-nimble/Cargo.toml -- --check \
# 	--- fmt --manifest-path examples/apps/Cargo.toml -- --check \
# 	--- fmt --manifest-path examples/esp32/Cargo.toml -- --check \
# 	--- fmt --manifest-path examples/nrf-sdc/Cargo.toml -- --check \
# 	--- fmt --manifest-path examples/rp-pico-2-w/Cargo.toml -- --check \
# 	--- fmt --manifest-path examples/rp-pico-w/Cargo.toml -- --check \
# 	--- fmt --manifest-path examples/serial-hci/Cargo.toml -- --check \
# 	--- fmt --manifest-path examples/tests/Cargo.toml -- --check \

# Clippy Main Library
echo "Running Cargo Clippy"
cd host && cargo clippy -- -D warnings && cd ..
cd host-macros && cargo clippy -- -D warnings && cd ..

# Clippy Examples
cd examples
echo "Running Cargo Clippy on the examples directory"
# cd apache-nimble && cargo clippy -- -D warnings  && cd ..
cd apps && cargo clippy -- -D warnings && cd ..

# ESP32 Examples
echo "Running Cargo Clippy on ESP32 examples"
cd esp32
# cd esp32 && cargo clippy --no-default-features --features=esp32 --target=xtensa-esp32-none-elf -- -D warnings  && cd ..
cargo clippy --no-default-features --features=esp32c2 --target=riscv32imc-unknown-none-elf -- -D warnings
cargo clippy --no-default-features --features=esp32c3 --target=riscv32imc-unknown-none-elf -- -D warnings
cargo clippy --no-default-features --features=esp32c6 --target=riscv32imac-unknown-none-elf -- -D warnings
cargo clippy --no-default-features --features=esp32h2 --target=riscv32imac-unknown-none-elf -- -D warnings
# cargo clippy --no-default-features --features=esp32s3 --target=xtensa-esp32s3-none-elf -- -D warnings
cd ..
# nrf-sdc
echo "Running Cargo Clippy on nrf-sdc example"
cd nrf-sdc
# cargo clippy --features=nrf52832  -- -D warnings
# cargo clippy --features=nrf52833  -- -D warnings
# cargo clippy --features=nrf52840  -- -D warnings
cd ..

# rp-pico-2-w
echo "Running Cargo Clippy on rp-pico-2-w example"
cd rp-pico-2-w && cargo clippy -- --D warnings && cd ..

# rp-pico-w
echo "Running Cargo Clippy on rp-pico-w example"
cd rp-pico-w && cargo clippy -- --D warnings && cd ..

# serial-hci
echo "Running Cargo Clippy on serial-hci example"
cd serial-hci && cargo clippy -- --D warnings && cd ..

# tests
echo "Running Cargo Clippy on tests example"
cd tests && cargo clippy -- --D warnings && cd ..
# Leave examples folder
cd ..

# Enable MegaLinter (you can set this flag in your CI/CD or local environment)
ENABLE_MEGALINTER=${ENABLE_MEGALINTER:-true} # Use variable or default to true
# Run and install MegaLinter (if enabled)
# Check if MegaLinter should be enabled
if [ "$ENABLE_MEGALINTER" = true ]; then
	echo "MegaLinter is enabled. Installing and running..."

	# Check if Node.js is installed; install if necessary
	if ! command -v node >/dev/null 2>&1; then
		install_node
	fi
	# Install MegaLinter globally (if not already installed)
	if ! command -v mega-linter-runner >/dev/null 2>&1; then
		echo "Installing MegaLinter..."
		npm install -g mega-linter-runner
	else
		echo "MegaLinter is already installed."
	fi

	# Run MegaLinter
	echo "Running MegaLinter..."
	mega-linter-runner
else
	echo "MegaLinter is not enabled. Skipping..."
fi

# Run tests
echo "Running Cargo test"
cargo test --manifest-path ./host/Cargo.toml --lib -- --nocapture
cargo test --manifest-path ./host/Cargo.toml --no-run -- --nocapture
cargo test --manifest-path ./examples/tests/Cargo.toml --no-run -- --nocapture

# Function to install Node.js if not installed
install_node() {
	echo "Node.js is not installed. Installing..."
	# Detect OS and install Node.js
	if [ "$(uname)" = "Darwin" ]; then
		brew install node
	elif [ "$(uname -s)" = "Linux" ]; then
		apt-get install nodejs
	else
		echo "Unsupported operating system. Please install Node.js manually."
		exit 1
	fi

	# Confirm npm is now available after Node.js installation
	if ! command -v npm >/dev/null 2>&1; then
		echo "npm is not available even after Node.js installation. Please check your installation."
		exit 1
	fi
}

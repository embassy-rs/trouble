# nRF examples

## Setup

These examples are set up assuming you are using [probe-rs](https://probe.rs) for flashing and debugging your chips.  Make sure you have it with:

```bash
cargo install cargo-binstall # binary installer tool (optional but recommended)
cargo binstall probe-rs-tools # or cargo install if you don't use binstall
```

You may also need to install the chip's toolchain too, if so that would be done with, for example:

```bash
rustup target add thumbv8m.main-none-eabihf
```

Build dependencies (nrf-sdc) also require clang to compile:

```bash
# Linux
sudo apt install llvm
# Windows (multiple ways to install)
choco install llvm 
# Mac
brew install llvm
```

We use features to turn on the appropriate configurations for the chip you are flashing to.  Currently supported chips are:

- `nrf54l15`

## Run

To build and run an example on your device, plug it in and run i.e.:

```bash
cd examples/nrf54 # make sure you are in the right directory

cargo run --release --features nrf54l15 --target thumbv8m.main-none-eabihf --bin ble_bas_peripheral
```

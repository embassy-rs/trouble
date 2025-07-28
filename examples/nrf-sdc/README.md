# nRF examples

## Setup

These examples are set up assuming you are using [probe-rs](https://probe.rs) for flashing and debugging your chips.  Make sure you have it with:

```bash
cargo install cargo-binstall # binary installer tool (optional but recommended)
cargo binstall probe-rs-tools # or cargo install if you don't use binstall
```

You may also need to install the chip's toolchain too, if so that would be done with, for example:

```bash
rustup target add thumbv7em-none-eabihf
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

- `nrf52832`
- `nrf52833`
- `nrf52840`

## Run

To build and run an example on your device, plug it in and run i.e.:

```bash
cd examples/nrf-sdc # make sure you are in the right directory

cargo run --release --features nrf52833 --target thumbv7em-none-eabihf --bin ble_bas_peripheral
```

See [microbit-bsp](https://github.com/lulf/microbit-bsp) for more examples of setting up nrf devices with trouble, specifically the BBC Microbit which is an nrf52833.

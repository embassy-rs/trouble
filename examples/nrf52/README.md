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

- `nrf52810`
- `nrf52832`
- `nrf52833`
- `nrf52840`

## Run

To build and run an example on your device, plug it in and run i.e.:

```bash
cd examples/nrf52 # make sure you are in the right directory

cargo run --release --features nrf52833 --target thumbv7em-none-eabihf --bin ble_bas_peripheral
```

## Peripheral-only builds

The `central`, `scan` and `extended-advertising` features are enabled by default. Turning them
off links the smaller peripheral-only SoftDevice Controller library, which saves around 32K of
flash, this matters on the nRF52810 which has only 192K flash.

```bash
cargo build --release --no-default-features --features nrf52810 --target thumbv7em-none-eabi --bin ble_bas_peripheral
```

This is required for the GATT examples on the nRF52810: with the default features they overflow
flash by a few KB.

## Boards with the Adafruit nRF52 bootloader

Many nRF52840 boards (Adafruit Feather nRF52840, nice!nano, Heltec T114, LilyGo T-Echo and
others) ship with the [Adafruit nRF52 bootloader](https://github.com/adafruit/Adafruit_nRF52_Bootloader)
and a SoftDevice in flash. The `adafruit-bootloader` feature links the examples behind them, so the
bootloader keeps working and no SWD probe is needed:

```bash
cargo build --release --features nrf52840,adafruit-bootloader --target thumbv7em-none-eabihf --bin ble_bas_peripheral
cargo objcopy --release --features nrf52840,adafruit-bootloader --target thumbv7em-none-eabihf --bin ble_bas_peripheral -- -O ihex ble_bas_peripheral.hex
uf2conv.py -c -f 0xADA52840 -o ble_bas_peripheral.uf2 ble_bas_peripheral.hex
```

`cargo objcopy` comes from [cargo-binutils](https://github.com/rust-embedded/cargo-binutils) and
`uf2conv.py` from [microsoft/uf2](https://github.com/microsoft/uf2/tree/master/utils). Double-tap
reset to get the bootloader drive, then copy the `.uf2` file onto it.

Things to know:

- `memory-nrf52840-adafruit.x` assumes SoftDevice S140 6.x.x, with the application at `0x26000`.
  Boards with S140 7.x.x need `0x27000`. `INFO_UF2.TXT` on the bootloader drive shows which one
  you have.
- The SoftDevice stays in flash but is never enabled: the examples use the SoftDevice Controller
  from `nrf-sdc`. The bootloader still uses the SoftDevice for its own BLE DFU.
- `build.rs` passes `--nmagic` to the linker. Without it, lld puts the ELF headers in a load
  segment at `0x20000`, which is inside the SoftDevice.
- The examples log with defmt over RTT, so without a probe you get no output. Use a BLE scanner
  to check that the device advertises.
- After a UF2 copy or serial DFU the bootloader jumps into the application without a reset.
  These examples start fine that way, but an application that also runs USB may hang at startup
  until the next reset. See [alexmoon/nrf-sdc#103](https://github.com/alexmoon/nrf-sdc/issues/103).

See [microbit-bsp](https://github.com/lulf/microbit-bsp) for more examples of setting up nrf devices with trouble, specifically the BBC Microbit which is an nrf52833.

# ESP32 examples

## Setup

These examples are set up assuming you are using espflash instead of probe-rs for flashing and debugging your chips.  Make sure you have it with:

```bash
cargo install cargo-binstall # binary installer tool (optional but recommended)
cargo binstall cargo-espflash espflash # or cargo install if you don't use binstall
```

You may also need to install the chip's toolchain too, if so that would be done with, for example:

```bash
rustup target add riscv32imac-unknown-none-elf
```

We use features to turn on the appropriate configurations for the chip you are flashing to.  Currently supported chips are:

- `esp32`
- `esp32c2`
- `esp32c3`
- `esp32c6`
- `esp32h2`
- `esp32s3`
- (esp32c5 coming soon)

## Run

To build and run an example on your device, plug it in and run i.e.:

```bash
cd examples/esp32 # make sure you are in the right directory
cargo run --release --no-default-features --features=esp32c6 --target=riscv32imac-unknown-none-elf --bin ble_bas_peripheral
```

We have added aliases to make this simpler (see how in [./.cargo/config.toml](./.cargo/config.toml)), so you can instead run:

```bash
# cargo <chip> --bin <example_name>
cargo esp32c6 --bin ble_bas_peripheral
```

See [esp32c3-devkit-demo](https://github.com/jamessizeland/esp32c3-devkit-demo) for more examples of setting up esp devices with trouble, specifically the [rust devkit](https://github.com/esp-rs/esp-rust-board) which is an esp32c3.

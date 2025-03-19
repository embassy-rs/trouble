# nRF examples

## Build

Build dependencies requires clang libraries.

Select chip to use with feature flag,

Currently supported chips are,
 - `nrf52832`
 - `nrf52833`
 - `nrf52840`

```shell
cargo build --release --features nrf52833 --target thumbv7em-none-eabihf
```

## Run

Select the binary to run and use cargo run to run the example using probe-rs.

```shell
cargo run --release --features nrf52833 --target thumbv7em-none-eabihf --bin ble_bas_peripheral
```

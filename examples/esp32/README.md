# ESP32 examples

## Build

Select chip to use with feature flag,

Currently supported chips are,
 - `esp32`
 - `esp32c2`
 - `esp32c3`
 - `esp32c6`
 - `esp32h2`
 - `esp32s3`

```shell
cargo build --release --no-default-features --features=esp32c6 --target=riscv32imac-unknown-none-elf
```

## Run

Select the binary to run and use cargo run to run the example using esptool.

```shell
cargo run --release --no-default-features --features=esp32c6 --target=riscv32imac-unknown-none-elf --bin ble_bas_peripheral
```

# `esp32` examples

## Build

```
$ cargo build --release --no-default-features --features=esp32c6 --target=riscv32imac-unknown-none-elf --bin ble_bas_peripheral
```

>Would be nice to have commands for building, running, without needing to resort to the aliases. That teaches more about the Rust/Cargo ecosystem.
>
>I deduced the above from `.cargo/config.toml`

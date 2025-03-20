# trouble

[![CI](https://github.com/embassy-rs/trouble/actions/workflows/ci.yaml/badge.svg)](https://github.com/embassy-rs/trouble/actions/workflows/ci.yaml)

TrouBLE is a Bluetooth Low Energy (BLE) Host implementation written in Rust, with a future goal of qualification. The initial implementation was based on [`bleps`](https://github.com/bjoernQ/bleps) but has been adapted to work with types and traits from [`bt-hci`](https://github.com/embassy-rs/bt-hci) and adding support for more of the BLE specification such as L2CAP connection oriented channels.  The current implementation also takes strong inspiration from the [`nrf-softdevice`](https://github.com/embassy-rs/nrf-softdevice) project.

## What is a Host?

A BLE Host is one side of the Host Controller Interface (HCI). The BLE specification defines the software of a BLE implementation in terms of a `controller` (lower layer) and a `host` (upper layer).

These communicate via a standardized protocol, that may run over different transports such as as UART, USB or a custom in-memory IPC implementation.

The advantage of this split is that the Host can generally be reused for different controller implementations.

## Hardware support

TrouBLE can use any controller that implements the traits from `bt-hci`. At present, that includes:

* [nRF Softdevice Controller](https://github.com/alexmoon/nrf-sdc).
* [UART HCI](https://docs.zephyrproject.org/latest/samples/bluetooth/hci_uart/README.html).
* [Raspberry Pi Pico W](https://github.com/embassy-rs/embassy/tree/main/cyw43).
* [Apache NimBLE Controller](https://github.com/benbrittain/apache-nimble-sys).
* [ESP32](https://github.com/esp-rs/esp-hal).

## Current status

The implementation has the following functionality working:

* Peripheral role - advertise as a peripheral and accept connections.
* Central role - scan for devices and establish connections.
* Basic GATT server supporting write, read, notifications
* Basic GATT client supporting service and characteristic lookup and read + write
* L2CAP CoC (Connection oriented Channels) with credit management (for both central and peripheral)

See the [issues](https://github.com/embassy-rs/trouble/issues) for a list of TODOs.

## Documentation

See the [documentation](https://embassy.dev/trouble) and the [rustdoc](https://docs.embassy.dev/trouble-host/git/default/index.html).

## Minimum supported Rust version (MSRV)

Trouble is guaranteed to compile on stable Rust 1.80 and up. It *might*
compile with older versions but that may change in any new patch release.

## Examples

See `examples` for example applications for different BLE controllers.

* `nrf-sdc` for the nRF52 based using the [`nrf-sdc`](https://github.com/alexmoon/nrf-sdc) crate.
* `serial-hci` which runs on std using a controller attached via a serial port (Such as [this Zephyr sample](https://developer.nordicsemi.com/nRF_Connect_SDK/doc/latest/zephyr/samples/bluetooth/hci_uart/README.html)).
* `apache-nimble` which uses the controller from the [NimBLE stack](https://github.com/apache/mynewt-nimble) through high-level bindings from the [`apache-nimble`](https://github.com/benbrittain/apache-nimble-sys) crate.
* `esp32` which uses the BLE controller in the [esp-hal](https://github.com/esp-rs/esp-hal).
* `rp-pico-w` which uses the BLE controller in the [Raspberry Pi Pico W](https://www.raspberrypi.com/documentation/microcontrollers/pico-series.html#raspberry-pi-pico-w).
* `rp-pico-2-w` which uses the BLE controller in the [Raspberry Pi Pico 2 W](https://www.raspberrypi.com/documentation/microcontrollers/pico-series.html#raspberry-pi-pico-2-w).

Since a lot of the examples demo the same BLE functionality, they only contain basic wiring specific to the BLE controller, and share the 'business logic' within the `examples/apps` folder.

More information on these examples can be found is the [examples/README.md](examples/README.md).

## License

Trouble is licensed under either of

* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

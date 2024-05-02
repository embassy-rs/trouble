# trouble

[![CI](https://github.com/embassy-rs/trouble/actions/workflows/ci.yaml/badge.svg)](https://github.com/embassy-rs/trouble/actions/workflows/ci.yaml)

*WIP* Basic functionality works, however API is likely to change a bit. Use [`nrf-softdevice`](https://github.com/embassy-rs/nrf-softdevice) for the time being if you want a production ready BLE Rust stack for nRF.

TrouBLE is a Bluetooth Low Energy (BLE) Host implementation written in Rust, with a future goal of qualification.

The initial implementation was based on [`bleps`](https://github.com/bjoernQ/bleps) but has been adopted to work with [`bt-hci`](https://github.com/alexmoon/bt-hci), which implements Rust types for the HCI specification as well as an interface
for a BLE Controller.

### HCI what?

The BLE specification defines the software of a BLE implementation in terms of a `controller` (lower layer) and a `host` (upper layer). These communicate via a standardized protocol called the Host-Controller Interface (HCI), which can operate over different transports such as UART, USB or a custom IPC implementation.

## Current status

The implementation has some basic functionality working:

* Peripheral role - advertise as a peripheral and accept connections.
* Central role - scan for devices and establish connections.
* Basic GATT server supporting write, read, notifications
* L2CAP CoC (Connection oriented Channels) with credit management (for both central and peripheral)
* Runs on any transport supporting the `Controller` and `ControllerCmd` traits from `bt-hci`. The `SerialTransport` and `ExternalController` helper types can be used to create additional implementations.

## Example

See `examples` for example applications. Currently there are two examples:

* `nrf-sdc` for the nRF52 based using the [`nrf-sdc`](https://github.com/alexmoon/nrf-sdc) crate.
* `serial-hci` which runs on a PC using a HCI controller attached via a serial port (Such as [this Zephyr sample](https://developer.nordicsemi.com/nRF_Connect_SDK/doc/latest/zephyr/samples/bluetooth/hci_uart/README.html)).


## License

Trouble is licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

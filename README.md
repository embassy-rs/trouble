# trouble

[![CI](https://github.com/embassy-rs/trouble/actions/workflows/ci.yaml/badge.svg)](https://github.com/embassy-rs/trouble/actions/workflows/ci.yaml)

*WIP* Basic functionality works, but API is likely to change a bit. Use [`nrf-softdevice`](https://github.com/embassy-rs/nrf-softdevice) for the time being if you want a production ready BLE stack.

An Rust host BLE stack with a future goal of qualification. Currently the focus is on implementing the host on top of a HCI interface.

The `trouble-host` crate is based on [`bleps`](https://github.com/bjoernQ/bleps) but has been adopted to work with [`bt-hci`](https://github.com/alexmoon/bt-hci). 

Done:
* Basic GATT write, read, notifications
* L2CAP CoC 
* Peripheral role 
* Central role

Missing:
* Security manager
* Gatt client
* Legacy Bluetooth
* Better error handling
* Supporting more configuration options

## Example

See `examples` for example applications. Currently there is only one, for the nRF52 based using the [`nrf-sdc`](https://github.com/alexmoon/nrf-sdc) crate.

NOTE: There is also an example `serial-hci` which should in theory work with any serial HCI adapter, but this has not been tested.

## License

Trouble is licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

# trouble

*WIP* Basic functionality like creating a GATT server works, but API is likely change a lot for the time being. Use [`nrf-softdevice`](https://github.com/embassy-rs/nrf-softdevice) for the time being if you want a production ready BLE stack.

An Rust host BLE stack with a future goal of qualification. Currently the focus is on implementing the host on top of a HCI interface.

The `trouble-host` is based on [`bleps`](https://github.com/bjoernQ/bleps) but has been adopted to work with [`bt-hci`](https://github.com/alexmoon/bt-hci). 

Done:
* Advertise
* Basic GATT
* L2CAP CoC create/accept

## Example

See `examples` for example applications. Currently there is only one, for the nRF52 based using the [`nrf-sdc`](https://github.com/alexmoon/nrf-sdc) crate.

## License

Trouble is licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

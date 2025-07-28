# Linux HCI socket example

This example opens a "user channel" with the [Linux HCI socket interface](https://github.com/bluez/bluez/wiki/HCI), which assumes full control of the device.

To bind this channel, the device must first be down (e.g. `hciconfig hci0 down`) and the process must have the `CAP_NET_ADMIN` capability.

To run an example with `CAP_NET_ADMIN`, either just run as root or try an incantation like the following (requires privileges to launch but runs as a regular user):
```
systemd-run \
  --pty \
  --uid=$(id -u) \
  --gid=$(id -g) \
  --same-dir \
  --setenv RUST_LOG=info \
  --setenv PATH \
  --property "AmbientCapabilities=CAP_NET_ADMIN" \
  cargo run --bin ble_scanner
```

To bind a different HCI device (e.g. `hci1`), pass a the device number as a single parameter (e.g. `cargo run --bin ble_scanner -- 1`)

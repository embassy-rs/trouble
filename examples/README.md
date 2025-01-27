# Examples

## Summary

Within this directory we have numerous examples showing how to get started using Trouble in your projects. We also test these examples using Automated CI. More information on this can be found below:

## Example Applications

Within this examples directory we have the following structure:

```bash
tree -L 1
.
├── README.md
├── apache-nimble
├── apps
├── esp32
├── nrf-sdc
├── rp-pico-2-w
├── rp-pico-w
├── serial-hci
```

The `apps` folder contains the functionality that is used in every example across the multiple platforms. This crate is then pulled into each example and can be run by simply flashing the code onto the devices using `cargo run` within each of the project directories.

The hardware for which each example uses is listed below:

- **[apache-nimble](./apache-nimble/Cargo.toml)**:
- **[esp32](./esp32/Cargo.toml)**: [ESP-Rust-Board](https://github.com/esp-rs/esp-rust-board)
- **[rp-pico-2-w](./rp-pico-2-w/Cargo.toml)**: [Raspberry Pi Pico 2 W](https://thepihut.com/products/raspberry-pi-pico-2-w?variant=53727839027585&country=GB&currency=GBP&utm_medium=product_sync&utm_source=google&utm_content=sag_organic&utm_campaign=sag_organic&gad_source=1&gclid=CjwKCAiAkc28BhB0EiwAM001TXNknX7fTXNwbaySLfbvbUJRaOgFseqj6RcDeu4Dd8RE64GgZ0imnxoCVVYQAvD_BwE)
- **[rp-pico-w](./rp-pico-w/Cargo.toml)**: [Raspberry Pico W](https://thepihut.com/products/raspberry-pi-pico-w)
- **[serial-hci](./serial-hci/Cargo.toml)**: Can be used with any Serial HCI, the following has been used:
    - [Example 1]()
    - [Example 2]()
    - [Example 3]()

## Tests

### Hardware Indepedent Tests

The Tests inside the [tests crate](./tests/Cargo.toml) are being ran inside the GitHub Actions Runner on a cloud host. The commands for this can be found [here](../ci.sh) and [here](../.github/workflows/ci.yaml).

### Hardware in the Loop Tests

The Tests inside the [tests crate](./tests/Cargo.toml) are also run using a `self-hosted` runner utilising the [Hil Bench](https://github.com/lulf/hilbench/tree/main). This works by using the [tests.yaml](../.github/workflows/tests.yaml) flow in which `example-tests` is used alongside integrations tests.

The self hosted HIL Bench setup can be further understood using the following diagram:

![HIL Bench Setup](../docs/Diagram.drawio.svg)

[RodBot](https://github.com/ctron/rodbot) is used to setup the `tests` by using dedicated approvers to call the integration and example tests.

## Integration tests

In terms of integration tests these are defined in the [tests.yaml](../.github/workflows/tests.yaml) under `integration_tests` job. Which are running the tests in the [host crate](../host/tests/). These require the following hardware:

These tests do not use the [hilbench](https://github.com/lulf/hilbench/tree/main) helper crate.

## Example Tests

The tests that use hardware are the [example tests](../examples/tests/tests/). These tests require the hilbench.

The integration tests first work by downloading the artifacts which downloads the bins for each test. Then using the [config.json](../.ci/config.json) it selects the MCU to flash and run the tests on. Each time the tests are done on the Linux side with the examples being connected too.

# Serial HCI example

These examples require two Bluetooth dongles with a Host Controller Interface (HCI).
The examples have been tested with two nRF52840 dongles running the [HIC UART example](https://github.com/nrfconnect/sdk-zephyr/tree/main/samples/bluetooth/hci_uart).

## Using Zephyr HCI-UART

The [Zephyr HCI-UART sample](https://docs.zephyrproject.org/latest/samples/bluetooth/hci_uart/README.html) an be used as a controller for the serial-hci host.

### nRF52840 Dongle

To use the nRF528040-dongle as a HCI serial controller, build the HCI-UART sample for the `nrf52840dongle` board.

```shell
$ west build -p always -b nrf52840dongle samples/bluetooth/hci_uart
```

For refrence, see the [Nordic HCI-UART sample page](https://docs.nordicsemi.com/bundle/ncs-latest/page/zephyr/samples/bluetooth/hci_uart/README.html#bluetooth_hci_uart).

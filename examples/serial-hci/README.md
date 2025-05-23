# Serial HCI example

These examples require two Bluetooth dongles with a Host Controller Interface (HCI).
The examples have been tested with two nRF52840 dongles running the [HIC UART example](https://github.com/nrfconnect/sdk-zephyr/tree/main/samples/bluetooth/hci_uart).

## Using Zephyr HCI-UART

The [Zephyr HCI-UART sample](https://docs.zephyrproject.org/latest/samples/bluetooth/hci_uart/README.html) an be used as a controller for the serial-hci host.

### nRF52840 Dongle

To use the nRF528040-dongle as a HCI serial controller, build the HCI-UART sample for the `nrf52840dongle` board.

```bash
west build -p always -b nrf52840dongle samples/bluetooth/hci_uart
```

For refrence, see the [Nordic HCI-UART sample page](https://docs.nordicsemi.com/bundle/ncs-latest/page/zephyr/samples/bluetooth/hci_uart/README.html#bluetooth_hci_uart).

## High throughput example

The high throughput examples require some modifications to the default configurations of the HCI UART example.
The default configuration will set up an HCI UART Bluetooth dongle that has 3, 27-byte wide TX buffers.
This is indicated by the following information log

```bash
INFO  trouble_host::host] [host] setting txq to 3, fragmenting at 27
```

The high throughput examples require these buffers to be the maximum size of 251 and as many buffers as allowed, 20.
To affect these changes, add the following to the `proj.conf` file of the HCI UART example.

```conf
# Enable data length extension
CONFIG_BT_CTLR_DATA_LENGTH_MAX=251
CONFIG_BT_BUF_ACL_TX_SIZE=251
 
# Increase buffer count
CONFIG_BT_CTLR_SDC_TX_PACKET_COUNT=20
CONFIG_BT_CTLR_SDC_RX_PACKET_COUNT=20
```

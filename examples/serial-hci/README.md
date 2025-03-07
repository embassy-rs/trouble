# Serial HCI example

These examples require two Bluetooth dongles that implement the Host Controller Interface (HCI).
The examples have been tested with two nRF52840 dongles running the [HCI UART example](https://github.com/nrfconnect/sdk-zephyr/tree/main/samples/bluetooth/hci_uart).

## High throughput example

The high throughput examples require some modifications to the default configurations of the HCI UART example.
The default configuration will set up an HCI UART Bluetooth dongle that has 3, 27-byte wide TX buffers.
This is indicated by the following information log
```
INFO  trouble_host::host] [host] setting txq to 3, fragmenting at 27
```

The high throughput examples require these buffers to be the maximum size of 251 and as many buffers as allowed, 20.
To affect these changes, add the following to the `proj.conf` file of the HCI UART example.

```
# Enable data length extension
CONFIG_BT_CTLR_DATA_LENGTH_MAX=251
CONFIG_BT_BUF_ACL_TX_SIZE=251
 
# Increase buffer count
CONFIG_BT_CTLR_SDC_TX_PACKET_COUNT=20
CONFIG_BT_CTLR_SDC_RX_PACKET_COUNT=20
```

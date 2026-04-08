# USB HCI Examples

This directory contains examples demonstrating Bluetooth Low Energy (BLE) functionality using USB HCI controllers.

## Prerequisites

### Linux

To use USB Bluetooth dongles directly on Linux, you need to install appropriate udev rules to grant user access to the device. Create a file `/etc/udev/rules.d/99-bluetooth.rules` with the following content:

```
SUBSYSTEM=="usb", ATTRS{idVendor}=="0b05", ATTRS{idProduct}=="190e", MODE="0666", GROUP="plugdev"
```

Adjust the Vendor and Product IDs to the correct values for your USB device.

After installing the rules, reload them with:

```bash
sudo udevadm control --reload-rules
sudo udevadm trigger
```

### Windows

To use USB Bluetooth dongles on Windows, you need to install the WinUSB driver using Zadig. Download Zadig from https://zadig.akeo.ie/, run it as administrator, select your Bluetooth dongle from the device list, choose "WinUSB" as the driver, and click "Install Driver".

After installing the driver, the device will be accessible through the WinUSB interface instead of the default Windows Bluetooth stack.
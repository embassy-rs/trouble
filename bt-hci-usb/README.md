# bt-hci-usb

A USB HCI transport implementation (Core Vol. 4 Part B) for the [`bt-hci`](crate).

This project requires raw USB access to the Bluetooth adapter. The required setup depends on the host operating system.

## Windows (WinUSB via Zadig)

On Windows, the Bluetooth USB adapter must be bound to **WinUSB** so it can be accessed from user space.  
Install the WinUSB driver using [Zadig](https://zadig.akeo.ie/) (select the correct device—this will disable native Windows Bluetooth for that adapter).

## Linux (udev permissions + kernel module)

### Add udev rule for non-root access

Create `/etc/udev/rules.d/99-bt-usb.rules` with a rule matching your device.

Example rule (for VID:PID `0b05:190e`):  
`SUBSYSTEM=="usb", ATTR{idVendor}=="0b05", ATTR{idProduct}=="190e", MODE="0660", GROUP="plugdev", TAG+="uaccess"`

Reload rules and replug the device:

```bash
sudo udevadm control --reload-rules
sudo udevadm trigger
```

### Unload kernel HCI USB module when needed

If you get a "device busy" error, the kernel Bluetooth stack is likely already bound to the adapter. Unload `btusb` before running this tool:

```bash
sudo modprobe -r btusb
```

You can load it again later with:

```bash
sudo modprobe btusb
```

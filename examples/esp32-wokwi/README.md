# ESP32-C3 Wokwi + HCI UART + BlueZ

Minimal reproduction of the mycelium sim path: **trouble-host** on an ESP32-C3 talks HCI H4 over UART to a host-side Bumble bridge, which exposes a virtual controller to **BlueZ**. The Linux VM acts as the BLE central (equivalent to `ble_bas_central`).

Uses **ESP32-C3** (`board-esp32-c3-devkitm-1`) and the `riscv32imc-unknown-none-elf` target so you can build with the stock Rust toolchain — no Xtensa GCC or `espup` required.

## Architecture

```
Wokwi ESP32-C3 (ble_bas_peripheral_hci, trouble-host)
  UART0 GPIO21/20 → HCI H4 @ 115200
       ↓ Wokwi RFC2217 :4000
       ↓ socat PTY /tmp/trouble-hci
edge-hci-bridge.py (repo root)
       ↓ vhci
BlueZ in Lima VM → bluetoothctl / btmon
```

## Build (host)

```bash
cd examples/esp32-wokwi
cargo wokwi
```

Output: `target/riscv32imc-unknown-none-elf/release/ble_bas_peripheral_hci`

Open this folder in VS Code with the Wokwi extension and start the simulator (`F1` → Wokwi: Start Simulator).

UART0 is wired to `$serialMonitor` in `diagram.json`; RFC2217 listens on port **4000** (`wokwi.toml`).

## Lima VM (BlueZ + Bumble)

From the repo root:

```bash
limactl start ubuntu-bumble.yaml
limactl shell ubuntu-bumble
```

Inside the VM (or on the host, depending on where you run socat):

```bash
# Terminal 1 — link Wokwi TCP to a PTY (adjust host IP if needed)
socat -d -d pty,link=/tmp/trouble-hci,raw,echo=0 tcp:host.lima.internal:4000

# Terminal 2 — bridge PTY to vhci
sudo chmod 666 /dev/vhci
/opt/bumble-venv/bin/python edge-hci-bridge.py --pty /tmp/trouble-hci --baud 115200 --verbose
```

## Central (BlueZ)

In the Lima VM:

```bash
bluetoothctl
power on
scan on
# Look for "TrouBLE" or the BAS peripheral
connect <MAC>
info <MAC>
menu-gatt
list-attributes
```

For low-level debugging:

```bash
sudo btmon
```

## Compare with on-chip BLE

The stock `examples/esp32` examples use `esp-radio` (`BleConnector`) and talk to a real radio. This example replaces the controller with `ExternalController` + `SerialTransport` over UART — same pattern as `examples/serial-hci` and `examples/usb-hci`, but targeting Wokwi.

## Pins

| Signal | ESP32-C3 pin | Wokwi |
|--------|--------------|-------|
| UART TX | GPIO21 | `esp:TX` → serial monitor RX |
| UART RX | GPIO20 | `esp:RX` ← serial monitor TX |

`esp-println` uses the `no-op` feature so logs do not corrupt the HCI byte stream on UART0.

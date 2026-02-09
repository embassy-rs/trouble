# TrouBLE Tester nRF Firmware

BTP tester firmware for the nRF52840 DK. Communicates with auto-pts over UART0
(115200 baud, hardware flow control) and streams defmt logs over USB CDC.

## Prerequisites

- [probe-rs](https://probe.rs/) for flashing
- [defmt-print](https://crates.io/crates/defmt-print) for viewing logs
- An nRF52840 DK

## Building and Flashing

Commands must be run from the `tester/nrf52` directory:

```bash
# Build
cargo build --release

# Flash and run
cargo run --release
```

## Viewing Logs

Defmt logs are streamed over USB CDC instead of RTT because auto-pts needs
access to the probe to reset the Implementation Under Test (IUT).

To view the logs, connect to the USB port on the DK and run:

```bash
./defmt-log.sh /dev/cu.usbmodemXXXX
```

The script survives device resets by waiting for the tty to reappear.

**Important note:** You must not configure `embassy-sync` with `trace` level
logs (e.g. using `DEFMT_LOG="trace"`). The `defmt` implementation uses `Pipe`
from `embassy-sync` which emits log messages at the trace level which causes
a panic due to re-entrant log statements.

## Running auto-pts

Follow the [auto-pts Linux setup guide](https://docs.zephyrproject.org/latest/connectivity/bluetooth/autopts/autopts-linux.html)
to install and configure PTS and auto-pts.

Once set up, run the auto-pts client with a command like:

```bash
python ./autoptsclient-zephyr.py trouble \
    -t /dev/cu.usbmodem0010502573281 \
    -b nrf52 \
    --pylink_reset \
    -j 1050257328 \
    -i 10.111.109.121 \
    -l 10.111.109.158 \
    --rtscts
```

Adjust the serial port (`-t`), J-Link serial number (`-j`), and IP addresses
(`-i` for PTS host, `-l` for local) to match your setup.

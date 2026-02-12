#!/bin/bash
# Receive defmt logs from trouble-tester-nrf over USB CDC.
# Survives device resets by waiting for the tty to reappear.

ELF="target/thumbv7em-none-eabihf/release/trouble-tester-nrf52"
TTY="$1"

if [ -z "$TTY" ]; then
    echo "Usage: $0 /dev/<USB serial device>"
    exit 1
fi

if [ ! -f "$ELF" ]; then
    echo "ELF not found: $ELF"
    echo "Build first: cargo build --release"
    exit 1
fi

while true; do
    while [ ! -e "$TTY" ]; do
        sleep 0.2
    done

    echo "--- Connected: $TTY ---"
    # Open TTY once; stty operates on the already-open stdin so DTR
    # is only raised once and never toggled between commands.
    (stty raw; exec defmt-print --show-skipped-frames -e "$ELF") < "$TTY"
    echo "--- Disconnected, waiting for device... ---"
    sleep 0.5
done

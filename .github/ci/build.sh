#!/bin/bash
## on push branch~=gh-readonly-queue/main/.*
## on pull_request
## priority 10
## dedup kill
## device /dev/serial/by-id/usb-ZEPHYR_Zephyr_HCI_UART_sample_265650C6A0739A40-if00 /dev/serial/by-id/usb-ZEPHYR_Zephyr_HCI_UART_sample_265650C6A0739A40-if00 
## device /dev/serial/by-id/usb-ZEPHYR_Zephyr_HCI_UART_sample_CBBC59EDA8BA738E-if00 /dev/serial/by-id/usb-ZEPHYR_Zephyr_HCI_UART_sample_CBBC59EDA8BA738E-if00
## cooldown 30s

set -euo pipefail

export CARGO_TARGET_DIR=/ci/cache/target
export CARGO_NET_GIT_FETCH_WITH_CLI=true

# Read probe-rs token from bender's mounted secrets directory
if [[ -f /ci/secrets/probe-rs-token ]]; then
    echo "Got HIL token!"
    export HIL_TOKEN=$(cat /ci/secrets/probe-rs-token)
fi

# Restore lockfiles
if [ -f /ci/cache/lockfiles.tar ]; then
    echo Restoring lockfiles...
    tar xf /ci/cache/lockfiles.tar
fi

# Run the shared build/lint/test script
./ci.sh

# Save lockfiles
echo Saving lockfiles...
find . -type f -name Cargo.lock -exec tar -cf /ci/cache/lockfiles.tar '{}' \+

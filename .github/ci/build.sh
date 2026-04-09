#!/bin/bash
## on push branch=main
## on pull_request
## priority 10
## dedup kill
## cooldown 30s

set -euxo pipefail

export CARGO_TARGET_DIR=/ci/cache/target

echo "=== netdbg ==="
cat /etc/resolv.conf
ip -br addr 2>/dev/null || true
getent hosts github.com || echo "github.com: LOOKUP FAILED"
getent hosts static.rust-lang.org || echo "static.rust-lang.org: LOOKUP FAILED"
echo "=== /netdbg ==="

# needed for "dumb HTTP" transport support
# used when pointing stm32-metapac to a CI-built one.
export CARGO_NET_GIT_FETCH_WITH_CLI=true

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

# Binary size report for PRs
if [[ -n "${CI_PR_NUMBER:-}" ]]; then
    rustup target add thumbv7em-none-eabihf
    rustup component add llvm-tools

    if ! command -v cargo-size &> /dev/null; then
        cargo install cargo-binutils
    fi

    NEW_ELF="${CARGO_TARGET_DIR}/thumbv7em-none-eabihf/release/ble_bas_peripheral"
    mkdir -p ~/artifacts
    cargo size --release --manifest-path examples/nrf52/Cargo.toml --features nrf52840 --bin ble_bas_peripheral > ~/artifacts/size-new.txt 2>&1

    if [[ -n "${CI_BASE_SHA:-}" ]]; then
        cp "$NEW_ELF" /tmp/new.elf
        git checkout "$CI_BASE_SHA"
        cargo build --release --manifest-path examples/nrf52/Cargo.toml --target thumbv7em-none-eabihf --features nrf52840 --bin ble_bas_peripheral
        if command -v bloaty &> /dev/null; then
            echo '## Binary size diff' > ~/comment.md
            echo '```' >> ~/comment.md
            bloaty /tmp/new.elf -- "$NEW_ELF" >> ~/comment.md
            echo '```' >> ~/comment.md
        fi
    fi
fi

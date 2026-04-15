#!/bin/bash
## on push branch=main
## priority -100
## dedup dequeue
## cooldown 15m

set -euo pipefail

export RUSTUP_HOME=/ci/cache/rustup
export CARGO_HOME=/ci/cache/cargo
export CARGO_TARGET_DIR=/ci/cache/target
export PATH=$CARGO_HOME/bin:$PATH

if ! command -v cargo-batch &> /dev/null; then
    mkdir -p $CARGO_HOME/bin
    curl -L https://github.com/embassy-rs/cargo-batch/releases/download/batch-0.6.0/cargo-batch > $CARGO_HOME/bin/cargo-batch
    chmod +x $CARGO_HOME/bin/cargo-batch
fi

# Read probe-rs token from bender's mounted secrets directory
if [[ -f /ci/secrets/kubeconfig.yml ]]; then
    echo "Got kubeconfig token!"
    export KUBECONFIG=$(cat /ci/secrets/kubeconfig.yml)
fi

pushd docs
make
popd

echo "Build book"
mkdir -p build
mv docs/book build/trouble
tar -C build -cf trouble.tar trouble
.ci/book.sh

echo "Build api doc"
mv rust-toolchain-nightly.toml rust-toolchain.toml
cargo install --git https://github.com/embassy-rs/docserver --locked --rev e16c30dcc60a41641fd73bd4ad1a8c4bd57d792d

docserver build -i host -o crates/trouble-host/git.zup
.ci/doc.sh

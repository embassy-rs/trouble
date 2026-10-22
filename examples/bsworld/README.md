# BSWorld example

Run the shared Battery Service central and peripheral applications as two native Linux processes with Python Controllers and the BabbleSim radio model. The test checks connection, GATT discovery, reads and periodic notifications over 12 simulated seconds. It uses [bsim](bsim) for H4 Unix sockets and discrete-time execution. No Bluetooth hardware is required.

## Setup

Use Linux, Python 3.12 or newer, and this repository's Rust toolchain. On Ubuntu 24.04, install the native build dependencies:

```sh
sudo apt-get install -y git repo make build-essential gcc-multilib g++-multilib python3.12-venv
```

From the TrouBLE repository root, prepare [BSWorld](https://github.com/XiaoMi/bsworld/) and its Python Controller:

```sh
cd examples/bsworld
export BSWORLD_ROOT="$PWD/.cache/bsworld"

python3.12 -m venv .venv
source .venv/bin/activate
mkdir -p .cache

git clone https://github.com/XiaoMi/bsworld.git .cache/bsworld
python -m pip install -e .cache/bsworld -e .cache/bsworld/components/bscontroller
```

In the same shell, fetch and build BabbleSim using BSWorld's pinned manifest:

```sh
cd "$BSWORLD_ROOT/../.."
export BSIM_OUT_PATH="$PWD/.cache/babblesim/build"
export BSIM_COMPONENTS_PATH="$PWD/.cache/babblesim/components"

mkdir -p .cache/babblesim
(
    cd .cache/babblesim
    repo init --standalone-manifest --depth=1 -u "file://$BSWORLD_ROOT/components/babblesim.xml"
    repo sync -c --no-tags
    make -j"$(nproc)" everything
)
```

## Run

In the same shell, build the example and run the test:

```sh
cd "$BSWORLD_ROOT/../.."
cargo build --locked
python -m pytest -v --out-dir /tmp/trouble-bsworld
```

The test starts the PHY, two Python Controllers and two TrouBLE Host processes. The Hosts reuse the applications in `examples/apps`; BSWorld manages the topology and assertions. If `CARGO_TARGET_DIR` is configured, set `BSWORLD_TROUBLE_NATIVE_BIN` to the absolute path of its `debug/ble_bas` executable before running pytest.

Results are saved below `/tmp/trouble-bsworld/run-*/`, including `central.log`, `peripheral.log`, `hci0.snoop`, `hci1.snoop` and `babblesim/ellisys.bttrp`. HCI captures open in Wireshark; radio traces open in Ellisys.

Run the transport, executor and clock unit tests from `examples/bsworld`:

```sh
cargo test --manifest-path bsim/Cargo.toml
```

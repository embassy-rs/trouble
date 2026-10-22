# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Two native TrouBLE Hosts using H4 sockets and BabbleSim time."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from bsworld.devices import BSController, ProcessInstance
from bsworld.env import env_path
from bsworld.topology import BluetoothTopology


def _add_host(topo: BluetoothTopology, role: str) -> ProcessInstance:
    binary = env_path("BSWORLD_TROUBLE_NATIVE_BIN") or (
        Path(__file__).resolve().parents[1] / "target/debug/ble_bas"
    )
    if not binary.is_file() or not binary.stat().st_mode & 0o111:
        pytest.fail(
            "Build examples/bsworld with cargo, or set BSWORLD_TROUBLE_NATIVE_BIN; "
            "see examples/bsworld/README.md."
        )
    controller = topo.add_controller(controller_type=BSController)

    def command() -> list[str | Path]:
        if controller.application_dev_id is None:
            raise RuntimeError("native TrouBLE requires a BabbleSim device id")
        return [
            binary,
            role,
            controller.socket_dir,
            controller.phy_id,
            str(controller.application_dev_id),
            controller.hci_sock,
        ]

    return topo.add_process(
        ProcessInstance(command=command, controller=controller, label=role, log_subdir=role)
    )


async def test_two_native_hosts_connect_discover_read_and_notify(topo: BluetoothTopology) -> None:
    central = _add_host(topo, "central")
    peripheral = _add_host(topo, "peripheral")
    topo.set_channel_attenuation(default_db=45.0)
    await topo.start()
    loop = asyncio.get_running_loop()
    stop_at = loop.time() + 12

    await peripheral.wait_log(r"\[adv\] connection established")
    await central.wait_log("Subscribing notifications")
    await central.wait_log(r"Read value: \d+")
    await central.wait_log(r"Got notification:.*val: 2\)")
    # The stock central reads every 10 seconds; the peripheral notifies every 2.
    # Reaching tick 6 exercises Rust timers well beyond connection setup.
    await central.wait_log(r"Got notification:.*val: 6\)")
    # End at the same simulation time for trace comparisons across CPU loads.
    assert loop.time() < stop_at
    await asyncio.sleep(stop_at - loop.time())

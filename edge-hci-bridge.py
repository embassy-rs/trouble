#!/usr/bin/env python3
"""
edge-hci-bridge — dual virtual controller version
====================================================

Bridges the ESP32 firmware's HCI *host* (trouble-host, over UART/PTY) to
BlueZ (also an HCI *host*, via vhci) by sandwiching TWO Bumble virtual
Controllers between them, joined by an in-process LocalLink.

    ESP32 (HCI HOST, trouble-host)
        │  serial:/tmp/trouble-hci,115200
        ▼
    Controller "ESP32"  ──┐
                           │  LocalLink
    Controller "BLUEZ"  ───┘
        │  vhci
        ▼
    BlueZ (HCI HOST) → hciN → bluetoothctl / btleplug

Usage
-----
    /opt/bumble-venv/bin/python edge-hci-bridge.py \\
        --pty /tmp/trouble-hci --baud 115200 --verbose

Prerequisites
-------------
    sudo modprobe hci_vhci
    sudo chmod 666 /dev/vhci   (or appropriate udev rule)
"""

from __future__ import annotations

import argparse
import asyncio
import inspect
import logging
from typing import TYPE_CHECKING

import bumble.logging
from bumble import core, hci
from bumble.controller import Controller
from bumble.link import LocalLink
from bumble.transport import open_transport

if TYPE_CHECKING:
    from bumble import ll

logger = logging.getLogger(__name__)

ACL_PREVIEW_LEN = 32
_trace_acl = True


def _hex_preview(data: bytes, limit: int = ACL_PREVIEW_LEN) -> str:
    if not data:
        return ""
    shown = data[:limit]
    suffix = "..." if len(data) > limit else ""
    return shown.hex() + suffix


def _format_address(address: hci.Address) -> str:
    return str(address)


def _le_connections_summary(link: LocalLink) -> str:
    parts: list[str] = []
    for controller in link.controllers:
        if not controller.le_connections:
            parts.append(f"{controller.name}:<none>")
            continue
        for peer, conn in controller.le_connections.items():
            parts.append(
                f"{controller.name}:self={conn.self_address} peer={peer} "
                f"role={conn.role.name} handle=0x{conn.handle:04X}"
            )
    return "; ".join(parts) if parts else "<no le connections>"


class LoggingLocalLink(LocalLink):
    """LocalLink with explicit ACL routing logs (Bumble drops ACL silently)."""

    def send_acl_data(
        self,
        sender_controller: Controller,
        destination_address: hci.Address,
        transport: core.PhysicalTransport,
        data: bytes,
    ) -> None:
        if not _trace_acl:
            super().send_acl_data(
                sender_controller, destination_address, transport, data
            )
            return

        if transport == core.PhysicalTransport.LE:
            destination_controller = self.find_le_controller(destination_address)
            source_address = sender_controller.random_address
            logger.info(
                "ACL link TX %s -> %s (%d B) dest_ctrl=%s lookup_sender=%s data=%s",
                sender_controller.name,
                _format_address(destination_address),
                len(data),
                destination_controller.name if destination_controller else "DROP",
                _format_address(source_address),
                _hex_preview(data),
            )
            if destination_controller is None:
                logger.warning(
                    "ACL link drop: no controller owns self_address=%s; %s",
                    _format_address(destination_address),
                    _le_connections_summary(self),
                )
                return

            asyncio.get_running_loop().call_soon(
                lambda: destination_controller.on_link_acl_data(
                    source_address, transport, data
                )
            )
            return

        if transport == core.PhysicalTransport.BR_EDR:
            destination_controller = self.find_classic_controller(destination_address)
            source_address = sender_controller.public_address
            logger.info(
                "ACL link TX %s -> %s (BR/EDR %d B) dest_ctrl=%s",
                sender_controller.name,
                _format_address(destination_address),
                len(data),
                destination_controller.name if destination_controller else "DROP",
            )
            if destination_controller is None:
                logger.warning(
                    "ACL link drop: no classic controller for %s",
                    _format_address(destination_address),
                )
                return

            asyncio.get_running_loop().call_soon(
                lambda: destination_controller.on_link_acl_data(
                    source_address, transport, data
                )
            )
            return

        raise ValueError("unsupported transport type")

    def send_advertising_pdu(
        self,
        sender_controller: Controller,
        packet: ll.AdvertisingPdu,
    ) -> None:
        if _trace_acl and logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "ADV link TX %s: %s",
                sender_controller.name,
                packet,
            )
        super().send_advertising_pdu(sender_controller, packet)


class LoggingController(Controller):
    """Controller with ACL receive / host-TX visibility."""

    def on_link_acl_data(
        self,
        sender_address: hci.Address,
        transport: core.PhysicalTransport,
        data: bytes,
    ) -> None:
        if _trace_acl:
            if transport == core.PhysicalTransport.LE:
                connection = self.le_connections.get(sender_address)
            else:
                connection = self.classic_connections.get(sender_address)

            logger.info(
                "ACL link RX %s <- %s (%d B) conn=%s data=%s",
                self.name,
                _format_address(sender_address),
                len(data),
                (
                    f"peer={connection.peer_address} handle=0x{connection.handle:04X}"
                    if connection is not None
                    else "MISS"
                ),
                _hex_preview(data),
            )
            if connection is None:
                logger.warning(
                    "ACL link RX drop on %s: no connection for sender %s; peers=%s",
                    self.name,
                    _format_address(sender_address),
                    [
                        _format_address(peer)
                        for peer in self.le_connections.keys()
                    ],
                )

        super().on_link_acl_data(sender_address, transport, data)

    def on_hci_acl_data_packet(self, packet: hci.HCI_AclDataPacket) -> None:
        if _trace_acl:
            connection = self.find_connection_by_handle(packet.connection_handle)
            payload = bytes(getattr(packet, "data", b""))
            logger.info(
                "ACL host TX %s handle=0x%04X (%d B) peer=%s data=%s",
                self.name,
                packet.connection_handle,
                len(payload),
                (
                    _format_address(connection.peer_address)
                    if connection is not None
                    else "unknown"
                ),
                _hex_preview(payload),
            )
            if connection is None:
                logger.warning(
                    "ACL host TX drop on %s: unknown handle 0x%04X; %s",
                    self.name,
                    packet.connection_handle,
                    _le_connections_summary(self.link) if self.link else "no link",
                )

        super().on_hci_acl_data_packet(packet)


async def _start_controller_if_needed(controller: Controller) -> None:
    start = getattr(controller, "start", None)
    if start is None:
        return

    result = start()
    if inspect.isawaitable(result):
        await result


async def run_bridge(pty_path: str, baud: int) -> None:
    serial_spec = f"serial:{pty_path},{baud}"

    logger.info("Opening ESP32 HCI UART: %s", serial_spec)
    logger.info("Opening Linux VHCI (BlueZ side): vhci")

    async with await open_transport(serial_spec) as esp_transport:
        async with await open_transport("vhci") as bluez_transport:
            link = LoggingLocalLink()

            controller_esp = LoggingController(
                "ESP32",
                host_source=esp_transport.source,
                host_sink=esp_transport.sink,
                link=link,
            )

            controller_bluez = LoggingController(
                "BLUEZ",
                host_source=bluez_transport.source,
                host_sink=bluez_transport.sink,
                link=link,
            )

            await _start_controller_if_needed(controller_esp)
            await _start_controller_if_needed(controller_bluez)

            logger.info("Bridge running. Press Ctrl+C to stop.")
            logger.info("ACL tracing enabled — grep logs for 'ACL link' / 'ACL host'")
            logger.info("Check: hciconfig -a   (look for a new hciN, UP RUNNING)")

            await asyncio.wait(
                [
                    asyncio.ensure_future(esp_transport.source.terminated),
                    asyncio.ensure_future(bluez_transport.source.terminated),
                ],
                return_when=asyncio.FIRST_COMPLETED,
            )


def main() -> None:
    global _trace_acl

    parser = argparse.ArgumentParser(
        description="Bridge ESP32 HCI (serial) <-> BlueZ (vhci) via two "
        "Bumble virtual controllers on a shared LocalLink"
    )
    parser.add_argument(
        "--pty",
        default="/tmp/trouble-hci",
        help="PTY path created by socat (default: /tmp/trouble-hci)",
    )
    parser.add_argument(
        "--baud",
        type=int,
        default=115_200,
        help="UART baud rate (default: 115200)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable Bumble DEBUG logging (full HCI packet dumps)",
    )
    parser.add_argument(
        "--no-trace-acl",
        action="store_true",
        help="Disable bridge ACL routing logs (Bumble HCI logs unaffected by -v)",
    )
    args = parser.parse_args()

    _trace_acl = not args.no_trace_acl

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.verbose:
        bumble.logging.setup_basic_logging("DEBUG")
    else:
        bumble.logging.setup_basic_logging("WARNING")

    try:
        asyncio.run(run_bridge(args.pty, args.baud))
    except KeyboardInterrupt:
        logger.info("Bridge stopped.")


if __name__ == "__main__":
    main()

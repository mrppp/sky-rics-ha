"""Wake-on-LAN helpers for a MAC-keyed permitted target.

Kept transport-independent and importable from the HA component.
"""

from __future__ import annotations

import socket
import time

from .exclusions import normalize_mac


def send_wol(mac: str, ports=(9, 7)) -> None:
    """Send a magic packet to the broadcast address."""
    mac_bytes = bytes.fromhex(normalize_mac(mac))
    magic = b"\xff" * 6 + mac_bytes * 16
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for port in ports:
            try:
                sock.sendto(magic, ("255.255.255.255", port))
            except OSError:
                continue


def wait_for_port(ip: str, port: int = 8091, timeout: float = 45.0) -> bool:
    """Poll until the port accepts a connection, or the timeout expires."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((ip, port), timeout=2):
                return True
        except OSError:
            time.sleep(1.5)
    return False

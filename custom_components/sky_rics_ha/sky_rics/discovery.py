"""Passive mDNS and local neighbour-table discovery. No port probes or pairing."""

from __future__ import annotations

import json
import re
import shlex
import socket
import subprocess
import time
from dataclasses import asdict, dataclass, field

from .exclusions import DeviceIdentity, ExclusionPolicy, SafetyPolicy, normalize_mac

MDNS_SERVICE = "_rdk-rics._tcp.local."


@dataclass
class SkyDevice:
    ip: str = ""
    mac: str = ""
    hostname: str = ""
    port: int = 8091
    service: str = MDNS_SERVICE
    rics_advertised: bool = True
    properties: dict[str, str] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)
    type_guess: str = "Sky Stream/Glass (unresolved)"
    confidence: str = "LOW"
    excluded: bool = False
    exclusion_reason: str = ""


def read_neighbours() -> dict[str, dict[str, str]]:
    try:
        result = subprocess.run(["ip", "-j", "neigh"], check=False, capture_output=True, text=True, timeout=5)
        rows = json.loads(result.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {}
    return {row.get("dst", ""): {"mac": row.get("lladdr", ""), "state": row.get("state", "")} for row in rows if row.get("dst")}


def add_known_mac_neighbours(devices: list[SkyDevice], known_macs: set[str]) -> list[SkyDevice]:
    """Add neighbour-table records for known Sky MACs at their current IP."""
    neighbours = read_neighbours()
    existing = {normalize_mac(device.mac) for device in devices if device.mac}
    for ip, info in neighbours.items():
        mac = normalize_mac(info.get("mac"))
        if mac and mac in known_macs and mac not in existing:
            devices.append(SkyDevice(ip=ip, mac=mac, hostname="", port=8091, properties={}, sources=["neighbour-table"]))
    return devices


def discover_mdns(timeout: float = 5.0) -> list[SkyDevice]:
    try:
        from zeroconf import ServiceBrowser, Zeroconf
    except ImportError:
        return []
    found: dict[str, SkyDevice] = {}

    class Listener:
        def add_service(self, zc, service_type, name):
            info = zc.get_service_info(service_type, name)
            if not info:
                return
            properties = {str(key, "utf-8") if isinstance(key, bytes) else str(key): str(value, "utf-8", "replace") if isinstance(value, bytes) else str(value) for key, value in (info.properties or {}).items()}
            addresses = [socket.inet_ntoa(address) for address in info.addresses if len(address) == 4]
            if not addresses:
                return
            ip = addresses[0]
            found[ip] = SkyDevice(ip=ip, mac=properties.get("wowl_mac") or properties.get("wol_mac") or properties.get("device_id", ""), hostname=info.server or "", port=info.port or 8091, properties=properties, sources=["mDNS"])
        update_service = add_service
        remove_service = lambda self, zc, service_type, name: None

    zc = Zeroconf()
    try:
        ServiceBrowser(zc, MDNS_SERVICE, Listener())
        time.sleep(max(0.0, timeout))
        return list(found.values())
    finally:
        zc.close()


def discover_avahi(timeout: float = 5.0) -> list[SkyDevice]:
    """Read avahi-browse output when the Python zeroconf listener misses interfaces."""
    try:
        result = subprocess.run(
            ["avahi-browse", "-rt", "--parsable", MDNS_SERVICE],
            check=False,
            capture_output=True,
            text=True,
            timeout=max(1.0, timeout + 2.0),
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    found: dict[str, SkyDevice] = {}
    for line in result.stdout.splitlines():
        fields = line.split(";")
        if len(fields) < 10 or not fields[0].startswith("=") or fields[4] != "_rdk-rics._tcp":
            continue
        properties = {}
        for item in shlex.split(";".join(fields[9:])):
            if "=" in item:
                key, value = item.split("=", 1)
                properties[key] = value
        ip = fields[7]
        found[ip] = SkyDevice(
            ip=ip,
            mac=properties.get("wowl_mac") or properties.get("wol_mac") or properties.get("device_id", ""),
            hostname=fields[6],
            port=int(fields[8] or 8091),
            properties=properties,
            sources=["mDNS/avahi"],
        )
    return list(found.values())


def merge_and_classify(devices: list[SkyDevice], policy: ExclusionPolicy, safety: SafetyPolicy | None = None) -> list[SkyDevice]:
    neighbours = read_neighbours()
    for device in devices:
        neighbour = neighbours.get(device.ip, {})
        if not device.mac:
            device.mac = neighbour.get("mac", "")
        if "neighbour-table" not in device.sources:
            device.sources.append("neighbour-table")
        identity = DeviceIdentity(device.ip, device.mac, device.hostname)
        matches = policy.matches(identity)
        device.excluded = bool(matches)
        device.exclusion_reason = "; ".join(item.get("reason", "excluded") for item in matches)
        device.confidence = "HIGH" if device.mac and device.hostname else "MEDIUM"
        if safety and safety.permitted_target(identity):
            device.type_guess = "Permitted test target"
        if device.properties.get("device_id"):
            device.type_guess = "Sky RDK/RICS device"
    return devices


def read_hmc_inventory(path: str) -> list[SkyDevice]:
    """Read the existing HMC device-notes JSON without changing production data."""
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return []
    devices = []
    rows = data.get("devices", data) if isinstance(data, dict) else {}
    for key, item in rows.items() if isinstance(rows, dict) else []:
        if not isinstance(item, dict):
            continue
        label = " ".join(str(item.get(field, "")) for field in ("friendly_name", "purpose", "note"))
        if "sky" not in f"{key} {label}".lower():
            continue
        devices.append(SkyDevice(
            ip=key if re.match(r"^\d+\.\d+\.\d+\.\d+$", key) else str(item.get("ip", "")),
            mac=str(item.get("mac", "")),
            hostname=str(item.get("hostname", "")),
            service="",
            rics_advertised=False,
            sources=["Home Ops device_notes.json"],
            type_guess="Sky device from inventory (RICS not observed in this browse)",
            confidence="MEDIUM",
        ))
    return devices


def merge_inventory(devices: list[SkyDevice], inventory: list[SkyDevice]) -> list[SkyDevice]:
    for item in inventory:
        match = next((candidate for candidate in devices if (item.ip and candidate.ip == item.ip) or (item.mac and candidate.mac.lower() == item.mac.lower())), None)
        if match:
            for value in (item.mac, item.hostname):
                if value and not match.mac and value == item.mac:
                    match.mac = value
                if value and not match.hostname and value == item.hostname:
                    match.hostname = value
            match.sources.extend(source for source in item.sources if source not in match.sources)
            match.confidence = "HIGH" if match.mac and match.hostname else match.confidence
        elif item.ip or item.mac:
            devices.append(item)
    return devices


def as_records(devices: list[SkyDevice]) -> list[dict]:
    return [asdict(device) for device in devices]

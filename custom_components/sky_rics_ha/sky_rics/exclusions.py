"""Stable identity matching and fail-closed active-operation policy."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path


class SafetyError(RuntimeError):
    """Raised when an active operation is not safe to perform."""


def normalize_mac(value: str | None) -> str:
    return re.sub(r"[-:.]", "", (value or "")).lower()


def normalize_hostname(value: str | None) -> str:
    return (value or "").strip().lower().rstrip(".")


def normalize_ip(value: str | None) -> str:
    value = (value or "").strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value


@dataclass(frozen=True)
class DeviceIdentity:
    ip: str | None = None
    mac: str | None = None
    hostname: str | None = None


class ExclusionPolicy:
    def __init__(self, entries: list[dict[str, str]], source: Path | None = None):
        self.entries = entries
        self.source = source

    @classmethod
    def load(cls, path: str | Path) -> "ExclusionPolicy":
        source = Path(path)
        data = json.loads(source.read_text(encoding="utf-8"))
        return cls(list(data.get("entries", [])), source)

    def matches(self, identity: DeviceIdentity) -> list[dict[str, str]]:
        return _match_entries(self.entries, identity)

    def assert_allowed(self, identity: DeviceIdentity, *, active: bool = True) -> None:
        if not active:
            return
        matches = self.matches(identity)
        if matches:
            names = ", ".join(item.get("friendly_name", "excluded device") for item in matches)
            raise SafetyError(f"Refusing active operation for excluded identity: {names}")
        if not identity.mac or not identity.hostname:
            raise SafetyError("Refusing active operation: stable MAC and hostname identity are required")


class SafetyPolicy:
    """Fail-closed active gate: not excluded AND a MAC-keyed permitted target."""

    def __init__(self, exclusions: ExclusionPolicy, targets: list[dict[str, str]]):
        self.exclusions = exclusions
        self.targets = targets

    @classmethod
    def load(cls, exclusions_path: str | Path, targets_path: str | Path) -> "SafetyPolicy":
        exclusions = ExclusionPolicy.load(exclusions_path)
        source = Path(targets_path)
        data = json.loads(source.read_text(encoding="utf-8"))
        return cls(exclusions, list(data.get("entries", [])))

    def excluded(self, identity: DeviceIdentity) -> list[dict[str, str]]:
        return self.exclusions.matches(identity)

    def permitted_target(self, identity: DeviceIdentity) -> dict[str, str] | None:
        matches = _match_entries(self.targets, identity)
        for entry in matches:
            if normalize_mac(entry.get("mac")):
                return entry
        return None

    def assert_allowed(self, identity: DeviceIdentity, *, active: bool = True) -> None:
        if not active:
            return
        if self.excluded(identity):
            names = ", ".join(item.get("friendly_name", "excluded device") for item in self.excluded(identity))
            raise SafetyError(f"Refusing active operation for excluded identity: {names}")
        if not identity.mac:
            raise SafetyError("Refusing active operation: stable MAC identity is required")
        target = self.permitted_target(identity)
        if target is None:
            raise SafetyError("Refusing active operation: identity is not a MAC-keyed permitted target")


def _match_entries(entries: list[dict[str, str]], identity: DeviceIdentity) -> list[dict[str, str]]:
    values = {
        "ip": normalize_ip(identity.ip),
        "mac": normalize_mac(identity.mac),
        "hostname": normalize_hostname(identity.hostname),
    }
    matches = []
    for entry in entries:
        for field in ("ip", "mac", "hostname"):
            expected = entry.get(field)
            if not expected:
                continue
            actual = values[field]
            normalized = normalize_mac(expected) if field == "mac" else normalize_hostname(expected) if field == "hostname" else normalize_ip(expected)
            if actual and actual == normalized:
                matches.append(entry)
                break
    return matches

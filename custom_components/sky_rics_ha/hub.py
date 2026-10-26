"""Safety-gated hub for the sky_rics_ha research integration.

Wraps the fail-closed `sky_rics` client: resolves the permitted target's
current IP by MAC, enforces exclusions + permitted-target policy, redacts
authentication material, and exposes presence / bind / key-command operations
for Home Assistant to call.

All blocking network work happens in the caller's executor thread.
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .const import (CONF_ALLOW_KEYS, CONF_EXCLUSIONS, CONF_MAC, CONF_PORT,
                    CONF_REDACT, CONF_TARGETS, DOMAIN)

if TYPE_CHECKING:  # pragma: no cover
    from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)

# Where the research sky_rics package lives (repo root) or is bundled.
import sys  # noqa: E402

_CC_DIR = Path(__file__).resolve().parent
_BUNDLED = _CC_DIR / "sky_rics"
if _BUNDLED.is_dir() and str(_BUNDLED.parent) not in sys.path:
    sys.path.insert(0, str(_BUNDLED.parent))
REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@dataclass
class SkyRicsHub:
    """Per-target hub for one permitted Sky device."""

    mac: str
    exclusions_path: str
    targets_path: str
    cert_chain: str | None = None
    private_key: str | None = None
    port: int = 8091
    redact: bool = True
    allow_keys: bool = False
    host: str = ""  # resolved dynamically by MAC

    # Last session outcome. Updated only by real sessions, never by polling,
    # so the bound sensor reflects history instead of re-authenticating.
    last_session: dict = field(default_factory=lambda: {
        "bound": None, "reason": "no-session", "device_name": "", "bind_id": None,
    })
    _listeners: list = field(default_factory=list)

    def __post_init__(self):
        self._policy = None  # loaded lazily inside executor-thread operations

    # -- change notification --------------------------------------------------

    def add_listener(self, callback):
        """Register a no-arg callback; returns an unsubscribe function."""
        self._listeners.append(callback)
        return lambda: self._listeners.remove(callback)

    def _set_session(self, **kwargs) -> None:
        self.last_session = {**self.last_session, **kwargs}
        for callback in list(self._listeners):
            try:
                callback()
            except Exception:  # noqa: BLE001 - a bad listener must not break a send
                _LOGGER.debug("sky_rics listener failed", exc_info=True)

    def _get_policy(self):
        from sky_rics.exclusions import SafetyPolicy

        if self._policy is None:
            self._policy = SafetyPolicy.load(self.exclusions_path, self.targets_path)
        return self._policy

    # -- identity / policy ----------------------------------------------------

    def _neighbour_ip(self) -> str:
        """Look the MAC up in the kernel neighbour table (JSON, then text, then arp)."""
        from sky_rics.exclusions import normalize_mac

        want = normalize_mac(self.mac)
        try:
            result = subprocess.run(
                ["ip", "-j", "neigh"], check=False, capture_output=True, text=True, timeout=5
            )
            for row in json.loads(result.stdout or "[]"):
                if normalize_mac(row.get("lladdr", "")) == want and row.get("dst"):
                    return row["dst"]
        except (OSError, ValueError, subprocess.TimeoutExpired):
            pass

        # Busybox `ip` has no -j; fall back to parsing the text form.
        try:
            result = subprocess.run(
                ["ip", "neigh", "show"], check=False, capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if "lladdr" in parts:
                    idx = parts.index("lladdr")
                    if idx + 1 < len(parts) and normalize_mac(parts[idx + 1]) == want:
                        return parts[0]
        except (OSError, subprocess.TimeoutExpired):
            pass

        try:
            result = subprocess.run(
                ["arp", "-an"], check=False, capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                # arp -an: "? (192.168.0.165) at b0:45:30:61:ef:66 [ether] on eth0"
                if "(" in line and ")" in line and " at " in line:
                    ip = line.split("(", 1)[1].split(")", 1)[0]
                    mac = line.split(" at ", 1)[1].split()[0]
                    if normalize_mac(mac) == want:
                        return ip
        except (OSError, subprocess.TimeoutExpired):
            pass
        return ""

    def _static_ip(self) -> str:
        """Static IP recorded for this MAC in the permitted-targets file."""
        from sky_rics.exclusions import normalize_mac

        try:
            entries = json.loads(Path(self.targets_path).read_text()).get("entries", [])
        except (OSError, ValueError):
            return ""
        for entry in entries:
            if normalize_mac(entry.get("mac", "")) == normalize_mac(self.mac):
                return entry.get("ip", "") or ""
        return ""

    def _wake_neighbour(self, ip: str) -> None:
        """Send one UDP datagram so the kernel ARPs the device (no TCP/TLS)."""
        import socket

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(1)
                sock.connect((ip, self.port))
                sock.send(b"")
        except OSError:
            pass

    def resolve_ip(self) -> str:
        """Resolve the permitted MAC's current IP.

        The HA container's neighbour table is often empty because nothing has
        talked to the device yet, so this falls back to the static IP recorded
        for the MAC in the permitted-targets file. Policy is still MAC-keyed:
        the resolved IP is re-checked against the policy before any session.
        """
        ip = self._neighbour_ip()
        if ip:
            return ip
        ip = self._static_ip()
        if ip:
            self._wake_neighbour(ip)
        return ip

    def identity(self, ip: str):
        from sky_rics.exclusions import DeviceIdentity

        return DeviceIdentity(ip=ip, mac=self.mac, hostname="")

    def assert_allowed(self, ip: str) -> None:
        from sky_rics.exclusions import SafetyError

        try:
            self._get_policy().assert_allowed(self.identity(ip))
        except SafetyError as exc:  # noqa: BLE001
            _LOGGER.warning("sky_rics: blocked by policy: %s", exc)
            raise

    # -- operations (blocking; run in executor) ------------------------------

    def _session(self, ip: str):
        from sky_rics.client import RicsSession

        self.assert_allowed(ip)
        return RicsSession(
            identity=self.identity(ip),
            policy=self._get_policy(),
            cert_chain=self.cert_chain,
            private_key=self.private_key,
            port=self.port,
            _redact=self.redact,
        )

    def presence(self) -> bool:
        """True if TCP 8091 is reachable (device awake). No pairing, no TLS."""
        import socket

        ip = self.resolve_ip()
        if not ip:
            return False
        try:
            with socket.create_connection((ip, self.port), timeout=5):
                return True
        except OSError:
            return False

    def bind_state(self) -> dict:
        """Establish a pair+bind session and report bound state. No key sent."""
        ip = self.resolve_ip()
        if not ip:
            self._set_session(bound=False, reason="no-ip", device_name="", bind_id=None)
            return {"bound": False, "reason": "no-ip", "device_name": "", "bind_id": None}
        session = self._session(ip)
        try:
            session.connect()
            session.websocket_handshake()
            pair = session.pair()
            if not pair.get("status"):
                self._set_session(bound=False, reason="pair-failed", device_name=session.device_name, bind_id=None)
                return {"bound": False, "reason": "pair-failed", "device_name": session.device_name}
            session.device_name = pair.get("name", "")
            bind = session.bind(pair.get("pairingcode", ""), pair.get("stbnonce", ""))
            if not bind.get("status"):
                self._set_session(bound=False, reason="bind-failed", device_name=session.device_name, bind_id=None)
                return {"bound": False, "reason": "bind-failed", "device_name": session.device_name}
            self._set_session(bound=True, reason="ok", device_name=session.device_name, bind_id=session.bind_id)
            return {
                "bound": True,
                "reason": "ok",
                "device_name": session.device_name,
                "bind_id": session.bind_id,
            }
        except Exception as exc:  # noqa: BLE001
            _LOGGER.warning("sky_rics bind_state error: %s", exc)
            self._set_session(bound=False, reason=str(exc), device_name="", bind_id=None)
            return {"bound": False, "reason": str(exc), "device_name": ""}
        finally:
            session.close()

    def send_key(self, key: str) -> dict:
        """Send exactly one key command to the permitted device."""
        from sky_rics.exclusions import SafetyError

        if not self.allow_keys:
            raise SafetyError("key commands disabled (allow_key_commands=false)")
        ip = self.resolve_ip()
        if not ip:
            self._set_session(bound=False, reason="no-ip", device_name="", bind_id=None)
            return {"sent": False, "reason": "no-ip"}
        session = self._session(ip)
        try:
            session.connect()
            session.websocket_handshake()
            pair = session.pair()
            if not pair.get("status"):
                self._set_session(bound=False, reason="pair-failed", device_name=session.device_name, bind_id=None)
                return {"sent": False, "reason": "pair-failed"}
            session.device_name = pair.get("name", "")
            bind = session.bind(pair.get("pairingcode", ""), pair.get("stbnonce", ""))
            if not bind.get("status"):
                self._set_session(bound=False, reason="bind-failed", device_name=session.device_name, bind_id=None)
                return {"sent": False, "reason": "bind-failed"}
            self._set_session(bound=True, reason="ok", device_name=session.device_name, bind_id=session.bind_id)
            resp = session.send_key(key)
            return {"sent": resp.get("status", False) is True, "reason": "ok", "bind_id": session.bind_id}
        except Exception as exc:  # noqa: BLE001
            _LOGGER.warning("sky_rics send_key error: %s", exc)
            self._set_session(bound=False, reason=str(exc), device_name="", bind_id=None)
            return {"sent": False, "reason": str(exc)}
        finally:
            session.close()


def get_hub(hass: "HomeAssistant", config) -> SkyRicsHub:
    """Return the single shared hub for this MAC (one session owner)."""
    store = hass.data.setdefault(DOMAIN, {})
    mac = config[CONF_MAC]
    hub = store.get(mac)
    if hub is None:
        hub = SkyRicsHub(
            mac=mac,
            exclusions_path=config.get(CONF_EXCLUSIONS, ""),
            targets_path=config.get(CONF_TARGETS, ""),
            port=config.get(CONF_PORT, 8091),
            redact=config.get(CONF_REDACT, True),
            allow_keys=config.get(CONF_ALLOW_KEYS, False),
        )
        store[mac] = hub
    return hub
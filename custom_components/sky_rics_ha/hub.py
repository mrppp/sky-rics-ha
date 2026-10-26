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
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .const import (CONF_ALLOW_KEYS, CONF_EXCLUSIONS, CONF_MAC, CONF_PORT,
                    CONF_REDACT, CONF_TARGETS, CONF_WAKE_ON_ANY_KEY,
                    CONF_WAKE_SETTLE, DOMAIN)

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

    # Persistent session state. Measured: idle sessions die between 30s and
    # 600s, but a 20s WebSocket ping held one for 600s+ and it still accepted a
    # key. So the session is kept alive by pings and retired on any ping error.
    ping_interval: float = 20.0
    idle_retire: float = 90.0
    wake_settle: float = 30.0
    wake_timeout: float = 45.0
    wake_on_any_key: bool = False
    _conn: object = None
    _io_lock: object = field(default_factory=threading.Lock)
    _wake_lock: object = field(default_factory=threading.Lock)
    _keepalive_stop: object = None
    _keepalive_thread: object = None
    _last_used: float = 0.0
    _generation: int = 0
    _ping_ok: bool = True

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

    # -- persistent session ---------------------------------------------------

    def _new_session(self, ip: str):
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

    def _start_keepalive(self) -> None:
        stop = threading.Event()
        self._keepalive_stop = stop
        self._ping_ok = True
        thread = threading.Thread(
            target=self._keepalive_loop, args=(stop, self._generation), daemon=True,
            name=f"sky_rics_keepalive_{self.mac}",
        )
        self._keepalive_thread = thread
        thread.start()

    def _keepalive_loop(self, stop: threading.Event, generation: int) -> None:
        while not stop.wait(self.ping_interval):
            if generation != self._generation:
                return
            conn = self._conn
            if conn is None:
                return
            try:
                with self._io_lock:
                    conn.ping()
            except Exception as exc:  # noqa: BLE001
                _LOGGER.warning("sky_rics keepalive failed: %s", exc)
                self._ping_ok = False
                self._drop_session("keepalive-failed")
                return

    def _drop_session(self, reason: str) -> None:
        """Retire the current session. Safe to call from any thread."""
        self._generation += 1
        stop, self._keepalive_stop = self._keepalive_stop, None
        if stop is not None:
            stop.set()
        conn, self._conn = self._conn, None
        self._ping_ok = True
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
        if self.last_session.get("bound"):
            self._set_session(bound=False, reason=reason, bind_id=None)

    def _ensure_session(self):
        """Return a live bound session, opening one if needed.

        Caller must hold `_io_lock`. A session whose last ping failed is never
        reused. Only one connect/pair/bind attempt is made; a failed bind is
        not retried (repeated failures risk lockout).
        """
        conn = self._conn
        if conn is not None and self._ping_ok:
            if time.monotonic() - self._last_used < self.idle_retire:
                return conn
            self._drop_session("idle")
        elif conn is not None:
            self._drop_session("stale")

        ip = self.resolve_ip()
        if not ip:
            self._set_session(bound=False, reason="no-ip", device_name="", bind_id=None)
            raise ConnectionError("no-ip")

        conn = self._new_session(ip)
        try:
            conn.connect()
            conn.websocket_handshake()
            pair = conn.pair()
            if not pair.get("status"):
                self._set_session(bound=False, reason="pair-failed", device_name="", bind_id=None)
                raise ConnectionError("pair-failed")
            conn.device_name = pair.get("name", "")
            bind = conn.bind(pair.get("pairingcode", ""), pair.get("stbnonce", ""))
            if not bind.get("status"):
                self._set_session(bound=False, reason="bind-failed", device_name=conn.device_name, bind_id=None)
                raise ConnectionError("bind-failed")
        except Exception:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
            raise

        self._conn = conn
        self._last_used = time.monotonic()
        self._set_session(bound=True, reason="ok", device_name=conn.device_name, bind_id=conn.bind_id)
        self._start_keepalive()
        return conn

    # -- operations (blocking; run in executor) ------------------------------

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

    # -- wake -----------------------------------------------------------------

    def wake(self) -> bool:
        """Wake the device and wait for it to settle.

        Measured: a key sent the instant 8091 opens aborts the boot and drops
        the device back to standby, so the settle delay is load-bearing.
        """
        from sky_rics.wake import send_wol, wait_for_port

        with self._wake_lock:
            if self.presence():
                return True
            ip = self.resolve_ip()
            if not ip:
                return False
            send_wol(self.mac)
            if not wait_for_port(ip, self.port, self.wake_timeout):
                return False
            time.sleep(self.wake_settle)
            return True

    def _wake_in_background(self) -> None:
        if self._wake_lock.locked():
            return
        threading.Thread(
            target=self._safe_wake, daemon=True, name=f"sky_rics_wake_{self.mac}"
        ).start()

    def _safe_wake(self) -> None:
        try:
            self.wake()
        except Exception:  # noqa: BLE001
            _LOGGER.debug("sky_rics background wake failed", exc_info=True)

    def _asleep(self, key: str) -> dict:
        """Handle a command aimed at a device that is not reachable."""
        if key == "Power" or self.wake_on_any_key:
            return {}  # caller should wake then send
        self._wake_in_background()
        return {"sent": False, "reason": "asleep", "waking": True}

    def bind_state(self) -> dict:
        """Report bound state, reusing the live session when there is one."""
        try:
            with self._io_lock:
                conn = self._ensure_session()
                self._last_used = time.monotonic()
        except Exception as exc:  # noqa: BLE001
            reason = str(exc) or exc.__class__.__name__
            return {"bound": False, "reason": reason, "device_name": "", "bind_id": None}
        return {
            "bound": True,
            "reason": "ok",
            "device_name": conn.device_name,
            "bind_id": conn.bind_id,
        }

    def send_key(self, key: str) -> dict:
        """Send exactly one key command to the permitted device.

        A failure after the frame may have been written is reported as
        `uncertain` — the key may have executed even though no response came.
        """
        from sky_rics.exclusions import SafetyError

        if not self.allow_keys:
            raise SafetyError("key commands disabled (allow_key_commands=false)")

        if not self.presence():
            asleep = self._asleep(key)
            if asleep:
                return asleep
            if not self.wake():
                return {"sent": False, "reason": "wake-failed"}

        with self._io_lock:
            try:
                conn = self._ensure_session()
            except Exception as exc:  # noqa: BLE001
                reason = str(exc) or exc.__class__.__name__
                return {"sent": False, "reason": reason}
            try:
                response = conn.send_key(key)
            except Exception as exc:  # noqa: BLE001
                _LOGGER.warning("sky_rics send_key error: %s", exc)
                self._drop_session("connection-lost")
                return {"sent": False, "reason": str(exc), "uncertain": True}
            self._last_used = time.monotonic()
            return {
                "sent": response.get("status", False) is True,
                "reason": "ok",
                "bind_id": conn.bind_id,
            }

    def close(self) -> None:
        """Retire the session (used on unload)."""
        with self._io_lock:
            self._drop_session("closed")


def get_hub(hass: "HomeAssistant", config) -> SkyRicsHub:
    """Return the single shared hub for this MAC (one session owner).

    Platforms are set up in arbitrary order and only the remote platform
    carries allow_key_commands, so an existing hub is upgraded rather than
    silently keeping the first platform's defaults.
    """
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
            wake_on_any_key=config.get(CONF_WAKE_ON_ANY_KEY, False),
            wake_settle=config.get(CONF_WAKE_SETTLE, 30.0),
        )
        store[mac] = hub
    elif config.get(CONF_ALLOW_KEYS) and not hub.allow_keys:
        hub.allow_keys = True
    return hub
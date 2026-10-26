"""Safety-gated transport for permitted RICS validation (stops after bind)."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import ssl
import uuid
from dataclasses import dataclass

from .auth import compute_auth_token
from .exclusions import DeviceIdentity, SafetyError, SafetyPolicy
from .protocol import build_bind_request, build_key_command, build_pair_request
from .tls import client_leaf_fingerprint, create_client_context, default_credential_paths
from .websocket import PING, TEXT, build_client_frame, read_server_frame


@dataclass
class RicsSession:
    identity: DeviceIdentity
    policy: SafetyPolicy
    cert_chain: str | None = None
    private_key: str | None = None
    port: int = 8091
    sock: ssl.SSLSocket | None = None
    tid: str = ""
    controller_nonce: str = ""
    auth_token: str = ""
    bind_id: int | None = None
    device_name: str = ""
    _redact: bool = True

    def __post_init__(self):
        if not self.cert_chain or not self.private_key:
            self.cert_chain, self.private_key = default_credential_paths()

    # -- transport -----------------------------------------------------------

    def connect(self) -> None:
        self.policy.assert_allowed(self.identity)
        context = create_client_context(self.cert_chain, self.private_key)
        raw = socket.create_connection((self.identity.ip, self.port), timeout=10)
        self.sock = context.wrap_socket(raw, server_hostname="sky.xcal.tv")

    def websocket_handshake(self) -> bytes:
        if not self.sock:
            raise RuntimeError("not connected")
        key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET /iptarget HTTP/1.1\r\n"
            f"Host: sky.xcal.tv:{self.port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Origin: https://{self.identity.ip}:{self.port}/\r\n"
            f"User-Agent: Sky-RICS-Research/0.1\r\n"
            f"Cache-Control: no-cache\r\n"
            f"Accept-Encoding: gzip\r\n\r\n"
        )
        self.sock.sendall(request.encode())
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("closed during handshake")
            response += chunk
        status = response.split(b"\r\n", 1)[0].decode(errors="replace")
        if "101" not in status:
            raise ConnectionError(f"WebSocket upgrade failed: {status}")
        expected = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        if expected.encode() not in response:
            raise ConnectionError("WebSocket accept key mismatch")
        return response

    def _recv_exact(self, n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("connection closed")
            data += chunk
        return data

    def send_json(self, message: dict) -> None:
        if not self.sock:
            raise RuntimeError("not connected")
        payload = json.dumps(message, separators=(",", ":"), sort_keys=True).encode()
        self.sock.sendall(build_client_frame(payload, TEXT))
        self._log("SEND", message)

    def recv_json(self) -> dict:
        if not self.sock:
            raise RuntimeError("not connected")
        while True:
            opcode, payload = read_server_frame(self._recv_exact)
            if opcode == TEXT:
                message = json.loads(payload.decode("utf-8"))
                self._log("RECV", message)
                return message
            if opcode in (0x9, 0xA):  # ping/pong: protocol-level, not application JSON
                continue
            if opcode == 0x8:
                raise ConnectionError("websocket closed by server")

    # -- protocol ------------------------------------------------------------

    def pair(self) -> dict:
        self.tid = str(uuid.uuid4())
        self.controller_nonce = str(uuid.uuid4())
        self.send_json(build_pair_request(self.tid, self.controller_nonce))
        return self.recv_json()

    def bind(self, pairing_code: str, stb_nonce: str) -> dict:
        fingerprint = client_leaf_fingerprint(self.cert_chain)
        self.auth_token = compute_auth_token(fingerprint, pairing_code, self.controller_nonce, stb_nonce)
        self.send_json(build_bind_request(self.tid, self.auth_token))
        response = self.recv_json()
        if response.get("status"):
            self.bind_id = response.get("bind_id")
        return response

    def send_key(self, key: str) -> dict:
        """Send one key command; requires a successful bind first."""
        if self.bind_id is None or not self.auth_token:
            raise SafetyError("cannot send key without a successful bind")
        self.send_json(build_key_command(self.tid, self.auth_token, self.bind_id, key))
        return self.recv_json()

    def ping(self) -> None:
        """Send a protocol-level WebSocket ping (no application JSON).

        Any PONG is skipped by recv_json, so this is safe to interleave with
        real traffic.
        """
        if not self.sock:
            raise RuntimeError("not connected")
        self.sock.sendall(build_client_frame(b"", PING))

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            finally:
                self.sock = None

    # -- logging -------------------------------------------------------------

    def _log(self, direction: str, message: dict) -> None:
        safe = dict(message)
        for key in ("authtoken", "controllernonce", "stbnonce", "pairingcode"):
            if key in safe and self._redact:
                safe[key] = "<redacted>"
        print(f"[{direction}] {json.dumps(safe, sort_keys=True)}")

    def summary(self) -> dict:
        return {
            "ip": self.identity.ip,
            "mac": self.identity.mac,
            "device_name": self.device_name,
            "bind_id": self.bind_id,
            "pair_ok": bool(self.device_name),
            "bind_ok": self.bind_id is not None,
        }
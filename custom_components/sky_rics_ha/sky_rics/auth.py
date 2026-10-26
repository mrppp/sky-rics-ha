"""Pure authentication-token calculation; no transport or device access."""

from __future__ import annotations

import base64
import hashlib


AUTH_SALT = b"biT43y"


def compute_auth_token(cert_fingerprint: str, pairing_code: str, controller_nonce: str, stb_nonce: str) -> str:
    """Calculate the published two-stage SHA-256 RICS bind token."""
    fingerprint = bytes.fromhex(cert_fingerprint)
    inner = hashlib.sha256(fingerprint + pairing_code.encode() + controller_nonce.encode()).digest()
    return base64.b64encode(hashlib.sha256(stb_nonce.encode() + inner + AUTH_SALT).digest()).decode()

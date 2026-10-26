"""TLS context construction from operator-supplied credentials only."""

from __future__ import annotations

import hashlib
import re
import ssl
from pathlib import Path


_CERT = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)

_CERT_NAME = "sky.xcal.tv-ComcastRDKD2DECCICA1-20260430-20270430.pem"
_KEY_NAME = "softremote_sky_key.pem"
_PUBLISHED_LEAF_FINGERPRINT = "18486ecac9c50b49260278571dd485b94bd4153edc9d058fab4c21dd3fb3ed02"


def default_credential_paths() -> tuple[Path, Path]:
    """Resolve the published mTLS client identity installed under certs/.

    The material is gitignored; callers must check existence before use.
    """
    certs_dir = Path(__file__).resolve().parents[1] / "certs"
    return certs_dir / _CERT_NAME, certs_dir / _KEY_NAME


def client_leaf_fingerprint(cert_chain: str | Path) -> str:
    text = Path(cert_chain).read_text(encoding="utf-8")
    match = _CERT.search(text)
    if not match:
        raise ValueError("No certificate found in client chain")
    body = match.group().replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "")
    import base64
    return hashlib.sha256(base64.b64decode(body)).hexdigest()


def create_client_context(cert_chain: str | Path, private_key: str | Path, verify_server: bool = False) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    context.check_hostname = verify_server
    context.verify_mode = ssl.CERT_REQUIRED if verify_server else ssl.CERT_NONE
    context.load_cert_chain(str(cert_chain), str(private_key))
    return context

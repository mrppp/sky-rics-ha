"""Small, safety-gated Sky RICS protocol research library."""

from .auth import compute_auth_token
from .client import RicsSession
from .exclusions import ExclusionPolicy, SafetyError, SafetyPolicy
from .protocol import (
    build_bind_request,
    build_key_command,
    build_pair_request,
    parse_bind_response,
    parse_pair_response,
)

__all__ = [
    "ExclusionPolicy",
    "RicsSession",
    "SafetyError",
    "SafetyPolicy",
    "compute_auth_token",
    "build_bind_request",
    "build_key_command",
    "build_pair_request",
    "parse_bind_response",
    "parse_pair_response",
]

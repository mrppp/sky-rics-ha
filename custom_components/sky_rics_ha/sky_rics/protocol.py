"""JSON message builders/parsers for the RICS WebSocket protocol."""

from __future__ import annotations

import uuid
from typing import Any


def build_pair_request(tid: str, controller_nonce: str, name: str = "Sky RICS Research") -> dict[str, Any]:
    return {"command_name": "Pair Request", "tid": tid, "name": name, "manufacturer": "Comcast", "model": "IPRemote", "controllernonce": controller_nonce}


def parse_pair_response(message: dict[str, Any]) -> dict[str, Any]:
    required = ("status", "tid")
    if any(field not in message for field in required):
        raise ValueError("Pair response is missing status or tid")
    return message


def build_bind_request(tid: str, auth_token: str) -> dict[str, Any]:
    return {"command_name": "Bind Request", "tid": tid, "authtoken": auth_token}


def parse_bind_response(message: dict[str, Any]) -> dict[str, Any]:
    if "status" not in message or "tid" not in message:
        raise ValueError("Bind response is missing status or tid")
    if message.get("status") and "bind_id" not in message:
        raise ValueError("Successful bind response is missing bind_id")
    return message


def build_key_command(tid: str, auth_token: str, bind_id: int, key: str) -> dict[str, Any]:
    return {"command_name": "Key Command Request", "tid": tid, "authtoken": auth_token, "bind_id": bind_id, "cmd": "keyatomic", "key": key}


def new_session_ids() -> tuple[str, str]:
    return str(uuid.uuid4()), str(uuid.uuid4())

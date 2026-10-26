"""Small WebSocket framing helpers, kept transport-independent and testable."""

from __future__ import annotations

import os
import struct


TEXT = 0x1
CLOSE = 0x8
PING = 0x9
PONG = 0xA


def _mask(payload: bytes, key: bytes) -> bytes:
    return bytes(byte ^ key[index % 4] for index, byte in enumerate(payload))


def build_client_frame(payload: bytes, opcode: int = TEXT, mask_key: bytes | None = None) -> bytes:
    key = mask_key or os.urandom(4)
    length = len(payload)
    if length < 126:
        header = bytes((0x80 | opcode, 0x80 | length))
    elif length < 65536:
        header = bytes((0x80 | opcode, 0xFE)) + struct.pack("!H", length)
    else:
        header = bytes((0x80 | opcode, 0xFF)) + struct.pack("!Q", length)
    return header + key + _mask(payload, key)


def read_server_frame(read_exactly) -> tuple[int, bytes]:
    """Parse a server WebSocket frame using a read_exactly(n)->bytes callable.

    Server frames are unmasked. Returns (opcode, payload).
    """
    head = read_exactly(2)
    opcode = head[0] & 0x0F
    length = head[1] & 0x7F
    if length == 126:
        length = struct.unpack("!H", read_exactly(2))[0]
    elif length == 127:
        length = struct.unpack("!Q", read_exactly(8))[0]
    payload = read_exactly(length)
    return opcode, payload

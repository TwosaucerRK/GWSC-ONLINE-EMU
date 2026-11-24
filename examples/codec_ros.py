"""Example body codec: shows the contract, not a real scheme.

    python -m online_emu.server --body-codec examples/codec_ros.py:CODEC

A codec converts between the bytes on the wire and the ``key=value`` form the
server parses (requests) or the XML it renders (responses). Everything it needs
arrives in ``ctx``; it must not keep state between requests.

The sample below is a trivial XOR so the plumbing can be exercised end to end.
It is **not** the scheme the client uses: replace ``_xor`` with yours.
"""

from __future__ import annotations

from typing import Dict, Tuple

from online_emu.plugin import CodecContext

_KEY = b"change-me"


def _xor(data: bytes) -> bytes:
    if not _KEY:
        return data
    return bytes(byte ^ _KEY[i % len(_KEY)] for i, byte in enumerate(data))


class RosLikeCodec:
    """Minimal codec: decode before parsing, encode after rendering."""

    name = "example-xor"

    def decode(self, raw: bytes, ctx: CodecContext) -> bytes:
        # The ticket request arrives without a session, so nothing session
        # dependent can be used here.
        return _xor(raw)

    def encode(self, payload: bytes, ctx: CodecContext) -> Tuple[bytes, Dict[str, str]]:
        headers: Dict[str, str] = {}
        if len(payload) >= 20:
            headers["X-Body-Codec"] = self.name
        return _xor(payload), headers


CODEC = RosLikeCodec()

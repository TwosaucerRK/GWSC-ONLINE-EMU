"""Extension point for custom body codecs.

The server speaks plain XML with its own signing scheme (see ``crypto.py``).
To plug a client that expects a different encoding there is no need to touch
the server: write a *codec* and load it with ``--body-codec``.

This module only defines the contract and the loader; no scheme is
implemented here.

Contract
--------

A codec is a class (or an already built instance) with two methods::

    decode(raw, ctx) -> bytes
        Receives the raw body as it arrived. Returns the clear-text body the
        server will parse as a ``key=value&...`` form.

    encode(payload, ctx) -> (bytes, dict)
        Receives the rendered XML response. Returns the body to send plus a
        dict of extra headers (for example ``{"Content-Type": ...}``).

Both are called **only on the ``.asmx`` routes**. The web panel and
``/gwsc/api/`` always stay outside.

``ctx`` carries everything needed to avoid global state::

    ctx.method   "POST"
    ctx.path     "/gta5/11/gameservices/auth.asmx/CreateTicketSc3"
    ctx.headers  lowercase dict with the request headers
    ctx.raw      original untouched body (useful to log or hash it)
    ctx.ticket   the session Ticket, or None
    ctx.store    the Store (accounts, tickets)

The codec does not act on requests carrying ``ros-Encrypted-Body``: that path
is handled by the server's own body encryption.

Loading
-------

    python -m online_emu.server --body-codec module:Class
    python -m online_emu.server --body-codec path/to/file.py:Class

Without ``--body-codec`` there is no codec and the server behaves as usual.

Two notes that save headaches:

1. **The ticket call arrives without a session**, so ``ctx.ticket`` is
   ``None`` there. Any key needed for that first request has to come from
   your own configuration, not from the ticket.
2. If ``decode`` returns something that is not ``key=value``, the request is
   parsed empty and the ticket handler falls back to its tolerant mode (last
   account that logged in). It is silent: log what you decode while
   developing.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


@dataclass
class CodecContext:
    """Everything a codec needs to know about the current request."""

    method: str
    path: str
    headers: Dict[str, str]
    raw: bytes
    ticket: Any = None
    store: Any = None


class BodyCodec:
    """Null codec. This is the one used when nothing is configured."""

    name = "none"

    def decode(self, raw: bytes, ctx: CodecContext) -> bytes:
        return raw

    def encode(self, payload: bytes, ctx: CodecContext) -> Tuple[bytes, Dict[str, str]]:
        return payload, {}


def _load_symbol(spec: str):
    """Resolve ``module:Attr`` or ``file.py:Attr``."""
    target, _, attr = spec.partition(":")
    if not attr:
        attr = "CODEC"
    target = target.strip()
    if not target:
        raise ValueError("--body-codec needs a module or a file")

    looks_like_path = target.endswith(".py") or os.sep in target or "/" in target
    if looks_like_path:
        if not os.path.exists(target):
            raise FileNotFoundError("codec file not found: %s" % target)
        module_name = "online_emu_codec_%x" % (abs(hash(os.path.abspath(target))))
        module_spec = importlib.util.spec_from_file_location(module_name, target)
        if module_spec is None or module_spec.loader is None:
            raise ImportError("could not load %s" % target)
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
    else:
        module = importlib.import_module(target)

    if not hasattr(module, attr):
        raise AttributeError("%s does not define '%s'" % (target, attr))
    return getattr(module, attr)


def load_codec(spec: Optional[str]) -> BodyCodec:
    """Return the requested codec, or the null one when none was asked for."""
    if not spec:
        return BodyCodec()

    symbol = _load_symbol(spec)
    codec = symbol() if isinstance(symbol, type) else symbol

    for method in ("decode", "encode"):
        if not callable(getattr(codec, method, None)):
            raise TypeError("the codec must implement %s()" % method)
    return codec


def load_verifier(spec: Optional[str]):
    """Return the requested HMAC verifier, or None when none was asked for.

    A verifier is a class (or instance) with a method::

        verify(provided, method, path, session_ticket, challenge, session_key) -> bool

    where ``challenge`` is already decoded from base64 (bytes) and
    ``provided`` is the header exactly as it arrived. It is loaded the same
    way as a codec: ``module:Class`` or ``file.py:Class``.
    """
    if not spec:
        return None

    symbol = _load_symbol(spec)
    verifier = symbol() if isinstance(symbol, type) else symbol

    if not callable(getattr(verifier, "verify", None)):
        raise TypeError("the verifier must implement verify()")
    return verifier

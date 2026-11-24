"""Request signing scheme — STUB.

The client signs every request after the ticket with three headers
(``ros-SessionTicket``, ``ros-Challenge`` and ``ros-Hmac``). This module is
where that scheme is supposed to live, but **the implementation is not
included**: the details of the real scheme are exactly the part of this
project that is still open, and publishing a guessed version would only mislead
whoever continues the work.

What is known, and what the stub has to reproduce:

* ``ros-Challenge`` is random bytes (base64). The server hands it back
  unchanged when it recomputes the signature.
* ``ros-Hmac`` is a base64 MAC over a message that includes, at least, the
  HTTP method, the path, the security flags, the session ticket and the
  challenge. Whether the session key takes part, and how it is combined with
  any platform material, is not settled.
* The key material is not shipped with the client in a readable form, so a
  fully faithful verifier needs a platform key that somebody has to recover
  first. ``--hmac-verifier`` exists to plug such an implementation without
  touching the server (see ``ros_crypto.py``).

The methods below are the contract the server calls. Implement them and the
rest of the emulator works unchanged.
"""

from __future__ import annotations

import os

SECURITY_FLAGS = b"239"
CHALLENGE_BYTES = 16
SESSION_KEY_BYTES = 16
PLATFORM_KEY_BYTES = 64


def rc4(key: bytes, data: bytes) -> bytes:
    """RC4 (ARCFOUR) — STUB, left as an exercise on purpose.

    The transport may or may not use a stream cipher like this one; if your
    research shows it does, this is the place to put it. Implement it from
    scratch rather than pulling a library so the whole scheme stays readable.
    """
    raise NotImplementedError("rc4: implement the stream cipher used by the body codec")


class RosCrypto:
    """Cryptographic state shared between the server and authorized clients."""

    def __init__(self, platform_key: bytes) -> None:
        if len(platform_key) != PLATFORM_KEY_BYTES:
            raise ValueError("platform_key must be %d bytes" % PLATFORM_KEY_BYTES)
        self.platform_key = platform_key
        # TODO: derive the keys (XOR key, hash key, body key) from the
        # platform key. The derivation lives inside the client binary.

    @classmethod
    def generate(cls) -> "RosCrypto":
        return cls(os.urandom(PLATFORM_KEY_BYTES))

    @classmethod
    def from_hex(cls, value: str) -> "RosCrypto":
        return cls(bytes.fromhex(value))

    def new_session_key(self) -> str:
        import base64

        return base64.b64encode(os.urandom(SESSION_KEY_BYTES)).decode()

    def hmac_key(self, session_key_b64: str) -> bytes:
        """Derive the MAC key for a session.

        TODO: combine the session key with the platform material the same way
        the client does. Until this is known, no signature can be verified.
        """
        raise NotImplementedError("hmac_key: the key derivation is not implemented")

    def sign(
        self,
        method: str,
        path: str,
        session_ticket: str,
        challenge: bytes,
        session_key_b64: str,
    ) -> str:
        """Return the base64 ``ros-Hmac`` for one request.

        TODO: build the message (method, path, security flags, session ticket,
        challenge) and the key exactly as the client does.
        """
        raise NotImplementedError("sign: the request signing scheme is not implemented")

    def verify(
        self,
        provided: str,
        method: str,
        path: str,
        session_ticket: str,
        challenge: bytes,
        session_key_b64: str,
    ) -> bool:
        """Check one ``ros-Hmac`` header.

        Kept implemented on top of ``sign`` so a subclass only has to provide
        the scheme: constant-time comparison happens here.
        """
        import hmac as _hmac

        try:
            expected = self.sign(method, path, session_ticket, challenge, session_key_b64)
        except NotImplementedError:
            raise
        except Exception:
            return False
        return _hmac.compare_digest(expected, provided)

    @staticmethod
    def new_challenge() -> bytes:
        return os.urandom(CHALLENGE_BYTES)

    # -- encrypted bodies -------------------------------------------------
    def body_key(self, session_key_b64: str) -> bytes:
        """Key used for ``ros-Encrypted-Body`` requests."""
        raise NotImplementedError("body_key: the body encryption scheme is not implemented")

    def encrypt_body(self, data: bytes, session_key_b64: str) -> bytes:
        raise NotImplementedError("encrypt_body: the body encryption scheme is not implemented")

    def decrypt_body(self, data: bytes, session_key_b64: str) -> bytes:
        raise NotImplementedError("decrypt_body: the body encryption scheme is not implemented")

    # -- persistence ------------------------------------------------------
    def platform_key_hex(self) -> str:
        return self.platform_key.hex()

    @classmethod
    def load_or_create(cls, path: str) -> "RosCrypto":
        """Stable key across restarts.

        If the file exists it is reused; otherwise a new key is generated and
        stored as hex. Without this, every start would change the key and any
        session issued before a restart would stop verifying.
        """
        if os.path.exists(path):
            with open(path, "r", encoding="ascii") as handle:
                return cls.from_hex(handle.read().strip())
        crypto = cls.generate()
        # 0600: not a vendor secret, but nothing else needs to read it either.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(crypto.platform_key_hex())
        return crypto

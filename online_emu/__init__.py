"""Local emulator for the online service layer used by the game client.

It implements the ticket lifecycle, the per-request signature hooks and the
cloud endpoints a client asks for, so the protocol can be studied offline
without touching the live service.

Status: research base. The cryptographic modules are intentionally left as
stubs (see ``crypto.py`` and ``ros_crypto.py``).
"""

__version__ = "0.1.0"

"""Emulator state: accounts, session tickets and presence.

The token lengths mirror the real ones (208 characters for the service ticket
and 88 for the session ticket, i.e. 156 and 64 bytes in base64) so a client
that validates sizes behaves the same way here.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

TICKET_BYTES = 156  # -> 208 base64 characters
SESSION_TICKET_BYTES = 64  # -> 88 characters
# 32 bytes -> 44 base64 characters. The client compares the length against
# 0x2c (44) and 0x20 (32); 16 bytes were rejected.
SESSION_KEY_BYTES = 32


PASSWORD_ITERATIONS = 120_000


def make_token(nbytes: int) -> str:
    return base64.b64encode(os.urandom(nbytes)).decode()


def hash_password(password: str) -> str:
    """Return ``pbkdf2$iterations$salt$hash`` for a plain password.

    A local emulator does not need production-grade auth, but storing clear
    passwords in a JSON file (and showing that pattern in a public base) is a
    bad habit worth not teaching.
    """
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return "pbkdf2$%d$%s$%s" % (
        PASSWORD_ITERATIONS,
        base64.b64encode(salt).decode(),
        base64.b64encode(digest).decode(),
    )


def check_password(stored: str, password: str) -> bool:
    """Compare a plain password with the stored value.

    Accepts a legacy clear-text value so an old ``accounts.json`` keeps working
    until it is written back.
    """
    if not stored:
        return False
    if not stored.startswith("pbkdf2$"):
        return hmac.compare_digest(stored, password)
    try:
        _, iterations, salt_b64, digest_b64 = stored.split("$", 3)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, int(iterations)
        )
    except Exception:
        return False
    return hmac.compare_digest(candidate, expected)


@dataclass
class Account:
    account_id: int
    nickname: str
    email: str
    password_hash: str
    platform: str = "pcros"
    rank: int = 1
    cash: int = 0
    bank: int = 0


@dataclass
class Ticket:
    ticket: str
    session_ticket: str
    session_key: str
    account_id: int
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    expires_at: float = 0.0
    online: bool = True


class Store:
    """In-memory store with optional persistence of the accounts."""

    TICKET_TTL = 24 * 3600

    def __init__(self, path: Optional[str] = None, persist_tickets: bool = False) -> None:
        self.path = path
        # Off by default: a persisted ticket holds a live session key, so the
        # account file becomes a secret. Without it, a restart means the client
        # has to log in again.
        self.persist_tickets = persist_tickets
        self.accounts: Dict[int, Account] = {}
        self.tickets: Dict[str, Ticket] = {}
        self.invites: List[Dict[str, Any]] = []
        self.last_login_id: Optional[int] = None
        self._next_id = 1
        if self.path and os.path.exists(self.path):
            self.load()
        if not self.accounts:
            self.create_account("demo@local", "DEMOPLAYER", "demo1234")

    # -- persistence -----------------------------------------------------
    def load(self) -> None:
        with open(self.path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for raw in data.get("accounts", []):
            # Older files kept a clear-text `password` field.
            if "password" in raw and "password_hash" not in raw:
                raw["password_hash"] = hash_password(raw.pop("password"))
            account = Account(**raw)
            self.accounts[account.account_id] = account
        for raw in data.get("tickets", []):
            try:
                ticket = Ticket(**raw)
            except TypeError:
                continue
            self.tickets[ticket.session_ticket] = ticket
        self.last_login_id = data.get("last_login_id")
        self._next_id = max(self.accounts, default=0) + 1

    def save(self) -> None:
        if not self.path:
            return
        payload = {
            "accounts": [asdict(a) for a in self.accounts.values()],
            # Only written with --persist-tickets: these rows contain session
            # keys, i.e. live credentials.
            "tickets": (
                [asdict(t) for t in self.tickets.values()] if self.persist_tickets else []
            ),
            "last_login_id": self.last_login_id,
        }
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)

    # -- accounts --------------------------------------------------------
    def create_account(
        self, email: str, nickname: str, password: str, platform: str = "pcros"
    ) -> Account:
        account = Account(
            account_id=self._next_id,
            nickname=nickname,
            email=email,
            password_hash=hash_password(password),
            platform=platform,
        )
        self.accounts[account.account_id] = account
        self._next_id += 1
        self.save()
        return account

    def account(self, account_id: int) -> Optional[Account]:
        return self.accounts.get(account_id)

    def find_by_email(self, email: str) -> Optional[Account]:
        wanted = (email or "").strip().lower()
        for account in self.accounts.values():
            if account.email.strip().lower() == wanted:
                return account
        return None

    def mark_login(self, account: Account) -> None:
        """Remember who logged in last."""
        self.last_login_id = account.account_id
        self.save()

    def latest_account(self) -> Optional[Account]:
        """Fallback when the client does not identify itself.

        The last account that logged in is preferred over the last created
        one: the client sometimes sends no credentials and would otherwise be
        mapped to a test account.
        """
        if self.last_login_id is not None and self.last_login_id in self.accounts:
            return self.accounts[self.last_login_id]
        if not self.accounts:
            return None
        return self.accounts[max(self.accounts)]

    def find_by_nickname(self, nickname: str) -> Optional[Account]:
        wanted = nickname.strip().lower()
        for account in self.accounts.values():
            if account.nickname.strip().lower() == wanted:
                return account
        return None

    # -- tickets ---------------------------------------------------------
    def issue_ticket(self, account: Account) -> Ticket:
        ticket = Ticket(
            ticket=make_token(TICKET_BYTES),
            session_ticket=make_token(SESSION_TICKET_BYTES),
            session_key=make_token(SESSION_KEY_BYTES),
            account_id=account.account_id,
            expires_at=time.time() + self.TICKET_TTL,
        )
        self.tickets[ticket.session_ticket] = ticket
        self.save()
        return ticket

    def get_ticket(self, session_ticket: str) -> Optional[Ticket]:
        ticket = self.tickets.get(session_ticket)
        if ticket is None:
            return None
        if ticket.expires_at and ticket.expires_at < time.time():
            self.tickets.pop(session_ticket, None)
            return None
        return ticket

    def find_ticket(self, value: str) -> Optional[Ticket]:
        """Look a session up by session ticket or by the service ticket.

        The client sends the long ticket (the one from the ticket creation
        call) inside the body of signed routes instead of the
        ``ros-SessionTicket`` header, so both forms are accepted.
        """
        if not value:
            return None
        ticket = self.get_ticket(value)
        if ticket is not None:
            return ticket
        now = time.time()
        for candidate in self.tickets.values():
            if candidate.ticket == value:
                if candidate.expires_at and candidate.expires_at < now:
                    return None
                return candidate
        return None

    def touch(self, ticket: Ticket) -> None:
        """Mark activity, not presence.

        Holding a token only proves the client is logged in: the launcher
        polls every 30 s from its home screen. Counting that as "online" would
        show players in game without a session. Presence is set by
        ``mark_online``.
        """
        ticket.last_seen = time.time()

    def mark_online(self, ticket: Ticket) -> None:
        """The client already got its ticket: it is inside a session."""
        ticket.online = True
        ticket.last_seen = time.time()
        self.save()

    def online_tickets(self) -> List[Ticket]:
        now = time.time()
        return [t for t in self.tickets.values() if t.online and t.expires_at > now]

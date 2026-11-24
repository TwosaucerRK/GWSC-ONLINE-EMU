"""Adapter for launcher-style clients.

Some ports do not speak the ``.asmx`` protocol: they speak plain JSON REST
under ``/gwsc/api/``. This module translates between that surface and the same
accounts and ``Store`` used by the rest of the emulator.

Routes seen from a real Android client:

    GET  /gwsc/api/info
    POST /gwsc/api/login    {"email","password","client"}
    GET  /gwsc/api/me
    GET  /gwsc/api/friends
    GET  /gwsc/api/achievements
    POST /gwsc/api/achievements

The rest follow the same naming as the website (``/stats``, ``/online``,
``/garage``, ``/conversations``, ``/news``...), so they are implemented with
empty lists and compatible shapes until the client asks for real data.

Authentication: the token returned by ``login`` is the store's session ticket.
It is accepted in ``Authorization: Bearer``, in ``X-Token`` /
``X-Session-Token`` headers and in cookies. With no token at all, the last
issued session is used (convenience for a single-user server).
"""

from __future__ import annotations

import time
from typing import Optional, Tuple

from . import __version__
from .store import Store, check_password

AUTH_HEADERS = ("X-Token", "X-Session", "X-Session-Token", "X-Auth-Token", "X-Rockstar-Token")
COOKIE_NAMES = ("gwsc_token", "token", "session")


def profile(account) -> dict:
    return {
        "rockstarId": account.account_id,
        "account_id": account.account_id,
        "nickname": account.nickname,
        "name": account.nickname,
        "email": account.email,
        "platform": account.platform,
        "rank": account.rank,
        "cash": account.cash,
        "bank": account.bank,
        "avatar": "",
        "mugshot": "",
    }


class Launcher:
    """JSON surface for the port client."""

    def __init__(self, store: Store, crypto) -> None:
        self.store = store
        self.crypto = crypto
        self.seen = []

    # -- identity --------------------------------------------------------
    def _find(self, identity: str):
        account = self.store.find_by_nickname(identity or "")
        if account is not None:
            return account
        wanted = (identity or "").strip().lower()
        for candidate in self.store.accounts.values():
            if candidate.email.strip().lower() == wanted:
                return candidate
        return None

    def _token_from(self, headers, params) -> str:
        auth = headers.get("Authorization") or ""
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        for name in AUTH_HEADERS:
            value = headers.get(name)
            if value:
                return value.strip()
        cookie = headers.get("Cookie") or ""
        for part in cookie.split(";"):
            key, _, value = part.strip().partition("=")
            if key in COOKIE_NAMES and value:
                return value
        return (params or {}).get("token", "") or ""

    def _latest_session_account(self):
        """Last issued session: convenience for a single-user server."""
        tickets = sorted(self.store.tickets.values(), key=lambda t: t.created_at)
        for ticket in reversed(tickets):
            account = self.store.account(ticket.account_id)
            if account is not None:
                return account
        return None

    def _account_for(self, headers, params):
        token = self._token_from(headers, params)
        if token:
            ticket = self.store.get_ticket(token)
            if ticket is not None:
                self.store.touch(ticket)
                return self.store.account(ticket.account_id)
        return self._latest_session_account()

    def _online_accounts(self) -> list:
        seen = set()
        rows = []
        for ticket in self.store.online_tickets():
            if ticket.account_id in seen:
                continue
            account = self.store.account(ticket.account_id)
            if account is None:
                continue
            seen.add(ticket.account_id)
            rows.append(account)
        return rows

    # -- responses -------------------------------------------------------
    def _info(self) -> dict:
        online = self._online_accounts()
        return {
            "ok": True,
            "name": "Online Emulator",
            "server": "online-emu",
            "version": __version__,
            "accounts": len(self.store.accounts),
            "online": len(online),
            "playersOnline": len(online),
            "approvalRequired": False,
            "registration": "open",
            "time": int(time.time()),
        }

    def _login(self, body: dict) -> Tuple[int, dict]:
        identity = (
            body.get("email") or body.get("identity") or body.get("nickname") or body.get("username") or ""
        )
        password = body.get("password") or ""
        client = body.get("client") or "launcher"

        if not identity or not password:
            return 400, {
                "ok": False,
                "error": "missing_credentials",
                "message": "email and password are required",
            }

        account = self._find(identity)
        if account is None or not check_password(account.password_hash, password):
            return 401, {
                "ok": False,
                "error": "invalid_credentials",
                "message": "wrong credentials",
            }

        ticket = self.store.issue_ticket(account)
        self.store.mark_login(account)
        data = profile(account)
        return 200, {
            "ok": True,
            "status": "ok",
            "client": client,
            "token": ticket.session_ticket,
            "sessionToken": ticket.session_ticket,
            "session_token": ticket.session_ticket,
            "ticket": ticket.ticket,
            "sessionTicket": ticket.session_ticket,
            "rockstarId": account.account_id,
            "account": data,
            "user": data,
            "player": data,
        }

    def _register(self, body: dict) -> Tuple[int, dict]:
        email = (body.get("email") or "").strip()
        nickname = (body.get("nickname") or body.get("username") or "").strip()
        password = body.get("password") or ""
        if "@" not in email or not nickname or len(password) < 4:
            return 400, {
                "ok": False,
                "error": "invalid_data",
                "message": "a valid email, a nickname and a password of 4+ are required",
            }
        if self.store.find_by_nickname(nickname):
            return 409, {"ok": False, "error": "nickname_taken", "message": "that nickname already exists"}
        account = self.store.create_account(email, nickname, password)
        return 201, {"ok": True, "account": profile(account)}

    def _me(self, account) -> dict:
        data = profile(account)
        payload = {"ok": True, "account": data, "user": data, "player": data}
        payload.update(data)  # flat aliases, in case the client reads nickname at the top
        return payload

    def _stats(self, account) -> dict:
        stats = {
            "rank": account.rank,
            "cash": account.cash,
            "bank": account.bank,
            "playtime": "0d 0h 14m",
        }
        payload = {"ok": True, "stats": stats, "account": profile(account)}
        payload.update(stats)
        return payload

    def _online(self) -> dict:
        rows = [profile(a) for a in self._online_accounts()]
        return {"ok": True, "online": len(rows), "playersOnline": len(rows), "players": rows}

    # -- routing ---------------------------------------------------------
    def dispatch(self, method: str, subpath: str, body: dict, params, headers) -> Tuple[int, dict]:
        route = subpath.strip("/").lower()
        self.seen.append((method, "/gwsc/api/" + route, time.time()))
        account = self._account_for(headers, params)

        if method == "GET" and route in ("info", ""):
            return 200, self._info()
        if method == "POST" and route in ("login", "signin", "auth/login"):
            return self._login(body or params)
        if method == "POST" and route in ("register", "signup", "auth/register"):
            return self._register(body or params)
        if method == "POST" and route in ("logout", "signout"):
            return 200, {"ok": True}
        if route in ("online", "players"):
            return 200, self._online()

        # Everything below needs to know who the caller is.
        if account is None:
            return 401, {"ok": False, "error": "unauthorized", "message": "no session"}

        if route in ("me", "me/profile", "player/me"):
            return 200, self._me(account)
        if method == "GET" and route == "me/avatar":
            return 200, {"ok": True, "avatar": "", "presets": []}
        if method == "POST" and route in ("me/avatar", "me/avatar/preset", "me/profile"):
            return 200, {"ok": True, "account": profile(account)}
        if method == "POST" and route == "me/password":
            return 200, {"ok": True, "changed": False, "message": "password change not supported"}
        if route in ("stats", "me/stats"):
            return 200, self._stats(account)

        if route in ("friends", "blocks"):
            return 200, {
                "ok": True,
                "friends": [],
                "requests": [],
                "incoming": [],
                "outgoing": [],
                "pending": 0,
                "blocks": [],
                "count": 0,
            }
        if route in ("conversations", "messages"):
            return 200, {"ok": True, "conversations": [], "messages": [], "unread": 0}
        if route == "achievements":
            if method == "POST":
                return 200, {"ok": True, "saved": True}
            return 200, {"ok": True, "achievements": [], "items": [], "unlocked": 0, "total": 0}
        if route in ("garage", "plates", "vehicles"):
            return 200, {"ok": True, "garage": [], "vehicles": [], "plates": []}
        if route == "chop":
            return 200, {"ok": True, "collar": 0, "chop": None}
        if route in ("news", "newswire", "events"):
            return 200, {"ok": True, "news": [], "events": [], "items": [], "posts": []}
        if route in ("sharkcards", "store", "starterpack", "subscription"):
            return 200, {
                "ok": True,
                "items": [],
                "products": [],
                "purchases": [],
                "subscription": None,
                "starterpack": None,
            }
        if route == "avatars/presets":
            return 200, {"ok": True, "presets": []}

        # Unknown route: empty 200 so the client keeps going and the log shows
        # the next route it needs.
        return 200, {"ok": True, "route": route, "notImplemented": True}

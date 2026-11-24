"""Web panel for the emulator.

Serves a single page (HTML + JS, no build step, no dependencies) and a small
JSON API under ``/panel/api/`` to register, log in, list online players and
read the server state.

The panel session is independent from the game ticket: it is an ``HttpOnly``
cookie mapped to an account id. The service protocol (ticket + HMAC) stays
untouched on the ``.asmx`` routes; this is only the administrative side.
"""

from __future__ import annotations

import re
import secrets
from typing import Dict, Optional, Tuple

from . import __version__
from .store import Store, check_password

SESSION_COOKIE = "panel_token"
NICKNAME_RE = re.compile(r"[A-Za-z0-9_]{3,20}")

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Online Emulator - Panel</title>
<style>
:root{color-scheme:dark;--bg:#0d1117;--panel:#161b22;--line:#26303d;--txt:#e6edf3;--dim:#8b98a5;--acc:#3fb950}
*{box-sizing:border-box}
body{margin:0;font:15px/1.5 system-ui,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--txt)}
header{display:flex;justify-content:space-between;align-items:center;padding:16px 20px;border-bottom:1px solid var(--line)}
h1{font-size:18px;margin:0}
h1 small{color:var(--dim);font-weight:400;font-size:13px}
#who{color:var(--dim);font-size:13px}
nav{display:flex;gap:8px;padding:12px 20px;border-bottom:1px solid var(--line);flex-wrap:wrap}
nav button{background:transparent;border:1px solid var(--line);color:var(--txt);padding:7px 14px;border-radius:8px;cursor:pointer;font:inherit}
nav button.active{border-color:var(--acc);color:var(--acc)}
main{padding:20px;max-width:920px}
section{display:none}
section.active{display:block}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:16px}
h2{font-size:15px;margin:0 0 12px}
p.hint{color:var(--dim);font-size:13px;margin:0 0 10px}
label{display:block;font-size:13px;color:var(--dim);margin:10px 0 4px}
input{width:100%;padding:9px 11px;border-radius:8px;border:1px solid var(--line);background:#0d1117;color:var(--txt);font:inherit}
button.primary{background:var(--acc);color:#04120a;border:0;padding:10px 16px;border-radius:8px;font-weight:600;cursor:pointer;margin-top:14px;font:inherit}
button.ghost{background:transparent;border:1px solid var(--line);color:var(--txt);padding:9px 14px;border-radius:8px;cursor:pointer;margin-top:14px;font:inherit}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line)}
th{color:var(--dim);font-weight:500;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
code{background:#0d1117;border:1px solid var(--line);padding:3px 8px;border-radius:6px;font-size:14px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.stat{background:#0d1117;border:1px solid var(--line);border-radius:10px;padding:12px}
.stat b{display:block;font-size:20px}
.stat span{color:var(--dim);font-size:12px}
.msg{margin-top:12px;font-size:13px;min-height:18px}
.err{color:#f85149}
.ok{color:var(--acc)}
</style>
</head>
<body>
<header>
  <h1>Online Emulator <small>panel</small></h1>
  <span id="who">no session</span>
</header>

<nav>
  <button data-tab="server" class="active">Server</button>
  <button data-tab="access">Access</button>
  <button data-tab="players">Players</button>
  <button data-tab="account">Account</button>
</nav>

<main>
  <section id="server" class="active">
    <div class="card">
      <h2>Connect a client</h2>
      <p class="hint">Address to use in the client or port:</p>
      <p><code id="addr">...</code></p>
      <p class="hint" style="margin-top:14px">Routes exposed by the server:</p>
      <table>
        <thead><tr><th>Service</th><th>Method</th></tr></thead>
        <tbody id="routes"></tbody>
      </table>
    </div>
    <div class="card">
      <h2>State</h2>
      <div class="grid">
        <div class="stat"><b id="n-acc">-</b><span>accounts</span></div>
        <div class="stat"><b id="n-online">-</b><span>online</span></div>
        <div class="stat"><b id="n-routes">-</b><span>routes</span></div>
        <div class="stat"><b id="n-invites">-</b><span>invites</span></div>
      </div>
    </div>
  </section>

  <section id="access">
    <div class="card">
      <h2>Sign in</h2>
      <form id="login-form">
        <label>Nickname or email</label>
        <input name="identity" autocomplete="username" required>
        <label>Password</label>
        <input name="password" type="password" autocomplete="current-password" required>
        <button class="primary" type="submit">Sign in</button>
        <div class="msg" id="login-msg"></div>
      </form>
    </div>
    <div class="card">
      <h2>Create account</h2>
      <p class="hint">The account lives only on this server. No vendor account is needed.</p>
      <form id="register-form">
        <label>Email</label>
        <input name="email" type="email" autocomplete="email" required>
        <label>Nickname (3-20, letters, numbers or underscore)</label>
        <input name="nickname" autocomplete="username" required>
        <label>Password (4+ characters)</label>
        <input name="password" type="password" autocomplete="new-password" required>
        <button class="primary" type="submit">Create account</button>
        <div class="msg" id="register-msg"></div>
      </form>
    </div>
  </section>

  <section id="players">
    <div class="card">
      <h2>Online players</h2>
      <table>
        <thead><tr><th>Nickname</th><th>ID</th><th>Platform</th><th>Session</th></tr></thead>
        <tbody id="players"></tbody>
      </table>
      <div class="msg" id="players-msg"></div>
    </div>
  </section>

  <section id="account">
    <div class="card">
      <h2>My account</h2>
      <div class="grid">
        <div class="stat"><b id="c-nick">-</b><span>nickname</span></div>
        <div class="stat"><b id="c-id">-</b><span>account id</span></div>
        <div class="stat"><b id="c-rank">-</b><span>rank</span></div>
        <div class="stat"><b id="c-cash">-</b><span>cash</span></div>
        <div class="stat"><b id="c-bank">-</b><span>bank</span></div>
      </div>
      <button class="ghost" id="logout">Sign out</button>
      <div class="msg" id="cuenta-msg"></div>
    </div>
  </section>
</main>

<script>
const $ = (sel) => document.querySelector(sel);

async function api(path, options) {
  const res = await fetch('/panel/api/' + path, Object.assign({credentials: 'same-origin'}, options || {}));
  let data = {};
  try { data = await res.json(); } catch (e) { data = {}; }
  if (!res.ok) { throw new Error(data.error || ('error ' + res.status)); }
  return data;
}

async function post(path, payload) {
  return api(path, {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams(payload)
  });
}

function setMsg(id, text, ok) {
  const node = $(id);
  node.textContent = text;
  node.className = 'msg ' + (ok ? 'ok' : 'err');
}

function showTab(name) {
  document.querySelectorAll('nav button').forEach((b) => {
    b.classList.toggle('active', b.dataset.tab === name);
  });
  document.querySelectorAll('section').forEach((s) => {
    s.classList.toggle('active', s.id === name);
  });
  if (name === 'players') { loadPlayers(); }
  if (name === 'account') { loadAccount(); }
  if (name === 'server') { loadInfo(); }
}

document.querySelectorAll('nav button').forEach((btn) => {
  btn.addEventListener('click', () => showTab(btn.dataset.tab));
});

async function loadInfo() {
  $('#addr').textContent = location.host;
  try {
    const info = await api('info');
    $('#n-acc').textContent = info.accounts;
    $('#n-online').textContent = info.online;
    $('#n-routes').textContent = info.routes.length;
    $('#n-invites').textContent = info.invites;
    const body = $('#routes');
    body.innerHTML = '';
    info.routes.forEach((pair) => {
      const tr = document.createElement('tr');
      const a = document.createElement('td');
      const b = document.createElement('td');
      a.textContent = pair[0];
      b.textContent = pair[1];
      tr.appendChild(a);
      tr.appendChild(b);
      body.appendChild(tr);
    });
    $('#who').textContent = info.me ? (info.me.nickname + ' (#' + info.me.rockstarId + ')') : 'no session';
  } catch (e) {
    $('#who').textContent = 'server not responding';
  }
}

async function loadPlayers() {
  try {
    const data = await api('players');
    const body = $('#players');
    body.innerHTML = '';
    if (!data.players.length) {
      setMsg('#players-msg', 'Nobody is connected.', true);
    } else {
      setMsg('#players-msg', data.players.length + ' player(s) online', true);
    }
    data.players.forEach((p) => {
      const tr = document.createElement('tr');
      [p.nickname, p.rockstarId, p.platform, p.session].forEach((value) => {
        const td = document.createElement('td');
        td.textContent = value;
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });
  } catch (e) {
    setMsg('#players-msg', e.message, false);
  }
}

async function loadAccount() {
  try {
    const data = await api('stats');
    $('#c-nick').textContent = data.account.nickname;
    $('#c-id').textContent = data.account.rockstarId;
    $('#c-rank').textContent = data.stats.rank;
    $('#c-cash').textContent = '$' + data.stats.cash;
    $('#c-bank').textContent = '$' + data.stats.bank;
    $('#who').textContent = data.account.nickname + ' (#' + data.account.rockstarId + ')';
    setMsg('#cuenta-msg', '', true);
  } catch (e) {
    setMsg('#cuenta-msg', 'Sign in to see your account.', false);
  }
}

$('#login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.target;
  try {
    const data = await post('login', {
      identity: form.identity.value,
      password: form.password.value
    });
    setMsg('#login-msg', 'Welcome, ' + data.account.nickname, true);
    form.reset();
    loadInfo();
  } catch (e) {
    setMsg('#login-msg', e.message, false);
  }
});

$('#register-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.target;
  try {
    const data = await post('register', {
      email: form.email.value,
      nickname: form.nickname.value,
      password: form.password.value
    });
    setMsg('#register-msg', 'Account created: ' + data.account.nickname + '. You can sign in now.', true);
    form.reset();
    loadInfo();
  } catch (e) {
    setMsg('#register-msg', e.message, false);
  }
});

$('#logout').addEventListener('click', async () => {
  try {
    await post('logout', {});
    setMsg('#cuenta-msg', 'Signed out.', true);
    $('#who').textContent = 'no session';
  } catch (e) {
    setMsg('#cuenta-msg', e.message, false);
  }
});

loadInfo();
</script>
</body>
</html>
"""


def cookie_token(cookie_header: str) -> Optional[str]:
    for part in (cookie_header or "").split(";"):
        name, _, value = part.strip().partition("=")
        if name == SESSION_COOKIE:
            return value
    return None


class Panel:
    """Panel API. Sessions are in memory and bound to an account id."""

    def __init__(self, store: Store, crypto, routes) -> None:
        self.store = store
        self.crypto = crypto
        self.routes = routes
        self.sessions: Dict[str, int] = {}

    # -- helpers ---------------------------------------------------------
    def _account_for(self, headers):
        token = cookie_token(headers.get("Cookie", ""))
        if not token:
            return None
        account_id = self.sessions.get(token)
        if account_id is None:
            return None
        return self.store.account(account_id)

    @staticmethod
    def _profile(account) -> dict:
        return {
            "rockstarId": account.account_id,
            "nickname": account.nickname,
            "email": account.email,
            "platform": account.platform,
            "rank": account.rank,
            "cash": account.cash,
            "bank": account.bank,
        }

    def _info(self, account) -> dict:
        return {
            "name": "Online Emulator",
            "version": __version__,
            "accounts": len(self.store.accounts),
            "online": len(self.store.online_tickets()),
            "invites": len(self.store.invites),
            "routes": [[service, name] for (service, name) in sorted(self.routes)],
            "me": self._profile(account) if account else None,
        }

    def _players(self, account) -> list:
        caller = account.account_id if account else None
        rows = []
        seen = set()
        for ticket in self.store.online_tickets():
            player = self.store.account(ticket.account_id)
            if player is None or player.account_id in seen:
                continue
            seen.add(player.account_id)
            rows.append(
                {
                    "nickname": player.nickname,
                    "rockstarId": player.account_id,
                    "platform": player.platform,
                    "session": ticket.session_ticket[:8],
                    "me": player.account_id == caller,
                }
            )
        return rows

    # -- actions ---------------------------------------------------------
    def _register(self, params):
        email = params.get("email", "").strip()
        nickname = params.get("nickname", "").strip()
        password = params.get("password", "")

        if "@" not in email or len(email) < 5:
            return 400, {"error": "invalid email"}, {}
        if not NICKNAME_RE.fullmatch(nickname):
            return 400, {"error": "invalid nickname: 3-20 characters, letters, numbers or _"}, {}
        if len(password) < 4:
            return 400, {"error": "the password needs at least 4 characters"}, {}
        if self.store.find_by_nickname(nickname):
            return 409, {"error": "that nickname is already taken"}, {}

        account = self.store.create_account(email, nickname, password)
        return 201, {"ok": True, "account": self._profile(account)}, {}

    def _find_identity(self, identity: str):
        account = self.store.find_by_nickname(identity)
        if account is not None:
            return account
        wanted = identity.strip().lower()
        for candidate in self.store.accounts.values():
            if candidate.email.strip().lower() == wanted:
                return candidate
        return None

    def _login(self, params):
        identity = params.get("identity", "").strip()
        password = params.get("password", "")
        if not identity or not password:
            return 400, {"error": "missing fields"}, {}

        account = self._find_identity(identity)
        if account is None or not check_password(account.password_hash, password):
            return 401, {"error": "wrong credentials"}, {}

        token = secrets.token_urlsafe(24)
        self.sessions[token] = account.account_id
        self.store.mark_login(account)
        cookie = "%s=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400" % (SESSION_COOKIE, token)
        return 200, {"ok": True, "account": self._profile(account)}, {"Set-Cookie": cookie}

    def _logout(self, headers):
        token = cookie_token(headers.get("Cookie", ""))
        if token:
            self.sessions.pop(token, None)
        cookie = "%s=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0" % SESSION_COOKIE
        return 200, {"ok": True}, {"Set-Cookie": cookie}

    def _stats(self, account) -> dict:
        return {
            "rank": account.rank,
            "cash": account.cash,
            "bank": account.bank,
            "playtime": "0d 0h 14m",
        }

    # -- routing ---------------------------------------------------------
    def dispatch(self, method: str, subpath: str, params, headers) -> Tuple[int, dict, dict]:
        route = subpath.strip("/").lower()
        account = self._account_for(headers)

        if method == "GET" and route == "info":
            return 200, self._info(account), {}
        if method == "GET" and route == "players":
            return 200, {"players": self._players(account)}, {}
        if method == "POST" and route == "register":
            return self._register(params)
        if method == "POST" and route == "login":
            return self._login(params)
        if method == "POST" and route == "logout":
            return self._logout(headers)
        if method == "GET" and route == "me":
            if account is None:
                return 401, {"error": "no session"}, {}
            return 200, {"account": self._profile(account)}, {}
        if method == "GET" and route == "stats":
            if account is None:
                return 401, {"error": "no session"}, {}
            return 200, {"account": self._profile(account), "stats": self._stats(account)}, {}

        return 404, {"error": "unknown route"}, {}

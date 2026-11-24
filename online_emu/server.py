"""Server that emulates the online service layer used by the game client.

Routes follow the real shape:

    /gta5/<version>/gameservices/<service>.asmx/<Method>

In production each service family lives on its own host; here everything is
served from one local host, because what matters for research is the contract
(route + ticket + signature), not the DNS.

Every route except the ticket creation one requires three headers:
``ros-SessionTicket``, ``ros-Challenge`` and ``ros-Hmac``.

``/`` serves the web panel (see ``panel.py``); its API lives under
``/panel/api/``.
"""

from __future__ import annotations

import base64
import itertools
import json
import socket
import os
import re
import ssl
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

from .cloud import Cloud
from .crypto import RosCrypto
from .launcher import Launcher
from .plugin import BodyCodec, CodecContext, load_codec, load_verifier

# Null codec by default: when none is configured the server behaves as usual.
NULL_CODEC = BodyCodec()

# Full logging: with `EMU_LOG_FULL=1` neither request bodies nor the ticket
# response are truncated. Without it the log cuts at 800 / 256 / 700
# characters and exactly the fields the engine reads end up missing.
LOG_COMPLETO = os.environ.get("EMU_LOG_FULL", "").strip().lower() not in (
    "",
    "0",
    "no",
    "false",
)
from .panel import PAGE as PANEL_PAGE
from .panel import Panel
from .store import Store
from .xmlfmt import render

# The `/gta5/<version>/gameservices` prefix is optional: the engine builds the
# URLs of the services announced in `<Services>` as host + `ep`, and does not
# always include that prefix. Accepting both forms lands on the same handler.
ROUTE_RE = re.compile(
    r"^(?:/gta5/(?P<version>\d+)/gameservices)?/"
    r"(?P<service>[A-Za-z0-9_]+)\.asmx/(?P<method>[A-Za-z0-9_]+)$",
    re.IGNORECASE,
)

Handler = Callable[["RosRequest"], Tuple[int, dict]]


class RosRequest:
    def __init__(self, store, crypto, method, path, params, headers) -> None:
        self.store = store
        self.crypto = crypto
        self.method = method
        self.path = path
        self.params = params
        self.headers = headers
        self.session = None  # Ticket when the request is signed

    def param(self, name: str, default: str = "") -> str:
        return self.params.get(name, default)

    @property
    def account(self):
        if self.session is None:
            return None
        return self.store.account(self.session.account_id)


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------
# Service names exactly as the engine looks them up. This table is what the
# client uses for everything after the ticket: stats, matchmaking, presence,
# inbox, crews and the character save. Without it the engine keeps its built-in
# hosts, sends the ticket there and never calls this server again.
#
# The `ep` value has to be the service name in the binary's exact spelling
# (`socialclub.asmx`, `auth.asmx`, `Conductor.asmx`, `accounts.svc`). The
# engine compares it with a wildcard match against the full service path, so
# the entries are sent as wildcard patterns.
SERVICE_ENDPOINTS = [
    "*auth.asmx*",
    "*socialclub.asmx*",
    "*accounts.svc*",
    "*ProfileStats.asmx*",
    "*matchmaking.asmx*",
    "*Presence.asmx*",
    "*presence.asmx*",
    "*Friends.asmx*",
    "*Clans.asmx*",
    "*Inbox.asmx*",
    "*ugc.asmx*",
    "*Telemetry.asmx*",
    "*Conductor.asmx*",
    "*entitlements.asmx*",
    "*legalpolicies.asmx*",
    "*GeoLocation.asmx*",
    "*Leaderboards.asmx*",
    "*Unlocks.asmx*",
    "*SaveMigration.asmx*",
    "*SaveMigrationSingleplayer.asmx*",
    "*CashTransactions.asmx*",
    "*Complaint.asmx*",
    "*licenseplates.asmx*",
    "*cloudservices*",
]


# Privilege ids packed into the access mask (28 of them). All are granted
# EXCEPT 7: bit 7 of the mask is not another privilege but the sentinel for
# "invalid privileges / banned account", so granting it makes the client reject
# every privilege and report missing credentials.
PRIVILEGES = [i for i in range(28) if i != 7]


def service_list(host: str) -> list:
    """Build the ``<Services>`` block with every endpoint on ``host``."""
    partes = ['<Services Count="%d">' % len(SERVICE_ENDPOINTS)]
    partes += ['<S ep="%s" h="%s" />' % (ep, host) for ep in SERVICE_ENDPOINTS]
    partes.append("</Services>")
    return partes


def ssl_service_list(host: str) -> list:
    """Build the ``<SslServices>`` block.

    The client looks for an ``SslServices`` node inside ``<Result>`` and copies
    the text of each child into its SSL service table. Without that node the
    table stays empty and everything after the ticket is requested over plain
    HTTP, which dies on a TLS-only port without even a log line.

    Only the text of each child is read, so the entries carry the same ``ep``
    identifiers plus the local host.
    """
    entradas = list(SERVICE_ENDPOINTS)
    if host not in entradas:
        entradas.append(host)
    partes = ['<SslServices Count="%d">' % len(entradas)]
    partes += ["<S>%s</S>" % ep for ep in entradas]
    partes.append("</SslServices>")
    return partes


def create_ticket_sc3(req: RosRequest):
    """Game client login. Deliberately tolerant.

    The client may send this as SOAP/XML without the parameter names expected
    here. It never answers 400 for missing data: a 400 on this route kicks the
    player back to single player.

    Resolution order: nickname -> email -> new account -> latest account.
    """
    email = req.param("email")
    nickname = req.param("nickname") or req.param("nickName") or req.param("Nickname")
    password = req.param("password") or req.param("pass") or req.param("Password")
    platform = (
        req.param("platformName")
        or req.param("platform")
        or "pcros"
    )

    account = None
    if nickname:
        account = req.store.find_by_nickname(nickname)
    if account is None and email:
        account = req.store.find_by_email(email)
    if account is None and nickname and password and "@" in (email or ""):
        account = req.store.create_account(email, nickname, password, platform)
    if account is None:
        account = req.store.latest_account()

    if account is None:
        return 200, {"Status": 0, "Error": "NoAccount"}

    ticket = req.store.issue_ticket(account)
    # Presence starts here: the client moved from the launcher login to a
    # service ticket.
    req.store.mark_online(ticket)
    # The ticket parser reads Services, Privileges and RockstarAccount besides
    # the ticket itself. Without those sections the client discards the
    # credentials and never calls another service.
    host_header = (req.headers.get("Host") or "").strip()
    host_name, _, host_port = host_header.partition(":")
    host_name = host_name or "127.0.0.1"
    host_port = host_port or "8787"
    host_efectivo = host_header or ("%s:%s" % (host_name, host_port))

    # Value of the field above. "2" clears the response-HMAC bit for this
    # title; set EMU_SECURITY_FLAGS_OFF to another mask, or to "" to omit the
    # field entirely (only works if the client does not enforce that gate).
    flags_off = os.environ.get("EMU_SECURITY_FLAGS_OFF", "2").strip()

    ahora = int(time.time())
    restante = max(0, int(ticket.expires_at) - ahora)
    cloud_key = base64.b64encode(os.urandom(16)).decode("ascii")

    # Field names come from the ticket response parser. Note the structure:
    # the fields are NOT read from the root. The parser first looks for a node
    # named `Result` and then reads Ticket, SecsUntilExpiration,
    # PlayerAccountId, Privileges, Privs, Services and RockstarAccount among
    # its children. A `Result` with no children makes it fail and the task
    # reports an error. `<Status>` stays at the root because the HTTP task
    # reads it there.
    partes = [
        '<?xml version="1.0" encoding="utf-8"?>',
        "<Response>",
        # The HTTP task requires `<Status>` and only treats `Status == 1` as
        # success. Without it the task errors out before processing the
        # ticket.
        "<Status>1</Status>",
        "<Result>",
        "<Ticket>%s</Ticket>" % ticket.ticket,
        "<SecsUntilExpiration>%d</SecsUntilExpiration>" % restante,
        "<SessionTicket>%s</SessionTicket>" % ticket.session_ticket,
        "<SessionKey>%s</SessionKey>" % ticket.session_key,
        "<SessionId>%d</SessionId>" % account.account_id,
        "<CloudKey>%s</CloudKey>" % cloud_key,
        "<PublicIp>%s</PublicIp>" % host_name,
        "<PosixTime>%d</PosixTime>" % ahora,
        "<Region>us</Region>",
        "<PlayerAccountId>%d</PlayerAccountId>" % account.account_id,
        "<IsSubAccount>0</IsSubAccount>",
        # Workaround, not protocol: this tells the client to ignore the
        # response-header HMAC. Without it every post-ticket response is
        # rejected. See EMU_SECURITY_FLAGS_OFF.
        "<DisabledSecurityFlags>%s</DisabledSecurityFlags>" % flags_off,
        "<RockstarId>%d</RockstarId>" % account.account_id,
        "<Nickname>%s</Nickname>" % account.nickname,
        "<RockstarAccount>",
        "<RockstarId>%d</RockstarId>" % account.account_id,
        "<Nickname>%s</Nickname>" % account.nickname,
        "<Email>%s</Email>" % account.email,
        "<CountryCode>MX</CountryCode>",
        "<LanguageCode>es</LanguageCode>",
        "<AvatarUrl></AvatarUrl>",
        "<Age>18</Age>",
        "<ZipCode></ZipCode>",
        "</RockstarAccount>",
        # The privilege mask is built from the TEXT of `<Privileges>`: it is
        # split on commas, each piece parsed as an integer and bit `1 << id`
        # set for every id below 28. With an empty text the mask stays 0 and
        # the client closes the session. Nesting `<Privs>` inside is NOT valid:
        # a node with children stops exposing text and the ticket parsing
        # fails, so they go as siblings.
        "<Privileges Count=\"%d\">%s</Privileges>"
        % (len(PRIVILEGES), ",".join(str(i) for i in PRIVILEGES)),
    ] + ['<Privs id="%d">true</Privs>' % i for i in PRIVILEGES] + [
    ] + service_list(host_efectivo) + ssl_service_list(host_efectivo) + [
        "</Result>",
        "</Response>",
    ]
    return 200, "\n".join(partes).encode("utf-8")


def create_sc_auth_token(req: RosRequest):
    """Exchange the ticket for a Social Club token (the one the website uses)."""
    return 200, {
        "Status": 1,
        "ScAuthToken": base64.b64encode(os.urandom(16)).decode(),
        "RockstarId": req.session.account_id,
    }


def create_sc_auth_token_result(req: RosRequest):
    """First post-ticket call: the token exchange.

    The client calls it after the ticket with ``ticket``, ``audience="Game"``,
    ``ttlminutes=43200`` and ``userdata=""``. Its success handler looks for a
    ``Result`` child and copies its TEXT into a 256-byte buffer, so the answer
    has to be ``<Response>`` with ``<Status>1</Status>`` and the token as the
    direct text of ``<Result>`` — not as a separate field.
    """
    token = base64.b64encode(os.urandom(16)).decode()
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>'
        "<Response><Status>1</Status><Result>%s</Result></Response>" % token
    )
    return 200, xml.encode("utf-8")


def create_p2p_certificate(req: RosRequest):
    """Certificate for peer-to-peer connections (this server hosts no matches)."""
    account = req.account
    return 200, {
        "Status": 1,
        "Certificate": base64.b64encode(os.urandom(96)).decode(),
        "RockstarId": account.account_id,
        "HostAddress": "127.0.0.1",
        "HostPort": 61455,
    }


def get_account_info(req: RosRequest):
    account = req.account
    if account is None:
        return 404, {"Status": 0, "Error": "AccountNotFound"}
    # Kept aligned with the ticket's RockstarAccount block. The fields below
    # are the ones the client's parser expects.
    return 200, {
        "Status": 1,
        "RockstarAccount": {
            "RockstarId": account.account_id,
            "Nickname": account.nickname,
            "Email": account.email,
            "CountryCode": "MX",
            "LanguageCode": "es",
            "Age": 18,
            "AvatarUrl": "",
            "Dob": "",
            "IsApproxDob": "0",
            "LastPortalLoginDate": "",
            "Platform": account.platform,
        },
    }


def read_all_stats(req: RosRequest):
    account = req.account
    return 200, {
        "Status": 1,
        "ProfileStats": {
            "RockstarId": account.account_id,
            "Rank": account.rank,
            "Cash": account.cash,
            "Bank": account.bank,
            "PlayTime": "0d 0h 14m",
        },
    }


def presence_query(req: RosRequest):
    caller = req.session.account_id
    records = []
    seen = {caller}
    for ticket in req.store.online_tickets():
        if ticket.account_id in seen:
            continue
        account = req.store.account(ticket.account_id)
        if account is None:
            continue
        seen.add(account.account_id)
        records.append(
            {
                "RockstarId": account.account_id,
                "Nickname": account.nickname,
                "Platform": account.platform,
                "Session": ticket.session_ticket[:8],
            }
        )
    return 200, {"Status": 1, "Presence": records}


def presence_multi_post(req: RosRequest):
    target = req.param("to")
    if not target.isdigit():
        return 400, {"Status": 0, "Error": "InvalidRecipient"}
    req.store.invites.append(
        {
            "from": req.session.account_id,
            "to": int(target),
            "kind": req.param("kind", "FreeRoam"),
            "sent_at": time.time(),
        }
    )
    return 200, {"Status": 1, "Invites": len(req.store.invites)}


def presence_get_servers(req: RosRequest):
    """Presence server list (the online session).

    The success handler reads ``Count`` and ``IsSecure`` as ATTRIBUTES of
    ``<Result>``, and ``Host``, ``IsSecure`` and ``IsXblSg`` as ATTRIBUTES of
    each ``<Server>``. They are not child elements: sent as elements, Count
    ends up 0 and the list empty even though the task finishes fine.

    This machine is announced, and it is also the one answering peer-to-peer
    traffic (the P2P certificate call already returns port 61455).

    With ``IsSecure=0`` every task publishes OK; with ``IsSecure=1`` the client
    demands TLS on 61455, where only plain TCP listens. Default 0, and
    ``EMU_PRESENCE_SECURE=1`` is left for the day a TLS relay exists.
    """
    secure = os.environ.get("EMU_PRESENCE_SECURE", "0")
    host = (req.headers.get("Host") or "").split(":")[0] or "127.0.0.1"
    # Empty list with `EMU_PRESENCE_SERVER=0`; the engine still reports the
    # game services as unavailable in that case.
    if os.environ.get("EMU_PRESENCE_SERVER", "1") == "0":
        xml = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<Response><Status>1</Status>'
            '<Result Count="0" IsSecure="%s" />'
            "</Response>" % secure
        )
        return 200, xml.encode("utf-8")
    # Count="32" is the loop limit over the children of <Result>; a single
    # <Server> is enough. IsXblSg="0" counts, "1" does not.
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<Response><Status>1</Status>'
        '<Result Count="32" IsSecure="%s">'
        '<Server Host="%s:61455" IsSecure="%s" IsXblSg="0" />'
        "</Result></Response>" % (secure, host, secure)
    )
    return 200, xml.encode("utf-8")


def presence_replace_attributes(req: RosRequest):
    """Presence.asmx: publish player attributes. Nothing to publish here."""
    return _simple_response("1")


def presence_set_attributes(req: RosRequest):
    """Presence.asmx/SetAttributes: the game publishes its session attributes.

    The format of the acknowledgement is not derived from the client yet; a
    plain success is returned so the call does not fail.
    """
    return _simple_response("1")


def socialclub_check_text(req: RosRequest):
    """Text validation (character names, free text).

    Without this route the client treats the text as inappropriate and rejects
    the name. A plain success is returned; the exact response format has not
    been derived yet.
    """
    return _simple_response("1")


def ugc_query_content(req: RosRequest):
    """User generated content listing. Nothing stored: success with no results."""
    return 200, ('<?xml version="1.0" encoding="utf-8"?>'
                 '<Response><Status>1</Status>'
                 '<Results></Results></Response>').encode("utf-8")


def clans_get_invites(req: RosRequest):
    """Clans.asmx: the parser expects <Invites count MaxCount> under <Response>."""
    return 200, ('<?xml version="1.0" encoding="utf-8"?>'
                 '<Response><Status>1</Status>'
                 '<Invites count="0" MaxCount="0"></Invites></Response>').encode("utf-8")


# Last announced session blob (base64). Advertise stores it and Find returns
# it: the game announces a session and then looks for sessions, so an empty
# Find leaves it waiting. The blob is whatever the client sent, never invented.
LAST_SESSION_BLOB = ""
# Last MatchId returned by Advertise (a UUID). Its parser looks for a
# <MatchId> child and parses it as a GUID; without a valid one the parser fails
# and the session is not considered created.
LAST_MATCH_ID = ""


def matchmaking_find(req: RosRequest):
    """matchmaking.asmx/Find.

    The success handler looks for a ``<Results>`` child of ``<Response>``;
    without it Find fails. Each session inside ``<Results>`` carries a
    ``<Data>`` child with the base64 session blob (up to 125 decoded bytes).
    The layout of that blob is not mapped yet.

    An empty ``<Results/>`` is success with zero sessions, which is what a
    solo game needs. If a session was announced (Advertise stored its blob),
    Find returns it so the game sees its own session and can join.
    """
    global LAST_SESSION_BLOB
    if LAST_SESSION_BLOB:
        return 200, ('<?xml version="1.0" encoding="utf-8"?>'
                     '<Response><Status>1</Status>'
                     '<Results><Session><Data>' + LAST_SESSION_BLOB +
                     '</Data></Session></Results></Response>').encode("utf-8")
    return 200, ('<?xml version="1.0" encoding="utf-8"?>'
                 '<Response><Status>1</Status>'
                 '<Results></Results></Response>').encode("utf-8")


def matchmaking_advertise(req: RosRequest):
    """matchmaking.asmx/Advertise: the game announces (hosts) a session.

    Request fields: numSlots, availableSlots and attrsJson (game mode,
    discriminator, aim type, region, activity ids and the session Data blob in
    base64).

    Response format derived from the client: the success handler looks for a
    ``<MatchId>`` child and parses it as a GUID with
    ``sscanf("%08lx-%04hx-%04hx-%02hx%02hx-%02hx%02hx%02hx%02hx%02hx%02hx")``
    (11 fields). A missing or malformed MatchId makes the parser fail and the
    game does not consider the session created. The UUID is returned both under
    ``<Response>`` and inside ``<Result>`` so it is found whichever node the
    parser receives.

    The Data blob the game sends is the serialization of its session; Advertise
    keeps it so Find can return it afterwards.
    """
    global LAST_SESSION_BLOB, LAST_MATCH_ID
    try:
        attrs = json.loads(req.param("attrsJson") or "{}")
        data = attrs.get("Data") or ""
        if data:
            LAST_SESSION_BLOB = data
    except Exception:
        pass
    LAST_MATCH_ID = str(uuid.uuid4())
    return 200, ('<?xml version="1.0" encoding="utf-8"?>'
                 '<Response><Status>1</Status>'
                 '<MatchId>' + LAST_MATCH_ID + '</MatchId>'
                 '<Result><MatchId>' + LAST_MATCH_ID + '</MatchId></Result>'
                 '</Response>').encode("utf-8")


def matchmaking_unadvertise(req: RosRequest):
    """matchmaking.asmx/Unadvertise: the client stops announcing a session."""
    global LAST_SESSION_BLOB, LAST_MATCH_ID
    LAST_SESSION_BLOB = ""
    LAST_MATCH_ID = ""
    return _simple_response("1")


def clans_get_mine(req: RosRequest):
    """Clans.asmx: the parser expects <Memberships Count MaxCount> under <Response>."""
    return 200, ('<?xml version="1.0" encoding="utf-8"?>'
                 '<Response><Status>1</Status>'
                 '<Memberships Count="0" MaxCount="0"></Memberships></Response>').encode("utf-8")


def _simple_response(inner: str):
    """``<Response><Status>1</Status><Result>...</Result></Response>``."""
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>'
        "<Response><Status>1</Status><Result>%s</Result></Response>" % inner
    )
    return 200, xml.encode("utf-8")


# --- routes the client asks for right after login ----------------------
# These used to 404. They all arrive authenticated and none of them stops the
# login when it fails, but without them the log fills with errors and the port
# does not reach the screens depending on that data (friends, entitlements,
# inbox).


def get_accepted_version(req: RosRequest):
    """legalpolicies.asmx: accepted version of the terms.

    The success handler compares the root node name with "Version" and, if it
    does not match, walks ONLY the DIRECT children of the root. It then reads
    the text with ``sscanf("%d")`` and stores a 16-bit integer.

    Returning ``<Result><Version>1</Version></Result>`` (a grandchild) made the
    walk miss it and the client showed a policy download error.
    """
    # 0 = "not accepted": that leaves the policy state at 4 (asking for
    # acceptance) instead of 5. With matching versions the menu takes the
    # branch that requires the documents to be on disk and, if the policy
    # manager reports an error, shows the download-failed warning. With 4 the
    # client asks the player to accept, which is the path that works.
    return 200, ('<?xml version="1.0" encoding="utf-8"?>'
                 '<Response><Status>1</Status><Version>0</Version>'
                 '</Response>').encode("utf-8")


def get_password_requirements(req: RosRequest):
    return _simple_response(
        "<MinLength>8</MinLength><MaxLength>32</MaxLength>"
        "<RequiresNumbers>0</RequiresNumbers>"
        "<RequiresLetters>0</RequiresLetters>"
        "<ValidSymbols>!@#$%^*()_+-=[]{}|;:,./?</ValidSymbols>"
    )


def get_friends(req: RosRequest):
    """Friends.asmx: no friends (single-user server)."""
    return _simple_response('<Friends Count="0" Total="0"></Friends>')


def get_entitlements(req: RosRequest):
    """entitlements.asmx: the parser expects <Entitlements> under <Response>."""
    return 200, ('<?xml version="1.0" encoding="utf-8"?>'
                 '<Response><Status>1</Status>'
                 '<Entitlements></Entitlements></Response>').encode("utf-8")


def unadvertise_all(req: RosRequest):
    """matchmaking.asmx: the client stops announcing all its sessions."""
    global LAST_SESSION_BLOB, LAST_MATCH_ID
    LAST_SESSION_BLOB = ""
    LAST_MATCH_ID = ""
    return _simple_response("1")


def get_telemetry_client_config(req: RosRequest):
    """Telemetry.asmx: the parser expects <IsTelemetryEnabled> under <Response>.

    The task reports an error when the received node has no children or when
    the telemetry config object does not exist yet, so the answer keeps the
    fields as direct children in alphabetical order (a binary-search branch in
    the parser assumes that order).
    """
    return 200, ('<?xml version="1.0" encoding="utf-8"?>'
                 '<Response>'
                 '<IsTelemetryEnabled>0</IsTelemetryEnabled>'
                 '<Path></Path><RawConfig></RawConfig>'
                 '<Status>1</Status></Response>').encode("utf-8")


def read_stats_by_gamer2(req: RosRequest):
    """ProfileStats.asmx: player stats / by groups (mode 0, big-endian values).

    The body has to be wrapped in ``<Response><Status>1</Status><Result>...``
    or the client's SAX reader is never called and the task ends in error. The
    ``gh`` attribute must match what the client sends in ``gamerHandles``
    ("SC 2"). The two requested stats are 4-byte values, so base64
    ``AAAAAAAAAAA=``. The exact stat list of the group modes is not resolved
    yet, so a single complete record is returned.
    """
    envolver = os.environ.get("EMU_STATS_WRAP", "1") == "1"
    if "readstatsbygroups" in req.path.lower():
        # An empty <values> registers nothing and the task needs at least one
        # parsed record to succeed. A record is id (u32 BE) + type (u8) +
        # value (4 or 8 bytes), so a short blob is truncated and does not
        # count. A full record is sent by default; EMU_GROUPS_B64 overrides it.
        registro = os.environ.get("EMU_GROUPS_B64", "AAAAAAMAAAAA")   # id=0 t=3 v=0
        cuerpo = "<values>%s</values>" % registro
    else:
        cuerpo = '<results><r gh="SC 2">AAAAAAAAAAA=</r></results>'
    if envolver:
        xml = (
            '<?xml version="1.0" encoding="utf-8"?>'
            "<Response><Status>1</Status><Result>%s</Result></Response>" % cuerpo
        )
    else:
        xml = '<?xml version="1.0" encoding="utf-8"?>' + cuerpo
    return 200, xml.encode("utf-8")


def legal_territory_restrictions(req: RosRequest):
    """CashTransactions.asmx: no territory restrictions.

    The success handler walks the siblings of the result node looking for a
    child named ``restrictions``. When it is missing the task fails; when it
    exists and no restrictions were requested it succeeds without reading
    anything else. The request arrives with an empty country code, so an empty
    ``restrictions`` root is answered.
    """
    return 200, (
        '<?xml version="1.0" encoding="utf-8"?>'
        "<Response><Status>1</Status><restrictions></restrictions></Response>"
    ).encode("utf-8")


def write_stats(req: RosRequest):
    """ProfileStats.asmx/WriteStats: the client uploads stats on enter/exit.

    The task walks the siblings of the received root looking for three DIRECT
    children (ignoring any ``ns:`` prefix), each parsed as an integer:

      * ``NumWritten``
      * ``SecsUntilNextWrite``
      * ``MaxSubmissionBinarySize``

    It succeeds only when all three parse. ``SecsUntilNextWrite`` must not be
    0: the client multiplies it by 1000 to set the flush interval and a zero
    interval turns the "can synchronise" flag off right after the response,
    which sends the client back to the services-unavailable message in a loop.
    """
    return 200, (
        '<?xml version="1.0" encoding="utf-8"?>'
        "<Response><Status>1</Status>"
        "<NumWritten>1</NumWritten>"
        "<SecsUntilNextWrite>300</SecsUntilNextWrite>"
        "<MaxSubmissionBinarySize>65536</MaxSubmissionBinarySize>"
        "</Response>"
    ).encode("utf-8")


def reset_stats(req: RosRequest):
    """ProfileStats.asmx/ResetStats: the game resets the stats of a group.

    Asked for when the downloaded save is considered damaged and the client
    wants to start the group from scratch. The response format is not derived
    from the client yet; a minimal acknowledgement is returned.
    """
    return 200, ('<?xml version="1.0" encoding="utf-8"?>'
                 '<Response><Status>1</Status></Response>').encode("utf-8")


def inbox_get_messages(req: RosRequest):
    """Inbox.asmx: the parser expects <Messages Count Total> under <Response>."""
    return 200, ('<?xml version="1.0" encoding="utf-8"?>'
                 '<Response><Status>1</Status>'
                 '<Messages Count="0" Total="0"></Messages></Response>').encode("utf-8")


def inbox_get_unread(req: RosRequest):
    """Inbox.asmx: the parser expects <Messages Count Total> under <Response>."""
    return 200, ('<?xml version="1.0" encoding="utf-8"?>'
                 '<Response><Status>1</Status>'
                 '<Messages Count="0" Total="0"></Messages></Response>').encode("utf-8")


def get_location_info_from_ip(req: RosRequest):
    """GeoLocation.asmx: client location **and the session relays**.

    The success handler looks for ``LocInfo`` and ``RelaysList`` as DIRECT
    children of ``<Response>``. Inside them, ``RegionCode``/``CountryCode``/
    ``Latitude``/``Longitude`` and ``Count``/``IsSecure``/``Host``/``IsXblSg``
    are XML ATTRIBUTES, not elements: as elements the task succeeds but the
    relay list ends up empty.
    """
    if "EMU_RELAY_HOST" in os.environ:
        host = os.environ["EMU_RELAY_HOST"].strip()
    else:
        host = ((req.headers.get("Host") or "").split(":")[0] or "127.0.0.1") + ":61455"
    relays = (
        '<RelaysList Count="1" IsSecure="0"><Relay Host="%s" '
        'IsSecure="0" IsXblSg="0" /></RelaysList>' % host
        if host
        else '<RelaysList Count="0" IsSecure="0" />'
    )
    inner = (
        '<LocInfo RegionCode="us" CountryCode="MX" '
        'Latitude="19.4326" Longitude="-99.1332" />'
        "%s" % relays
    )
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>'
        "<Response><Status>1</Status>%s</Response>" % inner
    )
    return 200, xml.encode("utf-8")


def get_pack_value_usde(req: RosRequest):
    """CashTransactions.asmx: the parser expects <ItemList count> under <Response>."""
    return 200, ('<?xml version="1.0" encoding="utf-8"?>'
                 '<Response><Status>1</Status>'
                 '<ItemList count="0"></ItemList></Response>').encode("utf-8")


# Attempt counter for the save-migration status call (diagnostics only).
_SM_ATTEMPT = itertools.count(1)


def save_migration_status(req: RosRequest):
    """SaveMigration.asmx: nothing to migrate.

    The engine asks for this when entering online and, if it fails, stops with
    a message saying the saved data could not be loaded from the cloud.

    The success handler looks inside ``<Result>`` for:

      * ``<TransactionId>`` — mandatory integer (missing node fails the task);
      * ``<InProgress>``    — integer, must be 0 or 1;
      * ``<State>``         — free text stored as-is.

    With ``InProgress=0`` and ``TransactionId=0`` the client understands there
    is no migration in progress or pending, which is correct here: the cloud
    layer of this server owns the save.

    Each response is numbered in the log to tell "the same operation retries"
    apart from "the player entered several times":

        [save-migration] attempt=3 txn=0 inProgress=0 state=false

    Values can be changed without editing code through ``EMU_SM_INPROGRESS``
    (0/1), ``EMU_SM_STATE`` (free text) and ``EMU_SM_TXN`` (integer).
    """
    intento = next(_SM_ATTEMPT)
    txn = os.environ.get("EMU_SM_TXN", "0")
    en_curso = os.environ.get("EMU_SM_INPROGRESS", "0")
    estado = os.environ.get("EMU_SM_STATE", "false")
    print("[save-migration] attempt=%d txn=%s inProgress=%s state=%s"
          % (intento, txn, en_curso, estado), flush=True)
    return _simple_response(
        "<TransactionId>%s</TransactionId>"
        "<InProgress>%s</InProgress>"
        "<State>%s</State>" % (txn, en_curso, estado)
    )


ROUTES: Dict[Tuple[str, str], Handler] = {
    ("auth", "createticketsc3"): create_ticket_sc3,
    ("auth", "createticketscauthtoken2"): create_sc_auth_token,
    ("auth", "createscauthtoken"): create_sc_auth_token_result,
    ("auth", "createp2pcertificate"): create_p2p_certificate,
    ("socialclub", "getaccountinfo"): get_account_info,
    ("socialclub", "getscauthtoken"): create_sc_auth_token,
    ("socialclub", "createscauthtoken"): create_sc_auth_token_result,
    ("socialclub", "checktext"): socialclub_check_text,
    ("ugc", "checktext"): socialclub_check_text,
    ("ugc", "querycontent"): ugc_query_content,
    ("socialclub", "readallstats"): read_all_stats,
    ("profilestats", "readallstats"): read_all_stats,
    ("presence", "querywithmaxrecordlength"): presence_query,
    ("presence", "multipostmessage"): presence_multi_post,
    ("presence", "getpresenceservers"): presence_get_servers,
    ("presence", "replaceattributes"): presence_replace_attributes,
    ("presence", "setattributes"): presence_set_attributes,
    ("clans", "getinvites"): clans_get_invites,
    ("matchmaking", "find"): matchmaking_find,
    ("matchmaking", "advertise"): matchmaking_advertise,
    ("matchmaking", "unadvertise"): matchmaking_unadvertise,
    ("matchmaking", "unadvertiseall"): unadvertise_all,
    ("clans", "getmine"): clans_get_mine,
    ("legalpolicies", "getacceptedversion"): get_accepted_version,
    ("legalpolicies", "getversions"): get_accepted_version,
    ("socialclub", "getpasswordrequirements"): get_password_requirements,
    ("friends", "getfriends"): get_friends,
    ("entitlements", "getentitlements"): get_entitlements,
    ("telemetry", "gettelemetryclientconfig"): get_telemetry_client_config,
    ("profilestats", "readstatsbygamer2"): read_stats_by_gamer2,
    # Asked for after the ticket; the "my stats" answer works for the player
    # group too.
    ("profilestats", "readstatsbygroups"): read_stats_by_gamer2,
    ("profilestats", "writestats"): write_stats,
    ("profilestats", "resetstats"): reset_stats,
    ("inbox", "getmessages"): inbox_get_messages,
    ("inbox", "getunreadmessages"): inbox_get_unread,
    ("geolocation", "getlocationinfofromip"): get_location_info_from_ip,
    ("cashtransactions", "getpackvalueusde"): get_pack_value_usde,
    ("cashtransactions", "getlegalterritoryrestrictions"): legal_territory_restrictions,
    ("savemigration", "getsavemigrationstatus"): save_migration_status,
    ("savemigration", "getsavemigrationtransactionstatus"): save_migration_status,
}

PUBLIC: Set[Tuple[str, str]] = {("auth", "createticketsc3")}
class RosApp:
    def __init__(self, store: Store, crypto: RosCrypto) -> None:
        self.store = store
        self.crypto = crypto
        self.routes = ROUTES
        self.public = PUBLIC
        self.panel = Panel(store, crypto, ROUTES)
        self.launcher = Launcher(store, crypto)
        # Cloud services: tunables, availability check and the online character
        # save. Without them the client reports the cloud as unavailable.
        self.cloud = Cloud()
        # Optional hook (--hmac-verifier): when set, _authenticate uses that
        # verifier instead of the scheme in crypto.py.
        self.hmac_verifier = None


class RosHTTPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "online-emu/0.1"

    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def _read_body_bytes(self) -> bytes:
        """Request body, including ``Transfer-Encoding: chunked``.

        The game client sends POST bodies chunked (the encrypted body goes in a
        single chunk) and ``http.server`` does not decode it: those bytes stay
        in the socket and break the next request with a malformed syntax error.
        """
        if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            cuerpo = bytearray()
            while True:
                linea = self.rfile.readline(65536).strip()
                if not linea:
                    break
                try:
                    tam = int(linea.split(b";")[0], 16)
                except ValueError as exc:
                    raise ValueError("invalid chunk: %r" % linea) from exc
                if tam == 0:
                    # Optional trailer: discarded up to the empty line that
                    # closes the request.
                    while True:
                        resto = self.rfile.readline(65536)
                        if resto in (b"\r\n", b"\n", b""):
                            break
                    break
                cuerpo += self.rfile.read(tam)
                self.rfile.read(2)  # CRLF closing the chunk
            return bytes(cuerpo)
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _dispatch(self, method: str) -> None:
        app: RosApp = self.server.app
        parsed = urlparse(self.path)
        try:
            raw_bytes = self._read_body_bytes()
        except ValueError as exc:
            self._log("[online-emu] invalid chunked body: %s" % exc)
            self._send_xml(400, {"Status": 0, "Error": "BadChunkedBody"})
            return

        # Context for the pluggable codec (``--body-codec``). Built always
        # because the response path uses it too; with no codec nothing changes.
        codec = getattr(app, "codec", NULL_CODEC)
        session_header = self.headers.get("ros-SessionTicket") or ""
        codec_ctx = CodecContext(
            method=method,
            path=parsed.path,
            headers={key.lower(): value for key, value in self.headers.items()},
            raw=raw_bytes,
            ticket=app.store.get_ticket(session_header) if session_header else None,
            store=app.store,
        )
        is_asmx = ROUTE_RE.match(parsed.path) is not None
        if is_asmx:
            # Contract diagnostics: headers exactly as the game sends them.
            self._log("[online-emu] REQ %s %s" % (method, parsed.path))
            for nombre, valor in self.headers.items():
                self._log("[online-emu]     H %s: %s" % (nombre, valor))
            if raw_bytes:
                self._log(
                    "[online-emu]     raw body (%d B): %s"
                    % (len(raw_bytes), raw_bytes.hex())
                )
        if is_asmx and raw_bytes and not self.headers.get("ros-Encrypted-Body"):
            # The codec only handles bodies that did not come through the
            # server's own body encryption, so the two paths never overlap.
            raw_bytes = codec.decode(raw_bytes, codec_ctx)

        # Encrypted body (opt-in with ``ros-Encrypted-Body: 1``). The key comes
        # from the session ticket, so the ticket is resolved *before* decrypting.
        body_session = None
        if raw_bytes and (self.headers.get("ros-Encrypted-Body") or "") == "1":
            session_ticket = self.headers.get("ros-SessionTicket") or ""
            if session_ticket:
                body_session = app.store.get_ticket(session_ticket)
            if body_session is None:
                self._send_xml(401, {"Status": 0, "Error": "NotAuthenticated"})
                return
            raw_bytes = app.crypto.decrypt_body(raw_bytes, body_session.session_key)

        raw = raw_bytes.decode("utf-8", "replace")

        params: Dict[str, str] = {}
        for key, values in parse_qs(raw, keep_blank_values=True).items():
            params.setdefault(key, values[0])
        for key, values in parse_qs(parsed.query, keep_blank_values=True).items():
            params.setdefault(key, values[0])

        body_json: dict = {}
        if raw and "json" in (self.headers.get("Content-Type") or "").lower():
            try:
                loaded = json.loads(raw)
                if isinstance(loaded, dict):
                    body_json = loaded
            except Exception:
                body_json = {}

        # -- cloud services: tunables and character save -------------------
        # `/cloud/<n>/cloudservices/...` is not an `.asmx` route: it is served
        # separately and without a ticket in the body.
        if parsed.path.startswith("/cloud/"):
            respuesta = app.cloud.dispatch(method, parsed.path, raw_bytes)
            if respuesta is not None:
                status, tipo, payload = respuesta
                self._log(
                    "[online-emu] cloud %s %s -> %d (%d B)"
                    % (method, parsed.path, status, len(payload))
                )
                for nombre in ("ros-SecurityFlags", "ros-Challenge"):
                    valor = self.headers.get(nombre)
                    if valor:
                        self._log("[online-emu] cloud     H %s: %s" % (nombre, valor))
                # Response filtering applies to everything coming from this
                # host: a 20-byte-plus body that is not the expected container
                # is discarded and the client asks again. Sealing them like an
                # .asmx response avoids that loop. Bodies under 20 bytes pass
                # untouched. `EMU_CLOUD_PLAIN=1` serves them unsealed again.
                if (
                    status == 200
                    and len(payload) >= 20
                    and os.environ.get("EMU_CLOUD_PLAIN") != "1"
                ):
                    sellado, extra = codec.encode(payload, codec_ctx)
                    if sellado != payload:
                        extra = dict(extra or {})
                        tipo = extra.pop("Content-Type", tipo)
                        self._log(
                            "[online-emu] cloud %s %s -> sealed %d B (clear %d B)"
                            % (method, parsed.path, len(sellado), len(payload))
                        )
                        self._write(status, tipo, sellado, extra)
                        return
                self._write(status, tipo, payload)
                return

        # -- JSON API for the port client (gwsc) --------------------------
        if parsed.path.startswith("/gwsc/api/"):
            subpath = parsed.path[len("/gwsc/api/"):]
            auth = self.headers.get("Authorization") or ""
            if auth:
                self._log("[online-emu] gwsc %s %s auth=%s" % (method, parsed.path, auth[:22]))
            status, payload = app.launcher.dispatch(method, subpath, body_json, params, self.headers)
            self._send_json(status, payload)
            return

        # -- web panel ----------------------------------------------------
        if parsed.path in ("/", "/panel", "/index.html"):
            self._send_html(200, PANEL_PAGE)
            return

        if parsed.path.startswith("/panel/api/"):
            subpath = parsed.path[len("/panel/api/"):]
            status, payload, extra = app.panel.dispatch(method, subpath, params, self.headers)
            self._send_json(status, payload, extra)
            return

        if parsed.path == "/health":
            self._send_xml(200, {"Status": 1, "Service": "online-emu", "Routes": len(app.routes)})
            return

        # -- .asmx services -----------------------------------------------
        match = ROUTE_RE.match(parsed.path)
        if not match:
            self._trace_request(raw, raw_bytes)
            self._send_xml(404, {"Status": 0, "Error": "UnknownRoute", "Path": parsed.path})
            return

        service = match.group("service").lower()
        name = match.group("method").lower()
        handler = app.routes.get((service, name))
        if handler is None:
            self._trace_request(raw, raw_bytes)
            self._send_xml(
                404,
                {"Status": 0, "Error": "UnknownMethod", "Service": service, "Method": name},
            )
            return

        req = RosRequest(app.store, app.crypto, method, parsed.path, params, self.headers)
        if service == "auth" and name == "createticketsc3":
            self._trace_request(raw, raw_bytes)
        if (service, name) not in app.public:
            req.session = self._authenticate(app, method, parsed.path, params)
            if req.session is None:
                self._send_xml(401, {"Status": 0, "Error": "NotAuthenticated"})
                return
            app.store.touch(req.session)

        status, body = handler(req)
        if body_session is not None:
            # If the client encrypted the request it expects the response
            # encrypted the same way.
            self._send_encrypted_xml(status, body, body_session.session_key)
        else:
            self._send_via_codec(status, body, codec_ctx, codec)

    def _authenticate(self, app: RosApp, method: str, path: str, params=None):
        session_ticket = self.headers.get("ros-SessionTicket", "")
        if not session_ticket and params:
            # The real client does not send the header: it puts the ticket in
            # the body (the token exchange sends `ticket=<the ticket one>`).
            session_ticket = (params.get("ticket") or "").strip()
            if session_ticket:
                self._log("[online-emu] ticket taken from body (%d chars)" % len(session_ticket))
        challenge_b64 = self.headers.get("ros-Challenge", "")
        # The desktop client sends "ros-HeadersHmac"; the bundled test client
        # sends "ros-Hmac". Both are accepted.
        signature = (
            self.headers.get("ros-Hmac", "")
            or self.headers.get("ros-HeadersHmac", "")
        )
        # The security flags are whatever the client sent on THIS request: the
        # MAC is signed with that value, not with a fixed one. The ticket call
        # carries no header, so the default applies there.
        flags_header = (self.headers.get("ros-SecurityFlags") or "").strip()
        if flags_header:
            self._log("[online-emu] ros-SecurityFlags: %s" % flags_header)
        security_flags = (flags_header or "239").encode("utf-8")
        if not (session_ticket and challenge_b64 and signature):
            return None
        # ``find_ticket`` accepts both the session ticket (header) and the long
        # service ticket sent in the body.
        ticket = app.store.find_ticket(session_ticket)
        if ticket is None:
            self._log("[online-emu] unknown ticket: %s" % (session_ticket[:24] or "<empty>"))
            return None
        try:
            challenge = base64.b64decode(challenge_b64)
        except Exception:
            return None
        verifier = getattr(app, "hmac_verifier", None)
        if verifier is not None:
            # --hmac-verifier hook: the real verifier compares against the
            # client's platform key. There is no fallback on purpose: a silent
            # fallback would hide a key mismatch.
            try:
                ok = verifier.verify(
                    signature,
                    method,
                    path,
                    ticket.session_ticket,
                    challenge,
                    ticket.session_key,
                    security_flags,
                )
            except TypeError:
                # Older verifiers without the security_flags parameter.
                ok = verifier.verify(
                    signature,
                    method,
                    path,
                    ticket.session_ticket,
                    challenge,
                    ticket.session_key,
                )
            except NotImplementedError:
                # ros_crypto.py is a stub in this base: without a scheme no
                # signed request can be accepted.
                self._log("[online-emu] signature scheme not implemented (stub)")
                return None
            if not ok:
                # Diagnostics. The full dump (challenge, tickets, session key
                # and the expected MACs) is opt-in: those values identify a
                # live session, so they never go to the log by default.
                self._log(
                    "[online-emu] HMAC REJECTED %s %s flags=%s"
                    % (method, path, security_flags.decode("utf-8", "replace"))
                )
                if os.environ.get("EMU_DEBUG_HMAC") == "1":
                    self._dump_hmac_debug(verifier, method, path, ticket, challenge,
                                          challenge_b64, signature, security_flags)
                else:
                    self._log(
                        "[online-emu]     hmac=%s... ticket=%s... "
                        "(set EMU_DEBUG_HMAC=1 for the full dump)"
                        % (signature[:12], ticket.session_ticket[:8])
                    )
                return None
            return ticket
        try:
            if not app.crypto.verify(
                signature, method, path, ticket.session_ticket, challenge, ticket.session_key
            ):
                return None
        except NotImplementedError:
            # crypto.py is a stub in this base: without a working scheme no
            # signed request can be accepted.
            self._log("[online-emu] crypto scheme not implemented (stub)")
            return None
        return ticket

    def _dump_hmac_debug(
        self, verifier, method, path, ticket, challenge, challenge_b64, signature,
        security_flags,
    ) -> None:
        """Offline reproduction data for a rejected signature (opt-in).

        Everything needed to rebuild the MAC outside the server: the received
        one, the challenge, the ticket's session values and, when the verifier
        exposes ``headers_hmac``, the expected values for the layouts known so
        far. Enable it with ``EMU_DEBUG_HMAC=1`` only while researching.
        """
        self._log("[online-emu]     client hmac : %s" % signature)
        try:
            from online_emu.ros_crypto import HEADERS_HMAC_FLAGS

            firmador = getattr(getattr(verifier, "crypto", None), "headers_hmac", None)
            if firmador is None:
                raise RuntimeError("the verifier does not expose headers_hmac")
            for etiqueta, clave, stk, flags in (
                ("title (no session)", "", "", security_flags),
                ("session+header", ticket.session_key, ticket.session_ticket, security_flags),
                ("session+239", ticket.session_key, ticket.session_ticket, HEADERS_HMAC_FLAGS),
            ):
                valor = base64.b64encode(
                    firmador(challenge, method, path, clave, stk, security_flags=flags)
                ).decode()
                self._log("[online-emu]     expected hmac [%s]: %s" % (etiqueta, valor))
        except Exception as exc:  # noqa: BLE001 (diagnostics only)
            self._log("[online-emu]     expected hmac: <not computable: %s>" % exc)
        self._log("[online-emu]     challenge    : %s" % challenge_b64)
        self._log("[online-emu]     ticket       : %s" % ticket.session_ticket)
        self._log("[online-emu]     session_key  : %s" % ticket.session_key)
        for nombre, valor in self.headers.items():
            if nombre.lower().startswith("ros-"):
                self._log("[online-emu]     %s: %s" % (nombre, valor))

    def handle_one_request(self) -> None:
        try:
            super().handle_one_request()
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, ssl.SSLError):
            # The client hung up: not a server error, keep the log clean.
            self.close_connection = True

    # -- responses -------------------------------------------------------
    @staticmethod
    def _log(text: str) -> None:
        """Print without dying when the console cannot encode the bytes."""
        text = "[%s] %s" % (time.strftime("%H:%M:%S"), text)
        try:
            print(text, flush=True)
        except UnicodeEncodeError:
            print(text.encode("ascii", "backslashreplace").decode("ascii"), flush=True)
        # Copy to a file when EMU_LOG_FILE is set: the terminal scrolls and the
        # interesting windows get lost.
        ruta = os.environ.get("EMU_LOG_FILE", "")
        if ruta:
            try:
                with open(ruta, "a", encoding="utf-8", errors="replace") as fh:
                    fh.write(text + "\n")
            except OSError:
                pass

    def _trace_request(self, raw: str, raw_bytes: bytes = b"") -> None:
        """Dump method, path, headers and body of an unknown request.

        This is what makes the API of a foreign client discoverable.
        """
        self._log("[online-emu] >>> %s %s" % (self.command, self.path))
        for key, value in self.headers.items():
            self._log("[online-emu]     %s: %s" % (key, self._redact(key, value)))
        if raw:
            self._log(
                "[online-emu]     body: %s" % (raw if LOG_COMPLETO else raw[:800])
            )
        if raw_bytes:
            self._log("[online-emu]     body len: %d bytes" % len(raw_bytes))
            cuerpo_hex = raw_bytes.hex() if LOG_COMPLETO else raw_bytes[:256].hex()
            self._log("[online-emu]     body hex: %s" % cuerpo_hex)

    # Header values that identify a live session. They are shortened by
    # default and only shown in full with EMU_DEBUG_HMAC=1.
    SENSITIVE_HEADERS = (
        "ros-sessionticket",
        "ros-hmac",
        "ros-headershmac",
        "ros-challenge",
        "authorization",
        "cookie",
    )

    def _redact(self, name: str, value: str) -> str:
        if name.lower() not in self.SENSITIVE_HEADERS or os.environ.get("EMU_DEBUG_HMAC") == "1":
            return value
        return "%s...(%d chars)" % (value[:8], len(value))

    def _write(self, status: int, content_type: str, payload: bytes, extra=None) -> None:
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            for header, value in (extra or {}).items():
                self.send_header(header, value)
            self.end_headers()
            self.wfile.write(payload)
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, ssl.SSLError):
            self.close_connection = True

    def _send_xml(self, status: int, body: dict) -> None:
        self._write(status, "application/xml; charset=utf-8", render(body))

    def _send_via_codec(self, status: int, body: dict, ctx: CodecContext, codec) -> None:
        """.asmx response through the codec (plain XML when there is none)."""
        xml = body if isinstance(body, bytes) else render(body)
        if "createticketsc3" in (ctx.path or "").lower():
            # Shows exactly what XML the client receives: the only way to
            # iterate on the fields its parser expects. With EMU_LOG_FULL=1 it
            # goes in full; otherwise it is cut at 700 characters.
            respuesta = xml.decode("utf-8", "replace").replace("\n", " ")
            if not LOG_COMPLETO:
                respuesta = respuesta[:700]
            self._log("[online-emu] CreateTicketSc3 response: %s" % respuesta)
        payload, extra = codec.encode(xml, ctx)
        extra = dict(extra or {})
        content_type = extra.pop("Content-Type", "application/xml; charset=utf-8")
        self._write(status, content_type, payload, extra)

    def _send_encrypted_xml(self, status: int, body: dict, session_key: str) -> None:
        """Response with the XML encrypted under the session key."""
        payload = self.server.app.crypto.encrypt_body(render(body), session_key)
        self._write(
            status,
            "application/octet-stream",
            payload,
            {"ros-Encrypted-Body": "1"},
        )

    def _send_json(self, status: int, body: dict, extra=None) -> None:
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self._write(status, "application/json; charset=utf-8", payload, extra)

    def _send_html(self, status: int, page: str) -> None:
        self._write(status, "text/html; charset=utf-8", page.encode("utf-8"))

    def log_message(self, fmt, *args) -> None:
        self._log("[online-emu] " + (fmt % args))


class RosServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, app: RosApp) -> None:
        self.app = app
        super().__init__(address, RosHTTPHandler)


def create_server(
    host: str = "127.0.0.1",
    port: int = 8787,
    store: Optional[Store] = None,
    crypto: Optional[RosCrypto] = None,
    tls_cert: Optional[str] = None,
    tls_key: Optional[str] = None,
    app: Optional[RosApp] = None,
) -> RosServer:
    app = app or RosApp(store or Store(), crypto or RosCrypto.generate())
    server = RosServer((host, port), app)
    if tls_cert and tls_key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=tls_cert, keyfile=tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def lan_addresses() -> list[str]:
    """IPv4 addresses this machine is reachable on from the local network.

    Recomputed on every start on purpose: on most home networks the address
    changes, so the one that matters is today's.
    """
    found: list[str] = []

    def add(ip: str) -> None:
        if not ip or ip.startswith(("127.", "169.254.", "0.")) or ip in found:
            return
        found.append(ip)

    # UDP socket trick: no packet is sent, it only asks the system which source
    # address it would use, which is the active interface one.
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("8.8.8.8", 80))
            add(probe.getsockname()[0])
        finally:
            probe.close()
    except OSError:
        pass

    # Fallbacks for machines with several interfaces.
    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            add(ip)
    except OSError:
        pass

    return found


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Local emulator of the online service layer")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--store", default="accounts.json", help="JSON file used to persist accounts")
    parser.add_argument(
        "--persist-tickets",
        action="store_true",
        help="also persist session tickets (they hold live session keys)",
    )
    parser.add_argument("--tls-cert", default=None, help="PEM certificate to serve HTTPS")
    parser.add_argument("--tls-key", default=None, help="PEM key to serve HTTPS")
    parser.add_argument(
        "--body-codec",
        default=None,
        help="custom body codec: module:Class or file.py:Class",
    )
    parser.add_argument(
        "--hmac-verifier",
        default=None,
        help="header HMAC verifier: module:Class or file.py:Class (see ros_crypto.py)",
    )
    parser.add_argument(
        "--platform-key",
        default="platform.key",
        help="file with your own platform key, created when missing (empty = ephemeral)",
    )
    parser.add_argument(
        "--http-port",
        type=int,
        default=None,
        help="second plain-HTTP port sharing the same state (for the panel)",
    )
    args = parser.parse_args()

    # The Windows console may be cp1252: a stray byte from a client must not
    # kill the handler.
    try:
        sys.stdout.reconfigure(errors="backslashreplace")
        sys.stderr.reconfigure(errors="backslashreplace")
    except Exception:
        pass

    if bool(args.tls_cert) != bool(args.tls_key):
        parser.error("--tls-cert and --tls-key go together")

    # One Store and one RosApp for every listener: if the panel and the port
    # ran in different processes they would not see the same accounts.
    if args.platform_key:
        crypto = RosCrypto.load_or_create(args.platform_key)
    else:
        crypto = RosCrypto.generate()
    app = RosApp(Store(args.store, persist_tickets=args.persist_tickets), crypto)
    app.codec = load_codec(args.body_codec)
    app.hmac_verifier = load_verifier(args.hmac_verifier)
    if app.hmac_verifier is not None:
        print("hmac-verifier: %s" % type(app.hmac_verifier).__name__)
    server = create_server(
        args.host,
        args.port,
        app=app,
        tls_cert=args.tls_cert,
        tls_key=args.tls_key,
    )
    scheme = "https" if args.tls_cert else "http"
    print("online-emu listening on %s://%s:%d" % (scheme, args.host, args.port))

    # When listening on every interface, the useful value is the concrete IP to
    # type on the phone, not "0.0.0.0".
    if args.host in ("0.0.0.0", "", "::"):
        lan = lan_addresses()
    else:
        lan = [args.host]
    if lan:
        print("")
        print("=" * 64)
        print(" server address  ->  %s:%d" % (lan[0], args.port))
        print("   (that goes in the client's \"Server\" field)")
        print(" full url        ->  %s://%s:%d" % (scheme, lan[0], args.port))
        if len(lan) > 1:
            print(
                " other local IPs ->  %s"
                % ", ".join("%s:%d" % (ip, args.port) for ip in lan[1:])
            )
        print("=" * 64)
    else:
        print("WARNING: no LAN address found; check the network connection.")

    if args.http_port:
        plain = create_server(args.host, args.http_port, app=app)
        threading.Thread(target=plain.serve_forever, daemon=True).start()
        print("panel:      http://127.0.0.1:%d/  (same state)" % args.http_port)
    else:
        print("panel:      %s://127.0.0.1:%d/" % (scheme, args.port))
    print("routes:", ", ".join("%s.%s" % route for route in sorted(server.app.routes)))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()

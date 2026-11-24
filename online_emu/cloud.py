"""Cloud services (``/cloud/...``): tunables, availability check and saves.

The engine does not keep the online character in the ``.asmx`` services: it
uses a separate cloud layer made of plain GET/POST requests (no ticket in the
body) against ``/cloud/<n>/cloudservices/...``, signed with ``Scs-Ticket`` and
``ros-HeadersHmac``. Without those routes the client reports that cloud data
and progress are unavailable.

What the engine asks for:

  * ``titles/gta5/pcros/check.json``
        Cloud availability probe. If it fails the game flags the cloud as
        unavailable.
  * ``titles/gta5/pcros/0x1a098062.json``
        Tunables. The parser reads the keys ``version`` (must be 1),
        ``format``, ``contentlists``, ``tunables`` and ``bonus``. The member
        variant (``members/sc/<id>/secure/gta5/0x1a098062.xml``) is the same
        JSON: the engine parses it the same way and does not look at the
        extension.
  * ``members/sc/<id>/GTA5/saves/mpstats``
        The character save. The load operation downloads it and the save
        operation uploads it with POST, so the body is stored as-is and
        returned on the next GET. This is what makes progress survive between
        sessions.
  * ``members/sc/<id>/GTA5/car`` and ``GTA5/dog`` (POST) plus their
    ``gamesc.json`` / ``appsc.json`` (GET): garage and pet, stored like
    mpstats.

Files live under ``cloud-files/<account_id>/<path>``, outside any JSON index,
so binary blobs never end up inside the account file.
"""

from __future__ import annotations

import os
import re
from typing import Optional, Tuple
from urllib.parse import unquote

CLOUD_RE = re.compile(r"^/cloud/\d+/cloudservices/(?P<rest>.+)$")

# The tunables parser requires `version == 1`. Missing contentlists or
# tunables are fine: the engine starts with its built-in defaults.
TUNEABLES_JSON = (
    '{"version":1,"format":1,'
    '"contentlists":{},'
    '"tunables":{},'
    '"bonus":{}}'
).encode("utf-8")

JSON_EMPTY = b"{}"
# Languages the policy parser recognises. It looks inside the `eula` / `tos` /
# `pp` node for a child whose NAME is the active language, so all of them are
# emitted here.
POLICY_LANGUAGES = (
    b"es", b"mx", b"es-MX", b"en", b"fr", b"de", b"it", b"pt",
    b"pl", b"ru", b"ko", b"zh", b"ja", b"zh-Hans",
)


def _policy_block(nombre: bytes) -> bytes:
    """``<eula><es>1.0</es>...</eula>`` — the child text is read as a float."""
    hijos = b"".join(
        b"<" + idioma + b">1.0</" + idioma + b">" for idioma in POLICY_LANGUAGES
    )
    return b"<" + nombre + b">" + hijos + b"</" + nombre + b">"


# Legal document: a root with `eula`, `tos` and `pp` blocks, each holding one
# child per language. With an empty XML there are no nodes, the version stays
# unset and the policy manager reports an error, which the client shows as
# "could not download the online policies".
XML_LEGAL = (
    b'<?xml version="1.0" encoding="utf-8"?><LegalPolicies><Version>1</Version>'
    + _policy_block(b"eula")
    + _policy_block(b"tos")
    + _policy_block(b"pp")
    + b"</LegalPolicies>"
)
# `legal/version/version_num.xml` is not a legal document: it is the policy
# version table. It is parsed with the same routine, and the accepted-version
# task looks for a node literally named `Version` either as the root or as a
# direct child of it, then parses its text as an integer. The value is stored
# as a 16-bit integer.
XML_LEGAL_VERSION = (
    b'<?xml version="1.0" encoding="utf-8"?><Versions><Version>1</Version>'
    + _policy_block(b"eula")
    + _policy_block(b"tos")
    + _policy_block(b"pp")
    + b"</Versions>"
)
XML_COMMERCE = (
    # Root must be RageCommerceData: the SAX reader only knows that name and
    # its Products/Categories/Strings children. An empty <CommerceData> fills
    # nothing and the multiplayer gate requires valid commerce data.
    b'<?xml version="1.0" encoding="utf-8"?>'
    b"<RageCommerceData><Products></Products><Categories></Categories>"
    b"<Strings></Strings></RageCommerceData>"
)

Response = Tuple[int, str, bytes]


def _content_type(nombre: str) -> str:
    bajo = nombre.lower()
    if bajo.endswith(".json"):
        return "application/json"
    if bajo.endswith(".xml"):
        return "application/xml"
    if bajo.endswith(".dds"):
        return "image/vnd-ms.dds"
    return "application/octet-stream"


class Cloud:
    """Serves the cloud service files and stores the member ones."""

    def __init__(self, root: Optional[str] = None) -> None:
        self.root = root or os.environ.get("EMU_CLOUD_DIR") or "cloud-files"

    # -- storage ---------------------------------------------------------
    def _path(self, member: str, archivo: str) -> str:
        # `member` comes from the client path, so it is sanitized.
        member = re.sub(r"[^0-9A-Za-z_-]", "", member) or "0"
        limpio = archivo.replace("\\", "/").strip("/")
        if ".." in limpio.split("/"):
            limpio = limpio.replace("..", "_")
        return os.path.join(self.root, member, limpio)

    def _read(self, member: str, archivo: str) -> Optional[bytes]:
        ruta = self._path(member, archivo)
        try:
            with open(ruta, "rb") as fh:
                return fh.read()
        except OSError:
            return None

    def _write(self, member: str, archivo: str, cuerpo: bytes) -> None:
        ruta = self._path(member, archivo)
        os.makedirs(os.path.dirname(ruta), exist_ok=True)
        with open(ruta, "wb") as fh:
            fh.write(cuerpo)

    def _bgscripts(self, nombre: str) -> Optional[bytes]:
        """Background script package asked for right before entering online.

        The client requests it from the cloud (both under the member path and
        under the title path). It is served from ``EMU_BGSCRIPTS_DIR``
        (default ``cloud-files/bgscripts``). If the exact name is not on disk
        the known ones are tried, because the build number in the name changes
        with client updates. No file means 404: an invalid package can break
        the mount, so nothing is invented.
        """
        base = os.environ.get("EMU_BGSCRIPTS_DIR") or os.path.join(self.root, "bgscripts")
        for cand in (nombre, "bg_ng.rpf"):
            if not cand:
                continue
            try:
                with open(os.path.join(base, os.path.basename(cand)), "rb") as fh:
                    return fh.read()
            except OSError:
                continue
        return None

    # -- dispatch --------------------------------------------------------
    def dispatch(self, method: str, path: str, body: bytes) -> Optional[Response]:
        """Return ``None`` when the path is not a cloud one."""
        m = CLOUD_RE.match(path)
        if not m:
            return None
        rest = unquote(m.group("rest"))

        if rest.startswith("titles/"):
            return self._title(method, rest)
        if rest.startswith("members/"):
            return self._member(method, rest, body)
        if rest.startswith("global/"):
            if method == "GET":
                return 200, "application/json", JSON_EMPTY
            return 200, "application/octet-stream", b""
        return 404, "application/octet-stream", b""

    def _title(self, method: str, rest: str) -> Response:
        # titles/gta5/pcros/<file...>
        partes = rest.split("/", 3)
        archivo = partes[3] if len(partes) > 3 else ""
        if method != "GET":
            return 200, "application/octet-stream", b""

        if archivo == "check.json":
            # Existing and valid JSON is enough for the readiness probe.
            return 200, "application/json", JSON_EMPTY
        if archivo.endswith("0x1a098062.json"):
            return 200, "application/json", TUNEABLES_JSON
        if archivo.startswith("legal/version/"):
            # Policy version table (see XML_LEGAL_VERSION).
            return 200, "application/xml", XML_LEGAL_VERSION
        if archivo.startswith("legal/"):
            return 200, "application/xml", XML_LEGAL
        if archivo.startswith("store/") and archivo.endswith(".xml"):
            return 200, "application/xml", XML_COMMERCE
        if archivo.startswith("news/") or archivo.endswith(".json"):
            return 200, "application/json", JSON_EMPTY
        if archivo.startswith("bgscripts/"):
            pack = self._bgscripts(archivo.rsplit("/", 1)[-1])
            if pack is not None:
                return 200, "application/octet-stream", pack
            return 404, "application/octet-stream", b""
        return 404, "application/octet-stream", b""

    def _member(self, method: str, rest: str, body: bytes) -> Response:
        # members/sc/<id>/<rest>
        partes = rest.split("/", 3)
        if len(partes) < 4:
            return 404, "application/octet-stream", b""
        member, archivo = partes[2], partes[3]

        if archivo.endswith("0x1a098062.xml"):
            # Member tunables: same JSON as the title one.
            return 200, "application/json", TUNEABLES_JSON
        if archivo.endswith("RosGamersSettings.json"):
            return 200, "application/json", JSON_EMPTY
        if "bgscripts/" in archivo:
            pack = self._bgscripts(archivo.rsplit("/", 1)[-1])
            if pack is not None:
                return 200, "application/octet-stream", pack
            return 404, "application/octet-stream", b""
        # `share/` (for example the character avatar) is served from disk like
        # any other stored file: 200 when it exists, 404 otherwise.

        if method == "POST":
            self._write(member, archivo, body)
            return 200, "application/octet-stream", b""
        if method == "DELETE":
            try:
                os.remove(self._path(member, archivo))
            except OSError:
                pass
            return 200, "application/octet-stream", b""

        # The mpstats response can be neutralised without touching the file:
        #   EMU_MPSTATS_MODE=file  (default) serve the save from disk
        #   EMU_MPSTATS_MODE=empty -> 200 with an empty body ("no character")
        #   EMU_MPSTATS_MODE=404   -> 404
        # Handy to tell "the stored save is a stub" apart from "something else
        # fails". The file on disk is never deleted.
        if "saves/mpstats/" in archivo and archivo.endswith(".save"):
            modo = os.environ.get("EMU_MPSTATS_MODE")
            if not modo:
                ruta_modo = os.path.join(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "mpstats-modo.txt",
                )
                try:
                    with open(ruta_modo, "r", encoding="utf-8") as fh:
                        modo = fh.read().strip()
                except OSError:
                    modo = ""
            modo = (modo or "file").lower()
            if modo == "empty":
                return 200, "application/octet-stream", b""
            if modo == "404":
                return 404, "application/octet-stream", b""

        guardado = self._read(member, archivo)
        if guardado is not None:
            return 200, _content_type(archivo), guardado
        if archivo.endswith(".json"):
            # The engine accepts an empty object and moves on; a 404 there is
            # retried in a loop.
            return 200, "application/json", JSON_EMPTY
        if "saves/mpstats/" in archivo and archivo.endswith(".save"):
            # A 404 on the save is taken as a cloud failure by the engine and
            # shows a warning. An empty 200 is taken as "no character".
            return 200, "application/octet-stream", b""
        return 404, "application/octet-stream", b""

"""Test client: talks to the local server signing every request.

It does what the real client does: asks for a ticket, keeps the session key and
from then on signs method + path + challenge with the configured scheme.
"""

from __future__ import annotations

import base64
import os
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

from .crypto import RosCrypto


class RosError(RuntimeError):
    pass


class RosClient:
    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8787",
        crypto: Optional[RosCrypto] = None,
        version: str = "11",
        verbose: bool = False,
        encrypt_body: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.crypto = crypto or RosCrypto.generate()
        self.version = version
        self.verbose = verbose
        # With True every signed request travels with an encrypted body and
        # expects the response encrypted the same way.
        self.encrypt_body = encrypt_body
        self.ticket = ""
        self.session_ticket = ""
        self.session_key = ""
        self.account_id = 0

    # -- plumbing --------------------------------------------------------
    def path_for(self, service: str, method: str) -> str:
        return "/gta5/%s/gameservices/%s.asmx/%s" % (self.version, service, method)

    def call(
        self,
        service: str,
        method: str,
        params: Optional[Dict[str, str]] = None,
        signed: bool = True,
        tamper: bool = False,
    ) -> Tuple[int, ET.Element]:
        path = self.path_for(service, method)
        body = urllib.parse.urlencode(params or {}).encode("utf-8")
        request = urllib.request.Request(self.base_url + path, data=body, method="POST")
        request.add_header("Content-Type", "application/x-www-form-urlencoded")

        if signed:
            if not self.session_ticket:
                raise RosError("no session: call create_ticket() first")
            challenge = os.urandom(16)
            signature = self.crypto.sign(
                "POST", path, self.session_ticket, challenge, self.session_key
            )
            if tamper:
                first = "A" if signature[0] != "A" else "B"
                signature = first + signature[1:]
            request.add_header("ros-SessionTicket", self.session_ticket)
            request.add_header("ros-Challenge", base64.b64encode(challenge).decode())
            request.add_header("ros-Hmac", signature)

        if signed and self.encrypt_body and self.session_key:
            request.data = self.crypto.encrypt_body(body, self.session_key)
            request.add_header("ros-Encrypted-Body", "1")

        if self.verbose:
            print("->", path)

        encrypted = False
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                payload = response.read()
                status = response.status
                encrypted = (response.headers.get("ros-Encrypted-Body") or "") == "1"
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            status = exc.code
            encrypted = (exc.headers.get("ros-Encrypted-Body") or "") == "1"

        if encrypted and self.session_key:
            payload = self.crypto.decrypt_body(payload, self.session_key)
        return status, ET.fromstring(payload)

    # -- parsing helpers --------------------------------------------------
    @staticmethod
    def text(root: ET.Element, tag: str) -> str:
        # The engine reads the ticket fields inside `<Result>`, so they are
        # looked up there when they are not hanging from the root.
        node = root.find(tag)
        if node is None:
            resultado = root.find("Result")
            if resultado is not None:
                node = resultado.find(tag)
        if node is None or node.text is None:
            return ""
        return node.text

    @staticmethod
    def items(root: ET.Element, tag: str) -> List[Dict[str, str]]:
        node = root.find(tag)
        if node is None:
            return []
        return [
            {child.tag: (child.text or "") for child in item} for item in node.findall("Item")
        ]

    # -- high level operations --------------------------------------------
    def create_ticket(
        self, email: str, nickname: str, password: str, platform: str = "pcros"
    ) -> ET.Element:
        status, root = self.call(
            "auth",
            "CreateTicketSc3",
            {"email": email, "nickname": nickname, "password": password, "platform": platform},
            signed=False,
        )
        if status != 200:
            raise RosError(
                "CreateTicketSc3 returned %d (%s)" % (status, self.text(root, "Error"))
            )
        self.ticket = self.text(root, "Ticket")
        self.session_ticket = self.text(root, "SessionTicket")
        self.session_key = self.text(root, "SessionKey")
        self.account_id = int(self.text(root, "RockstarId") or 0)
        return root

    def account_info(self) -> ET.Element:
        return self.call("socialclub", "GetAccountInfo")[1]

    def profile_stats(self) -> ET.Element:
        return self.call("ProfileStats", "ReadAllStats")[1]

    def presence(self) -> ET.Element:
        return self.call("Presence", "QueryWithMaxRecordLength", {"maxNumRecords": "32"})[1]

    def find_lobbies(self) -> ET.Element:
        return self.call("matchmaking", "Find", {"activity": "0"})[1]

    def crews(self) -> ET.Element:
        return self.call("Clans", "GetMine")[1]

    def send_invite(self, target_id: int, kind: str = "FreeRoam") -> ET.Element:
        return self.call(
            "Presence", "MultiPostMessage", {"to": str(target_id), "kind": kind}
        )[1]

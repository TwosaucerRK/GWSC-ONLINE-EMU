# Architecture

## Request lifecycle

```
client ──► RosHTTPHandler._dispatch
             ├── /cloud/...        → Cloud.dispatch        (no ticket in body)
             ├── /gwsc/api/...     → Launcher.dispatch     (JSON, token based)
             ├── /panel/api/...    → Panel.dispatch        (cookie session)
             ├── /  /panel         → panel HTML
             ├── /health           → tiny XML status
             └── *.asmx/<Method>   → ROUTES[(service, method)]
                                       └── _authenticate() first,
                                           except for the ticket route
```

The route regex accepts both `/gta5/<version>/gameservices/<svc>.asmx/<Method>`
and the bare `/<svc>.asmx/<Method>` form, because the client builds the URLs of
the announced services by concatenating host and `ep` and does not always add
the prefix.

## Ticket

`auth.asmx/CreateTicketSc3` is the only public route. It issues a ticket and
answers a document that has to satisfy a fairly picky parser:

```
<Response>
  <Status>1</Status>              # the HTTP task only accepts 1
  <Result>                        # everything below is read as a child of Result
    <Ticket/> <SessionTicket/> <SessionKey/>
    <SecsUntilExpiration/> <PlayerAccountId/> <RockstarAccount>…</RockstarAccount>
    <Privileges Count="27">0,1,2,…</Privileges>   # text, split on commas
    <Privs id="…">true</Privs>                    # siblings, NOT children
    <Services Count="…"><S ep="…" h="…"/></Services>
    <SslServices Count="…"><S>…</S></SslServices>
  </Result>
</Response>
```

Two details that break the client when they are wrong:

* the service table must be present, otherwise the client keeps its built-in
  hosts and never calls the emulator again;
* the SSL table must be present, otherwise every post-ticket call goes over
  plain HTTP and dies on a TLS-only port.

## Signed requests

Every route except the ticket one expects:

| header | meaning |
| --- | --- |
| `ros-SessionTicket` | session ticket, or the long ticket in the body |
| `ros-Challenge` | random bytes, base64 |
| `ros-Hmac` / `ros-HeadersHmac` | MAC over the request, base64 |
| `ros-SecurityFlags` | flags the client used to sign (default `239`) |

`RosHTTPHandler._authenticate` resolves the ticket, then delegates to
`app.hmac_verifier` when one is plugged (`--hmac-verifier`), otherwise to
`crypto.RosCrypto.verify`. **That default is a stub**, so signed routes answer
`401` until the scheme is implemented.

On a rejection the log only shows a redacted summary by default, because a
challenge, a session ticket and a session key together identify a live
session. Set `EMU_DEBUG_HMAC=1` to dump them next to the received MAC and, when
the verifier exposes `headers_hmac`, the expected ones — that is the data needed
to rebuild a signature offline, and it belongs in a throwaway log.

## Cloud

`/cloud/<n>/cloudservices/{titles,members,global}/...` does not use the ticket
header. Titles paths serve the availability probe, tunables, legal policies and
commerce data; member paths store and return whatever the client uploads
(saves, garage, pet) under `cloud-files/<account>/<path>`.

Responses above 19 bytes are passed through the configured body codec, because
the client filters out bodies that are not in the container format it expects.

## Extending

* **Body encoding**: implement `decode`/`encode` and load it with
  `--body-codec` (see `plugin.py`).
* **Signature**: implement `verify` and load it with `--hmac-verifier`
  (see `ros_crypto.py`).
* **Routes**: add a handler and an entry in `ROUTES`; mark it public only if it
  must work before the ticket exists.

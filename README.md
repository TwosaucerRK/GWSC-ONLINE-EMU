# GWSC online emu

A local base to investigate and test how an online server works, on a PC or
laptop you own. Not for profit.

This project provides a base covering roughly 60-80% of how such a server
works. There is no way to enter and play with it as-is: that part is up to
whoever uses it, and it is not shared here to avoid possible problems.

It covers things like accounts, matchmaking, presence, stats and the cloud
save endpoints.

> **Status: research base, incomplete (60-80%).**
> The signing/encryption module is **not included**: only the interface the
> server expects is declared, with no keys and no algorithm. Whoever uses this
> has to provide or rebuild it. Because of that, the ticket route works but
> every signed request answers `401`, and entering a session is not possible
> with this base alone.
>
> The base targets build **2699** of the client.
## What works

- Ticket issuing (`auth.asmx/CreateTicketSc3`) with the full response document
  a client expects: `Result` block, privileges mask, service and SSL service
  lists.
- The cloud surface (`/cloud/<n>/cloudservices/...`): availability probe,
  tunables, legal policy documents and versions, per-account saves.
- A JSON adapter for launcher-style clients under `/gwsc/api/`.
- A small web panel (single HTML page, no build step) on `/`.
- A test client (`online_emu/client.py`) and a body-codec plugin point so other
  encodings can be plugged without touching the server.

## What is missing

1. **Request signature.** `online_emu/ros_crypto.py` declares the interface
   only. The client signs method, path, security flags, ticket and challenge;
   how the key is derived is not settled. Plug your implementation with
   `--hmac-verifier online_emu.ros_crypto:VERIFIER`.
2. **Body encryption** (`ros-Encrypted-Body`). Declared, not implemented.
3. **Session blob layout.** `matchmaking.asmx/Find` returns the blob the client
   itself announced, but its bit layout is not mapped.
4. **Exact response formats** for a few routes (marked in the code), where only
   a permissive acknowledgement is returned today.

## Requirements

- Python 3.9 or higher (standard library only, no dependencies to install).
- GTA V, purchased, preferably build 2699.
- GTA V Android GWSC port.
- Git, to clone the repository.
- OpenSSL, only if you want HTTPS (to generate your own certificate).

## How to clone

```bash
git clone https://github.com/TwosaucerRK/GWSC-ONLINE-EMU.git
cd GWSC-ONLINE-EMU
```

Then copy the templates and put your own data in (never commit the real ones):

```bash
cp accounts.example.json accounts.json
cp platform.key.example platform.key
```

If you want HTTPS, generate your own certificate:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout certs/server.key -out certs/server.crt \
  -subj "/CN=localhost" -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"
```

And to start it:

```bash
python run.py --port 8787
```

The panel is at `http://127.0.0.1:8787/`.

Useful flags:

| flag | meaning |
| --- | --- |
| `--host`, `--port` | listen address (default `0.0.0.0:8787`) |
| `--tls-cert`, `--tls-key` | serve HTTPS with your own certificate |
| `--store accounts.json` | JSON file used to persist accounts |
| `--platform-key file` | own platform key, created if missing |
| `--body-codec module:Class` | plug a custom body encoding |
| `--hmac-verifier module:Class` | plug a real signature verifier |
| `--http-port 8788` | second plain HTTP port sharing the same state |
| `--persist-tickets` | keep session tickets across restarts (they hold live keys) |

The platform key is read from `EMU_PLATFORM_KEY_B64` or from the file named
by `EMU_PLATFORM_KEY_FILE`; it is never committed.

## Layout

```
run.py                   launcher
online_emu/
  server.py              HTTP server, routes and handlers
  cloud.py               cloud services: tunables, policies, saves
  store.py               accounts, tickets, presence
  launcher.py            JSON adapter for launcher clients
  panel.py               web panel
  client.py              test client
  crypto.py              signing contract  (STUB)
  ros_crypto.py          verifier + body encryption interface (STUB)
  plugin.py              body codec extension point
  xmlfmt.py              response serializer
examples/codec_ros.py    codec example (plumbing only)
docs/ARCHITECTURE.md     request lifecycle and where each piece fits
```

## Updating to a new build

The base targets build 2699. but you can use it for a newer build.

## Acknowledgements

Thanks to the projects this work builds on and learned from:

- **yubie-re / GTA-V-Script-Decompiler** — https://github.com/yubie-re/GTA-V-Script-Decompiler
  Decompiled the PC `maintransition.ysc` (state machine, cases 33/46).
- **fivefury** (PyPI: https://pypi.org/project/fivefury/)
  Python library for GTA V asset formats; used to read `update2.rpf` and
  extract the logical `maintransition.ysc` / `freemode.ysc` (build 2699).
- **gta5-map / Social-Club-API-cheat-sheet** — https://github.com/gta5-map/Social-Club-API-cheat-sheet
  Social Club API reference used for the server endpoints.
- **gta5-map / SocialClub-example-parser** — https://github.com/gta5-map/SocialClub-example-parser
  Example Social Club parser (Node.js) used as API reference.

## Legal

This is an independent, clean-room implementation of a protocol, published for
interoperability research and education. It ships no code, data, artwork or key
material from any game, and it is not affiliated with or endorsed by any
publisher.

- No game files are included or redistributed.
- No keys, certificates or account files are included. Templates are provided
  (`accounts.example.json`, `platform.key.example`, `certs/README.md`) and the
  real files are gitignored.
- The signing/encryption module is not included; only its interface is
  declared. Whoever uses this has to provide or rebuild it themselves.

Do not use it against services you do not own, and do not commit platform
keys, certificates or account files.

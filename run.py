"""Convenience launcher: starts the server with sane defaults.

    python run.py
    python run.py --port 8787 --tls-cert certs/server.crt --tls-key certs/server.key

Everything it does could be done with ``python -m online_emu.server``.
"""

from __future__ import annotations

import os
import runpy
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

if __name__ == "__main__":
    runpy.run_module("online_emu.server", run_name="__main__", alter_sys=True)

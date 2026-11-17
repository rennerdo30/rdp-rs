#!/usr/bin/env python3
"""Runs `remora-agent capture-probe` (RDP-67) inside a Remote Desktop session
of a throwaway lab clone: once while a client is connected, once after it
disconnected.

    python scripts/capture-probe-vm.py [--seconds 10]

The client is `examples/clip_e2e` (no window here); the clone is headless
(`winclone start --rdp`) and discarded at the end. The helper must have been
built with the C runtime linked in (`scripts/helper-vm-test.py` does that).
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import string
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from importlib import import_module

h = import_module("helper-vm-test")  # wc, ps, log, G
ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=10)
    a = ap.parse_args()
    meta = json.loads(subprocess.run(["cargo", "metadata", "--format-version", "1", "--no-deps"],
                                     cwd=ROOT, capture_output=True, text=True, check=True).stdout)
    target = Path(meta["target_directory"])
    agent = Path(str(target) + "-static") / "release" / "remora-agent.exe"
    subprocess.run(["cargo", "build", "--release", "--locked", "-p", "remora-agent",
                    "--target-dir", str(agent.parent.parent), "--message-format=short"], cwd=ROOT,
                   env=dict(os.environ, RUSTFLAGS="-C target-feature=+crt-static"), check=True)
    subprocess.run(["cargo", "build", "--release", "-p", "rdp", "--example", "clip_e2e",
                    "--message-format=short"], cwd=ROOT, check=True)
    client_exe = target / "release" / "examples" / "clip_e2e.exe"
    work = Path(tempfile.mkdtemp(prefix="probe-"))
    client = None
    try:
        h.log("starting the clone")
        h.wc("start", "--rdp", "--minutes", "30", timeout=900)
        pw = work / "pw.txt"
        pw.write_text("Rm-" + "".join(secrets.choice(string.ascii_letters + string.digits)
                                      for _ in range(20)) + "!9", encoding="ascii")
        h.wc("push", str(pw), h.G + r"\pw.txt")
        h.ps(rf"$p = Get-Content -Raw '{h.G}\pw.txt'; Remove-Item '{h.G}\pw.txt'; net user $env:USERNAME $p.Trim() | Out-Null",
             elevated=True)
        user = h.ps("$env:USERNAME").strip().splitlines()[-1]
        h.wc("push", str(agent), h.G + r"\remora-agent.exe")
        client = subprocess.Popen([str(client_exe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, text=True,
                                  env=dict(os.environ, E2E_HOST="127.0.0.1", E2E_PORT="13389",
                                           E2E_USER=user, E2E_PASSWORD_FILE=str(pw)))
        line = client.stdout.readline().strip()
        h.log(f"client: {line}")
        pw.unlink()
        time.sleep(5)
        probe = rf"& '{h.G}\remora-agent.exe' capture-probe {a.seconds} | Out-String"
        h.log("probe while connected:\n" + h.ps(probe, timeout=a.seconds + 120).strip())
        client.stdin.write("quit\n")
        client.stdin.flush()
        client.wait(timeout=20)
        client = None
        time.sleep(5)
        h.log("probe after the client disconnected:\n" + h.ps(probe, timeout=a.seconds + 120).strip())
    finally:
        if client:
            client.kill()  # our own child only
        try:
            h.wc("stop")
            h.log("clone stopped")
        except Exception as e:
            h.log(f"could not stop the clone: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

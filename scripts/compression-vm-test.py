#!/usr/bin/env python3
"""Live test of bulk compression (RDP-69) and the command line's certificate
check (RDP-54) against Windows' own RDP server in a throwaway lab clone.

    python scripts/compression-vm-test.py [--seconds 45]

For each compression type Remora can advertise, the headless recorder
(`remora <host> --record ... --wait N --compression T`) stays connected
while the session keeps drawing (the helper's capture probe blinks a square,
Explorer windows open); a protocol error fails the run. First, without
`--expect-fingerprint` and without a console, the unknown certificate must
be refused. Nothing appears on this PC; the clone is discarded.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import string
import subprocess
import sys
import tempfile
import time
from importlib import import_module
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
h = import_module("helper-vm-test")  # wc, ps, log, G
ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=45)
    a = ap.parse_args()
    meta = json.loads(subprocess.run(["cargo", "metadata", "--format-version", "1", "--no-deps"],
                                     cwd=ROOT, capture_output=True, text=True, check=True).stdout)
    target = Path(meta["target_directory"])
    static = Path(str(target) + "-static")
    subprocess.run(["cargo", "build", "--release", "--locked", "-p", "remora-agent",
                    "--target-dir", str(static), "--message-format=short"], cwd=ROOT,
                   env=dict(os.environ, RUSTFLAGS="-C target-feature=+crt-static"), check=True)
    subprocess.run(["cargo", "build", "--release", "-p", "remora", "--message-format=short"],
                   cwd=ROOT, check=True)
    remora = target / "release" / "remora.exe"
    agent = static / "release" / "remora-agent.exe"
    work = Path(tempfile.mkdtemp(prefix="compr-"))
    results = []

    def check(name, ok, detail=""):
        results.append(ok)
        h.log(f"{'PASS' if ok else 'FAIL'} {name} {detail}")

    try:
        h.wc("start", "--rdp", "--minutes", "40", timeout=900)
        pw = "Rm-" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(20)) + "!9"
        f = work / "pw.txt"
        f.write_text(pw, encoding="ascii")
        h.wc("push", str(f), h.G + r"\pw.txt")
        f.unlink()
        h.ps(rf"$p = Get-Content -Raw '{h.G}\pw.txt'; Remove-Item '{h.G}\pw.txt'; net user $env:USERNAME $p.Trim() | Out-Null",
             elevated=True)
        user = h.ps("$env:USERNAME").strip().splitlines()[-1]
        h.wc("push", str(agent), h.G + r"\remora-agent.exe")
        env = dict(os.environ, RDP_PASSWORD=pw)
        host = "127.0.0.1:13389"

        # RDP-54: an unknown certificate without a console is refused.
        r = subprocess.run([str(remora), host, "-u", user, "--screenshot", str(work / "x.png"),
                            "--wait", "5"], env=env, stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=120)
        out = r.stdout + r.stderr
        m = re.search(r"--expect-fingerprint ([0-9a-f]{64})", out)
        check("unknown certificate refused without a console", r.returncode != 0 and m is not None,
              f"exit {r.returncode}")
        if not m:
            h.log(out[-800:])
            return 1
        fp = m.group(1)

        for comp in ["rdp61", "rdp6", "rdp5", "rdp4"]:
            # Something to draw for the whole run.
            h.wc("exec-background", rf'"{h.G}\remora-agent.exe" capture-probe {a.seconds}')
            h.wc("exec-background", r"explorer.exe C:\Windows\System32")
            log = work / f"{comp}.log"
            t = time.time()
            r = subprocess.run([str(remora), host, "-u", user, "--expect-fingerprint", fp,
                                "--compression", comp, "--record", str(work / f"{comp}.mp4"),
                                "--wait", str(a.seconds), "-v"],
                               env=env, stdin=subprocess.DEVNULL, capture_output=True,
                               text=True, errors="replace", timeout=a.seconds + 180)
            out = r.stdout + r.stderr
            log.write_text(out, encoding="utf-8")
            negotiated = sorted(set(re.findall(r"compression type (\d)", out)))
            frames = re.search(r"recorded [\d.]+ s, (\d+) frames", out)
            ok = r.returncode == 0 and "protocol error" not in out
            check(f"compression {comp} for {a.seconds} s", ok,
                  f"exit {r.returncode}, {frames.group(1) if frames else '?'} frames, "
                  f"{time.time() - t:.0f} s; log {log}")
            if not ok:
                h.log("\n".join(l for l in out.splitlines() if "error" in l.lower())[-1500:])
    finally:
        try:
            h.wc("stop")
            h.log("clone stopped")
        except Exception as e:
            h.log(f"could not stop the clone: {e}")
    h.log(f"{sum(results)} passed, {len(results) - sum(results)} failed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())

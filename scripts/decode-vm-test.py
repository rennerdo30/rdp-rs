#!/usr/bin/env python3
"""Measures Remora's own decoding cost (RDP-67): how much of the latency
meter's fixed part is spent on this PC, per picture size.

    python scripts/decode-vm-test.py [--seconds 30] [--sizes 1280x800,3688x1984]

A throwaway lab clone prefers H.264 (AVC444) like a server after Remora's
Improve (`remora-agent tune apply`); the helper's capture probe animates a
small square in the session, like the latency marker. For each size the
headless client (`remora --gfx --size WxH --screenshot`) stays connected for
the given time and prints the graphics pipeline's frames, decoding time per
frame and codec. Nothing appears on this PC; the clone is discarded.
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
import zlib
from importlib import import_module
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
h = import_module("helper-vm-test")  # wc, ps, log, G
ROOT = Path(__file__).resolve().parent.parent


def lit_share(png: Path) -> float:
    """Share of the screenshot's bytes that are not black: a session that
    decodes frames but shows nothing (RDP-70) has almost none."""
    b = png.read_bytes()
    i, data = 8, b""
    while i < len(b):
        n = int.from_bytes(b[i:i + 4], "big")
        if b[i + 4:i + 8] == b"IDAT":
            data += b[i + 8:i + 8 + n]
        i += 12 + n
    raw = zlib.decompress(data)[::7]
    return sum(1 for x in raw if x > 8) / max(len(raw), 1)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=30)
    ap.add_argument("--sizes", default="1280x800,3688x1984")
    a = ap.parse_args()
    meta = json.loads(subprocess.run(["cargo", "metadata", "--format-version", "1", "--no-deps"],
                                     cwd=ROOT, capture_output=True, text=True, check=True).stdout)
    target = Path(meta["target_directory"])
    static = Path(str(target) + "-static")
    subprocess.run(["cargo", "build", "--release", "--locked", "-p", "remora-agent",
                    "--target-dir", str(static), "--message-format=short"], cwd=ROOT,
                   env=dict(os.environ, RUSTFLAGS="-C target-feature=+crt-static"), check=True)
    subprocess.run(["cargo", "build", "--release", "-p", "remora-client", "--message-format=short"],
                   cwd=ROOT, check=True)
    remora = target / "release" / "remora.exe"
    agent = static / "release" / "remora-agent.exe"
    work = Path(tempfile.mkdtemp(prefix="decode-"))
    rows = []
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
        # Like focalor after Improve: AVC444 preferred (60 fps needs a restart
        # and does not change the decoding cost per frame).
        h.log(h.ps(rf"& '{h.G}\remora-agent.exe' tune apply | Out-String", elevated=True).strip())
        env = dict(os.environ, RDP_PASSWORD=pw)
        host = "127.0.0.1:13389"
        r = subprocess.run([str(remora), host, "-u", user, "--screenshot", str(work / "x.png"),
                            "--wait", "5"], env=env, stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=120)
        m = re.search(r"--expect-fingerprint ([0-9a-f]{64})", r.stdout + r.stderr)
        if not m:
            h.log((r.stdout + r.stderr)[-800:])
            return 1
        fp = m.group(1)
        for size in a.sizes.split(","):
            h.wc("exec-background", rf'"{h.G}\remora-agent.exe" capture-probe {a.seconds + 20}')
            out = subprocess.run([str(remora), host, "-u", user, "--expect-fingerprint", fp, "--gfx",
                                  "--size", size, "--screenshot", str(work / f"{size}.png"),
                                  "--wait", str(a.seconds)],
                                 env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                 errors="replace", timeout=a.seconds + 180)
            text = out.stdout + out.stderr
            (work / f"{size}.log").write_text(text, encoding="utf-8")
            line = next((l for l in text.splitlines() if l.startswith("graphics pipeline:")),
                        f"no graphics pipeline figures (exit {out.returncode})")
            shot = work / f"{size}.png"
            lit = lit_share(shot) if shot.exists() else 0.0
            line += f"; picture {lit:.0%} not black" + ("" if lit > 0.2 else " (FAIL: black)")
            rows.append((size, line))
            h.log(f"{size}: {line}")
    finally:
        try:
            h.wc("stop")
            h.log("clone stopped")
        except Exception as e:
            h.log(f"could not stop the clone: {e}")
    for size, line in rows:
        print(f"{size:>10}  {line}")
    return 0 if rows and all("ms decoding" in l and "FAIL" not in l for _, l in rows) else 1


if __name__ == "__main__":
    sys.exit(main())

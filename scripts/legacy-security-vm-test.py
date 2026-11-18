#!/usr/bin/env python3
"""Live test of legacy RDP security (Standard RDP Security, MS-RDPBCGR 5.3;
RDP-73) against Windows' own RDP server in a throwaway lab clone.

    python scripts/legacy-security-vm-test.py [--seconds 60] [--levels 1,2,3,4]

The clone's RDP-Tcp listener is set to the RDP Security Layer
(SecurityLayer=0, no NLA) and each encryption level in turn
(MinEncryptionLevel 1 Low, 2 Client Compatible, 3 High, 4 FIPS; RDP-84).
For each level:

1. Without `--legacy-security` the headless client must refuse the server
   and say so ("only legacy RDP security"); this also proves the registry
   change took effect (else the listener is restarted once).
2. Without a console the unknown server key is refused and its fingerprint
   printed (the same trust check as a TLS certificate, RDP-54).
3. With `--legacy-security --expect-fingerprint`, the client records the
   desktop for `--seconds` while a test window repaints at 30 fps: exit 0, no
   protocol error or MAC mismatch, the trace names the cipher (RC4
   strength, or FIPS Triple DES at level 4) and level, and at least one RC4
   key update (after 4,096 packets, 5.3.7) happens in a run with an RC4
   level.

Nothing appears on this PC; the clone is discarded.
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
VIDEO_WINDOW = import_module("video-vm-test").VIDEO_WINDOW  # repaints at 30 fps
ROOT = Path(__file__).resolve().parent.parent
RDP_TCP = r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=60)
    ap.add_argument("--levels", default="1,2,3,4",
                    help="encryption levels to test (a key update needs 4,096 packets: "
                         "use one level and --seconds 900 to see one)")
    a = ap.parse_args()
    meta = json.loads(subprocess.run(["cargo", "metadata", "--format-version", "1", "--no-deps"],
                                     cwd=ROOT, capture_output=True, text=True, check=True).stdout)
    target = Path(meta["target_directory"])
    subprocess.run(["cargo", "build", "--release", "-p", "remora", "--message-format=short"],
                   cwd=ROOT, check=True)
    remora = target / "release" / "remora.exe"
    work = Path(tempfile.mkdtemp(prefix="legacy-"))
    results = []
    updates = 0

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
        win = work / "video-window.ps1"
        win.write_text(VIDEO_WINDOW, encoding="utf-8-sig")
        h.wc("push", str(win), h.G + r"\video-window.ps1")
        env = dict(os.environ, RDP_PASSWORD=pw)
        host = "127.0.0.1:13389"

        def run(*extra, timeout=180):
            r = subprocess.run([str(remora), host, "-u", user, *extra], env=env,
                               stdin=subprocess.DEVNULL, capture_output=True, text=True,
                               errors="replace", timeout=timeout)
            return r.returncode, r.stdout + r.stderr

        names = {1: "low", 2: "client compatible", 3: "high", 4: "FIPS"}
        rc4_runs = 0
        for level in [int(v) for v in a.levels.split(",")]:
            name = names[level]
            h.ps(f"Set-ItemProperty '{RDP_TCP}' SecurityLayer 0; "
                 f"Set-ItemProperty '{RDP_TCP}' UserAuthentication 0; "
                 f"Set-ItemProperty '{RDP_TCP}' MinEncryptionLevel {level}", elevated=True)

            # 1. Not allowed: refused, and the message says why.
            code, out = run("--screenshot", str(work / "x.png"), "--wait", "5")
            if "only legacy RDP security" not in out:
                h.log("listener still offers TLS: restarting TermService once")
                h.ps("Restart-Service TermService -Force; Start-Sleep 5", elevated=True)
                code, out = run("--screenshot", str(work / "x.png"), "--wait", "5")
            check(f"[{name}] refused without --legacy-security",
                  code != 0 and "only legacy RDP security" in out, f"exit {code}")

            # 2. The unknown server key is refused without a console.
            code, out = run("--legacy-security", "--screenshot", str(work / "x.png"), "--wait", "5")
            m = re.search(r"--expect-fingerprint ([0-9a-f]{64})", out)
            check(f"[{name}] unknown server key refused without a console",
                  code != 0 and m is not None, f"exit {code}")
            if not m:
                h.log(out[-800:])
                continue

            # 3. Allowed: a drawing session, encrypted both ways.
            # A window repainting at 30 fps: enough server packets for a key
            # update (4,096 per direction) within a few minutes.
            h.wc("exec-background",
                 rf'powershell -NoProfile -ExecutionPolicy Bypass -File "{h.G}\video-window.ps1" -Seconds {a.seconds + 30}')
            h.wc("exec-background", r"explorer.exe C:\Windows\System32")
            log = work / f"level{level}.log"
            t = time.time()
            code, out = run("--legacy-security", "--expect-fingerprint", m.group(1),
                            "--record", str(work / f"level{level}.mp4"),
                            "--screenshot", str(work / f"level{level}.png"),
                            "--wait", str(a.seconds), "-v", timeout=a.seconds + 180)
            log.write_text(out, encoding="utf-8")
            sec = re.search(r"legacy RDP security \(no TLS\): (\d+-bit RC4|FIPS Triple DES), "
                            r"encryption level (\d)", out)
            frames = re.search(r"recorded [\d.]+ s, (\d+) frames", out)
            updates += out.count("RC4 key updated")
            fips = sec is not None and sec.group(1).startswith("FIPS")
            rc4_runs += sec is not None and not fips
            ok = (code == 0 and sec is not None and int(sec.group(2)) >= level
                  and (fips or level < 4)
                  and "protocol error" not in out and "MAC mismatch" not in out
                  and (work / f"level{level}.png").exists())
            check(f"[{name}] session for {a.seconds} s", ok,
                  f"exit {code}, {sec.group(0) if sec else 'no legacy trace'}, "
                  f"{frames.group(1) if frames else '?'} frames, {time.time() - t:.0f} s; log {log}")
            if not ok:
                h.log("\n".join(l for l in out.splitlines() if "error" in l.lower())[-1500:])
        if rc4_runs:
            check("an RC4 key update (4,096 packets) happened and the session went on",
                  updates > 0, f"{updates} updates")
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

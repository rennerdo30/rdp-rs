#!/usr/bin/env python3
"""Live test of the UDP transport (RDP-79, MS-RDPEMT / MS-RDPEUDP) against
Windows' own RDP server.

    python scripts/udp-vm-test.py [--seconds 30]              (lab clone)
    python scripts/udp-vm-test.py --lab-udp [--seconds 30]    (lab clone that
                                                    also forwards UDP 13389)
    python scripts/udp-vm-test.py --server HOST[:PORT] --user USER
                                  [--expect-fingerprint SHA256] [--seconds 30]
                                  (a real server; password in RDP_PASSWORD)

Each run is the headless recorder with the graphics pipeline and UDP
offered (`remora <host> --gfx --udp --record ... --wait N -v`). Remora
prints at the end which transport carried the session:
`transport: Active, N dynamic channels on UDP, ...` or `transport: Failed`.

- Lab clone (`winclone start --rdp`): QEMU forwards only TCP 3389 to
  127.0.0.1:13389, so the UDP handshake to 127.0.0.1:13389 gets no answer.
  That is the fallback check: the server asks for UDP, the tunnel fails,
  Remora answers E_ABORT and the session must run on over TCP (exit 0,
  frames recorded, "transport: Failed"). With `--lab-udp` (the lab driver
  also forwards udp:127.0.0.1:13389 to the guest's 3389) the run must use
  UDP instead.
- `--server`: a Windows server reached directly (no gateway) with UDP 3389
  open. The run must use UDP: "UDP tunnel ready" in the log, the Soft-Sync
  moving channels ("moves to UDP"), "transport: Active" with at least one
  channel, frames recorded and no protocol error.

Nothing appears on this PC; the lab clone is discarded at the end.
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
ROOT = Path(__file__).resolve().parent.parent


def build() -> Path:
    meta = json.loads(subprocess.run(["cargo", "metadata", "--format-version", "1", "--no-deps"],
                                     cwd=ROOT, capture_output=True, text=True, check=True).stdout)
    subprocess.run(["cargo", "build", "--release", "-p", "remora-client", "--message-format=short"],
                   cwd=ROOT, check=True)
    return Path(meta["target_directory"]) / "release" / "remora.exe"


def run(remora: Path, host: str, user: str, fp: str | None, seconds: int, work: Path,
        env: dict, name: str) -> str:
    args = [str(remora), host, "-u", user, "--gfx", "--udp",
            "--record", str(work / f"{name}.mp4"), "--wait", str(seconds), "-v"]
    if fp:
        args += ["--expect-fingerprint", fp]
    r = subprocess.run(args, env=env, stdin=subprocess.DEVNULL, capture_output=True,
                       text=True, errors="replace", timeout=seconds + 180)
    out = r.stdout + r.stderr + f"\nexit {r.returncode}\n"
    (work / f"{name}.log").write_text(out, encoding="utf-8")
    return out


def judge(out: str, want_udp: bool) -> tuple[bool, str]:
    exit_ok = re.search(r"\nexit 0\n", out) is not None
    frames = re.search(r"recorded [\d.]+ s, (\d+) frames", out)
    t = re.search(r"transport: (\w+), (\d+) dynamic channels on UDP", out)
    state, channels = (t.group(1), int(t.group(2))) if t else ("?", 0)
    asked = "multitransport request" in out
    ok = exit_ok and frames is not None and int(frames.group(1)) > 0 \
        and "protocol error" not in out and asked
    if want_udp:
        ok = ok and state == "Active" and channels >= 1 and "UDP tunnel ready" in out \
            and "moves to UDP" in out
    else:
        ok = ok and state == "Failed" and "UDP tunnel failed" in out
    detail = (f"exit_ok={exit_ok}, frames={frames.group(1) if frames else '?'}, "
              f"server asked={asked}, transport={state}, channels on UDP={channels}")
    return ok, detail


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=30)
    ap.add_argument("--server", help="HOST[:PORT] of a real server instead of the lab clone")
    ap.add_argument("--user")
    ap.add_argument("--expect-fingerprint")
    ap.add_argument("--lab-udp", action="store_true",
                    help="the lab clone also forwards UDP 13389 to the guest's 3389")
    a = ap.parse_args()
    remora = build()
    work = Path(tempfile.mkdtemp(prefix="udp-"))
    print(f"logs in {work}", flush=True)

    if a.server:
        if not a.user or "RDP_PASSWORD" not in os.environ:
            print("--server needs --user and RDP_PASSWORD", file=sys.stderr)
            return 2
        out = run(remora, a.server, a.user, a.expect_fingerprint, a.seconds, work,
                  dict(os.environ), "server")
        ok, detail = judge(out, want_udp=True)
        print(f"{'PASS' if ok else 'FAIL'} session over UDP: {detail}", flush=True)
        return 0 if ok else 1

    h = import_module("helper-vm-test")  # wc, ps, log
    try:
        h.wc("start", "--rdp", "--minutes", "30", timeout=900)
        pw = "Rm-" + "".join(secrets.choice(string.ascii_letters + string.digits)
                             for _ in range(20)) + "!9"
        f = work / "pw.txt"
        f.write_text(pw, encoding="ascii")
        h.wc("push", str(f), h.G + r"\pw.txt")
        f.unlink()
        h.ps(rf"$p = Get-Content -Raw '{h.G}\pw.txt'; Remove-Item '{h.G}\pw.txt'; "
             r"net user $env:USERNAME $p.Trim() | Out-Null", elevated=True)
        user = h.ps("$env:USERNAME").strip().splitlines()[-1]
        env = dict(os.environ, RDP_PASSWORD=pw)
        host = "127.0.0.1:13389"
        # The certificate's fingerprint from the refusal without a console.
        r = subprocess.run([str(remora), host, "-u", user, "--screenshot", str(work / "x.png"),
                            "--wait", "5"], env=env, stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=120)
        m = re.search(r"--expect-fingerprint ([0-9a-f]{64})", r.stdout + r.stderr)
        if not m:
            h.log("no certificate fingerprint in the refusal")
            return 1
        h.wc("exec-background", r"explorer.exe C:\Windows\System32")
        t = time.time()
        out = run(remora, host, user, m.group(1), a.seconds, work, env, "lab")
        ok, detail = judge(out, want_udp=a.lab_udp)
        what = "session over UDP" if a.lab_udp else "UDP blocked: session stays on TCP"
        h.log(f"{'PASS' if ok else 'FAIL'} {what}: {detail}, {time.time() - t:.0f} s")
        if not ok:
            h.log("\n".join(l for l in out.splitlines()
                            if "udp" in l.lower() or "error" in l.lower())[-2000:])
        return 0 if ok else 1
    finally:
        try:
            h.wc("stop")
            h.log("clone stopped")
        except Exception as e:
            h.log(f"could not stop the clone: {e}")


if __name__ == "__main__":
    sys.exit(main())

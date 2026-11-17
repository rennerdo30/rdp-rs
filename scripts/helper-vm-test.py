#!/usr/bin/env python3
"""Live test of the server helper over a real Remote Desktop session
(RDP-64 folders both ways, RDP-61 self-update), in a throwaway lab clone.

    python scripts/helper-vm-test.py [--big-mib 1024] [--keep]

The clone (`winclone start --rdp`, headless) runs Windows' own RDP server;
`remora-agent` (built with the C runtime linked in) runs in the user's
session. Remora's side is the ignored test `helper::live_tests` (the real
helper code, no window), which talks to this script through files in a
work folder. Pairing needs no clicks: the test's key is trusted with
`remora-agent trust-client`, the helper's with its fingerprint.

Checks: the helper pairs and agrees on folders; a folder (with a big sparse
file) goes PC -> server into Downloads\\From Remora and a folder comes back
with `remora-agent send` (what Send To runs), compared by SHA-256; the helper
replaces itself with an update and reconnects. This PC's desktop and
clipboard are never touched; `stop` discards the clone.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import string
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent
WINCLONE = r"E:\AgentData\renneros-lab\winclone\winclone.ps1"
G = r"C:\Users\Public\e2e"


def log(m: str) -> None:
    print(time.strftime("%H:%M:%S"), m, flush=True)


def wc(*a: str, timeout: int = 300) -> str:
    # The guest agent sometimes stops answering for a moment after heavy
    # disk work (hashing a big file): retry starts that never ran.
    tries = 3 if a[0] in ("exec-background", "push") else 1
    for i in range(tries):
        r = subprocess.run(["pwsh", "-NoProfile", "-File", WINCLONE, *a], capture_output=True,
                           text=True, timeout=timeout)
        if r.returncode == 0:
            return r.stdout
        if i + 1 < tries and "stopped answering" in r.stdout + r.stderr:
            log(f"winclone {a[0]}: guest agent busy, retrying")
            time.sleep(20)
            continue
        raise RuntimeError(f"winclone {a[0]} failed ({r.returncode}): {r.stdout}{r.stderr}")
    return ""


def ps(script: str, timeout: int = 300, elevated: bool = False) -> str:
    """PowerShell in the user's session (ASCII scripts; names come back escaped)."""
    f = Path(tempfile.mkdtemp()) / f"s{secrets.token_hex(4)}.ps1"
    f.write_text(script, encoding="utf-8-sig")
    wc("push", str(f), G + "\\" + f.name)
    f.unlink()
    a = ["exec", f'powershell -NoProfile -ExecutionPolicy Bypass -File "{G}\\{f.name}"',
         "-TimeoutSec", str(timeout)]
    if elevated:
        a.append("-Elevated")
    return wc(*a, timeout=timeout + 60)


def sha(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while b := f.read(8 << 20):
            h.update(b)
    return h.hexdigest()


def local_hashes(root: Path) -> dict:
    return {str(f.relative_to(root)).replace("/", "\\"): sha(f)
            for f in sorted(root.rglob("*")) if f.is_file()}


def guest_hashes(path: str) -> dict:
    out = ps(rf"""
$d = '{path}'
Get-ChildItem -Recurse -File $d | ForEach-Object {{
  "{{0}}|{{1}}" -f [uri]::EscapeDataString($_.FullName.Substring($d.Length + 1)), (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLower()
}}
""", timeout=1200)
    return {unquote(k): v for k, v in (l.strip().split("|", 1) for l in out.splitlines() if "|" in l)}


def wait(work: Path, name: str, limit: int, proc) -> str:
    end = time.time() + limit
    while time.time() < end:
        f = work / name
        if f.exists():
            return f.read_text()
        if proc.poll() is not None:
            raise RuntimeError(f"the test ended before '{name}' (exit {proc.returncode})")
        time.sleep(1)
    raise RuntimeError(f"no '{name}' within {limit} s")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--big-mib", type=int, default=1024)
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()
    results: list[tuple[str, bool, str]] = []

    def check(name, ok, detail=""):
        results.append((name, ok, detail))
        log(f"{'PASS' if ok else 'FAIL'} {name} {detail}")

    meta = json.loads(subprocess.run(["cargo", "metadata", "--format-version", "1", "--no-deps"],
                                     cwd=ROOT, capture_output=True, text=True, check=True).stdout)
    static = Path(meta["target_directory"] + "-static")
    log("building remora-agent with the C runtime linked in")
    env = dict(os.environ, RUSTFLAGS="-C target-feature=+crt-static")
    subprocess.run(["cargo", "build", "--release", "--locked", "-p", "remora-agent",
                    "--target-dir", str(static), "--message-format=short"], cwd=ROOT, env=env, check=True)
    agent = static / "release" / "remora-agent.exe"
    log("building the live test")
    subprocess.run(["cargo", "test", "-p", "remora", "--no-run", "--message-format=short"],
                   cwd=ROOT, check=True)

    work = Path(tempfile.mkdtemp(prefix="helper-e2e-"))
    proc = None
    trace = None
    try:
        log("starting the clone (Remote Desktop, headless)")
        wc("start", "--rdp", "--minutes", "90", timeout=900)
        pw = work / "pw.txt"
        pw.write_text("Rm-" + "".join(secrets.choice(string.ascii_letters + string.digits)
                                      for _ in range(20)) + "!9", encoding="ascii")
        wc("push", str(pw), G + r"\pw.txt")
        ps(rf"$p = Get-Content -Raw '{G}\pw.txt'; Remove-Item '{G}\pw.txt'; net user $env:USERNAME $p.Trim() | Out-Null",
           elevated=True)
        user = ps("$env:USERNAME").strip().splitlines()[-1]
        wc("push", str(agent), G + r"\remora-agent.exe")
        log("server files")
        ps(rf"""
$s = '{G}\srv\Server tree'
New-Item -ItemType Directory -Force "$s\sub\deeper" | Out-Null
Set-Content "$s\readme.txt" 'from the server'
$b = New-Object byte[] (7MB + 9); (New-Object Random 7).NextBytes($b)
[IO.File]::WriteAllBytes("$s\sub\random.bin", $b)
[IO.File]::WriteAllBytes("$s\sub\deeper\empty.txt", @())
fsutil file createnew "$s\big.bin" {a.big_mib * 1048576} | Out-Null
'ok'
""")
        up = work / "up" / "PC tree"
        (up / "deep").mkdir(parents=True)
        (up / "notes.txt").write_text("from the pc\n")
        (up / "deep" / "random.bin").write_bytes(os.urandom(5 * (1 << 20) + 3))
        big = up / "big.bin"
        big.write_bytes(b"")
        subprocess.run(["fsutil", "sparse", "setflag", str(big)], check=True, capture_output=True)
        with open(big, "r+b") as f:
            f.truncate(a.big_mib << 20)

        log("starting the live test")
        trace = open(work / "test.log", "w", encoding="utf-8")
        tenv = dict(os.environ, E2E_HOST="127.0.0.1", E2E_PORT="13389", E2E_USER=user,
                    E2E_PASSWORD_FILE=str(pw), E2E_DIR=str(work))
        proc = subprocess.Popen(["cargo", "test", "-p", "remora", "live_helper", "--",
                                 "--ignored", "--nocapture", "--test-threads=1"],
                                cwd=ROOT, env=tenv, stdout=trace, stderr=subprocess.STDOUT)
        client_fp = wait(work, "client.fp", 300, proc).strip()
        out = ps(rf"& '{G}\remora-agent.exe' trust-client '{client_fp}' | Out-String")
        log("trust-client: " + " ".join(out.split())[:120])
        (work / "trusted").write_text("ok")
        wait(work, "connected", 120, proc)
        pw.unlink()
        # The helper in the RDP session, as its logon task would start it.
        wc("exec-background", rf'"{G}\remora-agent.exe" run')
        time.sleep(5)
        # The running helper's key, as a user reads it to compare.
        fp = ps(rf"& '{G}\remora-agent.exe' fingerprint | Out-String").strip().splitlines()
        helper_fp = next((l.strip() for l in fp if sum(c in "0123456789abcdefABCDEF" for c in l) >= 32), "")
        log(f"helper fingerprint: {helper_fp}")
        (work / "helper.fp").write_text(helper_fp)
        paired = wait(work, "paired", 180, proc)
        check("helper paired over the session", True, paired)

        want = local_hashes(up.parent)
        t = time.time()
        sent = wait(work, "sent", 3600, proc)
        got = guest_hashes(r"C:\Users\%s\Downloads\From Remora" % user)
        check("PC -> server folder", got == want, f"{len(got)}/{len(want)} files, {sent}, "
              f"{sum((up / k.split(chr(92), 1)[1]).stat().st_size for k in want) / max(time.time() - t, 0.1) / 1e6:.0f} MB/s incl. hashing")

        want = guest_hashes(G + r"\srv")
        wc("exec-background", rf'"{G}\remora-agent.exe" send "{G}\srv\Server tree"')
        received = wait(work, "received", 3600, proc)
        got = local_hashes(work / "down")
        check("server -> PC folder (Send To)", got == want, f"{len(got)}/{len(want)} files, {received}")

        (work / "agent.exe").write_bytes(agent.read_bytes())
        (work / "update.go").write_text("ok")
        updated = wait(work, "updated", 300, proc)
        check("helper accepts the update", "Installed" in updated, updated)
        rejoined = wait(work, "rejoined", 180, proc)
        check("updated helper reconnects", True, rejoined)
        proc.wait(timeout=60)
        check("live test passed", proc.returncode == 0, f"exit {proc.returncode}")
    except Exception as e:
        check("run", False, repr(e))
    finally:
        if proc and proc.poll() is None:
            proc.kill()  # our own child only
            proc.wait()
        if trace:
            trace.close()
            log(f"test log: {work / 'test.log'}")
        if not a.keep:
            try:
                wc("stop")
                log("clone stopped (all changes discarded)")
            except Exception as e:
                log(f"could not stop the clone: {e}")
        for f in (work / "pw.txt", work / "agent.exe"):
            if f.exists():
                f.unlink()
    failed = [r for r in results if not r[1]]
    log(f"{len(results) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

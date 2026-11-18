#!/usr/bin/env python3
"""Live test of serial port redirection (RDP-74, MS-RDPESP) over a real
Remote Desktop session, in a throwaway lab clone.

    python scripts/serial-vm-test.py [--keep]

No real port is needed or opened: Remora's side is the ignored test
`serial::live_tests` (the real rdpdr device and protocol, no window), which
shares "COM9" backed by an in-process loopback. In the session, PowerShell's
System.IO.Ports.SerialPort opens COM9 at 19200 baud, writes a line and reads
it back, which drives create, the settings IOCTLs, WAIT_ON_MASK, write, read
and close through the server's redirector. Then the test removes the port
live and the script checks that COM9 no longer opens.

The clone (`winclone start --rdp`, headless) runs Windows' own RDP server;
this PC's desktop is never touched; `stop` discards the clone.
"""

from __future__ import annotations

import argparse
import os
import secrets
import string
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WINCLONE = r"E:\AgentData\renneros-lab\winclone\winclone.ps1"
G = r"C:\Users\Public\e2e"

OPEN_AND_ECHO = r"""
$ErrorActionPreference = 'Stop'
try {
  $p = New-Object System.IO.Ports.SerialPort 'COM9', 19200, 'None', 8, 'One'
  $p.ReadTimeout = 5000; $p.WriteTimeout = 5000
  $p.Open()
  $p.Write('ping-serial-74')
  $got = ''; $t = [Diagnostics.Stopwatch]::StartNew()
  while ($got.Length -lt 14 -and $t.ElapsedMilliseconds -lt 10000) {
    $got += $p.ReadExisting(); Start-Sleep -Milliseconds 100
  }
  $baud = $p.BaudRate
  $p.Close()
  "echo=$got baud=$baud"
} catch { "error=$($_.Exception.Message)" }
"""

OPEN_AFTER_REMOVE = r"""
try {
  $p = New-Object System.IO.Ports.SerialPort 'COM9'
  $p.Open(); $p.Close(); 'opened'
} catch { "error=$($_.Exception.Message)" }
"""


def log(m: str) -> None:
    print(time.strftime("%H:%M:%S"), m, flush=True)


def wc(*a: str, timeout: int = 300) -> str:
    r = subprocess.run(["pwsh", "-NoProfile", "-File", WINCLONE, *a], capture_output=True,
                       text=True, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"winclone {a[0]} failed ({r.returncode}): {r.stdout}{r.stderr}")
    return r.stdout


def ps(script: str, timeout: int = 120, elevated: bool = False) -> str:
    """PowerShell in the user's session, where redirected ports live."""
    f = Path(tempfile.mkdtemp()) / f"s{secrets.token_hex(4)}.ps1"
    f.write_text(script, encoding="utf-8-sig")
    wc("push", str(f), G + "\\" + f.name)
    f.unlink()
    a = ["exec", f'powershell -NoProfile -ExecutionPolicy Bypass -File "{G}\\{f.name}"',
         "-TimeoutSec", str(timeout)]
    if elevated:
        a.append("-Elevated")
    return wc(*a, timeout=timeout + 60)


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
    ap.add_argument("--keep", action="store_true", help="leave the clone running at the end")
    a = ap.parse_args()
    results: list[tuple[str, bool, str]] = []

    def check(name, ok, detail=""):
        results.append((name, ok, detail))
        log(f"{'PASS' if ok else 'FAIL'} {name} {detail}")

    log("building the live test")
    subprocess.run(["cargo", "test", "-p", "remora", "--no-run", "--message-format=short"],
                   cwd=ROOT, check=True)
    work = Path(tempfile.mkdtemp(prefix="serial-e2e-"))
    pw = work / "pw.txt"
    proc = None
    trace = None
    try:
        log("starting the clone (Remote Desktop, headless)")
        wc("start", "--rdp", "--minutes", "30", timeout=900)
        pw.write_text("Rm-" + "".join(secrets.choice(string.ascii_letters + string.digits)
                                      for _ in range(20)) + "!9", encoding="ascii")
        wc("push", str(pw), G + r"\pw.txt")
        ps(rf"$p = Get-Content -Raw '{G}\pw.txt'; Remove-Item '{G}\pw.txt'; net user $env:USERNAME $p.Trim() | Out-Null",
           elevated=True)
        # Port redirection must be allowed on the server (policy off).
        ps(r"Remove-ItemProperty -ErrorAction SilentlyContinue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' fDisableCcm; 'ok'",
           elevated=True)
        user = ps("$env:USERNAME").strip().splitlines()[-1]

        log("starting the live test")
        trace = open(work / "test.log", "w", encoding="utf-8")
        tenv = dict(os.environ, E2E_HOST="127.0.0.1", E2E_PORT="13389", E2E_USER=user,
                    E2E_PASSWORD_FILE=str(pw), E2E_DIR=str(work))
        proc = subprocess.Popen(["cargo", "test", "-p", "remora", "live_serial", "--",
                                 "--ignored", "--nocapture", "--test-threads=1"],
                                cwd=ROOT, env=tenv, stdout=trace, stderr=subprocess.STDOUT)
        wait(work, "connected", 180, proc)
        pw.unlink()

        out = " ".join(ps(OPEN_AND_ECHO).split())
        check("server opens COM9 and reads back what it wrote", "echo=ping-serial-74" in out, out)
        (work / "serial-done").write_text(out)
        client = wait(work, "client", 60, proc)
        check("Remora saw the baud rate, an open and a close",
              "19200" in client and "opens=0" not in client and "closes=0" not in client, client)

        wait(work, "removed", 60, proc)
        after = " ".join(ps(OPEN_AFTER_REMOVE).split())
        check("COM9 no longer opens after the live remove", after.startswith("error="), after)
        (work / "after-remove").write_text(after)
        proc.wait(timeout=60)
        check("live test passed", proc.returncode == 0, f"exit {proc.returncode}")
    except Exception as e:
        check("run", False, repr(e))
    finally:
        pw.unlink(missing_ok=True)
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
    failed = [r for r in results if not r[1]]
    log(f"{len(results) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

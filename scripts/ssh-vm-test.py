#!/usr/bin/env python3
"""Live test of SSH in Remora (RDP-87, RDP-88) against Windows' own OpenSSH
server in a throwaway lab clone.

    python scripts/ssh-vm-test.py [--reuse] [--keep]

The clone (`winclone start --rdp`, headless) gets Windows' OpenSSH Server
on port 3390 (one of the two guest ports this PC reaches), a throwaway
ed25519 key made for this run, and a random password for its user.

1. Jump host (RDP-88): Remora on this PC opens a real RDP session to the
   clone's own RDP server *through* the clone's sshd (`--jump`, key file,
   pinned host key), headless, and takes a screenshot. A wrong pinned key
   must refuse before any sign-in.
2. Terminal (RDP-87): inside the clone's session, `remora --ssh` starts
   ssh.exe in Windows Terminal the way the connection manager does, with a
   title that starts with a dash and has a semicolon. The check reads the
   command line ssh.exe really got (so Windows Terminal passed `-p`, `-l`,
   `-i` and `--` through) and sshd's log for the key sign-in.

Nothing touches this PC's desktop, its known_hosts or Remora's settings:
host keys are pinned on the command line. `stop` discards the clone unless
--keep.
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
SSH_PORT = 3390  # guest port; this PC reaches it as 13390
HOST_SSH = 13390
SSHD = r"C:\ProgramData\ssh"

SETUP_SSHD = r"""
$ErrorActionPreference = 'Stop'
if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) {
    $c = Get-WindowsCapability -Online -Name OpenSSH.Server*
    Add-WindowsCapability -Online -Name $c.Name | Out-Null
}
# The first start writes sshd_config and the host keys.
if (-not (Test-Path 'C:\ProgramData\ssh\sshd_config')) {
    Start-Service sshd; Stop-Service sshd
}
Stop-Service sshd -ErrorAction SilentlyContinue
$cfg = 'C:\ProgramData\ssh\sshd_config'
$t = Get-Content -Raw $cfg
$t = $t -replace '(?m)^#?Port \d+', 'Port PORT'
Set-Content -Path $cfg -Value $t -Encoding ascii
if (-not (Get-NetFirewallRule -Name remora-ssh-test -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name remora-ssh-test -DisplayName 'Remora SSH test' -Direction Inbound `
        -Protocol TCP -LocalPort PORT -Action Allow | Out-Null
}
# The run's public key, for an administrator and for a plain user.
$pub = Get-Content -Raw 'G\id.pub'
Set-Content -Path 'C:\ProgramData\ssh\administrators_authorized_keys' -Value $pub -Encoding ascii
icacls 'C:\ProgramData\ssh\administrators_authorized_keys' /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null
Start-Service sshd
(Get-Service sshd).Status
& 'C:\Windows\System32\OpenSSH\ssh-keygen.exe' -lf 'C:\ProgramData\ssh\ssh_host_ed25519_key.pub'
""".replace("PORT", str(SSH_PORT)).replace("G\\", h.G + "\\")

USER_SSH = r"""
$ErrorActionPreference = 'Stop'
$d = Join-Path $env:USERPROFILE '.ssh'
New-Item -ItemType Directory -Force $d | Out-Null
Copy-Item 'G\id.pub' (Join-Path $d 'authorized_keys') -Force
# ssh in the terminal must not stop at an unknown host key (keyscan's
# comments on stderr are not errors).
cmd /c "C:\Windows\System32\OpenSSH\ssh-keyscan.exe -p PORT 127.0.0.1 2>nul" |
    Set-Content -Path (Join-Path $d 'known_hosts') -Encoding ascii
$env:USERNAME
""".replace("PORT", str(SSH_PORT)).replace("G\\", h.G + "\\")

# The private key into the user's .ssh, owned by the user and readable by
# nobody else (ssh refuses a key others can read). Elevated: the pushed
# file belongs to the guest agent.
USER_KEY = r"""
$ErrorActionPreference = 'Stop'
$k = 'C:\Users\USER\.ssh\id_remora_test'
Move-Item 'G\id' $k -Force
icacls $k /setowner 'USER' | Out-Null
icacls $k /inheritance:r /grant 'USER:F' /grant 'SYSTEM:F' | Out-Null
'key in place'
""".replace("G\\", h.G + "\\")

# What Windows Terminal handed to ssh.exe, and sshd's record of the sign-in.
SSH_SEEN = r"""
$p = Get-CimInstance Win32_Process -Filter "Name='ssh.exe'" | Select-Object -First 1
'CMDLINE ' + $p.CommandLine
$e = Get-WinEvent -LogName 'OpenSSH/Operational' -MaxEvents 50 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'Accepted publickey for (\S+) from 127\.0\.0\.1' } | Select-Object -First 1
'ACCEPTED ' + $e.Message
Get-Process WindowsTerminal -ErrorAction SilentlyContinue | ForEach-Object { 'WT ' + $_.MainWindowTitle }
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reuse", action="store_true", help="use the running clone")
    ap.add_argument("--keep", action="store_true", help="leave the clone running")
    a = ap.parse_args()
    meta = json.loads(subprocess.run(["cargo", "metadata", "--format-version", "1", "--no-deps"],
                                     cwd=ROOT, capture_output=True, text=True, check=True).stdout)
    target = Path(meta["target_directory"])
    subprocess.run(["cargo", "build", "--release", "-p", "remora-client", "--message-format=short"],
                   cwd=ROOT, check=True)
    remora = target / "release" / "remora.exe"
    work = Path(tempfile.mkdtemp(prefix="ssh-vm-"))
    results = []

    def check(name, ok, detail=""):
        results.append(bool(ok))
        h.log(f"{'PASS' if ok else 'FAIL'} {name} {detail}")

    try:
        running = "running" in h.wc("status")
        if not (a.reuse and running):
            h.wc("start", "--rdp", "--minutes", "60", timeout=900)
        # A throwaway key for this run only.
        key = work / "id"
        subprocess.run([r"C:\Windows\System32\OpenSSH\ssh-keygen.exe", "-q", "-t", "ed25519",
                        "-N", "", "-C", "remora-ssh-test", "-f", str(key)], check=True,
                       stdin=subprocess.DEVNULL, capture_output=True)
        h.wc("push", str(key), h.G + r"\id")
        h.wc("push", str(key) + ".pub", h.G + r"\id.pub")
        out = h.ps(SETUP_SSHD, timeout=1500, elevated=True)
        fp = re.search(r"SHA256:[A-Za-z0-9+/]{43}", out)
        check("sshd up on the clone's port 3390", "Running" in out and fp, fp.group(0) if fp else out[-400:])
        if not fp:
            return 1
        user = h.ps(USER_SSH).strip().splitlines()[-1]
        h.ps(USER_KEY.replace("USER", user), elevated=True)
        pw = "Rm-" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(20)) + "!9"
        f = work / "pw.txt"
        f.write_text(pw, encoding="ascii")
        h.wc("push", str(f), h.G + r"\pw.txt")
        f.unlink()
        h.ps(rf"$p = Get-Content -Raw '{h.G}\pw.txt'; Remove-Item '{h.G}\pw.txt'; net user $env:USERNAME $p.Trim() | Out-Null",
             elevated=True)
        env = dict(os.environ, RDP_PASSWORD=pw)

        def run(*extra, timeout=180):
            r = subprocess.run([str(remora), "localhost", "-u", user, "-v",
                                "--jump", f"{user}@127.0.0.1:{HOST_SSH}", "--jump-key", str(key), *extra],
                               env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                               errors="replace", timeout=timeout)
            return r.returncode, r.stdout + r.stderr

        # 1a. A wrong pinned key: refused before any sign-in.
        code, out = run("--expect-jump-fingerprint", "SHA256:" + "A" * 43,
                        "--screenshot", str(work / "no.png"), "--wait", "2")
        check("a wrong jump host key is refused", code != 0 and "not trusted" in out
              and not (work / "no.png").exists(), f"exit {code}")
        # 1b. The right key: the RDP certificate is asked about next.
        code, out = run("--expect-jump-fingerprint", fp.group(0),
                        "--screenshot", str(work / "x.png"), "--wait", "2")
        cert = re.search(r"--expect-fingerprint ([0-9a-f]{64})", out)
        check("through the jump host to the PC's certificate check", cert is not None
              and "tunnel to localhost:3389" in out, f"exit {code}")
        if cert:
            t = time.time()
            code, out = run("--expect-jump-fingerprint", fp.group(0), "--expect-fingerprint", cert.group(1),
                            "--screenshot", str(work / "jump.png"), "--wait", "5")
            (work / "jump.log").write_text(out, encoding="utf-8")
            check("RDP session through the SSH jump host", code == 0 and (work / "jump.png").exists(),
                  f"exit {code}, {time.time() - t:.0f} s; {work / 'jump.png'}, log {work / 'jump.log'}")
            if code != 0:
                h.log("\n".join(l for l in out.splitlines() if "rror" in l or "ssh" in l)[-1500:])

        # 2. ssh.exe in Windows Terminal, started by Remora inside the clone.
        h.wc("push", str(remora), r"C:\remora\remora.exe", timeout=600)
        title = "-Lab; ssh"
        out = h.wc("exec", rf'C:\remora\remora.exe --ssh {user}@127.0.0.1:{SSH_PORT} '
                           rf'--ssh-key %USERPROFILE%\.ssh\id_remora_test --title "{title}"',
                   "-TimeoutSec", "60", timeout=120)
        check("remora --ssh starts Windows Terminal", "wt.exe" in out, out.strip()[-300:])
        seen = ""
        for _ in range(30):
            time.sleep(2)
            seen = h.ps(SSH_SEEN)
            if "Accepted publickey for" in seen:
                break
        cmd = re.search(r"CMDLINE (.*)", seen)
        cmd = cmd.group(1).strip() if cmd else ""
        want = f"-p {SSH_PORT} -l {user} -i"
        check("ssh.exe got -p, -l, -i and -- from Windows Terminal",
              want in cmd and cmd.rstrip().endswith("-- 127.0.0.1"), cmd)
        check("the key sign-in reached sshd", "Accepted publickey for" in seen,
              (re.search(r"ACCEPTED (.*)", seen) or [None, ""])[1][:120])
        h.log("terminal: " + "; ".join(l for l in seen.splitlines() if l.startswith("WT ")))
    finally:
        if not a.keep:
            try:
                h.wc("stop")
                h.log("clone stopped")
            except Exception as e:
                h.log(f"could not stop the clone: {e}")
        for p in [work / "id"]:
            try:
                p.unlink()
            except OSError:
                pass
    h.log(f"{sum(results)} passed, {len(results) - sum(results)} failed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())

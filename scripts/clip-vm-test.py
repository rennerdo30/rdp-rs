#!/usr/bin/env python3
"""End-to-end clipboard test against a real Windows RDP server (RDP-62, RDP-63).

    python scripts/clip-vm-test.py [--big-gib 4.3] [--keep] [--winclone <winclone.ps1>]

A throwaway clone of the renner.dev OS lab's Windows VM is the server
(`winclone start --rdp --headless`: Remote Desktop on, guest 3389 at
127.0.0.1:13389, no window on this PC). The script gives the clone's user a
random password for this run and connects `examples/clip_e2e` (a client
with a scripted clipboard: this PC's clipboard and desktop are never
touched). Then, in both directions, it copies:

- text and an image;
- a folder tree with a file over 4 GiB (a sparse file here, an unwritten
  `fsutil` file there, so nothing large is written except the final paste
  into the clone), compared by SHA-256.

Server-side steps run as PowerShell in the clone user's session, which is
the RDP session once the client is logged on. `stop` discards every change
in the clone, also on errors. Every wait has a timeout.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import queue
import secrets
import string
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent
WINCLONE = r"E:\AgentData\renneros-lab\winclone\winclone.ps1"
PWSH = "pwsh"
GUEST = r"C:\Users\Public\e2e"
HOST_PORT = 13389


def log(msg: str) -> None:
    print(time.strftime("%H:%M:%S"), msg, flush=True)


class Clone:
    def __init__(self, script: str):
        self.script = script

    def run(self, *args: str, timeout: int = 300, stdin: str | None = None) -> str:
        cmd = [PWSH, "-NoProfile", "-File", self.script, *args]
        p = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout)
        if p.returncode != 0:
            raise RuntimeError(f"winclone {args[0]} failed ({p.returncode}): {p.stdout}{p.stderr}")
        return p.stdout

    def ps(self, script: str, timeout: int = 300, elevated: bool = False) -> str:
        """Runs a PowerShell script in the user's session (or elevated)."""
        local = Path(tempfile.mkdtemp()) / f"step{secrets.token_hex(4)}.ps1"
        script = "[Console]::OutputEncoding = [Text.Encoding]::UTF8\n" + script
        local.write_text(script, encoding="utf-8-sig")
        guest = GUEST + "\\" + local.name
        self.run("push", str(local), guest)
        local.unlink()
        flags = ["-Elevated"] if elevated else []
        line = f'powershell -NoProfile -ExecutionPolicy Bypass -Sta -File "{guest}"'
        return self.run("exec", line, *flags, "-TimeoutSec", str(timeout), timeout=timeout + 60)


class Client:
    """examples/clip_e2e, driven over stdin/stdout."""

    def __init__(self, exe: Path, env: dict, trace: Path):
        self.trace = open(trace, "w", encoding="utf-8")
        self.p = subprocess.Popen(
            [str(exe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.trace,
            text=True, encoding="utf-8", env=env, bufsize=1,
        )
        self.lines: queue.Queue[str] = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        for line in self.p.stdout:
            self.lines.put(line.rstrip("\n"))
        self.lines.put("error client exited")

    def expect(self, word: str, timeout: float = 600) -> list[str]:
        """Collects lines until one starts with `word` (or `error`)."""
        got = []
        end = time.time() + timeout
        while True:
            line = self.lines.get(timeout=max(0.1, end - time.time()))
            got.append(line)
            if line.startswith("error"):
                raise RuntimeError(f"client: {line}")
            if line.split(" ", 1)[0] == word:
                return got

    def cmd(self, line: str, word: str | None = None, timeout: float = 600) -> list[str]:
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()
        return self.expect(word or line.split(" ", 1)[0], timeout)

    def close(self) -> None:
        try:
            self.p.stdin.write("quit\n")
            self.p.stdin.flush()
            self.p.wait(timeout=10)
        except Exception:
            self.p.kill()  # our own child only
            self.p.wait()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8 << 20):
            h.update(chunk)
    return h.hexdigest()


def make_sparse(path: Path, size: int) -> None:
    path.write_bytes(b"")
    subprocess.run(["fsutil", "sparse", "setflag", str(path)], check=True, capture_output=True)
    with open(path, "r+b") as f:
        f.truncate(size)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--big-gib", type=float, default=4.3)
    ap.add_argument("--keep", action="store_true", help="leave the clone running at the end")
    ap.add_argument("--winclone", default=WINCLONE)
    a = ap.parse_args()
    big = int(a.big_gib * (1 << 30))

    log("building examples/clip_e2e")
    subprocess.run(["cargo", "build", "--release", "-p", "rdp", "--example", "clip_e2e",
                    "--message-format=short"], cwd=ROOT, check=True)
    meta = subprocess.run(["cargo", "metadata", "--format-version", "1", "--no-deps"], cwd=ROOT,
                          capture_output=True, text=True, check=True).stdout
    import json
    target = Path(json.loads(meta)["target_directory"])
    exe = target / "release" / "examples" / "clip_e2e.exe"

    work = Path(tempfile.mkdtemp(prefix="clip-e2e-"))
    clone = Clone(a.winclone)
    client = None
    results: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        results.append((name, ok, detail))
        log(f"{'PASS' if ok else 'FAIL'} {name} {detail}")

    try:
        log("starting the clone (Remote Desktop on, headless: no window here)")
        clone.run("start", "--rdp", "--headless", "--minutes", "90", timeout=900)
        log("test password for the clone's user")
        alphabet = string.ascii_letters + string.digits
        password = "Rm-" + "".join(secrets.choice(alphabet) for _ in range(20)) + "!9"
        pw_file = work / "pw.txt"
        pw_file.write_text(password, encoding="ascii")
        clone.run("push", str(pw_file), GUEST + r"\pw.txt")
        clone.ps(rf"""
$ErrorActionPreference = 'Stop'
$p = Get-Content -Raw '{GUEST}\pw.txt'
Remove-Item '{GUEST}\pw.txt'
net user $env:USERNAME $p.Trim() | Out-Null
'ok'
""", elevated=True)
        user = clone.ps("$env:USERNAME").strip().splitlines()[-1]

        log("preparing server files")
        clone.ps(rf"""
$ErrorActionPreference = 'Stop'
$s = '{GUEST}\src\Remora folder'
New-Item -ItemType Directory -Force "$s\sub\deeper" | Out-Null
New-Item -ItemType Directory -Force "$s\empty dir" | Out-Null
New-Item -ItemType Directory -Force '{GUEST}\dst' | Out-Null
Set-Content -Encoding utf8 "$s\readme $([char]0xFC).txt" 'hello from the server'
$b = New-Object byte[] (5MB + 123); (New-Object Random 42).NextBytes($b)
[IO.File]::WriteAllBytes("$s\sub\random.bin", $b)
[IO.File]::WriteAllBytes("$s\sub\deeper\empty.txt", @())
fsutil file createnew "$s\huge.bin" {big} | Out-Null
'ok'
""")
        log("connecting the test client as the clone's user")
        env = dict(os.environ, E2E_HOST="127.0.0.1", E2E_PORT=str(HOST_PORT), E2E_USER=user,
                   E2E_PASSWORD_FILE=str(pw_file))
        trace = Path(tempfile.gettempdir()) / "clip-e2e-client.log"
        env["E2E_TRACE"] = "1"  # the client's protocol trace (credentials redacted)
        client = Client(exe, env, trace)
        log(f"client trace: {trace}")
        client.expect("connected", timeout=120)
        pw_file.unlink()
        # A copy made before rdpclip runs in the new session is never
        # announced: wait for it (at most 90 s), then a little more.
        out = clone.ps(r"""
$end = (Get-Date).AddSeconds(90)
while (-not (Get-Process rdpclip -ErrorAction SilentlyContinue) -and (Get-Date) -lt $end) { Start-Sleep 1 }
if (Get-Process rdpclip -ErrorAction SilentlyContinue) { 'rdpclip up' } else { 'no rdpclip' }
""", timeout=150)
        log(out.strip().splitlines()[-1])
        time.sleep(3)

        # ---- server -> PC: text
        # Non-ASCII from code points: the pushed scripts stay ASCII.
        clone.ps("Set-Clipboard -Value \"h$([char]0xE9)llo from the server $([char]0x2713)\"")
        client.cmd("wait-offer text", "offer", timeout=60)
        out = client.cmd("get-text", "text", timeout=60)[-1]
        check("server->pc text", out == "text h\u00e9llo from the server \u2713", out)

        # ---- server -> PC: image
        clone.ps(r"""
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
$b = New-Object Drawing.Bitmap 123, 45
$g = [Drawing.Graphics]::FromImage($b); $g.Clear([Drawing.Color]::Orange); $g.Dispose()
[Windows.Forms.Clipboard]::SetImage($b)
'ok'
""")
        offer = client.cmd("wait-offer dib", "offer", timeout=60)[-1]
        out = client.cmd("get-dib", "dib", timeout=60)[-1]
        parts = out.split()
        check("server->pc image", len(parts) == 5 and parts[2:4] == ["123", "45"], f"{offer}; {out}")

        # ---- server -> PC: folder tree with a big file
        hashes = clone.ps(rf"""
Get-ChildItem -Recurse -File '{GUEST}\src' | ForEach-Object {{
  "{{0}}|{{1}}" -f [uri]::EscapeDataString($_.FullName.Substring('{GUEST}\src\'.Length)), (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLower()
}}
""", timeout=900)
        want = {unquote(k): v for k, v in (l.strip().split("|", 1) for l in hashes.splitlines() if "|" in l)}
        clone.ps(rf"Set-Clipboard -Path '{GUEST}\src\Remora folder'")
        client.cmd("wait-offer files", "offer", timeout=60)
        lines = client.cmd("get-files", "files", timeout=3600)
        got = {}
        for l in lines:
            p = l.split(" ")
            if p[0] == "file" and p[-1] != "dir":
                got[" ".join(p[1:-2])] = p[-1]
        check("server->pc folder tree", got == want, f"{len(got)} files; {lines[-1]}")
        dirs = [l for l in lines if l.endswith(" dir")]
        check("server->pc empty folders listed", any("empty dir" in d for d in dirs), str(dirs))

        # ---- PC -> server: text
        client.cmd("set-text Grüße vom PC ✓", "set-text")
        time.sleep(1)
        # Compared as UTF-16 code units: no console encoding in between.
        out = clone.ps("((Get-Clipboard -Raw).ToCharArray() | ForEach-Object { [int]$_ }) -join ' '")
        want = " ".join(str(ord(c)) for c in "Grüße vom PC ✓")
        check("pc->server text", out.strip().splitlines()[-1].strip() == want, out.strip())

        # ---- PC -> server: image
        client.cmd("set-dib 64 48", "set-dib")
        time.sleep(1)
        out = clone.ps(r"""
Add-Type -AssemblyName System.Windows.Forms
$i = [Windows.Forms.Clipboard]::GetImage()
if ($i) { "{0}x{1}" -f $i.Width, $i.Height } else { 'none' }
""").strip()
        check("pc->server image", out.endswith("64x48"), out)

        # ---- PC -> server: folder trees
        def tree(root: Path, huge: bool) -> dict:
            (root / "deep" / "deeper").mkdir(parents=True)
            (root / "empty dir").mkdir()
            (root / "notes \u00e4.txt").write_text("from the pc\n", encoding="utf-8")
            (root / "deep" / "random.bin").write_bytes(os.urandom(3 * (1 << 20) + 77))
            (root / "deep" / "deeper" / "zero.txt").write_bytes(b"")
            if huge:
                make_sparse(root / "huge.bin", big)
            return {str(f.relative_to(root.parent)).replace("/", "\\"): sha256_file(f)
                    for f in sorted(root.rglob("*")) if f.is_file()}

        def listing(out: str) -> dict:
            return {unquote(k): v for k, v in (l.strip().split("|", 1) for l in out.splitlines() if "|" in l)}

        list_ps = r"""
Get-ChildItem -Recurse -File $d | ForEach-Object {
  "{0}|{1}" -f [uri]::EscapeDataString($_.FullName.Substring($d.Length + 1)), (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLower()
}
"""
        # Explorer itself pastes (in the session's own logon session: a
        # process started by the test runs in another one, and OLE then
        # hides the per-file FileContents of rdpclip's data object).
        def explorer_paste(dest: str, total: int, minutes: int) -> str:
            return clone.ps(rf"""
$d = '{dest}'
New-Item -ItemType Directory -Force $d | Out-Null
$sh = New-Object -ComObject Shell.Application
$sh.Open($d)
$w = $null
for ($i = 0; $i -lt 30 -and -not $w; $i++) {{
  Start-Sleep 1
  $w = $sh.Windows() | Where-Object {{ try {{ $_.Document.Folder.Self.Path -eq $d }} catch {{ $false }} }} | Select-Object -First 1
}}
if (-not $w) {{ 'no explorer window'; exit }}
$w.Document.Folder.Self.InvokeVerb('Paste')
$end = (Get-Date).AddMinutes({minutes})
do {{
  Start-Sleep -Seconds 2
  $n = (Get-ChildItem -Recurse -File $d -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
}} while ($n -lt {total} -and (Get-Date) -lt $end)
Start-Sleep -Seconds 3
""" + list_ps, timeout=minutes * 60 + 600)

        small = work / "Small tree"
        want = tree(small, huge=False)
        client.cmd(f"set-files {small}", "set-files")
        time.sleep(1)
        total = sum(f.stat().st_size for f in small.rglob("*") if f.is_file())
        out = explorer_paste(GUEST + r"\dst-small", total, 3)
        got = listing(out)
        check("pc->server folder (Explorer paste)", got == want, f"{len(got)}/{len(want)} files")
        check("pc->server empty folder", bool(clone.ps(
            rf"if (Test-Path '{GUEST}\dst-small\Small tree\empty dir') {{ 'EMPTYDIR' }}").strip()))

        up = work / "Upload tree"
        want = tree(up, huge=True)
        total = sum(f.stat().st_size for f in up.rglob("*") if f.is_file())
        client.cmd(f"set-files {up}", "set-files")
        time.sleep(1)
        t = time.time()
        out = explorer_paste(GUEST + r"\dst", total, 40)
        secs = time.time() - t
        got = listing(out)
        check("pc->server folder with a file over 4 GiB (Explorer paste)", got == want,
              f"{len(got)}/{len(want)} files, {total / secs / 1e6:.0f} MB/s incl. hashing")
    except Exception as e:
        check("run", False, repr(e))
    finally:
        if client:
            client.close()
        if not a.keep:
            try:
                clone.run("stop", timeout=300)
                log("clone stopped (all changes discarded)")
            except Exception as e:
                log(f"could not stop the clone: {e}")
        for f in sorted(work.rglob("*"), reverse=True):
            f.unlink() if f.is_file() else f.rmdir()
        work.rmdir()
    failed = [r for r in results if not r[1]]
    log(f"{len(results) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

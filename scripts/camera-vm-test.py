#!/usr/bin/env python3
"""End-to-end camera redirection test against a real Windows RDP server (RDP-75).

    python scripts/camera-vm-test.py [--keep] [--winclone <winclone.ps1>]

The same throwaway clone of the renner.dev OS lab's Windows VM as
`clip-vm-test.py` is the server (`winclone start --rdp --headless`: no
window on this PC). The client is `examples/camera_e2e`, which shares one
synthetic camera ("Remora Test Camera", a moving test pattern in YUY2 or
NV12): no camera of this PC is listed or opened.

Checks, in the clone user's session (the RDP session):
- the server negotiates the protocol version and the camera appears among
  the session's video capture devices (WinRT DeviceInformation);
- an app in the session (WinRT MediaCapture) takes a photo from it: the
  client sees media types asked, a stream started, samples sent, and the
  stream stopped when the app closes the camera.

`stop` discards every change in the clone, also on errors. Every wait has
a timeout.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import secrets
import string
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The clone and client helpers of the clipboard test.
_spec = importlib.util.spec_from_file_location("clipvm", ROOT / "scripts" / "clip-vm-test.py")
clipvm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(clipvm)
Clone, Client, log = clipvm.Clone, clipvm.Client, clipvm.log
GUEST, HOST_PORT, WINCLONE = clipvm.GUEST, clipvm.HOST_PORT, clipvm.WINCLONE

# WinRT from Windows PowerShell 5.1: await IAsyncOperation / IAsyncAction.
WINRT = r"""
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$ext = [System.WindowsRuntimeSystemExtensions].GetMethods()
$opT = ($ext | ? { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
    $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
$actT = ($ext | ? { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
    $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncAction' })[0]
function Await($op, $type) {
    $t = $opT.MakeGenericMethod($type).Invoke($null, @($op))
    if (-not $t.Wait(30000)) { throw 'timed out' }
    $t.Result
}
function AwaitAction($op) {
    $t = $actT.Invoke($null, @($op))
    if (-not $t.Wait(30000)) { throw 'timed out' }
}
[Windows.Devices.Enumeration.DeviceInformation, Windows.Devices.Enumeration, ContentType = WindowsRuntime] | Out-Null
[Windows.Media.Capture.MediaCapture, Windows.Media.Capture, ContentType = WindowsRuntime] | Out-Null
[Windows.Storage.Streams.InMemoryRandomAccessStream, Windows.Storage.Streams, ContentType = WindowsRuntime] | Out-Null
function Cameras {
    Await ([Windows.Devices.Enumeration.DeviceInformation]::FindAllAsync(
        [Windows.Devices.Enumeration.DeviceClass]::VideoCapture)) `
        ([Windows.Devices.Enumeration.DeviceInformationCollection])
}
"""

LIST = WINRT + r"""
$end = (Get-Date).AddSeconds(60)
do {
    $found = @(Cameras | ? { $_.Name -like '*Remora Test Camera*' })
    if ($found.Count) { break }
    Start-Sleep 2
} while ((Get-Date) -lt $end)
Cameras | % { "camera: $($_.Name)" }
if ($found.Count) { 'found' } else { 'missing' }
"""

PHOTO = WINRT + r"""
$dev = @(Cameras | ? { $_.Name -like '*Remora Test Camera*' })[0]
$s = New-Object Windows.Media.Capture.MediaCaptureInitializationSettings
$s.VideoDeviceId = $dev.Id
$s.StreamingCaptureMode = [Windows.Media.Capture.StreamingCaptureMode]::Video
$mc = New-Object Windows.Media.Capture.MediaCapture
AwaitAction ($mc.InitializeAsync($s))
$stream = New-Object Windows.Storage.Streams.InMemoryRandomAccessStream
$jpeg = [Windows.Media.MediaProperties.ImageEncodingProperties]::CreateJpeg()
AwaitAction ($mc.CapturePhotoToStreamAsync($jpeg, $stream))
"photo $($stream.Size) bytes"
$mc.Dispose()
'closed'
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true", help="leave the clone running at the end")
    ap.add_argument("--winclone", default=WINCLONE)
    a = ap.parse_args()

    log("building examples/camera_e2e")
    subprocess.run(["cargo", "build", "--release", "-p", "rdp", "--example", "camera_e2e",
                    "--message-format=short"], cwd=ROOT, check=True, timeout=1800)
    meta = subprocess.run(["cargo", "metadata", "--format-version", "1", "--no-deps"], cwd=ROOT,
                          capture_output=True, text=True, check=True, timeout=120).stdout
    exe = Path(json.loads(meta)["target_directory"]) / "release" / "examples" / "camera_e2e.exe"

    work = Path(tempfile.mkdtemp(prefix="camera-e2e-"))
    clone = Clone(a.winclone)
    client = None
    results: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        results.append((name, ok, detail))
        log(f"{'PASS' if ok else 'FAIL'} {name} {detail}")

    try:
        log("starting the clone (Remote Desktop on, headless: no window here)")
        clone.run("start", "--rdp", "--headless", "--minutes", "60", timeout=900)
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

        log("connecting the test client as the clone's user")
        env = dict(os.environ, E2E_HOST="127.0.0.1", E2E_PORT=str(HOST_PORT), E2E_USER=user,
                   E2E_PASSWORD_FILE=str(pw_file), E2E_TRACE="1")
        trace = Path(tempfile.gettempdir()) / "camera-e2e-client.log"
        client = Client(exe, env, trace)
        log(f"client trace: {trace}")
        client.expect("connected", timeout=120)
        pw_file.unlink()
        got = client.expect("version", timeout=120)
        check("version negotiated", True, got[-1])

        out = clone.ps(LIST, timeout=120)
        log(out.strip())
        check("camera listed in the session", out.strip().splitlines()[-1] == "found")

        out = clone.ps(PHOTO, timeout=120)
        log(out.strip())
        lines = out.strip().splitlines()
        check("photo taken in the session", any(l.startswith("photo ") for l in lines), lines[-1])
        seen = client.expect("stop", timeout=60)
        check("media types asked", "media-types" in seen)
        check("stream started", any(l.startswith("start ") for l in seen))
        check("samples sent", any(l.startswith("sample ") for l in seen))
        check("stream stopped after the app closed it", seen[-1] == "stop")
    except Exception as e:
        check("run", False, str(e))
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

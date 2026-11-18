#!/usr/bin/env python3
"""Live check of video redirection (RDP-76): does Windows send video as
Video Optimized Remoting (MS-RDPEVOR) placed by geometry tracking
(MS-RDPEGT), and does Remora show it?

    python scripts/video-vm-test.py [--seconds 40] [--variants default,tuned]

A throwaway lab clone (`winclone start --rdp`, headless) runs Windows' own
RDP server. In the user's session a small window plays "video": moving
colour bars over changing noise at 30 fps, 480 x 270, for the whole run.
The headless client (`remora --gfx --video -v --screenshot`) stays
connected for the given time; its trace shows which dynamic channels the
server opened, the presentations it started and the frames Remora decoded
and showed (the "video redirection:" statistics line).

Variants:
- `default`: the server as installed.
- `tuned`: after Remora's Improve (`remora-agent tune apply`: AVC444
  preferred, as on a server that sends the whole desktop as H.264).
- `novideo`: `--gfx` without `--video`: whether the server even asks for
  the video channels (they are refused, "not found" in the trace).

For each variant it prints: the video channels the server opened (or asked
for), presentations, samples decoded, frames shown, decoding time, and how
much of the screenshot is lit. Nothing appears on this PC; the clone is
discarded. Exit 0 when a variant with `--video` showed at least 30 frames
of a presentation; 1 otherwise (then the trace says whether the server did
not use VOR at all, which answers the "when does Windows use it" question,
or whether Remora failed).
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
from importlib import import_module
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
h = import_module("helper-vm-test")  # wc, ps, log, G
d = import_module("decode-vm-test")  # lit_share
ROOT = Path(__file__).resolve().parent.parent

CHANNELS = {
    "control": "Microsoft::Windows::RDS::Video::Control::v08.01",
    "data": "Microsoft::Windows::RDS::Video::Data::v08.01",
    "geometry": "Microsoft::Windows::RDS::Geometry::v08.01",
}

# A 480 x 270 window at (120, 120) repainting at 30 fps: colour bars that
# move and a band of fresh noise, so the server's classifier sees video.
VIDEO_WINDOW = r"""
param([int]$Seconds = 60)
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
$w = 480; $h = 270
$f = New-Object System.Windows.Forms.Form
$f.Text = 'Remora video test'; $f.StartPosition = 'Manual'
$f.Location = New-Object System.Drawing.Point(120, 120)
$f.ClientSize = New-Object System.Drawing.Size($w, $h); $f.TopMost = $true
$pb = New-Object System.Windows.Forms.PictureBox; $pb.Dock = 'Fill'; $f.Controls.Add($pb)
$bmp = New-Object System.Drawing.Bitmap($w, $h, [System.Drawing.Imaging.PixelFormat]::Format32bppRgb)
$buf = New-Object byte[] ($w * $h * 4); $noise = New-Object byte[] ($w * 90 * 4)
$rnd = New-Object System.Random; $script:n = 0
$end = (Get-Date).AddSeconds($Seconds)
$t = New-Object System.Windows.Forms.Timer; $t.Interval = 33
$t.Add_Tick({
  if ((Get-Date) -gt $end) { $f.Close(); return }
  $script:n++
  for ($x = 0; $x -lt $w; $x++) {
    $c = (($x + 4 * $script:n) % $w) * 255 / $w
    for ($y = 0; $y -lt 180; $y += 4) {
      $i = ($y * $w + $x) * 4; $buf[$i] = $c; $buf[$i + 1] = 255 - $c; $buf[$i + 2] = ($c * 3) % 256
    }
  }
  $rnd.NextBytes($noise); [Array]::Copy($noise, 0, $buf, 180 * $w * 4, $noise.Length)
  $r = New-Object System.Drawing.Rectangle(0, 0, $w, $h)
  $bd = $bmp.LockBits($r, 'WriteOnly', $bmp.PixelFormat)
  [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $bd.Scan0, $buf.Length)
  $bmp.UnlockBits($bd); $pb.Image = $bmp; $pb.Invalidate()
})
$t.Start(); [System.Windows.Forms.Application]::Run($f)
"""


def summarize(text: str) -> dict:
    """What the trace says about the video channels and the statistics line."""
    out = {}
    for key, name in CHANNELS.items():
        if re.search(rf"dvc create {re.escape(name)} \(\d+\)$", text, re.M):
            out[key] = "opened"
        elif f'dvc create "{name}"' in text:
            out[key] = "asked, refused"
        else:
            out[key] = "not asked"
    out["starts"] = len(re.findall(r"^\[rdp\] video \d+: start ", text, re.M))
    m = re.search(r"^video redirection: (\d+) presentations, (\d+) samples decoded, "
                  r"(\d+) frames shown, (\d+) skipped, ([\d.]+) ms", text, re.M)
    if m:
        out.update(presentations=int(m[1]), decoded=int(m[2]), shown=int(m[3]),
                   skipped=int(m[4]), ms=float(m[5]))
    out["not_offered"] = "video redirection not offered" in text
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=40)
    ap.add_argument("--variants", default="default,tuned,novideo")
    a = ap.parse_args()
    variants = a.variants.split(",")
    meta = json.loads(subprocess.run(["cargo", "metadata", "--format-version", "1", "--no-deps"],
                                     cwd=ROOT, capture_output=True, text=True, check=True).stdout)
    target = Path(meta["target_directory"])
    static = Path(str(target) + "-static")
    if "tuned" in variants:
        subprocess.run(["cargo", "build", "--release", "--locked", "-p", "remora-agent",
                        "--target-dir", str(static), "--message-format=short"], cwd=ROOT,
                       env=dict(os.environ, RUSTFLAGS="-C target-feature=+crt-static"), check=True)
    subprocess.run(["cargo", "build", "--release", "-p", "remora", "--message-format=short"],
                   cwd=ROOT, check=True)
    remora = target / "release" / "remora.exe"
    agent = static / "release" / "remora-agent.exe"
    work = Path(tempfile.mkdtemp(prefix="video-"))
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
        h.log(h.ps("(Get-CimInstance Win32_OperatingSystem).Caption").strip())
        win = work / "video-window.ps1"
        win.write_text(VIDEO_WINDOW, encoding="utf-8-sig")
        h.wc("push", str(win), h.G + r"\video-window.ps1")
        # -v writes Remora's diagnostic log under LOCALAPPDATA: keep it in
        # the work folder, not over this PC's own log.
        local = work / "localappdata"
        local.mkdir()
        env = dict(os.environ, RDP_PASSWORD=pw, LOCALAPPDATA=str(local))
        host = "127.0.0.1:13389"
        r = subprocess.run([str(remora), host, "-u", user, "--screenshot", str(work / "x.png"),
                            "--wait", "5"], env=env, stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=120)
        m = re.search(r"--expect-fingerprint ([0-9a-f]{64})", r.stdout + r.stderr)
        if not m:
            h.log((r.stdout + r.stderr)[-800:])
            return 1
        fp = m.group(1)
        order = [v for v in ("default", "novideo", "tuned") if v in variants]
        for variant in order:
            if variant == "tuned":
                h.wc("push", str(agent), h.G + r"\remora-agent.exe")
                h.log(h.ps(rf"& '{h.G}\remora-agent.exe' tune apply | Out-String", elevated=True).strip())
            h.wc("exec-background",
                 rf'powershell -NoProfile -ExecutionPolicy Bypass -File "{h.G}\video-window.ps1" -Seconds {a.seconds + 40}')
            flags = ["--gfx"] + ([] if variant == "novideo" else ["--video"])
            out = subprocess.run([str(remora), host, "-u", user, "--expect-fingerprint", fp, *flags, "-v",
                                  "--size", "1280x800", "--screenshot", str(work / f"{variant}.png"),
                                  "--record", str(work / f"{variant}.mp4"), "--wait", str(a.seconds)],
                                 env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                 errors="replace", timeout=a.seconds + 180)
            text = out.stdout + out.stderr
            (work / f"{variant}.log").write_text(text, encoding="utf-8")
            s = summarize(text)
            shot = work / f"{variant}.png"
            s["lit"] = d.lit_share(shot) if shot.exists() else 0.0
            s["exit"] = out.returncode
            rows.append((variant, s))
            h.log(f"{variant}: {s}")
    finally:
        try:
            h.wc("stop")
            h.log("clone stopped")
        except Exception as e:
            h.log(f"could not stop the clone: {e}")
        h.log(f"logs, screenshots and recordings in {work}")
    for variant, s in rows:
        chans = ", ".join(f"{k} {s[k]}" for k in CHANNELS)
        stats = (f"{s.get('presentations', 0)} presentations, {s.get('decoded', 0)} decoded, "
                 f"{s.get('shown', 0)} shown, {s.get('skipped', 0)} skipped, "
                 f"{s.get('ms', 0.0):.2f} ms/sample") if "decoded" in s else "no statistics line"
        print(f"{variant:>8}  {chans}; {stats}; picture {s['lit']:.0%} lit; exit {s['exit']}")
    ok = any(v != "novideo" and s.get("presentations", 0) > 0 and s.get("shown", 0) >= 30
             for v, s in rows)
    if not ok:
        print("no variant showed redirected video: see the logs (did the server open the video "
              "channels and start a presentation?)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

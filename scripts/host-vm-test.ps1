# Tests Remora Host end to end on a real Windows: a throwaway clone of the
# renner.dev OS lab's Windows VM (QEMU, GPU through Venus/Venera, or plain
# virtio-vga with -NoGpu). The server runs in the guest user's desktop
# session; Remora connects from this PC through the clone's port forward.
#
#   pwsh scripts/host-vm-test.ps1 [-NoGpu] [-BinDir <folder>] [-Wait 10] [-Capture auto|dxgi|gdi]
#                                 [-WinClone <winclone.ps1>] [-Interactive]
#
# The clone tool (`winclone.ps1`, from the renner.dev OS lab) starts the
# clone, copies files in, runs commands in the logged-on user's session, and
# `stop` discards every change. Only one clone runs at a time, and it shares
# this PC's GPU, so the script stops it right after the test, also on errors.
# Do not run it while the lab runs GPU benchmarks.
#
# Steps: build (static CRT, unless -BinDir), start the clone, copy
# remora-host.exe and a random test password in, allow port 3390 (the only
# elevated step), set the password and delete its file, read the certificate
# fingerprint, start the server in the background, wait for the port, then
# connect Remora headless (`--screenshot`, pinned with --expect-fingerprint).
# The screenshot and the server's log land in artifacts/host-vm/.
[CmdletBinding()]
param(
    [switch]$NoGpu,
    [string]$BinDir,
    [int]$Wait = 10,
    [ValidateSet('auto', 'dxgi', 'gdi')][string]$Capture = 'auto',
    [string]$WinClone = 'E:\AgentData\renneros-lab\winclone\winclone.ps1',
    [switch]$Interactive
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path -LiteralPath $WinClone)) { throw "clone tool not found: $WinClone" }
$pwsh = (Get-Process -Id $PID).Path

function Invoke-Bounded([string]$File, [string[]]$Arguments, [int]$Seconds, [hashtable]$Environment = @{}) {
    $info = [Diagnostics.ProcessStartInfo]::new($File)
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($a in $Arguments) { $info.ArgumentList.Add($a) }
    foreach ($k in $Environment.Keys) { $info.Environment[$k] = $Environment[$k] }
    $p = [Diagnostics.Process]::Start($info)
    $out = $p.StandardOutput.ReadToEndAsync()
    $err = $p.StandardError.ReadToEndAsync()
    try {
        if (-not $p.WaitForExit($Seconds * 1000)) {
            $p.Kill($true) # only this process and its own children
            $p.WaitForExit()
            throw "$(Split-Path -Leaf $File) timed out after $Seconds s"
        }
        [pscustomobject]@{ Code = $p.ExitCode; Out = $out.GetAwaiter().GetResult(); Err = $err.GetAwaiter().GetResult() }
    } finally { $p.Dispose() }
}

# One clone command; throws unless it exits 0. Returns its output.
function Clone([string[]]$Arguments, [int]$Seconds = 180) {
    $r = Invoke-Bounded $pwsh (@('-NoProfile', '-File', $WinClone) + $Arguments) $Seconds
    if ($r.Code) { throw "winclone $($Arguments[0]) failed ($($r.Code)): $($r.Out)$($r.Err)" }
    $r.Out
}

# Fails when the screenshot is one colour (a black or empty capture): the
# connection worked but the server saw no picture. Samples a 32 x 32 grid.
function Assert-Picture([string]$Png) {
    Add-Type -AssemblyName System.Drawing
    $bmp = [Drawing.Bitmap]::new($Png)
    try {
        $colours = [Collections.Generic.HashSet[int]]::new()
        for ($i = 0; $i -lt 32; $i++) {
            for ($j = 0; $j -lt 32; $j++) {
                $x = [int](($bmp.Width - 1) * $i / 31)
                $y = [int](($bmp.Height - 1) * $j / 31)
                [void]$colours.Add($bmp.GetPixel($x, $y).ToArgb())
            }
        }
        if ($colours.Count -lt 2) {
            throw "the picture is a single colour ($('{0:X8}' -f ($colours | Select-Object -First 1))): the server captured nothing"
        }
        Write-Host "Picture check: $($colours.Count) colours in a 32 x 32 sample"
    } finally { $bmp.Dispose() }
}

# --- binaries (static CRT: a clean Windows has no vcruntime140.dll)
Push-Location $root
try {
    if (-not $BinDir) {
        $meta = cargo metadata --format-version 1 --no-deps | ConvertFrom-Json
        $target = "$($meta.target_directory)-static"
        $env:RUSTFLAGS = '-C target-feature=+crt-static'
        cargo build --release --locked -p remora -p remora-host --target-dir $target
        if ($LASTEXITCODE) { throw 'build failed' }
        $BinDir = Join-Path $target 'release'
    }
} finally { Pop-Location }
$hostExe = Join-Path $BinDir 'remora-host.exe'
$client = Join-Path $BinDir 'remora.exe'
foreach ($f in @($hostExe, $client)) { if (-not (Test-Path -LiteralPath $f)) { throw "missing $f" } }

$stage = Join-Path ([IO.Path]::GetTempPath()) ('remora-vm-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage | Out-Null
$bytes = [byte[]]::new(18)
[Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$password = [Convert]::ToBase64String($bytes).Replace('+', 'x').Replace('/', 'y')
$pwFile = Join-Path $stage 'pw.txt'
Set-Content -LiteralPath $pwFile -Value $password -NoNewline -Encoding ascii
$out = Join-Path $root 'artifacts/host-vm'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$data = 'C:\Users\Public\remora\data'

$started = $false
$serverId = $null
try {
    # --- clone
    $startArgs = @('start', '--minutes', '30')
    if ($NoGpu) { $startArgs += '--no-gpu' }
    Clone $startArgs 300 | Out-Null
    $started = $true
    Write-Host "Clone started ($(if ($NoGpu) { 'virtio-vga' } else { 'GPU' }))"

    # --- server
    Clone @('push', $hostExe) | Out-Null
    Clone @('push', $pwFile) | Out-Null
    Remove-Item -LiteralPath $pwFile
    Clone @('exec', 'netsh advfirewall firewall add rule name="Remora Host" dir=in action=allow protocol=TCP localport=3390', '-Elevated') | Out-Null
    Clone @('exec', "C:\remora\remora-host.exe set-password --data-dir $data --password-file C:\remora\pw.txt") | Out-Null
    Clone @('exec', 'del C:\remora\pw.txt', '-Elevated') | Out-Null
    $fp = Clone @('exec', "C:\remora\remora-host.exe fingerprint --data-dir $data")
    $fingerprint = ([regex]::Match($fp, '([0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}')).Value
    if (-not $fingerprint) { throw "no certificate fingerprint from the guest: $fp" }
    # The server logs to stderr; the clone tool's log shows stdout.
    $bg = Clone @('exec-background', "C:\remora\remora-host.exe run --data-dir $data --capture $Capture --verbose 2>&1")
    # exec-background prints the run id alone on its first line.
    $serverId = ($bg -split "`r?`n")[0].Trim()
    if ($serverId -notmatch '^[A-Za-z0-9_-]+$') { throw "no run id from exec-background: $bg" }
    $addr = (Clone @('addr')).Trim()
    $hostPart, $portPart = $addr.Split(':')
    Write-Host "Server starting in the guest, reachable at $addr, certificate $fingerprint"
    # --- client (headless: no window, only a PNG). The port forward accepts
    # connections before the server listens, so readiness is a successful
    # RDP connection, retried for up to two minutes.
    $png = Join-Path $out ("screenshot-" + $(if ($NoGpu) { 'virtio' } else { 'gpu' }) + '.png')
    $deadline = (Get-Date).AddSeconds(120)
    $attempt = 0
    while ($true) {
        $attempt++
        Remove-Item -LiteralPath $png -ErrorAction SilentlyContinue
        $r = Invoke-Bounded $client @("${hostPart}:$portPart", '-u', 'tester', '--expect-fingerprint', $fingerprint, '--screenshot', $png, '--wait', "$Wait") ($Wait + 90) @{ RDP_PASSWORD = $password }
        if ($r.Code -eq 0 -and (Test-Path -LiteralPath $png)) { break }
        $log = Clone @('log', $serverId)
        if ($log -match '\[exited') { throw "the server stopped:`n$log" }
        if ((Get-Date) -gt $deadline) {
            Write-Host $r.Out
            if ($r.Err) { Write-Host $r.Err }
            throw "the client failed ($($r.Code)) after $attempt attempts"
        }
        Start-Sleep -Seconds 3
    }
    Write-Host "Connected on attempt $attempt"
    Write-Host $r.Out
    if ($r.Err) { Write-Host $r.Err }
    Assert-Picture $png
    Write-Host "PASS: Remora connected and saved $png"

    if ($Interactive) {
        Write-Host ''
        Write-Host "Connect with Remora to $addr (any user name), password: $password"
        Write-Host "Certificate fingerprint: $fingerprint"
        Read-Host 'Press Enter to stop the clone'
    }
} finally {
    if ($serverId) {
        try {
            $name = 'host-' + $(if ($NoGpu) { 'virtio' } else { 'gpu' }) + '.log'
            Clone @('log', $serverId) 60 | Set-Content -LiteralPath (Join-Path $out $name)
        } catch { Write-Warning "could not read the server log: $_" }
    }
    if ($started) {
        try { Clone @('stop') 180 | Out-Null; Write-Host 'Clone stopped (changes discarded)' } catch { Write-Warning "could not stop the clone: $_" }
    }
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}

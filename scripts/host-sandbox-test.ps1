# Tests Remora Host end to end in Windows Sandbox: the server runs in a
# throwaway sandbox (its own desktop, its own input), Remora connects to it
# from this PC.
#
#   pwsh scripts/host-sandbox-test.ps1 [-BinDir <folder>] [-Wait 10] [-Capture auto|dxgi|gdi] [-Interactive]
#
# Steps: build (unless -BinDir), start a sandbox with the `wsb` CLI, share a
# staging folder with remora-host.exe and a random test password, open the
# sandbox window (`wsb connect`: the sandbox only has a logged-on desktop
# while its window is open), allow port 3390 in the sandbox's firewall, set
# the password, start the server, then connect Remora in its headless
# screenshot mode, pinned to the certificate fingerprint the server printed
# (`--expect-fingerprint`). The screenshot and the server's log land in
# artifacts/host-sandbox/. -Interactive keeps the sandbox running so you can
# connect with Remora's window and type and click; press Enter to end.
#
# Needs Windows Sandbox with the `wsb` CLI (Windows 11 24H2 or later). The
# sandbox is always stopped at the end, also on errors. Nothing here touches
# this PC's desktop: the server captures and injects input inside the
# sandbox only. Every wait has a timeout.
[CmdletBinding()]
param(
    [string]$BinDir,
    [int]$Wait = 10,
    [ValidateSet('auto', 'dxgi', 'gdi')][string]$Capture = 'auto',
    [switch]$Interactive
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$wsbCmd = Get-Command wsb -ErrorAction SilentlyContinue
if (-not $wsbCmd) {
    throw 'The Windows Sandbox CLI (wsb) is not available: enable Windows Sandbox (Windows 11 24H2 or later).'
}
$wsbExe = $wsbCmd.Source

# -NoOutput: no pipes. `wsb connect` starts the sandbox window process,
# which inherits the pipes and holds them open: reading them never ends.
function Invoke-Bounded([string]$File, [string[]]$Arguments, [int]$Seconds, [hashtable]$Environment = @{}, [switch]$NoOutput) {
    $info = [Diagnostics.ProcessStartInfo]::new($File)
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = -not $NoOutput
    $info.RedirectStandardError = -not $NoOutput
    foreach ($a in $Arguments) { $info.ArgumentList.Add($a) }
    foreach ($k in $Environment.Keys) { $info.Environment[$k] = $Environment[$k] }
    $p = [Diagnostics.Process]::Start($info)
    $out = if ($NoOutput) { $null } else { $p.StandardOutput.ReadToEndAsync() }
    $err = if ($NoOutput) { $null } else { $p.StandardError.ReadToEndAsync() }
    try {
        if (-not $p.WaitForExit($Seconds * 1000)) {
            $p.Kill($true) # only this process and its own children
            $p.WaitForExit()
            throw "$(Split-Path -Leaf $File) timed out after $Seconds s"
        }
        [pscustomobject]@{
            Code = $p.ExitCode
            Out  = if ($out) { $out.GetAwaiter().GetResult() } else { '' }
            Err  = if ($err) { $err.GetAwaiter().GetResult() } else { '' }
        }
    } finally { $p.Dispose() }
}

function Wsb([string[]]$Arguments, [int]$Seconds = 120) {
    $r = Invoke-Bounded $wsbExe $Arguments $Seconds
    if ($r.Code) { throw "wsb $($Arguments[0]) failed ($($r.Code)): $($r.Out)$($r.Err)" }
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

# --- binaries
Push-Location $root
try {
    if (-not $BinDir) {
        # The C runtime linked in (the sandbox has no vcruntime140.dll), in
        # its own target folder so the normal build cache stays as it is.
        $meta = cargo metadata --format-version 1 --no-deps | ConvertFrom-Json
        $target = "$($meta.target_directory)-static"
        $env:RUSTFLAGS = '-C target-feature=+crt-static'
        cargo build --release --locked -p remora-client -p remora-host --target-dir $target
        if ($LASTEXITCODE) { throw 'build failed' }
        $BinDir = Join-Path $target 'release'
    }
} finally { Pop-Location }
$hostExe = Join-Path $BinDir 'remora-host.exe'
$client = Join-Path $BinDir 'remora.exe'
foreach ($f in @($hostExe, $client)) { if (-not (Test-Path -LiteralPath $f)) { throw "missing $f" } }

# --- staging folder (shared into the sandbox as C:\remora, writable)
$stage = Join-Path ([IO.Path]::GetTempPath()) ('remora-sandbox-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage | Out-Null
Copy-Item -LiteralPath $hostExe -Destination $stage
$bytes = [byte[]]::new(18)
[Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$password = [Convert]::ToBase64String($bytes).Replace('+', 'x').Replace('/', 'y')
Set-Content -LiteralPath (Join-Path $stage 'pw.txt') -Value $password -NoNewline -Encoding ascii
Set-Content -LiteralPath (Join-Path $stage 'run-host.cmd') -Encoding ascii -Value @"
@echo off
C:\remora\remora-host.exe run --data-dir C:\remora\data --capture $Capture --verbose > C:\Users\Public\host.log 2>&1
"@
$out = Join-Path $root 'artifacts/host-sandbox'
New-Item -ItemType Directory -Force -Path $out | Out-Null

$id = $null
$server = $null
try {
    # --- sandbox
    $id = (Wsb @('start', '--raw') | ConvertFrom-Json).Id
    Write-Host "Sandbox $id started"
    Wsb @('share', '--id', $id, '-f', $stage, '-s', 'C:\remora', '-w') | Out-Null
    # The logged-on desktop exists only while the sandbox window is open.
    $r = Invoke-Bounded $wsbExe @('connect', '--id', $id) 60 -NoOutput
    if ($r.Code) { throw "wsb connect failed ($($r.Code))" }
    $deadline = (Get-Date).AddSeconds(120)
    while ($true) {
        $r = Invoke-Bounded $wsbExe @('exec', '--id', $id, '-c', 'cmd /c exit 0', '-r', 'ExistingLogin') 30
        if ($r.Code -eq 0) { break }
        if ((Get-Date) -gt $deadline) { throw "no logged-on desktop in the sandbox: $($r.Out)$($r.Err)" }
        Start-Sleep -Seconds 2
    }
    Write-Host 'Sandbox desktop is up'

    # --- server
    Wsb @('exec', '--id', $id, '-c', 'netsh advfirewall firewall add rule name="Remora Host" dir=in action=allow protocol=TCP localport=3390', '-r', 'System') | Out-Null
    Wsb @('exec', '--id', $id, '-c', 'C:\remora\remora-host.exe set-password --data-dir C:\remora\data --password-file C:\remora\pw.txt', '-r', 'ExistingLogin') | Out-Null
    # The certificate is made now and its fingerprint written to a file that
    # is closed at once: a file the sandbox still holds open shows no content
    # on this side of the shared folder.
    Wsb @('exec', '--id', $id, '-c', 'cmd /c C:\remora\remora-host.exe fingerprint --data-dir C:\remora\data > C:\remora\fp.txt', '-r', 'ExistingLogin') | Out-Null
    $fingerprint = (Get-Content -LiteralPath (Join-Path $stage 'fp.txt') -Raw).Trim()
    if ($fingerprint -notmatch '^[0-9A-Fa-f:]{64,}$') { throw "no certificate fingerprint from the sandbox: $fingerprint" }
    # `wsb exec` ends what its command started when the command returns, so
    # the server runs as the command itself, from a background wsb process
    # on this PC that lasts until the sandbox stops.
    $serverInfo = [Diagnostics.ProcessStartInfo]::new($wsbExe)
    $serverInfo.UseShellExecute = $false
    $serverInfo.CreateNoWindow = $true
    foreach ($a in @('exec', '--id', $id, '-c', 'C:\remora\run-host.cmd', '-r', 'ExistingLogin')) { $serverInfo.ArgumentList.Add($a) }
    $server = [Diagnostics.Process]::Start($serverInfo)
    Write-Host "Server started through wsb (PID $($server.Id))"
    $ip = (Wsb @('ip', '--id', $id)).Trim()
    Write-Host "Server starting in the sandbox at ${ip}:3390, certificate $fingerprint"
    # Ready when the port answers.
    $deadline = (Get-Date).AddSeconds(60)
    while ($true) {
        $tcp = [Net.Sockets.TcpClient]::new()
        try { if ($tcp.ConnectAsync($ip, 3390).Wait(1000) -and $tcp.Connected) { break } } catch {} finally { $tcp.Dispose() }
        if ($server.HasExited) { throw "the server stopped (see artifacts/host-sandbox/host.log)" }
        if ((Get-Date) -gt $deadline) { throw "port 3390 in the sandbox did not answer within 60 s (see artifacts/host-sandbox/host.log)" }
        Start-Sleep -Seconds 1
    }
    Write-Host 'Server is listening'

    # --- client (headless: no window, only a PNG)
    $png = Join-Path $out 'screenshot.png'
    Remove-Item -LiteralPath $png -ErrorAction SilentlyContinue
    $r = Invoke-Bounded $client @("${ip}:3390", '-u', 'tester', '--expect-fingerprint', $fingerprint, '--screenshot', $png, '--wait', "$Wait") ($Wait + 90) @{ RDP_PASSWORD = $password }
    Write-Host $r.Out
    if ($r.Err) { Write-Host $r.Err }
    if ($r.Code -or -not (Test-Path -LiteralPath $png)) { throw "the client failed ($($r.Code))" }
    Assert-Picture $png
    Write-Host "PASS: Remora connected and saved $png"

    if ($Interactive) {
        Write-Host ''
        Write-Host "Connect with Remora to ${ip}:3390 (any user name), password: $password"
        Write-Host "Certificate fingerprint: $fingerprint"
        Read-Host 'Press Enter to stop the sandbox'
    }
} finally {
    # The server's log, copied out (and so closed) before the sandbox goes.
    if ($id) {
        try {
            Invoke-Bounded $wsbExe @('exec', '--id', $id, '-c', 'cmd /c copy /y C:\Users\Public\host.log C:\remora\host.log', '-r', 'System') 30 | Out-Null
        } catch { Write-Warning "could not copy the server log: $_" }
    }
    if (Test-Path -LiteralPath (Join-Path $stage 'host.log')) {
        Copy-Item -LiteralPath (Join-Path $stage 'host.log') -Destination (Join-Path $out 'host.log') -Force
    }
    if ($id) {
        try { Wsb @('stop', '--id', $id) | Out-Null; Write-Host "Sandbox $id stopped" } catch { Write-Warning "could not stop sandbox ${id}: $_" }
    }
    # The background wsb ends with the sandbox; if not, only that PID goes.
    if ($server -and -not $server.WaitForExit(15000)) { $server.Kill($true) }
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}

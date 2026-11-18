# Live check of session shadowing (RDP-77) against a lab Windows server:
# lists its sessions, asks for a shadow invitation (MS-TSTS RpcShadow2) and
# connects to it headless, saving a screenshot and the multiparty events.
#
#   pwsh scripts/shadow-live-test.ps1 -Server <lab-server> [-SessionId N] [-Control]
#                                     [-NoConsent] [-Preconnection] [-Wait 15] [-BinDir <folder>]
#
# Needs, on the server (never this PC: the script refuses its own names and
# addresses):
# - Windows Server 2012 R2 / Windows 8.1 or later, with a user signed in.
# - This PC's Windows user is an administrator there. Use `runas /netonly`
#   for a lab account.
# - Firewall: "File and Printer Sharing (SMB-In)" and "Remote Desktop -
#   Shadow (TCP-In)".
# - For -NoConsent: policy "Set rules for remote control of Remote Desktop
#   Services user sessions" = full control (or view) without permission.
#   Otherwise someone answers the consent prompt in the session within 30 s.
#
# Output: artifacts/shadow/shadow.png and remora.log (the session list); the
# shadow step prints its "shared desktop:" events and -v trace to this console.
# What it proves:
# - RPC: --list-sessions and the invitation succeed.
# - Security: the sharer accepts TLS without NLA. A "Standard RDP Security"
#   error means it does not.
# - Pinning: whether the invitation's KH matches the TLS key. The trace
#   says "carries the invitation's key". Otherwise the console asks once
#   for the certificate.
# - Picture: shadow.png is the shadowed desktop.
# - encomsp: "shared desktop:" lines show the control level.
# Every launch is bounded and only processes this script started are stopped.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Server,
    [int]$SessionId = -1,
    [switch]$Control,
    [switch]$NoConsent,
    [switch]$Preconnection,
    [int]$Wait = 15,
    [string]$BinDir
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root 'artifacts/shadow'
New-Item -ItemType Directory -Force $out | Out-Null

# Never shadow this PC (owner rule): refuse its names and addresses.
$own = @('localhost', '127.0.0.1', '::1', $env:COMPUTERNAME, [Net.Dns]::GetHostName())
$own += [Net.Dns]::GetHostAddresses([Net.Dns]::GetHostName()) | ForEach-Object { $_.ToString() }
$target = [Net.Dns]::GetHostAddresses($Server) | ForEach-Object { $_.ToString() }
if ($own -contains $Server -or ($target | Where-Object { $own -contains $_ })) {
    throw "refusing to shadow this PC ($Server); use a lab server"
}

if (-not $BinDir) {
    Push-Location $root
    try { cargo build -p remora-client; if ($LASTEXITCODE) { throw 'build failed' } } finally { Pop-Location }
    $meta = cargo metadata --format-version 1 --no-deps --manifest-path (Join-Path $root 'Cargo.toml') | ConvertFrom-Json
    $BinDir = Join-Path $meta.target_directory 'debug'
}
$remora = Join-Path $BinDir 'remora.exe'
if (-not (Test-Path -LiteralPath $remora)) { throw "not found: $remora" }

function Invoke-Remora([string[]]$Arguments, [int]$Seconds) {
    $info = [Diagnostics.ProcessStartInfo]::new($remora)
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($a in $Arguments) { $info.ArgumentList.Add($a) }
    $p = [Diagnostics.Process]::Start($info)
    $o = $p.StandardOutput.ReadToEndAsync()
    $e = $p.StandardError.ReadToEndAsync()
    try {
        if (-not $p.WaitForExit($Seconds * 1000)) {
            $p.Kill($true) # only this process and its own children
            $p.WaitForExit()
            throw "remora timed out after $Seconds s"
        }
        $r = [pscustomobject]@{ Code = $p.ExitCode; Out = $o.GetAwaiter().GetResult(); Err = $e.GetAwaiter().GetResult() }
        Add-Content -LiteralPath (Join-Path $out 'remora.log') -Value "> remora $($Arguments -join ' ') (exit $($r.Code))`n$($r.Out)$($r.Err)"
        $r
    } finally { $p.Dispose() }
}

Remove-Item -LiteralPath (Join-Path $out 'remora.log') -ErrorAction SilentlyContinue
$list = Invoke-Remora @($Server, '--list-sessions') 60
Write-Host $list.Out $list.Err
if ($list.Code) { throw '--list-sessions failed (SMB, rights?)' }
if ($SessionId -lt 0) {
    # The first active session with a user.
    $row = $list.Out -split "`r?`n" | Where-Object { $_ -match '^\s*(\d+)\s+\S+\s+Active\s+\S' } | Select-Object -First 1
    if (-not $row) { throw 'no active session with a signed-in user to shadow' }
    $SessionId = [int]([regex]::Match($row, '^\s*(\d+)').Groups[1].Value)
}
$argv = @($Server, '--shadow', "$SessionId", '--screenshot', (Join-Path $out 'shadow.png'), '--wait', "$Wait", '-v')
if ($Control) { $argv += '--control' }
if ($NoConsent) { $argv += '--no-consent-prompt' }
if ($Preconnection) { $argv += '--preconnection' }
# This step runs in this console, unredirected: if the certificate is not
# pinned by the invitation, Remora asks here whether to trust it. The
# consent prompt in the session waits up to about 30 s first.
Write-Host "> remora $($argv -join ' ')"
$quoted = $argv | ForEach-Object { if ($_ -match '\s') { "`"$_`"" } else { $_ } }
$p = Start-Process -FilePath $remora -ArgumentList $quoted -NoNewWindow -PassThru
try {
    if (-not $p.WaitForExit(($Wait + 120) * 1000)) {
        $p.Kill($true) # only the process this script started
        throw 'shadow timed out'
    }
    if ($p.ExitCode) { throw "shadow failed (exit $($p.ExitCode))" }
} finally { $p.Dispose() }
Write-Host "shadow ok: $out/shadow.png (the -v trace is in Remora's diagnostic log)"

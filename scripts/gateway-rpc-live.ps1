<#
.SYNOPSIS
Live check of the RD Gateway RPC over HTTP transport (RDP-78) against a real
Windows Server RD Gateway. Headless: nothing appears on this PC.

.DESCRIPTION
Needs a Windows Server with the RD Gateway role (RPC over HTTP is on by
default; the HTTP transport can be turned off in RD Gateway Manager,
Properties, Transport Settings), a CAP and a RAP that allow the user to
reach -Target, and the gateway certificate's name in -Gateway.

Runs, each with its own timeout:
 1. forced RPC (--gateway-rpc): a screenshot of the target's desktop through
    the gateway, and "RPC bound to TsProxy" in the -v log;
 2. automatic transport: a screenshot; with the HTTP transport turned off on
    the gateway the log shows "trying RPC over HTTP";
 3. forced RPC with a wrong password: refused, naming "RPC OUT channel".

The password is read from -PasswordFile and passed to remora only in its own
environment (RDP_PASSWORD); it is never printed or logged.

.EXAMPLE
pwsh scripts/gateway-rpc-live.ps1 -Gateway rdg.lab.example -Target srv01.lab.example `
    -User 'LAB\tester' -PasswordFile E:/AgentData/secrets/lab-tester.txt
#>
param(
    [Parameter(Mandatory)] [string] $Gateway,
    [Parameter(Mandatory)] [string] $Target,
    [Parameter(Mandatory)] [string] $User,
    [Parameter(Mandatory)] [string] $PasswordFile,
    [int] $Wait = 20,
    [int] $TimeoutSeconds = 120
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$meta = cargo metadata --format-version 1 --no-deps --manifest-path "$root/Cargo.toml" | ConvertFrom-Json
cargo build --release -p remora --manifest-path "$root/Cargo.toml" --message-format=short
if ($LASTEXITCODE -ne 0) { throw 'build failed' }
$remora = Join-Path $meta.target_directory 'release/remora.exe'
$work = New-Item -ItemType Directory -Force (Join-Path ([IO.Path]::GetTempPath()) "gw-rpc-$PID")
$password = (Get-Content -Raw $PasswordFile).TrimEnd("`r", "`n")
$results = @()

function Invoke-Remora([string] $name, [string[]] $extra, [string] $pw) {
    $png = Join-Path $work "$name.png"
    $log = Join-Path $work "$name.log"
    $psi = [Diagnostics.ProcessStartInfo]::new($remora)
    foreach ($a in @($Target, '-u', $User, '--gateway', $Gateway, '--screenshot', $png,
                     '--wait', "$Wait", '-v') + $extra) { $psi.ArgumentList.Add($a) }
    $psi.Environment['RDP_PASSWORD'] = $pw
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardOutput = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $p = [Diagnostics.Process]::Start($psi)   # our own PID, closed only by us
    $err = $p.StandardError.ReadToEndAsync()
    $out = $p.StandardOutput.ReadToEndAsync()
    if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
        $p.Kill()
        $p.WaitForExit()
    }
    Set-Content $log ($out.Result + $err.Result)
    [pscustomobject]@{ Code = $p.ExitCode; Png = $png; Log = (Get-Content -Raw $log) }
}

function Check([string] $name, [bool] $ok, [string] $detail) {
    $script:results += $ok
    Write-Host ("{0} {1} {2}" -f ($(if ($ok) { 'PASS' } else { 'FAIL' })), $name, $detail)
}

$r = Invoke-Remora 'rpc' @('--gateway-rpc') $password
Check 'forced RPC: desktop screenshot' ((Test-Path $r.Png) -and $r.Code -eq 0) "exit $($r.Code)"
Check 'forced RPC: bound to TsProxy' ($r.Log -match 'RPC bound to TsProxy') ''

$r = Invoke-Remora 'auto' @() $password
Check 'automatic: desktop screenshot' ((Test-Path $r.Png) -and $r.Code -eq 0) "exit $($r.Code)"
$via = if ($r.Log -match 'trying RPC over HTTP') { 'RPC over HTTP (fallback)' } else { 'HTTP transport' }
Write-Host "      automatic transport used: $via"

$r = Invoke-Remora 'wrong-password' @('--gateway-rpc') ('x' + [guid]::NewGuid())
Check 'wrong password names the RPC channel' ($r.Code -ne 0 -and $r.Log -match 'RPC OUT channel') "exit $($r.Code)"

Write-Host "logs and screenshots: $work"
if ($results -contains $false) { exit 1 }

# Builds the Windows packages into artifacts/installer:
#   remora-<version>-setup.exe, remora-<version>-windows-x64.zip (Remora and
#   the server helper), remora-agent-<version>-windows-x64.exe (the server
#   helper alone, to copy onto a server),
#   rdpc-<version>-setup.exe (a byte-identical copy of the setup under the
#   name rdpc 0.1.0-beta.1's updater looks for; docs/RELEASING.md) and
#   SHA256SUMS.txt over all of them.
# Build only: never installs Remora, never runs the setup, never changes PATH.
#
#   scripts\package.ps1 [-MakeNsis <makensis.exe>] [-BinDir <folder with remora.exe and remora-agent.exe>]
#
# NSIS 3.13 (zlib licence, a build tool, not shipped): scripts/fetch-nsis.ps1
# downloads the pinned portable ZIP; on the owner PC it is already at
# E:/Development/_cache/tools/nsis-3.13/makensis.exe. Without -BinDir the
# release build runs first. THIRD-PARTY-NOTICES.txt comes from cargo-about
# when it is installed (CI); otherwise a local test notice is written.
[CmdletBinding()]
param(
    [string]$MakeNsis = $(if ($env:REMORA_MAKENSIS) { $env:REMORA_MAKENSIS } else { 'E:/Development/_cache/tools/nsis-3.13/makensis.exe' }),
    [string]$BinDir
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$toml = Get-Content -LiteralPath (Join-Path $root 'Cargo.toml') -Raw
if ($toml -notmatch '(?m)^\[workspace\.package\][\s\S]*?^version\s*=\s*"([^"]+)"') { throw 'No workspace version in Cargo.toml' }
$version = $Matches[1]
if ($version -notmatch '^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?$') { throw "Unexpected version: $version" }
$numeric = "$($Matches[1]).$($Matches[2]).$($Matches[3]).0"
if (!(Test-Path -LiteralPath $MakeNsis -PathType Leaf)) {
    throw "NSIS compiler not found at '$MakeNsis'. Run scripts/fetch-nsis.ps1 -Destination <folder> and pass -MakeNsis."
}
$commit = & git -C $root rev-parse --short HEAD 2>$null
Write-Host "Remora $version from commit $(if ($commit) { $commit } else { 'unknown' })"

function Invoke-Bounded([string]$File, [string[]]$Arguments, [int]$Seconds) {
    $info = [Diagnostics.ProcessStartInfo]::new($File)
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.WorkingDirectory = $root
    foreach ($a in $Arguments) { $info.ArgumentList.Add($a) }
    $p = [Diagnostics.Process]::Start($info)
    Write-Host "Started PID $($p.Id): $(Split-Path -Leaf $File) (timeout $Seconds s)"
    $out = $p.StandardOutput.ReadToEndAsync()
    $err = $p.StandardError.ReadToEndAsync()
    try {
        if (!$p.WaitForExit($Seconds * 1000)) {
            $p.Kill($true) # only this process and its own children
            $p.WaitForExit()
            throw "$File timed out after $Seconds s"
        }
        $o = $out.GetAwaiter().GetResult(); if ($o) { Write-Host $o }
        $e = $err.GetAwaiter().GetResult(); if ($e) { Write-Host $e }
        if ($p.ExitCode) { throw "$File failed ($($p.ExitCode))" }
        return $o
    } finally { $p.Dispose() }
}

$cargo = (Get-Command cargo -ErrorAction Stop).Source
if (!$BinDir) {
    Invoke-Bounded $cargo @('build', '--release', '--locked', '-j', '8', '-p', 'remora', '-p', 'remora-agent') 3600 | Out-Null
    $meta = Invoke-Bounded $cargo @('metadata', '--format-version', '1', '--no-deps') 120 | ConvertFrom-Json
    $BinDir = Join-Path $meta.target_directory 'release'
}
$exe = Join-Path $BinDir 'remora.exe'
if (!(Test-Path -LiteralPath $exe -PathType Leaf)) { throw "Missing remora.exe in $BinDir" }
$agentExe = Join-Path $BinDir 'remora-agent.exe'
if (!(Test-Path -LiteralPath $agentExe -PathType Leaf)) { throw "Missing remora-agent.exe in $BinDir" }

$out = Join-Path $root 'artifacts/installer'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$stage = Join-Path $out ('stage-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage | Out-Null
Copy-Item -LiteralPath $exe -Destination $stage
# rdp-rs is dual-licensed; LICENSE.txt carries both texts (the setup shows it).
$sep = "`r`n" + ('=' * 80) + "`r`n"
$license = "rdp-rs (Remora) is licensed under either of the MIT license or the Apache License, Version 2.0, at your option." +
    $sep + (Get-Content -LiteralPath (Join-Path $root 'LICENSE-MIT') -Raw) +
    $sep + (Get-Content -LiteralPath (Join-Path $root 'LICENSE-APACHE') -Raw)
[IO.File]::WriteAllText((Join-Path $stage 'LICENSE.txt'), ($license -replace "`r?`n", "`r`n"))
$notices = Join-Path $stage 'THIRD-PARTY-NOTICES.txt'
if (Get-Command cargo-about -ErrorAction SilentlyContinue) {
    Invoke-Bounded $cargo @('about', 'generate', '-o', $notices, (Join-Path $root 'about.hbs')) 600 | Out-Null
} else {
    Write-Warning 'cargo-about is not installed: writing a local test notice. Release builds generate the real one in CI.'
    "Third-party notices are generated in CI release builds.`r`nThis is a local test package of Remora $version." | Set-Content -LiteralPath $notices -Encoding utf8
}

$setup = Join-Path $out "remora-$version-setup.exe"
Invoke-Bounded $MakeNsis @('-V3', "-DVERSION=$version", "-DVI_VERSION=$numeric", "-DSRC=$stage", "-DOUTFILE=$setup", (Join-Path $root 'installer/remora.nsi')) 300 | Out-Null
# The setup installs Remora only (it lists its files); the zip and the
# separate download also carry the server helper, which runs on servers.
Copy-Item -LiteralPath $agentExe -Destination $stage
$zip = Join-Path $out "remora-$version-windows-x64.zip"
if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip }
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip
$agent = Join-Path $out "remora-agent-$version-windows-x64.exe"
Copy-Item -LiteralPath $agentExe -Destination $agent -Force
Remove-Item -LiteralPath $stage -Recurse -Force
# Legacy asset: rdpc (the app's name before Remora) updates only from a setup
# named rdpc-<version>-setup.exe. The same bytes under that name let its
# updater find, verify and run this setup, which moves the install to Remora.
# Publish it until the owner drops it (docs/RELEASING.md).
$legacy = Join-Path $out "rdpc-$version-setup.exe"
Copy-Item -LiteralPath $setup -Destination $legacy -Force
if ((Get-FileHash -LiteralPath $legacy).Hash -ne (Get-FileHash -LiteralPath $setup).Hash) { throw "$legacy differs from $setup" }

$lines = foreach ($f in @($setup, $legacy, $zip, $agent)) {
    $h = (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host ('{0:N0} bytes  {1}' -f (Get-Item -LiteralPath $f).Length, $f)
    "$h  $(Split-Path -Leaf $f)"
}
# sha256sum format with LF endings, the contract with the in-app updater.
[IO.File]::WriteAllText((Join-Path $out 'SHA256SUMS.txt'), (($lines -join "`n") + "`n"))
Write-Host "Wrote $(Join-Path $out 'SHA256SUMS.txt')"

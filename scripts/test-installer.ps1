# Installer lifecycle test. CI ONLY: it installs rdpc for the current user,
# writes HKCU and %LOCALAPPDATA%, and uninstalls again. It refuses to run
# outside GitHub Actions so it can never touch a real profile.
#   scripts/test-installer.ps1 -Setup <rdpc-x.y.z-setup.exe> -Version <x.y.z>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Setup,
    [Parameter(Mandatory)][string]$Version
)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'test-installer.ps1 runs only on disposable CI runners.' }

$dir = Join-Path $env:LOCALAPPDATA 'Programs\rdpc'
$exe = Join-Path $dir 'rdpc.exe'
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\rdpc'

function Run([string]$File, [string[]]$Arguments, [int]$Seconds = 120) {
    $p = Start-Process -FilePath $File -ArgumentList $Arguments -PassThru
    if (!$p.WaitForExit($Seconds * 1000)) { $p.Kill(); throw "$File $Arguments timed out" }
    return $p.ExitCode
}

function Assert-Installed {
    if (!(Test-Path -LiteralPath $exe)) { throw "rdpc.exe missing in $dir" }
    foreach ($f in 'LICENSE.txt', 'THIRD-PARTY-NOTICES.txt', 'uninstall.exe') {
        if (!(Test-Path -LiteralPath (Join-Path $dir $f))) { throw "$f missing" }
    }
    $entry = Get-ItemProperty -LiteralPath $key
    if ($entry.DisplayVersion -ne $Version) { throw "DisplayVersion is '$($entry.DisplayVersion)', expected $Version" }
    if (!(Test-Path -LiteralPath (Join-Path ([Environment]::GetFolderPath('Programs')) 'rdpc.lnk'))) { throw 'Start menu shortcut missing' }
    $out = Join-Path $env:RUNNER_TEMP 'rdpc-version.txt'
    $p = Start-Process -FilePath $exe -ArgumentList '--version' -RedirectStandardOutput $out -PassThru -NoNewWindow
    if (!$p.WaitForExit(30000)) { $p.Kill(); throw 'rdpc --version timed out' }
    $line = (Get-Content -LiteralPath $out -Raw).Trim()
    if ($line -ne "rdpc $Version") { throw "rdpc --version printed '$line'" }
}

Write-Host '1. Silent install'
if ((Run $Setup @('/S'))) { throw 'Setup failed' }
Assert-Installed

Write-Host '2. Silent reinstall over the existing copy (what an update does)'
if ((Run $Setup @('/S'))) { throw 'Reinstall failed' }
Assert-Installed

Write-Host '3. A locked rdpc.exe (as while rdpc runs) makes a silent install give up after 30 s'
# Hosted runners have no interactive desktop for a real rdpc window, so the
# test holds the same lock a running exe has: no write sharing.
$lock = [IO.File]::Open($exe, 'Open', 'Read', 'Read')
try {
    $started = Get-Date
    $code = Run $Setup @('/S') 90
    $waited = ((Get-Date) - $started).TotalSeconds
} finally { $lock.Dispose() }
if ($code -eq 0) { throw 'Setup replaced a locked rdpc.exe' }
if ($waited -lt 25) { throw "Setup gave up after $([int]$waited) s instead of waiting about 30 s" }
Write-Host ("   setup refused with exit code {0} after {1:N0} s" -f $code, $waited)
Assert-Installed

Write-Host '4. Silent uninstall'
if ((Run (Join-Path $dir 'uninstall.exe') @('/S'))) { throw 'Uninstall failed' }
# The NSIS uninstaller copies itself to TEMP and finishes there.
$deadline = (Get-Date).AddSeconds(30)
while ((Test-Path -LiteralPath $exe) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
if (Test-Path -LiteralPath $exe) { throw 'rdpc.exe still present after uninstall' }
if (Test-Path -LiteralPath $key) { throw 'Installed apps entry still present' }
Write-Host 'Installer lifecycle passed.'

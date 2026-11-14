# Installer lifecycle test. CI ONLY: it installs Remora (and the published
# rdpc 0.1.0-beta.1) for the current user, writes HKCU, %LOCALAPPDATA% and
# %APPDATA%, and uninstalls again. It refuses to run outside GitHub Actions so
# it can never touch a real profile.
#   scripts/test-installer.ps1 -Setup <remora-x.y.z-setup.exe> -Version <x.y.z>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Setup,
    [Parameter(Mandatory)][string]$Version
)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'test-installer.ps1 runs only on disposable CI runners.' }

$dir = Join-Path $env:LOCALAPPDATA 'Programs\Remora'
$exe = Join-Path $dir 'remora.exe'
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Remora'
$startMenu = [Environment]::GetFolderPath('Programs')
$desktop = [Environment]::GetFolderPath('Desktop')
# rdpc, the app's name before Remora (0.1.0-beta.1).
$oldDir = Join-Path $env:LOCALAPPDATA 'Programs\rdpc'
$oldExe = Join-Path $oldDir 'rdpc.exe'
$oldKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\rdpc'
$oldFiles = 'rdpc.exe', 'LICENSE.txt', 'THIRD-PARTY-NOTICES.txt', 'uninstall.exe'

function Run([string]$File, [string[]]$Arguments, [int]$Seconds = 120) {
    $p = Start-Process -FilePath $File -ArgumentList $Arguments -PassThru
    if (!$p.WaitForExit($Seconds * 1000)) { $p.Kill(); throw "$File $Arguments timed out" }
    return $p.ExitCode
}

function New-Shortcut([string]$Path, [string]$Target) {
    $s = (New-Object -ComObject WScript.Shell).CreateShortcut($Path)
    $s.TargetPath = $Target
    $s.Save()
}

function Assert-Installed {
    if (!(Test-Path -LiteralPath $exe)) { throw "remora.exe missing in $dir" }
    foreach ($f in 'LICENSE.txt', 'THIRD-PARTY-NOTICES.txt', 'uninstall.exe') {
        if (!(Test-Path -LiteralPath (Join-Path $dir $f))) { throw "$f missing" }
    }
    $entry = Get-ItemProperty -LiteralPath $key
    if ($entry.DisplayName -ne 'Remora') { throw "DisplayName is '$($entry.DisplayName)'" }
    if ($entry.DisplayVersion -ne $Version) { throw "DisplayVersion is '$($entry.DisplayVersion)', expected $Version" }
    if (!(Test-Path -LiteralPath (Join-Path $startMenu 'Remora.lnk'))) { throw 'Start menu shortcut missing' }
    $out = Join-Path $env:RUNNER_TEMP 'remora-version.txt'
    $p = Start-Process -FilePath $exe -ArgumentList '--version' -RedirectStandardOutput $out -PassThru -NoNewWindow
    if (!$p.WaitForExit(30000)) { $p.Kill(); throw 'remora --version timed out' }
    $line = (Get-Content -LiteralPath $out -Raw).Trim()
    if ($line -ne "Remora $Version") { throw "remora --version printed '$line'" }
}

function Assert-RdpcGone {
    if (Test-Path -LiteralPath $oldDir) { throw "$oldDir still present: $((Get-ChildItem -LiteralPath $oldDir -Force).Name -join ', ')" }
    if (Test-Path -LiteralPath $oldKey) { throw 'rdpc Installed apps entry still present' }
    foreach ($l in (Join-Path $startMenu 'rdpc.lnk'), (Join-Path $desktop 'rdpc.lnk')) {
        if (Test-Path -LiteralPath $l) { throw "$l still present" }
    }
}

# User data the migration must never touch.
$markers = foreach ($base in $env:LOCALAPPDATA, $env:APPDATA) {
    $d = Join-Path $base 'rdp-rs'
    New-Item -ItemType Directory -Force -Path $d | Out-Null
    $m = Join-Path $d 'installer-test-marker.txt'
    Set-Content -LiteralPath $m -Value 'user data'
    $m
}
function Assert-DataKept {
    foreach ($m in $markers) { if (!(Test-Path -LiteralPath $m)) { throw "user data $m was removed" } }
}

Write-Host '1. Silent install'
if ((Run $Setup @('/S'))) { throw 'Setup failed' }
Assert-Installed

Write-Host '2. Silent reinstall over the existing copy (what an update does)'
if ((Run $Setup @('/S'))) { throw 'Reinstall failed' }
Assert-Installed

Write-Host '3. A locked remora.exe (as while Remora runs) makes a silent install give up after 30 s'
# Hosted runners have no interactive desktop for a real Remora window, so the
# test holds the same lock a running exe has: no write sharing.
$lock = [IO.File]::Open($exe, 'Open', 'Read', 'Read')
try {
    $started = Get-Date
    $code = Run $Setup @('/S') 90
    $waited = ((Get-Date) - $started).TotalSeconds
} finally { $lock.Dispose() }
if ($code -eq 0) { throw 'Setup replaced a locked remora.exe' }
if ($waited -lt 25) { throw "Setup gave up after $([int]$waited) s instead of waiting about 30 s" }
Write-Host ("   setup refused with exit code {0} after {1:N0} s" -f $code, $waited)
Assert-Installed

function Uninstall-Remora {
    if ((Run (Join-Path $dir 'uninstall.exe') @('/S'))) { throw 'Uninstall failed' }
    # The NSIS uninstaller copies itself to TEMP and finishes there.
    $deadline = (Get-Date).AddSeconds(30)
    while ((Test-Path -LiteralPath $exe) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
    if (Test-Path -LiteralPath $exe) { throw 'remora.exe still present after uninstall' }
    if (Test-Path -LiteralPath $key) { throw 'Installed apps entry still present' }
    if (Test-Path -LiteralPath (Join-Path $startMenu 'Remora.lnk')) { throw 'Start menu shortcut still present' }
}

Write-Host '4. Silent uninstall'
Uninstall-Remora
Assert-DataKept

Write-Host '5. Update from the published rdpc 0.1.0-beta.1'
# The real beta.1 setup, checked against its published checksum.
$rel = 'https://github.com/rennerdo30/rdp-rs/releases/download/v0.1.0-beta.1'
$beta = Join-Path $env:RUNNER_TEMP 'rdpc-0.1.0-beta.1-setup.exe'
$sums = Join-Path $env:RUNNER_TEMP 'rdpc-0.1.0-beta.1-SHA256SUMS.txt'
Invoke-WebRequest -Uri "$rel/rdpc-0.1.0-beta.1-setup.exe" -OutFile $beta -TimeoutSec 120
Invoke-WebRequest -Uri "$rel/SHA256SUMS.txt" -OutFile $sums -TimeoutSec 60
$want = (Get-Content -LiteralPath $sums | Where-Object { $_ -match '\s\*?rdpc-0\.1\.0-beta\.1-setup\.exe$' }) -replace '\s.*$', ''
if ((Get-FileHash -LiteralPath $beta).Hash -ne $want) { throw 'rdpc beta.1 setup does not match its published checksum' }
if ((Run $beta @('/S'))) { throw 'rdpc beta.1 setup failed' }
foreach ($f in $oldFiles) { if (!(Test-Path -LiteralPath (Join-Path $oldDir $f))) { throw "beta.1 did not install $f" } }
if (!(Test-Path -LiteralPath $oldKey)) { throw 'beta.1 wrote no uninstall key' }
New-Shortcut (Join-Path $desktop 'rdpc.lnk') $oldExe

Write-Host '   5a. While rdpc.exe is locked (rdpc still closing), the setup waits 30 s and changes nothing'
$lock = [IO.File]::Open($oldExe, 'Open', 'Read', 'Read')
try {
    $started = Get-Date
    # The arguments rdpc 0.1.0-beta.1's updater passes (crates/rdpc-update at v0.1.0-beta.1).
    # /UPDATE would start remora.exe afterwards; a refused setup must not.
    $code = Run $Setup @('/S', '/UPDATE') 90
    $waited = ((Get-Date) - $started).TotalSeconds
} finally { $lock.Dispose() }
if ($code -eq 0) { throw 'Setup went ahead while rdpc.exe was locked' }
if ($waited -lt 25) { throw "Setup gave up after $([int]$waited) s instead of waiting about 30 s" }
if (Test-Path -LiteralPath $exe) { throw 'A refused setup installed remora.exe' }
foreach ($f in $oldFiles) { if (!(Test-Path -LiteralPath (Join-Path $oldDir $f))) { throw "A refused setup removed rdpc's $f" } }
if (!(Test-Path -LiteralPath $oldKey)) { throw "A refused setup removed rdpc's uninstall key" }

Write-Host '   5b. rdpc closed: the setup installs Remora and removes rdpc, never user data'
if ((Run $Setup @('/S'))) { throw 'Setup over rdpc failed' }
Assert-Installed
Assert-RdpcGone
Assert-DataKept

Write-Host '6. Running the setup again changes nothing (idempotent)'
if ((Run $Setup @('/S'))) { throw 'Second setup failed' }
Assert-Installed
Assert-RdpcGone

Write-Host '7. A partly removed rdpc install is cleaned up too'
# Folder with some files but no rdpc.exe, the uninstall key, no shortcuts.
New-Item -ItemType Directory -Force -Path $oldDir | Out-Null
Set-Content -LiteralPath (Join-Path $oldDir 'LICENSE.txt') -Value 'x'
New-Item -Path $oldKey -Force | Out-Null
New-ItemProperty -LiteralPath $oldKey -Name InstallLocation -Value $oldDir -Force | Out-Null
if ((Run $Setup @('/S'))) { throw 'Setup over a partial rdpc failed' }
Assert-Installed
Assert-RdpcGone
# Only the uninstall key, no folder.
New-Item -Path $oldKey -Force | Out-Null
New-ItemProperty -LiteralPath $oldKey -Name InstallLocation -Value $oldDir -Force | Out-Null
if ((Run $Setup @('/S'))) { throw 'Setup over a stale rdpc key failed' }
Assert-RdpcGone

Write-Host '8. Files rdpc never installed stay in its folder (no recursive delete)'
New-Item -ItemType Directory -Force -Path $oldDir | Out-Null
foreach ($f in $oldFiles) { Set-Content -LiteralPath (Join-Path $oldDir $f) -Value 'x' }
$foreign = Join-Path $oldDir 'notes.txt'
Set-Content -LiteralPath $foreign -Value 'not rdpc'
if ((Run $Setup @('/S'))) { throw 'Setup failed' }
foreach ($f in $oldFiles) { if (Test-Path -LiteralPath (Join-Path $oldDir $f)) { throw "rdpc's $f still present" } }
if (!(Test-Path -LiteralPath $foreign)) { throw 'The setup removed a file rdpc never installed' }
Remove-Item -LiteralPath $oldDir -Recurse -Force

Write-Host '9. Silent uninstall'
Uninstall-Remora
Assert-DataKept
Write-Host 'Installer lifecycle passed.'

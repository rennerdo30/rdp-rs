# Retakes the screenshots of the website (website/assets/shots) and the user
# guide (docs/images), and refreshes the site's icons from assets/.
#
#   pwsh scripts/screenshots.ps1 [-Exe <built remora.exe>]
#
# Everything is rendered offscreen with the app's own paint code and sample
# data (`remora --snapshot-ui`): no window opens and no saved connection is
# read. The site renders at 125 % (1600 x 1000 images, the editor 1800 x
# 1125), the guide at 100 % (1280 x 800 and the 1320 x 860 window). Nothing
# is resampled. Images are lossless WebP, made with ffmpeg (libwebp), which
# must be on PATH. Each run of the app has a two-minute timeout. Commit the results; retake them when the UI changes.
[CmdletBinding()]
param([string]$Exe)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$site = Join-Path $root 'website/assets/shots'
$docs = Join-Path $root 'docs/images'
if (-not (Get-Command ffmpeg -ErrorAction SilentlyContinue)) {
    throw 'ffmpeg (with libwebp) is needed on PATH for the WebP images'
}

Push-Location $root
try {
    $meta = cargo metadata --format-version 1 --no-deps | ConvertFrom-Json
    if ($LASTEXITCODE) { throw 'cargo metadata failed' }
    if (-not $Exe) {
        cargo build --release -p remora
        if ($LASTEXITCODE) { throw 'build failed' }
        $Exe = Join-Path $meta.target_directory 'release/remora.exe'
    }
} finally { Pop-Location }
Write-Host "Using $Exe"

$raw = Join-Path $meta.target_directory 'shots'
Remove-Item -Recurse -Force -LiteralPath $raw -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $raw, $site, $docs | Out-Null

function Run-App([string[]]$argv) {
    $p = Start-Process -FilePath $Exe -ArgumentList $argv -PassThru -NoNewWindow -RedirectStandardError (Join-Path $raw 'stderr.txt')
    if (-not $p.WaitForExit(120000)) { $p.Kill(); throw "$($argv -join ' ') timed out" }
    if ($p.ExitCode) { throw "$($argv -join ' ') failed: $(Get-Content -Raw (Join-Path $raw 'stderr.txt'))" }
}

function To-Webp([string]$src, [string]$dst) {
    if (-not (Test-Path -LiteralPath $src)) { throw "missing snapshot $src" }
    ffmpeg -v error -y -i $src -c:v libwebp -lossless 1 -compression_level 6 $dst
    if ($LASTEXITCODE) { throw "conversion of $src failed" }
}

New-Item -ItemType Directory -Force (Join-Path $raw 'site'), (Join-Path $raw 'docs') | Out-Null
Run-App @('--snapshot-ui', (Join-Path $raw 'site/ui.png'), '--scale', '1.25')
Run-App @('--snapshot-ui', (Join-Path $raw 'docs/ui.png'), '--scale', '1')

# Website: whole windows at 125 % (snapshot suffix -> file name).
$siteShots = [ordered]@{
    'site-session'       = 'hero'
    'site-session-light' = 'hero-light'
    'site-home'          = 'home'
    'site-home-light'    = 'home-light'
    'site-palette'       = 'palette'
    'site-connecting'    = 'connecting'
    'site-failed'        = 'failed'
    'site-monitors'      = 'monitors'
    'site-apps'          = 'remoteapp'
    'site-sharing'       = 'sharing'
    'site-quality'       = 'quality'
    'site-vault'         = 'vault'
    'site-cert'          = 'certificate'
    'site-editor'        = 'editor'
}
foreach ($k in $siteShots.Keys) {
    To-Webp (Join-Path $raw "site/ui-$k.png") (Join-Path $site "$($siteShots[$k]).webp")
}

# User guide at 100 %: the site scenes where they fit, plus single screens.
$docShots = [ordered]@{
    'site-session'       = 'session'
    'site-home'          = 'home'
    'site-home-light'    = 'home-light'
    'site-quick'         = 'quick-connect'
    'site-palette'       = 'palette'
    'site-connecting'    = 'connecting'
    'site-monitors'      = 'editor-display'
    'site-apps'          = 'remoteapp-tab'
    'site-sharing'       = 'panel-sharing'
    'site-quality'       = 'panel-quality'
    'site-vault'         = 'settings-vault'
    'site-cert'          = 'certificate'
    'site-editor'        = 'editor-general'
    'empty'              = 'first-start'
    'home-new-host'      = 'quick-connect-new'
    'form-experience'    = 'editor-experience'
    'form-sharing'       = 'editor-sharing'
    'form-advanced'      = 'editor-advanced'
    'group'              = 'group'
    'apps-form'          = 'editor-apps'
    'toolbar-menu'       = 'toolbar-menu'
    'panel-display'      = 'panel-display'
    'panel-session'      = 'panel-session'
    'fullscreen-toolbar' = 'fullscreen'
    'spanned'            = 'spanned'
    'palette-query'      = 'palette-search'
    'settings'           = 'settings'
    'unlock'             = 'unlock'
    'cert-changed'       = 'certificate-changed'
    'reconnecting'       = 'reconnecting'
    'ended-other-user'   = 'ended'
    'failed-host'        = 'failed-host'
    'failed-refused'     = 'failed-refused'
    'failed-password'    = 'failed-password'
    'failed-cert'        = 'failed-certificate'
    'failed-license'     = 'failed-license'
}
foreach ($k in $docShots.Keys) {
    To-Webp (Join-Path $raw "docs/ui-$k.png") (Join-Path $docs "$($docShots[$k]).webp")
}

# The site's icons come from the app's own: the logo, the .ico and PNGs
# drawn by the app (`--icon-png`) for the web manifest.
Copy-Item -LiteralPath (Join-Path $root 'assets/logo.svg') -Destination (Join-Path $root 'website/assets/logo.svg') -Force
Copy-Item -LiteralPath (Join-Path $root 'assets/remora.ico') -Destination (Join-Path $root 'website/favicon.ico') -Force
foreach ($n in 180, 512) {
    $png = Join-Path $raw "icon-$n.png"
    Run-App @('--icon-png', $png, '--icon-size', "$n")
    Copy-Item -LiteralPath $png -Destination (Join-Path $root "website/assets/icon-$n.png") -Force
}

# The link preview (1200 x 630 JPEG, which every preview reader takes).
ffmpeg -v error -y -i (Join-Path $raw 'site/ui-site-session.png') -vf 'scale=1200:-1:flags=lanczos,crop=1200:630:0:0' -q:v 3 (Join-Path $root 'website/assets/og.jpg')
if ($LASTEXITCODE) { throw 'link preview failed' }

Get-ChildItem $site, $docs -Filter *.webp | Where-Object { $_.Length -gt 300KB } | ForEach-Object { Write-Warning "$($_.Name) is $([int]($_.Length / 1KB)) KB" }
Write-Host "Screenshots written to $site and $docs"

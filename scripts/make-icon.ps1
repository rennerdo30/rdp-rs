# Writes assets/remora.ico (16, 24, 32, 48, 64 and 256 px, PNG entries) from
# the icon Remora draws itself (`remora --icon-png <file> --icon-size <n>`), so
# the exe and installer icon always match the window icon and assets/logo.svg.
# Rerun it after changing crates/remora/src/icon.rs and commit the .ico.
#   scripts\make-icon.ps1 [-Exe <built remora.exe>] [-Output <file.ico>]
# Without -Exe it builds and runs remora through cargo.
[CmdletBinding()]
param(
    [string]$Output = (Join-Path (Split-Path -Parent $PSScriptRoot) 'assets/remora.ico'),
    [string]$Exe
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$sizes = 16, 24, 32, 48, 64, 256
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('remora-icon-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $entries = foreach ($size in $sizes) {
        $png = Join-Path $tmp "$size.png"
        if ($Exe) {
            & $Exe --icon-png $png --icon-size $size
        } else {
            & cargo run --release --quiet -j 8 -p remora --manifest-path (Join-Path $root 'Cargo.toml') -- --icon-png $png --icon-size $size
        }
        if ($LASTEXITCODE -or !(Test-Path -LiteralPath $png)) { throw "remora --icon-png failed for $size px" }
        , [IO.File]::ReadAllBytes($png)
    }
    $ms = [IO.MemoryStream]::new()
    $w = [IO.BinaryWriter]::new($ms)
    $w.Write([uint16]0); $w.Write([uint16]1); $w.Write([uint16]$sizes.Count)
    $offset = 6 + 16 * $sizes.Count
    for ($i = 0; $i -lt $sizes.Count; $i++) {
        $dim = if ($sizes[$i] -ge 256) { 0 } else { $sizes[$i] }
        $w.Write([byte]$dim); $w.Write([byte]$dim); $w.Write([byte]0); $w.Write([byte]0)
        $w.Write([uint16]1); $w.Write([uint16]32)
        $w.Write([uint32]$entries[$i].Length); $w.Write([uint32]$offset)
        $offset += $entries[$i].Length
    }
    foreach ($bytes in $entries) { $w.Write($bytes) }
    $w.Flush()
    [IO.File]::WriteAllBytes($Output, $ms.ToArray())
    Write-Host "Wrote $Output ($($ms.Length) bytes)"
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

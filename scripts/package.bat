@echo off
rem Build the Windows setup, the portable zip and SHA256SUMS.txt into
rem artifacts\installer. Builds only: nothing is installed or started.
rem
rem   scripts\package.bat                       uses the local NSIS 3.13
rem   scripts\package.bat -MakeNsis C:\nsis\makensis.exe
setlocal
cd /d "%~dp0.."
where cargo >nul 2>nul || (echo cargo was not found. Install Rust from https://rustup.rs & exit /b 1)
where pwsh >nul 2>nul || (echo PowerShell 7 ^(pwsh^) was not found. & exit /b 1)
if not exist ".cargo\config.toml" if exist "E:\Development\_tools\sccache" (
    copy /y ".cargo\config.example.toml" ".cargo\config.toml" >nul
    echo Created .cargo\config.toml from the template ^(sccache, rust-lld^).
)
pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0package.ps1" %*
if errorlevel 1 (
    echo Packaging failed. See the messages above.
    pause
    exit /b 1
)
echo Packages are in artifacts\installer.
exit /b 0

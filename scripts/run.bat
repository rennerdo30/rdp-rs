@echo off
rem Build and start Remora (the connection manager) from this checkout.
rem
rem   scripts\run.bat              debug build
rem   scripts\run.bat --release    optimized build (slower to build, the real speed)
rem   scripts\run.bat --pull       update to the latest main first (fast-forward only)
rem   scripts\run.bat -v           protocol trace (also written to the log file)
rem
rem Other options are passed to remora.
setlocal EnableDelayedExpansion
cd /d "%~dp0.."
call "%~dp0_setup.bat" || exit /b 1
set "PULL="
set "RELEASE="
set "ARGS="
:parse
if "%~1"=="" goto parsed
if /i "%~1"=="--pull" (set "PULL=1" & shift & goto parse)
if /i "%~1"=="--release" (set "RELEASE=--release" & shift & goto parse)
set "ARGS=!ARGS! %1"
shift
goto parse
:parsed
if defined PULL (
    echo Updating to the latest main...
    git pull --ff-only origin main || (echo Pull failed. Fix the checkout first. & exit /b 1)
)
echo Building Remora %RELEASE%...
cargo build %RELEASE% -j %JOBS% --quiet -p remora || (echo Build failed. & pause & exit /b 1)
cargo run %RELEASE% -j %JOBS% --quiet -p remora -- !ARGS!
if errorlevel 1 (
    echo Remora exited with an error. See the messages above.
    pause
    exit /b 1
)
exit /b 0

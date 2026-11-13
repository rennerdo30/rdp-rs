@echo off
rem Shared setup for the scripts (called, not run directly):
rem - checks that cargo and git are on PATH;
rem - copies the local Cargo config from its template on the owner PC, so a
rem   fresh checkout or worktree uses sccache and rust-lld right away;
rem - sets JOBS to half the CPU threads (at most 8), so the PC stays responsive.
where cargo >nul 2>nul || (echo cargo was not found. Install Rust from https://rustup.rs & exit /b 1)
where git >nul 2>nul || (echo git was not found. Install Git first. & exit /b 1)
if not exist ".cargo\config.toml" if exist "E:\Development\_tools\sccache" (
    copy /y ".cargo\config.example.toml" ".cargo\config.toml" >nul
    echo Created .cargo\config.toml from the template ^(sccache, rust-lld^).
)
set /a JOBS=%NUMBER_OF_PROCESSORS% / 2
if %JOBS% LSS 1 set JOBS=1
if %JOBS% GTR 8 set JOBS=8
exit /b 0

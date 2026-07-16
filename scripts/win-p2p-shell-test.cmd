@echo off
REM ---------------------------------------------------------------------------
REM Launcher for win-p2p-shell-test.ps1 — validates the Windows nkCryptoTool
REM P2P shell server (ConPTY) + client end to end. Bypasses the PowerShell
REM execution policy so you can just double-click or run this .cmd.
REM
REM   win-p2p-shell-test.cmd [path\to\nkCryptoTool.exe]
REM
REM Run from a STANDARD (non-Administrator) command prompt: the shell server
REM refuses to run elevated (no privilege drop).
REM ---------------------------------------------------------------------------
setlocal
set "EXE=%~1"
if "%EXE%"=="" set "EXE=.\nkCryptoTool.exe"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0win-p2p-shell-test.ps1" -Exe "%EXE%"
set "RC=%ERRORLEVEL%"
echo.
pause
endlocal & exit /b %RC%

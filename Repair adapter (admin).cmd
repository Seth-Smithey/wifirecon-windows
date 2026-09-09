@echo off
title wifirecon adapter repair
cd /d "%~dp0"

rem  Elevates itself, then runs the adapter repair. This is the reliable path
rem  when the in-app "Restart as administrator" button is awkward.

net session >nul 2>&1
if errorlevel 1 (
  echo   Requesting administrator rights...
  powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

echo.
echo   Running as administrator.
echo.

set "PY=%~dp0.venv\Scripts\python.exe"
if not exist "%PY%" (
  echo   wifirecon is not set up yet. Run "Setup wifirecon.cmd" first.
  echo.
  pause
  exit /b 1
)

"%PY%" -m app --fix-adapter

echo.
pause

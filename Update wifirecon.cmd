@echo off
setlocal
title wifirecon update
cd /d "%~dp0"

rem  Drag a wifirecon zip onto this file, or double-click and paste the path.
rem  Replaces the app in place, keeps your data, backs up the old version first.

set "PKG=%~1"

if "%PKG%"=="" (
  echo.
  echo   Update wifirecon
  echo   ------------------------------------------
  echo.
  echo   Drag the new wifirecon zip onto this file, or paste its full path below.
  echo.
  set /p PKG="   Path to zip: "
)

rem strip surrounding quotes if the path was pasted with them
set PKG=%PKG:"=%

if not exist "%PKG%" (
  echo.
  echo   Could not find: %PKG%
  echo.
  pause
  exit /b 1
)

set "PY=%~dp0.venv\Scripts\python.exe"
if not exist "%PY%" (
  echo   wifirecon is not set up yet. Run "Setup wifirecon.cmd" first.
  pause
  exit /b 1
)

echo.
echo   Stopping any running copy...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Get-CimInstance Win32_Process -Filter \"Name='python.exe' OR Name='pythonw.exe'\" | Where-Object { $_.CommandLine -match '-m\s+app' -and $_.CommandLine -match [regex]::Escape('%~dp0') } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }" >nul 2>&1
timeout /t 2 /nobreak >nul

echo   Applying the update...
echo.
"%PY%" -m app --update-from "%PKG%"
set RC=%ERRORLEVEL%

if "%RC%"=="0" (
  echo.
  echo   Updating dependencies...
  "%PY%" -m pip install -r "%~dp0requirements.txt" --quiet --upgrade
  echo.
  echo   Done. Start it with wifirecon.vbs.
) else (
  echo.
  echo   The update did not complete. Nothing was changed.
)
echo.
pause
exit /b %RC%

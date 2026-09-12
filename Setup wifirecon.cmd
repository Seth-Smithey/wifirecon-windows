@echo off
setlocal enabledelayedexpansion
title wifirecon setup
cd /d "%~dp0"

rem  One-time setup. Double-click this, or let the launcher call it.

set "FROM_LAUNCHER="
if "%~1"=="--from-launcher" set "FROM_LAUNCHER=1"

echo.
echo   wifirecon setup
echo   ------------------------------------------
echo.

rem --- find a usable Python -------------------------------------------------
set "PYCMD="
for %%C in ("py -3" "python" "python3") do (
  if not defined PYCMD (
    %%~C --version >nul 2>&1
    if not errorlevel 1 (
      for /f "tokens=2" %%V in ('%%~C --version 2^>^&1') do (
        for /f "tokens=1,2 delims=." %%A in ("%%V") do (
          if %%A GEQ 3 if %%B GEQ 10 set "PYCMD=%%~C"
        )
      )
    )
  )
)

if not defined PYCMD (
  echo   Python 3.10 or newer is required and was not found.
  echo.
  echo   Install it from https://www.python.org/downloads/
  echo   IMPORTANT: tick "Add python.exe to PATH" during installation.
  echo.
  pause
  exit /b 1
)

for /f "tokens=*" %%V in ('%PYCMD% --version 2^>^&1') do echo   Found %%V

rem --- virtual environment -------------------------------------------------
set "VENV=%~dp0.venv"
if not exist "%VENV%\Scripts\python.exe" (
  echo   Creating the virtual environment...
  %PYCMD% -m venv "%VENV%"
  if errorlevel 1 (
    echo   Could not create the virtual environment.
    pause
    exit /b 1
  )
)
set "PY=%VENV%\Scripts\python.exe"

echo   Installing dependencies. Qt is about 200 MB, so this takes a minute.
"%PY%" -m pip install --upgrade pip --quiet
"%PY%" -m pip install -r "%~dp0requirements.txt"
if errorlevel 1 (
  echo.
  echo   Dependency installation failed. The message above says why.
  echo   The usual causes are no internet connection, or a Python version
  echo   with no matching wheel yet.
  echo.
  pause
  exit /b 1
)
echo   Dependencies installed.

rem --- the interface -------------------------------------------------------
rem  Without Qt there is no window, so this is checked rather than assumed.
"%PY%" -c "from PySide6 import QtWidgets" >nul 2>&1
if errorlevel 1 (
  echo.
  echo   PySide6 did not install, so wifirecon has no interface to draw.
  echo   Try running this by hand to see the error:
  echo       "%PY%" -m pip install PySide6-Essentials
  echo.
  pause
  exit /b 1
)
for /f "tokens=*" %%Q in ('"%PY%" -c "import PySide6;print(PySide6.__version__)" 2^>nul') do (
  echo   Interface ready - PySide6 %%Q, native window, no browser.
)

rem --- vendor database (optional) ------------------------------------------
set "DATADIR=%LOCALAPPDATA%\wifirecon-win"
if not exist "%DATADIR%" mkdir "%DATADIR%" >nul 2>&1
if not exist "%DATADIR%\manuf" (
  echo   Fetching the vendor database...
  "%PY%" -c "import urllib.request,sys; urllib.request.urlretrieve('https://www.wireshark.org/download/automated/data/manuf', r'%DATADIR%\manuf')" >nul 2>&1
  if exist "%DATADIR%\manuf" (echo   Vendor database saved.) else (echo   Skipped - the built-in list will be used.)
)

rem --- desktop shortcut ----------------------------------------------------
echo   Creating a desktop shortcut...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$s=New-Object -ComObject WScript.Shell; $l=$s.CreateShortcut([IO.Path]::Combine($env:USERPROFILE,'Desktop','wifirecon.lnk')); $l.TargetPath='%~dp0wifirecon.vbs'; $l.WorkingDirectory='%~dp0'; $l.Description='Wireless survey'; $l.Save()" >nul 2>&1

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$s=New-Object -ComObject WScript.Shell; $p=[IO.Path]::Combine($env:APPDATA,'Microsoft\Windows\Start Menu\Programs','wifirecon.lnk'); $l=$s.CreateShortcut($p); $l.TargetPath='%~dp0wifirecon.vbs'; $l.WorkingDirectory='%~dp0'; $l.Description='Wireless survey'; $l.Save()" >nul 2>&1

rem --- diagnostics ---------------------------------------------------------
echo.
echo   Running diagnostics...
echo.
"%PY%" -m app --doctor

echo.
echo   ------------------------------------------
echo   Setup finished.
echo.
echo   Start it by double-clicking wifirecon.vbs, or the wifirecon
echo   shortcut on your desktop. It opens its own window.
echo.
echo   Use "Start wifirecon (console).cmd" when you want to watch the log.
echo.

if not defined FROM_LAUNCHER pause
exit /b 0

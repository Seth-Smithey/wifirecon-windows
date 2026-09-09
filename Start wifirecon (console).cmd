@echo off
setlocal enabledelayedexpansion
title wifirecon
cd /d "%~dp0"

rem  Double-click launcher. Runs regardless of PowerShell execution policy,
rem  sets itself up on first run, and keeps the application alive if it stops
rem  unexpectedly. Use wifirecon.vbs for normal use; this one keeps the log
rem  visible.

set "VENV=%~dp0.venv"
set "PY=%VENV%\Scripts\python.exe"

if not exist "%PY%" (
  echo.
  echo   First run - setting up. This takes a couple of minutes.
  echo.
  call "%~dp0Setup wifirecon.cmd" --from-launcher
  if errorlevel 1 (
    echo.
    echo   Setup did not finish. Read the message above.
    echo.
    pause
    exit /b 1
  )
)

set /a RESTARTS=0
set /a MAXRESTARTS=5

:run
echo.
echo   Starting wifirecon with the log visible.
echo   For normal use, double-click wifirecon.vbs instead - no console window.
echo.
echo   Close the application window, or press Ctrl+C here, to stop.
echo.

"%PY%" -m app --console %*
set EXITCODE=%ERRORLEVEL%

rem  0 is a clean stop. 3 means the interface could not start, which restarting
rem  will not fix. Anything else is a crash, and the application is restarted so
rem  a bad driver call cannot end the session.
if "%EXITCODE%"=="0" goto done
if "%EXITCODE%"=="3" goto nointerface
if "%EXITCODE%"=="4" goto fatal
rem  A negative code here is a Windows structured exception - a missing Qt
rem  platform plugin or runtime. Restarting repeats it exactly.
if %EXITCODE% LSS 0 goto fatal

set /a RESTARTS+=1
if !RESTARTS! GTR %MAXRESTARTS% (
  echo.
  echo   wifirecon has stopped %MAXRESTARTS% times in a row ^(last code %EXITCODE%^).
  echo   Not restarting again. The log is at:
  echo     %LOCALAPPDATA%\wifirecon-win\wifirecon.log
  echo.
  pause
  exit /b %EXITCODE%
)

echo.
echo   wifirecon stopped unexpectedly ^(code %EXITCODE%^). Restarting - attempt !RESTARTS! of %MAXRESTARTS%.
timeout /t 3 /nobreak >nul
goto run

:fatal
echo.
echo   wifirecon could not start ^(code %EXITCODE%^). This does not get better
echo   by retrying. The log is at:
echo     %LOCALAPPDATA%\wifirecon-win\wifirecon.log
echo.
pause
exit /b %EXITCODE%

:nointerface
echo.
echo   The interface could not start. The message above says what is missing.
echo.
pause
exit /b 3

:done
echo.
echo   wifirecon stopped.
echo.
exit /b 0

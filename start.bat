@echo off
REM Double-click this to run LogMind on Windows.
REM
REM It asks Windows for administrator rights straight away, because the
REM Security log - failed logons, RDP attacks, new accounts - is unreadable
REM without them. Windows shows its own UAC prompt; that cannot be bypassed by
REM any program, and should not be. Decline it and LogMind still runs on the
REM logs you can read.
REM
REM   start.bat            request admin, then run
REM   start.bat limited    skip the request, run with current rights

setlocal
cd /d "%~dp0"

REM Find python NOW, while still in the user's own environment. Python is
REM often installed per-user, and an elevated shell does not inherit that PATH
REM - so the full path is handed to the elevated copy of this script.
set "PY=%~2"
if not defined PY (
  for /f "delims=" %%p in ('where python 2^>nul') do (
    if not defined PY set "PY=%%p"
  )
)
if not defined PY (
  for /f "delims=" %%p in ('where py 2^>nul') do (
    if not defined PY set "PY=%%p"
  )
)
if not defined PY (
  echo Python was not found.
  echo Install it from https://python.org/downloads and tick
  echo "Add python.exe to PATH" during setup, then run this file again.
  pause
  exit /b 1
)

if "%~1"=="limited"  goto :run
if "%~1"=="elevated" goto :run
net session >nul 2>&1
if not errorlevel 1 goto :run

echo Requesting administrator rights so LogMind can read the Security log...
echo (Choose No and it will still run on the logs you can read.)
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList 'elevated','\"%PY%\"' -Verb RunAs" 2>nul
if errorlevel 1 (
  echo Continuing without administrator rights.
  goto :run
)
exit /b 0

:run
echo.
echo Using Python: %PY%
echo Checking LogMind...
"%PY%" logmind.py --test
if errorlevel 1 (
  echo.
  echo Self-check FAILED - do not demo this build.
  pause
  exit /b 1
)

echo.
echo ============================================================
echo  Starting LogMind. Your browser opens by itself.
echo  The address is printed on the next line - use THAT one,
echo  not localhost:8000, which another program may be using.
echo ============================================================
echo.
"%PY%" logmind.py --live
echo.
echo LogMind has stopped.
pause

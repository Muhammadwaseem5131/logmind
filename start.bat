@echo off
REM Double-click this to run LogMind on Windows.
cd /d "%~dp0"

where python >nul 2>&1
if errorlevel 1 (
  echo Python was not found.
  echo Install it from https://python.org/downloads and tick
  echo "Add python.exe to PATH" during setup, then run this file again.
  pause
  exit /b 1
)

echo Checking LogMind...
python logmind.py --test
if errorlevel 1 (
  echo.
  echo Self-check FAILED - do not demo this build.
  pause
  exit /b 1
)

echo.
echo Starting the dashboard. Close this window to stop it.
python logmind.py
pause

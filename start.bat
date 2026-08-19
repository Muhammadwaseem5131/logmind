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

REM Reading the Windows Security log - the one that records logons, RDP
REM attempts and new accounts - needs administrator rights. Ask; never take.
net session >nul 2>&1
if not errorlevel 1 goto :run
if "%1"=="elevated" goto :run

echo.
echo LogMind can watch this PC's Security log - failed logons, RDP attacks,
echo new accounts - but Windows only allows that with administrator rights.
echo.
echo   [Y] Restart with administrator rights  (full monitoring)
echo   [N] Continue without                   (demo log and readable files only)
echo.
set /p ELEV="Choice [Y/N]: "
if /i "%ELEV%"=="Y" (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList 'elevated' -Verb RunAs"
  exit /b 0
)

:run
echo.
echo Checking LogMind...
python logmind.py --test
if errorlevel 1 (
  echo.
  echo Self-check FAILED - do not demo this build.
  pause
  exit /b 1
)

echo.
echo Starting LogMind: live monitoring + dashboard.
echo Close this window to stop it.
python logmind.py --live
pause

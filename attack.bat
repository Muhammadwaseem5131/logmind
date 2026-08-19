@echo off
REM Double-click to write a fake attack into the log LogMind is watching.
REM Start LogMind first (start.bat), then run this.
cd /d "%~dp0"
python simulate.py %1
echo.
echo Look at the LogMind live page - the finding should be there.
pause

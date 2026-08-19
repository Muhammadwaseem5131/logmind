#!/bin/sh
# Run LogMind on macOS or Linux:  ./start.sh
cd "$(dirname "$0")" || exit 1

PY=$(command -v python3 || command -v python)
if [ -z "$PY" ]; then
  echo "Python 3 was not found. Install it, then run this again."
  exit 1
fi

# /var/log/auth.log is usually group-readable by `adm`, not world-readable.
# Say so once rather than silently monitoring nothing useful.
if [ "$(id -u)" -ne 0 ] && [ ! -r /var/log/auth.log ] && [ ! -r /var/log/secure ]; then
  echo "Note: the system auth log is not readable by this user."
  echo "  Preferred: sudo usermod -aG adm \"$USER\"   (then log out and back in)"
  echo "  Or run this script with sudo for a one-off full run."
  echo
fi

echo "Checking LogMind..."
"$PY" logmind.py --test || { echo; echo "Self-check FAILED - do not demo this build."; exit 1; }

echo
echo "Starting LogMind: live monitoring + dashboard. Ctrl+C to stop."
exec "$PY" logmind.py --live

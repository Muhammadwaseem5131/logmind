#!/bin/sh
# Run LogMind on macOS or Linux:  ./start.sh
cd "$(dirname "$0")" || exit 1

PY=$(command -v python3 || command -v python)
if [ -z "$PY" ]; then
  echo "Python 3 was not found. Install it, then run this again."
  exit 1
fi

echo "Checking LogMind..."
"$PY" logmind.py --test || { echo; echo "Self-check FAILED - do not demo this build."; exit 1; }

echo
echo "Starting LogMind: live monitoring + dashboard. Ctrl+C to stop."
exec "$PY" logmind.py --live

#!/usr/bin/env bash
# Linux / macOS launcher:  ./start.sh      (use  sudo ./start.sh  for monitor-mode scans)
cd "$(dirname "$0")" || exit 1
PY="$(command -v python3 || command -v python)"
if [ -z "$PY" ]; then echo "Python 3.8+ is required: https://www.python.org/downloads/"; exit 1; fi
exec "$PY" run.py "$@"

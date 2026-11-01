#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "Python 3 is required. Install it with: brew install python"
  exit 1
fi

echo "Starting process / file (eslogger) and network (packet capture, lsof, nettop) telemetry."
echo "Grant Full Disk Access to Terminal (System Settings > Privacy & Security > Full Disk Access)."
echo "Press Ctrl-C to stop."
exec sudo "$PYTHON" "$PWD/agent/hostwatch_agent.py" "$@"

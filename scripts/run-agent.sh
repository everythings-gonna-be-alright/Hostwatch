#!/bin/bash
# Runs the collector by hand (as root) for development: the app connects to it instead of starting one.
set -euo pipefail
cd "$(dirname "$0")/.."

BIN=".build/release/Hostwatch"
[ -x "$BIN" ] || swift build -c release
echo "Starting process / file (eslogger) and network (packet capture, lsof, nettop) telemetry."
echo "Grant Full Disk Access to Terminal (System Settings > Privacy & Security > Full Disk Access)."
echo "Press Ctrl-C to stop."
exec sudo "$PWD/$BIN" --collector "$@"

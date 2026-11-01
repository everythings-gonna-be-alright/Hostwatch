#!/bin/bash
# Runs every test: Swift (patterns, stories, signing, domains) and Python (collector parsers).
# Exit code is non-zero if anything fails. Used by the pre-merge-commit hook.
set -uo pipefail
cd "$(dirname "$0")/.."
log=$(mktemp -t hostwatch-tests)
status=0

echo "== Swift tests"
if swift test >"$log" 2>&1; then
  grep -E "^✔ Test run with" "$log"
else
  status=1
  grep -E "error:|✘|Expectation failed|recorded an issue" "$log" | head -40
  grep -qE "✘ Test run with" "$log" || tail -20 "$log"   # build failure: show the end of the log
fi

echo "== Collector tests"
if python3 -I -m unittest discover -s tests/agent >"$log" 2>&1; then
  tail -3 "$log" | grep -E "^Ran|^OK"
else
  status=1
  cat "$log"
fi

rm -f "$log"
[ $status -eq 0 ] && echo "All tests passed." || echo "TESTS FAILED."
exit $status

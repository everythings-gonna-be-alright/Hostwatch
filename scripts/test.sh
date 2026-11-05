#!/bin/bash
# Runs every test (Swift Testing: the app, the collector, the MCP server).
# Exit code is non-zero if anything fails. Used by the pre-merge-commit hook.
set -uo pipefail
cd "$(dirname "$0")/.."
log=$(mktemp -t hostwatch-tests)
status=0

# Tests that measure this process's memory run alone afterwards: in the parallel run other tests' allocations
# land in the same measurement.
alone="CollectorLineLoops"

echo "== Swift tests"
if swift test --skip "$alone" >"$log" 2>&1; then
  grep -E "^✔ Test run with" "$log"
else
  status=1
  grep -E "error:|✘|Expectation failed|recorded an issue" "$log" | head -40
  grep -qE "✘ Test run with" "$log" || tail -20 "$log"   # build failure: show the end of the log
fi

echo "== Memory tests (alone)"
if swift test --filter "$alone" --no-parallel >"$log" 2>&1; then
  grep -E "^✔ Test run with" "$log"
else
  status=1
  grep -E "error:|✘|Expectation failed|recorded an issue" "$log" | head -20
fi

echo "== Demo build (demo mode compiled in)"
if swift test --build-path .build-demo -Xswiftc -DDEMO --filter DemoData >"$log" 2>&1; then
  grep -E "^✔ Test run with" "$log"
else
  status=1
  grep -E "error:|✘|Expectation failed|recorded an issue" "$log" | head -20
  grep -qE "✘ Test run with" "$log" || tail -20 "$log"
fi

rm -f "$log"
[ $status -eq 0 ] && echo "All tests passed." || echo "TESTS FAILED."
exit $status

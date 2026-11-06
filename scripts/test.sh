#!/bin/bash
# Runs every test (Swift Testing: the app, the collector, the MCP server).
# Exit code is non-zero if anything fails. Used by the pre-merge-commit hook.
set -uo pipefail
cd "$(dirname "$0")/.."
log=$(mktemp -t hostwatch-tests)
status=0

# Tests that measure this process's memory, CPU or disk writes run afterwards, each in a process of its own: in the
# parallel run other tests' work lands in the same measurement, and even one test's leftovers skew the next one's.
alone="CollectorLineLoops|PerformanceBudget"
alone_tests="CollectorLineLoops PerformanceBudget/appEventPipeline PerformanceBudget/historyWriting PerformanceBudget/collectorEsloggerLoop PerformanceBudget/timeTravelReading"

echo "== Swift tests"
if swift test --skip "$alone" >"$log" 2>&1; then
  grep -E "^✔ Test run with" "$log"
else
  status=1
  grep -E "error:|✘|Expectation failed|recorded an issue" "$log" | head -40
  grep -qE "✘ Test run with" "$log" || tail -20 "$log"   # build failure: show the end of the log
fi

echo "== Memory and performance budget (each alone)"
for t in $alone_tests; do
  if swift test --filter "$t" --no-parallel >"$log" 2>&1; then
    grep -E "^PERF " "$log" || echo "$t: ok"
  else
    status=1
    grep -E "^PERF |error:|✘|Expectation failed|recorded an issue|↳" "$log" | head -12
  fi
done

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

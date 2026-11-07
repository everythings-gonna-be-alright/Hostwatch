#!/bin/bash
# Runs every test (Swift Testing: the app, the collector, the MCP server).
# Exit code is non-zero if anything fails. Used by the pre-merge-commit hook.
set -uo pipefail
cd "$(dirname "$0")/.."

# Only part of it:
#   ./scripts/test.sh --only 'FewerPatterns|RuleText'   suites or tests matching a regex (swift test --filter)
#   ./scripts/test.sh --changed                          the suites that mention types declared in files changed
#                                                        since main (plus uncommitted ones); the gate still runs all
if [ "${1:-}" = "--only" ] || [ "${1:-}" = "--changed" ]; then
  if [ "$1" = "--only" ]; then
    filter="${2:?a regex, e.g. --only 'FewerPatterns|RuleText'}"
  else
    changed=$( (git diff --name-only main -- src tests; git diff --name-only -- src tests; git ls-files --others --exclude-standard src tests) | sort -u)
    [ -z "$changed" ] && { echo "nothing changed since main"; exit 0; }
    # Types the changed source files declare, and test files that use them (a changed test file counts as itself).
    types=$(grep -hoE '^(struct|enum|final class|class|actor|extension) [A-Z][A-Za-z0-9_]+' $(echo "$changed" | grep '^src/' || true) 2>/dev/null \
            | awk '{print $NF}' | sort -u | paste -sd'|' -)
    files=$(echo "$changed" | grep '^tests/' || true)
    [ -n "$types" ] && files="$files $(grep -lE "\b($types)\b" tests/swift/*.swift 2>/dev/null)"
    filter=$(grep -hoE '@Suite(\([^)]*\))? struct [A-Za-z0-9_]+' $files 2>/dev/null | awk '{print $NF}' | sort -u | paste -sd'|' -)
    [ -z "$filter" ] && { echo "no test suite mentions the changed types ($changed)"; exit 0; }
    echo "== Suites for the changed files: $(echo "$filter" | tr '|' ' ')"
  fi
  swift test --skip "CollectorLineLoops|PerformanceBudget" --filter "$filter" 2>&1 | grep -E "error:|✘|✔ Test run with|Expectation failed|recorded an issue" | head -40
  exit "${PIPESTATUS[0]}"
fi
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

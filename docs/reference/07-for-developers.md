## For developers

### Where to start

- `CLAUDE.md` in the repository root: how to build, test and release, the git workflow, and the invariants that bite.
- `docs/ARCHITECTURE.md`: the flow from the collector to the views and a map of every source file.
- `docs/DESIGN.md`: the rules for anything you can see, from Apple's guidelines to this app's words.
- `docs/adr/`: the decisions behind the shape, one file each.

`src/hostwatch` is the app and the collector, one binary. `tests/swift` holds the tests.

### Build & run

You need macOS 26 and the Xcode 26 Command Line Tools, which bring Swift 6.2+ and the macOS 26 SDK:

```bash
xcode-select --install
```

```bash
swift build                     # debug binary at .build/debug/Hostwatch (the command-line tools work from it)
./scripts/build-app.sh          # dist/Hostwatch.app
open dist/Hostwatch.app
./scripts/package.sh            # a release: universal build, notarized, stapled and zipped
```

- **Signing:** `build-app.sh` signs with your Developer ID when the keychain has one. Such a build registers the
  collector as a background service once (one password). A build without a Developer ID starts the collector with an
  admin prompt each time it launches.
- **Full Disk Access after a rebuild:** an ad-hoc signed build looks like a new app to macOS, so every rebuild needs
  Full Disk Access granted again. Remove the old Hostwatch entry with − and add it again. To avoid this, build with a
  stable identity: `CODESIGN_IDENTITY="Apple Development: you@example.com (TEAMID)" ./scripts/build-app.sh`.
- **Running the collector by hand:** `./scripts/run-agent.sh` builds a release binary and runs
  `sudo Hostwatch --collector` in Terminal, and the app connects to it instead of starting its own. Grant Full Disk
  Access to Terminal for this. Options: `--no-files`, `--no-net`, `--net-interval <seconds>`, `--socket <path>`.
  Started this way, the collector accepts connections only from the user who ran `sudo`.

A quick check with the collector running:

```bash
/usr/bin/id                                # a process
curl -sI https://example.com >/dev/null    # a process and a connection
cat ~/.zshrc >/dev/null                    # a file
```

### Test

```bash
./scripts/test.sh                                 # everything, about 30 s, the same as the merge gate
./scripts/test.sh --changed                       # the suites that mention types declared in files changed since main
./scripts/test.sh --only 'FewerPatterns|RuleText' # suites or tests matching a regex
```

- **Swift tests** (`tests/swift`, Swift Testing) cover patterns and risk, stories (attack chains must fire, everyday
  dev work must stay quiet), code signing on real binaries made in a temp folder, domains, beaconing, the collector's
  parsers, secret masking and the socket's checks. They use in-memory stores and a scratch signing database, so they
  never touch your data.
- **The story corpus** (`tests/corpus/stories.jsonl`) holds every false story seen on a real Mac, anonymised (`$HOME`
  for the home folder), beside attack chains. `StoryCorpus` replays it with the live threat-list filters: it fails if
  a false story comes back or an attack goes quiet. A new false story found with `--story-report` belongs there.
- **The demo build** is built and its tests run too.
- **Performance budget** (`PerformanceBudgetTests.swift`) runs realistic workloads (the app's pipeline, the history
  writer, the collector's reader, Time Travel) and compares CPU time, bytes written and memory with
  `tests/perf-baseline.json`. A change fails when it writes more than +20%, keeps or peaks more than +30% memory, or
  uses more than twice the CPU. After a change meant to cost more or less, record a new baseline on purpose and commit
  it: `HOSTWATCH_PERF_RECORD=1 ./scripts/test.sh`. Numbers depend on the Mac, so record one on yours if it is much
  faster or slower.
- **Merges are gated.** `scripts/hooks/pre-merge-commit` runs the tests on the merged result and refuses the merge
  if anything fails. Enable it after a fresh clone with `git config core.hooksPath scripts/hooks`.

### Debug tools and environment variables

Run each as `Hostwatch <flag>` from `.build/debug/Hostwatch` or from the app bundle. All of them only read, unless
noted.

| Flag | What it does |
|------|--------------|
| `--signature-report <history.jsonl>` | How events group into patterns. `REPORT_NOSIGN=1` turns the signing rules off to measure their effect. |
| `--regroup-report [folder]` | What the next launch's regrouping would do to the saved patterns. |
| `--origin-report [history folder]` | How many kinds of origin each tool pattern has. `DAYS`, `HOURS`, `LEARN_DAYS` and `REPORT_TOP` shape it. |
| `--story-replay <history.jsonl>` | Feeds recorded events (a file or a history folder) through the story engine, as live: today's threat lists (from a scratch copy), your patterns for what was everyday, and the domains you knew before. Prints the stories and how many would have alerted. `REPLAY_PLAIN=1` leaves lists, patterns and domains out, `REPLAY_LEARN_MINUTES` sets the learning time then (60 by default), `HOSTWATCH_OWN_BUNDLE` the app to treat as Hostwatch. About 11 minutes and 2 GB for a busy day: replay one day at a time. Run it from the signed app. |
| `--package-scan [folder]` | Finds projects (Spotlight, or only `folder`), downloads the malicious-package lists they need into a scratch folder kept between runs, and prints the packages per language, what was found, the size of the lists the collector gets, and timings. Never touches your own lists or findings. Run it from the signed app. |
| `--suggest-rules` | A dry run of rule suggestions from your decisions. Asks Claude, checks every proposal and writes nothing. |
| `--triage-benchmark` | Compares AI models on your own decisions: false Safe, how many it settles, speed. `BENCH_MODELS=apple,<ollama model>,claude:haiku` picks them, `BENCH_N` the sample size, `BENCH_OUT` the details file. Run it from the signed app. |
| `--signing-check <path>…` | Signing facts and the trust decision for files, and records them. |
| `--guard-report` | What the Claude Code guard stopped, grouped by reason with how you answered and a few examples, then the same commands through today's rules. Run it from the signed app (the log is sealed). |
| `--story-report [N]` | The last N stories (default 60) as text, with a count by stages, to study which chains are noise. Read only. Run it from the signed app (stories are sealed). |
| `--time-travel-probe [folder]` | Times reading and searching history for Time Travel. |
| `--compress-history <folder>` | Compresses plain history files and prints sizes and timings. |
| `sudo … --watch-test <pid> [seconds]` | Records a process like Watch Closely (30 s by default) and prints the result. |
| `sudo … --firewall-probe` | Checks that the firewall's relay works on this Mac, on two test destinations, for about 15 seconds. |
| `sudo … --firewall-relay-test [seconds]` | Runs the relay and reports what passes through it. |

The app starts these by itself: `--collector` (the collector, as root, with `--daemon`, `--owner-pid`, `--token-file`
and `--socket`) and `--collector-launcher` (started by launchd, it spawns the collector).

Variables that change what the app trusts (`HOSTWATCH_SOCKET`, `HOSTWATCH_SIGNING_DB`, `HOSTWATCH_OWN_BUNDLE`,
`REPORT_NOSIGN`) work only in debug and demo builds. The shipped app ignores them, so another program can't relaunch
it with one set. Run the tools that use them from `.build/debug/Hostwatch`.

| Variable | What it does |
|----------|--------------|
| `HOSTWATCH_SOCKET` | Points the app at another collector socket. Its folder then need not be root-owned. |
| `HOSTWATCH_SIGNING_DB` | A scratch signing database, for tests and `--signing-check`. |
| `HOSTWATCH_MCP_TOKEN` | The MCP server's access token, set by the registration command from Settings ▸ AI. |
| `HOSTWATCH_PERF_RECORD=1` | Records a new performance baseline. |
| `CLAUDE_PATH` | Where the `claude` command is, when it isn't in a usual place. |
| `CODESIGN_IDENTITY` | The identity `build-app.sh` signs with. |
| `DEMO=1`, `RELEASE=1` | `build-app.sh` makes the demo build, or keeps whole-module optimisation as releases do. |

### Demo mode (screenshots)

Demo mode fills the app with made-up activity, for screenshots and the website. It exists only in the demo build.
The normal build, and every release, has no demo code at all.

**Build it:** `DEMO=1 ./scripts/build-app.sh` makes `dist/Hostwatch Demo.app`, with the Swift flag `-DDEMO`, its own
bundle id `tech.hostwatch.demo` and its own build folder `.build-demo`.

**Run it:**
`"Hostwatch Demo.app/Contents/MacOS/Hostwatch" --demo <folder> [hud|events|live|running|patterns|stories|network|map|firewall|protection|watch]`

- **What it shows:** a made-up user (`/Users/alex`) at everyday work, plus a fake download that removes its
  quarantine, reads cookies and the keychain, adds a launch agent and calls home. It opens the scene you name.
- **`live`** keeps adding events about once a second, for the website's background video.
- **Isolation:** everything it keeps goes to `<folder>`. It never connects to the collector and starts nothing as
  root.
- **Screenshot options:** `HOSTWATCH_DEMO_SIZE=full` fills the screen, `=fullscreen` enters full screen (the default
  is 1280 × 780). `HOSTWATCH_DEMO_PAGE=files`, `found` or `firewall` opens another Protection page.
  `HOSTWATCH_DEMO_MEASURE=sent` sizes the network map by data sent.

### Prototype notes

The collector is an Endpoint Security client in the root service (ADR 0018). Only the collector is entitled: it runs
from its own bundle inside the app (`Contents/Library/Helpers/Hostwatch Collector.app`, `tech.hostwatch.collector`),
and the app keeps the signature it always had, so its keychain identity and data key never change. Apple grants the
`com.apple.developer.endpoint-security.client` entitlement per team, through a Developer ID provisioning profile for
`tech.hostwatch.collector` that `build-app.sh` embeds when it finds one (`HOSTWATCH_COLLECTOR_PROFILE`, or
`~/.hostwatch-signing/HostwatchCollector.provisionprofile`). Without the profile there is no helper, and the collector
falls back to Apple's `eslogger`, a tool Apple documents for exploring and prototyping, whose output may change.
Don't disable SIP as a way around this.

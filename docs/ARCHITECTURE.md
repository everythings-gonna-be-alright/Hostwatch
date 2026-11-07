# Architecture

One Swift package, one binary. `Hostwatch` is the menu-bar app; the same binary run with a flag is the root
collector (`--collector`), its launcher, the MCP server (`--mcp`), the Claude Code hook (`--claude-hook`) and the
developer tools (`--signature-report`, `--regroup-report`, `--story-replay`, `--time-travel-probe`,
`--firewall-probe`…). `Main.swift` dispatches on the flag; everything else is ordinary code.

## The flow

```
 root collector (Agent*.swift)                       app, main actor
 ───────────────────────────                         ───────────────────────────────────────────────────────────
 eslogger exec/exit/open ─┐                          HUDModel.receive(line)
 pktap DNS + SYN ─────────┼─ JSON lines, masked ──▶    ActivityEvent (Events.swift)
 NetworkStatistics ───────┤   over a Unix socket        │ SignatureBuilder.signature(for:)   pure: kind|process|pattern + risk
 libproc processes ───────┘   (CollectorSocket)         ├─ SignatureStore.observe   ──▶ PatternStore: status, source, counts
                                                        ├─ StoryEngine.ingest      ──▶ Stories: suspicious steps per process tree
                                                        ├─ DomainRegistry.observe  ──▶ first-seen domains
                                                        ├─ FirewallMonitor.observe ──▶ Watch / Ask / Strict (relay in the collector)
                                                        ├─ ThreatIntel             ──▶ known-bad domains, IPs, hashes
                                                        └─ HistoryRecorder.append  ──▶ compressed JSONL on disk (HistoryStream)
                                                      views read the engines (ObservableObject); AppDelegate wires them
```

A pattern (`SignatureEntry`) is the unit of decision: *who* (normalized program path) does *what* (a normalized
target) → New / Safe / Suspicious / Dangerous, with `source` = who decided (you, rule, baseline, claude,
on-device, auto). Everything downstream — Needs You, Stories, the firewall, the AI — reads that.

## Map of `src/hostwatch`

**Events and patterns**
- `Events.swift` — `ActivityEvent`, `EventKind`; parsing the collector's JSON.
- `PatternModel.swift` — `SignatureEntry`, `SignatureStatus`, `PatternRisk`, the Show filter.
- `PatternBuilder.swift` — `SignatureBuilder`: normalization, path knowledge (sensitive places, zones, LOLBins),
  the pattern rules (the general rule `specificPath` / `isTooWide`, projects, scratch trees, Homebrew, system
  programs' ordinary reads, plain tools), code-signing adjustments (`withSigning`).
- `PatternStore.swift` — `SignatureStore`: observe, decide, rules applied, persistence (snapshot + journal), tidy
  (prune, fold), regroup (migration into today's pattern forms), merges and aliases, `dropInterpreterTrust`.
- `PatternClassifier.swift` — batch classification with Claude or the on-device model (`OnDeviceTriage.swift`).
- `PatternMerges.swift`, `BuiltInSafe.swift`, `MemoCache.swift`, `PatternTools.swift` (developer reports).
- `Baseline.swift` — `BaselinePolicy` (what a trusted app may do), `BaselineLearner` (rules from code signatures).
- `Rules.swift` — learned rules: `LearnedRule`, evaluation and regression, `RuleBook`, `RuleText` (plain words).
- `Signing.swift` — who signed a binary, cached (`SigningCache.shared`); `Secrets.swift` — masking.

**Detection**
- `Stories.swift` — `StoryEngine`: stages, scoring per process tree, what counts as a step. `StoryReplay.swift`.
- `NetSignals.swift`, `Domains.swift`, `DomainDetails.swift` — beaconing, raw IPs, first-seen domains, risk score.
- `ThreatIntel.swift` — threat lists, matched locally. `Hold.swift` — holding a process while you decide.
- `Watch.swift` — Watch Closely (a second eslogger on one process). `CommandGuard.swift`, `ClaudeGuard.swift` —
  the Claude Code hook: judge a tool call before it runs.
- `Firewall.swift`, `FirewallRelay.swift`, `PFRedirect.swift`, `SocketOwner.swift` — modes, the relay, pf rules.

**History**
- `HistoryRecorder.swift` (what to write, rotation, the cap), `HistoryStream.swift` (compressed as written, crash
  safety), `HistoryFiles.swift` (files, indexes, gunzip), `HistoryArchive.swift` (reading by time),
  `TimeTravel.swift` (state), `ProcessHistory.swift`, `Metrics.swift`, `ProcessVitals.swift`.

**Collector (root)**
- `Agent.swift` (loop, sources, JSON out), `AgentNet.swift` (parsers, pure), `AgentSystem.swift` (libproc),
  `AgentProcesses.swift`, `AgentFirewall.swift`, `AgentWatch.swift`, `NetStats.swift`, `Collector.swift` (start and
  stop from the app), `CollectorLauncher.swift`, `CollectorSocket.swift`.

**App**
- `Main.swift` — entry point and command-line modes. `App.swift` — `AppDelegate`'s state and launch wiring;
  `AppDelegate+Features/Overlay/Menus/Windows.swift` — the rest of it.
- `HUDModel.swift` — the live event list, filters, search; `HUDView.swift` — the overlay; `ActivityWindowView.swift`
  — the main window; `*View.swift` per tab or window; `Settings.swift`; `SharedViews.swift`, `Tables.swift`.
- `MCPServer.swift`, `MCPAccess.swift` — read-only MCP for Claude Code. `AskAI.swift` / `AskAIView.swift`.
- `Updates.swift`, `LoginItem.swift`, `Reset.swift`, `AppPaths.swift`, `Demo.swift` (demo build only).

## Where things live on disk

`~/Library/Application Support/Hostwatch/`: `signatures-v2.json` + `.journal` (patterns), `rules.json`,
`domains.json`, `firewall-watch.json`, `claude-guard.json`, `intel/`, `collector.token`.
`~/Library/Logs/Hostwatch/History/`: `activity-*.jsonl.gz` + `.blocks`/`.idx`, `metrics-*`, `processes-*`.
Settings in `UserDefaults` (`local.hostwatch.app`).

## Tests

`tests/swift`, Swift Testing. Suites mirror the map: `PatternTests`, `FewerPatternsTests`, `RuleTests`,
`StoryTests` (attack chains fire, everyday work stays quiet), `AgentTests` (real captured lines), `HistoryStream`,
`TimeTravel`, `MCPServer`, `PerformanceBudgetTests` (CPU, writes, memory against `tests/perf-baseline.json`, each
alone in its own process). `./scripts/test.sh` is the gate; `--changed` and `--only` for the edit loop.

## Decisions

See `docs/adr/` for the decisions behind the shape: zone-based patterns, no blanket trust of interpreters,
compressed-as-written history, the single binary, Developer ID signing, and the "fewer patterns" rules.

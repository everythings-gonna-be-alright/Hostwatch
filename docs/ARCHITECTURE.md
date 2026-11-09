# Architecture

One Swift package, one binary. `Hostwatch` is the menu-bar app; the same binary run with a flag is the root
collector (`--collector`), its launcher, the MCP server (`--mcp`), the Claude Code hook (`--claude-hook`) and the
developer tools (`--signature-report`, `--regroup-report`, `--origin-report`, `--story-replay`, `--time-travel-probe`,
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

One folder per area; a folder is the map, a file is one concept named after its main type. Views read the engines
and never the reverse, so they sit in `Views/` (a few live next to their engine as `…View.swift`). The structure
test (`tests/swift/StructureTests.swift`) keeps it so: every file in an area folder, no SwiftUI outside `Views/`,
`App/`, `AI/` and `Events/`, nothing over 1,000 lines.

**`Events/`** — `Events.swift` (`ActivityEvent`, `EventKind`, parsing the collector's JSON), `Exclusions.swift`,
`HUDModel.swift` (the live event list, filters, search), `Secrets.swift` (masking), `Vault.swift` (everything on
disk sealed with the data key kept in the Secure Enclave or the keychain, ADR 0009).

**`Patterns/`**
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
- `Signing.swift` — who signed a binary, cached (`SigningCache`).

**`Detection/`**
- `Stories.swift` — `StoryEngine`: stages, scoring per process tree, what counts as a step. `StoryReplay.swift`.
- `AgentSessions.swift` — coding-agent sessions (Claude Code, Cursor agent, Codex, Gemini CLI): one per agent process
  and its tree, by lineage at event time; named from Claude's transcript; replayed from history for Time Travel.
- `NetSignals.swift`, `Domains.swift`, `DomainDetails.swift` — beaconing, raw IPs, first-seen domains, risk score.
- `ThreatIntel.swift` — threat lists, matched locally. `Hold.swift` — holding a process while you decide.
- `Watch.swift` — Watch Closely (a second eslogger on one process). `CommandGuard.swift`, `ClaudeGuard.swift` —
  the Claude Code hook: judge a tool call before it runs.

**`Firewall/`** — `Firewall.swift` (modes, what it would do), `FirewallRelay.swift` (the relay), `PFRedirect.swift`
(pf rules), `SocketOwner.swift`, `FirewallProbe.swift`, `FirewallRelayTest.swift` (the `sudo` self-checks).

**`Protection/`** — `ProtectionPolicy.swift` (modes, protected-file cards, what a launch or file access gets: pure),
`ProtectionMonitor.swift` (the Watch rehearsal on the live feed, findings, the collector's settings and questions,
ADR 0011), `ReactiveEnforcer.swift` (Ask and Strict until Endpoint Security: stop or pause right after the event). The page is `Views/ProtectionView.swift` (Rules ▸ Protection), the question panel
`Views/ProtectionPromptView.swift`, the wiring `App/AppDelegate+Protection.swift`.

**`History/`** — `HistoryRecorder.swift` (what to write, rotation, the cap), `HistoryStream.swift` (compressed as
written, crash safety), `HistoryFiles.swift` (files, indexes, gunzip), `HistoryArchive.swift` (reading by time),
`TimeTravel.swift` (state), `ProcessHistory.swift`, `Metrics.swift`, `ProcessVitals.swift`.

**`Collector/`** (runs as root, no UI) — `Agent.swift` (loop, sources, JSON out), `AgentNet.swift` (parsers, pure),
`AgentSystem.swift` (libproc), `AgentProcesses.swift`, `AgentFirewall.swift`, `AgentWatch.swift`, `NetStats.swift`;
`Collector.swift` (start and stop from the app), `CollectorDaemon.swift` (the background service: `SMAppService`
registration and status), `CollectorLauncher.swift`, `CollectorSocket.swift`.

**`AI/`** — `AskAI.swift` / `AskAIView.swift` (the Ask AI window), `MCPServer.swift`, `MCPAccess.swift` (read-only
MCP for Claude Code), `ClaudeUsage.swift` (tokens and cost).

**`App/`** — `Main.swift` (entry point and command-line modes), `App.swift` (`AppDelegate`'s state and launch
wiring), `AppDelegate+Features/Overlay/Menus/Windows.swift`, `Settings.swift`, `Updates.swift`, `LoginItem.swift`,
`Reset.swift`, `AppPaths.swift`, `HotKey.swift`, `MenuBarIcon.swift`.

**`Views/`** — `HUDView.swift` (the overlay), `ActivityWindowView.swift` (the main window), one `…View.swift` per
tab or window (`PatternsView` with `PatternInspector`, `RulesView`, `StoriesView`, `NetworkView`, `RunningView`, `WatchView`,
`FirewallView`, `StoryDetails`, `DiskView`, `TimelineBar`, `ClaudeGuardView`, `FullDiskAccessView`, `HeldView`,
`DomainDetailView`, `MetricsViews`, `VitalsViews`),
`OverviewView.swift` (the tab bar), `SharedViews.swift`, `SessionViews.swift` (the makers' marks, session facts), `Tables.swift` (row models),
`EventsTable.swift` + `EventsTableCells.swift` (the Events list as an AppKit outline view with reused cells, ADR 0010), `EventMenus.swift` (its
right-click menus), `LaunchChainView.swift` (the Show Launch Chain window), `Demo.swift` (demo build only).

## Where things live on disk

`~/Library/Application Support/Hostwatch/`: `signatures-v2.json` + `.journal` (patterns), `rules.json`,
`domains.json`, `firewall-watch.json`, `claude-guard.json`, `intel/`, `collector.token`.
`~/Library/Logs/Hostwatch/History/`: `activity-*.jsonl.gz` + `.blocks`/`.idx`, `metrics-*`, `processes-*`.
Settings in `UserDefaults` (`tech.hostwatch.app`; `local.hostwatch.app` up to 0.13.0, carried over by `Migration`).

## Tests

`tests/swift`, Swift Testing. Suites mirror the map: `PatternTests`, `FewerPatternsTests`, `RuleTests`,
`StoryTests` (attack chains fire, everyday work stays quiet), `AgentTests` (real captured lines), `HistoryStream`,
`TimeTravel`, `MCPServer`, `PerformanceBudgetTests` (CPU, writes, memory against `tests/perf-baseline.json`, each
alone in its own process). `./scripts/test.sh` is the gate; `--changed` and `--only` for the edit loop.

## Decisions

See `docs/adr/` for the decisions behind the shape: zone-based patterns, no blanket trust of interpreters,
compressed-as-written history, the single binary, Developer ID signing, and the "fewer patterns" rules.

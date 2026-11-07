# Hostwatch — working notes for Claude Code (and anyone new)

Behaviour-based intrusion detection for macOS, one Swift package, one app binary that is also the collector, the
MCP server and every command-line tool. Read `docs/ARCHITECTURE.md` first (the map), then the chapter of
`docs/reference/` for the area you touch (the spec: the website docs are generated from it).

## Build, test, release

```bash
swift build                                  # debug binary at .build/debug/Hostwatch (command-line modes work from it)
./scripts/build-app.sh                       # dist/Hostwatch.app, signed with the Developer ID when the keychain has it
./scripts/test.sh                            # everything (~30 s): the merge gate runs exactly this
./scripts/test.sh --changed                  # only the suites that mention types declared in changed files
./scripts/test.sh --only 'FewerPatterns|RuleText'
HOSTWATCH_PERF_RECORD=1 ./scripts/test.sh    # new performance baseline (tests/perf-baseline.json), on purpose only
./scripts/package.sh                         # release: universal build, notarized, stapled, zipped
```

- Swift Testing (`@Suite`, `#expect`), in `tests/swift`. Tests use scratch folders and in-memory stores, never the
  user's data. `HOSTWATCH_SIGNING_DB` points the signing cache at a scratch file.
- Command Line Tools toolchain, not Xcode: SwiftUI's `@State` macro is unavailable, use a small `ObservableObject`
  (`ExpandState`) instead. Swift 6 language-mode warnings are known; don't add new ones.
- Demo build (`DEMO=1 ./scripts/build-app.sh`) adds `Demo.swift` behind `-DDEMO`; the release has no demo code.

## Git workflow (local-only repository)

- Never push. Work on a branch, then `git merge --no-ff` into `main`; the `pre-merge-commit` hook runs the full gate
  and refuses a failing merge. Don't commit on `main` directly.
- Commit messages: what changed and why, in plain words. `CHANGELOG.md` is for people: group by New / Faster and
  lighter / Fixes; the top section is "Unreleased" until a release.
- Before a release, the privacy scan must find no personal names or private hosts in the repo (the Developer ID
  inside the signed binary is expected).

## Invariants that bite (learned the hard way)

- **Pattern text carries meaning.** A file pattern ending in `]` (`r ~/.ssh/*  [SSH keys]`) is *sensitive*:
  `isTooWide` lets it through, `withSigning` never makes it routine, Baseline and Stories treat it as a sensitive
  read. A new label must not end in `]` unless it is sensitive; `[ordinary files]` is the exception by name.
- **`SignatureBuilder.isTooWide` is the general rule**: no file pattern may cover a whole area (`r ~/*`,
  `r ~/Documents/*`, `r /tmp/*`). Rules, merges and the tidy fold are validated against it, and
  `dropInterpreterTrust()` deletes wide patterns at launch unless you or a rule decided them. A new pattern form
  that is wide by text but specific by meaning needs an explicit exemption there.
- **Interpreters, shells and LOLBins are never trusted broadly** (`isLolbin`, `runsAnyCode`): their patterns name the
  script, the exact folder or the destination, and a Safe rule for them is refused. Keep it that way.
- **Precedence:** you > your rules > Claude / on-device > automatic. `source` on a `SignatureEntry` records who
  decided; code that changes a status must respect it (`ruleOverridable`, `mayRegroup`, tidy).
- **Risk only goes up by itself.** `raise` reopens a Safe decision when a binary is swapped or quarantined; nothing
  lowers risk automatically except `reassess` after signing facts change.
- **History is append-only and crash-safe**: compressed as written, a block list that only grows, nothing written
  twice. Readers must tolerate a streaming file with no finished blocks yet.
- **The collector runs as root** and talks over a Unix socket with a token. Everything it sends is masked
  (`Secrets`) before it reaches history or any prompt. Nothing leaves the Mac except: Claude calls you enabled,
  threat-list downloads, the update check, and the firewall relay's self-check.
- **Patterns are keys.** `kind|process|pattern` is the identity of a decision; changing how a pattern is built
  orphans old decisions unless `SignatureStore.regroup` (or a merge alias) moves them.

## Style

- Files are one concept each, named after the main type; keep them under ~700 lines (split along `// MARK:` when
  they grow). `Foo.swift` is the model/engine, `FooView.swift` the SwiftUI, `AppDelegate+Foo.swift` the wiring.
- Pure functions over values for anything decided (`SignatureBuilder`, `RuleText`, `BaselinePolicy`): testable
  without a store, no singletons inside. Engines are `@MainActor` `ObservableObject`s owned by `AppDelegate`.
- Comments say *why* and what would break, not what the line does. User-facing text is plain language, no jargon,
  no semicolons.
- Measure before and after on real data when a change is about volume or speed (`--regroup-report`,
  `--signature-report`, `--time-travel-probe`); report the numbers.

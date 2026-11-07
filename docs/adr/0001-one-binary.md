# 0001 One binary: app, root collector, MCP server and tools

**Context.** The collector needs root (eslogger, pktap, libproc for every user). A separate helper binary means a
second signing identity, a second update path and a bundle layout to keep in sync.

**Decision.** `Hostwatch` is one executable. `Main.swift` dispatches on the first flag: `--collector` (root, started
by a launchd job through `--collector-launcher`), `--mcp`, `--claude-hook`, `--demo` (demo build only) and the
developer tools. The app and the collector share the event model and the masking code.

**Consequences.** One signature, one notarization, one version. Everything that runs as root must be reachable from
the same code base, so the collector's files (`Agent*.swift`) must not import AppKit and must not reach into the
app's state. The socket between them carries a token (`collector.token`, mode 0600) and the collector checks the
peer's uid.

**Update (0.13).** The collector runs as an `SMAppService` daemon: a LaunchDaemon plist inside the bundle
(`Contents/Library/LaunchDaemons/local.hostwatch.collectord.plist`, `BundleProgram` the same binary, run with
`--collector-launcher self --collector --daemon`). Registered once, approved once, started by launchd at boot; the
agent serves the console user and ignores shutdown requests (the app unregisters it instead). The admin-prompted
temporary job stays as the fallback for unsigned builds. The label differs from the old job's so both can exist.

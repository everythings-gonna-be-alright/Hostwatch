## Settings

Open Settings with ⌘,. It has one pane per area. Every control is listed below with its default.

### Settings: General

This pane covers startup, the collector, permissions, updates and resetting Hostwatch.

- **Startup:** *Open Hostwatch at login* is off by default. It uses macOS's login item for the app, so Hostwatch is
  listed in System Settings ▸ General ▸ Login Items, where you can also remove it. If macOS asks for approval first,
  the setting says so, with **Open Login Items…**. Together with *Start collector when Hostwatch opens*, watching starts
  at login, with no password: the collector is a background service.
- **Collector:** the status, and *Start…* or *Remove…*. The collector runs as a **background service**: the first
  time you start it, macOS asks for your password once and lists it under System Settings ▸ General ▸ Login Items ▸
  *Allow in the Background* (approve it there once if asked). From then on macOS starts it at boot, as root, and
  Hostwatch connects to it: no password at launch. *Remove…* unregisters it (your password again), for example
  before uninstalling. *Register the collector when Hostwatch opens* is on by default. The pane also shows the
  collector's log (`/var/log/hostwatch-collector.log`).
- **Permissions:** shows your Full Disk Access status, with an **Open Settings…** button, and *Data on disk*: whether
  Hostwatch's files are encrypted and where the key is kept (see
  [Encryption at rest](06-privacy-security-and-limits.md#encryption-at-rest)).
- **Updates:** shows the version you run. *Check for updates automatically* is on by default and checks once a day.
  Use **Check Now** / **Open Release Page** to check by hand or see the release.
- **Reset:** *Reset Hostwatch…* asks what to erase: learned data, settings and history. All three are ticked by
  default. Full Disk Access stays granted. See [Reset Hostwatch](06-privacy-security-and-limits.md#reset-hostwatch).

### Settings: HUD

The HUD is Hostwatch's on-screen overlay. This pane sets what it shows and how it looks.

- *Show HUD* turns it on or off. It is off by default. Shortcut: ⌃⌥⌘H.
- *Click-through* is off by default.
- *Show CPU, memory, network and disk* is on by default.
- **Background:** choose Glass, Clear Glass or Solid. Preview tiles show each one. With Reduce Transparency on, glass
  shows as Solid.
- **Contrast:** goes from Lighter to Darker, at 0.45 by default. A warning appears below 0.25.
- **Appearance:** text size is Small, Medium (default), Large or Extra Large. You can also reset the size and position,
  which returns the HUD to 24 rows × 360 pt.

### Settings: Detection

This pane decides how Hostwatch reacts to suspicious and unusual activity.

- **Hold:** *Hold suspicious processes* is off by default. When you don't answer within 60 s, the process is either
  resumed (the default) or killed. You pick which.
- **Baseline:** *Trust new apps from developers you trust*.
- **Heavy processes:** *Highlight heavy processes in Events* marks processes that use a lot of resources. You set the
  limits:
  - CPU: 25%, 50% (default), 100% or 200%.
  - Memory: 500 MB, 1 GB (default), 2 GB or 4 GB.
- **Baselines:** Update Baseline, Show in Rules.
- **Known threats:** *Check against known threats* is on by default. The pane shows counts per list. It also holds the
  **ThreatFox and MalwareBazaar** key, with Add Key… / Replace Key… / Remove Key.
- *Watch for exploited macOS vulnerabilities* is on by default.

### Firewall settings

The firewall is set in *Protection*, next to launch and file protection, not in Settings. See
[Launch and file protection](03-features.md#launch-and-file-protection-rules--protection) and
[Firewall](03-features.md#firewall).

### Settings: AI

This pane controls how Hostwatch uses AI and how Claude Code can work with it.

- **Classifying new patterns and Ask AI:** choose the engine: hybrid (the default), the local model or Claude. The
  pane also shows the local model's status and the Claude Code command.
- **Local model:** Apple On-Device (*General* or *Content Tagging*) or a custom OpenAI-compatible server, with its
  address, model, API key and a *Test* button.
- **Claude:** which Claude model to use: Claude Code's default, Opus, Sonnet or Haiku.
- **Suggestions:** *Suggest for new patterns automatically* and *Accept AI suggestions without asking*.
- **Claude Code guard:** turn it on or off, see the hook fragment, and read the log. See
  [Claude Code guard](03-features.md#claude-code-guard).
- **Use with Claude Code:** *Allow Claude Code to read Hostwatch data (MCP)*, with its token. The token is shown only
  once. See [MCP server](03-features.md#mcp-server).
- **Claude usage:** the tokens and cost Hostwatch has used, all-time. The tooltip breaks them down per feature. A Reset
  button clears the count.

### Settings: Exclusions

This pane holds the exclusions editor. See [Exclusions](#exclusions).

### Settings: History

This pane controls the activity history. See [Activity history](#activity-history).

- *Record activity history* turns recording on or off.
- *Apply exclusions to history*.
- **Size limit:** 5 GB by default, or Custom….
- **Location:** where the history is kept.
- **Clearing:** you can clear the history from here.

### Exclusions

Exclusions hide activity you don't want to see, such as routine system noise. Write one pattern per line.

- **Matching:** patterns are case-insensitive.
- **Comments:** start a comment with `#`.
- **Globs:** a pattern with `*` or `?` is a glob, a wildcard pattern. It must match the whole value.
- **Substrings:** any other pattern matches if it appears anywhere in the value.

```
mdworker              # hide everything from matching processes (name or path)
proc:/usr/libexec/*   # hide spawns of matching executables
net:*:53              # hide connections to matching remote host:port
net:17.*              # hide connections to Apple's 17.0.0.0/8 range
file:/System/*        # hide opens of matching file paths
file:*.plist
```

Sensible noise defaults come preloaded: `/System`, `/usr/lib`, caches, loopback and Spotlight. **Restore Defaults** in
the editor brings them back.

Exclusions are saved with your settings, in `~/Library/Preferences/tech.hostwatch.app.plist`.

### Activity history

Hostwatch writes all activity to disk, so you can look back at it later. The history lives in
`~/Library/Logs/Hostwatch/History` by default: `activity-*` files for events, `metrics-*` for resource samples and
`processes-*` for process lists. The files are compressed and encrypted as they are written.

You control it in *Settings ▸ History*:

- **On/off:** turn recording on or off.
- **Maximum size:** 500 MB … 50 GB, or Custom….
- **Location** and **Show in Finder**.
- **Clear History…** erases it.
- The activity window footer shows how much space it uses now.

**What gets recorded:**

- **Apply exclusions to history** is off by default, so everything is recorded. Turn it on to record only what passes
  your exclusions.
- The history is not limited by the overlay's display rate.
- It keeps recording while the overlay is paused or a kind is hidden.

**Max size:** the default is **5 GB**. It caps the space all history files take on disk together, activity, resource
samples and process lists alike.

- Files are compressed, so the cap holds far more history than its size in plain text.
- When the total would go over the cap, the oldest day goes first: its activity, then its samples and process lists.
- Today's files and the file being written are never deleted.

**Crash safety:** if the app crashes, at most the last second of history is lost. The next launch recovers what was
written. After a kernel panic or power loss, the last few seconds can be lost. New activity shows up in Time Travel
within about 30 seconds.

**Exporting:** the history files are encrypted, so `zcat` and `grep` can't read them. Export them as plain JSON lines,
one event per line, from Terminal:

```bash
/Applications/Hostwatch.app/Contents/MacOS/Hostwatch --export-history > history.jsonl
/Applications/Hostwatch.app/Contents/MacOS/Hostwatch --export-history | jq -c 'select(.kind=="net")' | tail
```

Without an argument it exports the whole history folder. You can also pass one file or another folder. Each event looks
like this:

```
{"kind":"net","time":"20:25:36","pid":812,"ppid":1,"name":"curl","proc":"/usr/bin/curl","target":"140.82.112.3:443","extra":"TCP","ts":"2026-10-31T20:25:36.385+02:00"}
```

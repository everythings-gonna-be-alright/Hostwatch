<p align="center">
  <img src="assets/AppIcon.png" width="128" alt="Hostwatch icon">
</p>

<h1 align="center">Hostwatch</h1>

<p align="center">
  Behavior-based intrusion detection for macOS.<br>
  Learns what's normal on your Mac, flags what isn't, connects small signs into a story,<br>
  and can stop unknown connections and risky Claude Code commands.
</p>

<p align="center">
  <a href="https://github.com/everythings-gonna-be-alright/Hostwatch/releases/latest"><img src="https://img.shields.io/github/v/release/everythings-gonna-be-alright/Hostwatch" alt="Latest release"></a>
  <img src="https://img.shields.io/badge/macOS-26%2B-black" alt="macOS 26+">
  <img src="https://img.shields.io/badge/Swift-6-orange" alt="Swift 6">
  <img src="https://img.shields.io/badge/status-prototype-yellow" alt="Status: prototype">
  <img src="https://img.shields.io/badge/license-PolyForm%20Shield-blue" alt="PolyForm Shield license">
  <a href="https://vshymanskyy.github.io/StandWithUkraine/"><img src="https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/badges/StandWithUkraine.svg" alt="Stand With Ukraine"></a>
</p>

<p align="center">
  <a href="https://hostwatch.tech/"><b>Website</b></a> ·
  <a href="#install"><b>Install</b></a> ·
  <a href="#whats-new">What's new</a> ·
  <a href="#what-it-does">Features</a> ·
  <a href="#privacy">Privacy</a> ·
  <a href="https://hostwatch.tech/docs/"><b>Docs</b></a> ·
  <a href="CHANGELOG.md">Changelog</a>
</p>

<p align="center">
  <img src="docs/images/site/events.png" alt="Hostwatch Events tab: processes, files and connections, with what's new and risky marked">
</p>

<p align="center">
  <img src="docs/images/site/hud.png" width="360" alt="Hostwatch HUD: live processes, connections and file opens, with a story on top">
</p>

<p align="center"><sub>Screenshots show made-up demo data.</sub></p>

---

## Why

**One machine was enough.** In 2026, [GitHub](https://techcrunch.com/2026/05/20/github-says-hackers-stole-data-from-thousands-of-internal-repositories/)
lost about 3,800 internal repositories to a poisoned editor extension on one employee's device.
[Grafana Labs](https://grafana.com/blog/grafana-labs-security-update-latest-on-tanstack-npm-supply-chain-ransomware-incident/)
had its codebase taken through a compromised npm package. [Binance](https://www.bleepingcomputer.com/news/security/binance-says-fake-job-interview-led-to-63-billion-crypto-heist/)
lost $6.3 billion to a coding task from a fake job interview. Each was code someone trusted and ran.

Meanwhile new CVEs grew **+49.5%** in the first half of 2026 ([Jerry Gamblin](https://jerrygamblin.com/2026/07/01/3528/)),
and new macOS backdoor variants **+67%** in 2025 ([Moonlock](https://moonlock.com/mid-2026-macos-threat-report)).

Hostwatch watches what runs on your Mac, what it touches and where it connects, and links small signs into the story
of what happened. Its firewall and Claude Code guard can stop what you didn't allow. It never deletes anything.

## What's new

**0.14.0**
- **🧬 Who really started it** – *Show Launch Chain* rebuilds a process's parents up to launchd from what was
  recorded, so it works after they've exited, and names the origin: terminal, app, AI session. Ask AI gets it too.
- **🚫 Block one domain for one app** – right-click a domain in the Network tab ▸ *Block for an App*, instead of
  blocking an app's whole web access.
- **⚡ A lighter Events list** – rebuilt on AppKit: a quarter of the CPU it took under a busy coding agent.
- **🗂️ One list style** for Events, Patterns and Running Now, with a *Parent* column, hundredths of a second, and
  group rows that read as headings.
- **🛡️ Fixes** – Forget no longer lets a blocked destination through, and marking several events Safe marks them all.

**0.13.0**
- **🔑 No password at launch** – the collector is a background service: registered once, approved once, started by
  macOS at boot from then on. Only Hostwatch's own signed code may talk to it, and it idles when the app is closed.
- **🔒 Encrypted at rest** – patterns, stories, history and logs are sealed with a key only Hostwatch's own code can
  use, so no other program running as you (an AI agent included) can read your activity.
- **🪪 New identity** `tech.hostwatch.app` – settings carry over, and Full Disk Access is granted once more.


Earlier versions: see the [changelog](CHANGELOG.md).

## What it does

**👀 See what happens**
- **Live HUD** – new processes, connections and file opens as they happen.
- **Running Now** – every running process with CPU, CPU time, memory and uptime. Jump to the moment it was spawned.
- **Time Travel** – scrub back through recorded activity, resources and heavy processes.
- **Heavy processes** – programs you started that keep eating CPU or memory stand out (and miners score).

**🧠 Learn what's normal**
- **Baseline** – the first hour learns your Mac: one rule per trusted app, nothing unsigned or downloaded.
- **Patterns** – events grouped by behaviour and by program. Ordinary ones are decided automatically, so few need you.
- **Rules tab** – *Needs You* (what's left for you), *Rules* (what decides automatically), *Decisions* (who decided what).

**🚨 Spot what's wrong**
- **Stories** – related suspicious steps become one story you can open event by event.
- **Network tab** – hostnames, first-seen domains, beaconing, raw-IP connections, and the firewall's verdict for each.
- **Known threats** – daily public threat lists matched on your Mac, plus exploited macOS flaws vs. your updates.

**🛡️ Stop what you didn't allow** (off until you turn it on)
- **Firewall** – each app's new connections checked before they're made: allowed ones pass, unknown ones wait
  while a window asks **Allow / Block** (*Ask*), or are refused (*Strict*). *Watch* only shows what it would do.
  Containers and VMs are judged per destination.
- **Claude Code guard** – Claude Code's commands checked before they run: the dangerous blocked, the risky
  need your OK.

**✨ Ask AI** (Claude or Apple's on-device model, your choice)
- **AI suggests, you decide** – it never trusts high-risk code, python or bash on its own.
- **Ask about anything** – an event, a domain, a firewall question: what it is, the risks, what to do.
- **Watch Closely** – a recording of what one process really does, explained.
- **MCP** – let Claude Code investigate your history (read-only).

## Install

1. Download `Hostwatch-<version>-macOS-universal.zip` from
   [Releases](https://github.com/everythings-gonna-be-alright/Hostwatch/releases), unzip, move
   `Hostwatch.app` to `/Applications`.
2. Open it. It's signed and notarized by Apple, so macOS opens it without a warning. A short setup window helps you
   turn on **Full Disk Access**.
3. Enter your administrator password once: it registers the collector as a background service, which macOS
   starts at boot from then on. Done.

Or build it: `./scripts/build-app.sh && open dist/Hostwatch.app` (Xcode 26 or the Command Line Tools).

**Requirements:** macOS 26+. Optional: Apple Intelligence (on-device AI),
[Claude Code](https://claude.com/claude-code) (Claude AI and MCP).

## How it works

Two parts, one app. The collector runs as root and only watches. Hostwatch.app is where everything is decided and
shown. They talk over one Unix socket that accepts nothing but Hostwatch's own signed code.

```
┌──────────────────────────────────┐                    ┌───────────────────────────────────────┐
│  Collector  (root, background)   │                    │  Hostwatch.app  (you)                 │
│                                  │                    │                                       │
│  eslogger      processes, files  │  activity ───────► │  learns patterns, keeps the baseline, │
│  tcpdump       DNS answers       │                    │  connects stories, records history    │
│  NetworkStats  every connection  │                    │                                       │
│                                  │                    │  HUD · window · Time Travel           │
│  firewall relay (pf)             │ ◄─── allow / block │  Ask AI · MCP for Claude Code         │
│                                  │                    │                                       │
│  Watch Closely recorder          │  profile ────────► │  Watch Closely window                 │
└──────────────────────────────────┘                    └───────────────────────────────────────┘
                              one Unix socket, Hostwatch's own code only
```

- **Activity** flows one way: what started, what was opened, who connected to what. The app turns it into patterns
  and stories and writes the history.
- **Allow / block** flows back only when the firewall is on: the collector then relays your apps' new connections
  through itself (macOS's own pf, no extension or paid entitlement) and asks the app what to do.
- **Watch Closely** is a second, deeper recording of one process, on request.

The collector is a background service: registered once, approved once, started by macOS at boot. Everything stays on
your Mac, except what you send to Claude and a daily update check (both optional).

## Privacy

- History, patterns and stories stay in `~/Library/Application Support/Hostwatch` and `~/Library/Logs/Hostwatch`.
- Passwords and tokens are masked before they're recorded, and again before anything goes to an AI.
- The firewall reads only which server an app asks for. It never decrypts traffic.
- Watch Closely records only the process you pick, only while it runs, and keeps it on your Mac until you ask AI.
- *Apple On-Device* AI keeps everything on the Mac. Claude is used only if you choose it.
- The MCP server needs your permission and a token, and can't change anything.
- *Settings ▸ General ▸ Reset Hostwatch…* erases it all.

## Limitations

A working prototype, not a commercial product. It uses Apple's `eslogger` (a prototyping tool), and the optional
process hold is best effort. The firewall
covers your own apps, not programs running as root or macOS's own DNS lookups. Containers are judged by
destination (which program inside made a connection can't be seen). VMs with bridged networking aren't covered.

## Development

Start with [`CLAUDE.md`](CLAUDE.md) (build, test, workflow, invariants), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (the map) and [`docs/adr/`](docs/adr/) (the decisions).

```bash
./scripts/test.sh       # all tests
./scripts/package.sh    # tests + universal build + zip
```

`src/hostwatch` is the app and collector, `tests/swift` the tests. Every rule, threshold and setting is
in **[docs/reference.md](docs/reference.md)**, changes in **[CHANGELOG.md](CHANGELOG.md)**.

## License

**Free for everyone, at home and at work.** Hostwatch is source available under the
[PolyForm Shield License 1.0.0](LICENSE): use it, change it, fork it and share it, personally or in your company, at
no cost. The one thing the licence doesn't allow is using the code to make a product or service that competes with
Hostwatch, such as your own server or cloud edition of it.

Companies that want the centralised versions, a server that watches a whole fleet of Macs from one place or a hosted
cloud (SaaS), will get them as paid editions. Write to
[contact@hostwatch.tech](mailto:contact@hostwatch.tech?subject=Hostwatch%20Server%20or%20Cloud).

Versions up to 0.11.1 were released under the MIT license and stay under it.

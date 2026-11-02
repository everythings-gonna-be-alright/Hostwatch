# Changelog

## Unreleased

- **Domain details with a risk score:** double-click a domain (or right-click ▸ *Details & Ask AI…*) for the
  same design as event details: a 0–100 risk score from what this Mac saw, with every reason and its points
  (new, untrusted program, beaconing, abused top-level domain, random-looking or look-alike name, how widely
  it's used), the domain's hostnames, addresses, first and last contact (with Time Travel), the programs with
  their signers, recent connections, and Ask AI (Claude or on-device) with its own risk score. Mark Known
  from the window. Event and pattern verdicts show the AI's risk score too.
- **First-run baseline in three waves (5, 15, 60 minutes), as baseline rules:** one narrow rule per trusted
  app and its signer (*Slack · Slack Technologies*), one for macOS system services, and optionally one for
  Homebrew tools, in the Rules tab. A rule keeps trusting the app's normal-risk patterns, now and later. Never
  high-risk, unsigned, downloaded or temporary; sensitive places only for macOS services or apps you trusted.
  Signed-but-untrusted developers go to the on-device model; the rest waits in **Needs your review**, one row
  per app with its reasons: **Trust** (adds a rule marked *Trusted by you*), **Dismiss** (stays New, not listed
  again), Mark Suspicious; interpreters like python or node can't be trusted from here, since they run any
  script. Hostwatch's own activity is never listed. Pause, Delete and **Update Baseline**
  (local, no AI; separate from *Suggest Rules from My Decisions*, which asks Claude). Your decisions win and
  stories ignore baseline trust. It replaces the old "Trust Baseline…", which trusted everything.
- **`sqlite3` is recognised as a living-off-the-land tool** (its name was cut at the digit before).
- **Domain learning now lasts an hour** (was 12 hours), and a domain first reached by unsigned, quarantined or
  downloaded software during learning stays new.
- **CPU, memory, network and disk in the HUD:** one compact line under its title (sparklines when there's
  room, memory coloured by memory pressure). Settings ▸ HUD can hide it.
- **The event list isn't empty after a restart:** it starts with the newest recorded events (up to 5,000,
  display only, below new events), and the footer says how many came from before the restart.
- **On-device Ask no longer fails with "Detected content likely to be unsafe":** it uses Apple's
  guardrail mode for analysing sensitive text, retries once with the core evidence if still refused, and
  explains a refusal in plain words. A live test of the real model on security evidence is opt-in.
- **Redesigned Ask AI window:** a plain-English summary of what happened with status chips (pattern status,
  signer, first time, high risk, new domain, beacon, raw IP), detail cards with labelled rows for the
  connection (destination, protocol, traffic in readable sizes), file (access, size, modified, quarantine)
  and process (executable with Reveal in Finder / Copy, signature and team, running since, command line),
  the parent chain as breadcrumbs, recent activity of the process, and a verdict card with confidence. The
  raw evidence for the AI is a collapsed, editable section; the Ask bar stays at the bottom.

## 0.5.2 – no code injection

- **Hardened runtime:** Hostwatch is now signed with Apple's hardened runtime (free, also with ad-hoc
  signing). macOS ignores `DYLD_INSERT_LIBRARIES` and similar variables for it and loads only Apple-signed
  libraries, so no code can be injected into Hostwatch, its collector or its MCP server. The build fails
  if the flag is missing.

## 0.5.1 – lighter and harder

- **Much lower CPU for the app:** the event list, counters and HUD now update in batches (at most 5 times a
  second) instead of on every event, don't re-sort when showing newest first, and pause while neither the
  window nor the HUD is on screen. Detection, stories, the hold and history still see every event at once.

Security hardening from a design review:

- **No AI marks a high-risk pattern Safe** anymore, including Claude (before, only the on-device model was
  guarded): crafted file names or hostnames could talk a model into it. It stays New for you to decide.
- **Only the verified app's own process tree is hidden.** Other runs of the Hostwatch program (e.g. the MCP
  server) are reported, so malware can't hide by starting the Hostwatch binary with injected code.
- **tcpdump drops root** (`-Z nobody`) right after opening the capture device, so packets from the network
  are never decoded as root.

## 0.5.0 – resources and compact history

- **The collector is now Swift, built into the app** (`Hostwatch --collector`): no Python and no Command
  Line Tools needed to run Hostwatch. Same design and sources (eslogger, tcpdump, lsof, nettop, libproc),
  same socket security and the same history format; helpers no longer inherit open files.
- **Collector CPU fix:** the `nettop` network backstop used about 1.4 CPU cores all the time (it polled
  its `/dev/null` stdin for key presses in a tight loop). It now gets an open pipe as stdin: about 1%.
- **CPU, memory, network and disk** in the Events footer, live with sparklines, and recorded every 5 s for
  Time Travel: CPU and memory lines under the timeline, values and the busiest process at the playhead.
  A popover lists the busiest processes (from the collector, which sees every user's processes).
- **Compressed history:** finished history files are gzip-compressed in the background (≈24× smaller on
  real history, so the 5 GB cap now holds weeks instead of about a day). Files are split into independent
  ≈4 MB gzip blocks with a time index, so Time Travel and the MCP server read only what they need, as
  fast as before. Still normal `.gz` files (`zcat`/`zgrep`). Existing history is compressed on first
  start; files rotate at 100 MB at most (was 256 MB). **Older versions can't read compressed history.**
- **Hostwatch's own activity is hidden:** the app (history and metrics writes, update check, codesign
  checks), the MCP server and their children no longer show up in the HUD, events, history or stories.
  Only the exact executable of the app that started the collector counts; exited pids are dropped.
- Time Travel: slightly larger playback buttons.

## 0.4.0 – time travel

- **Time Travel** (toolbar button, *View ▸ Time Travel* ⌥⌘T): browse recorded history in the Events tab.
  A floating timeline shows activity over the whole recording with marks for stories and new domains;
  drag the playhead, step with ⌘[ / ⌘], play at 1×–600×, pick a date or a 1 min–1 h window. Story cards
  have **Show in Timeline**. Reads only the slice you look at, so large histories open instantly.
- **Stories chain only related steps:** links by cause (same process, parent → child, same script, same
  file) and by shared evidence (the same untrusted program, a login item and the program it starts,
  the same new domain or raw IP). Programs reading their own keychain items, AI coding agents' command
  wrappers and trusted apps reading their own config no longer raise stories. On a day of real use:
  0 false stories, down from 10.
- **Hold suspicious processes** (opt-in, *Settings ▸ Detection*): freezes your own process when it does
  something suspicious and asks you to allow or kill it. Fails open: a watchdog resumes it if Hostwatch
  quits or crashes. Best effort: quick commands can finish first.
- **Menus and Settings:** a short menu bar icon menu (status and quick actions), a full app menu bar
  (View, Activity, Window, Help, with ⌘1–⌘5 for tabs) and a **Settings window** (⌘,) with General, HUD,
  Detection, AI, Exclusions and History. A banner says when the collector is off; Exclude is on
  right-click for events and HUD rows.
- **MCP access requires permission and a token.** `Hostwatch --mcp` refuses everything until you allow it in
  *Settings ▸ AI*, which issues a random token for the Claude Code registration command (only its hash is
  stored). *New Token…* or turning access off cuts off earlier registrations; sessions are logged.
  **Existing registrations stop working:** copy the new command from Settings ▸ AI.
- **Check for Updates…** (*Hostwatch* menu, *Settings ▸ General*): asks GitHub for the latest release.
  Automatic once a day (can be turned off); nothing is downloaded or installed by itself.

## 0.3.0 – learn, investigate, secure

- **Rules learned from your decisions** (Rules tab): Claude proposes general rules from the patterns you
  marked. Hostwatch refuses any that contradict your decisions or are too broad, and applies only
  those you approve. Each rule re-checks itself and pauses if it contradicts you later.
- **MCP server for Claude Code** (`Hostwatch --mcp`, *Detection ▸ Use with Claude Code…*): read-only tools to
  search events, patterns, stories, domains, process trees and code signatures, for investigating by
  conversation.
- Stories: an inferred connection with an unknown destination no longer counts as an outbound connection.
- **Secure collector channel:** the TCP port 127.0.0.1:47831 is replaced by a Unix socket in a root-owned
  folder. The collector accepts only the app that started it (kernel peer credentials). The app connects
  only to a socket only root could have created. Other programs and users can no longer read the
  activity stream or pose as the collector.

## 0.2.0 – on-device AI

- **On-device AI triage:** Apple's on-device model triages new patterns first (private, offline, free);
  Claude only gets what it can't settle. High-risk patterns are never settled on-device.
  "Classify with Claude" is now "Classify New".
- **Choose the AI engine** in *Detection ▸ AI Engine*: Apple On-Device (private), Claude, or on-device
  first with Claude for the rest. The Ask window has a Claude / On-device switch; "Ask Claude" menus are
  now "Ask AI".

## 0.1.0 – first public version

Behavior-based intrusion detection for macOS.

- **Live HUD** (Liquid Glass): new processes, connections and file opens as they happen, with badges
  for anything new or worth a look. Movable, resizable, optional click-through.
- **Patterns with local risk:** events grouped into fingerprints; routine ones auto-marked safe; new
  ones rated routine / normal / high.
- **Code signing:** trusted developers (seeded from installed apps) and Apple are routine; unsigned
  code from downloads, modified binaries and binaries replaced at a known path are high risk.
  Optional trust for Homebrew-installed tools.
- **Stories:** suspicious steps correlated along the process tree into one Suspicious/Dangerous chain.
- **Network signals:** hostnames from DNS answers, first-seen domains (with a learning period),
  beaconing and raw-IP connections.
- **Ask Claude** (Claude Code CLI) for a verdict on any event or story; optional auto-classification.
- Activity window with sortable Events, Patterns, Stories and Domains tables; exclusions; history.
- Collector: eslogger, pktap packet capture, lsof and nettop, read-only, as root.
- Tests (Swift Testing + Python unittest) and a pre-merge test gate.

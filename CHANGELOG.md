# Changelog

## Unreleased

- **CPU, memory, network and disk** in the Events footer, live with sparklines, and recorded every 5 s for
  Time Travel: CPU and memory lines under the timeline, values and the busiest process at the playhead.
  A popover lists the busiest processes (from the collector, which sees every user's processes).

- **Compressed history:** finished history files are gzip-compressed in the background (≈24× smaller on
  real history, so the size cap now holds weeks instead of a day). Files are split into independent
  ≈4 MB gzip blocks with a time index, so Time Travel and the MCP server read only what they need, as
  fast as before. Still normal `.gz` files (`zcat`/`zgrep`). Existing history is compressed on first start.
- History files rotate at 100 MB at most (was 256 MB), so recent history is compressed sooner.

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

# Changelog

## Unreleased

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

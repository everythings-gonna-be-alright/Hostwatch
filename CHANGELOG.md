# Changelog

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

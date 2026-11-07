# 0005 `eslogger` and `tcpdump` as sources until an Endpoint Security extension

**Context.** True process and file control needs an Endpoint Security system extension, which needs Apple's
entitlement (requested per team, not guaranteed) and a Network Extension for connections. Apple documents
`eslogger` as a prototyping tool whose JSON may change.

**Decision.** Ship on `eslogger` (exec, exit, open; a second one for Watch Closely), `tcpdump` pktap (DNS answers,
SYNs), NetworkStatistics and libproc, all read by the root collector. Blocking is done where it is possible without
ES: the firewall through pf redirects to the collector's relay, and Claude Code through its hook. Keep the
collector's parsers pure and fixture-tested so the source can be swapped.

**Consequences.** Hostwatch observes and holds; it cannot deny a file open or a launch. The collector is a separate
process tree with its own event loop, which is the shape an ES extension will have too. When the entitlement comes,
the extension replaces `Agent.swift`'s sources behind the same socket protocol.

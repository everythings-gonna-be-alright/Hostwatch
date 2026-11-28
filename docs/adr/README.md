# Architecture decision records

One file per decision that shaped the code and would be expensive to revisit. Short: context, decision, consequences.
Add one when a change settles a question that the next person (or AI) would otherwise reopen.

| # | Decision |
|---|---|
| [0001](0001-one-binary.md) | One binary: app, root collector, MCP server and tools |
| [0002](0002-patterns-as-decisions.md) | Zone-based patterns are the unit of decision; the general rule |
| [0003](0003-no-blanket-trust-for-interpreters.md) | Interpreters, shells and LOLBins are never trusted broadly |
| [0004](0004-history-compressed-as-written.md) | History compressed as it is written, append-only, crash-safe |
| [0005](0005-eslogger-prototype.md) | `eslogger` and `tcpdump` as sources until an Endpoint Security extension |
| [0006](0006-developer-id-signing.md) | Releases signed with a personal Developer ID and notarized |
| [0007](0007-fewer-patterns.md) | Fewer patterns where the detail says nothing, with a launch-time regroup |
| [0008](0008-flat-module-one-concept-files.md) | One module, one concept per file; no architecture framework |
| [0009](0009-encryption-at-rest.md) | Everything on disk encrypted; the key in the Secure Enclave or a code-bound keychain item |
| [0010](0010-appkit-event-list.md) | The Events list is an AppKit outline view with reused cells (SwiftUI's Table cost a core under a busy agent) |
| [0011](0011-protection.md) | Launch and file protection: rehearse on the event feed, enforce with Endpoint Security later |
| [0012](0012-triage-warning-signs.md) | One triage prompt with checked warning signs, and a warning sign outranks a local model's Safe |
| [0013](0013-ai-safe-project-reads.md) | An AI may mark Safe a run-anything tool's plain read of an exact project folder |
| [0018](0018-endpoint-security-client.md) | The collector is its own Endpoint Security client, eslogger only as the fallback |
| [0019](0019-patterns-name-who-did-it.md) | A tool's or interpreter's pattern names who did it (the app or AI agent behind it) |
| [0020](0020-firewall-rules-per-app.md) | Firewall rules per app (its own Everywhere and destinations), next to the general ones |
| [0021](0021-file-rules-per-app.md) | File rules per app (its own Every protected place and places), next to the general ones |
| [0022](0022-story-evidence.md) | What counts as evidence in a story: no list matches on local or CDN addresses, two signs from two events |
| [0023](0023-story-confidence.md) | How sure a sign is: blocklist matches are signs not proof, everyday signs don't count, Not a Threat remembers exact signs |

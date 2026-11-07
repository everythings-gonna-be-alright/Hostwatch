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

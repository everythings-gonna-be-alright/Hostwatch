# 0011 Launch and file protection: rehearse on the event feed, enforce with Endpoint Security later

**Context.** Hostwatch watches but can't stop a launch or a file open: that needs Apple's Endpoint Security
entitlement (0005), which is requested and pending. Turning blocking on without knowing what it would hit breaks
builds, agents and updaters. The toolbar has no room for another control.

**Decision.** One policy, `ProtectionPolicy`, decides launches and protected-file access the way the firewall decides
connections: your pattern decision first, then risk, then macOS's own programs (never the ones that run whatever they
are told). Protected files are cards built on the sensitive labels patterns already carry. Each area has the
firewall's modes. Watch runs the policy on the live eslogger feed and records what would be stopped or asked about,
so you decide those patterns before anything is enforced. Ask and Strict stay unavailable until the collector reports
a working Endpoint Security client. The page is a Rules segment, the state is in the window subtitle.

**Consequences.** Rehearsal works today and costs one policy call per event. The app already speaks the collector
protocol for held launches and opens (`guard_ask`, `guard_answer`, `guard_status`, `guard_block`) and has the
countdown panel, but this version ships no Endpoint Security client: the collector half is the remaining work once
the entitlement arrives. Its fail-safes are part of this decision: everything passes without the app or past
macOS's deadline, Hostwatch's own processes are never held, and nothing is held unless a mode enforces.

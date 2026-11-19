# 0018 The collector is its own Endpoint Security client

**Context.** ADR 0005 shipped on `eslogger` until Apple granted the Endpoint Security entitlement. It is granted now
(per team, as a Developer ID provisioning profile). `eslogger` is a prototyping tool: a second process, JSON for
every event, a format that may change, and notify events only.

**Decision.** The root collector calls `es_new_client` itself (`ESSource.swift`) for exec, exit and open, in the
same service, not a system extension: the collector already runs as root from the signed bundle, which is what an
Endpoint Security client needs. Only the collector is entitled, from its own bundle inside the app
(`Contents/Library/Helpers/Hostwatch Collector.app`, identifier `tech.hostwatch.collector`, its own profile); the
launcher, the app's binary, starts it, so the app's Full Disk Access still applies, and the collector accepts
clients that satisfy the app's requirement. The app itself is never entitled: the first build that was moved it into
another keychain group, it could no longer open its data key, made a new one, and the data sealed with the old key
was lost. Upgrading from 0.18 needs nothing to move. Each message is turned into the fields of eslogger's JSON
that `Agent.normalize` reads, so one path follows both sources and the existing tests cover it. `build-app.sh`
embeds the profile and signs the collector with the entitlement only when the profile is present and names the
collector and the entitlement: a restricted entitlement without its profile stops macOS from starting it. Without it, or when
the client is refused for lack of entitlement, the collector falls back to `eslogger` as before. Full Disk Access
is still required, and its absence is still reported through the `eslogger` fallback.

**Consequences.** One process fewer, no JSON on the hot path, and the collector's own file opens are muted in the
kernel. Watch Closely keeps its own `eslogger` for now. The next step is AUTH events: refusing a launch or a protected
file open by rule, before it happens, instead of stopping the program right after (ADR 0011). A question you answer
can't wait inside an AUTH deadline, so questions keep the hold-and-ask flow.

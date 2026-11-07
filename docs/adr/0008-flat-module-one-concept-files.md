# 0008 One module, one concept per file; no architecture framework

**Context.** 28k lines, one developer plus an AI. The six biggest files held 13 types each and cost a reading of
hundreds of lines before any change. Layered architectures (MVVM frameworks, protocol-per-type, DI containers) were
considered.

**Decision.** Keep one app module and plain Swift: pure functions over values for anything decided
(`SignatureBuilder`, `RuleText`, `BaselinePolicy`), `@MainActor` engines as `ObservableObject`s owned by
`AppDelegate`, SwiftUI views that read them. Files are one concept each, named after the main type, kept under ~700
lines, split along `// MARK:` sections when they grow (`AppDelegate+Menus.swift`, `PatternStore.swift`…). Protocols
only where a second implementation exists. Orientation lives in `CLAUDE.md`, `docs/ARCHITECTURE.md` and these ADRs.

**Consequences.** Behaviour reads top to bottom; a file name is a map entry; `./scripts/test.sh --changed` can pick
suites by the types a file declares. The price is that nothing enforces the dependency direction (collector → core
← app) except review; splitting into SwiftPM targets would enforce it at the cost of `public` on every shared
declaration, and is deferred until the Endpoint Security extension needs a shared core anyway.

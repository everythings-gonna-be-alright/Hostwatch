# 0007 Fewer patterns where the detail says nothing, with a launch-time regroup

**Context.** 21,000 patterns on a developer's Mac; 65% were reads by macOS's own programs, one per folder, all
auto-Safe and saying nothing. Each decision the user makes should cover something meaningful.

**Decision.** Collapse exactly where the detail carries no information and keep everything that could be a signal:

- reads by programs on the sealed system volume (not shells, interpreters or `/bin`, `/usr/bin` tools): one pattern
  per program, `r *  [ordinary files]`; their writes and sensitive places stay specific;
- random temp names (`zshVJbGMW`) → `name*`; a scratch tree in `/tmp` → `/tmp/name/**`;
- reads inside a git project by a tool (not a shell) → `r <project>/**`; never the home folder or a repo so near the
  root that the pattern would be wide;
- reads in a Homebrew formula's tree → per formula; a shell starting plain system tools → `/usr/bin/*  (plain tools)`,
  with the watched tools (`curl`, `osascript`, `security`, `launchctl`…) and admin tools kept one each with arguments.

`SignatureStore.regroup()` runs at launch and moves only automatic patterns (routine Safe, or New untouched) into the
new keys, adding counts and keeping first/last-seen; the user's, a rule's and the AI's decisions never move.
`--regroup-report` previews it.

**Consequences.** 21,172 → ~7,600 on the reference store, then one-offs expire. A user rule written for a specific
folder no longer matches an Apple daemon's reads there (they are one pattern now); accepted because nothing can
modify those programs. Pattern text gained two forms (`[ordinary files]`, `(plain tools)`) that `isTooWide`,
`dropInterpreterTrust` and `RuleText` know about.

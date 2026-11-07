# 0002 Zone-based patterns are the unit of decision; the general rule

**Context.** The first version made one pattern per folder for everything: ~20,000 patterns, all New, nobody could
decide them. A decision must cover enough to be worth making and little enough to mean something.

**Decision.** A pattern is `kind | normalized program | normalized target`. Targets are normalized (home → `~`,
`$TMPDIR`, UUIDs and hashes → placeholders, numbers → `#`) and collapsed by zone (`zoneDepth`: how many folders
below `/System`, `~/Library`, `/tmp`… a pattern keeps). Each pattern gets a local risk (routine / normal / high)
from the pattern text alone, so risk is a function of the key. Routine patterns are decided Safe automatically.

**The general rule** (`SignatureBuilder.isTooWide`): no file pattern may cover a whole area (`r ~/*`,
`r ~/Documents/*`, `r /tmp/*`, `r *`). Everything that makes patterns wider — rules, merges, tidy's fold, the
fewer-patterns rules — is checked against it. Sensitive places (`…  [SSH keys]`) are specific by construction.

**Consequences.** Changing how a pattern is built changes keys and orphans decisions: a change needs a migration
(`SignatureStore.regroup`, merge aliases). The old `signatures.json` (v1) was not migrated on purpose. Pattern text
is also an interface: `]` means sensitive, `/**` means a deep tree, `(plain tools)` a folder of system tools.

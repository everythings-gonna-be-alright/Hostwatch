# 0019 A tool's pattern names who did it

**Context.** A pattern was `kind | program | what it did` (ADR 0002). For an app that is enough: Safari is Safari.
For a tool or interpreter it isn't: `node` reading `~/proj/.git/*` from Cursor and from a script someone dropped
are one pattern, and one Safe covers both. Over twelve hours of real history (`--origin-report`), 4.2 million of
17.8 million events came from tools and interpreters, in 41,660 patterns. 98% of those patterns only ever came from
one kind of origin, so naming who did it adds a few percent more patterns, not thousands.

**Decision.** For tools and interpreters (`ProcessOrigin.isToolLike`, the launch's parent for a launch), the
pattern's program names who did it, `/opt/homebrew/bin/node via Cursor`, and only when it is proven. A decision for
one origin must never reach another, so a wrong name is worse than none.

Who comes from kernel facts only (`Lineage`, in the collector). Endpoint Security names each program execution
exactly, (pid, pidversion), a new version with every exec, so a reused pid is never mistaken for the old process. The
collector subscribes to fork as well as exec, and records each execution's parent when it is created: a fork's child
comes from the process that forked it, an exec's new program from the one it replaced. A process first seen later
takes its parent token, unless that is launchd for a process that started elsewhere (`original_ppid`): adopted, so
its real parent is unknown. First facts win.

Walking up from the process:
- **A verified agent** names it: its signature, as the kernel checked it, is the agent's (team `Q6L2SF6YDW`,
  `com.anthropic.claude-code`, valid). Never a name or a path: a program called `claude` signed by anyone else is
  not Claude Code. Agents that run as scripts (Codex, Gemini CLI, cursor-agent: the running program is node or bash)
  can't be proven and are not named.
- **Something that only looks like an agent** (by name or command line) withholds who below it. Names are only ever
  used to say less, so faking one can only take attribution away.
- **Every link known up to launchd, no agent**: the app macOS holds responsible (`responsible_audit_token`, a kernel
  fact), by name, unless the process answers for itself.
- **Any link not known**: nobody is named, and the pattern stays plain.

A launch held for your answer has no execution yet: who is worked out for a child of the launching process, which
is part of its chain. The collector adds `agent` (the verified agent's name) or `resp` (the responsible app's path)
to every event and question. The pattern text is untouched, so its meaning (`]`, `/**`, `isTooWide`) doesn't change.
Who sits in the program part after ` via `: `programPath` gives back the path for every check that reads it as a file.

**Carry-over.** A pattern that names who starts with the decision its plain pattern had (status, source and note),
unless it is riskier, and isn't New then. A key not seen yet answers with the plain one (history, Time Travel).
Rules and whole-process rules that don't name who match the program from anyone, as before. One that names who
matches only that. Combined patterns apply before who is added.

**Consequences.** Decisions made from now on are per origin: Safe for `node via Cursor` says nothing about
`node via Claude Code`. The AI is told who did it and that the pattern is about that. Old plain patterns stay and
keep their decisions. Events recorded before this have no `resp` or `agent`, so replaying them gives plain patterns. The collector does a
little more (fork events and the lineage): about one point of CPU on a busy Mac, 3.9% to 5.1%.

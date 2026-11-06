## Everyday use

### Controls at a glance

Each kind of control has one home. Use this section as a map: it tells you where to find a command, and the sections
below explain what each one does.

**Menu bar icon.** The icon is the app icon's list mark, tinted like your other menu bar icons. It is for a quick
glance and quick actions.

- **Status line:** Live, Paused, Starting… or Collector off, plus the number of open stories and high-risk patterns.
- **Extra lines, only when they apply:**
  - *N processes held — Review…*
  - *N known-bad matches this week…*
  - *A macOS update fixes N exploited flaws…* (or *N exploited macOS flaws since your last update…*)
  - *Claude Code guard was removed — Restore*
  - *Claude Code: N actions blocked today…*
  - *Learning this Mac's normal behaviour (wave N of 3)*
  - *<version> Available…*
- **Actions:**
  - **Start Collector…** (shown when the collector is off)
  - **Open Hostwatch** (⌘O)
  - **Stories**, **Patterns** and **Network**, each with a badge. The Network badge shows waiting firewall questions,
    or else new domains.
  - Pause Live Stream
  - **Show HUD** (⌃⌥⌘H). This shortcut works from any app.
  - Hold Suspicious Processes
  - **Settings…** (⌘,)
  - **Quit** (⌘Q)

**App menus.** These are available while a Hostwatch window is open.

| Menu | Commands |
|------|----------|
| *Edit* | Undo, Redo, Cut, Copy, Paste, Select All, Find (⌘F) |
| *View* | Events ⌘1 · Patterns ⌘2 · Rules ⌘3 · Stories ⌘4 · Network ⌘5, Running Now (⌥⌘R), Time Travel (⌥⌘T), Earlier (⌘[) and Later (⌘]) during Time Travel, the **Show** filter, event-kind toggles, Show HUD, Enter Full Screen (⌃⌘F; Esc leaves) |
| *Activity* | Pause Live Stream, Clear Events (⌘K), Ask AI About Selection (⌘↩), Watch Selected Process Closely… (⌥⌘W), Mark Safe / Suspicious / Dangerous / Unclassified, Exclude Selection…, Start/Stop Collector |
| *Window* | Activity Window (⌘0), Held Processes |
| *Help* | **Hostwatch Help** (these docs), Use with Claude Code…, Collector Log, Full Disk Access Settings |

**Right-click a row.** This works on events, patterns and domains. It also works in the HUD while click-through is
off. The menu offers:

- **Ask AI: Is This Dangerous?…** and **Watch <name> Closely…**
- Mark its pattern, or **Mark All … From This Process** (with *Clear Rule*).
- **Exclude ▸** *Hide process*, *Hide spawns of*, *Hide host*, *Hide domain \*.x*, or *Edit Exclusions…*
- **Copy Detail**, **Copy Process Path**, **Reveal in Finder**.

**Events toolbar.** It holds the tab bar, the event-kind counters (click one to hide that kind), Time Travel, Pause,
**Clear**, **HUD**, **Settings** and search.

### HUD

The HUD is a compact overlay that shows your Mac's activity as it happens, on top of other windows. It can be
click-through, so your clicks pass through it to the apps underneath.

It shows one line per event:

| Icon | Kind | Shows |
|------|------|-------|
| ▶ cyan | new process (`exec`) | name, `pid ← ppid`, time |
| 🌐 green | new connection | name, `TCP/UDP remote:port`, time |
| 📄 orange | newly opened file | name, `r/w/rw path`, time |

The kind toggles only **hide** rows from view. Collecting, patterns, stories and history always get every kind.

**Moving and resizing.** **Click-through** is off by default. While it is off, you can move and resize the HUD with
the mouse:

- **Move:** drag its header bar.
- **Resize:** drag the ◣ grip in its bottom-left corner. Width changes smoothly. Height snaps to whole rows. The
  top-right corner stays put.
- **Width or height only:** drag the HUD's left edge to change only the width, or its bottom edge to change only the
  height.

Position and size are remembered. The HUD starts at 24 rows × 360 pt.

**System row.** A row of CPU, memory, network and disk sits at the top unless you turn it off (Settings ▸ HUD).

Quitting also stops the collector the app started.

### Window tabs

The activity window has five tabs: Events ⌘1 · Patterns ⌘2 · Rules ⌘3 · Stories ⌘4 · Network ⌘5. Network covers
domains and the firewall.

- **Badges:** each tab shows its icon and its count as a badge. When the window is narrow, only the icons show.
- **Event-kind counters:** these appear on Events only.
- **macOS flaw banner:** when exploited macOS flaws aren't fixed yet, a slim banner at the top says so. It offers
  *Details*, *Software Update* and ✕. Closing it with ✕ hides it until another flaw is listed.

**The Show filter.** **Show** is a scope bar on Events and Patterns, also at *View ▸ Show*. It lets you narrow the list
to what needs your attention. It applies to the HUD, Events and Patterns. The choices are **All · New · Important**:

- **New:** not decided yet.
- **Important:** Suspicious and Dangerous, plus new high-risk items.
- **Both:** new domains, beacons, raw IPs and known-bad matches count as both New and Important.

Each choice shows how many rows it would list in that tab. On Events it counts events, taking the kind toggles, search
and *Only These* as they are. On Patterns it counts patterns.

### Running Now

Running Now shows every process running on your Mac at this moment, like Activity Monitor, inside Hostwatch. It is
the quickest way to see what is busy right now and where it came from.

To open it, use the Events tab's switch (**Events · Running Now**), or *View ▸ Running Now* (⌥⌘R). It replaces the
event list. While the window is on screen, the list refreshes every 3 s.

**Columns.** You can sort by any column.

| Column | What it shows |
|--------|---------------|
| process | name with its app's icon; ✦ when Hostwatch saw it start |
| PID | process ID |
| user | root is shown in orange |
| % CPU | since the previous refresh; orange from 50% |
| *Writing* | bytes per second written to disk since the previous refresh; orange from 1 MB/s |
| CPU time | total processor time used |
| memory | physical footprint, as Activity Monitor's *Memory* |
| threads | number of threads |
| running for | time since it started |
| parent | the process that started it |

The search field matches name, path, command line, user or PID. The footer totals CPU and memory.

**Information.** Double-click a row, or right-click ▸ *Show Info*. A panel opens below the list and follows the
selection until you close it. It shows:

- path, parent, user, started, running for
- CPU now, CPU time, and average CPU share since it started
- memory and threads
- the full command line, with secrets masked
- the pattern status of its launch, when Hostwatch recorded it

**Show Spawn in Timeline.** This button is only in the information panel, so a double-click never leaves the list. It
opens Time Travel at the moment the process started, with its launch selected. Anything that would hide it is
cleared: the search, *Only These* and the Show filter. A process that started before the recording began can't be
shown there.

**Other actions:** Watch Closely…, Ask AI… (when its launch was recorded this session), Reveal in Finder, Copy Command
Line, Copy Path, Copy PID.

**In Time Travel.** Running Now shows what was running at the playhead, and follows it as you drag or play. Hostwatch
takes the list recorded at or just before the playhead and rebuilds the moment between that list and the next:

- Processes appear at the moment they started.
- CPU time and memory move between the two lists.
- CPU % is the rate across them.
- "Running for" counts to the playhead.

**How it is recorded for Time Travel.** Hostwatch records the list once a minute while the collector runs and history
is on (Settings ▸ History). It goes into `History/processes-YYYYMMDD.jsonl`.

- **What is stored:** every process each 30 minutes, and only what changed in between.
- **Size:** a few tens of MB a day. The file is compressed when the day is over.
- **Limits and cleanup:** it is counted in the history size limit and removed together with the activity history.
- **Gaps:** moments from before this recording started, or more than 3 minutes after the last list (Hostwatch closed),
  say so.

**How it works.** The app asks the collector for the list. The collector runs as root and reads every process with
libproc (`proc_pid_rusage`, the task info and `KERN_PROCARGS2` for command lines). It answers with one list. CPU % is
the difference between two lists. Nothing is asked while the list is closed or the window is hidden, except the
once-a-minute list recorded for Time Travel.

### Heavy processes

A process that keeps using a lot of CPU or memory can be a sign of trouble, such as a hidden cryptominer. Hostwatch
highlights such processes in Events so you notice them.

**Which processes are followed.** Only processes Hostwatch **saw start** and that are still running. Apps that were
already running when Hostwatch started aren't followed. Otherwise Xcode and browsers would be flagged all day.

**What counts as heavy.** Heavy means sustained use, by either measure:

- **CPU:** averaged over 30 s (at least 25 s of samples), at or above the limit. The default is 50% of one core.
- **Memory:** a memory footprint at or above the limit. The default is 1 GB.

*Settings ▸ Detection ▸ Heavy processes* sets both limits, or turns the feature off.

**What you see:**

- **Badge on the launch row:** a live badge such as `🔥 380% CPU · 2.1 GB · 12 min`, or a memory chip when memory is
  the reason. A flame appears in Status.
- **In the HUD:** `🔥 380%`.
- **After it exits:** the badge turns grey for 10 minutes, for example `ended 1 min ago · peak 240% · 900 MB`.
- **Banner above the list:** it names the heavy ones. For each it shows the app icon, the name (with an *Untrusted*
  tag when it is), the program that started it, a CPU gauge (400% fills it), memory and running time.
- **Banner actions:** ✦ asks AI. ⋯ has Show in Finder and Copy Path. **Only These** filters Events to them.
- **Collapsing:** the chevron collapses the banner to one line with the busiest names. So it never hides that
  something is there.

**Time Travel uses the same design.** The heavy list is recorded with each 5-second metrics sample, usually 0–3
entries. At the playhead the banner reads *Running heavy at 14:32:05*. The launch rows carry the same badges as they
did live, with the running time computed for that moment.

**Detection.** A heavy process that is unsigned, ad-hoc, quarantined or from a download/temp folder adds the story
stage *Heavy untrusted process* (3 points, strong). This is the cryptominer pattern.

**How it works.**

- Every 5 s, the collector's existing sampler (libproc `proc_pid_rusage`, already used for the busiest processes) also
  sends every process above a floor: ≥ 5% CPU or ≥ 300 MB, at most 50. Each comes with its start time.
- Launch events carry the start time too (`pstart`). So a reused pid is never mistaken for the process that started.
- Exits are checked with `kill(pid, 0)`.
- Launches restored from history after a restart are followed too.
- Nothing new is recorded, only numbers.

### Resource use (CPU, memory, network, disk)

Hostwatch keeps an eye on how hard your Mac is working, so you can spot unusual load and see which program caused it.
Every 5 seconds it records system-wide resource use.

**The footer strip.** The Events tab's footer shows resource use live, with 5-minute sparklines (small trend lines):

- **CPU:** share of all cores.
- **Mem:** apps + wired + compressed, the same as Activity Monitor's "Memory Used". The line turns orange or red with
  macOS memory pressure.
- **network:** download ↓ / upload ↑ over Wi-Fi, Ethernet and cellular. VPN tunnels and loopback aren't
  double-counted.
- **disk:** read/write.

The list button shows the **busiest processes** at that moment: CPU % of one core, memory footprint and disk
throughput.

**Disk space.** The strip shows the startup disk's free space, as Finder counts it, purgeable space included. Click it
to see:

- free space over the last hour or 24 hours, live or ending at the playhead in Time Travel;
- the programs that **wrote the most** to disk in that period, with bytes and how many processes.

Writes come from two sources. One is the collector: each process's bytes written since it started (its rate is the
*Writing* column in Running Now). The other is the once-a-minute process lists, so programs that already ended count
too. A process that lived less than a minute between two lists isn't seen.

macOS doesn't track the space each program occupies, so bytes written is the measure. Temporary files that were
deleted again count too.

**Time Travel.** The timeline shows CPU (blue) and memory (green) lines under the activity bars, on the same time
axis. The footer strip shows the slice around the playhead. The banner shows the values and the busiest process at
the playhead. Times before this feature existed simply have no line.

**Recording.** Resource use is recorded while Hostwatch is open, one line per sample, in
`History/metrics-YYYYMMDD.jsonl` (a few MB per day).

- Past days are gzip-compressed.
- Days older than the oldest activity history are deleted with it.
- *Clear History* removes them too.

**Sources.**

- CPU, memory and network come from the kernel's counters. No special rights are needed.
- The busiest processes and disk throughput come from the collector. As root it can see every user's processes
  (`proc_pid_rusage`). The app alone can't see about a third of processes, all of them system ones.
- The collector sends them every 5 s only to the live window, never into the event history.

**Checking the numbers.** `Hostwatch --metrics-probe` prints three readings, for comparing with Activity Monitor or
`top`.

### Time Travel

Time Travel lets you go back and see exactly what happened on your Mac at any recorded moment. It is how you
investigate something after the fact.

To open it, click *Time Travel* in the activity window's toolbar, or use *View ▸ Time Travel* (⌥⌘T). The Events tab
switches from the live stream to recorded history. Live collection carries on in the background.

**Timeline.** It floats at the bottom of the window.

- **Bars:** they show how busy the Mac was across the whole recording. They use a square-root scale, so one burst
  doesn't flatten the rest. Gaps are when nothing was recorded.
- **Dots:** red and orange dots mark stories. Purple dots mark new domains.
- **Using it:** hover for the time and drag to move. Clicking near a dot lands on it.

**The slice.** The list shows the window of time ending at the playhead: 1 min, 5 min, 15 min or 1 hour. Newest is
first. It uses the same Show filter, kind toggles, exclusions and search as live.

The list is read a page at a time, about 3,000 events. Scrolling to the end of the list loads the next older page. A
very busy window stops at its newest ~20,000 events and says so. A shorter window shows the rest.

**Moving through time:**

- **Step:** ⌘[ and ⌘] (or ◀︎ ▶︎) step one window.
- **Play:** ▶︎ plays forward at 1× (real time), 10×, 60× or 600×.
- **Jump:** the date picker jumps anywhere.
- **Back to live:** **Return to Live** (Esc) goes back.

The banner has the window (1 min, 5 min, 15 min, 1 hour), the playback speed (1×, 10×, 60×, 600×) and a date picker.

**From a story.** *Show in Timeline* opens the slice around it.

**Search all history.** Type two characters or more in the toolbar search field. The list then shows matches from
everything recorded, not only the slice.

- **Results:** newest first, with the day in the Time column. Tick marks on the timeline show where they happened.
- **What it matches:** the same as the live search: name, path, detail, host, or the exact PID.
- **Speed:** the search runs in the background and the list fills as it goes (≈5 s for 20 GB of history).
- **Limit:** it stops at the newest **1,000 matches** and says how far back it got. A more specific search reaches
  older ones.
- **Opening a match:** double-click it (or *Show in Timeline*) to open its moment, with it selected.
- **Scope:** the scope bar switches between **All History** and **This Window** (only the shown slice).

**How it reads history.** Only the slice you look at is loaded, so it stays fast.

- In the plain (current) file, lines are in time order. So the offset of any moment is a binary search away.
- Compressed files are found through their block index.
- Bar heights come from byte counts (per-minute counts for compressed files).
- Timings: the overview takes milliseconds; a busy slice of ~20,000 events takes ≈0.3 s.
- A search reads blocks newest first and parses only lines whose bytes contain the search text.

`Hostwatch --time-travel-probe [dir]` prints these timings, searches included.

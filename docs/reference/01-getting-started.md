## Getting started

### Requirements

- **macOS 26 or later.**
- **Full Disk Access for Hostwatch.app.** The setup window walks you through it.
- **Your administrator password, once.** It registers the collector as a background service.

### Install

1. Download `Hostwatch-<version>-macOS-universal.zip` from
   [Releases](https://github.com/everythings-gonna-be-alright/Hostwatch/releases/latest).
2. Check the download: `shasum -a 256 Hostwatch-*.zip` must match the `.sha256` file next to it.
3. Unzip and move `Hostwatch.app` to `/Applications`.
4. Open it. It's signed with a Developer ID and notarized by Apple, so macOS opens it without a warning. To check:
   `spctl -a -vv /Applications/Hostwatch.app` says *Notarized Developer ID*.
5. A setup window asks for **Full Disk Access**. Click *Open Settings…*, turn access on, then click **Quit & Reopen**.
   Your other choices in this window:
   - **Start Without Access** watches the network only.
   - *Later* / *Not Now* close the guide.
   - **Start Watching** continues once access is on.
6. Enter your administrator password once. The collector starts and the learning day begins.

> [!WARNING]
> Keep Hostwatch.app in `/Applications`, or another folder only you can write to. The collector runs from it as root,
> so anything able to change the app would get root rights the next time the collector starts.

**The welcome guide:** on a fresh install, after the Full Disk Access setup, five short pages say what Hostwatch
does, what each tab is for, how decisions work, what the learning day is, and how Protection starts. It shows once.
**Help ▸ Welcome Guide** opens it again at any time.

### Built-in collector

The collector is the part of Hostwatch that runs with administrator (root) rights and gathers activity. It is built
into the app, so there is nothing else to install.

**How it starts:** as a background service, approved once.

1. The first time, Hostwatch registers the collector as a background service. macOS asks for your administrator
   password once, and may list it under System Settings ▸ General ▸ Login Items ▸ *Allow in the Background*, where
   you approve it once.
2. From then on macOS starts the collector itself: at boot, after a crash, after an update. Hostwatch connects to it
   when it opens, with no password.
3. If macOS ever refuses to start the service (this can happen when the app is replaced during an update), Hostwatch
   notices within half a minute of opening and registers it again, with your password.
4. *Settings ▸ General ▸ Remove…* unregisters the service (your password again), for example before uninstalling.
   It stops and won't start at boot. You can turn off the registration at launch with *Register the collector when
   Hostwatch opens*.

> [!NOTE]
> To uninstall, first choose *Settings ▸ General ▸ Remove…*, so the collector stops and won't start at boot. Then
> delete Hostwatch.app.

**Where Full Disk Access goes:** macOS counts the collector's access as Hostwatch's, so Full Disk Access must be
granted to **Hostwatch.app**. The app checks for it before asking for your password, and shows a guide if it's
missing. If the collector log shows `ERR_NOT_PERMITTED`, use **Open Full Disk Access Settings**, enable Hostwatch,
then start the collector again.

**Where the log goes:** `/var/log/hostwatch-collector.log`. Open it with *Help ▸ Collector Log*.

**If the app quits or dies:** the collector keeps running but goes idle after 15 s with no app connected. It stops
watching, and the firewall is off, until Hostwatch opens again.

### Baseline: the learning day

On the first launch, Hostwatch spends a day learning what is normal on your Mac, so it doesn't ask you about
everything. It learns in **waves at 5, 15 and 60 minutes, then every hour** until the day is over. *Settings ▸
Detection ▸ Learning day* makes it 3 or 7 days, *Extend by a Day* adds one, *End Now* finishes it, and *Learn This Mac
Again* starts it over. The menu bar icon shows how long is left.

During the learning day, what other signed programs do **again and again** (at least three times, over at least an
hour) goes to the on-device AI, and its sure *Safe* is applied, recorded as the AI's decision ("learned during the
learning day"). One-offs aren't typical, so they wait. After the learning day, the AI's answers are suggestions again.

> [!NOTE]
> Shells, interpreters, your sensitive files and high-risk patterns are never learned, not even during the learning
> day. They wait for your own decision.

Each wave sorts the New patterns seen so far into these groups:

- **Trusted:** marked Safe, with source "baseline". This needs all of the following:
  - normal risk
  - the acting program is signed by Apple or by the developer of an installed app. For a launch, the launched program
    must be too
  - a valid signature, and not quarantined
  - not in Downloads, temp, Shared or a volume
  - not touching a sensitive place (login items, credentials, mail, messages).
- **Exception for macOS system services:** daemons and agents on the sealed system volume may touch sensitive places.
  Indexing, sync and malware scanning is their job. This doesn't include command-line tools like `cat`, `sqlite3` or a
  shell.
- **On-device model:** for programs that are signed, but whose developer isn't trusted yet. This is never Claude. Its
  verdicts are suggestions in Needs You, and it never suggests Safe for high risk.
- **Needs You:** these stay New. This covers high risk, unsigned or ad-hoc programs, quarantined ones, Downloads or
  temp, sensitive places, or a program that is gone. Malware already on the Mac lands here, so the baseline can't be
  poisoned.
- **Never trusted or listed:** Hostwatch's own activity, and interpreters and shells (macOS's own included). They stay
  New.

**Baseline rules** appear in Patterns ▸ Rules. They are narrow:

- **One per app and its signer,** for example *Slack · Slack Technologies*. It includes the app's helpers, and the
  signer must match.
- **One macOS system rule.**

A rule keeps trusting that app's **future** normal-risk patterns, checked every 30 s.

After learning, a new app isn't added by itself. Use **Update Baseline** (Patterns ▸ Rules or Settings ▸ Detection) to
sort New patterns again and add rules for trusted apps among them. It is local and uses code signatures only, no AI.

- **Pause** a rule: its patterns go back to New and it stops applying. The rule is kept, so Update Baseline won't
  recreate it.
- **Delete** a rule: the same as Pause, and the rule is removed.
- **Remove all:** *⋯ ▸ Remove All Baseline Rules* removes every baseline rule.
- **Decided isn't forever.** A Safe pattern is **reopened** when something about it changes, whoever decided it (you
  included). Reopened means back to New and listed first in Needs You as *Reopened: …*. This happens when:
  - one of its steps is part of a story that fires (*part of a story: Slack → sh → curl*)
  - its program contacts known malware infrastructure or is a known malware file. This reopens every Safe pattern of
    that program
  - it becomes high-risk: the binary was swapped or modified, is quarantined or runs from a download/temp folder.

  A reopened pattern is never decided again by a baseline rule, a learned rule, *Accept AI suggestions without asking*
  or *Classify with AI*. Only your own decision (Mark, Trust, Accept) closes it. Decided By shows *Reopened*.
- **Low weight:** your markings and learned rules win over baseline rules. Stories ignore baseline trust: they count
  only your decisions and learned rules, so a chain still alerts.
- **Needs You** has one row per app with all its reasons. An example for an app installed after learning:
  *signed by Zoom (trusted developer, no rule yet)*.
  - **Trust** marks its patterns Safe, as your decision. For a signed app it also adds a baseline rule marked
    *Trusted by you*. That rule also covers the app's own sensitive places, but never high-risk, unsigned or
    downloaded ones. Unsigned or ad-hoc programs are trusted pattern by pattern, with no rule.
  - **Interpreters and shells aren't listed** (python, node, ruby, bash, osascript…). They run any script they're
    given, so trusting them would trust a virus's script too. Their patterns stay New, visible in Patterns, and
    stories keep watching them.
  - **Dismiss** hides the row. Its patterns stay New and aren't listed again.
  - **See the patterns:** click *N patterns ›* to list them in the row.
  - **More actions:** *⋯* ▸ **Mark Suspicious**, or **Show in Patterns**. Show in Patterns opens exactly those
    patterns, and a removable chip replaces the Show filter.
- **Fewer decisions for you:**
  - **macOS itself is always trusted.** Apple tools on the sealed system volume fall under the one *macOS system*
    rule, made by itself, from the first minute. This also applies when a trusted app starts them, such as Cursor
    running `/bin/rm`.
  - **New apps from developers you trust get a rule by themselves.** The setting is *Settings ▸ Detection ▸ Trust new
    apps from developers you trust*, on. These rules are marked *Automatic*. A rule you delete isn't made
    again by itself, though Update Baseline still can.
  - **A rule trusts only what its app normally does.** In its first week, it learns the app's kinds of behaviour
    (`launches node`, `connects to the web`, `reads ~/Documents`, `writes its own data`…). After that, a pattern of a
    new kind isn't trusted and comes to Needs You as *new for Slack: writes ~/Movies*. macOS's own rule doesn't learn
    this.
  - **Needs You lists only what's active.** A pattern not seen for 7 days leaves it. It stays New in Patterns and
    comes back if it happens again.
  - **Homebrew tools share one row.**
  - **Recent automatic trust:** Patterns ▸ Rules shows *Trusted automatically in the last 24 hours: N new patterns
    (Docker 12, …)* with Show.

### After a restart

After a restart, the event list isn't empty. It starts with the newest recorded events from history, up to its
5,000-event limit. The footer shows how many came from before the restart.

These older events are display only, because detection already saw them. They sort below every new event. Time
Travel shows the rest.

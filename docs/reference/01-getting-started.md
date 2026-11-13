## Getting started

### Requirements

Before you install, check that your Mac has these:

- **macOS 26 or later.** Hostwatch uses the Liquid Glass UI, and `eslogger` is included with this version.
- **Xcode 26 Command Line Tools.** They provide Swift 6.2+ and the macOS 26 SDK.
- **Full Disk Access for Hostwatch.app.** If you use run-agent.sh, grant it to Terminal instead.
- **Your administrator password, once.** It registers the collector as a background service.

Install the command line tools if needed:

```bash
xcode-select --install
```

### Install

1. Download `Hostwatch-<version>-macOS-universal.zip` from
   [Releases](https://github.com/everythings-gonna-be-alright/Hostwatch/releases/latest).
2. Check the download: `shasum -a 256 Hostwatch-*.zip` must match the `.sha256` file next to it.
3. Unzip and move `Hostwatch.app` to `/Applications`. Keep it somewhere only you can write to, because the collector
   runs from it as root.
4. Open it. It's signed with a Developer ID and notarized by Apple, so macOS opens it without a warning. To check:
   `spctl -a -vv /Applications/Hostwatch.app` says *Notarized Developer ID*. Builds from 0.11.0 and earlier weren't
   notarized and need **System Settings ▸ Privacy & Security ▸ Open Anyway** once.
5. A setup window asks for **Full Disk Access**. Click *Open Settings…*, turn access on, then click **Quit & Reopen**.
   Your other choices in this window:
   - **Start Without Access** watches the network only.
   - *Later* / *Not Now* close the guide.
   - **Start Watching** continues once access is on.
6. Enter your administrator password once. The collector starts and the first-hour baseline begins.

### Built-in collector

The collector is the part of Hostwatch that runs with administrator (root) rights and gathers activity through
`eslogger`. It is built into the app, so there is no separate script to install.

**How it starts:** as a background service, approved once.

1. The first time, Hostwatch registers the collector as a launchd service that ships inside the app
   (`Contents/Library/LaunchDaemons/tech.hostwatch.collectord.plist`). macOS asks for your administrator password
   once, and may list the collector under System Settings ▸ General ▸ Login Items ▸ *Allow in the Background*, where
   you approve it once.
2. From then on macOS starts the collector itself: at boot, after a crash, after an update. It runs as root, and
   Hostwatch connects to its socket (`/var/run/hostwatch/collector.sock`) when it opens. No password at launch.
3. The service runs `Hostwatch --collector-launcher self --collector --daemon`: the launcher spawns the agent, so
   Hostwatch.app stays the responsible process for Full Disk Access. The agent serves the user at the Mac.
4. If macOS ever refuses to start the registered service (it happens when the app bundle is replaced at the very
   moment the service restarts), Hostwatch notices within half a minute of opening and registers it again, with
   your password.
5. *Settings ▸ General ▸ Remove…* unregisters the service (your password again), for example before uninstalling.
   You can turn the registration at launch off with *Register the collector when Hostwatch opens*.

**Coming from 0.12.0 or earlier:** 0.13.0 has a new identity (`tech.hostwatch.app`). Your settings are carried
over on the first launch. macOS keys Full Disk Access and the keychain by identity, so grant Full Disk Access once
more (the setup window appears by itself) and choose *Always Allow* in the one keychain dialog for *Hostwatch data
key*. The collector service is registered again, with your password once.

A build without a Developer ID signature (your own build from source) has no service: it starts the collector as a
temporary launchd job after an administrator prompt, every launch.

**Where Full Disk Access goes:** macOS treats Hostwatch.app as the responsible process for eslogger. So Full Disk
Access must be granted to **Hostwatch.app**.

**Where the log goes:** the service writes `/var/log/hostwatch-collector.log`. A collector started by the admin
prompt (a build without a Developer ID) writes `~/Library/Logs/Hostwatch/agent.log`. Open it with *Help ▸ Collector
Log*.

**Stopping and safety:**

- **Remove…** (the service): unregisters it with your password. It stops and won't start at boot. **Stop** (an
  admin-prompted collector) sends a shutdown command carrying a random token, written with mode 0600 to
  `~/Library/Application Support/Hostwatch/collector.token`. The service ignores that command.
- **If the app quits or dies:** the service keeps running but goes idle after 15 s with no client (no `eslogger`,
  no packet capture, firewall off) until Hostwatch connects again. An admin-prompted collector exits within about
  2 s if the app that launched it dies (`--owner-pid`).

**Full Disk Access problems:**

- **The error:** `eslogger` needs Full Disk Access. If the log shows `ERR_NOT_PERMITTED`, use
  **Open Full Disk Access Settings** and enable Hostwatch, then start the collector again.
- **Checked in advance:** the app checks for this before asking for your password. If access is missing, it shows a
  guide.
- **After every rebuild:** builds are ad-hoc signed by default, so **every rebuild needs the grant redone**. Remove the
  old Hostwatch entry with − and add it again.
- **To avoid this:** build with a stable identity:
  `CODESIGN_IDENTITY="Apple Development: you@example.com (TEAMID)" ./scripts/build-app.sh`.

**Running it by hand:** `./scripts/run-agent.sh` runs the collector from Terminal (`sudo Hostwatch --collector`).
The app detects it and does not start a second one.

### Baseline: the first hour

On the first launch, Hostwatch learns what is normal on your Mac, so it doesn't ask you about everything. It learns
in **three waves, at 5, 15 and 60 minutes**.

Each wave sorts the New patterns seen so far (`BaselinePolicy`) into these groups:

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

**Baseline rules** appear in the Rules tab. They are narrow:

- **One per app and its signer,** for example *Slack · Slack Technologies*. It includes the app's helpers, and the
  signer must match.
- **One macOS system rule.**

A rule keeps trusting that app's **future** normal-risk patterns. It checks every 30 s, always through the same
policy.

After learning, a new app isn't added by itself. Use **Update Baseline** to sort New patterns again and add rules for
trusted apps among them. It is local and uses code signatures only, no AI.

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

  New kinds of behaviour from a trusted app reach you through its rule's profile (see *A rule trusts only what its
  app normally does* below).
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
- **Existing installs** don't start learning by themselves. Use **Update Baseline** (Rules tab or Settings ▸
  Detection).
- **Fewer decisions for you:**
  - **macOS itself is always trusted.** Apple tools on the sealed system volume fall under the one *macOS system*
    rule, made by itself, from the first minute. This also applies when a trusted app starts them, such as Cursor
    running `/bin/rm`.
  - **New apps from developers you trust get a rule by themselves.** The setting is *Settings ▸ Detection ▸ Trust new
    apps from developers you trust*, on. These rules are marked *Automatic*. A rule you delete isn't made
    again by itself, though Update Baseline still can.
  - **A rule trusts only what its app normally does.** In its first week, it learns the app's kinds of behaviour
    (`launches node`, `connects to the web`, `reads ~/Documents`, `writes its own data`…). After that, a pattern of a
    new kind isn't trusted and comes to Needs You as *new for Slack: writes ~/Movies*. Rules from before this keep
    what they already trusted as their profile. macOS's own rule doesn't learn a profile.
  - **Needs You lists only what's active.** A pattern not seen for 7 days leaves it. It stays New in Patterns and
    comes back if it happens again.
  - **Homebrew tools share one row.**
  - **Recent automatic trust:** Rules ▸ Rules shows *Trusted automatically in the last 24 hours: N new patterns
    (Docker 12, …)* with Show.
- **Older baselines:** baselines from the first version (one rule per developer) are undone once and sorted again.

### After a restart

After a restart, the event list isn't empty. It starts with the newest recorded events from history, up to its
5,000-event limit. The footer shows how many came from before the restart.

These older events are display only, because detection already saw them. They sort below every new event. Time
Travel shows the rest.

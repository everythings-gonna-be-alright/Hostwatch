## Threat model and attack coverage

What Hostwatch defends against, what it doesn't, how it protects itself, and which attack techniques it sees, mapped
to MITRE ATT&CK. Everything here is checked against the code of the current release. Where Hostwatch is weak, this
page says so.

### What Hostwatch is for

Hostwatch watches one Mac for an attacker who got code running **as you**: a malicious download, a poisoned package,
an infostealer, a backdoor that wants to start again after a reboot, or an AI coding agent tricked into running
something harmful. It learns what is normal, flags what isn't, joins small steps into one story, and can stop
launches, file access and connections you didn't allow.

**What it protects:**

- your secrets: SSH and GPG keys, keychains, cloud and developer credentials, browser passwords and cookies
- what starts by itself: launch agents and daemons, login items, shell startup files, cron
- your network: which programs talk to which servers
- its own record of what happened: the history, patterns and decisions, encrypted on disk

**Who it defends against:**

| Attacker | In scope |
|----------|----------|
| Malware running as you (dropper, infostealer, backdoor, persistence) | Yes, the main case |
| A program you were tricked into opening | Yes |
| An AI coding agent following malicious instructions | Yes, with the Claude Code guard for Claude Code |
| Known malware servers and files | Yes, through public threat lists |
| Another user account on the same Mac | Partly: it can't read Hostwatch's socket or data, but its processes aren't stopped |
| Malware that already has root, or a kernel exploit | No |
| Someone with physical access to your unlocked Mac | No |
| Attacks on other devices on your network | No |

### What Hostwatch assumes

- **System Integrity Protection is on.** Hostwatch relies on macOS protecting its own tools (`eslogger`, `pfctl`,
  `tcpdump`) and the code signing checks.
- **The app is somewhere only an administrator can write**, such as `/Applications`. The collector is the app's own
  binary, run as root. Anything that can replace the app gains root at its next start.
- **Full Disk Access is granted** to the collector. Without it, `eslogger` sees nothing.
- **macOS itself is not compromised.** Hostwatch reads what macOS reports. A rootkit can lie to both.

### Trust boundaries

Each line where data crosses from a less trusted side to a more trusted one, and what guards it.

| Boundary | What crosses | Guard |
|----------|--------------|-------|
| Your account → root collector | commands and firewall answers over `/var/run/hostwatch/collector.sock` | Unix socket only, no network port. The kernel names the peer (audit token), and the collector accepts only code that satisfies its own designated requirement: same Team ID and bundle id. Socket 0600, folder root-owned. |
| Root collector → app | the event stream | The app connects only to a socket owned by you, mode 0600, not a link, in a root-owned folder. |
| App → disk | history, patterns, decisions, logs | AES-256-GCM through one sealing point (`Vault`). The key is in a keychain item only Hostwatch's code may read, or wrapped by the Secure Enclave. |
| Events → AI | command lines, paths, evidence | Every prompt is masked for secrets right before it's sent. An AI can't mark a shell, interpreter or system tool Safe beyond an exact folder in your own projects. Your decisions always win over any AI. |
| Internet → app | threat lists, the update check | HTTPS, no cookies. A list must be text in the right shape and size, can never make anything trusted, and can't flag the big platforms by their own domain. The update check only tells you, nothing is downloaded or installed. |
| Claude Code → its tools | each command before it runs | A `PreToolUse` hook. It can only make Claude Code stricter, never answers `allow`. |
| MCP client → history | read-only questions | A random token you register once, kept only as a SHA-256 hash, compared in constant time. Every tool is read-only. |
| Your programs → the network | connections | With the firewall on Ask or Strict, the packet filter sends your programs' new connections through a relay that waits for your decision. Root's connections pass. |

### How Hostwatch protects itself

| Part | Threat | Protection | What remains |
|------|--------|------------|--------------|
| Root collector | Another program talks to it, reads the stream or answers firewall questions | Peer audit token checked against Hostwatch's designated requirement on every connection | A process with root can do anything, as always |
| Root collector | Code injection into it | Hardened runtime: macOS ignores `DYLD_INSERT_LIBRARIES` and loads only Apple-signed libraries. Verified with a test library. | None known |
| Root collector | Commands from the client | Client config is only used as filters. The collector runs no command a client sends. | None known |
| The app | Replaced by malware | Signed and notarized. macOS checks the signature at launch. Keep it in `/Applications`. | An app in a folder you can write can be replaced |
| Data on disk | Read by another program running as you | Encrypted. The key needs Hostwatch's code signature, or your keychain password in a dialog. | Settings (the preferences file) are plain |
| Secrets in command lines | Stored in history or sent to an AI | Masked by one rule set: headers, tokens, passwords, URL credentials, known token formats, private keys | A secret in a shape no rule knows can slip through |
| Threat lists | A poisoned list flags a popular domain, or a list carries code | Shape, size and growth checks. Big platforms can't be flagged by their own domain. A malicious file on a platform anyone can publish to (GitHub, Telegram, Dropbox…) doesn't flag the platform. Lists only raise alerts. | A list provider can still miss things or be late. Malware calling home through such a platform isn't a list match, only its behaviour is judged. |
| Your exceptions and rules | An Allow opens a place or a server to more than you meant | A place's exceptions name one program each, never "any program". Destinations: the most specific decides, Block when a program is on both lists. | A program you always allow in a place can read it, by your choice. |
| AI check of paused programs | A crafted command line talks the AI into letting a program go on | Only a sure Safe lets it go on, once. Never a shell, interpreter, high-risk program or sensitive file. A warning sign Hostwatch found blocks it. The decision stays yours | One launch of an ordinary program could get through on a wrong verdict. Turn the check off in Settings ▸ AI. |
| AI triage | A command line written to fool the AI ("this is safe") | The AI never decides alone for shells and interpreters. Precedence: you, then your rules, then AI, then automatic. Risk only goes up by itself. | The AI can still be wrong about ordinary programs. Its verdict is shown as the AI's, and you can reopen it. |
| Hold and protection | A process frozen forever, or the wrong process signalled | A watchdog resumes every held process after 65 s. The path is checked before every signal, so a reused pid is left alone. | Stopping happens just after the start, see below |
| Release | A tampered download | Developer ID signature, Apple notarization, a stapled ticket, a published SHA-256 | Trust in Apple and GitHub |

### Known weaknesses

These are real, and listed so you can judge Hostwatch fairly.

- **Malware running as you can quit Hostwatch.** The app runs as you, so a process of yours can end it. The collector
  then stops watching after 15 seconds without a client, and nothing records what happens next. Restarting the app
  resumes everything. Raising an alert when the app goes away unexpectedly is planned.
- **It sees most things just after they happen.** `eslogger` reports events, it can't refuse them. Ask and Strict stop a
  program a few milliseconds after it starts or opens a protected file. A very quick command can finish first. Stopping
  before the start needs Apple's Endpoint Security approval, which is pending.
- **Only your own processes can be stopped.** Launch and file protection and holds act on processes of your user.
  A root process, or another user's, is reported but not stopped. The firewall judges your programs' connections too:
  root's connections and macOS's DNS service pass without being asked about.
- **Detection judges behaviour and text.** Well-hidden code, an unknown way to persist, or a secret in an unusual
  format can get through. The always-on monitor records launches, file opens and connections, not every file write or
  rename. Watch Closely records about 60 kinds of event, but only for the program you point it at.
- **Containers, virtual machines and some network traffic** aren't fully covered: see Known limitations in
  [Privacy, security and limits](06-privacy-security-and-limits.md#known-limitations).
- **The AI can be wrong.** It suggests, you decide. An explicit *Apply the Verdicts* is your decision, recorded as yours.

### Attack coverage (MITRE ATT&CK)

[MITRE ATT&CK](https://attack.mitre.org/matrices/enterprise/macos/) is the public catalogue of how attackers work,
used to compare security tools. This table maps the macOS techniques Hostwatch sees. What each level means:

- **Alerts:** raises a story, a `KNOWN BAD` tag or a badge by itself or together with other steps.
- **Flags:** a new pattern you're asked to review, and a weak step in stories. Not an alert on its own.
- **Can stop:** stopped or blocked when the named feature is on. Off by default unless the table says so.
- **Recorded:** kept in the history and searchable, without a signal.
- **Gap:** not covered today.

#### Execution and getting in

| Technique | Coverage | How |
|-----------|----------|-----|
| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) User Execution: Malicious File | Alerts, can stop | *Ran downloaded/temp file* and *Unsigned download ran* stages. A file known to malware lists is *Known malware*. Launches on Ask or Strict stop unknown launches. |
| [T1059.004](https://attack.mitre.org/techniques/T1059/004/) Unix Shell | Alerts, can stop | *App spawned shell* (a browser or Office starting `sh`), *Encoded/piped command* (`curl … \| sh`). The Claude Code guard asks before `curl \| sh`. |
| [T1059.002](https://attack.mitre.org/techniques/T1059/002/) AppleScript | Alerts | `osascript` is a watched tool. `osascript -e` is an encoded command. |
| [T1059.006](https://attack.mitre.org/techniques/T1059/006/) Python, [T1059.007](https://attack.mitre.org/techniques/T1059/007/) JavaScript | Flags, alerts | Interpreters are judged by the script they run, never trusted broadly. `python -c` is an encoded command. |
| [T1105](https://attack.mitre.org/techniques/T1105/) Ingress Tool Transfer | Alerts | *Download* stage (writes into Downloads, `/Users/Shared`), `curl` and `wget` are watched tools. |
| [T1553.001](https://attack.mitre.org/techniques/T1553/001/) Gatekeeper Bypass | Alerts | *Quarantine removed* (`xattr -d com.apple.quarantine`, `xattr -c`). With running the file, the story is Dangerous. |
| [T1027](https://attack.mitre.org/techniques/T1027/) Obfuscated Files, [T1140](https://attack.mitre.org/techniques/T1140/) Deobfuscate/Decode | Alerts | *Encoded/piped command* (`base64 -d`, piped shells). |
| [T1569.001](https://attack.mitre.org/techniques/T1569/001/) Launchctl | Flags | `launchctl` is a watched tool. The Claude Code guard asks before `launchctl load`. |

#### Staying on the Mac

| Technique | Coverage | How |
|-----------|----------|-----|
| [T1543.001](https://attack.mitre.org/techniques/T1543/001/) Launch Agent | Alerts, can stop | *Autostart write*, the strongest single stage. Files on Ask or Strict stop programs writing autostart places. |
| [T1543.004](https://attack.mitre.org/techniques/T1543/004/) Launch Daemon | Alerts | *Autostart write*. Writers are usually root, which protection can't stop. |
| [T1547.015](https://attack.mitre.org/techniques/T1547/015/) Login Items | Alerts, can stop | Background task and login item databases are autostart places. |
| [T1546.004](https://attack.mitre.org/techniques/T1546/004/) Unix Shell Configuration | Alerts, can stop | `.zshrc`, `.bashrc`, `.profile`, fish config and `/etc` shell files are autostart places. |
| [T1053.003](https://attack.mitre.org/techniques/T1053/003/) Cron | Alerts | Cron and `at` folders and `periodic` are autostart places. `crontab` is a watched tool. |
| [T1037.005](https://attack.mitre.org/techniques/T1037/005/) Startup Items | Alerts | `/Library/StartupItems` is an autostart place. |
| [T1554](https://attack.mitre.org/techniques/T1554/) Compromise Host Software Binary | Alerts | *Binary replaced*: a known path whose signer changed. It also reopens a Safe decision. |
| [T1647](https://attack.mitre.org/techniques/T1647/) Plist File Modification | Alerts | For plists in autostart places. Elsewhere it's a gap. |

#### Defence evasion and privilege

| Technique | Coverage | How |
|-----------|----------|-----|
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) Disable or Modify Tools | Partial | The Claude Code guard blocks `spctl --master-disable` and changing Hostwatch's files, and asks before `pkill Hostwatch`. Other programs quitting Hostwatch is a gap (see Known weaknesses). |
| [T1553.006](https://attack.mitre.org/techniques/T1553/006/) Code Signing Policy Modification | Flags | `csrutil` and `spctl` are watched tools. The Claude Code guard blocks turning them off. |
| [T1562.004](https://attack.mitre.org/techniques/T1562/004/) Disable or Modify System Firewall | Flags | `pfctl` is a watched tool. |
| [T1548.003](https://attack.mitre.org/techniques/T1548/003/) Sudo and Sudo Caching | Flags, can stop | `sudoers` and PAM config are protected places. The Claude Code guard asks before `sudo`. |
| [T1222.002](https://attack.mitre.org/techniques/T1222/002/) File Permissions Modification | Recorded | `chmod`, `chown` and `chflags` are kept as their own patterns. |
| [T1055](https://attack.mitre.org/techniques/T1055/) Process Injection | Partial | Watch Closely flags task ports, debugging and thread injection, while it records one program. Always-on: gap. |
| [T1564.001](https://attack.mitre.org/techniques/T1564/001/) Hidden Files and Directories | Gap | |
| [T1070.004](https://attack.mitre.org/techniques/T1070/004/) File Deletion | Gap | Watch Closely shows deletes while it records. |

#### Stealing credentials and data

| Technique | Coverage | How |
|-----------|----------|-----|
| [T1555.001](https://attack.mitre.org/techniques/T1555/001/) Keychain | Alerts, can stop | *Credential access* for keychain files and `security find-generic-password`. Keychains are a protected group. |
| [T1555.003](https://attack.mitre.org/techniques/T1555/003/) Credentials from Web Browsers | Alerts, can stop | Browser password and cookie stores are a protected group. |
| [T1539](https://attack.mitre.org/techniques/T1539/) Steal Web Session Cookie | Alerts, can stop | `~/Library/Cookies` and browser cookie stores. |
| [T1552.004](https://attack.mitre.org/techniques/T1552/004/) Private Keys | Alerts, can stop | `~/.ssh`, `~/.gnupg`, `/etc/ssh`. |
| [T1552.001](https://attack.mitre.org/techniques/T1552/001/) Credentials In Files | Alerts, can stop | AWS, Azure, Google Cloud, GitHub, Docker, Kubernetes, `.netrc`, `.npmrc`, `.pypirc`, `.git-credentials`, `pass`. |
| [T1005](https://attack.mitre.org/techniques/T1005/) Data from Local System | Partial, can stop | Messages and Mail are a protected group, and you can add your own folders and files. Other files: recorded. |
| [T1056.002](https://attack.mitre.org/techniques/T1056/002/) GUI Input Capture | Flags | A fake password dialog needs `osascript`, a watched tool. |
| [T1113](https://attack.mitre.org/techniques/T1113/) Screen Capture | Flags | `screencapture` is a watched tool. Capture through system frameworks: gap. |
| [T1082](https://attack.mitre.org/techniques/T1082/) System Information Discovery, [T1057](https://attack.mitre.org/techniques/T1057/) Process Discovery | Recorded | |

#### Calling home and sending data out

| Technique | Coverage | How |
|-----------|----------|-----|
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) Web Protocols | Alerts, can stop | *New domain*, *Beaconing* (steady interval, low jitter), known command servers from threat lists. The firewall on Ask or Strict blocks new destinations. |
| [T1571](https://attack.mitre.org/techniques/T1571/) Non-Standard Port | Alerts, can stop | *Raw-IP connection*: a public IP, an unusual port, no DNS answer before it, an untrusted program. |
| [T1095](https://attack.mitre.org/techniques/T1095/) Non-Application Layer Protocol | Partial | Raw-IP connections. The Claude Code guard blocks `/dev/tcp` and `nc -e`. UDP sent without connecting: gap. |
| [T1568.002](https://attack.mitre.org/techniques/T1568/002/) Domain Generation Algorithms | Partial | Every never-seen domain is *New domain* after the learning period. No dedicated DGA check. |
| [T1071.004](https://attack.mitre.org/techniques/T1071/004/) DNS | Partial | Known bad domains are caught. Data hidden inside DNS queries: gap. |
| [T1041](https://attack.mitre.org/techniques/T1041/) Exfiltration Over C2 Channel | Can stop | The firewall blocks destinations you didn't allow. No check on how much is sent. |
| [T1567](https://attack.mitre.org/techniques/T1567/) Exfiltration Over Web Service | Partial | The Claude Code guard blocks secrets sent to paste and webhook sites. Elsewhere: new domains and the firewall only. |
| [T1048](https://attack.mitre.org/techniques/T1048/) Exfiltration Over Alternative Protocol | Partial | `scp`, `sftp`, `ftp` are watched tools. |
| [T1090](https://attack.mitre.org/techniques/T1090/) Proxy | Gap | Traffic through a proxy shows only the proxy. |

#### Damage

| Technique | Coverage | How |
|-----------|----------|-----|
| [T1486](https://attack.mitre.org/techniques/T1486/) Data Encrypted for Impact | Gap | Watch Closely flags mass renames while it records. Always-on ransomware detection: gap. |
| [T1485](https://attack.mitre.org/techniques/T1485/) Data Destruction | Partial | The Claude Code guard blocks `rm -rf ~`, `diskutil eraseDisk` and similar. Other programs: gap. |
| [T1490](https://attack.mitre.org/techniques/T1490/) Inhibit System Recovery | Flags | `tmutil` and `diskutil` are watched tools. |

#### Beyond ATT&CK: AI agents

Prompt injection against coding agents isn't an ATT&CK technique yet (it is in
[MITRE ATLAS](https://atlas.mitre.org/)). For Claude Code, the guard checks every shell command, file write and read
of a secret before it happens, and blocks or asks. AI sessions show what each agent session did, grouped.

### Checking these claims yourself

```bash
# The release is signed, notarized and unchanged
codesign --verify --deep --strict --verbose=2 /Applications/Hostwatch.app
spctl --assess --type execute --verbose=2 /Applications/Hostwatch.app

# Hardened runtime is on (flags=0x10000(runtime))
codesign -dv /Applications/Hostwatch.app 2>&1 | grep flags

# The collector's socket: root-owned folder, socket 0600 and yours
ls -ld /var/run/hostwatch /var/run/hostwatch/collector.sock

# Data on disk is sealed (starts with HWV1)
head -c 4 ~/Library/Application\ Support/Hostwatch/stories.json && echo

# Replay your own history through the story rules
/Applications/Hostwatch.app/Contents/MacOS/Hostwatch --story-replay <history.jsonl>
```

The source is public. Each decision behind these rules is written down in `docs/adr/`. To report a way around any of
them, see [SECURITY.md](https://github.com/everythings-gonna-be-alright/Hostwatch/blob/main/SECURITY.md).

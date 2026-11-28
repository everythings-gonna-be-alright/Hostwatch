## Hostwatch vs LuLu, Little Snitch and BlockBlock

What Hostwatch does, who it is for, and how it compares with three well-known Mac security tools. What this page
says about the other tools comes from their makers' own pages, read in November 2026 and linked under
[Sources](#sources).

### What Hostwatch does

Hostwatch is a host intrusion detection system (HIDS) for macOS. It watches what programs run, which files they
open and where they connect, through Apple's Endpoint Security. It learns what is normal on your Mac and asks you
only about what is new.

- **It joins events into stories.** A download, a removed quarantine flag, a new login item and a call to an unknown
  server are four small events. Hostwatch shows them as one attack chain.
- **It can step in.** A firewall asks before a program connects somewhere new. Launch and file protection can ask
  before a program starts, or before it reads places like your SSH keys.
- **It keeps a record.** Everything it saw is kept on your Mac, encrypted, and Time Travel plays it back.
- **It works with AI if you want.** Apple's on-device model or Claude can explain an event. A guard checks the
  commands Claude Code wants to run.

Hostwatch is free for everyone, at home and at work, and its source code is public. Everything stays on your Mac.

### Who Hostwatch is for

- **Developers.** You install packages, editor extensions and command-line tools written by strangers, and each one
  runs with your access to your keys and tokens.
- **People who use AI coding agents.** An agent can be tricked into running a harmful command. Hostwatch records
  what the agent did and can stop the dangerous commands.
- **Anyone who keeps secrets on a Mac.** SSH keys, cloud credentials, browser passwords and cookies are what an
  infostealer comes for.
- **Small teams without a security department.** When something odd happens, you want the story of what ran and
  what it touched, not only a blocked connection.

Hostwatch is not for you yet if your Mac runs a macOS older than 26, or if you need one console for a whole fleet
of Macs. A fleet server is planned as a paid edition for companies.

### At a glance

A dash means the tool's own page doesn't describe that job. It is not a fault: each of these tools does one thing
on purpose.

| | Hostwatch | LuLu | Little Snitch | BlockBlock |
|---|---|---|---|---|
| What it is | Intrusion detection with a firewall | Outgoing firewall | Network monitor and application firewall | Persistence monitor |
| Made by | The Hostwatch project | Objective-See | Objective Development | Objective-See |
| Price | Free | Free | 59 € for one licence, with a free trial | Free |
| Licence | PolyForm Shield, source public | GPL-3.0, open source | Commercial | GPL-3.0, open source |
| macOS | 26 or later | 10.15 or later | See its page | 10.15 or later |
| Watches | Programs, files and connections | Outgoing connections | Connections, both ways | New items that start by themselves |
| Outgoing connections | Watch, ask or block, per program and destination | Asks about each new one, allow or block | Asks about each new one, allow or deny | – |
| Incoming connections | Shows who tried to reach this Mac, can block an address both ways | – | Rules can cover them | – |
| Files and secrets | Asks or blocks before a program reads protected places | – | – | – |
| Program launches | Asks or blocks before a program starts | – | – | Optional: blocks programs that aren't notarized |
| Things that start by themselves | Flags new launch agents, login items, cron jobs and shell startup files | – | – | Its main job: asks, and can remove the item |
| Attack chains | Stories join related events into one alert | – | – | – |
| History | Recorded activity with Time Travel | – | Traffic charts for up to twelve months | A log file |
| Known threats | Public threat lists, checked daily on your Mac | Block lists you add | Curated blocklists, updated daily | VirusTotal links in its alerts |
| AI | On-device or Claude, a Claude Code guard, an MCP server | – | – | – |
| Encrypted DNS | – | – | DoH, DoT or DoQ | – |

### Hostwatch vs LuLu

[LuLu](https://objective-see.org/products/lulu.html) is a free, open-source firewall from Objective-See. It asks
you when a program makes a new outgoing connection, and remembers your answer as a rule for that program or for one
destination. It has block and allow lists, a passive mode, a mode that blocks everything, and profiles. It watches
outgoing traffic only.

**Where they overlap.** Both ask before a program connects somewhere new, both are free, and both let you read the
source.

**What LuLu does that Hostwatch doesn't.**

- It runs on macOS 10.15 and later. Hostwatch needs macOS 26.
- It is a small tool with one job.
- A rule can expire by itself after a time you set.
- Its licence is the GPL, a classic open-source licence. Hostwatch's licence keeps the source public but doesn't
  allow a competing product.

**What Hostwatch adds.**

- The rest of the picture: which program started the one that connected, which files it read first, and whether it
  made itself start at login.
- Stories, so a connection is judged together with what led to it.
- Protection for your files and secrets, and for what may start.
- Who tried to reach this Mac from your network.
- A history you can search and play back.

**Choose LuLu** if you want a simple outgoing firewall and nothing else, or your Mac runs an older macOS.
**Choose Hostwatch** if you want to know what a program did, not only where it connected.

### Hostwatch vs Little Snitch

[Little Snitch](https://www.obdev.at/products/littlesnitch/index.html) is a network monitor and application firewall
from Objective Development. It asks when an app wants to connect, with rules by server, domain, port or protocol,
for outgoing and incoming connections. Its Network Monitor shows where your Mac connects on a world map, with
traffic charts going back up to twelve months. It also has curated blocklists, profiles that switch by themselves,
encrypted DNS and a command-line tool. One licence costs 59 €. Little Snitch Mini, in the Mac App Store, shows
connections for free and blocks them with an in-app purchase.

**Where they overlap.** Both ask before a program connects somewhere new, both show which program talks to which
server, and both use lists of known bad servers.

**What Little Snitch does that Hostwatch doesn't.**

- Encrypted DNS (DoH, DoT or DoQ).
- A map of where in the world the servers are, and traffic history for up to a year.
- Rules by port and protocol, in groups you can subscribe to.
- A firewall at its sixth major version, with the seventh announced. Hostwatch's firewall is much younger.

**What Hostwatch adds.**

- It looks beyond the network: launches, file access, and things that make themselves start at login.
- Stories and a learned baseline, so you are asked about what is new for this Mac, not about every first connection.
- Protection for your SSH keys, credentials and browser data against a program that reads them, whether or not it
  connects anywhere.
- AI explanations, the Claude Code guard and an MCP server.
- It is free, and its source code is public.

**Choose Little Snitch** if the network is what you care about and you want the most complete tool for it.
**Choose Hostwatch** if you want intrusion detection for the whole Mac, with a firewall as one part of it.

### Hostwatch vs BlockBlock

[BlockBlock](https://objective-see.org/products/blockblock.html) is a free, open-source tool from Objective-See. It
watches the places where software installs itself to start again by itself, and alerts you when something new is
added there. You answer Allow or Block, and Block removes the item. Like Hostwatch, it uses Apple's Endpoint
Security and needs Full Disk Access. Optional extras block programs that aren't notarized, block download scripts,
and check what you paste into Terminal.

**Where they overlap.** Both notice when a program makes itself start at login, both use Endpoint Security, and both
can stop a program before it runs.

**What BlockBlock does that Hostwatch doesn't.**

- It removes the new startup item when you answer Block. Hostwatch flags the write and can pause the program that
  made it, and leaves removing the item to you.
- Paste Protection checks commands pasted into Terminal, a defence against fake "paste this to fix it" pages.
  Hostwatch doesn't look at the clipboard. It sees the commands once they run.
- It runs on macOS 10.15 and later.

**What Hostwatch adds.**

- What happened before and after: what dropped the program, what it read, where it connected.
- The network: a firewall, new domains, beacons and who reached this Mac.
- Protection for files and secrets.
- A new startup item counts as one step of a story, next to the download and the connection that came with it.

**Choose BlockBlock** if you want one quiet check on what installs itself to start again.
**Choose Hostwatch** if you want that as part of everything else a program does.

### When another tool is the better choice

- **Your Mac runs a macOS older than 26:** LuLu and BlockBlock run on macOS 10.15 and later.
- **You want only a firewall, with the finest control:** Little Snitch.
- **You want a free firewall and nothing more:** LuLu.
- **You want encrypted DNS:** Little Snitch has it, Hostwatch doesn't.
- **You manage many Macs from one place:** Hostwatch doesn't do that today. A fleet server is planned.

### Using them together

Nothing in Hostwatch gets in the way of the other three. Hostwatch's firewall is built on macOS's own packet
filter, and it can be set to Watch or Off while everything else in Hostwatch keeps working.

- **With LuLu or Little Snitch:** let one firewall ask. Two would ask you about the same connection twice. Set
  Hostwatch's firewall to Watch and it still records and judges every connection.
- **With BlockBlock:** both can run. You will hear about a new startup item from each.

We haven't tested every combination and version. If two tools disagree on your Mac, please
[tell us](https://github.com/everythings-gonna-be-alright/Hostwatch/issues).

### Sources

Read on 28 November 2026. Prices, versions and features change, so check the makers' pages before you decide.

- LuLu: <https://objective-see.org/products/lulu.html> and <https://github.com/objective-see/LuLu>
- Little Snitch: <https://www.obdev.at/products/littlesnitch/index.html> and
  <https://www.obdev.at/products/littlesnitch-mini/index.html>
- BlockBlock: <https://objective-see.org/products/blockblock.html> and <https://github.com/objective-see/BlockBlock>
- Hostwatch: [Features](03-features.md), [Privacy, security and limits](06-privacy-security-and-limits.md) and the
  [Threat model](08-threat-model.md), which lists where Hostwatch is weak.

LuLu and BlockBlock are projects of Objective-See. Little Snitch is a product of Objective Development Software
GmbH. Hostwatch isn't connected with either of them. Found a mistake here? Write to contact@hostwatch.tech and
it will be fixed.

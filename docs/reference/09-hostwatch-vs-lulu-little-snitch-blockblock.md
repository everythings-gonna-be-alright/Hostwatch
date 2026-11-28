## Hostwatch vs LuLu, Little Snitch and BlockBlock

Four Mac security tools with four different jobs. Here is what each one does, and when to pick it.

### In one line

- **Hostwatch:** intrusion detection for the whole Mac. It watches programs, files and connections, and has a
  firewall. Free.
- **LuLu:** a simple firewall for outgoing connections. Free and open source.
- **Little Snitch:** a full network monitor and firewall. 59 €.
- **BlockBlock:** warns you when something sets itself to start again. Free and open source.

### At a glance

| | Hostwatch | LuLu | Little Snitch | BlockBlock |
|---|---|---|---|---|
| Asks before a program connects out | Yes | Yes | Yes | – |
| Incoming connections | Yes | – | Yes | – |
| Protects files and secrets | Yes | – | – | – |
| Checks programs before they start | Yes | – | – | Optional |
| Notices new startup items | Yes | – | – | Yes |
| Joins events into attack stories | Yes | – | – | – |
| History you can play back | Yes | – | Traffic charts | – |
| Lists of known bad servers | Yes | Your own | Yes | – |
| Encrypted DNS | – | – | Yes | – |
| AI explanations | Yes | – | – | – |
| Price | Free | Free | 59 € | Free |
| Source code | Public | Open source | – | Open source |
| Runs on macOS | 26 or later | 10.15 or later | See its page | 10.15 or later |

A dash means the maker's page doesn't mention it. Read on 28 November 2026.

### Hostwatch vs LuLu

[LuLu](https://objective-see.org/products/lulu.html), from Objective-See, asks you when a program makes a new
outgoing connection. It is a firewall and nothing else.

- **Pick LuLu if**
  - you want only an outgoing firewall
  - your Mac runs a macOS older than 26
  - you want a classic open-source licence
- **Pick Hostwatch if**
  - you want to know what a program did, not only where it connected
  - you want your keys and passwords protected too
  - you want small signs joined into one story

### Hostwatch vs Little Snitch

[Little Snitch](https://www.obdev.at/products/littlesnitch/index.html), from Objective Development, asks when an
app connects, in or out, and shows it all on a world map. It has the most network features of the four.

- **Pick Little Snitch if**
  - the network is all you want to watch
  - you want encrypted DNS and a year of traffic charts
  - you want rules by port and protocol
- **Pick Hostwatch if**
  - you want launches, files and startup items watched too
  - you want a tool that learns what's normal and asks only about what's new
  - you want it free, with the source public

### Hostwatch vs BlockBlock

[BlockBlock](https://objective-see.org/products/blockblock.html), from Objective-See, alerts you when a program
sets itself to start again, and can remove it.

- **Pick BlockBlock if**
  - you want one quiet check on startup items
  - you want the new item removed for you
  - you want what you paste into Terminal checked
- **Pick Hostwatch if**
  - you want to see what led to it: the download, the files read, the connection
  - you want a firewall and file protection as well
  - you want a history you can search and play back

### Who Hostwatch is for

- **Developers** who install packages, extensions and tools written by strangers.
- **People who use AI coding agents** and want to see, and limit, what the agent runs.
- **Anyone with keys and passwords on a Mac**, which is what an infostealer comes for.
- **Small teams** who want the story of what happened, not only a blocked connection.

Hostwatch needs macOS 26 or later. More in [Features](03-features.md) and the [Threat model](08-threat-model.md),
which lists where Hostwatch is weak. Choosing for a company? See
[Hostwatch vs Jamf Protect, CrowdStrike Falcon and Microsoft Defender](10-hostwatch-vs-jamf-protect-crowdstrike-defender.md).

### Do you need more than one?

Usually not. Hostwatch has its own firewall and notices new startup items, so it does the main job of each of the
other three. Pick the one that fits and run that. If you do keep a second firewall, let only one of them ask, or
you'll answer every question twice.

### Sources

- [LuLu](https://objective-see.org/products/lulu.html) and [its source](https://github.com/objective-see/LuLu)
- [Little Snitch](https://www.obdev.at/products/littlesnitch/index.html) and
  [Little Snitch Mini](https://www.obdev.at/products/littlesnitch-mini/index.html)
- [BlockBlock](https://objective-see.org/products/blockblock.html) and
  [its source](https://github.com/objective-see/BlockBlock)

Prices and features change, so check the makers' pages before you decide. LuLu and BlockBlock are projects of
Objective-See, Little Snitch is a product of Objective Development Software GmbH, and Hostwatch isn't connected with
either. Found a mistake? Write to contact@hostwatch.tech.

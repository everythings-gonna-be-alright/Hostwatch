## Hostwatch vs Wazuh, osquery and Santa

Three free, open-source security tools that run on a Mac, each with a different idea of the job. Here is what each
one does, and when to pick it.

### In one line

- **Hostwatch:** intrusion detection that learns each Mac, asks you about what's new and tells the story of an
  attack. Free, with the source public.
- **Wazuh:** a security platform for a whole company. An agent on each machine reports to a Wazuh server.
- **osquery:** turns the operating system into a database you question in SQL.
- **Santa:** decides which programs may run on a Mac, and which may read protected files.

### At a glance

| | Hostwatch | Wazuh | osquery | Santa |
|---|---|---|---|---|
| Watches | Programs, files, connections | Files, logs, settings | What you ask for | Programs and files |
| Stops a program before it runs | Yes | – | – | Yes |
| Keeps other programs out of your files | Yes | – | – | Yes |
| Firewall for outgoing connections | Yes | – | – | – |
| Checks for known vulnerabilities | macOS itself | Yes | – | – |
| Compliance and settings checks | – | Yes | – | – |
| Answers your own questions in SQL | – | – | Yes | – |
| A server | Not needed | Needed | Optional | Optional |
| Price | Free | Free | Free | Free |
| Source code | Public | Open source | Open source | Open source |
| Runs on | Mac | Many systems | Mac, Linux, Windows | Mac |

A dash means the maker's page doesn't mention it. Read on 28 November 2026.

### Hostwatch vs Wazuh

[Wazuh](https://wazuh.com/) calls itself the open source security platform, with XDR and SIEM in one. On a Mac it
is an agent that reports to a Wazuh server, where the checking and the alerts happen.

- **Pick Wazuh if**
  - you look after many machines of different kinds
  - you need compliance checks and file integrity reports
  - you have someone to run its server
- **Pick Hostwatch if**
  - you want it working on a Mac in two minutes, with no server
  - you want to be asked before something new runs or connects
  - you want an attack told as one story

### Hostwatch vs osquery

[osquery](https://github.com/osquery/osquery) shows the operating system as a database. You write SQL to list
processes, open connections or startup items, by hand or on a schedule across many machines.

- **Pick osquery if**
  - you want to ask your own questions, in SQL
  - you already collect the answers in a fleet or logging tool
  - you want one tool for Mac, Linux and Windows
- **Pick Hostwatch if**
  - you want answers without writing queries
  - you want to be told when something is wrong
  - you want a tool that can stop a program or a connection

### Hostwatch vs Santa

[Santa](https://github.com/northpolesec/santa), from North Pole Security, is a binary and file access
authorization system for macOS. Rules name the programs that may run. In Lockdown mode only listed programs run.

- **Pick Santa if**
  - you want to say exactly which programs may run
  - you keep the rules for many Macs on a sync server
  - you want a classic open-source licence
- **Pick Hostwatch if**
  - you want the network watched too
  - you'd rather it learns what's normal than keep a list yourself
  - you want a history you can search and play back

### Questions and answers

#### Is Hostwatch a host intrusion detection system (HIDS) for Mac?

Yes. It watches programs, files and connections on the Mac itself, learns what is normal and flags what isn't.

#### Is Hostwatch an alternative to Wazuh on a single Mac?

Yes. Wazuh needs a server for its agents to report to. Hostwatch needs nothing else: you install it and it starts
watching. For many machines of different kinds, Wazuh is the better fit today.

#### Is Hostwatch open source?

Its source code is public under the PolyForm Shield licence. You may read, use, change and share it, at home and at
work. The licence doesn't allow building a competing product from it, so it isn't open source in the strict sense.

### Sources

- [Wazuh](https://wazuh.com/) and
  [its macOS agent](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-macos.html)
- [osquery](https://github.com/osquery/osquery)
- [Santa](https://github.com/northpolesec/santa)

Features change, so check the makers' pages before you decide. The names belong to their owners, and Hostwatch
isn't connected with any of them. Found a mistake? Write to contact@hostwatch.tech. More comparisons:
[LuLu, Little Snitch and BlockBlock](09-hostwatch-vs-lulu-little-snitch-blockblock.md) and
[Jamf Protect, CrowdStrike Falcon and Microsoft Defender](10-hostwatch-vs-jamf-protect-crowdstrike-defender.md).

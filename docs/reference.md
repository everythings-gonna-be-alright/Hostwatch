# Hostwatch reference

This reference covers every feature, setting and rule of Hostwatch, in the order you'll meet them.

For a short overview, see the [README](../README.md). The same text is on the website at
<https://hostwatch.tech/docs/>.

**Free for everyone, at home and at work.** The Mac app described here is free to use, change, fork and share, personally or in your
company, under the [PolyForm Shield License 1.0.0](https://polyformproject.org/licenses/shield/1.0.0/). The source code stays public. The one
thing the licence doesn't allow is using the code to make a product or service that competes with Hostwatch, such as your own server or cloud
edition of it. Versions up to 0.11.1 were released under the MIT license.

A paid edition will be only for companies: a server that watches a whole fleet of Macs from one place, and a hosted
cloud (SaaS) version.

## Chapters

1. **[Getting started](reference/01-getting-started.md)**: what you need, installing, the collector and the first hour.
2. **[Everyday use](reference/02-everyday-use.md)**: the HUD, the window, Running Now, resource use and Time Travel.
3. **[Features](reference/03-features.md)**: what Hostwatch does for you, in six groups: patterns, stories, network, stepping in, threats and AI.
4. **[Settings](reference/04-settings.md)**: every setting, pane by pane, with its default, plus exclusions and the activity history.
5. **[Advanced and command line](reference/05-advanced-and-command-line.md)**: command-line flags for exporting history and checking your Mac, how the collector watches, and updates.
6. **[Privacy, security and limits](reference/06-privacy-security-and-limits.md)**: what is stored and sent, how Hostwatch protects itself, reset, troubleshooting, limits.
7. **[For developers](reference/07-for-developers.md)**: building from source, testing, debug tools and demo mode.
8. **[Threat model and attack coverage](reference/08-threat-model.md)**: what Hostwatch defends against and what it doesn't, how it protects itself, and which MITRE ATT&CK techniques it sees.
9. **[Hostwatch vs LuLu, Little Snitch and BlockBlock](reference/09-hostwatch-vs-lulu-little-snitch-blockblock.md)**: what Hostwatch does, who it is for, and how it compares with three well-known Mac security tools.
10. **[Hostwatch vs Wazuh, osquery and Santa](reference/10-hostwatch-vs-wazuh-osquery-santa.md)**: how Hostwatch compares with three free, open-source security tools that run on a Mac.
11. **[Hostwatch vs Jamf Protect, CrowdStrike Falcon and Microsoft Defender](reference/11-hostwatch-vs-jamf-protect-crowdstrike-defender.md)**: how Hostwatch compares with the endpoint security tools companies buy for their Macs.
12. **[How to detect an infostealer on a Mac](reference/12-how-to-detect-an-infostealer-on-a-mac.md)**: the signs, what to check by hand, and how Hostwatch watches for one.
13. **[How to see what an npm package does on your Mac](reference/13-how-to-see-what-an-npm-package-does-on-your-mac.md)**: what to check before you install, and how to watch an install run.
14. **[How to monitor Claude Code on a Mac](reference/14-how-to-monitor-claude-code-on-a-mac.md)**: see what an AI coding agent did, and stop the commands you'd never allow.

## Questions and answers

### What is Hostwatch?

Hostwatch is a host intrusion detection system (HIDS) for macOS. It watches processes, files and network connections
through Apple's Endpoint Security, learns what is normal on your Mac and flags what isn't. Related events are joined
into stories, so an attack chain reads as one alert, not a thousand.

### Is Hostwatch free?

Yes. It is free for everyone, at home and at work, under the
[PolyForm Shield License 1.0.0](https://polyformproject.org/licenses/shield/1.0.0/). The source code is public. A paid
edition will come only for companies: a fleet server and a hosted cloud.

### Does Hostwatch send my data anywhere?

No. What it learns stays on your Mac, encrypted on disk. Only a few things leave it: what you choose to send to an AI,
a daily anonymous update check, the daily threat-list downloads and, while the firewall is on, a check that it still
lets connections through. The update check and the threat lists can be turned off.

### Which Macs does it run on?

macOS 26 or later, on Apple silicon and Intel. The app is signed and notarized by Apple. Setup takes about two
minutes: Full Disk Access and your administrator password once.

### Is Hostwatch an antivirus?

Not exactly. An antivirus looks for known malware files. Hostwatch watches behaviour: what runs, what it touches and
where it connects. It also checks public threat lists, so known malware is caught too, and new behaviour that no
signature knows yet is flagged.

### How is Hostwatch different from LuLu, Little Snitch and BlockBlock?

LuLu and Little Snitch are firewalls: they watch the network. BlockBlock watches what installs itself to start
again. Hostwatch is intrusion detection for the whole Mac: programs, files and connections, joined into stories,
with a firewall as one part of it. Little Snitch has more network features, such as encrypted DNS, and LuLu and
BlockBlock run on older macOS. The full comparison is in
[Hostwatch vs LuLu, Little Snitch and BlockBlock](reference/09-hostwatch-vs-lulu-little-snitch-blockblock.md).

### How is Hostwatch different from Jamf Protect, CrowdStrike Falcon and Microsoft Defender?

Those three are bought by a company, installed on every Mac by an administrator and watched from one console.
Hostwatch starts on a single Mac with nothing to set up: it learns that Mac, asks the person using it and tells an
attack as one story. It is free. A server for a whole fleet and a hosted cloud version are planned for companies.
The full comparison is in
[Hostwatch vs Jamf Protect, CrowdStrike Falcon and Microsoft Defender](reference/11-hostwatch-vs-jamf-protect-crowdstrike-defender.md).

### Can Hostwatch block connections?

Yes. Its firewall, built on macOS's own packet filter, can ask you before a program connects somewhere new, or block
it. It reads only which server a program asks for and never decrypts traffic.

### Does Hostwatch work with AI?

Yes, if you want it to. Apple's on-device model or Claude can explain events and suggest rules. An MCP server lets
Claude Code investigate your history, read-only and only with your permission. A Claude Code guard checks Claude
Code's commands before they run.

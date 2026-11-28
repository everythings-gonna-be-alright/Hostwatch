# 0022 What counts as evidence in a story

**Context.** In November 2026 all eight stories on a real Mac were false, seven of them Dangerous. Five were one
ThreatFox listing of Discord's gateway (a Cloudflare address), one was `169.254.169.254` (the cloud metadata service)
on ThreatFox, one an ad network on HaGeZi's list, and two were the AWS command-line tool signing in: Python reading
`~/.aws` and a `python3 -c` one-liner reading JSON. Every list match also carried an *Outbound connection* stage, so
"two stages" was met by one event, and a story came back every 40 minutes for the same listing.

**Decision.** Rules in `StoryEvidence` and `SharedNetworks`:
1. A threat list can't speak for local addresses (private, link-local, loopback, multicast) or a CDN's shared range
   (Cloudflare, Fastly): such entries are dropped when the lists load, and IP matches there are ignored. Domain
   matches still apply. An infected device on your network is caught by behaviour: port scans, new devices, and a
   large upload to a device that isn't yours (`NetworkMapPolicy.isLargeUpload`).
2. *Outbound connection* is context: shown, never counted in the score or toward firing.
3. A story needs two signs from two different events. A malware tracker's match (ThreatFox, Feodo, MalwareBazaar)
   still stands alone; a HaGeZi match needs another sign.
4. The same listing for the same program within a day joins the story already told, without a new alert.
5. Inline interpreter code is an encoded command only when it decodes, runs something or goes online. One command
   passed on through launchers (python3 → python3.9 → Python.app) is one step.
6. A tool reading its own sign-in (`aws` under `~/.aws`, `kubectl` under `~/.kube`, …) isn't credential access. The
   tool is the program or the script an interpreter runs, never one in a download or temp folder.

**Consequences.** A single event no longer makes a story, unless it is a malware tracker's match: an unsigned app run
from Downloads waits for what it does next. Next steps (not done): confidence levels per list and indicator type,
discounting steps the baseline says are routine, and a "Not a threat" that records a narrow exception.

# 0020 Firewall rules per app, next to the general ones

**Context.** The Network Firewall's rules were destination-first: a destination card with what any program meets
there, and program chips for the exceptions. What one app may do was spread over the Everywhere card's chips, a chip
on each destination, and blocks made from questions ("kubescape|tracker.example", listed apart in Your rules). There
was no one place to see or change what one app may reach.

**Decision.** The page has two sections built on the same principle. **General** is for every program: Everywhere
(Firewall decides or Block) and specific destinations (Allow or Block). **Apps** has one card per app (a bundle covers
every program inside it), with its own Everywhere (Firewall decides, Allow or Block) and its own destinations (Allow
or Block). An app's rules live only on its card: the program chips left General, and older chips, Everywhere lists
and question blocks are read into cards (`AppRulesList.migrated`, `FirewallMonitor.adoptPrograms`).

The first rule that decides wins (`FirewallPolicy.decide`):
1. Hostwatch itself is allowed.
2. The app's own destinations, the most specific one.
3. The app's Everywhere ▸ Block (your network too).
4. General's destinations.
5. The app's Everywhere ▸ Allow, never past a threat list without Allow Anyway.
6. General's Everywhere ▸ Block.
7. The local network, threat lists, patterns and risk, as before.

The more specific rule wins, but a broad Allow doesn't undo a specific Block: an app allowed everywhere still meets
General's Block of a domain, and an app blocked everywhere still reaches only what its own card allows.

A card is about a path, or about a name when only the name is known (the Network tab and older blocks name programs
as `displayProcessName` does). A change about one program goes to the card that already decides for it, else to a new
card for its outermost app bundle. A card made only by blocks goes when they do, one you added stays.

The sections were later named **Global rules** and **App rules**, Global rules tinted light blue (DESIGN.md).

**Consequences.** Always Block in a question adds the destination to the app's card, and Allow Anyway adds an Allow
(the card's own destinations come before threat lists, so it needs no list of its own). The separate Your rules list
is gone: a program's blocked connection patterns and destinations asked about again show on its card, a card made
for them when it has none. The patterns stay patterns, not destinations: they name one port and who did it
(`python3.12 via Claude Code`), and a destination would block more. Every card change
flushes the collector's remembered answers, so it is in effect at once.

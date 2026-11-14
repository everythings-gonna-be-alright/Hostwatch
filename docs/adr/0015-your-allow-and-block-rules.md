# 0015 Your own Allow and Block rules for folders and destinations

**Context.** Protection decided file access from its protected groups and pattern decisions, and the firewall from
domain blocks, threat lists and patterns. There was no way to say directly "block every program from this folder",
"let this one app into my keys" or "always let this tool reach this server". The user asked for it, for files and for
the network.

**Decision.** `AccessRule`: a folder or file, or a domain (its subdomains too) or an IP, for one program (an app's
bundle covers the programs inside it) or any program, Allow or Block. They are your decisions, so they come before
everything automatic: in ProtectionPolicy before the protected groups and any pattern status, in FirewallPolicy after
the local network and Hostwatch itself, before your domain blocks, threat lists and patterns. The most specific rule
wins (one program beats any program, a longer path or domain a shorter one), and Block wins a tie. Block acts in Ask
and Strict and shows as "would block" in Watch, like every other verdict. `AccessRules.refusal` refuses allowing any
program a whole area (your home or a folder right below it, the disk, /tmp and the like) or a protected place, the
line `isTooWide` holds for patterns (0003, 0013). Block may be as broad as you like, and allowing one program is your
call. The rules live in Protection's settings, the firewall reads the network ones through the app, and a change
makes it judge its list again and the collector forget its cached answers.

**Consequences.** An Allow rule for one program can open a secret to it, by your choice. Rules don't apply to launches
(a launch has patterns and the Launches mode), only to file access and connections.

**Update: places with exceptions.** File rules in a list of their own overlapped "Your folders and files": blocking
every program from a folder was already a protected folder with *Others: Block*, and two lists could contradict each
other. Files now have one model. Every place (a built-in group or yours) has `PlaceExceptions`: programs always
allowed and always blocked there, decided before the pattern's status, Block when a program is on both, the deepest
place first. "Allow any program" is no longer a choice for files: a place is protected or it isn't. Earlier file rules
are moved into the place that covers them (`moveFileRulesIntoPlaces`). Network rules stay `AccessRule`, unchanged.

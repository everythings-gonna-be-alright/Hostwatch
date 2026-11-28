# 0023 How sure a sign is: blocklist matches, everyday signs, Not a Threat

**Context.** ADR 0022 stopped the false stories that came from how evidence was counted. Three causes remained:
every threat-list match was proof, whether a malware tracker's exact domain or an address on HaGeZi's broad list;
what a program had done every day for weeks counted as much as something new; and *Always Ignore This Chain* muted
an origin and a set of stages, broad enough to hide a real attack that happened to look the same.

**Decision.**
1. A match is **Known malware** (proof, weight 8, a story by itself, Dangerous) only for a known malware file, a
   malware tracker's exact domain, or a Feodo Tracker address (curated botnet servers). HaGeZi matches and other
   address-only matches are **On a blocklist** (a sign, weight 3): they need a sign from another event, and don't
   overrule a pattern you marked Safe (`ThreatHit.confident`, `ActivityEvent.listedOnly`). The firewall blocks both.
2. A pattern seen for three days or more and at least ten times, not Suspicious or Dangerous and not sent back to you,
   is **everyday** (`SignatureStore.routine`). Its weaker signs are kept in the chain, marked, and not counted. Threat
   matches, swapped or unsigned binaries, autostart writes and quarantine removal always count
   (`StoryStage.discountable`).
3. **Not a Threat** replaces Always Ignore. It records each sign of the story by stage, program and destination,
   folder, command or parent (`StoryEvidence.exceptionKey`), and deletes the story. Old ignored chains still apply.
   Both are sent with rule suggestions as what you said isn't worth a story.

**Consequences.** Malware that runs unnoticed for three days becomes everyday for its weaker signs, so it is caught by
what can't become everyday (its autostart write, a threat match, a swapped binary) or by anything new it does. The
KNOWN BAD tag in lists still shows for both kinds of match.

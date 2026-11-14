# 0014 An AI may let a paused program go on once, never decide it

**Context.** In Ask mode an unknown launch or file access is paused and you are asked. Most are ordinary, and
answering each one is the cost of Ask. The user asked for the AI to evaluate them first and let the clearly safe ones
go on, with a visible notice while it looks, even with every window closed, and a way to turn it off.

**Decision.** `LiveAICheck` decides. A paused question is first checked by the fast model you chose (on-device or
your own server. Claude's command line is too slow for a program that waits), within 12 s of its 30 s pause. Only a
Safe with high confidence lets it go on, and only this time: the pattern stays New for your own decision, the same
pattern passes without another check for the rest of the session, and Found records it as allowed by AI. Never by AI
alone: what `aiSafeRefusal` refuses (shells, interpreters, run-anything tools, sensitive files, whole areas, 0013),
high-risk patterns, and anything Hostwatch itself found a warning sign in (0012). Those, any other verdict, and no
answer become your question, with what the AI said in it. While it checks, a glass notice at the top right says so
(a non-activating panel on every Space). After a Safe it says "allowed by AI" for a moment. Settings ▸ AI turns the
check off. It is on by default. Questions from Endpoint Security, when it comes, wait only seconds and aren't checked.

**Consequences.** A crafted command line can at most get one launch through, of a program that isn't a shell or an
interpreter and touches nothing sensitive, and the decision stays yours. The firewall's questions aren't checked.

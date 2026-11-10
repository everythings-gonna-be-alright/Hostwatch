# 0012 One triage prompt with checked warning signs, and a warning sign outranks a local model's Safe

**Context.** `Hostwatch --triage-benchmark` scored local models and Claude on 20 patterns you marked Safe plus 20
attack-shaped ones (two of them real patterns Claude had flagged). Every small model trusted an Apple signature on a
run-anything tool: osascript reading Messages, xattr removing the quarantine flag, bash writing a LaunchAgent. A
general rule in the instructions didn't stop it, and calibrating the prompt for developer tools made it worse
(Apple's model went from 2 to 5 false Safes while settling 70% instead of 15%).

**Decision.** The local model and Claude share one prompt (`TriagePrompt`): each program's signer and where it lives,
who started the pattern's example (only when that launch is still recorded), its history, and warning signs Hostwatch
checked itself, spelled out ("curl runs whatever it is told", "removes the quarantine flag"). Machine text is kept on
one line so it can't forge a fact. When Hostwatch found a warning sign, the router never takes a local model's Safe:
the pattern goes to Claude or stays for you.

**Consequences.** Measured on the same sample (November 2026, M3 Pro):

| Model | Your ordinary patterns settled | Attacks settled Safe |
|---|---|---|
| Apple on-device, first prompt | 15% | 2 of 20 |
| Apple on-device, this prompt and rule | 50% | 1 of 20 (a credential check since fixed) |
| Gemma 4 E4B (Ollama), this prompt and rule | 60% | 0 of 20 |
| Claude Haiku, this prompt | 90% | 0 of 20 |
| Claude Sonnet, this prompt | 85% | 0 of 20 |
| Claude Opus, this prompt | 75% | 0 of 20 |

A warning sign sends some ordinary patterns (a developer tool in a hidden folder) to Claude or to you instead of
settling them. The benchmark is the check for any change to the prompt or the signs: false Safe must not rise.

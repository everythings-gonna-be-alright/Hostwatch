# 0013 An AI may mark Safe a run-anything tool's plain read of an exact project folder

**Context.** No AI's Safe was taken for any pattern of a shell, an interpreter or another run-anything tool (0003).
Classify with AI ▸ Apply the Verdicts then left codesign reading a project's build folder New, one click each, though
the AI was right: reading files isn't running code. The rule existed because what such a tool runs can't be judged
from its name, and small models trusted an Apple signature on one too easily (0012).

**Decision.** `SignatureBuilder.aiSafeRefusal` says, in words, why no AI may mark a pattern Safe, or nil when one
may. Still refused: high-risk patterns, and what a run-anything tool launches, connects to or writes, touches in a
sensitive place, or reads outside your own project folders (a folder in your home below two literal components, not
Library, Downloads or a hidden top-level folder), and patterns that cover a whole area. Allowed: its plain read of an
exact folder in your projects. A refused Safe is kept as a suggestion with its reason, shown in Patterns ("AI suggests
Safe · yours: …") and in the live list with a Mark Safe button. Accepting it by hand is your decision and applies.

**Update: Apply the Verdicts is your decision.** Clicking one Mark Safe per refused pattern after choosing Apply the
Verdicts was not what the user wanted: the click on Apply is the decision. An explicit run with Apply applies every AI
answer, refused Safes included, recorded with source "you" and a note naming the AI and why it would normally be
yours, so precedence and the launch-time clean-up keep it. What runs without that click doesn't: automatic
classification and "accept AI suggestions without asking" still never apply a refused Safe, and a warning sign still
stops a local model's Safe (it goes to Claude or stays New).

**Consequences.** Broad trust stays refused (no Safe rule for a shell, 0003), and the launch-time reset of AI Safes
on run-anything tools skips only these reads. `--triage-benchmark` counts the app's rules: false Safe must not rise.

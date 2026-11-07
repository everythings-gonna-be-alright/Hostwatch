# 0003 Interpreters, shells and LOLBins are never trusted broadly

**Context.** `python`, `bash`, `node`, `osascript`, `curl` do whatever a script tells them. "Everything python
does is Safe" trusts every future script, which is exactly how a compromise hides.

**Decision.** `SignatureBuilder.isLolbin` names them. Their launch patterns include the script or the command line
(`bash → perl ~/bin/build.pl`, `zsh → curl -s https://…`); their file patterns are the exact folder (never `/**`);
their connections name the domain, never `internet`. A whole-process Safe rule for them is refused
(`canTrustWholeProcess` is false), a learned Safe rule that would cover them broadly is rejected, and
`dropInterpreterTrust()` undoes blanket trust from earlier versions at launch. Only the user's own per-pattern
decisions stand.

**Consequences.** Shells produce more patterns than apps do; that is accepted. The fewer-patterns rules exempt
interpreters from project and scratch-tree collapsing (Homebrew formula trees and plain system tools are the two
deliberate exceptions: loading a library or starting `awk` says nothing about the script).

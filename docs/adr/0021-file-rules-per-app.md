# 0021 File rules per app, next to the general ones

**Context.** Protected places were place-first, as destinations were before ADR 0020: a card with what any other
program meets there, and program chips for the exceptions. What one app may open was spread over every card's chips,
and a folder could only be closed to one app by protecting it for every program first.

**Decision.** The Protected Files and Folders page has the firewall's two sections. **General** is for every
program: the built-in places and your folders and files, each with the programs expected there and Ask me or Block
for any other. **Apps** has one card per app (a bundle covers every program inside it) with **Every protected place**
(Protection decides, Allow or Block) and its own places, each Allow or Block: a built-in place, matched by the
pattern's label or its folders, or any folder or file. The chips left General, and older chips and per-program file
rules are read into the cards (`AppFileRulesList.migrated`, `ProtectionMonitor.moveFileRulesIntoPlaces`).

The first rule that decides wins (`ProtectionPolicy.decideFileAccess`):
1. Hostwatch itself is allowed.
2. The app's own places, the most specific one. A built-in place counts as deep as its folder, so SSH keys win over
   a home-wide rule. Autostart is about changes only, as in General.
3. The app's Every protected place ▸ Block or Allow, only where General protects.
4. General: your decision on the pattern, the programs expected there, the place's choice.

Every protected place means the places General protects, not every file: an app blocked from every file couldn't
run. A place on an app's card needs no protection in General, so one app can be kept out of a folder others use.

**The collector.** It still gets places with lists (`HoldPlace`): an app allowed or blocked in a whole place is on
its lists and answered without the app. An app with rules of its own inside a place isn't listed there, so the app
decides. An app's own folders and files are held as places of their own, keeping the lists of the place around them,
or with `othersPass` when General doesn't protect them, so other programs aren't held for nothing
(`FileHoldCards`).

**Consequences.** Every card change is sent to the collector at once. Launches stay as they are: a launch has no
place to be about.

# 0024 Package guard: know the bad packages, stop their scripts, contain the rest

**Status.** Accepted. Layers 1, 2 and 3 are built (Protection ▸ Packages). Layer 4 is next.

## Context

`npm install` and its cousins run strangers' code as you: install scripts run at once, and the package's own code runs
later when you build, test or start the project. Recent attacks show three shapes, and each needs a different defence.

| Attack | Shape | What would have stopped it |
|---|---|---|
| nx "s1ngularity" (Aug 2025) | A `postinstall` script ran Claude, Gemini and Q CLIs to hunt for secrets and posted them to GitHub | Contain install scripts: no secrets, no AI CLIs, registry only |
| Shai-Hulud worm (Sep 2025) | A `postinstall` script ran a secret scanner, read npm and GitHub tokens, and republished itself | The same containment, then the malicious-package list within hours |
| chalk and debug (Sep 2025) | No install script. Phished maintainer, payload inside the package's runtime code | Only the list, then a scan of every lockfile on the Mac |
| Typosquats, hallucinated names | A name one letter off a popular one, or a name an AI agent made up and an attacker registered | Name checks before the install, mostly for AI agents |

A list alone is always hours late. Behaviour alone misses code that waits for runtime. So the guard is layered.

What Hostwatch already has, and the guard reuses:
- **Endpoint Security holds** (`ESAuthClient`, `AgentGuard`): a launch or a protected open can be denied before it
  happens, within macOS's deadline of a few seconds. Only local lookups fit in that time.
- **Threat lists** (`ThreatIntel`): daily downloads, retro checks when a list changes.
- **The Claude Code guard** (`ClaudeGuard`, `CommandGuard`): sees an agent's command before it runs.
- **Protected places and the firewall per app** (0020, 0021): file opens and connections decided per program.
- **Stories and Watch Closely**: chains of signs and a recorded process tree.

## Decision (proposed)

Four layers. Each works without the ones after it.

### 1. Know: a local list of malicious packages

- Source: the malicious-package entries (`MAL-…`) of OSV.dev, fed by the OpenSSF malicious-packages project, for npm,
  PyPI, Go, crates.io, RubyGems, NuGet and Packagist. An ecosystem's list is downloaded only once a project uses it:
  the bulk export once (`all.zip`, read in place by `ZipReader`), then daily only the records OSV's
  `modified_id.csv` names as changed since, read until the last known change. More than 2,000 changes: the bulk again.
- Kept as a sealed text index per ecosystem, `name<TAB>id<TAB>versions`, and read line by line for the names a scan
  wants, so it never sits in memory. Lookups are exact name and version, so a match is proof, not a sign (unlike a
  domain blocklist, 0023). Names compare as the registry does: PyPI ignores case and `-_.`, npm doesn't (its old
  capitalised `Orchestrator` is listed, gulp's `orchestrator` isn't: the first real scan matched it wrongly).
- Measured on one Mac (28 Nov 2026): npm's export is 222 MB and 233,000 files, of which 224,700 malicious entries,
  209,000 of them "every version". Its index is 9 MB. Downloaded and indexed in 14 s, PyPI's 12,100 in 3 s. 252
  projects (274 lockfiles, 54,000 packages) found by Spotlight in 0.3 s and checked in 0.6 s. Peak memory 700 MB
  while the npm export is indexed, once.
- Privacy: it is a threat-list download. Nothing about your packages leaves the Mac. Per-package lookups online
  (OSV query API, Socket, deps.dev) are rejected for that reason.

### 2. Find: what is already installed

- **Lockfile scan**: `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `requirements*.txt`, `uv.lock`,
  `poetry.lock`, `Pipfile.lock`, `go.sum`, `Cargo.lock`, `Gemfile.lock`. Projects are found from history (folders
  where a package manager ran), plus any folder you add.
- Runs when a lockfile changes, when you ask (Scan Projects), and again for every project whenever the list
  gains entries. That last one is what catches a chalk or debug: the bad version is already on disk when it is listed.
- Also checks what lands on disk during an install: `node_modules/<name>/package.json`, `site-packages/*.dist-info`,
  the Go module cache, `~/.cargo/registry`.
- A match is a **Dangerous** story with the project, the package, the version and who brought it in (direct or
  through which dependency), and a fix: the safe version, or remove it.

### 3. Stop: deny what is known bad, before it runs

Built as below, with these choices (28 Nov 2026):
- **The collector decides alone.** The app turns its indexes into `ListedPackages`: per ecosystem, the sorted 64-bit
  FNV-1a hashes of names listed for every version, plus the few records that name versions. On one Mac: 241,000
  names, 3.4 MB on the socket once (and on every reconnect), built in 0.35 s, 0.13 µs a lookup. The collector can't
  read the vault, and a round trip to the app per script would let a busy app's silence through (`quickAnswer`).
  A hash collision would stop an unlisted package: at this size, about one chance in 10^14 per lookup.
- **What is an install**: `InstallContext`, pure. Scripts by environment (`npm_lifecycle_event` among preinstall,
  install, postinstall, prepare, with `npm_package_name`; `CARGO_PKG_NAME` only for a `build-script-*`), pip's build
  backend by `PKG-INFO` in its working folder, a gem by its `/gems/<name>-<version>/ext` folder. Named installs by
  the manager among the first words and its verb. The environment is read only while packages are guarded, and a
  variable is copied only when its first byte could start a wanted name.
- **Ask and Strict hold launches for this even when Launches is Off or Watch**: the exec client runs, and anything
  that isn't a listed install is answered at once by the existing local rule. Watch holds nothing: the lockfile
  scan already tells you, and a hold only to watch would put every launch through the client for nothing.
- **Unknown versions**: `npm install x` names no version. Only an every-version record covers it (209,000 of npm's
  225,000 records are).
- **Quarantine is npm only**: a project's `node_modules/<name>` and one level of nesting, when the version in its
  `package.json` matches. PyPI, Go and Cargo keep packages in shared places (site-packages, module caches), where
  moving one breaks other projects: the story gives the fix. Quarantined folders are your files, moved as they were,
  not Hostwatch data: they are not sealed.

- **Install scripts.** Package managers start each script as a new process: npm, pnpm, yarn and bun run
  `sh -c <script>` with `npm_package_name`, `npm_package_version` and `npm_lifecycle_event` in its environment, pip
  runs a build backend inside the unpacked package, Cargo runs `build-script-build` from a path naming the crate,
  RubyGems runs `extconf.rb`. The AUTH_EXEC hold reads the name and version (environment, or the working folder's
  manifest) and checks the index. Listed: denied, the install fails, a notification says why. A local lookup fits the
  deadline with room to spare.
- **Named installs.** `npm install x`, `pip install x`, `go get x`, `cargo add x` with a listed name are denied at
  launch the same way. This covers only the names on the command line. Dependencies are covered by the script hold
  and the arrival check.
- **Arrived, not run yet** (no install script, like chalk): the story gives the fix (the safe version, or remove it).
  Only **Strict** moves the package folder to Hostwatch's quarantine by itself, and the story says how to restore it.
  Moving files in your project without asking is too big a step for the default.
- **AI agents**: the Claude Code guard runs the same checks on the command, plus the name checks of layer 4, and
  blocks or asks before the command exists.

### 4. Contain: install scripts get less than you have

The part that works on day zero, before any list knows the package. While a package manager runs, every process its
scripts start is an **install script**. Install scripts:

- can't open protected places (SSH keys, cloud credentials, `.npmrc`, `.pypirc`, browser data, keychains). The
  package manager itself still can: it needs `.npmrc` to log in to your registry.
- can reach only the registries of that ecosystem and the hosts your own rules allow. Native builds that download
  binaries (`node-gyp`, `prebuild-install`, Electron, Puppeteer) are the known exceptions, kept as a short list of
  their hosts.
- can't add login items, launch agents or shell startup lines.
- can't start AI CLIs (`claude`, `gemini`, `q`, `codex`, `copilot`) or secret scanners (`trufflehog`, `gitleaks`).
- are recorded like Watch Closely. When an install did anything unusual, the summary is a story: "npm install in
  my-app: 3 scripts ran, one tried to read ~/.aws and was stopped."

Name checks for things that aren't known bad, used as signs, never as proof:
- **Lookalike name**: one edit from a popular package of the same ecosystem (a bundled top list, offline).
- **New package**: published in the last few days. Needs the registry, so it is an **opt-in** setting: when on, it
  asks only the registry the install was going to contact anyway, for the names on the command line. It adds a line
  to what leaves the Mac (06-privacy, CLAUDE.md).
- Lookalike or new, plus an install script: asked first for AI agents, a story sign for you.

### Modes and place in the app

A new area in Protection, **Packages**, with the same modes as the others (0011):

| Mode | Known bad | Install scripts | Arrived bad package |
|---|---|---|---|
| Watch | Story | Recorded, what would be stopped is listed | Story |
| Ask (default) | Denied | Contained | Story with the fix |
| Strict | Denied | Contained, lookalikes denied | Quarantined |

Watch first, as with files and launches (0011): it rehearses containment on real installs and shows what would have
broken before anything is enforced.

Code: `Detection/PackageIntel.swift` (index and download), `Detection/Lockfiles.swift` (parsers, one function per
format), `Detection/InstallContext.swift` (which processes are install scripts and of which package),
`Protection` gains the policy, `Views/PackagesView.swift` the page. Parsers and decisions are pure functions over
values, tested with fixtures in `tests/corpus/packages/`.

## Consequences

- Known-bad packages with install scripts can't run them. Known-bad packages without scripts are found on disk,
  quickly when the list updates, and quarantined on request.
- Day-zero install scripts lose the two things attacks wanted: secrets and a way out.
- **Limits, said plainly:**
  - Runtime code that isn't listed yet runs with your rights when you build or start the project. Stories and the
    firewall are the backstop there.
  - Secrets in environment variables reach install scripts. Hostwatch can't strip a process's environment.
  - Go modules have no install scripts and few listed malicious modules, so for Go this is mostly the list plus
    runtime behaviour.
  - Containment depends on Endpoint Security. With the eslogger fallback it can only stop a script after it starts,
    as Protection does today.
  - Native builds will need exceptions. Watch mode is there to find them before they break anyone's install.
- Cost: an index on disk, one lookup per install-script launch, lockfile parsing when a lockfile changes.

## Settled

1. Quarantine inside a project happens only in Strict. Ask gives the fix.
2. Containment covers `npx`, `uvx`, `pipx run`, `pnpm dlx`, `yarn dlx` and `bunx` too: they run a package at once.
3. The registry age check comes as an opt-in setting, with layer 4.

Layer 3 needs the lists in the collector, for lookups within the Endpoint Security deadline: name hashes, as above.

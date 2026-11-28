# Contributing to Hostwatch

Thank you for wanting to help. Hostwatch is a security tool with a part that runs as root, so the rules here are
stricter than in most projects. They are short, and the test run checks most of them for you.

## In short

1. Open an issue before anything bigger than a small fix.
2. Work on a branch, one change per branch.
3. Add or update tests, and run `./scripts/test.sh` before you send it.
4. Update the reference and the changelog when behaviour changes.
5. Keep personal data out: no real names, hosts, paths or secrets.
6. Open a pull request that says what changed and why.

## What to send, and where

| You have | Do this |
|---|---|
| A security flaw | Report it privately, never in an issue. See [SECURITY.md](SECURITY.md). |
| A bug | Open an issue with your Hostwatch version (*Hostwatch ▸ About*), your macOS version and the steps. |
| A false alert, or an attack Hostwatch missed | Open an issue. These are the most useful reports. See below. |
| A small fix (a typo, a wrong word, a clear bug) | Send a pull request. |
| A new feature, a new detection, or anything you can see in the app | Open an issue first, so we agree on the shape before you write it. |

Mask secrets and personal details in anything you paste. Dummy values are enough.

### False alerts and missed attacks

`Hostwatch --story-report` prints the last stories as text. A false story, or a chain that should have fired and
didn't, belongs in `tests/corpus/stories.jsonl`, anonymised: `$HOME` for the home folder, made-up names and hosts.
The test run replays that file, so the false story can't come back and the attack can't go quiet again.

## Set up

You need macOS 26 and the Xcode 26 Command Line Tools.

```bash
git clone https://github.com/everythings-gonna-be-alright/Hostwatch.git
cd Hostwatch
git config core.hooksPath scripts/hooks    # the merge gate
swift build
./scripts/test.sh                          # everything, about 30 seconds
```

[For developers](docs/reference/07-for-developers.md) has the rest: signing, running the collector by hand, the
debug tools and the demo build. Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) first, it is the map.

## Making a change

- **Branch from `main`.** One change per branch. Nothing is committed on `main` directly.
- **Tests come with the change.** While you work, run `./scripts/test.sh --changed` or
  `./scripts/test.sh --only 'Name'`. Before you send it, run `./scripts/test.sh`. Tests use scratch folders and
  in-memory stores, never real data.
- **Speed and size are tested too.** The performance budget fails a change that writes much more, keeps much more
  memory or uses twice the CPU. If your change costs more on purpose, record a new baseline with
  `HOSTWATCH_PERF_RECORD=1 ./scripts/test.sh`, commit it and say why in the pull request.
- **Measure when the change is about volume or speed.** Give the numbers before and after, on real data.
- **Commit messages** say what changed and why, in plain words.

### Docs and changelog

- **The reference is the spec.** When behaviour changes, update the chapter in `docs/reference/`, then run
  `python3 scripts/build-docs.py` and commit what it writes. Never edit `docs/docs/*.html`, `docs/sitemap.xml` or
  `docs/llms*.txt` by hand, they are generated.
- **A decision gets an ADR.** If you chose between real alternatives, add a short file to `docs/adr/`. Long
  explanations belong there, not in code comments.
- **The changelog is for people.** Add one tight line under "Unreleased" in `CHANGELOG.md`, in New, Faster and
  lighter, or Fixes.

## Code rules

The test run fails on most of these.

- **Swift 6 language mode, and no new warnings.** A `nonisolated(unsafe)` or `@unchecked Sendable` says on its line
  why it is safe.
- **Command Line Tools, not Xcode.** SwiftUI's `@State` macro isn't available. Use a small `ObservableObject`.
- **No new dependencies.** Hostwatch has none. Ask in an issue before adding one.
- **One folder per area** under `src/hostwatch/`, and one concept per file, named after its main type. Keep files
  under about 700 lines. SwiftUI lives in `Views/` only.
- **Decisions are pure functions over values**, testable without a store, with no singletons inside.
- **Comments say why**, and what would break. Not what the line does.
- **Anything you can see follows [docs/DESIGN.md](docs/DESIGN.md).** Read it before you add or change a view, and
  reuse the shared components before writing new ones.
- **Words are plain.** No jargon and no semicolons in anything a user reads: the app, the docs, the website. The
  product is spelled "Hostwatch".

## What a change must never break

These are the promises Hostwatch makes. A pull request that weakens one needs an issue and an ADR first.

- **Interpreters, shells and system tools that run any code are never trusted broadly.** Their patterns name the
  script, the exact folder or the destination.
- **No file pattern covers a whole area**, such as all of the home folder or all of `/tmp`.
- **Who decided wins in this order:** you, your rules, an AI, automatic. Code that changes a status respects it.
- **Risk only goes up by itself.** Nothing lowers it automatically.
- **Secrets are masked** before anything reaches history, a prompt or the MCP server.
- **Nothing new leaves the Mac quietly.** A new network call needs a setting or an ADR, and a line in the
  [privacy chapter](docs/reference/06-privacy-security-and-limits.md).
- **Every data file goes through `Vault`.** Never read or write a Hostwatch data file directly.
- **History is append-only and crash-safe.**
- **A pattern's text is its identity.** Changing how a pattern is built needs a way to move old decisions over.

The full list, with the reasons, is in [CLAUDE.md](CLAUDE.md) under "Invariants that bite".

## The pull request

Say what changed, why, and how you tested it. For a visible change, add a screenshot from the demo build
(`DEMO=1 ./scripts/build-app.sh`), which shows made-up data only.

Before you send it, check that nothing personal is in the code, the tests, the corpus or the screenshots: no real
names, email addresses, host names, private addresses, home folder paths or secrets.

Hostwatch has one maintainer, so a reply can take a few days. A pull request is merged only when the full test run
passes on the merged result.

### Written with an AI assistant

That is welcome, and much of Hostwatch is built this way. You are responsible for what you send: read it,
understand it and test it. [CLAUDE.md](CLAUDE.md) holds the notes an assistant needs.

## Licence of your contribution

Hostwatch is source available under the [PolyForm Shield License 1.0.0](LICENSE), and paid editions for companies,
a server and a cloud version, are planned. So that one code base can serve all of them, by sending a contribution
you agree that:

- you wrote it, or you have the right to send it
- it is released under the PolyForm Shield License 1.0.0 with the rest of Hostwatch
- you also give the maintainer of Hostwatch a lasting, worldwide, free licence to use, change and share it as
  part of Hostwatch and its other editions, including paid ones and under other licence terms

You keep the copyright in what you wrote. If your employer owns your work, make sure they agree.

## Being decent

Be kind and be specific. Talk about the code, not the person. Questions are welcome at contact@hostwatch.tech.

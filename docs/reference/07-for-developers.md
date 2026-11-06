## For developers

### Build & run

```bash
./scripts/build-app.sh
open dist/Hostwatch.app      # prompts for an admin password to start the collector
```

### Test

```bash
./scripts/test.sh
```

This runs every automated test, in about 10 s. There are two suites.

**Swift** (`tests/swift`, Swift Testing, `swift test`) covers:

- pattern grouping and risk rules
- Stories: attack chains must fire as Dangerous, and everyday dev work and known false positives must stay quiet
- code signing on real unsigned / ad-hoc / quarantined / replaced binaries made in a temp folder
- new-domain baseline and badges
- beaconing maths and rules, and raw-IP rules
- Homebrew tools not trusted by signature, on a real Homebrew binary when one is installed

Tests use in-memory engines and a scratch signing database, so they never touch your data.

**Collector** (`tests/swift/AgentTests.swift`) covers:

- DNS answers, pktap SYN and `nettop` parsing, with real lines captured on a Mac
- destination inference
- secret masking and exclusions
- JSON output identical to the former Python collector
- busiest processes and Hostwatch's own activity
- the socket's permissions and peer checks
- that helpers get a pipe as stdin and no inherited files

**Local MRs are gated.** `scripts/hooks/pre-merge-commit` runs the tests on the merged result and refuses the merge
commit if anything fails.

- **Enable it:** `git config core.hooksPath scripts/hooks`. It is already set in this repo. Run it again after a
  fresh clone.
- **Emergency bypass:** `git merge --no-verify`.

Manual check with the collector running:

```bash
/usr/bin/id                          # ▶ process
curl -sI https://example.com >/dev/null   # ▶ process + 🌐 connection
cat ~/.zshrc >/dev/null              # 📄 file
```

### Demo mode (screenshots)

Demo mode fills the app with made-up activity, for screenshots and the website. It exists only in the demo build. The
normal build, and every release, has no demo code at all.

**Build it:** `DEMO=1 ./scripts/build-app.sh` makes `dist/Hostwatch Demo.app`. It uses the Swift flag `-DDEMO`, its
own bundle id `local.hostwatch.demo` and its own build folder `.build-demo`.

**Run it:**
`"Hostwatch Demo.app/Contents/MacOS/Hostwatch" --demo <folder> [hud|events|live|running|patterns|stories|network|firewall|watch]`

- **What it shows:** the activity of a made-up user (`/Users/alex`). That is everyday work plus a fake download that
  removes its quarantine, reads cookies and the keychain, adds a launch agent and calls home.
- **Scene:** it opens the scene you asked for.
- **`live`:** keeps adding events about once a second. This is for the website's background video, recorded with
  `screencapture -v` and encoded with ffmpeg.
- **Isolation:** everything it keeps goes to `<folder>`. It never connects to the collector and starts nothing as
  root.
- **Tests:** `./scripts/test.sh` also runs the demo tests against the demo build.

### Prototype notes

Apple documents `eslogger` as a tool for exploring and prototyping, not an application API. Its JSON may change
without notice.

For a distributable tool, replace the collector with:

- a native Endpoint Security system extension (`com.apple.developer.endpoint-security.client` entitlement)
- a Network Extension for connections

### Production architecture

For production, implement a signed Endpoint Security system extension. Use XPC or a protected local IPC channel to
communicate with this HUD.

The system extension should:

- subscribe only to the event types required
- process callbacks quickly
- avoid blocking ES callbacks on UI or disk I/O

Apple's ES entitlement must be approved for the developer team. Do not disable SIP as a routine installation
workaround.

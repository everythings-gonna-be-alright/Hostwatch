## Privacy, security and limits

### Files Hostwatch writes

Hostwatch keeps what it learns on your Mac. Nothing is sent anywhere, with three exceptions:

- what you send to an AI you chose
- a daily anonymous update check, if it is on
- the daily threat-list downloads, if they are on

Here is where everything lives:

| Where | What |
|-------|------|
| `~/Library/Application Support/Hostwatch/` | patterns (`signatures-v2.json`), stories, domains, rules, signing facts, `collector.token` (0600), `claude-guard.json`, `firewall-watch.json` |
| `…/Hostwatch/intel/` | threat lists, `state.json`, `hits.json` |
| `…/Hostwatch/ask-claude/` | the empty working folder Claude runs in |
| `/var/log/hostwatch-collector.log` | the collector service's log (root-owned, readable) |
| `~/Library/Logs/Hostwatch/` | `agent.log` (an admin-prompted collector) and the `History` folder (by default): `activity-*` events, `metrics-*` resource samples, `processes-*` process lists |
| `~/Library/Preferences/tech.hostwatch.app.plist` | settings and exclusions (plain) |
| `…/Hostwatch/vault.key` | the data key, wrapped by the Secure Enclave (see Encryption at rest) |

### Encryption at rest

Everything Hostwatch keeps is encrypted on disk (AES-256-GCM): patterns and their journal, stories, domains, AI
sessions, rules, signing facts, the firewall and Claude Code guard logs, the MCP token hash and access log, and the
whole activity history (each compressed block sealed on its own, day files line by line). The point is *where the
key lives*: another process running as you, an AI agent included, can't fetch it silently.

- **Keychain** (today): the data key is a login-keychain item whose access list names only Hostwatch's code. Any
  other process, `security` from a terminal included, gets macOS's keychain dialog and needs your password.
- **Secure Enclave** (when the build can use it): the data key is wrapped by a key that never leaves the Enclave.
  The wrapped blob is `vault.key` in the support folder, useless on another Mac or to anything but Hostwatch's own
  signed code, and the keychain item goes. Enclave keys need an entitlement that only a provisioned build carries, so
  released builds use the keychain until that is in place. The code moves the key over by itself when it can.
- **What it looks like:** a sealed file starts with `HWV1`, a sealed line with `HWV1:`. Files from earlier versions
  are plain and still read. They're rewritten sealed the next time they're saved (history blocks when their file
  is finished or scrubbed).
- **Reading it yourself:** `zcat` and `zgrep` no longer work on the history files. Use
  `Hostwatch --export-history [file or folder]`, which prints plain JSON lines through the key, and pipe it to `jq`.
- **Settings ▸ General ▸ Permissions ▸ Data on disk** shows the state and where the key is.
- **If the key is lost** (the keychain item removed, the Enclave key gone): the sealed files can't be read. Hostwatch
  says so in Settings, starts a new key and begins again. A backup of the files is only useful together with your
  keychain, which Time Machine includes. The collector (root) writes none of these files.

### Security notes

Part of Hostwatch runs as root, and it sees command lines that can contain passwords. These notes explain how it keeps
that power and that data from being misused.

**Who runs with which rights**

- **The HUD:** runs as the logged-in user. Only the collector is elevated.
- **The collector:** it is the app's own binary, run as root (`--collector-launcher … --collector`). Keep the app
  somewhere only you can write to, for example `/Applications`. Otherwise anything that can modify it gains root on
  the next start.
- **Hardened runtime:** the app is signed with `--options runtime`. Ad-hoc builds are too, and `build-app.sh` refuses
  to finish without it.
  - macOS then ignores `DYLD_INSERT_LIBRARIES` and similar variables, and loads only Apple-signed libraries into
    Hostwatch.
  - So code can't be injected into the app, the root collector or the MCP server.
  - Verified: a test library injected into a build without the flag ran. With the flag, it doesn't.

**The collector channel**

The app and the collector talk over a Unix socket, `/var/run/hostwatch/collector.sock`, never over a network port. A
Unix socket is a local file-like connection point that only processes on this Mac can reach.

- **The folder:** root creates it with mode 0755. The collector refuses a folder it doesn't own, so no other process
  can create or replace the socket. A leftover socket is replaced. Any other file is not.
- **The socket:** it belongs to the client user, with mode 0600. Other users cannot connect.
- **Every connection is checked:** the collector asks the kernel who is connecting (peer credentials,
  `LOCAL_PEERPID` and `LOCAL_PEERCRED`).
  - When the app launched it, only that app process and user are accepted.
  - As a background service, only the user logged in at the Mac is accepted (the socket follows a user switch).
  - When started by hand, only the `sudo` user is accepted.
  - **And only Hostwatch's own code.** On the real socket the collector also asks the kernel for the peer's audit
    token and checks, through macOS code signing, that the process satisfies the collector's own designated
    requirement: the same Team ID and bundle identifier (or, for an ad-hoc build, the very same binary). Being the
    right user isn't enough: another program of yours can't read the stream, answer firewall questions or change
    exclusions. The audit token can't be fooled by a reused pid.
  - Rejections are logged with the process path.
- **A service with no client does nothing.** When the app isn't connected for 15 seconds, the background service
  stops `eslogger` and packet capture, turns the firewall off (nothing is held with nobody to ask) and waits. The
  next connection starts them again. It also notices when an update replaced the app and restarts itself as the
  new version.
- **The app checks too:** it connects only when the socket is a socket owned by you, mode 0600, not a link, and in a
  root-owned folder that nobody else can write. Otherwise it refuses and the HUD says why. So a fake collector run by
  an ordinary user cannot feed it data.
- **Shutdown:** the shutdown command also needs the per-launch token from `collector.token` (mode 0600).
- **Client config:** config lines sent by clients are only used as filters. The agent runs no commands based on them.

**Secrets in command lines**

New-process events carry the **command line**. It is forwarded to the app, shown, given to Claude and **written to
history**. So Hostwatch masks secrets first, with one rule set (`Secrets`). It masks:

- Authorization and API-key headers, and cookies
- `name=value` and `--name value` for password, token, secret, API/access/private key, auth, session and signature,
  including `GITHUB_TOKEN=`, `?token=` and `--password`
- URL credentials: `user:pass@` and `token@`
- `curl -u`, `security … -w`, `sshpass -p` and `mysql -p…`
- known token formats: `ghp_`, `github_pat_`, `glpat-`, `xox…`, `sk-`, `AKIA`/`ASIA`, `AIza`, `npm_`, `hf_`
- JWTs and private key blocks

History shows a masked secret as `***`. AI prompts show `[REDACTED]`.

- **Nothing unmasked goes to an AI:** every prompt is masked again right before it's sent, whatever built it. This
  covers Ask AI, pattern suggestions, rule proposals and domain details, on-device or Claude. MCP output is masked
  too.
- **Older history is masked too:** once, in the background, finished history files are re-masked. Compressed ones are
  rewritten with a new index. Every file is also masked again before it's compressed.
- **Limits:** a secret in a shape no rule knows can still slip through. Environment variables are never forwarded.

**What the collector can and can't do**

- **Network:** to find connections, the collector runs `tcpdump` as root. It reads only DNS answers and TCP SYN
  headers, no payloads. It also reads macOS's connection statistics, read-only. Nothing is captured to disk.
- **Processes and files:** `eslogger` is a notify-only observer. It cannot deny execution.

### Reset Hostwatch

Reset lets you start over as on the first launch. Open **Settings ▸ General ▸ Reset Hostwatch…** and choose what to
erase:

- **Patterns, decisions and baseline:** `~/Library/Application Support/Hostwatch` and the baseline's state. That
  folder holds patterns, stories, domains, your rules, signing facts and the MCP token.
- **Settings:** HUD, window, detection, AI, exclusions and history options (`tech.hostwatch.app` defaults).
- **Event history and logs:** `~/Library/Logs/Hostwatch`. In a custom history folder, only Hostwatch's `activity-*`,
  `metrics-*` and `processes-*` files are erased.

Reset also unregisters the collector service (your password), so the next launch starts as on a fresh install.

Then Hostwatch:

1. stops the collector
2. removes the settings
3. exits
4. lets a small helper delete the files once the app has quit, so nothing is saved back
5. opens again

Full Disk Access stays granted.

### Troubleshooting

| What you see | What to do |
|--------------|------------|
| **Nothing appears / "Collector off"** | Start it from the menu bar icon. Check *Help ▸ Collector Log*. |
| **`ERR_NOT_PERMITTED` in the log** | Full Disk Access is missing (see [Built-in collector](01-getting-started.md#built-in-collector)). Ad-hoc builds need the grant redone after every rebuild. |
| **The firewall turned itself to Watch** | Its web check through the relay failed twice. The status line in Settings ▸ Firewall says why. |

### Known limitations

- **Containers:** the firewall can't tell containers apart or name the program inside one. A container's connections
  are Docker's (or Podman's, OrbStack's…), judged per destination.
- **Virtual machines:** VMs with bridged or NAT networking aren't covered at all.
- **Very short connections:** they are caught by packet capture and by macOS's connection statistics. Only with the
  `nettop` fallback, on a macOS without that framework, do they arrive ~2 s late, with a destination inferred from the
  command line.
- **Unconnected UDP:** UDP sent without connecting (`sendto`) has no destination to show.
- **Listening sockets:** they aren't connections.
- **File opens:** they are high volume. The rate cap drops excess file events, so add exclusions for noisy apps.
- **`eslogger` output:** the JSON parser is defensive but may need updates across macOS releases.

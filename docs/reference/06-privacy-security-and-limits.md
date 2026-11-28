## Privacy, security and limits

### Files Hostwatch writes

Hostwatch keeps what it learns on your Mac. Nothing is sent anywhere, with these exceptions:

- what you send to an AI you chose: Claude, or a custom AI server that isn't on this Mac
- a daily anonymous update check, if it is on
- the daily threat-list downloads, if they are on, and the malicious-package lists for the languages your projects
  use (from OSV.dev: the whole list once, then only what changed. Your projects and packages are never sent)
- the firewall's web check, every 30 seconds while the firewall is on Ask or Strict, which confirms that its relay still
  lets connections through (if that fails, a second check without the relay tells a broken relay from no network)

On your own network, the network map asks devices to announce themselves (Bonjour, every 15 minutes, as the Finder
and AirPlay menus do). Those questions stay on your network and never reach the internet. macOS asks once whether
Hostwatch may use the local network.

Devices, addresses and ports you block on the network map are rules in macOS's packet filter, in a section of its own
(`com.apple/hostwatch-block`). They are removed when the collector stops, however it stops, and loaded again when the
app connects.

Here is where everything lives:

| Where | What |
|-------|------|
| `~/Library/Application Support/Hostwatch/` | patterns (`signatures-v2.json`), stories, domains, rules, signing facts, `collector.token` (0600), `claude-guard.json`, `firewall-watch.json` |
| `…/Hostwatch/intel/` | threat lists, `state.json`, `hits.json` |
| `…/Hostwatch/packages/` | malicious-package lists (one per language), the lockfiles checked, what was found and stopped (sealed). `quarantine/`: package folders Strict moved out of your projects, as they were |
| `…/Hostwatch/ask-claude/` | the empty working folder Claude runs in |
| `/var/log/hostwatch-collector.log` | the collector service's log (root-owned, readable) |
| `~/Library/Logs/Hostwatch/` | `agent.log` (the collector's log when it was started with an admin password prompt instead of as a background service) and the `History` folder (by default): `activity-*` events, `metrics-*` resource samples, `processes-*` process lists |
| `~/Library/Preferences/tech.hostwatch.app.plist` | settings and exclusions (plain) |
| `…/Hostwatch/network-map.json` | the network map's devices, incoming tries and outgoing connections (sealed) |
| `…/Hostwatch/vault.key` | the data key, wrapped by the Secure Enclave (see Encryption at rest) |

### Encryption at rest

Everything Hostwatch keeps is encrypted on disk (AES-256-GCM): patterns and their journal, stories, domains, AI
sessions, rules, signing facts, the firewall and Claude Code guard logs, the MCP token hash and access log, and the
whole activity history (each compressed block sealed on its own, day files line by line). The point is *where the
key lives*: another process running as you, an AI agent included, can't fetch it silently.

- **Keychain:** the data key is a login-keychain item whose access list names only Hostwatch's code. Any
  other process, `security` from a terminal included, gets macOS's keychain dialog and needs your password.
- **Secure Enclave:** on a build that can use it, the data key is wrapped by a key that never leaves the Enclave.
  The wrapped key is `vault.key` in the support folder, useless on another Mac or to anything but Hostwatch's own
  signed code, and the keychain item is removed. Hostwatch moves the key there by itself when it can.
- **What it looks like:** a sealed file starts with `HWV1`, a sealed line with `HWV1:`.
- **Reading it yourself:** `zcat` and `zgrep` don't work on the history files. Use
  `Hostwatch --export-history [file or folder]`, which prints plain JSON lines, and pipe it to `jq` (see
  [Activity history](04-settings.md#activity-history)).
- **Settings ▸ General ▸ Permissions ▸ Data on disk** shows the state and where the key is.
- **If the key is lost** (the keychain item removed, the Enclave key gone): the sealed files can't be read. Hostwatch
  says so in Settings, starts a new key and begins again. A backup of the files is only useful together with your
  keychain, which Time Machine includes. The collector (root) writes none of these files.

### Security notes

Part of Hostwatch runs as root, and it sees command lines that can contain passwords. These notes explain how it keeps
that power and that data from being misused.

For what Hostwatch defends against, its known weaknesses and its coverage of attack techniques, see
[Threat model and attack coverage](08-threat-model.md). To report a vulnerability, see
[SECURITY.md](https://github.com/everythings-gonna-be-alright/Hostwatch/blob/main/SECURITY.md).

**Who runs with which rights**

- **The HUD:** runs as the logged-in user. Only the collector is elevated.
- **The collector:** it is the app's own binary, run as root. Keep the app
  somewhere only you can write to, for example `/Applications`. Otherwise anything that can modify it gains root on
  the next start.
- **Hardened runtime:** the app is signed with the hardened runtime. macOS then ignores `DYLD_INSERT_LIBRARIES` and
  similar variables, and loads only Apple-signed libraries into Hostwatch. So code can't be injected into the app, the
  root collector or the MCP server. This was verified with a test library.

**The collector channel**

The app and the collector talk over a Unix socket, `/var/run/hostwatch/collector.sock`, never over a network port. A
Unix socket is a local file-like connection point that only processes on this Mac can reach.

- **The folder:** root creates it with mode 0755. The collector refuses a folder it doesn't own, so no other process
  can create or replace the socket. A leftover socket is replaced. Any other file is not.
- **The socket:** it belongs to the client user, with mode 0600. Other users cannot connect.
- **Every connection is checked:** the collector asks the kernel which process and user are connecting.
  - When the app launched it, only that app process and user are accepted.
  - As a background service, only the user logged in at the Mac is accepted (the socket follows a user switch).
  - When started by hand, only the `sudo` user is accepted.
  - **And only Hostwatch's own code.** On the real socket the collector also asks the kernel for the peer's audit
    token and checks, through macOS code signing, that the process satisfies the collector's own designated
    requirement: the same Team ID and bundle identifier. Being the
    right user isn't enough: another program of yours can't read the stream, answer firewall questions or change
    exclusions. The audit token can't be fooled by a reused pid.
  - Rejections are logged with the process path.
- **A service with no client does nothing.** When the app isn't connected for 15 seconds, the background service
  stops its Endpoint Security client and packet capture, turns the firewall off (nothing is held with nobody to ask) and waits. The
  next connection starts them again. It also notices when an update replaced the app and restarts itself as the
  new version.
- **The app checks too:** it connects only when the socket is a socket owned by you, mode 0600, not a link, and in a
  root-owned folder that nobody else can write. Otherwise it refuses and the HUD says why. So a fake collector run by
  an ordinary user cannot feed it data.
- **Shutdown:** the shutdown command also needs the per-launch token from `collector.token` (mode 0600).
- **Client config:** config lines sent by clients are only used as filters. The agent runs no commands based on them.

**Secrets in command lines**

New-process events carry the **command line**. It is forwarded to the app, shown, given to Claude and **written to
history**. So Hostwatch masks secrets first, with one set of rules. It masks:

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
- **Limits:** a secret in a shape no rule knows can still slip through. Environment variables are never forwarded.

**What the collector can and can't do**

- **Network:** to find connections, the collector runs `tcpdump` as root. It reads only DNS answers and TCP SYN
  headers, no payloads. It also reads macOS's connection statistics, read-only. Nothing is captured to disk.
- **Processes and files:** in Ask and Strict, the collector holds a launch, or an open in a protected place, until
  you or your rules answer, and denies what's blocked before it happens (see Protection). In Watch and Off it only
  listens.

### Reset Hostwatch

Reset lets you start over as on the first launch. Open **Settings ▸ General ▸ Reset Hostwatch…** and choose what to
erase:

- **Patterns, decisions and baseline:** `~/Library/Application Support/Hostwatch` and the baseline's state. That
  folder holds patterns, stories, domains, your rules, signing facts and the MCP token.
- **Settings:** HUD, window, detection, AI, exclusions and history options (`tech.hostwatch.app.plist`).
- **Event history and logs:** `~/Library/Logs/Hostwatch`. In a custom history folder, only Hostwatch's `activity-*`,
  `metrics-*` and `processes-*` files are erased.

Reset also unregisters the collector service (your password), so the next launch starts as on a fresh install.

> [!WARNING]
> Reset can't be undone. What you choose to erase is deleted, your decisions and rules included.

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
| **`ERR_NOT_PERMITTED` in the log** | Full Disk Access is missing (see [Built-in collector](01-getting-started.md#built-in-collector)). |
| **The firewall turned itself to Watch** | Its web check through the relay failed twice while the web worked without it. No network at all (lid closed, changing networks) doesn't count. The status line in Protection ▸ Network Firewall says why. |

### Known limitations

- **Containers:** the firewall can't tell containers apart or name the program inside one. A container's connections
  are Docker's (or Podman's, OrbStack's…), judged per destination.
- **Virtual machines:** VMs with bridged or NAT networking aren't covered at all.
- **Very short connections:** they are caught by packet capture and by macOS's connection statistics. On a macOS
  without those statistics they arrive about 2 s late, with a destination guessed from the command line.
- **Unconnected UDP:** UDP sent without connecting (`sendto`) has no destination to show.
- **Listening sockets:** they aren't connections.
- **File opens:** they are high volume. The rate cap drops excess file events, so add exclusions for noisy apps.
- **Builds without the entitlement:** a build you make yourself reads macOS's event monitor (`eslogger`), whose
  output can change between macOS releases and may need a Hostwatch update.

## Advanced and command line

### Command-line flags

You don't need any of these: the app runs without flags, and most are for testing. Run one as
`Hostwatch.app/Contents/MacOS/Hostwatch <flag>`.

| Flag | What it does |
|------|--------------|
| `--collector` | The collector itself (runs as root, started by the launcher). Options: `--daemon` (the background service: serves the user at the Mac, idles without a client), `--owner-pid`, `--token-file`, `--socket`. |
| `--collector-launcher` | Started by launchd: by the bundled service (`self` names this binary) or by the admin-prompted job. It spawns the collector. |
| `--mcp` | The read-only MCP server for Claude Code (see [MCP server](03-features.md#mcp-server)). |
| `--claude-hook` | Claude Code's PreToolUse hook (see [Claude Code guard](03-features.md#claude-code-guard)). |
| `--suggest-rules` | Dry run of rule suggestions from your decisions. |
| `--signature-report <history.jsonl>` | How events group into patterns (`REPORT_NOSIGN=1` skips signing checks). |
| `--triage-benchmark` | Compares local models on your own decisions and on attack-shaped patterns: false Safe, how many it settles, speed. `BENCH_MODELS=apple,<ollama model>,claude:haiku` picks them (Claude gets one batch, as in the app), `BENCH_N` the sample size. Run it from the signed app. |
| `--signing-check <path>…` | Signing facts for files (`HOSTWATCH_SIGNING_DB` for a scratch database). |
| `--story-replay <history.jsonl>` | Replays history through the story engine (`REPLAY_LEARN_MINUTES`, `HOSTWATCH_OWN_BUNDLE`). |
| `--metrics-probe` | Prints CPU, memory, network and disk samples. |
| `--compress-history <folder>` | Compresses plain history files by hand. |
| `--time-travel-probe [dir]` | Times reading history and searching it for Time Travel. |
| `--export-history [file or folder]` | The recorded events as plain JSON lines on stdout, through the data key (the files are sealed). |
| `sudo … --watch-test <pid> [seconds]` | Records a process like Watch Closely and prints the result. |
| `sudo … --firewall-probe` | Checks that the firewall's redirect works. |
| `sudo … --firewall-relay-test [seconds]` | Runs the relay and reports what passes through it. |

Environment variables:

- `CLAUDE_PATH`: where `claude` is.
- `HOSTWATCH_MCP_TOKEN`: MCP access.
- `CODESIGN_IDENTITY`: build with a stable signature.

### How the collector works

The collector is the part of Hostwatch that watches your Mac. It is built into the app (`Hostwatch --collector`,
written in Swift). Until 0.5 it was a Python script.

The launcher starts it as root. It combines five sources:

- **Processes and file opens:** `eslogger exec exit open` (Endpoint Security) reports processes and file opens.
  - `exit` is only used to keep the list of Hostwatch's own processes exact. It is never published.
  - Opens are deduplicated per (pid, path) for 2 minutes and capped at 40/s per client.
- **Outgoing connections:** packet capture sees every outgoing TCP connection, from its SYN packet, with the owning
  process.
  - It catches connections too short for any polling, like `curl google.com`. Endpoint Security has no connect event.
  - The command is `tcpdump -i pktap,all -k NPD -Z nobody`, read-only. It drops root right after opening the capture
    device, so packets are decoded without root.
- **Connected sockets:** every second, every process's connected sockets are read with libproc and compared with the
  previous look.
  - This finds incoming connections and long-lived UDP flows. It is also a fallback if packet metadata is unavailable.
  - Each connection is reported once, by whichever source sees it first.
  - Before 0.9 this was `lsof -i`.
- **Connection statistics:** macOS's NetworkStatistics.framework, what `nettop` is built on, reports every new TCP
  and UDP socket of every process. It gives the real destination, even for a socket that closes within milliseconds.
  - **Why it matters:** some security tools take over TCP flows in the kernel (e.g. a traffic-scanning network
    extension). Their short connections never appear as packets from the process.
  - **Fallback:** the framework is private, so it's opened at run time. If a macOS ever lacks it, the collector falls
    back to running `nettop`, under a small shell that stops it if the collector dies.
  - **Inferred connections:** in that fallback, a new process with TCP traffic that nobody else reported is reported
    as an **inferred** connection. Its destination is taken from what nettop saw or from the command line (`≈name`).
    It is marked as inferred, with byte counts.
- **Hostnames:** passive DNS answers (`tcpdump`, port 53, read-only) give a hostname for each new connection. That is
  the name that resolved to its IP, e.g. `curl TCP www.google.com:80`, kept even behind CNAMEs.
  - If no answer was seen, reverse DNS is used instead, shown as `~name`. This happens when the answer was cached
    before the collector started, or with encrypted DNS/DoH. The name is often a provider name like
    `~bt-in-f100.1e100.net`.
  - The Activity list still shows the IP, and Claude gets both.
  - Exclusions match hostnames: `net:*.google.com:*`.

**Hostwatch's own activity is not reported**, live, in history or in stories. That covers:

- the app that started the collector (verified by pid),
- the collector's own helpers (eslogger, tcpdump, nettop if used),
- and the children of these.

Other runs of the Hostwatch program, such as the MCP server Claude Code starts, are reported like any program. Hiding
"anything running the Hostwatch binary" would let malware hide by starting it with injected code. A pid leaves the
list when its process exits, so a reused pid is watched again.

Options: `./scripts/run-agent.sh --no-files --no-net --net-interval 0.5 --socket /var/run/hostwatch/collector.sock`.

Started by hand, the collector accepts connections only from the user who ran `sudo`. For development,
`HOSTWATCH_SOCKET` points the app at another socket path. Then its folder need not be root-owned.

The HUD sends its exclusions and enabled kinds to the agent, which filters per client before sending. So exclusions
also reduce load.

### Updates

Hostwatch can tell you when a newer version is out. It never downloads or installs anything by itself.

To check by hand, choose *Hostwatch ▸ Check for Updates…*:

1. Hostwatch asks `api.github.com/repos/everythings-gonna-be-alright/Hostwatch/releases/latest` for the newest
   published release. Drafts and pre-releases are ignored.
2. It compares that version numerically with this app's. For example, `0.10.0` is newer than `0.9.2`.
3. If it's newer, an alert shows the version, date and notes, with **Open Release Page**. Otherwise it says you're up
   to date, or why it couldn't check (offline, GitHub rate limit).

With *Check for updates automatically* (Settings ▸ General, on by default), the same check runs once a day, silently.
A newer release appears at the top of the menu bar icon menu and in Settings.

The request is anonymous (a `Hostwatch/<version>` user agent).

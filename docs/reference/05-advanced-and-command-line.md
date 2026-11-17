## Advanced and command line

### Command-line flags

You don't need any of these. The app runs without flags. Run one as
`/Applications/Hostwatch.app/Contents/MacOS/Hostwatch <flag>`.

| Flag | What it does |
|------|--------------|
| `--export-history [file or folder]` | Prints the recorded events as plain JSON lines, for your own scripts or another tool. History is encrypted on disk, so this is the way to read it. Without a path it exports the whole history folder. |
| `--metrics-probe` | Prints three readings of CPU, memory, network and disk, 2 s apart, to compare with Activity Monitor or `top`. |
| `--mcp` | The read-only MCP server for Claude Code. You don't run it yourself. *Settings ▸ AI* gives the command that registers it with Claude Code, with its access token (see [MCP server](03-features.md#mcp-server)). |
| `--claude-hook` | Claude Code's check before each command. Hostwatch installs it when you turn on the [Claude Code guard](03-features.md#claude-code-guard). |

Tools for building and testing Hostwatch are listed in [For developers](07-for-developers.md).

### How the collector works

The collector is the part of Hostwatch that watches your Mac. It is built into the app and runs as root in the
background. It only watches and reports, and everything is decided in the app. It combines five sources:

- **Processes and file opens:** Apple's `eslogger` (Endpoint Security) reports which programs start and which files
  they open.
- **Outgoing connections:** a read-only packet capture sees every new outgoing TCP connection, even one too short to
  notice any other way, like `curl google.com`. It gives up root right after it starts.
- **Connected sockets:** every second the collector looks at every process's open connections. This finds incoming
  connections and long-lived UDP traffic.
- **Connection statistics:** macOS's own network statistics, what `nettop` is built on, report every new connection
  with its real destination, even one that closes within milliseconds or is taken over by another security tool.
  When those statistics aren't available, a connection Hostwatch could only work out from a program's traffic is
  marked **inferred**, and its destination shows as `≈name`.
- **Hostnames:** the DNS answers your Mac receives give each connection the name that was looked up, such as
  `www.google.com`. If no answer was seen, for example with encrypted DNS, the name comes from a reverse lookup and
  shows as `~name`, often a provider's name like `~bt-in-f100.1e100.net`. Exclusions match hostnames, such as
  `net:*.google.com:*`.

**Hostwatch's own activity is not reported**, live, in history or in stories. That covers the app, the collector's
own helpers and their children. Other runs of the Hostwatch program, such as the MCP server Claude Code starts, are
reported like any program, so malware can't hide by starting Hostwatch with injected code.

Exclusions and the kinds of events you turned off are applied in the collector, so they also reduce load.

### Updates

Hostwatch can tell you when a newer version is out. It never downloads or installs anything by itself.

To check by hand, choose *Hostwatch ▸ Check for Updates…*. Hostwatch asks GitHub
(`api.github.com/repos/everythings-gonna-be-alright/Hostwatch/releases/latest`) for the newest published release,
ignoring drafts and pre-releases. If it's newer than yours, an alert shows the version, date and notes, with
**Open Release Page**. Otherwise it says you're up to date, or why it couldn't check (offline, GitHub's rate limit).

With *Check for updates automatically* (Settings ▸ General, on by default), the same check runs once a day, silently.
A newer release appears at the top of the menu bar icon menu and in Settings.

The request is anonymous. It sends only `Hostwatch/<version>` as its user agent.

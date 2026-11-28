## How to monitor Claude Code on a Mac

A coding agent runs shells, `git`, builds and `curl` as you, many times a minute. Here is how to see what it did,
and how to stop the commands you'd never allow. It works for the Cursor agent, Codex and Gemini CLI too.

### What Claude Code gives you

- **Permissions.** It asks before it runs a command, unless you told it not to ask.
- **Transcripts.** Each session is saved under `~/.claude/projects/`.

Both show what the agent said it would do. Neither shows what the programs it started then did.

### See what a session did

1. In Hostwatch's *Events*, set *Group* to *By AI Session*. Each session is one row, with everything it started
   under it.
2. Click *Only this session* to keep just that one.
3. Open the *Network* tab: a server the session reached carries a *via Claude* tag.
4. For yesterday's sessions, use *Time Travel*. The grouping works there too.

### Stop the dangerous commands

Turn on *Settings ▸ AI ▸ Claude Code guard*. Hostwatch then checks each command before it runs.

- **Blocked:** deleting your home folder, switching off macOS protections, sending a secret to a paste site,
  reaching a known malware server.
- **You're asked:** `curl … | sh`, `sudo`, reading SSH keys or cloud credentials, adding a launch agent.
- **Everything else:** Claude Code's own permissions apply. The guard can only make it stricter.

### Ask Claude Code about itself

Hostwatch has an MCP server. Connect it, and you can ask Claude Code what ran on your Mac yesterday. It reads
Hostwatch's history and can't change anything.

More in [AI sessions](03-features.md#ai-sessions-what-claude-code-did),
[Claude Code guard](03-features.md#claude-code-guard) and [MCP server](03-features.md#mcp-server).

### Questions and answers

#### Is it safe to let Claude Code run commands on my Mac?

It runs with your access, so a command it is tricked into running can read your keys or delete your files. Keep
its permission prompts on, and add a second check that sees what the commands really do.

#### Can I see what Claude Code did while I wasn't looking?

Yes. Hostwatch records every program a session starts and every server it reaches, and Time Travel plays it back.

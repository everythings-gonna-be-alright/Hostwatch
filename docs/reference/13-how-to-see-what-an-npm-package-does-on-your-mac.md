## How to see what an npm package does on your Mac

`npm install` can run a package's own scripts, with your access to your files, keys and tokens. Here is how to look
before you install, and how to watch while it runs.

### Before you install

1. See the scripts it would run: `npm view <package> scripts`. Look for `preinstall`, `install` and `postinstall`.
2. Install without running them: `npm install --ignore-scripts`
3. Read the code without installing it: `npm pack <package>`. It downloads the archive for you to open.

> [!NOTE]
> This shows what the package says it does. Code can hide, and a package brings other packages with it.

### Watch it run with Hostwatch

1. In Hostwatch, right-click your terminal's shell in *Events* and choose *Watch Selected Process Closely…* (⌥⌘W).
2. Run `npm install` in that terminal. Hostwatch records the shell and everything it starts, for up to 5 minutes.
3. Read the summary. **What stands out** comes first, then the processes as a tree, the network and the files.

Hostwatch watches without being asked too. A story is raised when an install pipes a download into a shell, reads
your keys or sets something to start at login. A server your Mac has never contacted is marked new.

### What to look for

- **Reads of your secrets:** `~/.ssh`, `~/.aws`, your npm token, browser data.
- **Connections to anything but the package registry.**
- **Files written outside the project folder.**
- **Changes to what starts by itself:** launch agents, login items, your shell's startup files.

More in [Watch Closely](03-features.md#watch-closely) and [Stories](03-features.md#stories-chains-not-single-events).

### Questions and answers

#### Can an npm package steal my SSH keys?

Yes. An install script runs as you, so it can read anything you can read, such as `~/.ssh`, and send it out.

#### Does this work for pip, Homebrew and other package managers?

Yes. Hostwatch watches programs, not package managers. Watch the shell you install from, whatever the tool.

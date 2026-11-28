## How to detect an infostealer on a Mac

An infostealer runs once, copies your passwords, browser cookies and keys, sends them out and often deletes itself.
So you look for the reading and the sending, not for a file that stays.

### The signs

- A program you just downloaded showed its own window asking for your Mac password.
- A web page told you to paste a command into Terminal "to fix" or "to verify" something.
- A program that has no reason to reads your keychain, browser data or SSH keys.
- Right after, a connection goes to a server your Mac has never talked to.

### Check by hand

1. Open *System Settings ▸ General ▸ Login Items & Extensions* and look for anything you don't know.
2. List what starts by itself: `ls -la ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons`
3. See which programs have connections open right now: `lsof -i -P -n`
4. Look at what arrived last: `ls -lt ~/Downloads | head`

A stealer that has already finished leaves little to find this way. It doesn't need to stay.

### Let Hostwatch watch for it

1. **It records who reads your secrets.** Keychains, SSH and cloud keys, browser passwords and cookies are marked
   as sensitive places, and every program that opens them is listed.
2. **It joins the steps.** A download, a removed quarantine flag, a read of your keys and a new server become one
   story, with a sound and a banner.
3. **It can ask first.** Set *Protection ▸ Protected Files and Folders* to Ask, and a program waits for your answer
   before it reads a protected place.
4. **It lets you look back.** Time Travel plays back what ran and where it connected, hours or days later.

More in [Features](03-features.md).

### If you find one

1. Disconnect the Mac from the network.
2. From another device, change your passwords, starting with email and your password manager.
3. Sign out other sessions and revoke tokens: browser logins, GitHub, cloud accounts.
4. Replace your SSH and cloud keys.
5. Then clean the Mac, or erase and reinstall it if you can't tell what was changed.

### Questions and answers

#### Can a Mac get an infostealer?

Yes. Stealers for macOS are sold as a service and arrive as fake apps, cracked software and commands you are asked
to paste into Terminal.

#### Does antivirus catch infostealers?

It catches the ones it already knows. A new build with no known signature gets through, which is why watching
what a program does matters: reading your keychain and browser data is the same whatever the file is called.

# 0009 Everything on disk is encrypted; the key lives where your other processes can't read it

**Context.** Hostwatch's files (patterns, stories, domains, sessions, logs, the activity history) were plain JSON
with mode 0600. That keeps other *users* out and nothing else: any process running as you, an AI agent included,
could read all of it. FileVault doesn't help (it protects the disk, not one user from their own processes).
Encrypting with a key that sits next to the data, or anywhere a same-user process can fetch it silently, would be
theatre.

**Decision.** One random 256-bit data key, AES-256-GCM for every file (`Vault`). The key is kept:

- in the **Secure Enclave** when there is one (Apple silicon, T2): wrapped by an Enclave key that never leaves it,
  the wrapped blob in `vault.key`; useless on another Mac or to anything but Hostwatch's own code, which the
  Enclave key's keychain access control checks;
- else as a **keychain item** whose access list names only Hostwatch's code (its designated requirement): any other
  process gets macOS's keychain dialog and needs your password.

Whole files: `HWV1` + the sealed box. Append-only files (the pattern journal, the MCP access log): one sealed,
base64 line each. History blocks: each sealed on its own, so Time Travel still reads only the blocks it needs.
A file or line without the marker is read as plain (older versions) and rewritten sealed on the next save. Tests
use an in-memory key and never touch the keychain. The collector (root) writes none of these files.

**Consequences.** `zcat`/`zgrep` on history files no longer work by hand; `--export-history` goes through the key.
A backup of the files is only useful together with the keychain (Time Machine includes it); a lost Enclave key or
keychain item means the files can't be read, and Hostwatch starts over with a new key and says so. Reading and
writing cost nothing noticeable (hardware AES). The MCP server, the same signed binary, reads through the key.

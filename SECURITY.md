# Security policy

Hostwatch is a security tool with a part that runs as root, so a flaw in it matters more than in most apps. Thank you
for taking the time to report one.

## Supported versions

Only the latest release gets security fixes. Fixes ship as a new release, never as a patch to an old one.

| Version | Supported |
|---------|-----------|
| Latest release (see [Releases](https://github.com/everythings-gonna-be-alright/Hostwatch/releases/latest)) | Yes |
| Anything older | No, please update |

## Reporting a vulnerability

Please report privately, not in a public issue:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability**. This opens a private advisory that only you and the maintainer can see.

Please include:

- the Hostwatch version (*Hostwatch ▸ About*) and your macOS version
- what an attacker needs first (for example "code running as the logged-in user", "a malicious threat list", "a
  crafted file name")
- what they gain (for example "root", "reading Hostwatch's encrypted data", "hiding a launch from Stories")
- steps to reproduce, ideally on a test account or a virtual machine

Please don't include real secrets, personal data or anyone else's files. Dummy values are enough.

## What happens next

- **Within 3 days:** a reply that the report arrived.
- **Within 14 days:** an assessment, whether it is a vulnerability, how severe, and a plan.
- **The fix:** as soon as it is ready and tested. A critical flaw (root for an unprivileged attacker, or reading
  Hostwatch's protected data) is worked on first and released on its own.
- **Disclosure:** coordinated with you. The default is to publish the advisory when the fix is released, and no later
  than 90 days after the report. You are credited in the advisory and the changelog unless you prefer not to be.

## In scope

Anything that breaks a promise Hostwatch makes about itself. The full list of promises, and what Hostwatch does *not*
protect against, is in the [threat model](docs/reference/08-threat-model.md). In particular:

- the root collector, its Unix socket and its check that only Hostwatch's own code may connect
- the firewall (packet filter rules, the relay) and launch and file protection
- encryption at rest (`Vault`) and where its key is kept
- secret masking before history, AI prompts and MCP output
- the Claude Code guard hook and the MCP server's token
- parsing of threat lists, `eslogger` output and anything else that comes from outside
- an AI (on-device, Claude or a custom server) being steered into marking something Safe that its rules forbid
- the update check and the signed, notarized release

## Out of scope

- An attacker who is already root or has kernel access. Hostwatch can't defend against the account it runs under.
- Physical access to an unlocked Mac.
- Ways to avoid detection that the documentation already lists as known limitations (containers, virtual machines,
  unconnected UDP, very short-lived processes). Report a new way around a detection Hostwatch claims as a normal
  issue. Report it privately if it hides something Hostwatch says it always catches.
- Denial of service against your own Mac by your own user account.
- Findings from automated scanners without a way to exploit them.

## Safe harbour

Research done in good faith on your own Mac, a test account or a virtual machine, that stays within this policy, is
welcome. It won't lead to any complaint from this project. Please don't test against other people's machines or data.

## Verifying a download

Every release is signed with a Developer ID, notarized by Apple, and published with a SHA-256 checksum:

```bash
shasum -a 256 -c Hostwatch-<version>-macOS-universal.zip.sha256
codesign --verify --deep --strict --verbose=2 Hostwatch.app
spctl --assess --type execute --verbose=2 Hostwatch.app    # expect: source=Notarized Developer ID
```

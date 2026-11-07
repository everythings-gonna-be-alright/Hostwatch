# 0006 Releases signed with a personal Developer ID and notarized

**Context.** Ad-hoc signed releases hit "Apple could not verify" and lost Full Disk Access on every update
(macOS ties the grant to the signature). An organization account was the alternative.

**Decision.** Since 0.11.1 releases are signed with the author's Developer ID Application certificate and notarized
(`package.sh`: universal build, `notarytool` with the keychain profile `hostwatch-notary`, staple, `spctl`). The
repository itself stays under the anonymous identity; the name inside the signature is accepted.

**Consequences.** Opens without warnings; Full Disk Access survives updates from 0.11.1 on. `build-app.sh` picks the
identity from the keychain automatically and falls back to ad-hoc on a machine without it. The privacy scan must
keep the author's name out of repo files, not out of the binary's signature.

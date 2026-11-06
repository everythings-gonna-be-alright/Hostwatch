#!/bin/bash
# Builds a universal (Apple Silicon + Intel) release and packs it for GitHub Releases:
#   dist/Hostwatch-<version>-macOS-universal.zip and its .sha256
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="$(tr -d '[:space:]' < VERSION)"
./scripts/test.sh
UNIVERSAL=1 RELEASE=1 ./scripts/build-app.sh

cd dist
ZIP="Hostwatch-$VERSION-macOS-universal.zip"
rm -f "$ZIP" "$ZIP.sha256"
# ditto keeps the bundle's symlinks, permissions and extended attributes intact.
ditto -c -k --sequesterRsrc --keepParent Hostwatch.app "$ZIP"

# Notarization (Developer ID builds): Apple checks the app, then the ticket is stapled to it so Gatekeeper opens it
# without asking, even offline. Credentials: `xcrun notarytool store-credentials hostwatch-notary` (NOTARY_PROFILE).
if codesign -dv Hostwatch.app 2>&1 | grep -q "Authority=Developer ID Application"; then
  xcrun notarytool submit "$ZIP" --keychain-profile "${NOTARY_PROFILE:-hostwatch-notary}" --wait
  xcrun stapler staple Hostwatch.app
  rm -f "$ZIP"
  ditto -c -k --sequesterRsrc --keepParent Hostwatch.app "$ZIP"      # the stapled app
  spctl --assess --type execute --verbose=2 Hostwatch.app
else
  echo "Note: not signed with a Developer ID, so not notarized (macOS will warn when it's opened)."
fi
shasum -a 256 "$ZIP" | tee "$ZIP.sha256"
echo "Packaged: $PWD/$ZIP"

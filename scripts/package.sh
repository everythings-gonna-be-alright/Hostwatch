#!/bin/bash
# Builds a universal (Apple Silicon + Intel) release and packs it for GitHub Releases:
#   dist/Hostwatch-<version>-macOS-universal.zip and its .sha256
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="$(tr -d '[:space:]' < VERSION)"
./scripts/test.sh
UNIVERSAL=1 ./scripts/build-app.sh

cd dist
ZIP="Hostwatch-$VERSION-macOS-universal.zip"
rm -f "$ZIP" "$ZIP.sha256"
# ditto keeps the bundle's symlinks, permissions and extended attributes intact.
ditto -c -k --sequesterRsrc --keepParent Hostwatch.app "$ZIP"
shasum -a 256 "$ZIP" | tee "$ZIP.sha256"
echo "Packaged: $PWD/$ZIP"

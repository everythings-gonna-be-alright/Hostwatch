#!/bin/bash
# Builds a universal (Apple Silicon + Intel) release and packs it for GitHub Releases:
#   dist/Hostwatch-<version>-macOS-universal.zip and its .sha256
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="$(tr -d '[:space:]' < VERSION)"
PROFILE="${NOTARY_PROFILE:-hostwatch-notary}"
# The credentials can live in a keychain file of their own (NOTARY_KEYCHAIN, or this one when it exists), so a
# missing profile is a file you can see, not an item gone from the shared keychain.
KEYCHAIN="${NOTARY_KEYCHAIN:-$HOME/Library/Keychains/hostwatch-notary.keychain-db}"
AUTH=(--keychain-profile "$PROFILE")
[ -f "$KEYCHAIN" ] && AUTH+=(--keychain "$KEYCHAIN")
ZIP="Hostwatch-$VERSION-macOS-universal.zip"

# `--resume <submission id>`: a run whose wait broke (network, a closed shell) picks up the submission Apple already
# has, for the app still in dist/, instead of building and uploading again.
RESUME=""
if [ "${1:-}" = "--resume" ]; then RESUME="${2:?usage: package.sh --resume <submission id>}"; fi

# Apple's verdict for a submission, waiting through dropped connections. `notarytool submit --wait` exits 0 even
# when the answer is Rejected, so the status is read back and anything but Accepted stops the release here, with
# Apple's reasons printed, and the un-notarized zip removed so it can't be uploaded by mistake.
notarize() {
  local id="$1" status=""
  for attempt in 1 2 3 4 5 6; do
    xcrun notarytool wait "$id" "${AUTH[@]}" || true
    status="$(xcrun notarytool info "$id" "${AUTH[@]}" --output-format json | plutil -extract status raw -)" || status=""
    [ -n "$status" ] && [ "$status" != "In Progress" ] && break
    echo "No answer from Apple yet (attempt $attempt), asking again in a minute..."
    sleep 60
  done
  if [ "$status" != "Accepted" ]; then
    echo "Notarization: ${status:-no answer, Apple could not be asked (offline, or the keychain locked)} (submission $id)" >&2
    xcrun notarytool log "$id" "${AUTH[@]}" >&2 || true
    rm -f "$ZIP" "$ZIP.sha256"
    [ "$status" = "In Progress" ] || [ -z "$status" ] && echo "Still with Apple. Later: ./scripts/package.sh --resume $id" >&2
    exit 1
  fi
}

if [ -z "$RESUME" ]; then
  ./scripts/test.sh
  UNIVERSAL=1 RELEASE=1 ./scripts/build-app.sh
fi

cd dist
[ -n "$RESUME" ] || {
  rm -f "$ZIP" "$ZIP.sha256"
  # ditto keeps the bundle's symlinks, permissions and extended attributes intact.
  ditto -c -k --sequesterRsrc --keepParent Hostwatch.app "$ZIP"
}

# Notarization (Developer ID builds): Apple checks the app, then the ticket is stapled to it so Gatekeeper opens it
# without asking, even offline. Credentials: `xcrun notarytool store-credentials hostwatch-notary --keychain <file>`.
# (not `grep -q`: it closes the pipe early, codesign dies of SIGPIPE, and under pipefail the test fails even when signed)
if codesign -dvv Hostwatch.app 2>&1 | grep "Authority=Developer ID Application" >/dev/null; then
  codesign --verify --deep --strict --verbose=2 Hostwatch.app
  if [ -n "$RESUME" ]; then
    ID="$RESUME"
  else
    # A failed upload (no saved credentials, no network) leaves no zip behind either.
    ID="$(xcrun notarytool submit "$ZIP" "${AUTH[@]}" --output-format json | plutil -extract id raw -)" \
      || { rm -f "$ZIP"; echo "Not sent to Apple, nothing packaged." >&2; exit 1; }
    echo "Submitted to Apple: $ID"
  fi
  notarize "$ID"
  xcrun stapler staple Hostwatch.app
  xcrun stapler validate Hostwatch.app
  rm -f "$ZIP"
  ditto -c -k --sequesterRsrc --keepParent Hostwatch.app "$ZIP"      # the stapled app
  spctl --assess --type execute --verbose=2 Hostwatch.app
elif [ -n "$RESUME" ]; then
  echo "dist/Hostwatch.app is not signed with a Developer ID, nothing to resume." >&2; exit 1
else
  echo "Note: not signed with a Developer ID, so not notarized (macOS will warn when it's opened)."
fi
shasum -a 256 "$ZIP" | tee "$ZIP.sha256"
echo "Packaged: $PWD/$ZIP"

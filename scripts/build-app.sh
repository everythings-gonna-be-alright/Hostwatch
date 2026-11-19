#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="$(tr -d '[:space:]' < VERSION)"
# UNIVERSAL=1 builds for Apple Silicon and Intel (used by package.sh for releases).
ARCH_FLAGS=()
if [ "${UNIVERSAL:-0}" = 1 ]; then ARCH_FLAGS=(--arch arm64 --arch x86_64); fi
# Map this folder to "." so source paths in the binary don't contain your home folder.
SWIFT_FLAGS=(-Xswiftc -file-prefix-map -Xswiftc "$PWD=.")
# DEMO=1 builds "Hostwatch Demo.app": demo mode compiled in (-DDEMO), its own bundle id and build folder, so it can
# never touch the real app's settings. Releases never set it: the normal build has no demo code at all.
NAME="Hostwatch"; BUNDLE_ID="tech.hostwatch.app"
if [ "${DEMO:-0}" = 1 ]; then
  SWIFT_FLAGS+=(-Xswiftc -DDEMO --build-path .build-demo)
  NAME="Hostwatch Demo"; BUNDLE_ID="tech.hostwatch.demo"
fi
# Endpoint Security (ADR 0018): only the root collector is entitled, from its own bundle inside the app
# (Contents/Library/Helpers/Hostwatch Collector.app, tech.hostwatch.collector). The app itself keeps exactly the
# signature it always had: an entitlement there changed its keychain identity, so it lost its data key. The
# entitlement is restricted: it needs Apple's Developer ID provisioning profile for the collector's identifier, or
# macOS refuses to start it. Both go in only together, only when the profile names the collector and grants it.
# The profile lives outside the repo (it names the team): HOSTWATCH_COLLECTOR_PROFILE, or the default path below.
# Checked before building, so a wrong profile stops here and never leaves an unsigned app behind.
COLLECTOR_ID="tech.hostwatch.collector"
PROFILE="${HOSTWATCH_COLLECTOR_PROFILE:-$HOME/.hostwatch-signing/HostwatchCollector.provisionprofile}"
ES_ENTITLED=0
if [ -f "$PROFILE" ] && [ "${DEMO:-0}" != 1 ]; then
  DECODED="$(mktemp)"; trap 'rm -f "$DECODED" "$DECODED.ent"' EXIT
  security cms -D -i "$PROFILE" > "$DECODED"
  TEAM="$(/usr/libexec/PlistBuddy -c 'Print :TeamIdentifier:0' "$DECODED")"
  APPID="$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.application-identifier' "$DECODED")"
  ES="$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.developer.endpoint-security.client' "$DECODED" 2>/dev/null || true)"
  EXPIRES="$(/usr/libexec/PlistBuddy -c 'Print :ExpirationDate' "$DECODED")"
  if [ "$APPID" != "$TEAM.$COLLECTOR_ID" ]; then
    echo "error: $PROFILE is for another identifier, not $COLLECTOR_ID" >&2; exit 1
  fi
  if [ "$ES" != "true" ]; then
    echo "error: $PROFILE doesn't grant Endpoint Security (enable it for $COLLECTOR_ID and download the profile again)" >&2; exit 1
  fi
  ES_ENTITLED=1
fi
# Whole-module optimisation re-optimises the whole app on any change (77 s for a one-line edit). Local builds skip it
# (40 s, a few percent slower at run time); releases (RELEASE=1, package.sh) keep it.
if [ "${RELEASE:-0}" != 1 ]; then SWIFT_FLAGS+=(-Xswiftc -no-whole-module-optimization); fi
swift build -c release ${ARCH_FLAGS[@]+"${ARCH_FLAGS[@]}"} "${SWIFT_FLAGS[@]}"
BIN="$(swift build -c release ${ARCH_FLAGS[@]+"${ARCH_FLAGS[@]}"} "${SWIFT_FLAGS[@]}" --show-bin-path)/Hostwatch"

APP="$PWD/dist/$NAME.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/Hostwatch"
# Shipped binaries don't need debug symbols (they also list build paths); strip before signing.
# KEEP_SYMBOLS=1 keeps them, to read a `sample` of the running app (never for a release).
if [ "${KEEP_SYMBOLS:-0}" != 1 ] || [ "${RELEASE:-0}" = 1 ]; then strip -S -x "$APP/Contents/MacOS/Hostwatch"; fi
# The collector ships inside the app; Hostwatch starts it with an admin prompt.
# Icon: regenerate with `swift scripts/make-icon.swift` after changing the design.
[ -f assets/AppIcon.icns ] || swift scripts/make-icon.swift
cp "assets/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
cp "assets/oui.tsv" "$APP/Contents/Resources/oui.tsv"        # hardware-address makers (scripts/make-oui.py)

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key><string>Hostwatch</string>
  <key>CFBundleIdentifier</key><string>$BUNDLE_ID</string>
  <key>CFBundleName</key><string>$NAME</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>NSHumanReadableCopyright</key><string>© 2026 everythings-gonna-be-alright. Free for everyone (PolyForm Shield 1.0.0).</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSUIElement</key><true/>
  <key>NSHighResolutionCapable</key><true/>
  <key>LSMinimumSystemVersion</key><string>26.0</string>
  <key>NSLocalNetworkUsageDescription</key><string>Hostwatch names the devices on your network map by what they announce about themselves, such as iPhone or a printer model. Nothing leaves your network.</string>
  <key>NSBonjourServices</key><array><string>_airplay._tcp</string><string>_companion-link._tcp</string><string>_device-info._tcp</string><string>_raop._tcp</string><string>_googlecast._tcp</string><string>_ipp._tcp</string><string>_printer._tcp</string><string>_hap._tcp</string></array>
</dict>
</plist>
PLIST

# Signing: a "Developer ID Application" certificate in the keychain is used automatically (releases are then
# notarized by package.sh); CODESIGN_IDENTITY picks another one, CODESIGN_IDENTITY=- forces ad-hoc. A stable identity
# also keeps the Full Disk Access grant across rebuilds (ad-hoc signatures change every time).
# Hardened runtime (works with ad-hoc signing too): macOS ignores DYLD_INSERT_LIBRARIES and
# friends for Hostwatch and loads only Apple-signed libraries into it, so no code can be injected.
if [ -z "${CODESIGN_IDENTITY:-}" ]; then
  CODESIGN_IDENTITY="$(security find-identity -v -p codesigning 2>/dev/null \
    | sed -n 's/.*"\(Developer ID Application: [^"]*\)".*/\1/p' | head -1)"
fi
# Notarization needs Apple's secure timestamp (RELEASE=1, set by package.sh); local builds skip the network call.
TIMESTAMP="--timestamp=none"
if [ "${RELEASE:-0}" = 1 ]; then TIMESTAMP="--timestamp"; fi
if [ -n "${CODESIGN_IDENTITY:-}" ] && [ "$CODESIGN_IDENTITY" != "-" ] && [ "${DEMO:-0}" != 1 ]; then
  # The collector as a background service (SMAppService daemon): registered once, approved once, started by launchd
  # as root from then on. Only a Developer ID build may ship it; the signature covers the plist.
  mkdir -p "$APP/Contents/Library/LaunchDaemons"
  cat > "$APP/Contents/Library/LaunchDaemons/tech.hostwatch.collectord.plist" <<DAEMON
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>tech.hostwatch.collectord</string>
  <key>BundleProgram</key><string>Contents/MacOS/Hostwatch</string>
  <key>ProgramArguments</key>
  <array>
    <string>Hostwatch</string>
    <string>--collector-launcher</string>
    <string>self</string>
    <string>--collector</string>
    <string>--daemon</string>
    <string>--socket</string>
    <string>/var/run/hostwatch/collector.sock</string>
  </array>
  <key>AssociatedBundleIdentifiers</key><array><string>$BUNDLE_ID</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Interactive</string>
  <key>StandardOutPath</key><string>/var/log/hostwatch-collector.log</string>
  <key>StandardErrorPath</key><string>/var/log/hostwatch-collector.log</string>
</dict>
</plist>
DAEMON
  if [ "$ES_ENTITLED" = 1 ]; then
    # The entitled collector: the same binary in a background-only bundle of its own, signed first (inside out).
    HELPER="$APP/Contents/Library/Helpers/Hostwatch Collector.app"
    mkdir -p "$HELPER/Contents/MacOS"
    cp "$APP/Contents/MacOS/Hostwatch" "$HELPER/Contents/MacOS/Hostwatch"
    cp "$PROFILE" "$HELPER/Contents/embedded.provisionprofile"
    cat > "$HELPER/Contents/Info.plist" <<HELPERPLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>$COLLECTOR_ID</string>
  <key>CFBundleName</key><string>Hostwatch Collector</string>
  <key>CFBundleExecutable</key><string>Hostwatch</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>LSMinimumSystemVersion</key><string>26.0</string>
  <key>LSBackgroundOnly</key><true/>
</dict>
</plist>
HELPERPLIST
    cat > "$DECODED.ent" <<ENT
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.application-identifier</key><string>$TEAM.$COLLECTOR_ID</string>
  <key>com.apple.developer.team-identifier</key><string>$TEAM</string>
  <key>com.apple.developer.endpoint-security.client</key><true/>
</dict>
</plist>
ENT
    codesign --force --options runtime $TIMESTAMP --entitlements "$DECODED.ent" --sign "$CODESIGN_IDENTITY" "$HELPER"
    echo "Endpoint Security: the collector is entitled (profile valid until $EXPIRES)"
  else
    echo "Endpoint Security: no profile at $PROFILE, the collector uses eslogger"
  fi
  # The app: no entitlements, ever (its keychain identity holds the data key).
  codesign --force --options runtime $TIMESTAMP --sign "$CODESIGN_IDENTITY" "$APP"
  echo "Signed: $CODESIGN_IDENTITY" | sed -E 's/\([A-Z0-9]{10}\)/(team)/'
else
  codesign --force --options runtime --sign - "$APP" >/dev/null 2>&1 || true
  echo "Note: ad-hoc signed. Re-grant Full Disk Access to Hostwatch after each rebuild."
fi

SIGNATURE="$(codesign -dv "$APP" 2>&1 || true)"
if [[ "$SIGNATURE" != *"runtime"* ]]; then
  echo "error: $APP is not signed with the hardened runtime" >&2
  exit 1
fi
echo "Built: $APP ($VERSION, $(lipo -archs "$APP/Contents/MacOS/Hostwatch"))"
echo "Launch with: open \"$APP\""

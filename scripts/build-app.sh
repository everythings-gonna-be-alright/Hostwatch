#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="$(tr -d '[:space:]' < VERSION)"
# UNIVERSAL=1 builds for Apple Silicon and Intel (used by package.sh for releases).
ARCH_FLAGS=()
if [ "${UNIVERSAL:-0}" = 1 ]; then ARCH_FLAGS=(--arch arm64 --arch x86_64); fi
# Map this folder to "." so source paths in the binary don't contain your home folder.
SWIFT_FLAGS=(-Xswiftc -file-prefix-map -Xswiftc "$PWD=.")
swift build -c release ${ARCH_FLAGS[@]+"${ARCH_FLAGS[@]}"} "${SWIFT_FLAGS[@]}"
BIN="$(swift build -c release ${ARCH_FLAGS[@]+"${ARCH_FLAGS[@]}"} "${SWIFT_FLAGS[@]}" --show-bin-path)/Hostwatch"

APP="$PWD/dist/Hostwatch.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/Hostwatch"
# Shipped binaries don't need debug symbols (they also list build paths); strip before signing.
strip -S -x "$APP/Contents/MacOS/Hostwatch"
# The collector ships inside the app; Hostwatch starts it with an admin prompt.
# Icon: regenerate with `swift scripts/make-icon.swift` after changing the design.
[ -f assets/AppIcon.icns ] || swift scripts/make-icon.swift
cp "assets/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key><string>Hostwatch</string>
  <key>CFBundleIdentifier</key><string>local.hostwatch.app</string>
  <key>CFBundleName</key><string>Hostwatch</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>NSHumanReadableCopyright</key><string>MIT License</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSUIElement</key><true/>
  <key>NSHighResolutionCapable</key><true/>
  <key>LSMinimumSystemVersion</key><string>26.0</string>
</dict>
</plist>
PLIST

# Full Disk Access is tied to the code signature. Ad-hoc signatures change on every
# rebuild, so the grant must be redone. Set CODESIGN_IDENTITY (e.g. "Apple Development: …")
# to keep a stable identity, and with it the grant.
# Hardened runtime (free, works with ad-hoc signing too): macOS ignores DYLD_INSERT_LIBRARIES and
# friends for Hostwatch and loads only Apple-signed libraries into it, so no code can be injected.
if [ -n "${CODESIGN_IDENTITY:-}" ]; then
  codesign --force --options runtime --sign "$CODESIGN_IDENTITY" "$APP"
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

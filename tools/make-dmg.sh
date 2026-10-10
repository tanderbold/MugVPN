#!/bin/bash
# Package build/MugVPN.app as build/MugVPN-<version>.dmg (drag to Applications).
# Only from a Developer ID build; tools/notarize.sh then notarizes and staples it (release.yml does both).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="$ROOT/build/MugVPN.app"
[ -d "$APP" ] || { echo "build the app first: tools/build.sh" >&2; exit 1; }
[ ! -e "$APP/Contents/Resources/testing-build" ] || { echo "this is a testing build (MUGVPN_TESTING=1): build a release first" >&2; exit 1; }
# A root helper from an ad-hoc build accepts any client named com.mugvpn.app: never package one,
# nor one whose pinned client requirement is not anchored to Apple's certificate chain.
# (In the helper that ships, not the source: what was compiled is what counts.)
strings "$APP/Contents/MacOS/MugVPNHelper" | grep -q 'anchor apple generic' || {
    echo "the helper's client requirement is not anchored to a Developer ID: build with MUGVPN_SIGN_ID and MUGVPN_TEAM" >&2; exit 1; }
if codesign -dv "$APP" 2>&1 | grep -q "Signature=adhoc"; then
    echo "ad-hoc signed: build with MUGVPN_SIGN_ID and MUGVPN_TEAM (Developer ID) to package" >&2; exit 1
fi
VERSION=$(/usr/libexec/PlistBuddy -c "Print CFBundleShortVersionString" "$APP/Contents/Info.plist")
STAGE="$ROOT/build/dmg"
OUT="$ROOT/build/MugVPN-$VERSION.dmg"
rm -rf "$STAGE" "$OUT"
mkdir -p "$STAGE"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
cp "$ROOT/README.md" "$STAGE/README.md"
hdiutil create -quiet -volname "MugVPN $VERSION" -srcfolder "$STAGE" -format UDZO -ov "$OUT"
rm -rf "$STAGE"
# Check: the image mounts and the app inside keeps a valid signature.
MNT=$(mktemp -d)
hdiutil attach -quiet -nobrowse -readonly -mountpoint "$MNT" "$OUT"
codesign --verify --deep --strict "$MNT/MugVPN.app"
hdiutil detach -quiet "$MNT"
rmdir "$MNT"
echo "==> $OUT ($(du -h "$OUT" | cut -f1))"

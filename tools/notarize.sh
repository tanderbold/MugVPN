#!/bin/bash
# Notarize and staple build/MugVPN-<version>.dmg (made by tools/make-dmg.sh from a Developer ID
# build), then write its SHA-256 beside it. Apple's notary service is asked with an App Store
# Connect API key: MUGVPN_NOTARY_KEY (path to the .p8), MUGVPN_NOTARY_KEY_ID, MUGVPN_NOTARY_ISSUER.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${MUGVPN_NOTARY_KEY:?the App Store Connect API key (.p8)}" "${MUGVPN_NOTARY_KEY_ID:?its key id}" "${MUGVPN_NOTARY_ISSUER:?its issuer id}"
VERSION=$(/usr/libexec/PlistBuddy -c "Print CFBundleShortVersionString" "$ROOT/build/MugVPN.app/Contents/Info.plist")
DMG="$ROOT/build/MugVPN-$VERSION.dmg"
[ -f "$DMG" ] || { echo "no $DMG: run tools/make-dmg.sh first" >&2; exit 1; }
xcrun notarytool submit "$DMG" --key "$MUGVPN_NOTARY_KEY" --key-id "$MUGVPN_NOTARY_KEY_ID" \
    --issuer "$MUGVPN_NOTARY_ISSUER" --wait --timeout 30m
xcrun stapler staple "$DMG"
xcrun stapler validate "$DMG"
# What Gatekeeper says of the app inside, as a user's Mac would see it.
MNT=$(mktemp -d)
hdiutil attach -quiet -nobrowse -readonly -mountpoint "$MNT" "$DMG"
spctl --assess --type execute -vv "$MNT/MugVPN.app"
hdiutil detach -quiet "$MNT"
rmdir "$MNT"
(cd "$(dirname "$DMG")" && shasum -a 256 "$(basename "$DMG")" > "$(basename "$DMG").sha256")
echo "==> $DMG notarized; $(cat "$DMG.sha256")"

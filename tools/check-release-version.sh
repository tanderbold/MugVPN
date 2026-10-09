#!/bin/bash
# The app's version (Info.plist), the helper's (MugVPNIDs.helperVersion) and, given one, the
# release tag (v<version>) must agree: a release is never built under another version's name.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
app=$(/usr/libexec/PlistBuddy -c "Print CFBundleShortVersionString" "$ROOT/Resources/Info.plist")
helper=$(sed -n 's/.*static let helperVersion = "\([^"]*\)".*/\1/p' "$ROOT/Sources/MugVPNCore/HelperProtocol.swift")
[ -n "$app" ] && [ -n "$helper" ] || { echo "cannot read the versions (app '$app', helper '$helper')" >&2; exit 1; }
[ "$app" = "$helper" ] || { echo "the app is $app but the helper is $helper" >&2; exit 1; }
if [ $# -gt 0 ]; then
    [ "$1" = "v$app" ] || { echo "the tag $1 is not v$app (the version the app and helper carry)" >&2; exit 1; }
fi
echo "version $app${1:+ (tag $1)}"

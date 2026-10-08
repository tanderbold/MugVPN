#!/bin/bash
# Make Resources/AppIcon.icns from one 1024x1024 PNG (all the sizes macOS needs).
#   tools/icon/make-icns.sh path/to/icon-1024.png
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC="${1:?usage: make-icns.sh icon-1024.png}"
[ "$(sips -g pixelWidth "$SRC" | awk '/pixelWidth/ {print $2}')" = 1024 ] || { echo "the PNG must be 1024x1024" >&2; exit 1; }
SET="$(mktemp -d)/AppIcon.iconset"
mkdir -p "$SET"
for s in 16 32 128 256 512; do
    sips -z $s $s "$SRC" --out "$SET/icon_${s}x${s}.png" >/dev/null
    sips -z $((s * 2)) $((s * 2)) "$SRC" --out "$SET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$SET" -o "$ROOT/Resources/AppIcon.icns"
rm -rf "$(dirname "$SET")"
echo "==> $ROOT/Resources/AppIcon.icns"

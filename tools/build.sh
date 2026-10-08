#!/bin/bash
# Build MugVPN.app: the app, the privileged helper, and the bundled openvpn.
#
#   tools/build.sh                      universal (arm64 + x86_64)
#   MUGVPN_ARCH=native tools/build.sh   host architecture only
#
# Requires only the Xcode Command Line Tools. Signing is ad-hoc unless
# MUGVPN_SIGN_ID names a Developer ID identity and MUGVPN_TEAM its team.
# Output: build/MugVPN.app
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/build"
APP="$OUT/MugVPN.app"
SIGN_ID="${MUGVPN_SIGN_ID:--}"
TEAM="${MUGVPN_TEAM:-}"
cd "$ROOT"

# Rebuild openvpn when its build scripts changed (or it is missing): never
# sign and pin a binary nobody knows the origin of.
stamp=$(cat tools/build-openvpn.sh tools/patch-dns-updown.sh tools/patch-openvpn-privsep.py | shasum -a 256 | cut -d' ' -f1)
if [ ! -x "$OUT/openvpn/openvpn" ] || [ ! -x "$OUT/openvpn/openvpn-root" ] || [ "$(cat "$OUT/openvpn/stamp" 2>/dev/null)" != "$stamp" ]; then
    tools/build-openvpn.sh
fi
if [ "$SIGN_ID" != "-" ] && [ -z "$TEAM" ]; then
    echo "MUGVPN_SIGN_ID without MUGVPN_TEAM: the helper would accept any client named com.mugvpn.app" >&2
    exit 1
fi

# Without a Developer ID: a signing certificate of this Mac's own, made once, in a keychain
# only its user can read. The helper then accepts only an app signed with it: anyone can
# sign a program "com.mugvpn.app" ad hoc, nobody else holds this key.
# (MUGVPN_ADHOC=1: plain ad-hoc signing, for development only.)
LOCAL_LEAF=""
KEYCHAIN_ARGS=()
if [ "$SIGN_ID" = "-" ] && [ "${MUGVPN_ADHOC:-}" != 1 ]; then
    KDIR="$HOME/Library/Application Support/MugVPN Build"
    KC="$KDIR/signing.keychain-db"
    mkdir -p "$KDIR"; chmod 700 "$KDIR"
    if [ ! -f "$KC" ]; then
        echo "==> a local signing certificate for MugVPN (once, in $KDIR)"
        tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
        printf '[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=MugVPN Local Signing\n[ext]\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,codeSigning\nbasicConstraints=critical,CA:false\n' > "$tmp/cert.cnf"
        /usr/bin/openssl req -x509 -newkey rsa:2048 -nodes -keyout "$tmp/key.pem" -out "$tmp/cert.pem" -days 3650 -config "$tmp/cert.cnf" 2>/dev/null
        (umask 077; /usr/bin/openssl rand -hex 24 > "$KDIR/keychain-password")
        pw=$(cat "$KDIR/keychain-password")
        /usr/bin/openssl pkcs12 -export -inkey "$tmp/key.pem" -in "$tmp/cert.pem" -out "$tmp/id.p12" -passout "pass:$pw"
        security create-keychain -p "$pw" "$KC"
        security set-keychain-settings "$KC"   # no auto-lock: unlocked for each build below
        security unlock-keychain -p "$pw" "$KC"
        security import "$tmp/id.p12" -k "$KC" -P "$pw" -T /usr/bin/codesign >/dev/null
        security set-key-partition-list -S apple-tool:,apple: -s -k "$pw" "$KC" >/dev/null
        /usr/bin/openssl x509 -in "$tmp/cert.pem" -outform der > "$KDIR/certificate.der"
        rm -rf "$tmp"; trap - EXIT
    fi
    security unlock-keychain -p "$(cat "$KDIR/keychain-password")" "$KC"
    LOCAL_LEAF=$(shasum -a 1 "$KDIR/certificate.der" | cut -d' ' -f1)
    SIGN_ID=$(echo "$LOCAL_LEAF" | tr a-f A-F)
    # codesign finds a key only in the user's keychain search list: added for this build only.
    SEARCH=()
    while IFS= read -r k; do k="${k#"${k%%[![:space:]]*}"}"; k="${k%\"}"; k="${k#\"}"; [ -n "$k" ] && SEARCH+=("$k"); done < <(security list-keychains -d user)
    restore_search() { security list-keychains -d user -s ${SEARCH[@]+"${SEARCH[@]}"}; }
    trap restore_search EXIT
    security list-keychains -d user -s ${SEARCH[@]+"${SEARCH[@]}"} "$KC"
    KEYCHAIN_ARGS=(--keychain "$KC")
fi

echo "==> sign openvpn"
mkdir -p "$OUT/stage"
# One code directory hash per architecture: the helper checks every slice.
pin() {
    local req=""
    for arch in $(lipo -archs "$1"); do
        h=$(codesign -dvvv --arch "$arch" "$1" 2>&1 | sed -n 's/^CDHash=//p')
        req="${req:+$req or }cdhash H\\\"$h\\\""
    done
    echo "$req"
}
cp "$OUT/openvpn/openvpn" "$OUT/stage/openvpn"
cp "$OUT/openvpn/openvpn-root" "$OUT/stage/openvpn-root"
codesign ${KEYCHAIN_ARGS[@]+"${KEYCHAIN_ARGS[@]}"} --force --options runtime --identifier com.mugvpn.openvpn -s "$SIGN_ID" "$OUT/stage/openvpn"
codesign ${KEYCHAIN_ARGS[@]+"${KEYCHAIN_ARGS[@]}"} --force --options runtime --identifier com.mugvpn.openvpn-root -s "$SIGN_ID" "$OUT/stage/openvpn-root"
OPENVPN_REQ=$(pin "$OUT/stage/openvpn")
OPENVPN_ROOT_REQ=$(pin "$OUT/stage/openvpn-root")
DNS_SHA=$(shasum -a 256 "$OUT/openvpn/dns-updown" | cut -d' ' -f1)

# The helper trusts only what is pinned here: openvpn by its code directory
# hash, the DNS script by its SHA-256, and its XPC clients by signature. An
# ad-hoc build has no team to anchor clients to, so it checks the identifier
# alone: fine for local development, never for a release.
if [ -n "$TEAM" ]; then
    # Developer ID only (not Apple Development builds of the same team).
    CLIENT_REQ="identifier \\\"com.mugvpn.app\\\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \\\"$TEAM\\\""
elif [ -n "$LOCAL_LEAF" ]; then
    CLIENT_REQ="identifier \\\"com.mugvpn.app\\\" and certificate leaf = H\\\"$LOCAL_LEAF\\\""
else
    CLIENT_REQ="identifier \\\"com.mugvpn.app\\\""
    echo "warning: MUGVPN_ADHOC=1: the helper accepts any program signed as com.mugvpn.app (development only)"
fi
cat > Sources/MugVPNHelper/BuildPins.swift <<EOF
// Generated by tools/build.sh. Do not edit.
enum BuildPins {
    static let openvpnRequirement = "$OPENVPN_REQ"
    static let openvpnRootRequirement = "$OPENVPN_ROOT_REQ"
    static let dnsUpdownSHA256 = "$DNS_SHA"
    static let clientRequirement = "$CLIENT_REQ"
}
EOF

# MUGVPN_TESTING=1: the build the stand's tests drive (E2E socket, developer
# subcommands). Never packaged: tools/make-dmg.sh refuses it.
SWIFT_FLAGS=()
if [ "${MUGVPN_TESTING:-}" = 1 ]; then SWIFT_FLAGS=(-Xswiftc -DMUGVPN_TESTING); fi
echo "==> swift build${MUGVPN_TESTING:+ (testing)}"
if [ "${MUGVPN_ARCH:-universal}" = "native" ]; then
    swift build -c release ${SWIFT_FLAGS[@]+"${SWIFT_FLAGS[@]}"} >/dev/null
    BIN="$(swift build -c release ${SWIFT_FLAGS[@]+"${SWIFT_FLAGS[@]}"} --show-bin-path)"
else
    # One architecture at a time: `--arch a --arch b` needs Xcode's xcbuild.
    BIN="$OUT/universal-bin"
    mkdir -p "$BIN"
    parts=()
    for arch in arm64 x86_64; do
        # A build folder per architecture: sharing one confuses SwiftPM's build database.
        swift build -c release ${SWIFT_FLAGS[@]+"${SWIFT_FLAGS[@]}"} --triple "$arch-apple-macosx13.0" --scratch-path "$ROOT/.build-$arch" >/dev/null
        parts+=("$(swift build -c release ${SWIFT_FLAGS[@]+"${SWIFT_FLAGS[@]}"} --triple "$arch-apple-macosx13.0" --scratch-path "$ROOT/.build-$arch" --show-bin-path)")
    done
    for exe in MugVPN MugVPNHelper; do
        lipo -create "${parts[0]}/$exe" "${parts[1]}/$exe" -output "$BIN/$exe"
    done
fi

echo "==> bundle"
rm -rf "$APP"
mkdir -p "$APP/Contents/"{MacOS,Helpers,Resources,Library/LaunchDaemons}
cp "$BIN/MugVPN" "$BIN/MugVPNHelper" "$APP/Contents/MacOS/"
cp "$OUT/stage/openvpn" "$OUT/stage/openvpn-root" "$APP/Contents/Helpers/"
cp "$OUT/openvpn/dns-updown" "$APP/Contents/Resources/dns-updown"
cp Resources/Info.plist "$APP/Contents/Info.plist"
cp -R Resources/*.lproj "$APP/Contents/Resources/"
cp THIRD-PARTY-NOTICES.txt LICENSE "$APP/Contents/Resources/"
cp Resources/menubar/*.png "$APP/Contents/Resources/"
if [ "${MUGVPN_TESTING:-}" = 1 ]; then echo "E2E socket and developer subcommands" > "$APP/Contents/Resources/testing-build"; fi
# The app icon, once there is one (tools/icon/make-icns.sh).
[ -f Resources/AppIcon.icns ] && cp Resources/AppIcon.icns "$APP/Contents/Resources/"
cp Resources/com.mugvpn.helper.plist "$APP/Contents/Library/LaunchDaemons/"

echo "==> sign"
codesign ${KEYCHAIN_ARGS[@]+"${KEYCHAIN_ARGS[@]}"} --force --options runtime --identifier com.mugvpn.helper -s "$SIGN_ID" "$APP/Contents/MacOS/MugVPNHelper"
codesign ${KEYCHAIN_ARGS[@]+"${KEYCHAIN_ARGS[@]}"} --force --options runtime --identifier com.mugvpn.app -s "$SIGN_ID" "$APP"
codesign --verify --deep --strict "$APP"
echo "==> $APP"

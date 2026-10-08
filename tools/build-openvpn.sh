#!/bin/bash
# Build the openvpn binary MugVPN ships, statically linked against its own
# OpenSSL, LZ4 and LZO, from pinned and checksummed sources.
#
#   tools/build-openvpn.sh                      universal (arm64 + x86_64)
#   MUGVPN_ARCH=native tools/build-openvpn.sh   host architecture only
#
# Output: build/openvpn/openvpn
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/third_party/src"
WORK="$ROOT/build/deps"
OUT="$ROOT/build/openvpn"
MIN_MACOS=13.0
JOBS="$(sysctl -n hw.ncpu)"
# openvpn's build asks git for its version; it must not find MugVPN's own repository.
export GIT_CEILING_DIRECTORIES="$ROOT/build"
# openvpn's default DNS script, compiled in. MugVPN's openvpn never runs it (the helper sets
# DNS), but the path it names stays one only root could ever write to.
DNS_UPDOWN="/Library/Application Support/MugVPN/libexec/dns-updown"
# OpenSSL compiles in where it looks for openssl.cnf, providers and engines,
# and openvpn (as root) loads that config at start. They must point where no
# one but root can ever put a file: under /var/empty, which stays empty.
SSL_ROOT=/var/empty/mugvpn-openssl

# The SHA-256 pins were checked once against the projects' signatures (2026-10-07):
#   openvpn-2.7.8.tar.gz.asc  good, OpenVPN security list key F554 A368 7412 CFFE BDEF E0A3 12F5 F7B4 2F2B 01E7
#   openssl-3.5.9.tar.gz.asc  good, OpenSSL key B146 647E 45A7 B339 47AB 226B 2A2C 87D1 6169 2D40
#                             (listed on https://openssl-library.org/source/)
#   LZ4 and LZO publish no signatures: their SHA-256 pins are from the official release files.
# A new version gets the same check before its pin changes.
OPENVPN_VER=2.7.8
OPENVPN_SHA=c070d1d2440b5a6fca6c2c68645c98cd492116ac36ef4f0946177115532c8e36
OPENSSL_VER=3.5.9
OPENSSL_SHA=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
LZ4_VER=1.10.0
LZ4_SHA=537512904744b35e232912055ccf8ec66d768639ff3abe5788d90d792ec5f48b
LZO_VER=2.10
LZO_SHA=c0f892943208266f9b6543b3ae308fab6284c5c90e627931446fb49b4221a072

fetch() { # url file sha
    local url=$1 file=$2 sha=$3
    mkdir -p "$SRC"
    [ -f "$SRC/$file" ] || curl -fsSL "$url" -o "$SRC/$file"
    echo "$sha  $SRC/$file" | shasum -a 256 -c --quiet - || { echo "checksum mismatch: $file" >&2; exit 1; }
}

fetch "https://github.com/OpenVPN/openvpn/releases/download/v$OPENVPN_VER/openvpn-$OPENVPN_VER.tar.gz" "openvpn-$OPENVPN_VER.tar.gz" $OPENVPN_SHA
fetch "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VER/openssl-$OPENSSL_VER.tar.gz" "openssl-$OPENSSL_VER.tar.gz" $OPENSSL_SHA
fetch "https://github.com/lz4/lz4/releases/download/v$LZ4_VER/lz4-$LZ4_VER.tar.gz" "lz4-$LZ4_VER.tar.gz" $LZ4_SHA
fetch "https://www.oberhumer.com/opensource/lzo/download/lzo-$LZO_VER.tar.gz" "lzo-$LZO_VER.tar.gz" $LZO_SHA

if [ "${MUGVPN_ARCH:-universal}" = "native" ]; then
    ARCHES=("$(uname -m)")
else
    ARCHES=(arm64 x86_64)
fi

build_arch() {
    local arch=$1
    local dir="$WORK/$arch" prefix="$WORK/$arch/prefix"
    local host; [ "$arch" = arm64 ] && host=aarch64-apple-darwin || host=x86_64-apple-darwin
    # File names in asserts and errors relative to the tree, not the builder's home.
    local cflags="-arch $arch -mmacosx-version-min=$MIN_MACOS -O2 -ffile-prefix-map=$ROOT=."
    rm -rf "$dir"; mkdir -p "$dir" "$prefix"

    echo "==> [$arch] OpenSSL $OPENSSL_VER"
    tar -xzf "$SRC/openssl-$OPENSSL_VER.tar.gz" -C "$dir"
    (cd "$dir/openssl-$OPENSSL_VER" &&
        ./Configure "darwin64-$arch-cc" no-shared no-tests no-docs no-apps no-legacy no-engine no-dso \
            --prefix="$SSL_ROOT" --openssldir="$SSL_ROOT/ssl" --libdir=lib -mmacosx-version-min=$MIN_MACOS >/dev/null &&
        make -j"$JOBS" >/dev/null && make install_sw DESTDIR="$dir/ssl-dest" >/dev/null)
    mkdir -p "$prefix/include" "$prefix/lib"
    cp -R "$dir/ssl-dest$SSL_ROOT/include/." "$prefix/include/"
    cp "$dir/ssl-dest$SSL_ROOT/lib/"{libssl.a,libcrypto.a} "$prefix/lib/"

    echo "==> [$arch] LZ4 $LZ4_VER"
    tar -xzf "$SRC/lz4-$LZ4_VER.tar.gz" -C "$dir"
    make -C "$dir/lz4-$LZ4_VER/lib" -j"$JOBS" CFLAGS="$cflags" liblz4.a >/dev/null
    mkdir -p "$prefix/include" "$prefix/lib"
    cp "$dir/lz4-$LZ4_VER/lib/"{lz4.h,lz4hc.h,lz4frame.h} "$prefix/include/"
    cp "$dir/lz4-$LZ4_VER/lib/liblz4.a" "$prefix/lib/"

    echo "==> [$arch] LZO $LZO_VER"
    tar -xzf "$SRC/lzo-$LZO_VER.tar.gz" -C "$dir"
    (cd "$dir/lzo-$LZO_VER" &&
        CFLAGS="$cflags" ./configure --host=$host --prefix="$prefix" --disable-shared >/dev/null &&
        make -j"$JOBS" >/dev/null && make install >/dev/null)

    echo "==> [$arch] openvpn $OPENVPN_VER"
    # Nothing root openvpn does not need: no plug-ins
    # (no code loaded from a path, whatever a profile says), no debug output
    # (key and packet dumps at verb 7+), no server-only or legacy features.
    # With MugVPN's patch (-DMUGVPN_MGMT_TUN): it runs without root and asks the helper
    # for its tunnel, routes and DNS.
    for flavour in privsep; do
        mkdir -p "$dir/$flavour"
        tar -xzf "$SRC/openvpn-$OPENVPN_VER.tar.gz" -C "$dir/$flavour"
        local extra=""
        if [ "$flavour" = privsep ]; then
            python3 "$ROOT/tools/patch-openvpn-privsep.py" "$dir/$flavour/openvpn-$OPENVPN_VER" >/dev/null
            extra="-DMUGVPN_MGMT_TUN"
        fi
        (cd "$dir/$flavour/openvpn-$OPENVPN_VER" &&
            CFLAGS="$cflags $extra" \
            OPENSSL_CFLAGS="-I$prefix/include" OPENSSL_LIBS="$prefix/lib/libssl.a $prefix/lib/libcrypto.a" \
            CPPFLAGS="-I$prefix/include" LDFLAGS="-L$prefix/lib" \
            LZ4_CFLAGS="-I$prefix/include" LZ4_LIBS="-llz4" \
            LZO_CFLAGS="-I$prefix/include" LZO_LIBS="-llzo2" \
            ./configure --host=$host --disable-plugins --disable-debug --disable-port-share \
                --with-openssl-engine=no --disable-ofb-cfb \
                --disable-pkcs11 --enable-lzo --enable-lz4 >/dev/null &&
            sed -i '' "s|-DDEFAULT_DNS_UPDOWN=[^ ]*|'-DDEFAULT_DNS_UPDOWN=\"$DNS_UPDOWN\"'|" src/openvpn/Makefile &&
            make -j"$JOBS" >/dev/null)
    done
}

for a in "${ARCHES[@]}"; do build_arch "$a"; done

mkdir -p "$OUT"
for flavour in privsep; do
    name=openvpn
    bins=(); for a in "${ARCHES[@]}"; do bins+=("$WORK/$a/$flavour/openvpn-$OPENVPN_VER/src/openvpn/openvpn"); done
    lipo -create "${bins[@]}" -output "$OUT/$name"
    # No path a user could write to may be compiled in (OpenSSL's config, modules, engines).
    # (Into a file first: with pipefail, `strings | grep -q` fails when grep stops early.)
    strings "$OUT/$name" > "$WORK/strings.txt"
    if grep -E '^(OPENSSLDIR|MODULESDIR|ENGINESDIR):' "$WORK/strings.txt" | grep -v "\"$SSL_ROOT"; then
        echo "$name names a directory outside $SSL_ROOT" >&2; exit 1
    fi
    # The compiled-in DNS script path is the root-only one (the Makefile edit took).
    grep -qF "$DNS_UPDOWN" "$WORK/strings.txt" || { echo "$name does not name $DNS_UPDOWN" >&2; exit 1; }
    if grep -F "$ROOT" "$WORK/strings.txt"; then
        echo "$name names the build directory $ROOT" >&2; exit 1
    fi
done
# The patch took: the privsep build asks for its tunnel.
strings "$OUT/openvpn" > "$WORK/strings.txt"
grep -qF "MugVPN's helper did not open a tunnel" "$WORK/strings.txt" || { echo "openvpn lacks MugVPN's privsep patch" >&2; exit 1; }
# What this binary was built from: tools/build.sh rebuilds when it changes.
cat "$ROOT/tools/build-openvpn.sh" "$ROOT/tools/patch-openvpn-privsep.py" | shasum -a 256 | cut -d' ' -f1 > "$OUT/stamp"
echo "==> $OUT/openvpn"
"$OUT/openvpn" --version | head -1
otool -L "$OUT/openvpn" | tail -n +2

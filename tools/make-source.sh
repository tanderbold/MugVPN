#!/bin/bash
# The complete corresponding source of a release (GPL-2.0 section 3): MugVPN's source at its tag (with the openvpn
# patch and the build scripts), the pinned source archives of what it bundles (openvpn, OpenSSL, LZ4, LZO, as
# tools/build-openvpn.sh fetched them, their SHA-256 checked again), and their checksums.
#   tools/make-source.sh v<version>   ->  build/MugVPN-<version>-source.tar.gz
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tag=${1:?usage: tools/make-source.sh v<version>}
ver=${tag#v}
git -C "$ROOT" rev-parse -q --verify "refs/tags/$tag" >/dev/null || { echo "no tag $tag" >&2; exit 1; }
v() { sed -n "s/^$1=//p" "$ROOT/tools/build-openvpn.sh"; }
name="MugVPN-$ver-source"
out="$ROOT/build/$name"
rm -rf "$out" "$out.tar.gz"
mkdir -p "$out/third_party"
git -C "$ROOT" archive --format=tar --prefix="MugVPN-$ver/" "$tag" | tar -x -C "$out"
# The archives as pinned in that tag's build script (not today's).
pins=$(git -C "$ROOT" show "$tag:tools/build-openvpn.sh")
pv() { sed -n "s/^$1=//p" <<<"$pins"; }
for a in "openvpn-$(pv OPENVPN_VER).tar.gz:$(pv OPENVPN_SHA)" "openssl-$(pv OPENSSL_VER).tar.gz:$(pv OPENSSL_SHA)" \
         "lz4-$(pv LZ4_VER).tar.gz:$(pv LZ4_SHA)" "lzo-$(pv LZO_VER).tar.gz:$(pv LZO_SHA)"; do
    f=${a%%:*} sum=${a##*:}
    [ -f "$ROOT/third_party/src/$f" ] || { echo "missing third_party/src/$f: run tools/build-openvpn.sh" >&2; exit 1; }
    [ "$(shasum -a 256 "$ROOT/third_party/src/$f" | cut -d' ' -f1)" = "$sum" ] || { echo "$f is not the pinned archive" >&2; exit 1; }
    cp "$ROOT/third_party/src/$f" "$out/third_party/"
done
cat > "$out/README.txt" <<TXT
MugVPN $ver: the complete corresponding source of its release.

MugVPN-$ver/      MugVPN's source at tag $tag (MIT; tools/patch-openvpn-privsep.py and the openvpn files it
                  changes are GPL-2.0 with OpenVPN's linking exceptions, LICENSES/OpenVPN-exceptions.txt)
third_party/      the source archives of what the app bundles, as released by their authors
SHA256SUMS        their checksums

To build: copy third_party/* to MugVPN-$ver/third_party/src/, then run MugVPN-$ver/tools/build-openvpn.sh
(openvpn, patched) and MugVPN-$ver/tools/build.sh (the app) on macOS with Xcode's command line tools.
TXT
(cd "$out/third_party" && shasum -a 256 *.tar.gz) > "$out/SHA256SUMS"
tar -czf "$out.tar.gz" -C "$ROOT/build" "$name"
rm -rf "$out"
echo "==> $out.tar.gz"

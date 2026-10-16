#!/bin/bash
# Write THIRD-PARTY-NOTICES.txt from the license files inside the pinned
# source archives of what MugVPN bundles (versions from tools/build-openvpn.sh).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/third_party/src"
ver() { sed -n "s/^$1_VER=//p" "$ROOT/tools/build-openvpn.sh"; }
OPENVPN=$(ver OPENVPN); OPENSSL=$(ver OPENSSL); LZ4=$(ver LZ4); LZO=$(ver LZO)
for t in "openvpn-$OPENVPN" "openssl-$OPENSSL" "lz4-$LZ4" "lzo-$LZO"; do
    [ -f "$SRC/$t.tar.gz" ] || { echo "missing $SRC/$t.tar.gz: run tools/build-openvpn.sh" >&2; exit 1; }
done
from() { tar -xzOf "$SRC/$1.tar.gz" "$1/$2"; }
rule() { printf '\n%s\n%s\n\n' "================================================================================" "$1"; }
{
cat <<HEAD
MugVPN — third-party notices

MugVPN itself is under the MIT License (see LICENSE). The app bundle also contains
the following programs and libraries, each under its own license. MugVPN runs
openvpn as a separate program; it does not link to it.

  openvpn $OPENVPN      Contents/Helpers/openvpn        GNU GPL version 2 (with OpenSSL and Apache-2.0 linking exceptions)
  OpenSSL $OPENSSL      linked into openvpn             Apache License 2.0
  LZ4 $LZ4             linked into openvpn             BSD 2-Clause
  LZO $LZO              linked into openvpn             GNU GPL version 2

Source code. These are built from the official releases below, by
tools/build-openvpn.sh in MugVPN's source (which pins each archive's SHA-256).
The libraries are unmodified. Contents/Helpers/openvpn is openvpn changed by
tools/patch-openvpn-privsep.py (in MugVPN's source, under
openvpn's license, GPL-2.0) to run without root and ask MugVPN's helper for its tunnel:
  https://github.com/OpenVPN/openvpn/releases/download/v$OPENVPN/openvpn-$OPENVPN.tar.gz
  https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL/openssl-$OPENSSL.tar.gz
  https://github.com/lz4/lz4/releases/download/v$LZ4/lz4-$LZ4.tar.gz
  https://www.oberhumer.com/opensource/lzo/download/lzo-$LZO.tar.gz
Changes made by MugVPN: besides that patch, openvpn is configured so that its default
DNS script is "/Library/Application Support/MugVPN/libexec/dns-updown" (a build setting,
no source change). MugVPN's patches and build
scripts are published at https://github.com/tanderbold/MugVPN, the archives at the
official addresses above (their SHA-256 pinned in tools/build-openvpn.sh). Each release
of MugVPN carries the complete corresponding source of the version it is, as
MugVPN-<version>-source.tar.gz among the release's files (MugVPN's source at the
release's tag, these archives, the patch and build scripts), and its tag
(https://github.com/tanderbold/MugVPN/tree/v<version>) stays. On request (open an issue
there) the same source is also available from the MugVPN authors for three years from
the date of distribution.

"OpenVPN" is a trademark of OpenVPN Inc. MugVPN is not affiliated with or endorsed
by OpenVPN Inc.
HEAD
rule "openvpn $OPENVPN — COPYING"
from "openvpn-$OPENVPN" COPYING
rule "openvpn $OPENVPN — GNU General Public License version 2 (COPYRIGHT.GPL)"
from "openvpn-$OPENVPN" COPYRIGHT.GPL
rule "OpenSSL $OPENSSL — Apache License 2.0 (LICENSE.txt)"
from "openssl-$OPENSSL" LICENSE.txt
rule "LZ4 $LZ4 — library license (BSD 2-Clause, lib/LICENSE)"
from "lz4-$LZ4" lib/LICENSE
# Each source liblz4.a is built from has a notice of its own (lz4file.c another copyright holder's): each one, as
# its file's first comment. (make liblz4.a builds every lib/*.c.)
for c in $(tar -tzf "$SRC/lz4-$LZ4.tar.gz" | grep -E "^lz4-$LZ4/lib/[^/]+\.c$" | sort); do
    rule "LZ4 $LZ4 — ${c#lz4-$LZ4/} (in liblz4.a, linked into openvpn)"
    tar -xzOf "$SRC/lz4-$LZ4.tar.gz" "$c" | awk '!done && /\/\*/ { on = 1 } on && !done { print } on && /\*\// { on = 0; done = 1 }'
done
rule "LZO $LZO — COPYING (GNU General Public License version 2)"
from "lzo-$LZO" COPYING
} > "$ROOT/THIRD-PARTY-NOTICES.txt"
echo "==> $ROOT/THIRD-PARTY-NOTICES.txt ($(wc -l < "$ROOT/THIRD-PARTY-NOTICES.txt") lines)"

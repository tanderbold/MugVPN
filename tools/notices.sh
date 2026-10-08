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

  openvpn $OPENVPN      Contents/Helpers/openvpn,       GNU GPL version 2 (with OpenSSL and Apache-2.0 linking exceptions)
                       Contents/Helpers/openvpn-root
  OpenSSL $OPENSSL      linked into openvpn             Apache License 2.0
  LZ4 $LZ4             linked into openvpn             BSD 2-Clause
  LZO $LZO              linked into openvpn             GNU GPL version 2
  dns-updown           Contents/Resources/dns-updown   BSD-2-Clause, OpenVPN Inc

Source code. These are built from the official releases below, by
tools/build-openvpn.sh in MugVPN's source (which pins each archive's SHA-256).
Contents/Helpers/openvpn-root and the libraries are unmodified. Contents/Helpers/openvpn
is openvpn changed by tools/patch-openvpn-privsep.py (in MugVPN's source, under
openvpn's license, GPL-2.0) to run without root and ask MugVPN's helper for its tunnel:
  https://github.com/OpenVPN/openvpn/releases/download/v$OPENVPN/openvpn-$OPENVPN.tar.gz
  https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL/openssl-$OPENSSL.tar.gz
  https://github.com/lz4/lz4/releases/download/v$LZ4/lz4-$LZ4.tar.gz
  https://www.oberhumer.com/opensource/lzo/download/lzo-$LZO.tar.gz
Changes made by MugVPN: openvpn is configured so that its default DNS script is
"/Library/Application Support/MugVPN/libexec/dns-updown" (a build setting, no source
change); the DNS script (openvpn's distro/dns-scripts/macos-dns-updown.sh) gets a
small addition for split DNS, made by tools/patch-dns-updown.sh. The complete
corresponding source of the GPL components (the archives above and MugVPN's
patches) is published at https://github.com/tanderbold/MugVPN; on request (open an
issue there) it is also available from the MugVPN authors for three years from
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
rule "LZO $LZO — COPYING (GNU General Public License version 2)"
from "lzo-$LZO" COPYING
rule "dns-updown — macos-dns-updown.sh from openvpn $OPENVPN (BSD-2-Clause)"
cat <<'BSD'
Copyright (C) 2025-2026 OpenVPN Inc <sales@openvpn.net>
SPDX-License-Identifier: BSD-2-Clause

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
BSD
} > "$ROOT/THIRD-PARTY-NOTICES.txt"
echo "==> $ROOT/THIRD-PARTY-NOTICES.txt ($(wc -l < "$ROOT/THIRD-PARTY-NOTICES.txt") lines)"

#!/bin/bash
# Usage: tools/patch-dns-updown.sh <openvpn macos-dns-updown.sh> <output>
set -euo pipefail
# MugVPN's change to openvpn's macOS DNS script: when the helper put a
# `split-dns` marker in the connection's run directory (a profile setting in
# the app; openvpn runs the script there), pushed search domains (legacy
# dhcp-option DOMAIN) become split domains instead of taking over all DNS.
# openvpn gives the script only DNS variables, so an environment variable
# would not reach it.
script="$1"
[ "$(grep -c 'local match_domains="$(match_domains_string $n)"' "$script")" = 2 ] || {
    echo "openvpn's macos-dns-updown.sh changed: review MugVPN's split DNS patch" >&2; exit 1; }
[ "$(grep -c '^lockdir=/var/lock$' "$script")" = 1 ] && [ "$(grep -c '/bin/chmod 1777 "${lockdir}"' "$script")" = 1 ] || {
    echo "openvpn's macos-dns-updown.sh changed: review MugVPN's lock directory patch" >&2; exit 1; }
# The lock lives where only root can write: in the world-writable /var/lock
# anyone could hold it and stop every tunnel's DNS changes.
# openvpn runs the script as root with no PATH at all, and bash then looks in
# /usr/local/bin and "." too: set it first thing.
[ "$(head -1 "$script")" = "#!/bin/bash" ] || { echo "openvpn's macos-dns-updown.sh changed: review the PATH line" >&2; exit 1; }
sed -e '1a\
PATH=/usr/bin:/bin:/usr/sbin:/sbin; export PATH # MugVPN
' \
    -e 's|^\( *\)/usr/bin/dscacheutil -flushcache$|&\
\1/usr/bin/killall -HUP mDNSResponder 2>/dev/null \|\| true # MugVPN: drop cached answers of the old DNS too|' \
    -e 's|^lockdir=/var/lock$|lockdir=/var/run/mugvpn|' \
    -e 's|/bin/chmod 1777 "${lockdir}"|/bin/chmod 700 "${lockdir}"|' \
    -e 's/local match_domains="$(match_domains_string $n)"/local match_domains="$(effective_match_domains $n)"/' \
    -e '/^function set_dns {/i\
# MugVPN: with a split-dns marker, search domains serve as match domains.\
function effective_match_domains {\
    local m="$(match_domains_string $1)"\
    if [ -z "$m" ] \&\& [ -f ./split-dns ]; then\
        m="$(search_domains_string $1)"\
    fi\
    echo "$m"\
}\
' "$script" > "$2"
grep -q 'effective_match_domains' "$2" || { echo "split DNS patch failed" >&2; exit 1; }
[ "$(sed -n 2p "$2")" = "PATH=/usr/bin:/bin:/usr/sbin:/sbin; export PATH # MugVPN" ] || { echo "PATH patch failed" >&2; exit 1; }
[ "$(grep -c 'killall -HUP mDNSResponder' "$2")" = "$(grep -c 'dscacheutil -flushcache' "$2")" ] || { echo "cache flush patch failed" >&2; exit 1; }

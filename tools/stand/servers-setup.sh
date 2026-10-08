#!/bin/bash
# Test stand: OpenVPN servers for MugVPN's integration tests. Runs as root on
# the Ubuntu VM "mugvpn-servers" (tools/stand/stand.sh pushes and runs it).
#
# Tart keeps its VMs apart (no traffic between them on the shared NAT), so
# the Mac VM reaches the servers through ssh port forwards over the host
# (stand.sh tunnel): 127.0.0.1:1194-1197 on the Mac VM. ssh forwards TCP only,
# hence every server here is TCP.
#
#   a  tcp/1194  tunnel 10.81.0.0/24, network 10.91.0.0/24 behind it,
#                DNS pushed the 2.6+ way: --dns, split domain a.test
#   b  tcp/1195  tunnel 10.82.0.0/24, network 10.92.0.0/24 behind it,
#                DNS pushed the legacy way: dhcp-option DNS/DOMAIN b.test
#   c  tcp/1196  tunnel 10.83.0.0/24, network 10.93.0.0/24 behind it,
#                username/password (test / secret) on top of certificates
#   d  tcp/1197  tunnel 10.84.0.0/24, pushes redirect-gateway def1; duplicate-cn,
#                so two profiles can be up on it at once (conflict tests)
#
# On each server, host.<x>.test resolves to the address of the network behind it.
# Client profiles land in /etc/openvpn/stand/clients/*.ovpn.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
if ! command -v openvpn >/dev/null || ! command -v dnsmasq >/dev/null; then
    apt-get update -qq
    apt-get install -y -qq openvpn easy-rsa dnsmasq-base >/dev/null
fi

STAND=/etc/openvpn/stand  # not under /root: the systemd unit hides home dirs
mkdir -p "$STAND/clients"
cd "$STAND"

if [ ! -f pki/issued/client.crt ]; then
    rm -rf pki
    cp -r /usr/share/easy-rsa/* .
    export EASYRSA_BATCH=1
    ./easyrsa init-pki >/dev/null
    EASYRSA_REQ_CN="MugVPN test CA" ./easyrsa build-ca nopass >/dev/null 2>&1
    ./easyrsa build-server-full server nopass >/dev/null 2>&1
    ./easyrsa build-client-full client nopass >/dev/null 2>&1
    openvpn --genkey tls-crypt tc.key
fi

cat > /usr/local/bin/stand-auth <<'EOF'
#!/bin/sh
# auth-user-pass-verify via-file: line 1 user, line 2 password
u=$(sed -n 1p "$1"); p=$(sed -n 2p "$1")
[ "$u" = test ] && [ "$p" = secret ]
EOF
chmod 755 /usr/local/bin/stand-auth

server() { # name proto port subnet-octet extra...
    local n=$1 proto=$2 port=$3 o=$4; shift 4
    local behind="10.9${o}.0.1"
    # The network behind the server and its DNS come up at every boot.
    cat > /etc/systemd/system/stand-net@$n.service <<UNIT
[Unit]
Description=MugVPN stand: network and DNS behind server $n
Before=openvpn-server@$n.service

[Service]
Type=forking
ExecStartPre=-/sbin/ip link add dummy-$n type dummy
ExecStartPre=/sbin/ip addr replace $behind/24 dev dummy-$n
ExecStartPre=/sbin/ip link set dummy-$n up
ExecStart=/usr/sbin/dnsmasq --conf-file=/dev/null --pid-file=/run/dnsmasq-stand-$n.pid --bind-dynamic --listen-address=10.8${o}.0.1 --no-resolv --no-hosts --address=/host.$n.test/$behind --address=/stand-$n/127.0.0.1
PIDFile=/run/dnsmasq-stand-$n.pid

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    pkill -f "dnsmasq.*stand-$n" || true
    systemctl enable stand-net@$n >/dev/null 2>&1
    systemctl restart stand-net@$n
    cat > /etc/openvpn/server/$n.conf <<EOF
dev tun-$n
dev-type tun
proto $proto
port $port
topology subnet
server 10.8${o}.0.0 255.255.255.0
push "route 10.9${o}.0.0 255.255.255.0"
ca $STAND/pki/ca.crt
cert $STAND/pki/issued/server.crt
key $STAND/pki/private/server.key
dh none
tls-crypt $STAND/tc.key
keepalive 5 30
verb 3
$(printf '%s\n' "$@")
EOF
    systemctl enable --now openvpn-server@$n >/dev/null 2>&1
    systemctl restart openvpn-server@$n
    client $n $proto $port
}

client() { # name proto port
    local n=$1 proto=$2 port=$3
    {
        echo "client"
        echo "dev tun"
        echo "proto tcp-client"
        echo "remote 127.0.0.1 $port"
        echo "nobind"
        echo "persist-key"
        echo "remote-cert-tls server"
        echo "verb 3"
        [ "$n" = c ] && echo "auth-user-pass"
        echo "<ca>"; cat pki/ca.crt; echo "</ca>"
        echo "<cert>"; sed -n '/BEGIN/,/END/p' pki/issued/client.crt; echo "</cert>"
        echo "<key>"; cat pki/private/client.key; echo "</key>"
        echo "<tls-crypt>"; cat tc.key; echo "</tls-crypt>"
    } > "clients/stand-$n.ovpn"
}

server a tcp-server 1194 1 \
    'push "dns server 1 address 10.81.0.1"' \
    'push "dns server 1 resolve-domains a.test"'
server b tcp-server 1195 2 \
    'push "dhcp-option DNS 10.82.0.1"' \
    'push "dhcp-option DOMAIN b.test"'
server c tcp-server 1196 3 \
    'script-security 2' \
    'auth-user-pass-verify /usr/local/bin/stand-auth via-file' \
    'push "dns server 1 address 10.83.0.1"' \
    'push "dns server 1 resolve-domains c.test"'
server d tcp-server 1197 4 \
    'duplicate-cn' \
    'push "redirect-gateway def1"' \
    'push "dns server 1 address 10.84.0.1"'

server e tcp-server 1198 5 \
    'push "dns server 1 address 10.85.0.1"' \
    'push "dns server 1 resolve-domains e.test"'
server f tcp-server 1199 6 \
    'push "dhcp-option DNS 10.86.0.1"' \
    'push "dhcp-option DOMAIN f.test"'

sleep 2
for n in a b c d e f; do
    printf '%s: %s, net %s\n' "$n" "$(systemctl is-active openvpn-server@$n)" "$(systemctl is-active stand-net@$n)"
done
ls clients

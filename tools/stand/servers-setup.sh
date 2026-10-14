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

# Web sign-in (server g): the password check is deferred, the client given a URL to open; opening it
# (https://127.0.0.1:8080/ok/<id> in the Mac VM, through stand.sh tunnel) signs it in.
mkdir -p /run/stand-webauth
cat > /usr/local/bin/stand-webauth <<'EOF'
#!/bin/sh
id=$(basename "$auth_control_file")
mkdir -p /run/stand-webauth
echo "$auth_control_file" > "/run/stand-webauth/$id"
printf '300\nwebauth\nWEB_AUTH::https://127.0.0.1:8080/ok/%s\n' "$id" > "$auth_pending_file"
exit 2
EOF
chmod 755 /usr/local/bin/stand-webauth
cat > /usr/local/bin/stand-webauth-site <<'EOF'
#!/usr/bin/env python3
import http.server, os, ssl
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parts = self.path.strip("/").split("/")
        f = f"/run/stand-webauth/{parts[1]}" if len(parts) == 2 and parts[0] == "ok" and parts[1].replace("_", "").replace(".", "").isalnum() else None
        ok = f is not None and os.path.exists(f)
        if ok:
            open(open(f).read().strip(), "w").write("1")
        self.send_response(200 if ok else 404)
        self.end_headers()
        self.wfile.write(b"signed in\n" if ok else b"no such sign-in\n")
srv = http.server.HTTPServer(("0.0.0.0", 8080), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/etc/openvpn/stand/pki/issued/server.crt", "/etc/openvpn/stand/pki/private/server.key")
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
EOF
chmod 755 /usr/local/bin/stand-webauth-site
cat > /etc/systemd/system/stand-webauth.service <<'UNIT'
[Unit]
Description=MugVPN stand: the web sign-in page of server g
[Service]
ExecStart=/usr/local/bin/stand-webauth-site
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable stand-webauth >/dev/null 2>&1
systemctl restart stand-webauth

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
ExecStartPre=-/sbin/ip -6 addr replace fd00:9${o}::1/64 dev dummy-$n
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
        { [ "$n" = c ] || [ "$n" = g ]; } && echo "auth-user-pass"
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
    'server-ipv6 fd00:85::/64' \
    'push "route-ipv6 fd00:95::/64"' \
    'push "dns server 1 address 10.85.0.1"' \
    'push "dns server 1 resolve-domains e.test"'
server f tcp-server 1199 6 \
    'push "dhcp-option DNS 10.86.0.1"' \
    'push "dhcp-option DOMAIN f.test"'
server g tcp-server 1200 7 \
    'script-security 2' \
    'tmp-dir /run/openvpn-server' \
    'auth-user-pass-verify /usr/local/bin/stand-webauth via-file' \
    'push "dns server 1 address 10.87.0.1"' \
    'push "dns server 1 resolve-domains g.test"'

# An HTTP proxy that asks for a password (proxy / proxypass), reached in the Mac VM as 127.0.0.1:3128 (stand.sh
# tunnel): CONNECT to the servers above only.
command -v tinyproxy >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tinyproxy >/dev/null
cat > /etc/tinyproxy/tinyproxy.conf <<'PROXY'
User tinyproxy
Group tinyproxy
Port 3128
Listen 0.0.0.0
Timeout 600
LogLevel Info
MaxClients 50
BasicAuth proxy proxypass
ConnectPort 1194
ConnectPort 1195
ConnectPort 1196
ConnectPort 1197
ConnectPort 1198
ConnectPort 1199
PROXY
systemctl enable tinyproxy >/dev/null 2>&1
systemctl restart tinyproxy

sleep 2
printf 'proxy: %s\n' "$(systemctl is-active tinyproxy)"
printf 'web sign-in: %s\n' "$(systemctl is-active stand-webauth)"
for n in a b c d e f g; do
    printf '%s: %s, net %s\n' "$n" "$(systemctl is-active openvpn-server@$n)" "$(systemctl is-active stand-net@$n)"
done
ls clients

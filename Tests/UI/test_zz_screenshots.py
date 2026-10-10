"""Screenshots for the README and the site. Not a test: runs only when
~/mugvpn/make-screenshots exists in the VM (tools/stand/stand.sh ui
test_zz_screenshots.py after creating it); pictures go to ~/mugvpn/screenshots."""
import os
import time

import pytest

from conftest import MINIMAL, launched, wait_for

OUT = os.path.expanduser("~/mugvpn/screenshots")
pytestmark = pytest.mark.skipif(not os.path.exists(os.path.expanduser("~/mugvpn/make-screenshots")),
                                reason="screenshots only on request")

CA = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ0EK\n-----END CERTIFICATE-----\n"
PROFILES = {
    "Office": ("remote vpn.office.example.com 1194 udp\n", ""),
    "Home Lab": ("remote home.example.net 443 tcp\n", ""),
    "Acme Client": ("remote gw.acme.example.com 1194 udp\nremote gw2.acme.example.com 1194 udp\n", "Clients"),
    "Datacenter": ("remote dc1.example.org 1194 udp\n", "Clients"),
    "Travel (all traffic)": ("remote travel.example.com 443 tcp\nredirect-gateway def1\n", ""),
}
LOG = [
    "OpenVPN 2.7.8 aarch64-apple-darwin [SSL (OpenSSL)] [LZO] [LZ4] [MH/RECVDA] [AEAD]",
    "TCP/UDP: Preserving recently used remote address: [AF_INET]203.0.113.10:1194",
    "UDPv4 link remote: [AF_INET]203.0.113.10:1194",
    "VERIFY OK: depth=1, CN=Office VPN CA",
    "VERIFY OK: depth=0, CN=vpn.office.example.com",
    "Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384, peer certificate: 2048 bits RSA",
    "[vpn.office.example.com] Peer Connection Initiated with [AF_INET]203.0.113.10:1194",
    "PUSH: Received control message: 'PUSH_REPLY,route 10.20.0.0 255.255.0.0,dns server 1 address 10.20.0.53,dns server 1 resolve-domains corp.example.com,topology subnet,ifconfig 10.8.0.6 255.255.255.0'",
    "Data Channel: cipher 'AES-256-GCM', peer-id: 3",
    "MANAGEMENT: CMD 'needok 'OPENTUN' ok'",
    "Opened utun device utun6",
    "MANAGEMENT: CMD 'needok 'IFCONFIG' ok'",
    "MugVPN: route add 10.20.0.0 255.255.0.0 10.8.0.1",
    "WARNING: this configuration may cache passwords in memory -- use the auth-nocache option to prevent this",
    "Initialization Sequence Completed",
]


def snap(a, kind, name):
    os.makedirs(OUT, exist_ok=True)
    w = a.window(kind)
    time.sleep(0.6)
    a.call("snapshot", window=w["id"], path=f"{OUT}/{name}.png")


def setup(a):
    import shutil
    shutil.rmtree(os.path.join(a.home, "config"), ignore_errors=True)
    for name, (remote, folder) in PROFILES.items():
        a.add_profile(name, "client\ndev tun\n" + remote + "auth-user-pass\n<ca>\n" + CA + "</ca>\n", folder=folder)


def up(a, name, ip):
    a.connect(name)
    a.feed(name, *[f">LOG:17000000{i:02d},I,{l}" for i, l in enumerate(LOG)])
    a.feed(name, f">STATE:1700000099,CONNECTED,SUCCESS,{ip},203.0.113.10,1194,,", ">BYTECOUNT:48211993,3120874")


def test_screenshots(home):
    for appearance, suffix in (("Light", ""), ("Dark", "-dark")):
        with launched(home, appearance=appearance) as a:
            setup(a)
            up(a, "Office", "10.8.0.6")
            up(a, "Home Lab", "10.77.0.2")
            up(a, "Datacenter", "10.31.4.18")
            for w in a.windows("status"):
                a.call("close", window=w["id"])
            os.makedirs(OUT, exist_ok=True)
            a.call("snapshot_menu", path=f"{OUT}/menu{suffix}.png")
            a.click("Office", "Show Status")
            snap(a, "status", f"status{suffix}")
            a.call("close", window=a.window("status")["id"])
            a.click("Office", "Connection Settings…")
            snap(a, "connections", f"connections-general{suffix}")
            a.set(a.window("connections"), "tabs", "options")
            snap(a, "connections", f"connections-options{suffix}")
            a.set(a.window("connections"), "tabs", "auth")
            snap(a, "connections", f"connections-auth{suffix}")
            a.call("close", window=a.window("connections")["id"])
            if not suffix:
                a.click("Settings…")
                snap(a, "settings", "settings")
            # Protection at work: a kill switch that fired, and a network that asks for a sign-in.
            a.call("fake_http", responses=[{"status": 200, "body": "<html>Accept the terms</html>"}])
            a.call("fake_blocks", names=["Travel (all traffic)"])
            a.call("system_event", event="networkChanged")
            wait_for(lambda: "Sign in to This Network…" in [i["title"] for i in a.menu()], 5, "the sign-in offer")
            a.call("snapshot_menu", path=f"{OUT}/menu-protection{suffix}.png")

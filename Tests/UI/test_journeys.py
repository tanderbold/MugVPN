"""UJ: what a person does, through the interface, with the real helper and real
tunnels to the stand's servers (MUGVPN_E2E_BACKEND=real). Run inside the Mac VM
by tools/stand/stand.sh ui; skipped when the stand is not up."""
import os
import re
import shutil
import socket
import subprocess
import time
from urllib.parse import unquote

import pytest

from conftest import BIN, launched, wait_for

STAND = os.path.expanduser("~/stand")


def stand_up():
    try:
        socket.create_connection(("127.0.0.1", 1194), timeout=2).close()
    except OSError:
        return False
    r = subprocess.run([BIN, "status", "--xpc"], capture_output=True, text=True, timeout=40)
    return "helper version" in r.stdout


pytestmark = pytest.mark.skipif(not os.path.isdir(STAND) or not stand_up(), reason="the stand is not up")


def tunnels():
    out = subprocess.run([BIN, "list"], capture_output=True, text=True, timeout=40).stdout
    return {line.split()[1]: line.split()[0] for line in out.splitlines() if line.strip()}


def ping(ip):
    return subprocess.run(["ping", "-c1", "-t3", ip], capture_output=True).returncode == 0


def resolve(name):
    out = subprocess.run(["dscacheutil", "-q", "host", "-a", "name", name], capture_output=True, text=True).stdout
    m = re.search(r"ip_address: (\S+)", out)
    return m.group(1) if m else None


def primary_dns():
    out = subprocess.run(["scutil", "--dns"], capture_output=True, text=True).stdout
    first = out.split("resolver #1", 1)[1].split("\n\n", 1)[0] if "resolver #1" in out else ""
    return re.findall(r"nameserver\[\d+\] : (\S+)", first)


@pytest.fixture
def real(home):
    for n in ("a", "b", "c", "d", "e"):
        shutil.copy(f"{STAND}/stand-{n}.ovpn", os.path.join(home, "config", f"stand-{n}.ovpn"))
    for n in ("stand-a", "stand-b"):  # the conftest's placeholders
        p = os.path.join(home, "config", f"{n}.ovpn")
        shutil.copy(f"{STAND}/{n}.ovpn", p)
    baseline = primary_dns()
    os.environ["MUGVPN_E2E_BACKEND"] = "real"
    try:
        with launched(home) as a:
            a.call("rescan")
            yield a
            for t in list(tunnels().values()):
                subprocess.run([BIN, "disconnect", t], capture_output=True, timeout=40)
    finally:
        del os.environ["MUGVPN_E2E_BACKEND"]
        wait_for(lambda: not tunnels(), 30, "every tunnel down")
        wait_for(lambda: primary_dns() == baseline, 20, "DNS back as it was")


def connected(a, name, timeout=60):
    wait_for(lambda: any(i["title"] == name and i["checked"] for i in a.menu()), timeout, f"{name} connected")


def test_uj01_connect_from_the_menu(real):
    real.click("stand-a", "Connect")
    connected(real, "stand-a")
    assert real.call("status")["icon"] == "connected"
    assert ping("10.91.0.1"), "the network behind the server answers"
    assert resolve("host.a.test") == "10.91.0.1", "split DNS through the tunnel"


def test_uj02_password_dialog_wrong_then_right(real):
    real.click("stand-c", "Connect")
    w = real.window("credentials", timeout=30)
    real.set(w, "username", "test")
    real.set(w, "password", "wrong")
    real.press(w, "ok")
    w = real.window("credentials", timeout=60)
    assert real.control(w, "error_text")["visible"], "the error is shown"
    real.set(w, "password", "secret")
    real.press(w, "ok")
    connected(real, "stand-c")
    assert ping("10.93.0.1")


def test_uj03_view_log_live_and_kept(real):
    real.click("stand-a", "Connect")
    connected(real, "stand-a")
    real.click("stand-a", "View Log")
    url = wait_for(lambda: next((u for u in real.call("opened_urls")["urls"] if u.endswith("openvpn.log")), None),
                   5, "the live log")
    path = unquote(url.replace("file://", ""))
    assert "Initialization Sequence Completed" in open(path).read(), "the user can read the live log"
    real.click("stand-a", "Disconnect")
    wait_for(lambda: "stand-a" not in tunnels(), 30, "a down")
    real.click("stand-a", "View Log")
    kept = wait_for(lambda: next((u for u in real.call("opened_urls")["urls"] if re.search(r"stand-a~[0-9a-f]{12}\.\d+\.log$", u)), None),
                    5, "the kept log")
    assert "SIGTERM" in open(unquote(kept.replace("file://", ""))).read()


def test_uj04_status_window_disconnect_and_connect_again(real):
    real.click("stand-a", "Connect")
    connected(real, "stand-a")
    real.click("stand-a", "Show Status")
    w = real.window("status")
    real.press(w, "disconnect")
    wait_for(lambda: "stand-a" not in tunnels(), 30, "a down")
    wait_for(lambda: real.control(real.window("status"), "connect")["enabled"], 10, "Connect offered")
    real.press(real.window("status"), "connect")
    connected(real, "stand-a")
    assert ping("10.91.0.1")


def test_uj05_split_dns_switch(real):
    before = primary_dns()
    real.click("stand-b", "Connection Settings…")
    real.set(real.window("connections"), "tabs", "options")
    real.set(real.window("connections"), "split_dns", True)
    real.press(real.window("connections"), "save")
    real.click("stand-b", "Connect")
    connected(real, "stand-b")
    assert primary_dns() == before, "the primary resolver is left alone"
    assert resolve("host.b.test") == "10.92.0.1"


def test_uj06_two_full_tunnels_warn(real, home):
    shutil.copy(f"{STAND}/stand-d.ovpn", os.path.join(home, "config", "stand-d2.ovpn"))
    real.call("rescan")
    real.click("stand-d", "Connect")
    connected(real, "stand-d")
    real.click("stand-d2", "Connect")
    connected(real, "stand-d2")
    wait_for(lambda: any("all traffic" in i["title"] for i in real.menu()), 15, "the warning in the menu")


def test_uj07_quit_and_come_back(home):
    for n in ("a",):
        shutil.copy(f"{STAND}/stand-{n}.ovpn", os.path.join(home, "config", f"stand-{n}.ovpn"))
    os.environ["MUGVPN_E2E_BACKEND"] = "real"
    try:
        with launched(home) as a:
            a.call("rescan")
            a.click("stand-a", "Connect")
            connected(a, "stand-a")
            a.click("Quit MugVPN")
            a.press(a.window("confirm"), "ok")
            a.proc.wait(timeout=60)
        assert "stand-a" not in tunnels(), "quitting disconnects"
        with launched(home, reset_defaults=False) as b:
            connected(b, "stand-a")
            assert ping("10.91.0.1")
            for t in list(tunnels().values()):
                subprocess.run([BIN, "disconnect", t], capture_output=True, timeout=40)
    finally:
        del os.environ["MUGVPN_E2E_BACKEND"]
        wait_for(lambda: not tunnels(), 30, "every tunnel down")


def dns_settings(real, profile, mode, servers="", domains=""):
    real.click(profile, "Connection Settings…")
    real.set(real.window("connections"), "tabs", "options")
    w = real.window("connections")
    real.set(w, "dns_mode", mode)
    if mode == "own":
        real.set(real.window("connections"), "dns_servers", servers)
        real.set(real.window("connections"), "dns_domains", domains)
    real.press(real.window("connections"), "save")
    w = real.window("connections")
    assert not real.control(w, "error_text")["visible"], real.control(w, "error_text")
    real.call("close", window=w["id"])


def test_uj08_own_dns_for_a_domain(real):
    before = primary_dns()
    dns_settings(real, "stand-d", "own", "10.84.0.1", "d.test")
    real.click("stand-d", "Connect")
    connected(real, "stand-d")
    assert resolve("host.d.test") == "10.94.0.1", "d.test through the tunnel's DNS"
    assert primary_dns() == before, "the server wanted all DNS; this connection asked for d.test only"


def test_uj09_dont_change_dns(real):
    dns_settings(real, "stand-a", "none")
    real.click("stand-a", "Connect")
    connected(real, "stand-a")
    assert ping("10.91.0.1"), "the tunnel works"
    assert resolve("host.a.test") is None, "a.test is not sent to the server's DNS"


def test_uj10_own_dns_for_all_names(real):
    dns_settings(real, "stand-a", "own", "10.81.0.1", "")
    real.click("stand-a", "Connect")
    connected(real, "stand-a")
    wait_for(lambda: "10.81.0.1" in primary_dns(), 10, "the tunnel's DNS takes all names")
    assert resolve("host.a.test") == "10.91.0.1"


def test_uj11_leak_check_with_a_real_tunnel(real):
    """A real all-traffic tunnel (stand-d): nothing to report; a public network
    then routed through en0 (as a rogue DHCP server would) is reported."""
    real.click("stand-d", "Connect")
    connected(real, "stand-d")
    assert real.call("leak_check")["findings"] == []
    gw = subprocess.run(["sh", "-c", "netstat -rn -f inet | awk '$1==\"default\" && $4==\"en0\" {print $2; exit}'"],
                        capture_output=True, text=True).stdout.strip()
    subprocess.run(["sudo", "/sbin/route", "-n", "add", "-net", "198.51.100.0/24", gw], capture_output=True, check=True)
    try:
        found = real.call("leak_check")["findings"]
        assert any("198.51.100.0/24" in f for f in found), found
    finally:
        subprocess.run(["sudo", "/sbin/route", "-n", "delete", "-net", "198.51.100.0/24", gw], capture_output=True)


def can_fetch(url="https://example.com"):
    return subprocess.run(["curl", "-s", "-m", "6", "-o", "/dev/null", url]).returncode == 0


def lan_dns_answers():
    gw = subprocess.run(["sh", "-c", "netstat -rn -f inet | awk '$1==\"default\" && $4==\"en0\" {print $2; exit}'"],
                        capture_output=True, text=True).stdout.strip()
    r = subprocess.run(["dig", "+time=3", "+tries=1", f"@{gw}", "example.com"], capture_output=True, text=True)
    return "ANSWER SECTION" in r.stdout


def test_uj12_kill_switch_with_a_real_tunnel(real):
    """PF protection for real: DNS only through the tunnel while stand-d takes all
    traffic; an unexpected drop blocks the Internet until Unblock."""
    assert can_fetch() and lan_dns_answers(), "the VM reaches the Internet and its router's DNS to begin with"
    real.click("stand-d", "Connection Settings…")
    real.set(real.window("connections"), "tabs", "options")
    real.set(real.window("connections"), "kill_switch", True)
    real.press(real.window("connections"), "save")
    real.call("close", window=real.window("connections")["id"])
    real.click("stand-d", "Connect")
    connected(real, "stand-d")
    wait_for(lambda: not lan_dns_answers(), 15, "DNS outside the tunnel blocked")
    subprocess.run(["sudo", "pkill", "-9", "-f", "MugVPN/libexec/openvpn"], capture_output=True)
    wait_for(lambda: any("blocked" in i["title"].lower() for i in real.menu()), 30, "the block in the menu")
    assert not can_fetch(), "nothing leaves outside the VPN after the drop"
    real.click("Unblock Internet")
    wait_for(can_fetch, 20, "the Internet back after Unblock")
    assert lan_dns_answers()

def ping6(ip):
    return subprocess.run(["ping6", "-c1", "-i1", ip], capture_output=True, timeout=10).returncode == 0


def test_uj13_ipv6_through_the_tunnel(real):
    """stand-e gives an IPv6 address and routes its IPv6 network (fd00:95::/64): reachable while connected, its
    route gone after."""
    real.click("stand-e", "Connect")
    connected(real, "stand-e")
    assert wait_for(lambda: ping6("fd00:95::1"), 10, "the server's IPv6 network")
    real.click("stand-e", "Disconnect")
    wait_for(lambda: "stand-e" not in tunnels(), 30, "e down")
    wait_for(lambda: "fd00:95::" not in subprocess.run(["netstat", "-rn", "-f", "inet6"], capture_output=True, text=True).stdout,
             15, "its IPv6 route gone")


def test_uj14_http_proxy_with_a_password(real, home):
    """stand-a through the stand's HTTP proxy (127.0.0.1:3128, proxy/proxypass): the proxy's password is asked,
    then the tunnel works."""
    try:
        socket.create_connection(("127.0.0.1", 3128), timeout=2).close()
    except OSError:
        pytest.skip("the stand's proxy is not forwarded")
    with open(f"{STAND}/stand-a.ovpn") as f:
        text = f.read()
    with open(os.path.join(home, "config", "stand-ap.ovpn"), "w") as f:
        f.write(text + "http-proxy 127.0.0.1 3128 auto\n")
    real.call("rescan")
    real.click("stand-ap", "Connect")
    w = real.window("credentials", timeout=30)
    real.set(w, "username", "proxy")
    real.set(w, "password", "proxypass")
    real.press(w, "ok")
    connected(real, "stand-ap")
    assert ping("10.91.0.1")


def test_uj15_pkcs12_with_a_password(real, home):
    """stand-a's certificate and key as a password-protected PKCS#12 file beside the profile: the key's password is
    asked, then the tunnel works."""
    with open(f"{STAND}/stand-a.ovpn") as f:
        text = f.read()
    cert = re.search(r"<cert>\n(.*?)</cert>", text, re.S).group(1)
    key = re.search(r"<key>\n(.*?)</key>", text, re.S).group(1)
    work = os.path.join(home, "p12")
    os.makedirs(work, exist_ok=True)
    with open(f"{work}/c.pem", "w") as f:
        f.write(cert)
    with open(f"{work}/k.pem", "w") as f:
        f.write(key)
    subprocess.run(["/usr/bin/openssl", "pkcs12", "-export", "-in", f"{work}/c.pem", "-inkey", f"{work}/k.pem",
                    "-out", os.path.join(home, "config", "client.p12"), "-passout", "pass:p12pass",
                    "-keypbe", "AES-256-CBC", "-certpbe", "AES-256-CBC", "-macalg", "sha256"], check=True, capture_output=True)
    profile = re.sub(r"<cert>.*?</cert>\n|<key>.*?</key>\n", "", text, flags=re.S) + "pkcs12 client.p12\n"
    with open(os.path.join(home, "config", "stand-a12.ovpn"), "w") as f:
        f.write(profile)
    real.call("rescan")
    real.click("stand-a12", "Connect")
    w = real.window("secret", timeout=30)
    real.set(w, "password", "p12pass")
    real.press(w, "ok")
    connected(real, "stand-a12")
    assert ping("10.91.0.1")


def test_uj16_web_sign_in(real, home):
    """stand-g defers the password check to a web sign-in: the app opens its page; once signed in there, the
    tunnel comes up."""
    import urllib.request
    try:
        socket.create_connection(("127.0.0.1", 8080), timeout=2).close()
    except OSError:
        pytest.skip("the stand's sign-in page is not forwarded")
    shutil.copy(f"{STAND}/stand-g.ovpn", os.path.join(home, "config", "stand-g.ovpn"))
    real.call("rescan")
    real.click("stand-g", "Connect")
    w = real.window("credentials", timeout=30)
    real.set(w, "username", "someone")
    real.set(w, "password", "anything")
    real.press(w, "ok")
    import ssl
    url = wait_for(lambda: next((u for u in real.call("opened_urls")["urls"] if "127.0.0.1:8080/ok/" in u), None), 30,
                   "the sign-in page opened")
    # (The stand's own certificate: the person signing in would trust it in their browser.)
    assert urllib.request.urlopen(url, timeout=10, context=ssl._create_unverified_context()).read() == b"signed in\n"
    connected(real, "stand-g")
    assert ping("10.97.0.1")

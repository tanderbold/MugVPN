"""INT-01..09, 22..24: tunnels, routes and DNS on the stand."""
import pytest

from conftest import wait_for

AUTH = {"MUGVPN_USER": "test", "MUGVPN_PASS": "secret"}


def test_int01_single_connection(vpn):
    vpn.connected("stand-a")
    assert "10.81.0.2" in vpn.tunnel_devices().values()
    assert vpn.route_iface("10.91.0.1").startswith("utun")
    assert vpn.ping("10.91.0.1")


def test_int02_four_at_once(vpn):
    vpn.connected("stand-a")
    vpn.connected("stand-b")
    vpn.connected("stand-c", env=AUTH)
    vpn.connected("stand-d")
    devices = vpn.tunnel_devices()
    assert sorted(devices.values()) == ["10.81.0.2", "10.82.0.2", "10.83.0.2", "10.84.0.2"]
    assert len(set(devices)) == 4, "each tunnel has its own utun"
    for net in (1, 2, 3, 4):
        assert vpn.ping(f"10.9{net}.0.1"), f"network behind server {net}"


def test_int03_split_dns_side_by_side(vpn):
    vpn.connected("stand-a")
    vpn.connected("stand-c", env=AUTH)
    assert vpn.resolve("host.a.test") == "10.91.0.1"
    assert vpn.resolve("host.c.test") == "10.93.0.1"
    assert vpn.primary_dns() == vpn.baseline_dns, "split DNS leaves the primary resolver alone"


def test_int04_legacy_dns_takes_the_primary_and_gives_it_back(vpn):
    vpn.connected("stand-b")
    assert vpn.primary_dns() == ["10.82.0.1"]
    assert vpn.resolve("host.b.test") == "10.92.0.1"
    vpn.disconnect_all()
    assert vpn.primary_dns() == vpn.baseline_dns


def test_int05_second_full_redirect_dns_is_refused(vpn, mac):
    vpn.connected("stand-b")
    d = vpn.connected("stand-d")
    assert "already another tunnel's" in vpn.helper_log(), "the helper refuses the second (privilege separation)"
    assert vpn.primary_dns() == ["10.82.0.1"], "the first tunnel keeps the primary DNS"
    vpn.cli(f"disconnect {d}")
    wait_for(lambda: "stand-d" not in vpn.list().values(), 20, "d to stop")
    assert vpn.primary_dns() == ["10.82.0.1"], "d did not own the primary DNS and does not restore it"


def test_int06_disconnect_in_any_order(vpn):
    vpn.connected("stand-a")
    b = vpn.connected("stand-b")
    vpn.connected("stand-c", env=AUTH)
    vpn.cli(f"disconnect {b}")
    wait_for(lambda: "stand-b" not in vpn.list().values(), 20, "b to stop")
    assert vpn.primary_dns() == vpn.baseline_dns
    assert vpn.resolve("host.a.test") == "10.91.0.1"
    assert vpn.resolve("host.c.test") == "10.93.0.1"
    assert vpn.ping("10.91.0.1") and vpn.ping("10.93.0.1")
    assert not vpn.ping("10.92.0.1")


def test_int07_nothing_left_after_all_disconnect(vpn):
    for p, env in (("stand-a", None), ("stand-b", None), ("stand-c", AUTH), ("stand-d", None)):
        vpn.connected(p, env=env)
    vpn.disconnect_all()
    state = vpn.clean_state()
    assert state["routes"] == [] and state["openvpn_keys"] == [] and state["run_dir"] == []
    assert state["processes"] == [] and state["primary_dns"] == vpn.baseline_dns


def test_int08_username_and_password(vpn):
    r, _ = vpn.connect("stand-c", env={"MUGVPN_USER": "test", "MUGVPN_PASS": "wrong"})
    assert r.returncode != 0 and "auth failed" in r.stdout
    vpn.disconnect_all()
    vpn.connected("stand-c", env=AUTH)


def test_int09_redirect_gateway_beside_split_tunnels(vpn):
    vpn.connected("stand-a")
    vpn.connected("stand-d")
    devices = {ip: dev for dev, ip in vpn.tunnel_devices().items()}
    assert vpn.route_iface("8.8.8.8") == devices["10.84.0.2"], "default traffic goes through d"
    assert vpn.route_iface("10.91.0.1") == devices["10.81.0.2"], "a's network still goes through a"
    assert vpn.ping("10.91.0.1") and vpn.ping("10.94.0.1")


def _variant(mac, name, extra, base="stand-a"):
    path = f"/Users/tester/stand/{name}.ovpn"
    mac.run(f"cp /Users/tester/stand/{base}.ovpn {path} && printf '{extra}' >> {path}", check=True)
    return path


def test_int22_user_nobody_refused(vpn, mac):
    path = _variant(mac, "stand-a-nobody", "user nobody\\ngroup nogroup\\npersist-tun\\n")
    r, cid = vpn.connect(path, wait=False)
    assert cid is None and "without root already" in r.stderr, r.stdout + r.stderr


def test_int23_auth_user_pass_file(vpn, mac):
    mac.run("printf 'test\\nsecret\\n' > /Users/tester/stand/c-auth.txt", check=True)
    path = f"/Users/tester/stand/stand-c-file.ovpn"
    mac.run(f"sed 's|^auth-user-pass$|auth-user-pass c-auth.txt|' /Users/tester/stand/stand-c.ovpn > {path}", check=True)
    vpn.connected(path)


def test_int24_reconnect_after_server_restart(vpn, mac, srv):
    a = vpn.connected("stand-a")
    log = f"'/Library/Application Support/MugVPN/run/{a}/openvpn.log'"
    srv.run("sudo systemctl restart openvpn-server@a", check=True)
    wait_for(lambda: mac.out(f"sudo grep -c 'Initialization Sequence Completed' {log}").strip() == "2", 90,
             "a to reconnect")
    assert vpn.resolve("host.a.test") == "10.91.0.1"
    assert len([k for k in vpn.openvpn_keys() if k.endswith("/DNS")]) == 1, "DNS not set up twice"
    assert vpn.ping("10.91.0.1")


@pytest.mark.skip(reason="INT-25: sleep and wake - stage 5, emulation in the VM to be decided")
def test_int25_sleep_wake():
    pass


@pytest.mark.skip(reason="INT-26: UDP needs Softnet on the stand (PLAN 3a)")
def test_int26_udp():
    pass


def test_int29_split_dns_for_legacy_servers(vpn, mac):
    r = vpn.cli("connect --split-dns /Users/tester/stand/stand-b.ovpn")
    assert r.returncode == 0 and "connected, ip" in r.stdout, r.stdout + r.stderr
    assert vpn.primary_dns() == vpn.baseline_dns, "the primary resolver is left alone"
    assert vpn.resolve("host.b.test") == "10.92.0.1"
    vpn.connected("stand-a")
    assert vpn.resolve("host.a.test") == "10.91.0.1"
    assert vpn.resolve("host.b.test") == "10.92.0.1"


def test_int41_route_around_the_tunnel_is_refused(vpn, mac):
    """Privilege separation: the helper sets routes only through the tunnel (or a host via the Mac's gateway)."""
    path = _variant(mac, "stand-a-around", "route 198.51.100.0 255.255.255.0 net_gateway\\n")
    r, cid = vpn.connect(path)
    assert cid, r.stdout + r.stderr
    assert "a route must go through the tunnel" in r.stdout, r.stdout
    assert "198.51.100" not in vpn.routes()
    assert vpn.ping("10.91.0.1"), "the tunnel itself works"

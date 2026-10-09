"""INT-27: the menu bar app with its real backends (XPC client, management socket) on the stand."""
import pytest

from conftest import APP, CLI, wait_for

CONFIG = "/Users/tester/Library/Application Support/MugVPN/config"


@pytest.fixture
def gui_app(mac):
    mac.run(f"mkdir -p '{CONFIG}' && cp /Users/tester/stand/stand-a.ovpn /Users/tester/stand/stand-b.ovpn '{CONFIG}/'", check=True)
    mac.run("pkill -x MugVPN; true")
    mac.run(f"open {APP}", check=True)
    wait_for(lambda: mac.run("pgrep -x MugVPN").returncode == 0, 15, "the app to start")
    yield
    mac.run(f"{CLI} --command exit; true")
    wait_for(lambda: mac.run("pgrep -x MugVPN").returncode != 0, 30, "the app to quit")
    mac.run(f"rm -rf '{CONFIG}'; defaults delete com.mugvpn.app reconnect_on_start; true")


def test_int27b_profile_added_while_running(vpn, mac, gui_app):
    mac.run(f"cp /Users/tester/stand/stand-c.ovpn '{CONFIG}/late.ovpn'", check=True)
    mac.run(f"{CLI} --command connect late", check=True)
    # stand-c needs a password: the app asks for it, so the tunnel is started but waits.
    wait_for(lambda: "late" in vpn.list().values(), 30, "the late profile to start")
    mac.run(f"{CLI} --command disconnect_all", check=True)
    wait_for(lambda: not vpn.list(), 30, "it to stop")


def test_int27c_command_right_after_launch(vpn, mac):
    mac.run(f"mkdir -p '{CONFIG}' && cp /Users/tester/stand/stand-a.ovpn '{CONFIG}/'", check=True)
    mac.run("pkill -x MugVPN; true")
    try:
        r = mac.run(f"open {APP} && {CLI} --command connect stand-a")
        assert r.returncode == 0, r.stdout + r.stderr
        wait_for(lambda: "stand-a" in vpn.list().values(), 30, "the command to arrive")
    finally:
        mac.run(f"{CLI} --command disconnect_all; {CLI} --command exit; true")
        wait_for(lambda: mac.run("pgrep -x MugVPN").returncode != 0, 30, "the app to quit")
        mac.run(f"rm -rf '{CONFIG}'; defaults delete com.mugvpn.app reconnect_on_start; true")


def test_int27_app_connects_and_disconnects(vpn, mac, gui_app):
    mac.run(f"{CLI} --command connect stand-a", check=True)
    wait_for(lambda: vpn.resolve("host.a.test") == "10.91.0.1", 60, "stand-a up through the app")
    mac.run(f"{CLI} --command connect stand-b", check=True)
    wait_for(lambda: vpn.ping("10.92.0.1"), 60, "stand-b up beside it")
    assert sorted(vpn.list().values()) == ["stand-a", "stand-b"]
    mac.run(f"{CLI} --command disconnect_all", check=True)
    wait_for(lambda: not vpn.list(), 30, "both down")


def test_int28_user_scripts(vpn, mac, gui_app):
    d = CONFIG
    mac.run(f"printf 'setenv SITE berlin\\n' >> '{d}/stand-a.ovpn'", check=True)
    mac.run(f"printf '#!/bin/sh\\necho \"ip=$ifconfig_local site=$SITE profile=$profile\" > /tmp/mugvpn-up.txt\\necho upscript-ran\\n' > '{d}/stand-a_up.sh'"
            f" && printf '#!/bin/sh\\nping -c1 -t2 10.91.0.1 >/dev/null && echo tunnel-up > /tmp/mugvpn-down.txt\\n' > '{d}/stand-a_down.sh'"
            f" && printf '#!/bin/sh\\nexit 1\\n' > '{d}/stand-b_pre.sh'"
            f" && chmod +x '{d}'/*.sh && rm -f /tmp/mugvpn-up.txt /tmp/mugvpn-down.txt", check=True)
    mac.run(f"{CLI} --command rescan; {CLI} --command connect stand-a", check=True)
    wait_for(lambda: mac.run("test -f /tmp/mugvpn-up.txt").returncode == 0, 60, "the up script")
    assert mac.out("cat /tmp/mugvpn-up.txt").strip() == "ip=10.81.0.2 site=berlin profile=stand-a"
    assert "upscript-ran" in mac.out("cat ~/Library/Logs/MugVPN/stand-a_up.log")
    mac.run("rm -f ~/Library/Logs/MugVPN/stand-b_pre.log")
    mac.run(f"{CLI} --command connect stand-b", check=True)
    wait_for(lambda: mac.run("test -f ~/Library/Logs/MugVPN/stand-b_pre.log").returncode == 0, 30, "the pre script")
    assert "stand-b" not in vpn.list().values(), "a failing pre script cancels the connection"
    mac.run(f"{CLI} --command disconnect stand-a", check=True)
    wait_for(lambda: not vpn.list(), 30, "a down")
    assert mac.out("cat /tmp/mugvpn-down.txt").strip() == "tunnel-up", "the down script ran before the tunnel went"


def test_int27d_command_results(vpn, mac, gui_app):
    """INT-27d: --command answers once it is done: exit codes, list/status JSON, --wait."""
    import json
    bad = mac.run(f"{CLI} --command connect nosuch")
    assert bad.returncode == 1 and "no profile nosuch" in bad.stderr, bad.stdout + bad.stderr
    assert mac.run(f"{CLI} --command connect stand-a --timeout x").returncode == 2
    r = mac.run(f"{CLI} --command connect stand-a --wait --timeout 60", timeout=90)
    assert r.returncode == 0, r.stdout + r.stderr
    assert vpn.resolve("host.a.test") == "10.91.0.1", "connected when the command returned"
    st = json.loads(mac.out(f"{CLI} --command status stand-a"))
    assert st[0]["name"] == "stand-a" and st[0]["status"] == "connected" and st[0]["ip"], st
    names = {p["name"]: p["status"] for p in json.loads(mac.out(f"{CLI} --command list"))}
    assert names.get("stand-b") == "disconnected" and names.get("stand-a") == "connected", names
    r = mac.run(f"{CLI} --command reconnect stand-a --wait", timeout=90)
    assert r.returncode == 0, r.stdout + r.stderr
    assert mac.run(f"{CLI} --command reconnect stand-b").returncode == 1, "not connected"
    r = mac.run(f"{CLI} --command disconnect stand-a --wait --timeout 30", timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not vpn.list()
    assert json.loads(mac.out(f"{CLI} --command status")) == []


def test_int27e_command_without_the_app(vpn, mac):
    """INT-27e: with no MugVPN running, commands on connections fail; connect starts it and reports."""
    mac.run(f"mkdir -p '{CONFIG}' && cp /Users/tester/stand/stand-a.ovpn '{CONFIG}/'", check=True)
    mac.run("pkill -x MugVPN; true")
    wait_for(lambda: mac.run("pgrep -x MugVPN").returncode != 0, 30, "no app")
    try:
        for c in ["disconnect stand-a", "reconnect stand-a", "status", "list"]:
            r = mac.run(f"{CLI} --command {c}")
            assert r.returncode == 3 and "not running" in r.stderr, (c, r.stdout + r.stderr)
        assert mac.run(f"{CLI} --command exit").returncode == 0
        r = mac.run(f"{CLI} --command connect stand-a --wait --timeout 60", timeout=120)
        assert r.returncode == 0, r.stdout + r.stderr
        assert "stand-a" in vpn.list().values()
    finally:
        mac.run(f"{CLI} --command disconnect_all; {CLI} --command exit; true")
        wait_for(lambda: mac.run("pgrep -x MugVPN").returncode != 0, 30, "the app to quit")
        mac.run(f"rm -rf '{CONFIG}'; defaults delete com.mugvpn.app reconnect_on_start; true")


def test_int27f_network_change_reconnects(vpn, mac, gui_app):
    """INT-27f: another network on the same interface (here: another DHCP server, written into
    SystemConfiguration as configd does on a new Wi-Fi network; the stand has one network) reconnects
    the tunnels; the same record written again (a renewal) does not."""
    import shlex
    import time
    from conftest import RUN_DIR
    r = mac.run(f"{CLI} --command connect stand-a --wait --timeout 60", timeout=90)
    assert r.returncode == 0, r.stdout + r.stderr
    cid = vpn.id_of("stand-a")
    log = shlex.quote(f"{RUN_DIR}/{cid}/openvpn.log")

    def restarts():
        return mac.out(f"sudo grep -c 'SIGUSR1' {log} || true").strip() or "0"

    service = mac.out("echo 'show State:/Network/Global/IPv4' | scutil | awk '/PrimaryService/{print $3}'").strip()
    key = f"State:/Network/Service/{service}/DHCP"

    def dhcp_server():
        return mac.out(f"echo 'show {key}' | scutil | awk '/Option_54/{{print $4}}'").strip()

    def write(server):
        mac.run(f"printf 'get {key}\\nd.add Option_54 %% {server[2:]}\\nset {key}\\n' | sudo scutil", check=True)

    original = dhcp_server()
    assert original.startswith("0x"), f"the stand's network is DHCP's: {original!r}"
    try:
        before = restarts()
        write(original)                                      # renewed: the same network
        time.sleep(5)
        assert restarts() == before, "the same network: no reconnect: " + mac.out(f"sudo grep -B3 'SIGUSR1' {log}")
        write("0xc0a840fe")
        wait_for(lambda: restarts() != before, 30, "a reconnect after the network changed")
        wait_for(lambda: vpn.resolve("host.a.test") == "10.91.0.1", 60, "stand-a up again")
    finally:
        write(original)
        wait_for(lambda: dhcp_server() == original, 30, "the stand's own lease back")
        mac.run(f"{CLI} --command disconnect_all; true")
        wait_for(lambda: not vpn.list(), 30, "it to stop")

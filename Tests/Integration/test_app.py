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

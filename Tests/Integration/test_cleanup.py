"""INT-10..15: the helper cleans up after openvpn and after itself."""
from conftest import LOGS_DIR, wait_for


def test_int10_kill9_redirect_tunnel_is_cleaned_up(vpn, mac):
    d = vpn.connected("stand-d")
    assert vpn.primary_dns() == ["10.84.0.1"]
    mac.run(f"sudo kill -9 {vpn.pid_of(d)}", check=True)
    wait_for(lambda: d not in vpn.list(), 10, "d to be gone")
    wait_for(lambda: vpn.primary_dns() == vpn.baseline_dns, 10, "the primary DNS to come back")
    assert vpn.openvpn_keys() == []
    assert vpn.stand_routes() == [], "the host route to the server is removed"


def test_int11_kill9_leaves_the_others_alone(vpn, mac):
    vpn.connected("stand-a")
    d = vpn.connected("stand-d")
    mac.run(f"sudo kill -9 {vpn.pid_of(d)}", check=True)
    wait_for(lambda: d not in vpn.list(), 10, "d to be gone")
    wait_for(lambda: vpn.primary_dns() == vpn.baseline_dns, 10, "the primary DNS to come back")
    assert vpn.resolve("host.a.test") == "10.91.0.1"
    assert vpn.ping("10.91.0.1")
    assert [k for k in vpn.openvpn_keys() if k.endswith("/DNS")] != [], "a's DNS stays"


def test_int12_sigterm_ignored_then_sigkill(vpn, mac):
    d = vpn.connected("stand-d")
    pid = vpn.pid_of(d)
    mac.run(f"sudo kill -STOP {pid}", check=True)
    vpn.cli(f"disconnect {d}")
    wait_for(lambda: d not in vpn.list(), 25, "the helper to kill the stuck openvpn")
    wait_for(lambda: vpn.primary_dns() == vpn.baseline_dns, 10, "the primary DNS to come back")
    assert vpn.stand_routes() == []


def test_int13_helper_restart_stops_tunnels_cleanly(vpn, mac):
    vpn.connected("stand-a")
    vpn.connected("stand-d")
    mac.run("sudo launchctl kickstart -k system/com.mugvpn.helper", check=True)
    wait_for(lambda: vpn.cli("list").returncode == 0 and not vpn.list(), 30, "the helper to come back empty")
    wait_for(lambda: vpn.primary_dns() == vpn.baseline_dns, 10, "the primary DNS to come back")
    assert vpn.stand_routes() == [] and vpn.openvpn_keys() == [] and vpn.openvpn_processes() == []


def test_int14_kill9_helper_then_next_start_cleans_up(vpn, mac):
    vpn.connected("stand-d")
    mac.run("sudo pkill -9 -f Contents/MacOS/MugVPNHelper", check=True)
    # launchd starts the helper again on the next request; it finds the leftovers.
    wait_for(lambda: vpn.cli("list").returncode == 0, 30, "the helper to answer again")
    wait_for(lambda: vpn.primary_dns() == vpn.baseline_dns, 15, "the primary DNS to come back")
    assert vpn.stand_routes() == [] and vpn.openvpn_keys() == []
    assert vpn.run_dir_entries() == [] and vpn.openvpn_processes() == []


def test_int15_connection_log_is_kept(vpn, mac):
    vpn.connected("stand-a")
    vpn.disconnect_all()
    uid = mac.out("id -u").strip()
    log = mac.out(f"sudo cat {LOGS_DIR}/stand-a.{uid}.log")
    owner = mac.out(f"stat -f '%Su %Lp' {LOGS_DIR}/stand-a.{uid}.log").strip()
    assert owner == "tester 600", f"the log is the user's alone: {owner}"
    assert "Initialization Sequence Completed" in log
    assert "SIGTERM" in log


def test_int35_helper_stays_responsive_through_cleanups(vpn, mac):
    import time
    for _ in range(5):
        d = vpn.connected("stand-d")
        mac.run(f"sudo kill -9 {vpn.pid_of(d)}", check=True)
        wait_for(lambda: d not in vpn.list(), 15, "the cleanup")
        start = time.time()
        r = vpn.cli("list")
        assert r.returncode == 0 and time.time() - start < 5, "the helper answers at once after a cleanup"
    wait_for(lambda: vpn.primary_dns() == vpn.baseline_dns, 15, "DNS back")



def test_int46_helper_restarts_for_an_update_only_when_idle(vpn, mac):
    """INT-46: the helper exits for launchd to start the updated one only when the one on disk is
    newer and nothing needs it (the test build pretends to run an older version)."""
    import re
    pretend = "'/Library/Application Support/MugVPN/test-running-version'"
    pid = lambda: mac.out("pgrep -f Contents/MacOS/MugVPNHelper || true").split()
    restart = lambda: mac.run("sudo launchctl kickstart -k system/com.mugvpn.helper", check=True)
    try:
        r = vpn.cli("restart-if-idle")
        assert r.returncode != 0 and "not newer" in r.stderr, "the same version on disk: stays: " + r.stdout + r.stderr
        mac.run(f"echo 0.0.1 | sudo tee {pretend} >/dev/null && sudo chmod 644 {pretend}", check=True)
        restart()
        wait_for(lambda: vpn.cli("list").returncode == 0, 30, "the helper to answer")
        vpn.connected("stand-a")
        r = vpn.cli("restart-if-idle")
        assert r.returncode != 0 and "in use" in r.stderr, r.stdout + r.stderr
        vpn.disconnect_all()
        before = pid()
        assert vpn.cli("restart-if-idle").returncode == 0
        wait_for(lambda: pid() != before, 10, "the old helper to exit")
        out = vpn.cli("helper-version").stdout.strip()
        assert re.fullmatch(r"\d+\.\d+\.\d+", out), out
        assert pid() and pid() != before, "launchd started it again on the next call"
    finally:
        mac.run(f"sudo rm -f {pretend}")
        restart()
        wait_for(lambda: vpn.cli("list").returncode == 0, 30, "the helper to answer")


def test_int47_dragged_to_the_trash(vpn, mac):
    """INT-47: the app dragged to the Trash: after a minute the helper removes MugVPN's system part and
    the users' logs and settings; profiles stay."""
    from conftest import APP
    support = "'/Library/Application Support/MugVPN'"
    user_cfg = "'/Users/tester/Library/Application Support/MugVPN/config'"
    trashed = "/Users/tester/.Trash/MugVPN.app"
    helper_up = lambda: mac.run("pgrep -f Contents/MacOS/MugVPNHelper").returncode == 0
    wait_for(lambda: vpn.cli("list").returncode == 0, 30, "the helper to answer")
    mac.run(f"mkdir -p {user_cfg} ~/Library/Logs/MugVPN && cp /Users/tester/stand/stand-a.ovpn {user_cfg}/keep.ovpn"
            f" && echo x > ~/Library/Logs/MugVPN/old.log && sudo mkdir -p {support}/config", check=True)
    try:
        mac.run(f"rm -rf {trashed} && mv {APP} {trashed}", check=True)
        wait_for(lambda: not helper_up(), 150, "the helper to take MugVPN away")
        assert mac.run(f"sudo test -e {support}/libexec").returncode != 0, "its files are gone"
        assert mac.run("sudo test -e /Library/Logs/MugVPN").returncode != 0
        assert mac.run("test -e ~/Library/Logs/MugVPN").returncode != 0, "the user's logs too"
        assert mac.run(f"test -f {user_cfg}/keep.ovpn").returncode == 0, "the user's profiles stay"
        assert mac.run(f"sudo test -d {support}/config").returncode == 0, "administrators' profiles stay"
        assert mac.run("sudo launchctl print system/com.mugvpn.helper").returncode != 0, "the service is gone"
    finally:
        mac.run(f"test -e {APP} || mv {trashed} {APP}; rm -rf {user_cfg}/keep.ovpn; bash /tmp/install-helper.sh")
        wait_for(lambda: vpn.cli("list").returncode == 0, 60, "the helper back")

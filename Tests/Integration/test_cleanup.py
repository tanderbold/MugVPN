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
    # Only this run's counts (an earlier one's would pass for it).
    mac.run(f"sudo rm -f {LOGS_DIR}/stand-a*.log")
    vpn.connected("stand-a")
    vpn.disconnect_all()
    uid = mac.out("id -u").strip()
    # Its own: named by the profile and its id (same-named profiles keep theirs).
    name = mac.out(f"ls {LOGS_DIR} | grep -E '^stand-a~[0-9a-f]{{12}}\\.{uid}\\.log$'").strip()
    assert name, mac.out(f"ls {LOGS_DIR}")
    log = mac.out(f"sudo cat {LOGS_DIR}/{name}")
    owner = mac.out(f"stat -f '%Su %Lp' {LOGS_DIR}/{name}").strip()
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
    # A volume the user mounted in there: root never enters it.
    vol = "/Users/tester/Library/Logs/MugVPN/vol"
    mac.run(f"rm -f /tmp/int47.dmg; hdiutil create -quiet -size 4m -fs APFS -volname INT47 /tmp/int47.dmg"
            f" && mkdir -p {vol} && hdiutil attach -quiet -nobrowse -mountpoint {vol} /tmp/int47.dmg && echo keep > {vol}/data", check=True)
    try:
        mac.run(f"rm -rf {trashed} && mv {APP} {trashed}", check=True)
        wait_for(lambda: not helper_up(), 150, "the helper to take MugVPN away")
        assert mac.run(f"test -f {vol}/data").returncode == 0, "a mounted volume's files stay"
        assert mac.run("test -e ~/Library/Logs/MugVPN/old.log").returncode != 0, "the user's own logs beside it go"
        assert mac.run(f"sudo test -e {support}/libexec").returncode != 0, "its files are gone"
        assert mac.run("sudo test -e /Library/Logs/MugVPN").returncode != 0
        assert mac.run(f"test -f {user_cfg}/keep.ovpn").returncode == 0, "the user's profiles stay"
        assert mac.run(f"sudo test -d {support}/config").returncode == 0, "administrators' profiles stay"
        assert mac.run("sudo launchctl print system/com.mugvpn.helper").returncode != 0, "the service is gone"
    finally:
        mac.run(f"hdiutil detach -quiet {vol}; rm -rf ~/Library/Logs/MugVPN /tmp/int47.dmg")
        mac.run(f"test -e {APP} || mv {trashed} {APP}; rm -rf {user_cfg}/keep.ovpn; bash /tmp/install-helper.sh")
        wait_for(lambda: vpn.cli("list").returncode == 0, 60, "the helper back")


def test_int47b_trash_then_helper_restarted(vpn, mac):
    """INT-47b: the app dragged to the Trash and the helper killed at once (or the Mac restarted) before its minute:
    started again from the Trash (as SMAppService finds the moved bundle), it still takes MugVPN away."""
    from conftest import APP
    support = "'/Library/Application Support/MugVPN'"
    trashed = "/Users/tester/.Trash/MugVPN.app"
    plist = "/Library/LaunchDaemons/com.mugvpn.helper.plist"
    helper_up = lambda: mac.run("pgrep -f Contents/MacOS/MugVPNHelper").returncode == 0
    wait_for(lambda: vpn.cli("list").returncode == 0, 30, "the helper to answer")
    try:
        mac.run(f"rm -rf {trashed} && mv {APP} {trashed}", check=True)
        # Killed before its minute is up; launchd starts it again from where the bundle now is.
        mac.run("sudo launchctl bootout system/com.mugvpn.helper; sudo pkill -9 -f Contents/MacOS/MugVPNHelper; true")
        mac.run(f"sudo /usr/bin/python3 -c \"import plistlib; p=plistlib.load(open('{plist}','rb'));"
                f" p['Program']='{trashed}/Contents/MacOS/MugVPNHelper'; plistlib.dump(p, open('{plist}','wb'))\""
                f" && sudo launchctl bootstrap system {plist}", check=True)
        wait_for(helper_up, 30, "the helper started again from the Trash")
        wait_for(lambda: not helper_up(), 200, "the helper to take MugVPN away all the same")
        assert mac.run(f"sudo test -e {support}/libexec").returncode != 0, "its files are gone"
        assert mac.run(f"sudo test -e {support}/uninstall-pending.json").returncode != 0, "no wish left behind"
        assert mac.run("sudo launchctl print system/com.mugvpn.helper").returncode != 0, "the service is gone"
    finally:
        mac.run(f"test -e {APP} || mv {trashed} {APP}; bash /tmp/install-helper.sh")
        wait_for(lambda: vpn.cli("list").returncode == 0, 60, "the helper back")


def test_int47c_trash_emptied_and_rebooted(vpn, mac):
    """INT-47c: from its first look at the app in the Trash, a boot cleanup (the system's shell) waits for the next
    boot; put back, it goes. The Trash emptied and the Mac restarted before the helper's minute: at boot it takes
    MugVPN's system part away; profiles stay."""
    from conftest import APP
    support = "'/Library/Application Support/MugVPN'"
    trashed = "/Users/tester/.Trash/MugVPN.app"
    aside = "/Users/tester/int47c-MugVPN.app"
    cleanup = "/Library/LaunchDaemons/com.mugvpn.cleanup.plist"
    armed = lambda: mac.run(f"test -f {cleanup}").returncode == 0
    wait_for(lambda: vpn.cli("list").returncode == 0, 30, "the helper to answer")
    mac.run(f"sudo mkdir -p {support}/config && sudo touch {support}/config/int47c.ovpn", check=True)
    try:
        mac.run(f"rm -rf {trashed} {aside} && mv {APP} {trashed}", check=True)
        wait_for(armed, 40, "the boot cleanup kept")
        mac.run(f"mv {trashed} {APP}", check=True)
        wait_for(lambda: not armed(), 40, "put back: the boot cleanup gone")
        mac.run(f"mv {APP} {trashed}", check=True)
        wait_for(armed, 40, "kept again")
        # The Trash emptied (the bundle gone: kept aside here) and the Mac restarted: the helper cannot start.
        mac.run(f"sudo launchctl bootout system/com.mugvpn.helper; sudo pkill -9 -f Contents/MacOS/MugVPNHelper;"
                f" mv {trashed} {aside}; true")
        mac.run(f"sudo launchctl bootstrap system {cleanup}", check=True)
        wait_for(lambda: mac.run(f"sudo test -e {support}/libexec").returncode != 0, 30, "the system part gone")
        wait_for(lambda: not armed(), 30, "the boot cleanup gone with it")
        assert mac.run("sudo test -e /Library/LaunchDaemons/com.mugvpn.helper.plist").returncode != 0
        assert mac.run("sudo test -e /Library/Logs/MugVPN").returncode != 0
        assert mac.run(f"sudo test -f {support}/config/int47c.ovpn").returncode == 0, "profiles stay"
        assert mac.run("sudo launchctl print system/com.mugvpn.cleanup").returncode != 0, "it ran once and left"
    finally:
        mac.run(f"sudo launchctl bootout system/com.mugvpn.cleanup 2>/dev/null; sudo rm -f {cleanup} {support}/config/int47c.ovpn;"
                f" test -e {APP} || mv {aside} {APP} 2>/dev/null || mv {trashed} {APP}; bash /tmp/install-helper.sh")
        wait_for(lambda: vpn.cli("list").returncode == 0, 60, "the helper back")

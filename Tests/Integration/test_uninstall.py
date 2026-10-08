"""INT-31: uninstalling MugVPN in the stand VM (runs last; puts the stand back after)."""
import os
import subprocess

import pytest

from conftest import APP, CLI, wait_for

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SUPPORT = "/Library/Application Support/MugVPN"


def in_session(cmd):
    """Run as tester inside the GUI login session (its keychain is unlocked there), as from Terminal."""
    return f"sudo launchctl asuser $(id -u) sudo -u tester {cmd}"


@pytest.fixture
def restore_stand(mac):
    yield
    mac.run("rm -rf ~/.Trash/MugVPN*.app")
    for step in ("push", "helper"):
        subprocess.run([f"{ROOT}/tools/stand/stand.sh", step], check=True, capture_output=True)


def test_int31_uninstall(vpn, mac, restore_stand):
    home_cfg = "/Users/tester/Library/Application Support/MugVPN/config"
    mac.run(f"mkdir -p '{home_cfg}' ~/Library/Logs/MugVPN && cp /Users/tester/stand/stand-a.ovpn '{home_cfg}/' "
            f"&& defaults write com.mugvpn.app log_append -bool true", check=True)
    # As if MugVPN had saved it: the item's access list names the app (clear leftovers of earlier runs first).
    while mac.run(in_session("security delete-generic-password -s MugVPN")).returncode == 0:
        pass
    mac.run(in_session(f"security add-generic-password -T {APP} -s MugVPN -a stand-a/password -w secret"), check=True)
    vpn.connected("stand-a")
    r = mac.run(in_session(f"{CLI} --uninstall --yes"), timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    wait_for(lambda: mac.run("pgrep -f MugVPNHelper").returncode != 0, 30, "the helper to end")
    assert mac.run(f"test -e '{SUPPORT}'").returncode != 0
    assert mac.run("test -e /Library/Logs/MugVPN").returncode != 0
    assert mac.run("test -e /Library/LaunchDaemons/com.mugvpn.helper.plist").returncode != 0
    assert mac.run("pgrep -f 'MugVPN/libexec/openvpn'").returncode != 0
    assert vpn.stand_routes() == [] and vpn.openvpn_keys() == []
    assert mac.run("test -e ~/Library/Application\\ Support/MugVPN").returncode != 0
    assert mac.run("test -e ~/Library/Logs/MugVPN").returncode != 0
    assert mac.run("defaults read com.mugvpn.app").returncode != 0
    assert mac.run(in_session("security find-generic-password -s MugVPN")).returncode != 0
    assert mac.run(f"test -e {APP}").returncode != 0, "the app went to the Trash"
    assert mac.run("ls ~/.Trash | grep -q '^MugVPN'").returncode == 0

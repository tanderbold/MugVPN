"""INT-30: persistent profiles (config-auto) started by the helper."""
import pytest

from conftest import APP, CLI, wait_for

AUTO = "/Library/Application Support/MugVPN/config-auto"


@pytest.fixture
def persistent_site(mac, vpn):
    mac.run(f"sudo mkdir -p '{AUTO}' && sudo cp /Users/tester/stand/stand-a.ovpn '{AUTO}/site.ovpn' "
            f"&& sudo chown -R root:wheel '{AUTO}' && sudo chmod 755 '{AUTO}'", check=True)
    yield
    mac.run(f"sudo rm -rf '{AUTO}'", check=True)
    mac.run("pkill -x MugVPN; true")
    vpn.disconnect_all()


def restart_helper(mac):
    mac.run("sudo launchctl kickstart -k system/com.mugvpn.helper", check=True)


def test_int30_persistent_profile(vpn, mac, persistent_site, second_user):
    restart_helper(mac)
    wait_for(lambda: "site" in vpn.list().values(), 30, "the helper to start site on its own")
    wait_for(lambda: vpn.resolve("host.a.test") == "10.91.0.1", 30, "site's tunnel up")
    site = vpn.id_of("site")
    # An administrator's profile keeps the classic openvpn, as root (it sets up its own tunnel).
    pid = vpn.pid_of(site)
    assert mac.out(f"ps -o user= -p {pid}").strip() == "root"
    assert mac.out(f"ps -o comm= -p {pid}").strip().endswith("/libexec/openvpn-root")
    seen = vpn.list(as_user=second_user)
    assert "site" in seen.values(), "every user sees it"
    assert site not in seen, "but not its real id: the management socket's path follows from it"
    r = vpn.cli(f"disconnect {site}", as_user=second_user)
    assert r.returncode != 0 and "not your connection" in r.stderr
    # The app attaches to it (setting "auto", the default).
    mac.run(f"open {APP}", check=True)
    log = f"'/Library/Application Support/MugVPN/run/{site}/openvpn.log'"
    wait_for(lambda: "MANAGEMENT: Client connected" in mac.out(f"sudo cat {log}"), 30, "the app to attach")
    mac.run(f"{CLI} --command exit")
    wait_for(lambda: mac.run("pgrep -x MugVPN").returncode != 0, 30, "the app to quit")
    assert site in vpn.list(), "quitting the app leaves a persistent tunnel up"
    assert vpn.cli(f"disconnect {site}").returncode == 0, "an administrator can stop it"
    wait_for(lambda: site not in vpn.list(), 30, "site to stop")


def test_int30b_untrusted_folder_is_ignored(vpn, mac, persistent_site):
    mac.run(f"sudo chmod 777 '{AUTO}'", check=True)
    restart_helper(mac)
    wait_for(lambda: vpn.cli("list").returncode == 0, 30, "the helper to answer")
    assert "site" not in vpn.list().values()

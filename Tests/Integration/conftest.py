"""Integration tests (layer I of the test plan): the helper, openvpn and the system,
on the test stand only.

Everything runs inside the stand VMs over ssh; nothing here touches the host's
network. Before any test, the targets are checked to be the stand's virtual
machines and not the host (see `_assert_vm`).

    tools/stand/stand.sh up && tools/stand/stand.sh tunnel
    tools/stand/stand.sh push && tools/stand/stand.sh helper
    .venv/bin/pytest Tests/Integration
"""
import ipaddress
import os
import re
import shlex
import socket
import subprocess
import time

import pytest

HOME = os.path.expanduser("~")
KNOWN = f"{HOME}/.ssh/mugvpn-known"
APP = "/Users/tester/Applications/MugVPN.app"
CLI = f"{APP}/Contents/MacOS/MugVPN"
RUN_DIR = "/Library/Application Support/MugVPN/run"
LOGS_DIR = "/Library/Logs/MugVPN"
PROFILES = "/Users/tester/stand"


def _tart_ip(vm):
    out = subprocess.run(["tart", "ip", vm], capture_output=True, text=True)
    if out.returncode != 0:
        pytest.exit(f"stand VM {vm} is not running: tools/stand/stand.sh up", returncode=3)
    return out.stdout.strip()


def _host_addresses():
    out = subprocess.run(["ifconfig"], capture_output=True, text=True).stdout
    return set(re.findall(r"inet (\d+\.\d+\.\d+\.\d+)", out))


class Remote:
    def __init__(self, vm, user, key):
        self.vm, self.user, self.key = vm, user, key
        self.ip = _tart_ip(vm)

    def run(self, cmd, timeout=120, check=False):
        r = subprocess.run(
            ["ssh", "-n", "-i", self.key, "-o", f"UserKnownHostsFile={KNOWN}",
             "-o", "ConnectTimeout=5", f"{self.user}@{self.ip}", cmd],
            capture_output=True, text=True, timeout=timeout)
        if check and r.returncode != 0:
            raise AssertionError(f"{cmd!r} failed ({r.returncode}): {r.stdout}{r.stderr}")
        return r

    def out(self, cmd, timeout=120):
        return self.run(cmd, timeout=timeout).stdout


def _assert_vm(remote, probe, expected):
    """Refuse to run anything unless the target is a stand VM, not the host."""
    ip = ipaddress.ip_address(remote.ip)
    assert ip in ipaddress.ip_network("192.168.64.0/24"), f"{remote.vm}: {ip} is not on Tart's network"
    assert remote.ip not in _host_addresses(), f"{remote.vm}: {ip} is the host itself"
    got = remote.out(probe).strip()
    assert got == expected, f"{remote.vm} does not say it is a VM ({probe!r} gave {got!r})"


@pytest.fixture(scope="session")
def mac():
    m = Remote("mugvpn-mac", "tester", f"{HOME}/.ssh/npp-e2e")
    _assert_vm(m, "sysctl -n kern.hv_vmm_present", "1")
    return m


@pytest.fixture(scope="session")
def srv():
    s = Remote("mugvpn-servers", "admin", f"{HOME}/.ssh/mugvpn-stand")
    _assert_vm(s, "systemd-detect-virt --vm >/dev/null && echo vm", "vm")
    # Servers, the networks behind them and their DNS: a broken stand would
    # otherwise show up as many confusing failures.
    health = s.out("for n in a b c d; do systemctl is-active openvpn-server@$n stand-net@$n; done").split()
    if health != ["active"] * 8:
        pytest.exit(f"stand servers are not healthy ({health}): tools/stand/stand.sh servers", returncode=3)
    return s


class VPN:
    """The MugVPN CLI and the state of the Mac VM's network."""

    def __init__(self, mac):
        self.mac = mac

    def cli(self, args, env=None, as_user=None, timeout=150):
        envs = " ".join(f"{k}={shlex.quote(v)}" for k, v in (env or {}).items())
        cmd = f"{envs} {CLI} {args}"
        if as_user:
            cmd = f"sudo -u {as_user} env {envs} {CLI} {args}"
        return self.mac.run(cmd, timeout=timeout)

    def connect(self, profile, env=None, wait=True, as_user=None):
        path = profile if profile.startswith("/") else f"{PROFILES}/{profile}.ovpn"
        r = self.cli(f"connect {'' if wait else '--no-wait '}{shlex.quote(path)}", env=env, as_user=as_user)
        m = re.search(r"^id: (\S+)", r.stdout, re.M)
        return r, (m.group(1) if m else None)

    def connected(self, profile, env=None):
        r, cid = self.connect(profile, env=env)
        assert r.returncode == 0 and "connected, ip" in r.stdout, f"{profile}: {r.stdout}{r.stderr}"
        return cid

    def list(self, as_user=None):
        out = self.cli("list", as_user=as_user).stdout
        return {line.split()[0]: line.split()[1] for line in out.splitlines() if line.strip()}

    def id_of(self, name):
        return next(i for i, n in self.list().items() if n == name)

    def pid_of(self, cid):
        out = self.cli("list").stdout
        for line in out.splitlines():
            if line.startswith(cid):
                return int(line.split("pid")[1].split()[0])
        return None

    def disconnect_all(self, timeout=30):
        for cid in self.list():
            self.cli(f"disconnect {cid}")
        wait_for(lambda: not self.list(), timeout, "all connections to end")

    # --- system state -----------------------------------------------------
    def routes(self):
        return self.mac.out("netstat -rn -f inet")

    def route_iface(self, dest):
        out = self.mac.out(f"route -n get {dest}")
        m = re.search(r"interface: (\S+)", out)
        return m.group(1) if m else None

    def primary_dns(self):
        # The first "resolver #1" only: a second section (scoped queries) repeats it.
        out = self.mac.out("scutil --dns | awk '/^resolver #1/{f=1} f&&/^$/{exit} f'")
        return re.findall(r"nameserver\[\d+\] : (\S+)", out)

    def openvpn_keys(self):
        out = self.mac.out("echo 'list State:/Network/Service/openvpn-.*' | scutil")
        return re.findall(r"= (State:\S+)", out)

    def resolve(self, name):
        out = self.mac.out(f"dscacheutil -q host -a name {name}")
        m = re.search(r"ip_address: (\S+)", out)
        return m.group(1) if m else None

    def ping(self, ip, tries=3):
        # Right after a tunnel comes up one packet can be lost: a few tries, each its own.
        return any(self.mac.run(f"ping -c1 -t3 {ip}").returncode == 0 for _ in range(tries))

    def tunnel_devices(self):
        out = self.mac.out("ifconfig")
        return dict(re.findall(r"^(utun\d+):.*\n(?:\t.*\n)*?\tinet (10\.8\d\.0\.\d+)", out, re.M))

    def run_dir_entries(self):
        return self.mac.out(f"sudo ls -A {shlex.quote(RUN_DIR)}").split()

    def openvpn_processes(self):
        return self.mac.out("pgrep -f 'MugVPN/libexec/openvpn' || true").split()

    def stand_routes(self):
        """Routes a stand tunnel adds: tunnel and server nets, default halves, the host route to the server."""
        return [l for l in self.routes().splitlines()
                if re.match(r"^(10\.(8|9)\d|0/1|128\.0/1|127\.0\.0\.1/32)\b", l)]

    def clean_state(self):
        return {
            "routes": self.stand_routes(),
            "openvpn_keys": self.openvpn_keys(),
            "run_dir": self.run_dir_entries(),
            "processes": self.openvpn_processes(),
            "primary_dns": self.primary_dns(),
        }

    def helper_log(self, n=30):
        return self.mac.out(f"sudo tail -{n} {LOGS_DIR}/helper.log")


def wait_for(cond, timeout, what):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if cond():
            return
        time.sleep(0.5)
    raise AssertionError(f"timed out waiting for {what}")


@pytest.fixture(scope="session")
def vpn(mac, srv):
    v = VPN(mac)
    if mac.run(f"test -x {CLI}").returncode != 0:
        pytest.exit("MugVPN is not on the Mac VM: tools/stand/stand.sh push && tools/stand/stand.sh helper", returncode=3)
    if mac.run("nc -z -w3 127.0.0.1 1194").returncode != 0:
        pytest.exit("the servers are not reachable from the Mac VM: tools/stand/stand.sh tunnel", returncode=3)
    v.disconnect_all()
    v.baseline_dns = v.primary_dns()
    return v


@pytest.fixture(autouse=True)
def clean_stand(request, vpn):
    """Each test starts and must end with no tunnels and nothing left behind."""
    if "vpn" not in request.fixturenames:
        yield
        return
    vpn.disconnect_all()
    before = vpn.clean_state()
    assert before == {"routes": [], "openvpn_keys": [], "run_dir": [], "processes": [],
                      "primary_dns": vpn.baseline_dns}, f"stand is not clean before the test: {before}"
    yield
    vpn.disconnect_all()
    wait_for(lambda: vpn.clean_state()["primary_dns"] == vpn.baseline_dns and not vpn.stand_routes(), 20,
             "the stand to be clean after the test")
    if request.node.name.startswith("test_int31"):
        return  # uninstalling removes the helper; the test's own fixture puts the stand back
    after = vpn.clean_state()
    assert after == before, f"left behind: {after}"


@pytest.fixture(scope="session")
def second_user(mac):
    if mac.run("id tester2").returncode != 0:
        # A throwaway account in the stand VM; it never logs in.
        mac.run("sudo sysadminctl -addUser tester2 -password \"$(uuidgen)\" -home /Users/tester2", check=True)
    return "tester2"

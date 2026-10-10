"""INT-16..21: what the helper refuses."""
import shlex

import pytest

from conftest import APP, CLI, PROFILES, wait_for

FORBIDDEN = ["up /bin/sh", "down /bin/sh", "route-up /bin/sh", "tls-verify /bin/sh", "plugin /tmp/x.so",
             "script-security 2", "log /etc/evil", "status /tmp/x", "writepid /tmp/x", "cd /", "chroot /",
             "daemon", "config /etc/hosts", "management 127.0.0.1 7505", "setenv opt up /bin/sh",
             "dns-updown /tmp/x", "iproute /tmp/x", "providers legacy", "pkcs11-providers /tmp/x.dylib",
             "tmp-dir /tmp", "dev tap", "user root"]


# directives hidden inside an inline block, where
# openvpn would end the block earlier than the policy did (CFG-22, CFG-23).
HIDDEN = ["\\f", "\\v", "\\r"]


@pytest.mark.parametrize("ws", HIDDEN)
def test_int16b_hidden_in_inline_block(vpn, mac, ws):
    path = "/Users/tester/stand/evil.ovpn"
    mac.run(f"printf 'client\\ndev tun\\nremote 127.0.0.1 1194\\n<ca>\\nX\\n{ws}</ca>\\nstatus /tmp/mugvpn-hidden\\n</ca>\\n' > {path}",
            check=True)
    r, cid = vpn.connect(path, wait=False)
    # Refused by the same parser on either side of XPC: a stray close tag.
    assert r.returncode != 0 and ("refused" in r.stderr or "stray tag" in r.stderr), r.stdout + r.stderr
    assert cid is None and vpn.openvpn_processes() == []
    assert mac.run("test -e /tmp/mugvpn-hidden").returncode != 0


@pytest.mark.parametrize("line", FORBIDDEN)
def test_int16_helper_refuses_forbidden_profiles(vpn, mac, line):
    path = "/Users/tester/stand/evil.ovpn"
    mac.run(f"printf 'client\\ndev tun\\nremote 127.0.0.1 1194\\n%s\\n' {line!r} > {path}", check=True)
    r, cid = vpn.connect(path, wait=False)
    assert r.returncode != 0 and "refused" in r.stderr, r.stdout + r.stderr
    assert cid is None and vpn.list() == {} and vpn.openvpn_processes() == []


@pytest.mark.parametrize("ident", ["com.example.other", "com.mugvpn.app"])
def test_int17_foreign_client_is_rejected(vpn, mac, ident):
    """Another program, even one signed ad hoc under MugVPN's own identifier, is refused."""
    mac.run(f"cp {CLI} /tmp/Other && codesign -f -s - -i {ident} /tmp/Other", check=True)
    r = mac.run("/tmp/Other status --xpc")
    assert "helper version" not in r.stdout
    assert r.returncode != 0


@pytest.fixture
def restore_bundle(mac):
    """Put the bundle's files back and the helper on its feet after a tampering test."""
    mac.run(f"cp {APP}/Contents/Helpers/openvpn /tmp/openvpn.orig", check=True)
    yield
    mac.run(f"cp /tmp/openvpn.orig {APP}/Contents/Helpers/openvpn", check=True)
    mac.run("sudo launchctl kickstart -k system/com.mugvpn.helper")
    wait_for(lambda: "helper version" in mac.out(f"{CLI} status --xpc"), 30, "the helper to come back")


def _helper_refuses_to_start(vpn, mac, message):
    mac.run("sudo launchctl kickstart -k system/com.mugvpn.helper")
    wait_for(lambda: message in vpn.helper_log(3), 15, "the helper to refuse")
    assert "helper version" not in mac.out(f"{CLI} status --xpc", timeout=60)


@pytest.mark.parametrize("how", ["append", "patch"])
def test_int18_tampered_openvpn(vpn, mac, restore_bundle, how):
    f = f"{APP}/Contents/Helpers/openvpn"
    if how == "append":
        mac.run(f"printf x >> {f}", check=True)
    else:
        mac.run(f"printf '\\x90' | dd of={f} bs=1 seek=40000 conv=notrunc 2>/dev/null", check=True)
    _helper_refuses_to_start(vpn, mac, "failed its signature check")


@pytest.mark.parametrize("target", ["genuine", "victim"])
def test_int18b_linked_openvpn(vpn, mac, restore_bundle, target):
    """Helpers/openvpn as a link. To a genuine copy the
    user can swap later, or to a root-only file root would have re-moded."""
    f = f"{APP}/Contents/Helpers/openvpn"
    mac.run("rm -rf /tmp/linked && mkdir /tmp/linked && cp /tmp/openvpn.orig /tmp/linked/openvpn", check=True)
    mac.run("sudo sh -c 'echo secret > /tmp/linked/victim && chown root:wheel /tmp/linked/victim && chmod 600 /tmp/linked/victim'",
            check=True)
    dest = "/tmp/linked/openvpn" if target == "genuine" else "/tmp/linked/victim"
    mac.run(f"rm -f {f} && ln -s {dest} {f}", check=True)
    try:
        _helper_refuses_to_start(vpn, mac, "is not a regular file")
        installed = "/Library/Application Support/MugVPN/libexec/openvpn"
        assert mac.run(f"test -L '{installed}'").returncode != 0, "no link installed"
        assert mac.out("stat -f '%Su %Lp' /tmp/linked/victim").strip() == "root 600", "the target is untouched"
    finally:
        mac.run(f"rm -f {f}", check=True)  # the fixture copies the original back, not through the link
        mac.run("sudo rm -rf /tmp/linked")


def test_int18c_openvpn_environment(vpn, mac):
    """Nothing of the helper's environment reaches openvpn (OPENSSL_CONF...)."""
    a = vpn.connected("stand-a")
    pid = mac.out("pgrep -x openvpn | head -1").strip()
    env = mac.out(f"sudo ps -E -o command= -p {pid}")
    assert "PATH=/usr/bin:/bin:/usr/sbin:/sbin" in env, env
    for bad in ("OPENSSL", "DYLD_", "TMPDIR", "HOME=/Users"):
        assert bad not in env, env
    vpn.disconnect_all()


def test_int20_other_users_cannot_touch_my_tunnels(vpn, mac, second_user):
    a = vpn.connected("stand-a")
    assert vpn.list(as_user=second_user) == {}, "another user does not see it"
    r = vpn.cli(f"disconnect {a}", as_user=second_user)
    assert r.returncode != 0 and "not your connection" in r.stderr
    sock = f"/Library/Application Support/MugVPN/run/{a}/sock/m.sock"
    r = mac.run(f"echo 'state' | sudo -u {second_user} nc -U -w2 '{sock}'")
    assert ">INFO" not in r.stdout and "CONNECTED" not in r.stdout, "management refuses other users"
    assert a in vpn.list()


def test_int21_limits(vpn, mac):
    # 16 tunnels waiting for an unreachable server, then one more.
    path = "/Users/tester/stand/nowhere.ovpn"
    mac.run(f"sed 's|^remote .*|remote 127.0.0.1 9|' /Users/tester/stand/stand-a.ovpn > {path}", check=True)
    for i in range(16):
        r, cid = vpn.connect(path, wait=False)
        assert cid, f"connection {i + 1}: {r.stdout}{r.stderr}"
    r, cid = vpn.connect(path, wait=False)
    assert cid is None and "too many connections" in r.stderr
    vpn.disconnect_all(timeout=60)
    mac.run("head -c 5000000 /dev/zero > /Users/tester/stand/big.bin && "
            f"(cat /Users/tester/stand/stand-a.ovpn; echo 'extra-certs big.bin') > /Users/tester/stand/big.ovpn", check=True)
    r, cid = vpn.connect("/Users/tester/stand/big.ovpn", wait=False)
    assert cid is None and "too large" in r.stderr


def test_int37_live_log_is_root_owned_and_readable(vpn, mac):
    """the live log stays root's (cleanup reads it); its owner can read, not write."""
    a = vpn.connected("stand-a")
    log = f"/Library/Application Support/MugVPN/run/{a}/openvpn.log"
    assert mac.out(f"stat -f %Su '{log}'").strip() == "root"
    assert mac.run(f"test -r '{log}'").returncode == 0, "the owner reads it"
    assert mac.run(f"test -w '{log}'").returncode != 0, "but cannot write it"
    vpn.disconnect_all()


def test_int38_openvpn_has_no_plugins_or_debug(vpn, mac):
    """the bundled openvpn cannot load plug-ins, whatever reached it."""
    ov = "/Library/Application Support/MugVPN/libexec/openvpn"
    out = mac.out(f"'{ov}' --plugin /tmp/x.so 2>&1 | head -5")
    assert "plugin" in out.lower() and ("not" in out.lower() or "unrecognized" in out.lower()), out
    out = mac.out(f"'{ov}' --version 2>&1 | head -3")
    assert "[PLUGINS]" not in out, out


def as_id(uid, cmd):
    """Run `cmd` as a bare id (no account: sudo -u '#id' refuses those)."""
    py = f"import os; os.chdir('/'); os.setgroups([]); os.setgid({uid}); os.setuid({uid}); os.execv('/bin/sh', ['sh', '-c', {cmd!r}])"
    return f"sudo /usr/bin/python3 -c {shlex.quote(py)}"


def test_int40_openvpn_runs_without_root(vpn, mac, second_user):
    """Privilege separation: each connection's openvpn runs as its own id (no account, no root)
    and asks the helper for its tunnel; one cannot read or signal another's."""
    a = vpn.connected("stand-a")
    b = vpn.connected("stand-c", env={"MUGVPN_USER": "test", "MUGVPN_PASS": "secret"})
    ids = []
    for cid in (a, b):
        uid = int(mac.out(f"ps -o uid= -p {vpn.pid_of(cid)}").strip())
        assert 470_000_000 <= uid < 470_000_000 + 4096, uid
        assert mac.run(f"id {uid}").returncode != 0, "no account has it"
        run = f"/Library/Application Support/MugVPN/run/{cid}"
        assert mac.out(f"sudo stat -f '%u %Lp' '{run}/sock'").strip() == f"{uid} 711"
        assert mac.out(f"sudo stat -f '%u:%g %Lp' '{run}/config.ovpn'").strip() == f"0:{uid} 640"
        assert mac.out(f"sudo stat -f '%u %Lp' '{run}/state.json'").strip() == "0 600"
        ids.append((uid, run))
    assert ids[0][0] != ids[1][0], "an id per connection"
    (ua, run_a), (ub, run_b) = ids
    assert mac.run(as_id(ua, "id -u")).stdout.strip() == str(ua), "the probe really runs as A's id"
    assert mac.run(as_id(ua, f"cat '{run_a}/config.ovpn' >/dev/null")).returncode == 0, "A reads its own profile"
    assert mac.run(as_id(ua, f"cat '{run_b}/config.ovpn'")).returncode != 0, "A's openvpn cannot read B's profile"
    assert mac.run(as_id(ua, f"kill -0 {vpn.pid_of(b)}")).returncode != 0, "nor signal B's openvpn"
    assert mac.run(as_id(ua, f"touch '{run_a}/x'")).returncode != 0, "nor write its own run folder"
    assert vpn.ping("10.91.0.1") and vpn.ping("10.93.0.1")
    vpn.disconnect_all()


def test_int42_nothing_outlives_a_connection_id(vpn, mac):
    """whatever runs as a connection's id (a compromised openvpn's children,
    forking as fast as they can) is gone when the connection ends."""
    a = vpn.connected("stand-a")
    uid = int(mac.out(f"ps -o uid= -p {vpn.pid_of(a)}").strip())
    forker = "\n".join([
        "import os, time",
        "if os.fork() == 0:",
        "    os.setsid(); os.chdir('/'); os.setgroups([]); os.setgid(%d); os.setuid(%d)" % (uid, uid),
        "    fd = os.open('/dev/null', os.O_RDWR)",
        "    for i in (0, 1, 2): os.dup2(fd, i)",
        "    while True:",
        "        try:",
        "            if os.fork() == 0:",
        "                time.sleep(300); os._exit(0)",
        "        except OSError:",
        "            pass",
        "        time.sleep(0.02)",
        "os._exit(0)",
    ])
    mac.run(f"sudo /usr/bin/python3 -c {shlex.quote(forker)}", check=True)
    wait_for(lambda: int(mac.out(f"pgrep -U {uid} | wc -l").strip()) > 5, 10, "the forks to start")
    vpn.disconnect_all()
    wait_for(lambda: mac.run(f"pgrep -U {uid}").returncode != 0, 20, "every process of the id to end")


def test_int43_openvpn_is_sandboxed(vpn, mac):
    """openvpn writes only its socket folder, starts nothing, and has a process limit."""
    a = vpn.connected("stand-a")
    pid = vpn.pid_of(a)
    run = f"/Library/Application Support/MugVPN/run/{a}"
    # (Checks with a path go through a variadic call ctypes cannot make on arm64: only these two.)
    probe = "\n".join([
        "import ctypes, sys",
        "lib = ctypes.CDLL('/usr/lib/libSystem.dylib')",
        "lib.sandbox_check.restype = ctypes.c_int",
        "lib.sandbox_check.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]",
        "for pid in map(int, sys.argv[1:]):",
        "    print(*[lib.sandbox_check(pid, op, 0) for op in (None, b'process-fork', b'job-creation', b'mach-register')])",
    ])
    out = mac.out(f"sudo /usr/bin/python3 -c {shlex.quote(probe)} {pid} $$").split()
    assert out == ["1"] * 4 + ["0"] * 4, f"openvpn sandboxed: no fork, no launchd jobs, no services of its own; the probe's shell free: {out}"
    # The sandbox's write rule, seen from outside: openvpn could not create its tmp files elsewhere.
    log = mac.out(f"sudo grep -c 'tmp-dir' '{run}/openvpn.log' || true").strip()
    assert log == "0", "no tmp-dir error: it writes where it may"
    assert vpn.ping("10.91.0.1")
    vpn.disconnect_all()


def test_int44_signature_holds_for_everyone(vpn, mac, second_user):
    """The app's signature verifies without its signing keychain, as root and as any user,
    and the helper answers both users over XPC."""
    for who in ("", "sudo ", f"sudo -u {second_user} "):
        r = mac.run(f"{who}codesign --verify --deep --strict {APP}")
        assert r.returncode == 0, who + r.stdout + r.stderr
    for who in ("", f"sudo -u {second_user} "):
        assert "helper version" in mac.out(f"{who}{CLI} status --xpc"), who


def test_int48_administrator_in_many_groups(vpn, mac):
    """an administrator in more groups than a short list holds is still one: all traffic allowed."""
    if mac.run("id tester3").returncode != 0:
        mac.run('sudo sysadminctl -addUser tester3 -password "$(uuidgen)" -home /Users/tester3 -admin', check=True)
    mac.run("for i in $(seq 1 80); do dseditgroup -o read mvg$i >/dev/null 2>&1 || sudo dseditgroup -o create mvg$i; "
            "sudo dseditgroup -o edit -a tester3 -t user mvg$i; done", timeout=600, check=True)
    assert int(mac.out("id -G tester3 | wc -w").strip()) > 64
    mac.run(f"cp {PROFILES}/stand-d.ovpn /tmp/stand-d.ovpn && chmod 644 /tmp/stand-d.ovpn", check=True)
    r, cid = vpn.connect("/tmp/stand-d.ovpn", as_user="tester3")
    assert r.returncode == 0 and "connected, ip" in r.stdout, r.stdout + r.stderr
    vpn.cli(f"disconnect {cid}", as_user="tester3")
    wait_for(lambda: not vpn.list(), 30, "the connection to end")

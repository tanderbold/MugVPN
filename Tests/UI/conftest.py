"""Interface tests (layer U of the test plan). They run INSIDE the Mac VM, in its
GUI session (tools/stand/stand.sh ui), against MugVPN in E2E mode with the
fake backend (PROTOCOL.md): no helper, no tunnels, no network.
"""
import contextlib
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time

import pytest

APP = os.environ.get("MUGVPN_APP", os.path.expanduser("~/Applications/MugVPN.app"))
BIN = f"{APP}/Contents/MacOS/MugVPN"

MINIMAL = "client\ndev tun\nremote vpn.example.com 1194\n"


class App:
    def __init__(self, home, sock, proc):
        self.home, self.sock_path, self.proc = home, sock, proc
        self.sock = None

    # --- transport ------------------------------------------------------
    def call(self, cmd, **args):
        if self.sock is None:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(self.sock_path)
            self.reader = self.sock.makefile("r")
        self.sock.sendall((json.dumps({"cmd": cmd, **args}) + "\n").encode())
        line = self.reader.readline()
        if not line:
            raise AssertionError(f"the app closed the socket on {cmd}")
        r = json.loads(line)
        if not r.get("ok"):
            raise AssertionError(f"{cmd} {args}: {r.get('error')}")
        return r

    # --- helpers --------------------------------------------------------
    def menu(self):
        return self.call("menu")["items"]

    def menu_item(self, *path):
        items = self.menu()
        node = None
        for title in path:
            node = next((i for i in items if i["title"] == title), None)
            assert node is not None, f"no menu item {title!r} in {[i['title'] for i in items]}"
            items = node.get("children", [])
        return node

    def click(self, *path):
        self.call("click_menu", path=list(path))

    def windows(self, kind=None):
        ws = self.call("windows")["windows"]
        return [w for w in ws if kind is None or w["kind"] == kind]

    def window(self, kind, timeout=5):
        w = wait_for(lambda: next(iter(self.windows(kind)), None), timeout, f"a {kind} window")
        return w

    def no_window(self, kind, timeout=5):
        wait_for(lambda: not self.windows(kind), timeout, f"the {kind} window to close")

    def control(self, w, cid):
        c = next((c for c in w["controls"] if c["id"] == cid), None)
        assert c is not None, f"window {w['kind']} has no control {cid!r}: {[c['id'] for c in w['controls']]}"
        return c

    def set(self, w, cid, value):
        self.call("set", window=w["id"], control=cid, value=value)

    def press(self, w, cid):
        self.call("press", window=w["id"], control=cid)

    def feed(self, profile, *lines):
        self.call("fake_feed", profile=profile, lines=list(lines))

    def sent(self, profile):
        return self.call("fake_sent", profile=profile)["lines"]

    def connect(self, profile):
        """Connect through the menu and bring the fake tunnel up."""
        self.click(profile, "Connect")
        wait_for(lambda: profile in self.call("fake_helper")["starts"], 5, f"{profile} to start")
        self.feed(profile, ">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,203.0.113.1,1194,,")

    def add_profile(self, name, text=MINIMAL, folder=""):
        d = os.path.join(self.home, "config", folder)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, f"{name}.ovpn"), "w") as f:
            f.write(text)
        self.call("rescan")


def wait_for(cond, timeout, what):
    deadline = time.time() + timeout
    while True:
        v = cond()
        if v:
            return v
        if time.time() > deadline:
            raise AssertionError(f"timed out waiting for {what}")
        time.sleep(0.1)


@contextlib.contextmanager
def launched(home, forced=None, reset_defaults=True, language=None, appearance=None, helper_version=None, env_extra=None):
    """MugVPN in E2E mode on `home`; quits it afterwards."""
    sock = os.path.join(tempfile.gettempdir(), f"mvpn-{os.getpid()}-{int(time.time() * 1000) % 100000}.sock")
    if reset_defaults:
        subprocess.run(["defaults", "delete", "com.mugvpn.app.e2e"], capture_output=True)
    env = dict(os.environ, MUGVPN_E2E="1", MUGVPN_E2E_SOCKET=sock, MUGVPN_E2E_HOME=home)
    if forced is not None:
        env["MUGVPN_E2E_FORCED"] = json.dumps(forced)
    if appearance:
        env["MUGVPN_E2E_APPEARANCE"] = appearance
    if helper_version:
        env["MUGVPN_E2E_HELPER_VERSION"] = helper_version
    env.update(env_extra or {})
    args = [BIN] + (["-AppleLanguages", f"({language})"] if language else []) \
        + (["-AppleInterfaceStyle", appearance] if appearance else [])
    proc = subprocess.Popen(args, env=env, stdout=open(os.path.join(home, "app.log"), "a"), stderr=subprocess.STDOUT)
    a = App(home, sock, proc)
    try:
        wait_for(lambda: os.path.exists(sock), 15, "the E2E socket")
        a.call("ping")
        yield a
    finally:
        try:
            a.call("quit")
        except Exception:
            pass
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.terminate()
        if os.path.exists(sock):
            os.unlink(sock)


@pytest.fixture
def home():
    h = tempfile.mkdtemp(prefix="mugvpn-ui-")
    os.makedirs(os.path.join(h, "config"))
    for n in ("stand-a", "stand-b"):
        with open(os.path.join(h, "config", f"{n}.ovpn"), "w") as f:
            f.write(MINIMAL)
    yield h
    shutil.rmtree(h, ignore_errors=True)


@pytest.fixture
def app(home):
    with launched(home) as a:
        yield a

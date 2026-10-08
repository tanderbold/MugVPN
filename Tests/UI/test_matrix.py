"""UI-29: no dead controls. UI-30: what each state offers.

Both bring the profile stand-a into one of four states first:
  disconnected  never connected
  connecting    Connect pressed, openvpn not up yet
  connected     CONNECTED,SUCCESS
  error         the tunnel ended without being asked to (management socket closed)
"""
import json
import subprocess
import time

import pytest

from conftest import launched, wait_for

STATES = ["disconnected", "connecting", "connected", "error"]
# Leaving the app is covered by UI-16/UI-25; here it would end the test.
SKIP_MENU = {"Quit MugVPN"}


def bring(a, state):
    if state == "disconnected":
        return
    a.click("stand-a", "Connect")
    wait_for(lambda: "stand-a" in a.call("fake_helper")["starts"], 5, "the start")
    for w in a.windows("status"):
        a.call("close", window=w["id"])
    if state == "connected":
        a.feed("stand-a", ">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,203.0.113.1,1194,,")
    elif state == "error":
        a.call("fake_close", profile="stand-a")
        wait_for(lambda: a.windows("error"), 5, "the error message")
        for w in a.windows("error"):
            a.call("close", window=w["id"])


def fingerprint(a):
    """Everything an action can observably change."""
    helper = a.call("fake_helper")
    settings = subprocess.run(["defaults", "export", "com.mugvpn.app.e2e", "-"], capture_output=True).stdout
    return json.dumps({
        "windows": sorted((w["kind"], w["title"]) for w in a.windows()),
        "sent": a.sent("stand-a") if "stand-a" in helper["starts"] else [],
        "helper": helper,
        "urls": a.call("opened_urls"),
        "notes": a.call("notifications")["items"],
        "menu": a.menu(),
        "settings": settings.decode(errors="replace"),
        "status": a.call("status"),
    }, sort_keys=True)


def menu_actions(a):
    """Enabled leaf items: (path) for stand-a's submenu and the general items."""
    out = [("stand-a", c["title"]) for c in a.menu_item("stand-a")["children"] if c["enabled"]]
    for item in a.menu():
        if item["title"] in SKIP_MENU or not item["enabled"] or item["title"].startswith("stand-"):
            continue
        if item.get("children"):
            out += [(item["title"], c["title"]) for c in item["children"] if c["enabled"]]
        else:
            out.append((item["title"],))
    return out


def settle(a, before, timeout=3):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if fingerprint(a) != before:
            return True
        time.sleep(0.1)
    return False


@pytest.mark.parametrize("state", STATES)
def test_ui29_every_menu_item_does_something(home, state):
    with launched(home) as probe:
        bring(probe, state)
        actions = menu_actions(probe)
    assert actions, "nothing to check"
    dead = []
    for path in actions:
        # A fresh app per action: each starts from exactly this state.
        with launched(home) as a:
            bring(a, state)
            before = fingerprint(a)
            a.click(*path)
            if not settle(a, before):
                dead.append(" > ".join(path))
    assert not dead, f"{state}: no effect from {dead}"


def status_window(a, state):
    """The status window of stand-a in `state`. For disconnected and error the
    window was opened while connecting and stays (UI-12b)."""
    if state in ("disconnected", "error"):
        a.click("stand-a", "Connect")
        wait_for(lambda: a.windows("status"), 5, "the status window")
        if state == "disconnected":
            a.click("stand-a", "Disconnect")
            a.feed("stand-a", ">STATE:1700000000,EXITING,SIGTERM,,,,,")
        a.call("fake_close", profile="stand-a")
        for e in a.windows("error"):
            a.call("close", window=e["id"])
    else:
        bring(a, state)
        a.click("stand-a", "Show Status")
    return a.window("status")


@pytest.mark.parametrize("state", STATES)
def test_ui29_every_status_window_button_does_something(home, state):
    with launched(home) as a:
        w = status_window(a, state)
        buttons = [c["id"] for c in w["controls"] if c["type"] == "button" and c["enabled"] and c["id"] != "hide"]
    assert buttons, f"{state}: the status window offers nothing"
    dead = []
    for b in buttons:
        with launched(home) as a:
            w = status_window(a, state)
            before = fingerprint(a)
            a.press(w, b)
            if not settle(a, before):
                dead.append(b)
    assert not dead, f"{state}: status window buttons without effect: {dead}"


EXPECTED_MENU = {
    "disconnected": {"Connect": True, "Disconnect": False, "Reconnect": False, "Show Status": False},
    "connecting": {"Connect": False, "Disconnect": True, "Reconnect": True, "Show Status": True},
    "connected": {"Connect": False, "Disconnect": True, "Reconnect": True, "Show Status": True},
    "error": {"Connect": True, "Disconnect": False, "Reconnect": False, "Show Status": False},
}
ALWAYS = ["View Log", "Edit Config", "Connection Settings…"]  # Clear Saved Passwords: only with something saved
EXPECTED_STATUS_WINDOW = {
    "disconnected": {"connect": True, "disconnect": False, "reconnect": False},
    "connecting": {"connect": False, "disconnect": True, "reconnect": True},
    "connected": {"connect": False, "disconnect": True, "reconnect": True},
    "error": {"connect": True, "disconnect": False, "reconnect": False},
}


@pytest.mark.parametrize("state", STATES)
def test_ui30_state_matrix(home, state):
    with launched(home) as a:
        w = status_window(a, state)
        got = {c["title"]: c["enabled"] for c in a.menu_item("stand-a")["children"]}
        for title, enabled in EXPECTED_MENU[state].items():
            assert got[title] == enabled, f"{state}: menu {title} enabled={got[title]}"
        for title in ALWAYS:
            assert got[title], f"{state}: menu {title} should always be available"
        w = a.window("status")
        for cid, enabled in EXPECTED_STATUS_WINDOW[state].items():
            assert a.control(w, cid)["enabled"] == enabled, f"{state}: status window {cid}"


def test_ui30b_clear_saved_passwords_only_with_something_saved(app):
    item = lambda: app.menu_item("stand-a", "Clear Saved Passwords")
    assert not item()["enabled"]
    app.click("stand-a", "Connect")
    app.feed("stand-a", ">PASSWORD:Need 'Auth' username/password")
    w = app.window("credentials")
    app.set(w, "username", "u")
    app.set(w, "password", "p")
    app.set(w, "save", True)
    app.press(w, "ok")
    wait_for(lambda: item()["enabled"], 5, "something to clear")
    app.click("stand-a", "Clear Saved Passwords")
    wait_for(lambda: not item()["enabled"], 5, "nothing left to clear")

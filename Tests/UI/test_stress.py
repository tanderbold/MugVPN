"""UI-32: load and odd inputs. UI-33: random sequences of actions."""
import os
import random
import time

import pytest

from conftest import MINIMAL, wait_for

ODD_NAMES = ["office vpn", "Офис Москва", "home 🏠", "x" * 70, "a.b-c_d (2)"]


def test_ui32_hundred_profiles(app):
    for i in range(100):
        app.add_profile(f"p{i:03d}", folder=f"team{i % 5}")
    start = time.time()
    items = app.menu()
    assert time.time() - start < 2, "the menu builds quickly"
    titles = [i["title"] for i in items]
    assert titles[:5] == [f"team{i}" for i in range(5)], titles[:6]
    assert sum(len(i.get("children", [])) for i in items[:5]) == 100


def test_ui32_odd_profile_names(app):
    for n in ODD_NAMES:
        app.add_profile(n)
    titles = [i["title"] for i in app.menu()]
    for n in ODD_NAMES:
        assert n in titles, n
        app.click(n, "Connect")
        wait_for(lambda: n in app.call("fake_helper")["starts"], 5, f"{n} to start")
        app.feed(n, ">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,203.0.113.1,1194,,")
    wait_for(lambda: all(any(i["title"] == n and i["checked"] for i in app.menu()) for n in ODD_NAMES), 5,
             "all connected")
    assert app.call("status")["icon"] == "connected"


def test_ui32_long_log(app):
    app.connect("stand-a")
    for chunk in range(20):
        app.feed("stand-a", *[f">LOG:17000{chunk:05d},I,2026-10-06 05:46:44 line {chunk * 1000 + i}" for i in range(1000)])
    start = time.time()
    app.click("stand-a", "Show Status")
    log = app.control(app.window("status"), "log")["value"]
    assert time.time() - start < 3, "the status window opens quickly with a long log"
    assert "line 19999" in log, "the latest line is there"
    assert log.count("\n") <= 5001, "older lines are dropped, the window stays light"


def test_ui32b_log_keeps_updating_past_the_cap(app):
    """Found by the past 5000 kept lines the status
    window stopped showing new ones."""
    app.connect("stand-a")
    app.click("stand-a", "Show Status")
    app.feed("stand-a", *[f">LOG:1700000000,I,2026-10-06 05:46:44 old {i}" for i in range(6000)])
    app.feed("stand-a", ">LOG:1700000001,I,2026-10-06 05:46:45 the newest line")
    wait_for(lambda: "the newest line" in app.control(app.window("status"), "log")["value"], 5, "the new line")
    assert app.control(app.window("status"), "log")["value"].count("\n") <= 5001


@pytest.mark.parametrize("content", [b"", b"\x00\x01\x02\xff" * 1000, b"client\n" + b"x" * 5_000_000,
                                     "client\nremote \"unterminated\n".encode()],
                         ids=["empty", "binary", "5MB", "unterminated"])
def test_ui32_broken_imports(app, tmp_path, content):
    f = tmp_path / "broken.ovpn"
    f.write_bytes(content)
    app.call("answer_open_panel", path=str(f))
    app.click("Import", "Import File…")
    w = app.window("error", timeout=10)
    assert app.control(w, "text")["value"], "an explanation"
    app.call("ping")
    assert not any(i["title"] == "broken" for i in app.menu())


SKIP_TITLES = {"Quit MugVPN", "Uninstall MugVPN…"}
SKIP_BUTTONS = {"uninstall"}
LINES = [
    ">STATE:{t},CONNECTED,SUCCESS,10.8.0.2,203.0.113.1,1194,,",
    ">STATE:{t},RECONNECTING,ping-restart,,,,,",
    ">STATE:{t},WAIT,,,,,,",
    ">STATE:{t},EXITING,SIGTERM,,,,,",
    ">PASSWORD:Need 'Auth' username/password",
    ">PASSWORD:Need 'Private Key' password",
    ">PASSWORD:Verification Failed: 'Auth'",
    ">INFOMSG:CR_TEXT:E,R:Code",
    ">ECHO:{t},msg-window Hello",
    ">BYTECOUNT:100,200",
    ">LOG:{t},I,2026-10-06 05:46:44 ERROR: something",
    "garbage line",
]


def leaves(items, prefix=()):
    for i in items:
        if not i["enabled"] or i["title"] in SKIP_TITLES:
            continue
        if i.get("children"):
            yield from leaves(i["children"], prefix + (i["title"],))
        else:
            yield prefix + (i["title"],)


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_ui33_random_actions(app, seed):
    rng = random.Random(seed)
    done = []
    for step in range(100):
        kind = rng.choice(["menu", "button", "feed", "close"])
        try:
            if kind == "menu":
                options = list(leaves(app.menu()))
                if options:
                    path = rng.choice(options)
                    app.click(*path)
                    done.append(("menu", path))
            elif kind == "button":
                ws = app.windows()
                if ws:
                    w = rng.choice(ws)
                    bs = [c["id"] for c in w["controls"] if c["type"] == "button" and c["enabled"]
                          and c["visible"] and c["id"] not in SKIP_BUTTONS and not (w["kind"] == "uninstall")]
                    if bs:
                        b = rng.choice(bs)
                        app.press(w, b)
                        done.append(("press", w["kind"], b))
            elif kind == "feed":
                started = set(app.call("fake_helper")["starts"])
                if started:
                    p = rng.choice(sorted(started))
                    line = rng.choice(LINES).format(t=1700000000 + step)
                    try:
                        app.feed(p, line)
                        done.append(("feed", p, line))
                    except AssertionError:
                        pass  # that tunnel's socket is closed already
            else:
                ws = app.windows()
                if ws:
                    w = rng.choice(ws)
                    app.call("close", window=w["id"])
                    done.append(("close", w["kind"]))
        except AssertionError as e:
            if "closed the socket" in str(e):
                raise AssertionError(f"seed {seed}: the app died at step {step}; last steps {done[-5:]}") from e
            # a window went away between listing and acting: fine
        # Invariants after every step.
        app.call("ping")
        status = app.call("status")
        checked = [i["title"] for i in app.menu() if i.get("checked")]
        assert (status["icon"] == "connected") == bool(checked), \
            f"seed {seed} step {step}: icon {status['icon']} but checked {checked}; last {done[-3:]}"
        assert len(app.windows()) < 40, f"seed {seed}: windows pile up"

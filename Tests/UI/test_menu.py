"""UI-01..04: the status menu and its icon."""
from conftest import wait_for

PROFILE_ITEMS = ["Connect", "Disconnect", "Reconnect", "Show Status", "View Log", "Edit Config", "Clear Saved Passwords",
                 "Connection Settings…"]


def enabled(app, profile):
    return {c["title"]: c["enabled"] for c in app.menu_item(profile)["children"]}


def test_ui01_icon_follows_the_tunnels(app):
    assert app.call("status")["icon"] == "idle"
    assert app.call("status")["image"] == "MenuIcon-idle", "our own icon, not a system symbol"
    app.click("stand-a", "Connect")
    wait_for(lambda: app.call("status")["icon"] == "connecting", 5, "connecting icon")
    app.feed("stand-a", ">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,203.0.113.1,1194,,")
    wait_for(lambda: app.call("status")["icon"] == "connected", 5, "connected icon")
    assert app.call("status")["image"] == "MenuIcon-connected"
    assert "stand-a" in app.call("status")["tooltip"]
    app.connect("stand-b")
    t = app.call("status")["tooltip"]
    assert "stand-a" in t and "stand-b" in t, t
    app.click("stand-a", "Disconnect")
    app.feed("stand-a", ">STATE:1700000001,EXITING,SIGTERM,,,,,")
    app.call("fake_close", profile="stand-a")
    wait_for(lambda: "stand-a" not in app.call("status")["tooltip"], 5, "a to leave the tooltip")
    assert app.call("status")["icon"] == "connected", "b is still up"


def test_ui02_profile_submenu_and_what_is_enabled(app):
    items = app.menu_item("stand-a")["children"]
    assert [i["title"] for i in items] == PROFILE_ITEMS
    e = enabled(app, "stand-a")
    assert e["Connect"] and not e["Disconnect"] and not e["Reconnect"] and not e["Show Status"]
    assert not app.menu_item("stand-a")["checked"]
    app.connect("stand-a")
    e = enabled(app, "stand-a")
    assert not e["Connect"] and e["Disconnect"] and e["Reconnect"] and e["Show Status"]
    assert app.menu_item("stand-a")["checked"]
    assert enabled(app, "stand-b")["Connect"], "another profile can connect at the same time"


def test_ui02b_single_profile_items_at_the_top(app):
    import os
    os.unlink(os.path.join(app.home, "config", "stand-b.ovpn"))
    app.call("rescan")
    titles = [i["title"] for i in app.menu()]
    assert titles[:len(PROFILE_ITEMS)] == PROFILE_ITEMS, titles


def test_ui03_general_items(app):
    titles = [i["title"] for i in app.menu()]
    assert titles[-5:] == ["Import", "Settings…", "Export Diagnostics…", "About MugVPN", "Quit MugVPN"], titles
    imp = [c["title"] for c in app.menu_item("Import")["children"]]
    assert imp == ["Import File…", "Import from Access Server…", "Import from URL…"]


def test_ui03b_no_profiles(app):
    import os
    for n in ("stand-a", "stand-b"):
        os.unlink(os.path.join(app.home, "config", f"{n}.ovpn"))
    app.call("rescan")
    first = app.menu()[0]
    assert first["title"] == "No profiles yet" and not first["enabled"]


def test_ui04_many_profiles_nest_by_folder(app):
    for i in range(30):
        app.add_profile(f"p{i:02d}", folder=f"team{i % 3}")
    titles = [i["title"] for i in app.menu()]
    assert titles[:3] == ["team0", "team1", "team2"], titles
    assert "stand-a" in titles, "loose profiles after the folders"
    assert [c["title"] for c in app.menu_item("team0", "p00")["children"]][0] == "Connect"


def test_ui22_split_dns_option(home):
    from conftest import launched

    def split_dns(a, profile):
        a.click(profile, "Connection Settings…")
        w = a.window("connections")
        a.set(w, "tabs", "options")
        v = a.control(a.window("connections"), "split_dns")["value"]
        return v

    with launched(home) as a:
        assert not split_dns(a, "stand-a")
        a.set(a.window("connections"), "split_dns", True)
        a.press(a.window("connections"), "save")
        assert not split_dns(a, "stand-b")
    with launched(home, reset_defaults=False) as b:
        assert split_dns(b, "stand-a"), "kept across launches"


def test_ui24_persistent_profiles(app):
    import os
    os.makedirs(os.path.join(app.home, "config-auto"))
    with open(os.path.join(app.home, "config-auto", "site.ovpn"), "w") as f:
        f.write("client\ndev tun\nremote site.example.com 1194\n")
    app.call("rescan")
    assert "site" in [i["title"] for i in app.menu()]
    app.click("Settings…")
    w = app.window("settings")
    app.set(w, "persistent", "disable")
    app.press(w, "ok")
    assert "site" not in [i["title"] for i in app.menu()]



def test_ui31_menu_bar_icon_is_drawn(app):
    s = app.call("status")
    assert s["image"].startswith("MenuIcon-")
    assert s["button_width"] >= 16, f"the status item takes room in the menu bar: {s['button_width']}"
    assert s["image_pixels"] > 20, "the picture is not empty"


def test_ui48_disconnect_all(app):
    titles = lambda: [i["title"] for i in app.menu()]
    assert "Disconnect All" not in titles(), "nothing to disconnect"
    app.connect("stand-a")
    assert "Disconnect All" not in titles(), "one: its own Disconnect"
    app.connect("stand-b")
    assert "Disconnect All" in titles()
    app.click("Disconnect All")
    stops = lambda: app.call("fake_helper")["stops"]
    wait_for(lambda: "stand-a" in stops() and "stand-b" in stops(), 5, "both to stop")



def test_ui56_sign_in_to_a_network(app):
    """A network that asks for a sign-in (its page instead of Apple's probe): the menu offers it; while
    a kill switch blocks, signing in lifts the block for two minutes."""
    portal = {"status": 200, "body": "<html>Accept the terms</html>"}
    app.call("fake_blocks", names=["stand-a"])
    app.call("fake_http", responses=[portal])
    app.call("system_event", event="networkChanged")
    wait_for(lambda: "Sign in to This Network…" in [i["title"] for i in app.menu()], 5, "the offer")
    assert any("http://captive.apple.com/hotspot-detect.html" == r["url"] for r in app.call("http_requests")["requests"])
    app.click("Sign in to This Network…")
    wait_for(lambda: app.call("fake_helper")["suspends"] == [120], 5, "the block lifted for a while")
    assert "http://captive.apple.com/hotspot-detect.html" in app.call("opened_urls")["urls"]
    app.call("fake_http", responses=[{"status": 200, "body": "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"}])
    app.call("system_event", event="networkChanged")
    wait_for(lambda: "Sign in to This Network…" not in [i["title"] for i in app.menu()], 5, "signed in")


def test_ui58_sign_in_offered_while_blocked_even_without_an_answer(app):
    """A kill switch's block keeps the probe from getting an answer: signing in is offered all the same."""
    app.call("fake_blocks", names=["stand-a"])          # the probe gets no answer (503 from the fake)
    wait_for(lambda: "Sign in to This Network…" in [i["title"] for i in app.menu()], 5, "the offer")
    app.call("fake_http", responses=[{"status": 200, "body": "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"}])
    app.click("Sign in to This Network…")
    wait_for(lambda: app.call("fake_helper")["suspends"] == [120], 5, "the block lifted for a while")
    # Looked at again once lifted: the network lets everything through, nothing more to offer.
    wait_for(lambda: "Sign in to This Network…" not in [i["title"] for i in app.menu()], 10, "nothing to sign in to")


def test_ui72_narrower_routes_one_quiet_line(app):
    """One VPN routes 10/8, the other subnets inside it: one quiet line in the menu, no notification
    (found with two real VPNs: a pile of warnings)."""
    def log(routes):
        return "".join(f"2026-10-10 05:46:44 MugVPN: route add {r}\n" for r in routes)
    app.connect("stand-a")
    app.call("fake_log", profile="stand-a", text=log(["10.0.0.0 255.0.0.0 10.8.0.1", "192.168.0.0 255.255.0.0 10.8.0.1"]))
    app.connect("stand-b")
    app.call("fake_log", profile="stand-b", text=log(["10.32.32.0 255.255.240.0 10.9.0.1", "10.40.16.0 255.255.248.0 10.9.0.1",
                                                      "192.168.192.0 255.255.255.128 10.9.0.1"]))
    app.feed("stand-b", ">STATE:1700000005,CONNECTED,SUCCESS,10.9.0.2,203.0.113.1,1194,,")
    wait_for(lambda: any("networks out of" in i["title"] for i in app.menu()), 5, "the line")
    lines = [i["title"] for i in app.menu() if "networks out of" in i["title"] or "both route" in i["title"]]
    assert lines == ["ⓘ stand-b takes 3 networks out of stand-a's routes (the more specific route wins)"], lines
    assert not any("networks out of" in n["text"] for n in app.call("notifications")["items"]), "no notification for it"


def test_ui75_warnings_are_items_with_details(app):
    """A warning in the menu is an item, not a greyed-out command: short, and a click shows the details
    with what to do (for DNS: the connection's options)."""
    app.connect("stand-a")
    app.connect("stand-b")
    app.call("fake_dns_state", profile="stand-a", state="all")
    app.call("fake_dns_state", profile="stand-b", state="waiting")
    app.feed("stand-b", ">STATE:1700000005,CONNECTED,SUCCESS,10.9.0.2,203.0.113.1,1194,,")
    item = lambda: next((i for i in app.menu() if "DNS" in i["title"] and i["title"].startswith("⚠︎")), None)
    wait_for(item, 5, "the warning")
    w = item()
    assert w["enabled"], "an item to click"
    assert len(w["title"]) <= 80, w["title"]
    app.click(w["title"])
    d = app.window("warning")
    assert "Only for domains" in app.control(d, "text")["value"]
    app.press(d, "ok")                          # Open Connection Settings
    c = app.window("connections")
    assert app.control(c, "list")["value"] == "stand-b"
    assert app.control(c, "tabs")["value"] == "options"


def test_ui79_open_settings_from_a_warning_finds_its_connection_whatever_the_search(app):
    """Open Connection Settings from a warning shows that connection even if the list's search hides it."""
    app.click("Connections…")
    c = app.window("connections")
    app.set(c, "search", "stand-a")
    app.connect("stand-a")
    app.connect("stand-b")
    app.call("fake_dns_state", profile="stand-a", state="all")
    app.call("fake_dns_state", profile="stand-b", state="waiting")
    app.feed("stand-b", ">STATE:1700000005,CONNECTED,SUCCESS,10.9.0.2,203.0.113.1,1194,,")
    item = lambda: next((i for i in app.menu() if "DNS" in i["title"] and i["title"].startswith("⚠︎")), None)
    wait_for(item, 5, "the warning")
    app.click(item()["title"])
    app.press(app.window("warning"), "ok")      # Open Connection Settings
    c = app.window("connections")
    assert app.control(c, "list")["value"] == "stand-b"
    assert app.control(c, "search")["value"] == "", "the search that hid it is cleared"

"""UI-35..40: the Connections window — settings of each connection, adding
and removing them (as in Viscosity and Tunnelblick)."""
import os
import time

from conftest import MINIMAL, launched, wait_for

CA = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"


def cfg(app, name):
    return open(os.path.join(app.home, "config", f"{name}.ovpn")).read()


def open_window(app, profile=None):
    if profile:
        app.click(profile, "Connection Settings…")
    else:
        app.click("Connections…")
    return app.window("connections")


def tab(app, name):
    w = app.window("connections")
    app.set(w, "tabs", name)
    return app.window("connections")


def select(app, name):
    app.set(app.window("connections"), "list", name)
    return app.window("connections")


def test_ui35_window_list_and_tabs(app):
    w = open_window(app)
    lst = app.control(w, "list")
    assert lst["items"] == ["stand-a", "stand-b"], lst
    assert app.control(w, "tabs")["items"] == ["general", "auth", "options", "advanced"]
    app.call("close", window=w["id"])
    w = open_window(app, "stand-b")
    assert app.control(w, "list")["value"] == "stand-b", "opened on the profile asked for"
    assert app.control(w, "name")["value"] == "stand-b"
    assert app.control(w, "servers")["value"] == "vpn.example.com 1194 udp"
    assert len(app.windows("connections")) == 1, "one window"
    items = [c["title"] for c in app.menu_item("stand-a")["children"]]
    assert "Connection Settings…" in items and "Split DNS by Domain" not in items, items


def test_ui36_edit_and_save(app):
    w = open_window(app, "stand-a")
    assert not app.control(w, "save")["enabled"], "nothing to save yet"
    app.set(w, "servers", "new.example.com 443 tcp\nbackup.example.com")
    app.set(w, "all_traffic", True)
    w = app.window("connections")
    assert app.control(w, "save")["enabled"]
    app.press(w, "save")
    text = cfg(app, "stand-a")
    assert "remote new.example.com 443 tcp\nremote backup.example.com 1194 udp\n" in text, text
    assert "redirect-gateway def1" in text and text.startswith("client\ndev tun\n"), text
    # Revert puts back what is saved.
    w = app.window("connections")
    app.set(w, "servers", "other.example.com")
    app.press(w, "revert")
    w = app.window("connections")
    assert app.control(w, "servers")["value"].startswith("new.example.com 443 tcp")
    # The text on Advanced goes back into the form.
    w = tab(app, "advanced")
    typed = "client\ndev tun\nremote typed.example.com 1195\n"
    app.set(w, "config", typed)
    w = tab(app, "general")
    assert app.control(w, "servers")["value"] == "typed.example.com 1195 udp"
    assert not app.control(w, "all_traffic")["value"]
    assert app.control(w, "save")["enabled"]
    app.press(w, "save")
    w = app.window("connections")
    assert cfg(app, "stand-a") == typed, app.control(w, "error_text")


def test_ui36_refused_edits_keep_the_file(app):
    before = cfg(app, "stand-a")
    w = open_window(app, "stand-a")
    app.set(w, "servers", "")
    w = app.window("connections")
    app.press(w, "save")
    w = app.window("connections")
    e = app.control(w, "error_text")
    assert e["visible"] and "server" in e["value"], e
    assert cfg(app, "stand-a") == before
    app.press(w, "revert")
    w = tab(app, "advanced")
    app.set(w, "config", MINIMAL + "up /bin/sh\n")
    app.press(app.window("connections"), "save")
    w = app.window("connections")
    assert "cannot use" in app.control(w, "error_text")["value"]
    assert cfg(app, "stand-a") == before


def test_ui37_new_connection(app, tmp_path):
    ca = tmp_path / "ca.crt"
    ca.write_text(CA)
    w = open_window(app)
    app.set(w, "add", "new")
    w = app.window("connections")
    assert app.control(w, "list")["value"] == "New Connection"
    app.set(w, "name", "Office")
    app.set(w, "servers", "office.example.com 443 tcp")
    app.press(w, "save")
    w = app.window("connections")
    assert app.control(w, "error_text")["visible"], "no CA, no sign-in yet"
    assert not os.path.exists(os.path.join(app.home, "config", "Office"))
    w = tab(app, "auth")
    app.call("answer_open_panel", path=str(ca))
    app.press(w, "ca_choose")
    w = app.window("connections")
    assert app.control(w, "ca_value")["value"] == "Embedded", app.control(w, "ca_value")
    app.set(w, "ask_password", True)
    app.press(app.window("connections"), "save")
    path = os.path.join(app.home, "config", "Office", "Office.ovpn")
    wait_for(lambda: os.path.exists(path), 5, "the new profile")
    text = open(path).read()
    assert "remote office.example.com 443 tcp" in text and "<ca>\n" + CA + "</ca>" in text and "auth-user-pass" in text
    assert any(i["title"] == "Office" for i in app.menu())
    assert "Office" in app.control(app.window("connections"), "list")["items"]


def test_ui37_import_and_duplicate(app, tmp_path):
    f = tmp_path / "imported.ovpn"
    f.write_text(MINIMAL)
    w = open_window(app, "stand-a")
    app.call("answer_open_panel", path=str(f))
    app.set(w, "add", "file")
    wait_for(lambda: "imported" in app.control(app.window("connections"), "list")["items"], 5, "the import listed")
    for m in app.windows("message"):
        app.call("close", window=m["id"])
    select(app, "stand-a")
    app.set(app.window("connections"), "add", "duplicate")
    w = app.window("connections")
    assert "stand-a copy" in app.control(w, "list")["items"]
    assert app.control(w, "list")["value"] == "stand-a copy"
    assert any(i["title"] == "stand-a copy" for i in app.menu())


def test_ui38_remove(app):
    w = open_window(app, "stand-b")
    app.press(w, "remove")
    c = app.window("confirm")
    app.press(c, "cancel")
    assert os.path.exists(os.path.join(app.home, "config", "stand-b.ovpn"))
    app.press(app.window("connections"), "remove")
    app.press(app.window("confirm"), "ok")
    wait_for(lambda: not os.path.exists(os.path.join(app.home, "config", "stand-b.ovpn")), 5, "the file gone")
    assert not any(i["title"] == "stand-b" for i in app.menu())
    assert app.control(app.window("connections"), "list")["items"] == ["stand-a"]


def test_ui38_connected_is_not_removed(app):
    app.connect("stand-a")
    w = open_window(app, "stand-a")
    app.press(w, "remove")
    app.press(app.window("confirm"), "ok")
    w = app.window("connections")
    assert "connected" in app.control(w, "error_text")["value"]
    assert os.path.exists(os.path.join(app.home, "config", "stand-a.ovpn"))


def test_ui39_options_take_effect(home):
    with launched(home) as a:
        w = open_window(a, "stand-a")
        w = tab(a, "options")
        for cid in ("auto_connect", "split_dns", "silent", "sleep", "proxy"):
            a.control(w, cid)
        assert not a.control(w, "proxy_host")["enabled"], "only for a proxy of its own"
        a.set(w, "auto_connect", True)
        a.set(w, "split_dns", True)
        a.set(w, "silent", "on")
        a.set(w, "proxy", "manual")
        w = a.window("connections")
        assert a.control(w, "proxy_host")["enabled"]
        a.set(w, "proxy_host", "proxy.lan")
        a.set(w, "proxy_port", "3128")
        a.press(a.window("connections"), "save")
        a.call("close", window=a.window("connections")["id"])
        a.click("stand-a", "Connect")
        wait_for(lambda: "stand-a" in a.call("fake_helper")["starts"], 5, "the start")
        assert a.call("fake_helper")["bundles"]["stand-a"]["split_dns"], "split DNS goes to the helper"
        time.sleep(0.5)
        assert not a.windows("status"), "silent: no status window"
        a.feed("stand-a", ">PROXY:1,TCP,vpn.example.com")
        wait_for(lambda: "proxy HTTP proxy.lan 3128" in a.sent("stand-a"), 5, "the own proxy")
        a.click("stand-b", "Connect")
        wait_for(lambda: "stand-b" in a.call("fake_helper")["starts"], 5, "b starts")
        assert not a.call("fake_helper")["bundles"]["stand-b"]["split_dns"]
        a.feed("stand-b", ">PROXY:1,TCP,vpn.example.com")
        wait_for(lambda: any(l.startswith("proxy ") for l in a.sent("stand-b")), 5, "b's answer")
        assert not any("proxy.lan" in l for l in a.sent("stand-b")), "b: as in the general settings"
    with launched(home, reset_defaults=False) as b:
        wait_for(lambda: "stand-a" in b.call("fake_helper")["starts"], 5, "auto-connect at launch")
        assert "stand-b" not in b.call("fake_helper")["starts"]


def test_ui40_unsaved_changes_are_asked_about(app):
    w = open_window(app, "stand-a")
    app.set(w, "servers", "changed.example.com")
    select(app, "stand-b")
    c = app.window("confirm")
    app.press(c, "cancel")
    w = app.window("connections")
    assert app.control(w, "list")["value"] == "stand-a", "stays on the edited one"
    assert app.control(w, "servers")["value"] == "changed.example.com"
    select(app, "stand-b")
    app.press(app.window("confirm"), "ok")
    w = app.window("connections")
    assert app.control(w, "list")["value"] == "stand-b"
    assert "changed" not in cfg(app, "stand-a"), "discarded"


def test_ui40_system_profile_is_read_only(app):
    d = os.path.join(app.home, "system-config")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "corp.ovpn"), "w") as f:
        f.write(MINIMAL)
    app.call("rescan")
    w = open_window(app, "corp")
    assert app.control(w, "readonly_text")["visible"]
    for cid in ("name", "servers", "all_traffic", "remove"):
        assert not app.control(w, cid)["enabled"], cid
    w = tab(app, "options")
    assert app.control(w, "auto_connect")["enabled"], "its MugVPN options are the user's own"


def test_ui41_certificate_buttons_stay_put(app, tmp_path):
    """User's report: Choose and Remove moved left and right with what was chosen;
    the button had a trailing ellipsis."""
    ca = tmp_path / "a-rather-long-certificate-file-name-from-the-admin.crt"
    ca.write_text(CA)
    open_window(app, "stand-a")
    w = tab(app, "auth")
    kinds = ["ca", "cert", "key", "tls_auth", "tls_crypt"]

    def xs(w):
        return {(k, b): app.control(w, f"{k}_{b}")["frame"][0] for k in kinds for b in ("choose", "remove")}

    before = xs(w)
    v = app.control(w, "ca_value")["frame"]
    assert before[("ca", "choose")] - (v[0] + v[2]) < 20, "the button sits next to its text"
    assert v[2] < 120, f"no wide empty gap after the text: {v}"
    assert len({before[(k, "choose")] for k in kinds}) == 1, f"Choose not lined up: {before}"
    assert len({before[(k, "remove")] for k in kinds}) == 1, f"Remove not lined up: {before}"
    assert not app.control(w, "ca_choose")["value"].endswith("…"), app.control(w, "ca_choose")["value"]
    app.call("answer_open_panel", path=str(ca))
    app.press(w, "ca_choose")
    w = app.window("connections")
    assert app.control(w, "ca_value")["value"] == "Embedded"
    assert xs(w) == before, "the buttons stay where they were"
    w = tab(app, "advanced")
    app.set(w, "config", MINIMAL + f"cert {ca.name}\n")
    w = tab(app, "auth")
    assert xs(w) == before, "a long file name does not push them either"


def test_ui42_dns_block(app):
    w = open_window(app, "stand-a")
    w = tab(app, "options")
    assert app.control(w, "dns_mode")["value"] == "server"
    assert not app.control(w, "dns_servers")["enabled"] and not app.control(w, "dns_domains")["enabled"]
    assert app.control(w, "split_dns")["enabled"], "split DNS applies to what the server pushes"
    app.set(w, "dns_mode", "own")
    w = app.window("connections")
    assert app.control(w, "dns_servers")["enabled"] and app.control(w, "dns_domains")["enabled"]
    assert not app.control(w, "split_dns")["enabled"]
    app.set(w, "dns_servers", "10.0.0.53, not-an-ip")
    app.set(w, "dns_domains", "corp.example.com")
    app.press(app.window("connections"), "save")
    w = app.window("connections")
    assert "not-an-ip" in app.control(w, "error_text")["value"]
    assert "dns server" not in cfg(app, "stand-a")
    app.set(w, "dns_servers", "10.0.0.53 10.0.0.54")
    app.press(app.window("connections"), "save")
    text = cfg(app, "stand-a")
    assert 'pull-filter ignore "dns "' in text and "dns server 1 address 10.0.0.53 10.0.0.54" in text, text
    assert "dns server 1 resolve-domains corp.example.com" in text
    app.call("close", window=app.window("connections")["id"])
    w = open_window(app, "stand-a")
    w = tab(app, "options")
    assert app.control(w, "dns_mode")["value"] == "own"
    assert app.control(w, "dns_servers")["value"] == "10.0.0.53, 10.0.0.54"
    assert app.control(w, "dns_domains")["value"] == "corp.example.com"
    app.set(w, "dns_mode", "none")
    app.press(app.window("connections"), "save")
    text = cfg(app, "stand-a")
    assert 'pull-filter ignore "dns "' in text and "dns server" not in text
    app.set(app.window("connections"), "dns_mode", "server")
    app.press(app.window("connections"), "save")
    assert cfg(app, "stand-a") == MINIMAL, "back to as it was"


def test_ui45_protection_options_and_unblock(app):
    """PF protection: per-connection switches go to the helper; a block a kill
    switch left shows in the menu with a way to lift it."""
    w = open_window(app, "stand-a")
    w = tab(app, "options")
    assert not app.control(w, "kill_switch")["value"]
    assert app.control(w, "block_ipv6")["value"] and app.control(w, "dns_only")["value"], "leak protection on by default"
    app.set(w, "kill_switch", True)
    app.set(app.window("connections"), "block_ipv6", False)
    app.press(app.window("connections"), "save")
    app.call("close", window=app.window("connections")["id"])
    app.click("stand-a", "Connect")
    wait_for(lambda: "stand-a" in app.call("fake_helper")["starts"], 5, "the start")
    p = app.call("fake_helper")["bundles"]["stand-a"]["protection"]
    assert p == {"killSwitch": True, "blockIPv6": False, "dnsOnlyTunnel": True, "allowLAN": False}, p
    app.call("fake_blocks", names=["stand-a"])
    wait_for(lambda: any("blocked" in i["title"].lower() for i in app.menu()), 5, "the block in the menu")
    app.click("Unblock Internet")
    wait_for(lambda: not any("blocked" in i["title"].lower() for i in app.menu()), 5, "lifted")
    assert app.call("fake_helper")["unblocks"] == 1


def test_ui45b_lan_while_blocked_is_a_general_setting(app):
    app.click("Settings…")
    w = app.window("settings")
    app.set(w, "allow_lan_when_blocked", True)
    app.press(w, "ok")
    app.click("stand-b", "Connect")
    wait_for(lambda: "stand-b" in app.call("fake_helper")["starts"], 5, "the start")
    assert app.call("fake_helper")["bundles"]["stand-b"]["protection"]["allowLAN"] is True


def test_ui47_persistent_settings_shown_not_changed(app):
    """A persistent profile: the settings the helper applies (beside it in config-auto) are shown,
    and what only the app could apply cannot be changed here."""
    d = os.path.join(app.home, "config-auto")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "site.ovpn"), "w") as f:
        f.write(MINIMAL)
    with open(os.path.join(d, "site.json"), "w") as f:
        f.write('{"kill_switch": true, "block_ipv6": false, "dns_only_tunnel": false, "split_dns": true}')
    app.call("rescan")
    w = open_window(app, "site")
    t = app.control(w, "readonly_text")
    assert t["visible"] and "site.json" in t["value"], t
    w = tab(app, "options")
    for cid, on in (("kill_switch", True), ("block_ipv6", False), ("dns_only", False), ("split_dns", True)):
        c = app.control(w, cid)
        assert bool(c["value"]) == on and not c["enabled"], (cid, c)
    for cid in ("sleep", "proxy"):
        assert not app.control(w, cid)["enabled"], cid
    assert app.control(w, "auto_connect")["enabled"], "the app's own options stay"


def test_ui50_other_sign_in_note_names_what_works(app):
    """PKCS#11 tokens are not supported (openvpn is built without them): the note does not offer them."""
    app.add_profile("p12", MINIMAL + "pkcs12 me.p12\n")
    open_window(app, "p12")
    t = app.control(tab(app, "auth"), "other_text")
    assert t["visible"] and "PKCS#12" in t["value"] and "token" not in t["value"].lower(), t



def test_ui52_find_a_profile(app):
    for n in ("berlin-office", "berlin-lab", "paris"):
        app.add_profile(n)
    w = open_window(app)
    app.set(w, "search", "berlin")
    w = app.window("connections")
    assert app.control(w, "list")["items"] == ["berlin-lab", "berlin-office"], app.control(w, "list")["items"]
    app.set(w, "search", "lab")
    w = app.window("connections")
    assert app.control(w, "list")["items"] == ["berlin-lab"]
    assert app.control(w, "name")["value"] == "berlin-lab", "the one found is shown"
    app.set(w, "search", "")
    assert len(app.control(app.window("connections"), "list")["items"]) == 5



def test_ui53_drop_profiles_on_the_window(app, tmp_path):
    good = tmp_path / "dropped.ovpn"
    good.write_text(MINIMAL)
    other = tmp_path / "notes.txt"
    other.write_text("hello")
    w = open_window(app)
    r = app.call("drop_files", kind="connections", paths=[str(good), str(other)])
    assert r["accepted"] == [str(good)], r
    wait_for(lambda: "dropped" in app.control(app.window("connections"), "list")["items"], 5, "the dropped profile")
    assert "notes" not in app.control(app.window("connections"), "list")["items"]

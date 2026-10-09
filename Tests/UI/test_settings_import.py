"""UI-13, 14, 15: settings and importing profiles."""
import os
import subprocess

from conftest import launched, wait_for


def read_default(key):
    r = subprocess.run(["defaults", "read", "com.mugvpn.app.e2e", key], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def test_ui13_settings_saved(app):
    app.click("Settings…")
    w = app.window("settings")
    for cid in ("silent_connection", "show_balloon", "log_append", "menu_view", "proxy_source", "proxy_host",
                "proxy_port", "preconnect_timeout", "connect_timeout", "disconnect_timeout", "popup_mute",
                "disable_popups", "persistent", "ok", "cancel"):
        app.control(w, cid)
    assert not app.control(w, "proxy_host")["enabled"], "manual proxy fields only for manual"
    app.set(w, "proxy_source", "manual")
    assert app.control(app.window("settings"), "proxy_host")["enabled"]
    app.set(w, "proxy_host", "proxy.lan")
    app.set(w, "proxy_port", "3128")
    app.set(w, "log_append", True)
    app.press(w, "ok")
    app.no_window("settings")
    assert read_default("log_append") == "1"
    assert read_default("proxy_source") == "manual"
    assert read_default("proxy_http_address") == "proxy.lan"


def test_ui13b_bad_value_is_refused(app):
    app.click("Settings…")
    w = app.window("settings")
    app.set(w, "disconnect_timeout", "0")
    app.press(w, "ok")
    w = app.window("settings")
    assert app.control(w, "error_text")["visible"]
    assert read_default("disconnectscript_timeout") is None


def test_ui13c_cancel_keeps_the_old_values(app):
    app.click("Settings…")
    w = app.window("settings")
    app.set(w, "log_append", True)
    app.press(w, "cancel")
    app.no_window("settings")
    assert read_default("log_append") is None


def test_ui14_import_file(app, tmp_path):
    src = tmp_path / "work.ovpn"
    src.write_text("client\ndev tun\nremote w 1194\nca ca.crt\n")
    (tmp_path / "ca.crt").write_text("CA")
    app.call("answer_open_panel", path=str(src))
    app.click("Import", "Import File…")
    wait_for(lambda: any(i["title"] == "work" for i in app.menu()), 5, "the new profile in the menu")
    assert os.path.exists(os.path.join(app.home, "config", "work", "ca.crt"))


def test_ui14b_open_from_finder_and_tblk(app, tmp_path):
    tb = tmp_path / "Office.tblk" / "Contents" / "Resources"
    tb.mkdir(parents=True)
    (tb / "config.ovpn").write_text("client\ndev tun\nremote o 1194\n")
    (tb / "up.sh").write_text("#!/bin/sh\n")
    single = tmp_path / "solo.ovpn"
    single.write_text("client\ndev tun\nremote s 1194\n")
    app.call("open_files", paths=[str(tmp_path / "Office.tblk"), str(single)])
    wait_for(lambda: {"Office", "solo"} <= {i["title"] for i in app.menu()}, 5, "both imported")
    w = app.window("message")
    assert "up.sh" in app.control(w, "text")["value"], "the import report names what was skipped"


def test_ui15_refused_profile_explained(app, tmp_path):
    bad = tmp_path / "evil.ovpn"
    bad.write_text("client\ndev tun\nup /bin/sh\n")
    app.call("answer_open_panel", path=str(bad))
    app.click("Import", "Import File…")
    w = app.window("error")
    text = app.control(w, "text")["value"]
    assert "up" in text and "line 3" in text
    assert not any(i["title"] == "evil" for i in app.menu())


def test_ui13d_forced_settings_are_locked(home):
    with launched(home, forced={"silent_connection": True}) as a:
        a.click("Settings…")
        w = a.window("settings")
        c = a.control(w, "silent_connection")
        assert c["value"] is True and not c["enabled"]
        assert "administrator" in c["label"].lower() or a.control(w, "locked_note")["visible"]


# A real PEM shape: the policy checks what inline blocks hold (POL-36).
PROFILE = "client\ndev tun\nremote vpn.example.com 1194\n<ca>\n-----BEGIN CERTIFICATE-----\nQ0E=\n-----END CERTIFICATE-----\n</ca>\n"


def test_ui23_import_from_access_server(app):
    app.call("fake_http", responses=[{"status": 200, "body": PROFILE, "disposition": 'attachment; filename="office-as.ovpn"'}])
    app.click("Import", "Import from Access Server…")
    w = app.window("import_as")
    for cid in ("server", "username", "password", "autologin", "ok", "cancel"):
        app.control(w, cid)
    app.set(w, "server", "vpn.example.com:943")
    app.set(w, "username", "alice")
    app.set(w, "password", "pw")
    app.set(w, "autologin", True)
    app.press(w, "ok")
    wait_for(lambda: any(i["title"] == "office-as" for i in app.menu()), 5, "the imported profile")
    r = app.call("http_requests")["requests"][0]
    assert r == {"url": "https://vpn.example.com:943/rest/GetAutologin?tls-cryptv2=1&action=import",
                 "username": "alice", "password": "pw"}


def test_ui23b_import_from_url_and_errors(app):
    app.call("fake_http", responses=[{"status": 404, "body": ""}, {"status": 200, "body": PROFILE}])
    app.click("Import", "Import from URL…")
    w = app.window("import_url")
    app.set(w, "url", "https://files.example.com/vpn/work.ovpn")
    app.press(w, "ok")
    e = app.window("error")
    assert "HTTP 404" in app.control(e, "text")["value"]
    app.press(e, "ok")
    app.click("Import", "Import from URL…")
    w = app.window("import_url")
    app.set(w, "url", "https://files.example.com/vpn/work.ovpn")
    app.press(w, "ok")
    wait_for(lambda: any(i["title"] == "work" for i in app.menu()), 5, "the imported profile")


def test_ui25_uninstall(home):
    with launched(home) as a:
        a.click("About MugVPN")
        w = a.window("about")
        a.press(w, "uninstall")
        c = a.window("uninstall")
        assert a.control(c, "keep_profiles")["value"] is False
        a.press(c, "cancel")
        a.no_window("uninstall")
        assert a.call("uninstall_log")["helper"] == []
        a.press(a.window("about"), "uninstall")
        c = a.window("uninstall")
        a.set(c, "keep_profiles", True)
        a.press(c, "ok")
        a.proc.wait(timeout=10)  # done: the app quits
    import json
    log = json.load(open(os.path.join(home, "uninstall.json")))
    assert log["helper"] == [{"keepProfiles": True}]
    assert any(p.endswith("/Library/Logs/MugVPN") for p in log["removed"])
    assert not any(p.endswith("/Application Support/MugVPN") for p in log["removed"]), "profiles kept"
    assert log["trashed"].endswith("MugVPN.app")


def test_ui26_about_license_and_notices(app):
    app.click("About MugVPN")
    w = app.window("about")
    texts = " ".join(c["value"] for c in w["controls"] if c["type"] == "label")
    assert "MIT" in texts and "Windows" not in texts and "GPL" not in texts, texts
    app.press(w, "third_party")
    wait_for(lambda: any(u.endswith("Contents/Resources/THIRD-PARTY-NOTICES.txt") for u in app.call("opened_urls")["urls"]),
             5, "the notices to open")


def test_ui43_outside_files_need_consent(app, tmp_path):
    """a profile naming files outside its
    folder is imported only once the user agrees to copy them."""
    secret = tmp_path / "secret.txt"
    secret.write_text("user\npass\n")
    d = tmp_path / "x"
    d.mkdir()
    prof = d / "evil.ovpn"
    prof.write_text(f"client\nremote e 1194\nauth-user-pass {secret}\n")
    app.call("open_files", paths=[str(prof)])
    c = app.window("confirm")
    shown = app.control(c, "prompt_text")["value"]
    assert str(secret).replace("/private/var/", "/var/") in shown, f"the user sees which file: {shown}"
    app.press(c, "cancel")
    assert not any(i["title"] == "evil" for i in app.menu())
    assert not os.path.exists(os.path.join(app.home, "config", "evil"))
    app.call("open_files", paths=[str(prof)])
    app.press(app.window("confirm"), "ok")
    wait_for(lambda: any(i["title"] == "evil" for i in app.menu()), 5, "imported after consent")


def test_ui43b_downloaded_profile_cannot_name_local_files(app):
    body = "client\nremote e 1194\nauth-user-pass /etc/hosts\n"
    app.call("fake_http", responses=[{"status": 200, "body": body}])
    app.click("Import", "Import from URL…")
    w = app.window("import_url")
    app.set(w, "url", "https://files.example.com/vpn/evil.ovpn")
    app.press(w, "ok")
    e = app.window("error")
    assert "/etc/hosts" in app.control(e, "text")["value"]
    assert not app.windows("confirm"), "not even offered"
    assert not any(i["title"] == "evil" for i in app.menu())


def test_ui43c_imported_script_is_refused(app, tmp_path):
    (tmp_path / "office.ovpn").write_text("client\nremote o 1194\nauth-user-pass office_pre.sh\n")
    (tmp_path / "office_pre.sh").write_text("#\n#\ntouch /tmp/mugvpn-ran\n")
    app.call("open_files", paths=[str(tmp_path / "office.ovpn")])
    e = app.window("error")
    assert "script" in app.control(e, "text")["value"]
    assert not any(i["title"] == "office" for i in app.menu())



def test_ui46_import_asked_by_another_program_needs_a_yes(app, tmp_path):
    """--command import comes from any program of the user: the user confirms."""
    prof = tmp_path / "asked.ovpn"
    prof.write_text("client\nremote a 1194\n")
    app.call("command_import", path=str(prof))
    c = app.window("confirm")
    assert "asked.ovpn" in app.control(c, "prompt_text")["value"]
    app.press(c, "cancel")
    assert not any(i["title"] == "asked" for i in app.menu())
    app.call("command_import", path=str(prof))
    app.press(app.window("confirm"), "ok")
    wait_for(lambda: any(i["title"] == "asked" for i in app.menu()), 5, "imported after yes")


def test_ui49_open_at_login(app):
    """MugVPN itself starts at login when asked (a login item of the system's)."""
    app.click("Settings…")
    w = app.window("settings")
    assert not app.control(w, "launch_at_login")["value"]
    app.set(w, "launch_at_login", True)
    app.press(w, "ok")
    assert app.call("login_item")["enabled"]
    app.click("Settings…")
    w = app.window("settings")
    assert app.control(w, "launch_at_login")["value"], "shows what the system has"
    app.set(w, "launch_at_login", False)
    app.press(w, "ok")
    assert not app.call("login_item")["enabled"]


def test_ui54_export_diagnostics(app, tmp_path):
    import zipfile
    app.add_profile("secretive", "client\nremote a 1194\n<key>\nTOPSECRET\n</key>\n")
    out = tmp_path / "diag.zip"
    app.call("answer_save_panel", path=str(out))
    app.click("Export Diagnostics…")
    wait_for(lambda: out.exists() and zipfile.is_zipfile(out), 30, "the archive")
    z = zipfile.ZipFile(out)
    names = [n.split("/", 1)[1] for n in z.namelist() if "/" in n]
    for want in ("summary.txt", "routes.txt", "dns.txt", "profiles/secretive.ovpn", "profiles/stand-a.ovpn"):
        assert want in names, (want, names)
    text = b"".join(z.read(n) for n in z.namelist() if not n.endswith("/"))
    assert b"TOPSECRET" not in text
    assert b"MugVPN:" in z.read(next(n for n in z.namelist() if n.endswith("summary.txt")))


def test_ui60_open_at_login_refused(app):
    """The system refuses the login item: the window stays, saying why; nothing is claimed done."""
    app.call("fake_login_item_refuses", message="Operation not permitted")
    app.click("Settings…")
    w = app.window("settings")
    app.set(w, "launch_at_login", True)
    app.press(w, "ok")
    w = app.window("settings")
    e = app.control(w, "error_text")
    assert e["visible"] and "Operation not permitted" in e["value"], e
    assert not app.call("login_item")["enabled"]

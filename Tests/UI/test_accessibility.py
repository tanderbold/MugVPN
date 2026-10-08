"""UI-20: accessibility labels and the dark appearance."""
from conftest import launched, wait_for


def titles(a, *path):
    """Menu titles by position, so the same steps work in any language."""
    items = a.menu()
    node = None
    for index in path:
        node = [i for i in items][index]
        items = node.get("children", [])
    return node["title"]


def open_every_window(a, localized=False):
    top = [i["title"] for i in a.menu()]
    settings, about = top[-3], top[-2]
    imp = top[-4]
    imports = [c["title"] for c in a.menu_item(imp)["children"]]
    a.click(settings)
    a.click(about)
    a.click(imp, imports[1])
    a.click(imp, imports[2])
    connect = a.menu_item("stand-a")["children"][0]["title"]
    a.click("stand-a", connect)
    a.feed("stand-a", ">PASSWORD:Need 'Auth' username/password SC:1,PIN")
    a.click("stand-b", connect)
    a.feed("stand-b", ">PASSWORD:Need 'Private Key' password")
    a.feed("stand-b", ">NEED-OK:Need 'x' confirmation MSG:Insert", ">NEED-STR:Need 'y' input MSG:Name")
    a.feed("stand-b", ">INFOMSG:CR_TEXT:E,R:Code")
    a.click("stand-b", a.menu_item("stand-b")["children"][-1]["title"])  # Connection Settings…
    a.call("fake_helper_status", status="requiresApproval")
    a.add_profile("third")
    a.click("third", connect)
    kinds = {"settings", "about", "import_as", "import_url", "credentials", "secret", "confirm", "string",
             "challenge", "status", "helper_setup", "connections"}
    wait_for(lambda: kinds <= {w["kind"] for w in a.windows()}, 10, f"windows {kinds}")
    return a.windows()


def test_ui20a_every_control_has_a_label(app):
    problems = []
    windows = open_every_window(app)
    conn = next(w for w in windows if w["kind"] == "connections")
    for t in app.control(conn, "tabs")["items"][1:]:
        app.set(conn, "tabs", t)
        windows.append(app.window("connections"))
    for w in windows:
        for c in w["controls"]:
            if c["type"] == "view" or not c["visible"]:
                continue
            label = c["label"] if c["type"] not in ("label", "text") or c["label"] else c["value"]
            if c["type"] in ("label",) or c["id"] in ("log", "text", "prompt_text", "error_text", "state_text",
                                                         "ip_text", "bytes_in", "bytes_out", "version", "locked_note"):
                continue  # static text reads itself
            if not label or label == c["id"]:
                problems.append(f"{w['kind']}.{c['id']} ({c['type']}): {label!r}")
    assert not problems, "\n".join(problems)


def test_ui20b_dark_appearance(home):
    import subprocess
    system_dark = subprocess.run(["defaults", "read", "-g", "AppleInterfaceStyle"], capture_output=True,
                                 text=True).stdout.strip() == "Dark"
    with launched(home) as a:
        a.click("Settings…")
        assert a.window("settings")["appearance"] == ("darkAqua" if system_dark else "aqua"), "follows the system"
    with launched(home, appearance="Dark") as a:
        a.click("Settings…")
        assert a.window("settings")["appearance"] == "darkAqua"

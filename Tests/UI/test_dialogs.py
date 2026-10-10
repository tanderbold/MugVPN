"""UI-06..10: what openvpn asks, as the user sees it."""
import base64
import time

from conftest import wait_for


def b64(s):
    return base64.b64encode(s.encode()).decode()


def test_ui06_username_password(app):
    app.click("stand-a", "Connect")
    app.feed("stand-a", ">PASSWORD:Need 'Auth' username/password")
    w = app.window("credentials")
    assert w["profile"] == "stand-a"
    assert app.control(w, "password")["type"] == "secure"
    assert not app.control(w, "error_text")["visible"]
    assert app.control(w, "save")["enabled"]
    app.set(w, "username", "alice")
    app.set(w, "password", "s3cret")
    app.press(w, "ok")
    app.no_window("credentials")
    assert app.sent("stand-a")[-2:] == ['username "Auth" "alice"', 'password "Auth" "s3cret"']


def test_ui06b_wrong_password_asks_again_with_the_error(app):
    app.click("stand-a", "Connect")
    app.feed("stand-a", ">PASSWORD:Need 'Auth' username/password")
    w = app.window("credentials")
    app.set(w, "username", "alice")
    app.set(w, "password", "bad")
    app.call("key", window=w["id"], key="return")
    app.no_window("credentials")
    app.feed("stand-a", ">PASSWORD:Verification Failed: 'Auth'", ">PASSWORD:Need 'Auth' username/password")
    w = app.window("credentials")
    assert app.control(w, "error_text")["visible"]
    assert "Authentication failed" in app.control(w, "error_text")["value"]
    assert app.control(w, "username")["value"] == "alice"
    assert app.control(w, "password")["value"] == ""


def test_ui06c_cancel_disconnects(app):
    app.click("stand-a", "Connect")
    app.feed("stand-a", ">PASSWORD:Need 'Auth' username/password")
    w = app.window("credentials")
    app.call("key", window=w["id"], key="escape")
    app.no_window("credentials")
    wait_for(lambda: "stand-a" in app.call("fake_helper")["stops"], 5, "the tunnel to stop")


def test_ui07_private_key_password(app):
    app.click("stand-a", "Connect")
    app.feed("stand-a", ">PASSWORD:Need 'Private Key' password")
    w = app.window("secret")
    assert app.control(w, "password")["type"] == "secure"
    app.set(w, "password", "keypw")
    app.press(w, "ok")
    assert app.sent("stand-a")[-1] == 'password "Private Key" "keypw"'


def test_ui08_static_challenge(app):
    app.click("stand-a", "Connect")
    app.feed("stand-a", ">PASSWORD:Need 'Auth' username/password SC:1,Enter your PIN")
    w = app.window("credentials")
    r = app.control(w, "response")
    assert r["visible"] and r["type"] == "text", "echo flag: the response is shown"
    assert app.control(w, "prompt_text")["value"] == "Enter your PIN"
    app.set(w, "username", "u")
    app.set(w, "password", "p")
    app.set(w, "response", "1234")
    app.press(w, "ok")
    assert app.sent("stand-a")[-1] == f'password "Auth" "SCRV1:{b64("p")}:{b64("1234")}"'


def test_ui08b_dynamic_challenge(app):
    app.click("stand-a", "Connect")
    app.feed("stand-a", f">PASSWORD:Verification Failed: 'Auth' ['CRV1:R:sid:{b64('alice')}:One-time code']")
    w = app.window("challenge")
    assert app.control(w, "prompt_text")["value"] == "One-time code"
    assert app.control(w, "response")["type"] == "secure", "no echo flag"
    app.set(w, "response", "424242")
    app.press(w, "ok")
    app.feed("stand-a", ">PASSWORD:Need 'Auth' username/password")
    wait_for(lambda: 'password "Auth" "CRV1::sid::424242"' in app.sent("stand-a"), 5, "the CRV1 answer")
    assert not app.windows("credentials")


def test_ui08c_cr_text(app):
    app.click("stand-a", "Connect")
    app.feed("stand-a", ">INFOMSG:CR_TEXT:E,R:Approve, then type the code")
    w = app.window("challenge")
    app.set(w, "response", "77")
    app.press(w, "ok")
    assert app.sent("stand-a")[-1] == f"cr-response {b64('77')}"


def test_ui09_web_authentication(app):
    app.click("stand-a", "Connect")
    app.feed("stand-a", ">INFOMSG:WEB_AUTH::https://sso.example.com/login?x=1")
    wait_for(lambda: "https://sso.example.com/login?x=1" in app.call("opened_urls")["urls"], 5, "the browser")
    assert "web" in app.call("status")["tooltip"].lower()


def test_ui10_server_messages(app):
    app.connect("stand-a")
    app.feed("stand-a", ">ECHO:1,msg Maintenance tonight", ">ECHO:1,msg-window Notice")
    w = app.window("message")
    # Whose message it is, in the window title; the server's title inside.
    assert w["title"] == "MugVPN — stand-a"
    assert app.control(w, "title_text")["value"] == "Notice"
    assert "Maintenance tonight" in app.control(w, "text")["value"]
    app.feed("stand-a", ">ECHO:1,msg Saved", ">ECHO:1,msg-notify Heads up")
    wait_for(lambda: {"title": "stand-a: Heads up", "text": "Saved"} in app.call("notifications")["items"], 5,
             "a notification, under its profile's name")


def test_ui10b_confirm_and_string_requests(app):
    app.click("stand-a", "Connect")
    app.feed("stand-a", ">NEED-OK:Need 'token-insertion-request' confirmation MSG:Insert your token")
    w = app.window("confirm")
    assert "Insert your token" in app.control(w, "prompt_text")["value"]
    app.press(w, "ok")
    assert app.sent("stand-a")[-1] == "needok 'token-insertion-request' ok"
    app.feed("stand-a", ">NEED-STR:Need 'name' input MSG:Your name")
    w = app.window("string")
    app.set(w, "response", "Ann")
    app.press(w, "ok")
    assert app.sent("stand-a")[-1] == "needstr 'name' \"Ann\""


def test_ui10c_pkcs11_choice(app):
    app.click("stand-a", "Connect")
    app.feed("stand-a", ">NEED-STR:Need 'pkcs11-id-request' input MSG:x", ">PKCS11ID-COUNT:2",
             ">PKCS11ID-ENTRY:'0', ID:'id0', BLOB:'B0'", ">PKCS11ID-ENTRY:'1', ID:'id1', BLOB:'B1'")
    w = app.window("pkcs11")
    app.set(w, "certificates", "1")
    app.press(w, "ok")
    assert app.sent("stand-a")[-1] == "needstr 'pkcs11-id-request' \"id1\""


def test_ui70_menu_bar_icon_brings_windows_forward(app):
    """A password prompt lost behind other apps: clicking MugVPN's menu bar icon brings its windows
    forward, the prompt on top, without taking the keyboard from the app in use."""
    app.click("stand-a", "Connect")
    app.feed("stand-a", ">PASSWORD:Need 'Auth' username/password")
    app.window("credentials")
    app.call("send_windows_back")
    wait_for(lambda: not app.call("status")["active"], 5, "another app in use")
    app.call("menu_will_open")
    w = app.window("credentials")
    assert w["front_index"] == 0, w["front_index"]
    time.sleep(0.5)
    assert not app.call("status")["active"], "only shown: the keyboard stays with the app in use"


def test_ui71_paste_into_the_password_field(app):
    """Cmd+V (and the other Edit shortcuts) work in MugVPN's fields: an app without a Dock icon still
    has an Edit menu for them (found in 0.2.4: pasting a password did nothing)."""
    app.click("stand-a", "Connect")
    app.feed("stand-a", ">PASSWORD:Need 'Auth' username/password")
    w = app.window("credentials")
    app.call("pasteboard", text="s3cret-from-the-clipboard")
    app.call("focus", window=w["id"], control="password")
    r = app.call("key_equivalent", key="v")
    assert r["handled"], "the Edit menu takes Cmd+V"
    app.press(app.window("credentials"), "ok")
    assert app.sent("stand-a")[-1] == 'password "Auth" "s3cret-from-the-clipboard"', app.sent("stand-a")[-2:]


def test_ui77_a_prompt_stays_above_windows_opened_after_it(app):
    """A password prompt is up; the user opens Connections from the menu: the prompt stays above it
    (the connection would look stuck behind it), without floating over other apps."""
    app.click("stand-a", "Connect")
    app.feed("stand-a", ">PASSWORD:Need 'Auth' username/password")
    app.window("credentials")
    app.click("Connections…")
    app.window("connections")
    w = app.window("credentials")
    assert w["front_index"] == 0, w["front_index"]
    assert not w["floating"]


def test_ui82_a_window_shown_again_stays_where_it_was_put(app):
    """Settings, Status, Connections opened again: not moved back to the centre (nor to another screen)."""
    app.click("Connections…")
    w = app.window("connections")
    app.call("move", window=w["id"], x=40.0, y=60.0)
    before = app.window("connections")["origin"]
    app.click("Connections…")
    assert app.window("connections")["origin"] == before

"""UI-05, 11, 12, 16, 17, 18: connecting, the status window, notifications, quitting."""
from conftest import MINIMAL, launched, wait_for


def test_ui05_status_window_while_connecting(app):
    app.click("stand-a", "Connect")
    w = app.window("status")
    assert w["profile"] == "stand-a"
    app.feed("stand-a", ">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,203.0.113.1,1194,,")
    app.no_window("status")


def test_ui05b_silent_connection_shows_no_window(app):
    app.click("Settings…")
    s = app.window("settings")
    app.set(s, "silent_connection", True)
    app.press(s, "ok")
    app.click("stand-a", "Connect")
    wait_for(lambda: "stand-a" in app.call("fake_helper")["starts"], 5, "the start")
    assert not app.windows("status")


def test_ui11_notification_on_connect(app):
    app.connect("stand-a")
    wait_for(lambda: any("stand-a" in n["title"] for n in app.call("notifications")["items"]), 5, "connected notice")
    count = len(app.call("notifications")["items"])
    app.feed("stand-a", ">STATE:1700000001,RECONNECTING,ping-restart,,,,,",
             ">STATE:1700000002,CONNECTED,SUCCESS,10.8.0.2,203.0.113.1,1194,,")
    assert len(app.call("notifications")["items"]) == count, "mode 1: not after reconnects"


def test_ui12_status_window_contents(app):
    app.connect("stand-a")
    app.click("stand-a", "Show Status")
    w = app.window("status")
    assert "10.8.0.2" in app.control(w, "ip_text")["value"]
    assert "Connected" in app.control(w, "state_text")["value"]
    app.feed("stand-a", ">BYTECOUNT:2048,1048576", ">LOG:1700000003,I,hello from openvpn")
    def updated():
        w2 = app.window("status")
        return "2.0 KB" in app.control(w2, "bytes_in")["value"] and "1.0 MB" in app.control(w2, "bytes_out")["value"] \
            and "hello from openvpn" in app.control(w2, "log")["value"]
    wait_for(updated, 5, "counters and log")
    app.press(app.window("status"), "reconnect")
    assert app.sent("stand-a")[-1] == "signal SIGUSR1"
    app.press(app.window("status"), "disconnect")
    wait_for(lambda: "stand-a" in app.call("fake_helper")["stops"], 5, "the stop")


def test_ui16_quit_with_tunnels_up(app):
    app.connect("stand-a")
    app.click("Quit MugVPN")
    w = app.window("confirm")
    assert "stand-a" in app.control(w, "prompt_text")["value"]
    app.press(w, "cancel")
    app.no_window("confirm")
    assert app.call("status")["icon"] == "connected", "cancel keeps everything"


def test_ui16b_quit_and_come_back(home):
    with launched(home) as a:
        a.connect("stand-a")
        a.click("Quit MugVPN")
        w = a.window("confirm")
        a.press(w, "ok")
        wait_for(lambda: "stand-a" in a.call("fake_helper")["stops"], 5, "the stop")
        a.call("fake_close", profile="stand-a")
        a.proc.wait(timeout=10)
    with launched(home, reset_defaults=False) as b:
        wait_for(lambda: "stand-a" in b.call("fake_helper")["starts"], 5, "stand-a to come back")


def test_ui17_helper_not_approved(app):
    app.call("fake_helper_status", status="requiresApproval")
    app.click("stand-a", "Connect")
    w = app.window("helper_setup")
    app.press(w, "open_settings")
    wait_for(lambda: any("LoginItems" in u for u in app.call("opened_urls")["urls"]), 5, "System Settings")
    assert "stand-a" not in app.call("fake_helper")["starts"]


def test_ui18_conflict_warning(app):
    halves = ("2026-10-06 05:46:44 /sbin/route add -net 0.0.0.0 10.8.0.1 128.0.0.0\n"
              "2026-10-06 05:46:44 /sbin/route add -net 128.0.0.0 10.8.0.1 128.0.0.0\n")
    app.connect("stand-a")
    app.call("fake_log", profile="stand-a", text=halves)
    app.connect("stand-b")
    app.call("fake_log", profile="stand-b", text=halves)
    app.feed("stand-b", ">STATE:1700000005,CONNECTED,SUCCESS,10.8.0.3,203.0.113.1,1194,,")
    wait_for(lambda: any("all traffic" in i["title"] for i in app.menu()), 5, "a warning in the menu")
    assert any("all traffic" in n["text"] for n in app.call("notifications")["items"])


def test_ui21_wake_and_network_change_reconnect(app):
    app.connect("stand-a")
    app.call("system_event", event="didWake")
    assert app.sent("stand-a")[-1] == "signal SIGUSR1"
    app.call("system_event", event="networkChanged")
    wait_for(lambda: app.sent("stand-a").count("signal SIGUSR1") == 2, 5, "the debounced reconnect")


def test_ui21b_disconnect_on_sleep_setting(app):
    app.click("Settings…")
    w = app.window("settings")
    assert app.control(w, "disconnect_on_sleep")["value"] is False
    app.set(w, "disconnect_on_sleep", True)
    app.press(w, "ok")
    app.connect("stand-a")
    app.call("system_event", event="willSleep")
    wait_for(lambda: "stand-a" in app.call("fake_helper")["stops"], 5, "the stop for sleep")
    app.call("fake_close", profile="stand-a")
    app.call("system_event", event="didWake")
    wait_for(lambda: app.call("fake_helper")["starts"].count("stand-a") == 2, 5, "the reconnect after wake")


def test_ui12b_status_window_connects_again(app):
    app.connect("stand-a")
    app.click("stand-a", "Show Status")
    w = app.window("status")
    assert not app.control(w, "connect")["enabled"] and app.control(w, "disconnect")["enabled"]
    app.press(w, "disconnect")
    app.feed("stand-a", ">STATE:1700000009,EXITING,SIGTERM,,,,,")
    app.call("fake_close", profile="stand-a")
    def disconnected():
        w2 = app.window("status")
        return app.control(w2, "connect")["enabled"] and not app.control(w2, "disconnect")["enabled"] \
            and not app.control(w2, "reconnect")["enabled"]
    wait_for(disconnected, 5, "the window to offer Connect")
    app.press(app.window("status"), "connect")
    wait_for(lambda: app.call("fake_helper")["starts"].count("stand-a") == 2, 5, "connecting again")


def test_ui12c_view_log(app):
    import os
    app.click("stand-a", "View Log")
    w = app.window("message")
    assert "stand-a" in app.control(w, "text")["value"]
    app.press(w, "ok")
    app.connect("stand-a")
    live = os.path.join(app.home, "run", "F-stand-a", "openvpn.log")
    os.makedirs(os.path.dirname(live))
    open(live, "w").write("log\n")
    app.click("stand-a", "View Log")
    wait_for(lambda: any(u.endswith("/run/F-stand-a/openvpn.log") for u in app.call("opened_urls")["urls"]), 5, "the live log")


def test_ui28_coloured_log_and_theme(app):
    import subprocess
    app.connect("stand-a")
    app.feed("stand-a",
             ">LOG:1700000001,I,2026-10-06 05:46:44 Peer Connection Initiated with [AF_INET]192.168.64.1:1194",
             ">LOG:1700000002,E,2026-10-06 05:46:45 ERROR: OS X route add command failed",
             ">LOG:1700000003,I,2026-10-06 05:46:46 Initialization Sequence Completed")
    app.click("stand-a", "Show Status")
    def marks():
        log = app.control(app.window("status"), "log")
        return set(log["highlights"]) >= {"error", "success", "timestamp", "address"} and log
    log = wait_for(marks, 5, "a coloured log")
    w = app.window("status")
    assert app.control(w, "log_theme")["value"] == "system"
    app.set(w, "log_theme", "dark")
    assert app.control(app.window("status"), "log")["theme"] == "dark"
    app.set(app.window("status"), "log_theme", "light")
    assert app.control(app.window("status"), "log")["theme"] == "light"
    r = subprocess.run(["defaults", "read", "com.mugvpn.app.e2e", "log_theme"], capture_output=True, text=True)
    assert r.stdout.strip() == "light", "the choice is kept"


FULL = ("2026-10-06 05:46:44 UDPv4 link remote: [AF_INET]203.0.113.1:1194\n"
        "2026-10-06 05:46:44 Opened utun device utun4\n"
        "2026-10-06 05:46:44 /sbin/route add -net 203.0.113.1 192.168.64.1 255.255.255.255\n"
        "2026-10-06 05:46:44 /sbin/route add -net 0.0.0.0 10.84.0.1 128.0.0.0\n"
        "2026-10-06 05:46:44 /sbin/route add -net 128.0.0.0 10.84.0.1 128.0.0.0\n")
NETSTAT = ("Destination        Gateway            Flags               Netif Expire\n"
           "0/1                10.84.0.1          UGScg               utun4\n"
           "default            192.168.64.1       UGScg                 en0\n"
           "128.0/1            10.84.0.1          UGSc                utun4\n"
           "203.0.113.1/32     192.168.64.1       UGSc                  en0\n"
           "192.168.64         link#5             UCS                   en0      !\n")
SCUTIL = "resolver #1\n  nameserver[0] : 10.84.0.1\n"


def test_ui44_leak_warning(app):
    """Leak check (LEAK-*): a public network routed around a tunnel that should
    carry all traffic shows up in the menu and as a notification."""
    app.connect("stand-a")
    app.call("fake_log", profile="stand-a", text=FULL)
    app.call("fake_network", netstat=NETSTAT, scutil=SCUTIL, interfaces={"10.84.0.1": "utun4"})
    assert app.call("leak_check")["findings"] == [], "all through the tunnel"
    app.call("fake_network", netstat=NETSTAT + "198.51.100/24      192.168.64.1       UGSc                  en0\n",
             scutil=SCUTIL, interfaces={"10.84.0.1": "en0"})
    found = app.call("leak_check")["findings"]
    assert any("198.51.100.0/24" in f for f in found) and any("10.84.0.1" in f for f in found), found
    assert any("198.51.100.0/24" in i["title"] for i in app.menu())
    assert any("198.51.100.0/24" in n["text"] for n in app.call("notifications")["items"])
    app.call("fake_network", netstat=NETSTAT, scutil=SCUTIL, interfaces={"10.84.0.1": "utun4"})
    app.call("leak_check")
    assert not any("⚠︎" in i["title"] for i in app.menu()), "gone once fixed"



SOON_CERT = """-----BEGIN CERTIFICATE-----
MIIBcjCCARegAwIBAgIUTNfpzIXzMkRyMSy1ufaOULblylwwCgYIKoZIzj0EAwIw
DjEMMAoGA1UEAwwDdDEwMB4XDTI2MTAwOTEwNTUzNFoXDTI2MTAxOTEwNTUzNFow
DjEMMAoGA1UEAwwDdDEwMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0XUKhMns
SyI/QaP0cieWzzeOk+wgjjD7m4LpmLAUOiiHyra3xnqG7hcJNmR2FCBCyJWDw84p
yp7JXOTfdJH4caNTMFEwHQYDVR0OBBYEFF+2aFuvl0iubwubrHbTYpNSkJDcMB8G
A1UdIwQYMBaAFF+2aFuvl0iubwubrHbTYpNSkJDcMA8GA1UdEwEB/wQFMAMBAf8w
CgYIKoZIzj0EAwIDSQAwRgIhAIAWd3qjbOZre+3b8VH5TiHy5IzItQViE5KLfmCo
tA79AiEAtNDiOKdnF5YDdi01W91wn6BMR1WpUHA58PHwP++u98I=
-----END CERTIFICATE-----"""


def test_ui51_certificate_running_out(app):
    """Connecting with a client certificate that ends within 30 days (or has ended): a warning."""
    app.add_profile("old", MINIMAL + "<cert>\n" + SOON_CERT + "\n</cert>\n")
    app.connect("old")
    wait_for(lambda: any("certificate" in n["text"].lower() for n in app.call("notifications")["items"]), 5, "the warning")
    n = [n for n in app.call("notifications")["items"] if "certificate" in n["text"].lower()]
    assert len(n) == 1 and "old" in n[0]["title"], n
    app.connect("stand-a")
    assert len([n for n in app.call("notifications")["items"] if "certificate" in n["text"].lower()]) == 1, "stand-a has none"



def test_ui55_helper_of_another_version(home):
    """The running helper is another version than the app (an update it has not taken yet): said once."""
    with launched(home, helper_version="0.0.9") as a:
        wait_for(lambda: any("0.0.9" in n["text"] for n in a.call("notifications")["items"]), 5, "the notice")
        assert len([n for n in a.call("notifications")["items"] if "0.0.9" in n["text"]]) == 1
        a.connect("stand-a")
        assert len([n for n in a.call("notifications")["items"] if "0.0.9" in n["text"]]) == 1, "once"
    with launched(home) as b:
        b.connect("stand-a")
        assert not any("version" in n["text"] for n in b.call("notifications")["items"])



EXPIRED_CERT = """-----BEGIN CERTIFICATE-----
MIIBeTCCAR+gAwIBAgIUHA0JhZP9nGDU+Fu7tTTnY8ihsF8wCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHZXhwaXJlZDAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAw
MDBaMBIxEDAOBgNVBAMMB2V4cGlyZWQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AAQorViZxatob+n+682MKXJ9qF1uHXo5eYchBURUEuOnuizxMwqHZ88zA6Y1LWQB
rWgCZ3Z5Udu2bSUKsONlZfJAo1MwUTAdBgNVHQ4EFgQUvpl4O2aNaI+rtJgOPyAc
rzIuXfIwHwYDVR0jBBgwFoAUvpl4O2aNaI+rtJgOPyAcrzIuXfIwDwYDVR0TAQH/
BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiB+u+NwEO8WkG1OfwO7YezUCjsuhHhb
x8vdTbuTm32sNAIhAPECcIp0nOAM2IjVGagEtD7UR2yroQd8bctvgn+xyZ5Z
-----END CERTIFICATE-----"""


def test_ui59_expired_certificate_said_before_connecting(app):
    """An expired client certificate: said when connecting starts (the server refuses it before any
    connected state)."""
    app.add_profile("expired", MINIMAL + "<cert>\n" + EXPIRED_CERT + "\n</cert>\n")
    app.click("expired", "Connect")
    wait_for(lambda: any("expired" in n["text"] for n in app.call("notifications")["items"]), 5, "the warning")


def test_ui61_an_older_helper_is_put_in_place_by_hand(home):
    """An older helper (no version, no restart call) cannot start itself again: the menu offers to put
    the new one in place; it asks first (every user's tunnels stop), then registers the service again."""
    with launched(home, helper_version="none") as a:
        wait_for(lambda: "Update MugVPN's Helper…" in [i["title"] for i in a.menu()], 5, "the offer")
        a.click("Update MugVPN's Helper…")
        c = a.window("confirm")
        assert "every" in a.control(c, "prompt_text")["value"].lower()
        a.press(c, "cancel")
        assert a.call("fake_helper")["setup"] == []
        a.click("Update MugVPN's Helper…")
        a.press(a.window("confirm"), "ok")
        wait_for(lambda: a.call("fake_helper")["setup"] == ["unregister", "register"], 5, "registered again")

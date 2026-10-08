"""UI-19: the interface in the user's language."""
import pytest

from conftest import launched

EXPECTED = {
    "ru": {"connect": "Подключить", "settings": "Настройки…"},
    "de": {"connect": "Verbinden", "settings": "Einstellungen…"},
}


@pytest.mark.parametrize("lang", sorted(EXPECTED))
def test_ui19_language(home, lang):
    e = EXPECTED[lang]
    with launched(home, language=lang) as a:
        titles = [i["title"] for i in a.menu()]
        assert e["settings"] in titles, titles
        assert a.menu_item("stand-a")["children"][0]["title"] == e["connect"]
        a.click(e["settings"])
        w = a.window("settings")
        assert w["title"] != "MugVPN Settings", "the settings window is translated too"
        ok = a.control(w, "ok")["value"]
        assert ok and ok != "OK" or lang == "de", f"OK button: {ok}"

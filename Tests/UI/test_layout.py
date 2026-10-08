"""UI-27: nothing is cut off, in English and in longer languages."""
import pytest

from conftest import launched
from test_accessibility import open_every_window


LANGUAGES = ["en", "cs", "de", "da", "el", "es", "fa", "fi", "fr", "it", "ja", "ko", "nl", "nb", "pl", "pt-BR",
             "ru", "sv", "tr", "uk", "zh-Hans", "zh-Hant"]


@pytest.mark.parametrize("lang", LANGUAGES)
def test_ui27_nothing_cut_off(home, lang):
    with launched(home, language=None if lang == "en" else lang) as a:
        windows = open_every_window(a, localized=lang != "en")
        # Every tab of the Connections window, not only the first.
        conn = next(w for w in windows if w["kind"] == "connections")
        for t in a.control(conn, "tabs")["items"][1:]:
            a.set(conn, "tabs", t)
            windows.append(a.window("connections"))
        cut = [f"{w['kind']}.{c['id']} {c['value']!r}" for w in windows for c in w["controls"]
               if c["visible"] and c.get("clipped")]
        assert not cut, f"{lang}: " + "; ".join(cut)

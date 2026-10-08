"""CFG-DIFF: our config tokenizer and serializer against openvpn's own parser.

The helper checks a profile with our parser and hands openvpn our serialized
form. If the two parsers ever disagree, a profile could mean one thing to
the policy and another to openvpn. Random `remote` tokens with quotes,
backslashes, spaces and comment characters go through both; openvpn, run as
an ordinary user in the Mac VM, prints what it read (`remote = '...'`) and
stops before it could open a tunnel.
"""
import json
import random
import shlex

from conftest import APP, CLI

OPENVPN = f"{APP}/Contents/Helpers/openvpn"
BASE = ("client\ndev tun\nnobind\nauth-user-pass\nverb 4\n"
        "peer-fingerprint 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF\n")
ALPHABET = list("ab c\\\"'#;\t") + ["\\\\", "\\\"", "\\ ", "\"\"", "''"]


def openvpn_remote(mac, text):
    """What openvpn reads as the remote host, or None if it refuses the config."""
    mac.run(f"cat > /tmp/cfgdiff.ovpn <<'MUGVPN_EOF'\n{text}\nMUGVPN_EOF", check=True)
    out = mac.out(f"{OPENVPN} --config /tmp/cfgdiff.ovpn </dev/null 2>&1 | head -200")
    if "Options error" in out:
        return None
    for line in out.splitlines():
        if "  remote = '" in line:
            return line.split("remote = '", 1)[1].rsplit("'", 1)[0]
    return None


def ours(mac, text):
    mac.run(f"cat > /tmp/cfgdiff-ours.ovpn <<'MUGVPN_EOF'\n{text}\nMUGVPN_EOF", check=True)
    return json.loads(mac.out(f"{CLI} parse /tmp/cfgdiff-ours.ovpn"))


def test_cfg_diff_remote_tokens(vpn, mac):
    rng = random.Random(20261007)
    checked = refused_by_us = 0
    problems = []
    for _ in range(250):
        raw = "".join(rng.choice(ALPHABET) for _ in range(rng.randint(1, 8)))
        text = BASE + f"remote {raw} 1194\n"
        r = ours(mac, text)
        if not r["ok"]:
            refused_by_us += 1
            continue
        remotes = [d["args"] for d in r["directives"] if d["name"] == "remote"]
        if len(remotes) != 1 or len(remotes[0]) != 2 or remotes[0][1] != "1194":
            continue  # tokenized into something that is not a single host: the policy sees exactly that
        host = remotes[0][0]
        if not host:
            continue  # openvpn prints nothing useful for an empty host
        checked += 1
        from_serialized = openvpn_remote(mac, r["serialized"])
        if from_serialized != host:
            problems.append(f"{raw!r}: we read {host!r}, openvpn read our serialization as {from_serialized!r}")
        from_raw = openvpn_remote(mac, text)
        if from_raw is not None and from_raw != host:
            problems.append(f"{raw!r}: we read {host!r}, openvpn read the original as {from_raw!r}")
    assert checked >= 40, f"too few comparable cases ({checked}; refused by us {refused_by_us})"
    assert not problems, "\n".join(problems[:10])


def test_cfg_diff_inline_block_end(vpn, mac):
    """an inline block ends for us exactly
    where it ends for openvpn, whatever whitespace precedes the close tag."""
    problems = []
    for ws in ["", " ", "\t", "\v", "\f", "\r", "\v \t", "\f\f"]:
        text = BASE + f"<ca>\nX\n{ws}</ca>\nremote marker 1194\n"
        r = ours(mac, text)
        we_close = r["ok"] and any(d["name"] == "remote" for d in r["directives"])
        openvpn_closes = openvpn_remote(mac, text) == "marker"
        if we_close != openvpn_closes:
            problems.append(f"{ws!r}: ours {we_close}, openvpn {openvpn_closes}")
    assert not problems, problems


def test_cfg_diff_long_lines_refused(vpn, mac):
    """CFG-23: a line openvpn would read in pieces is refused by us."""
    for text in [BASE + "<ca>\n" + "A" * 300 + "\n</ca>\nremote marker 1194\n",
                 BASE + "setenv-safe X " + "B" * 250 + "\nremote marker 1194\n"]:
        assert not ours(mac, text)["ok"]

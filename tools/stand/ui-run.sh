#!/bin/zsh
# Runs on the Mac VM (stand.sh ui): pytest for the interface tests as a
# launchd job of the user's GUI session, so the app's windows can become key
# and active as on a real desktop. Streams the output; exits with pytest's code.
set -e
args_b64=$1
venv=~/mugvpn/venv
if [[ ! -x $venv/bin/pytest ]]; then
    /Library/Frameworks/Python.framework/Versions/3.13/bin/python3 -m venv $venv
    $venv/bin/pip -q install pytest==9.1.1 pytest-timeout==2.4.0
fi
id="com.mugvpn.ui.$(uuidgen)"
d=~/mugvpn/runs/$id
mkdir -p $d
print -r -- "$args_b64" | base64 -D > $d/args
cat > $d/job.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Label</key><string>$id</string>
<key>ProgramArguments</key><array>
<string>/bin/zsh</string><string>-c</string>
<string>cd ~/mugvpn/ui; $venv/bin/pytest -p no:cacheprovider --timeout 120 \$(cat '$d/args') &gt; '$d/out' 2&gt;&amp;1; echo \$? &gt; '$d/rc'</string>
</array>
<key>RunAtLoad</key><true/>
</dict></plist>
EOF
: > $d/out
launchctl bootstrap "gui/$(id -u)" $d/job.plist
tail -n +1 -f $d/out & t=$!
while [[ ! -f $d/rc ]]; do sleep 1; done
sleep 1
kill $t 2>/dev/null || true
launchctl bootout "gui/$(id -u)/$id" 2>/dev/null || true
rc=$(cat $d/rc)
rm -rf $d
exit $rc

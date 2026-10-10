#!/bin/bash
# Runs on the Mac VM (stand.sh helper): install MugVPN's helper from
# ~/Applications/MugVPN.app as a plain LaunchDaemon, for development only.
set -euo pipefail
A=/Users/tester/Applications/MugVPN.app
"$A/Contents/MacOS/MugVPN" unregister >/dev/null 2>&1 || true
sudo launchctl bootout system/com.mugvpn.helper 2>/dev/null || true
sudo mkdir -p /Library/Logs/MugVPN
sudo /usr/bin/python3 - "$A" <<'EOF'
import plistlib, sys
app = sys.argv[1]
p = plistlib.load(open(app + "/Contents/Library/LaunchDaemons/com.mugvpn.helper.plist", "rb"))
bundle_program = p.pop("BundleProgram")
p["Program"] = app + "/" + bundle_program
# argv[0] as SMAppService gives it: relative to the bundle (0.2.2 took its bundle from argv[0] and
# found /Contents; the stand's absolute path had hidden that).
p["ProgramArguments"] = [bundle_program]
p["RunAtLoad"] = True
p["KeepAlive"] = {"SuccessfulExit": False}
# Not tied to the app's Login Items entry: an unapproved SMAppService
# registration of the same label would keep it from loading at boot.
p.pop("AssociatedBundleIdentifiers", None)
plistlib.dump(p, open("/Library/LaunchDaemons/com.mugvpn.helper.plist", "wb"))
EOF
sudo chown root:wheel /Library/LaunchDaemons/com.mugvpn.helper.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/com.mugvpn.helper.plist
for _ in $(seq 1 20); do
    sudo launchctl print system/com.mugvpn.helper 2>/dev/null | grep -q "state = running" && break
    sleep 0.5
done
sudo launchctl print system/com.mugvpn.helper | grep -E "state =|last exit" || true
sudo tail -3 /Library/Logs/MugVPN/helper.log

#!/bin/bash
# The MugVPN test stand: two Tart VMs on the host's shared NAT.
#   mugvpn-mac      macOS client (a clone of NotepadMac's npp-e2e VM, user tester)
#   mugvpn-servers  Ubuntu with the OpenVPN test servers (user admin)
# Nothing here touches the host's own network or VPN profiles.
#
#   tools/stand/stand.sh up              start both VMs, wait for ssh
#   tools/stand/stand.sh servers         (re)configure the servers, fetch client profiles
#   tools/stand/stand.sh tunnel          forward the servers' ports into the Mac VM
#   tools/stand/stand.sh push           copy build/MugVPN.app and the profiles to the Mac VM
#   tools/stand/stand.sh helper          (re)install the helper as a plain LaunchDaemon
#                                        (development path: no Login Items approval)
#   tools/stand/stand.sh ui [pytest args]  interface tests in the Mac VM's GUI session
#   tools/stand/stand.sh mac 'cmd'       run a command on the Mac VM
#   tools/stand/stand.sh srv 'cmd'       run a command on the server VM
#   tools/stand/stand.sh down            stop both VMs
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MAC_VM=mugvpn-mac
SRV_VM=mugvpn-servers
KNOWN="$HOME/.ssh/mugvpn-known"
MAC_SSH=(ssh -n -i "$HOME/.ssh/npp-e2e" -o UserKnownHostsFile="$KNOWN" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5)
SRV_SSH=(ssh -n -i "$HOME/.ssh/mugvpn-stand" -o UserKnownHostsFile="$KNOWN" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5)
PROFILES="$ROOT/build/stand/profiles"

ip_of() { tart ip "$1" 2>/dev/null || tart ip --resolver arp "$1" 2>/dev/null; }

start() { # vm user ssh...
    local vm=$1; shift
    if ! tart list | awk -v v="$vm" '$2 == v && $NF == "running" {f=1} END {exit !f}'; then
        mkdir -p "$ROOT/build/stand"
        nohup tart run --no-graphics "$vm" </dev/null >"$ROOT/build/stand/$vm.log" 2>&1 &
    fi
    for _ in $(seq 1 120); do
        local ip; ip=$(ip_of "$vm") && "$@" "$ip" true 2>/dev/null && return 0
        sleep 1
    done
    echo "$vm: no ssh" >&2; return 1
}

mac() { "${MAC_SSH[@]}" "tester@$(ip_of $MAC_VM)" "$@"; }
srv() { "${SRV_SSH[@]}" "admin@$(ip_of $SRV_VM)" "$@"; }

case "${1:-}" in
    up)
        start $SRV_VM sh -c "${SRV_SSH[*]} admin@\$0 \"\$@\""
        start $MAC_VM sh -c "${MAC_SSH[*]} tester@\$0 \"\$@\""
        echo "servers $(ip_of $SRV_VM), mac $(ip_of $MAC_VM)"
        # After a reboot: load the development helper again if the app is there.
        if mac 'test -x ~/Applications/MugVPN.app/Contents/MacOS/MugVPNHelper'; then
            "$0" helper | tail -1
        fi
        ;;
    servers)
        scp -q -i "$HOME/.ssh/mugvpn-stand" -o UserKnownHostsFile="$KNOWN" \
            "$ROOT/tools/stand/servers-setup.sh" "admin@$(ip_of $SRV_VM):/tmp/servers-setup.sh"
        srv 'sudo bash /tmp/servers-setup.sh 2>&1 | grep -v "^[.+*-]" | tail -6'
        mkdir -p "$PROFILES"
        for n in a b c d e f; do
            srv "sudo cat /etc/openvpn/stand/clients/stand-$n.ovpn" > "$PROFILES/stand-$n.ovpn"
        done
        ls "$PROFILES"
        ;;
    push)
        [ -e "$ROOT/build/MugVPN.app/Contents/Resources/testing-build" ] || {
            echo "the stand needs the testing build: MUGVPN_TESTING=1 tools/build.sh" >&2; exit 1; }
        rs() { rsync -a --delete -e "ssh -i $HOME/.ssh/npp-e2e -o UserKnownHostsFile=$KNOWN" "$@"; }
        mac 'mkdir -p ~/Applications ~/stand'
        rs "$ROOT/build/MugVPN.app/" "tester@$(ip_of $MAC_VM):Applications/MugVPN.app/"
        rs "$PROFILES/" "tester@$(ip_of $MAC_VM):stand/"
        ;;
    helper)
        # An ad-hoc build's Login Items approval is tied to its cdhash, so every
        # rebuild would need a click in System Settings. For development the
        # helper runs as an ordinary LaunchDaemon from the same bundle instead.
        scp -q -i "$HOME/.ssh/npp-e2e" -o UserKnownHostsFile="$KNOWN" \
            "$ROOT/tools/stand/install-helper.sh" "tester@$(ip_of $MAC_VM):/tmp/install-helper.sh"
        mac 'bash /tmp/install-helper.sh'
        ;;
    tunnel)
        # Tart isolates its VMs from each other, so the Mac VM's 127.0.0.1:1194-1197
        # (and 1198-1199) are forwarded over ssh, through the host, to the servers (TCP only).
        pidf="$ROOT/build/stand/tunnel.pid"
        [ -f "$pidf" ] && kill "$(cat "$pidf")" 2>/dev/null || true
        srv_ip=$(ip_of $SRV_VM)
        fw=(); for p in 1194 1195 1196 1197 1198 1199; do fw+=(-R "127.0.0.1:$p:$srv_ip:$p"); done
        ssh -N -f -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -i "$HOME/.ssh/npp-e2e" \
            -o UserKnownHostsFile="$KNOWN" "${fw[@]}" "tester@$(ip_of $MAC_VM)"
        pgrep -f "ssh -N -f .*127.0.0.1:1194:$srv_ip" > "$pidf"
        echo "tunnel up (pid $(cat "$pidf"))"
        ;;
    ui)
        # Interface tests inside the Mac VM's GUI session (Tests/UI, PROTOCOL.md).
        shift
        rs() { rsync -a --delete -e "ssh -i $HOME/.ssh/npp-e2e -o UserKnownHostsFile=$KNOWN" "$@"; }
        mac 'mkdir -p ~/mugvpn'
        rs "$ROOT/Tests/UI/" "tester@$(ip_of $MAC_VM):mugvpn/ui/"
        rs "$ROOT/tools/stand/ui-run.sh" "tester@$(ip_of $MAC_VM):mugvpn/ui-run.sh"
        mac "zsh ~/mugvpn/ui-run.sh $(printf '%s ' "${@:-.}" | base64)"
        ;;
    mac) shift; mac "$@" ;;
    srv) shift; srv "$@" ;;
    down)
        tart stop $MAC_VM 2>/dev/null || true
        tart stop $SRV_VM 2>/dev/null || true
        ;;
    *) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac

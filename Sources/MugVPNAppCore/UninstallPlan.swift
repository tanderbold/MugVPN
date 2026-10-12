import Foundation
import MugVPNCore

/// What uninstalling removes for the user (the helper removes the system part).
public enum UninstallPlan {
    /// That command as printed for an administrator to paste (single-quoted: nothing in it for their shell).
    public static func printedCommand(keepProfiles: Bool) -> String {
        "sudo sh -c " + ShellProcessCheck.quoted(systemRemovalScript(keepProfiles: keepProfiles))
    }

    /// The system part, removed without the helper (one that does not answer): a command for an administrator.
    public static func systemRemovalScript(keepProfiles: Bool) -> String {
        let support = "/Library/Application Support/MugVPN"
        // What a tunnel left that only a helper can undo (its run records, DNS on record): nothing is removed while
        // there is any (exit 2, MugVPN stays installed; started again, its helper undoes it). The run folder goes
        // only when empty.
        var paths = [support + "/uninstall-pending.json", support + "/libexec", support + "/locks.json", support + "/app-location",
                     "/Library/Logs/MugVPN", "/Library/LaunchDaemons/com.mugvpn.helper.plist",
                     "/Library/LaunchDaemons/com.mugvpn.cleanup.plist"]
        if !keepProfiles { paths += [support + "/config", support + "/config-auto", support + "/policy.json"] }
        // Each step must hold, or nothing is removed (the helper's files are what could put things back): the
        // helper gone from launchd, its openvpn stopped, MugVPN's PF rules out (its token given back).
        // Gone only when launchd says so ("Could not find service"; any other answer, or none, stops it), and no helper
        // process left once it had its time to stop its tunnels (up to 17 s). (And the boot cleanup kept while the app
        // was in the Trash.) Any answer of pgrep or pkill but "found" or "none" stops it all.
        func unload(_ label: String) -> String {
            "launchctl bootout system/\(label) 2>/dev/null; gone_from_launchd \(label) 30 || "
                + "{ echo 'launchd still has \(label) (or could not tell): try again.' >&2; exit 1; }; "
        }
        let openvpnPattern = ShellProcessCheck.quoted(ShellProcessCheck.pattern(support + "/libexec/openvpn"))
        let gone = ShellProcessCheck.noneLeftFunction(onError: "echo 'Could not tell which MugVPN processes run: try again.' >&2")
            + ShellProcessCheck.goneFromLaunchdFunction
            + unload("com.mugvpn.helper") + unload("com.mugvpn.cleanup")
            + "none_left \(ShellProcessCheck.quoted(ShellProcessCheck.helperPattern)) 20 || "
            + "{ echo 'The MugVPN helper still runs: try again.' >&2; exit 1; }; "
        let openvpn = "pkill -9 -f \(openvpnPattern); [ $? -le 1 ] || { echo 'Could not stop the MugVPN openvpn: try again.' >&2; exit 1; }; "
            + "none_left \(openvpnPattern) 5 || { echo 'The MugVPN openvpn still runs: try again.' >&2; exit 1; }; "
        // PF's token taken back. Refused: only an earlier boot's token may go without (it means nothing now); this
        // boot's, or one whose boot cannot be told, stops it all. No file of its own anywhere (a world-writable
        // folder could hold a link): the boot time goes to grep as patterns on its standard input.
        let token = "'\(support)/pf.token'", answer = "'\(support)/pf.release'"
        let pf = "pfctl -a 'com.apple/mugvpn' -F all || exit 1; "
            // (A token PF no longer knows was given back before, the run stopped before its file went: counts as given.)
            // (Asked once; its answer kept in MugVPN's own folder, which only root can write to.)
            + "if [ -f \(token) ]; then cut -d' ' -f2 \(token) | xargs -n1 pfctl -X > \(answer) 2>&1 || "
            + "grep -q -e 'Invalid argument' -e 'No such' \(answer) || { "
            + "sysctl -n kern.boottime | grep -q 'sec = ' || exit 1; "
            + "sysctl -n kern.boottime | sed -e 's/^{ sec = \\([0-9]*\\),.*/^\\1 /' | grep -q -f /dev/stdin \(token) "
            + "&& { echo 'PF did not take back MugVPN s token: try again.' >&2; exit 1; }; }; fi; "
            + "rm -f \(token) \(answer) || exit 1; "
        let stop = "{ echo 'A tunnel left DNS or routes that the helper must undo first: open MugVPN again, then uninstall.' >&2; exit 2; }"
        let pending = "ls -A '\(support)/run' 2>/dev/null | grep -q . && \(stop); [ -e '\(support)/dns-left.json' ] && \(stop); "
        var script = gone + openvpn + pending + pf + "rm -rf " + paths.map { "'\($0)'" }.joined(separator: " ") + " || exit 1"
            // (Empty by now: checked above.) Either folder that would not go is not success.
            + "; [ ! -e '\(support)/run' ] || rmdir '\(support)/run' || exit 1"
        if !keepProfiles {
            script += "; [ ! -e '\(support)' ] || rmdir '\(support)' || { echo 'Something MugVPN did not expect is still in "
                + "\(support): remove it, then uninstall again.' >&2; exit 1; }"
        }
        return script + "; exit 0"
    }

    public static func userPaths(home: String, keepProfiles: Bool) -> [String] {
        var paths: [String] = []
        if !keepProfiles { paths.append(home + "/Library/Application Support/MugVPN") }
        paths.append(home + "/Library/Logs/MugVPN")
        paths.append(home + "/Library/Preferences/com.mugvpn.app.plist")
        return paths
    }
}

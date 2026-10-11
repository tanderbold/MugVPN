import Foundation

/// What uninstalling removes for the user (the helper removes the system part).
public enum UninstallPlan {
    /// The system part, removed without the helper (one that does not answer): a command for an
    /// administrator (fixed paths, single-quoted: nothing for a shell to expand).
    public static func systemRemovalScript(keepProfiles: Bool) -> String {
        let support = "/Library/Application Support/MugVPN"
        // What a tunnel left that only a helper can undo (its run records, DNS on record): nothing is removed while
        // there is any (exit 2, MugVPN stays installed; started again, its helper undoes it). The run folder goes
        // only when empty.
        var paths = [support + "/uninstall-pending.json", support + "/libexec", support + "/locks.json",
                     "/Library/Logs/MugVPN", "/Library/LaunchDaemons/com.mugvpn.helper.plist"]
        if !keepProfiles { paths += [support + "/config", support + "/config-auto", support + "/policy.json"] }
        // (Nothing for a shell to expand: the command is also printed for pasting into sudo sh -c "...".)
        // Each step must hold, or nothing is removed (the helper's files are what could put things back): the
        // helper gone from launchd, its openvpn stopped, MugVPN's PF rules out (its token given back).
        let gone = "launchctl bootout system/com.mugvpn.helper 2>/dev/null; launchctl print system/com.mugvpn.helper >/dev/null 2>&1 && exit 1; "
        let openvpn = "pkill -9 -f '\(support)/libexec/openvpn' 2>/dev/null; "
        // PF's token: this boot's must be taken back (or nothing is removed); an earlier boot's means nothing now and
        // goes. (The boot time compared through a pattern file: nothing for a shell to expand.)
        let token = "'\(support)/pf.token'", boot = "'/private/var/tmp/mugvpn-uninstall-boot'"
        let pf = "pfctl -a 'com.apple/mugvpn' -F all || exit 1; "
            + "sysctl -n kern.boottime | sed -e 's/^{ sec = \\([0-9]*\\),.*/^\\1 /' > \(boot); "
            + "if [ -f \(token) ] && grep -q -f \(boot) \(token); then cut -d' ' -f2 \(token) | xargs -n1 pfctl -X "
            + "|| { echo 'PF did not take back MugVPN s token: try again.' >&2; rm -f \(boot); exit 1; }; fi; "
            + "rm -f \(token) \(boot); "
        let stop = "{ echo 'A tunnel left DNS or routes that the helper must undo first: open MugVPN again, then uninstall.' >&2; exit 2; }"
        let pending = "ls -A '\(support)/run' 2>/dev/null | grep -q . && \(stop); [ -e '\(support)/dns-left.json' ] && \(stop); "
        var script = gone + openvpn + pending + pf + "rm -rf " + paths.map { "'\($0)'" }.joined(separator: " ") + " || exit 1"
            + "; rmdir '\(support)/run' 2>/dev/null"
        if !keepProfiles { script += "; rmdir '\(support)' 2>/dev/null" }
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

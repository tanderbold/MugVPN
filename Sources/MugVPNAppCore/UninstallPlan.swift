import Foundation

/// What uninstalling removes for the user (the helper removes the system part).
public enum UninstallPlan {
    /// The system part, removed without the helper (one that does not answer): a command for an
    /// administrator (fixed paths, single-quoted: nothing for a shell to expand).
    public static func systemRemovalScript(keepProfiles: Bool) -> String {
        let support = "/Library/Application Support/MugVPN"
        // The helper's wish to uninstall goes too: a reinstall finding it would remove itself.
        var paths = [support + "/uninstall-pending.json", support + "/libexec", support + "/run", support + "/locks.json", "/Library/Logs/MugVPN",
                     "/Library/LaunchDaemons/com.mugvpn.helper.plist"]
        if !keepProfiles { paths.append(support) }
        // MugVPN's PF rules out and PF given back (its token), before the helper's files go.
        // (Nothing for a shell to expand: the command is also printed for pasting into sudo sh -c "...".)
        // Each step must hold, or nothing is removed (the helper's files are what could put things back): the
        // helper gone from launchd, MugVPN's PF rules out (its token given back).
        let pf = "pfctl -a 'com.apple/mugvpn' -F all || exit 1; "
            + "cut -d' ' -f2 '\(support)/pf.token' 2>/dev/null | xargs -n1 pfctl -X 2>/dev/null; "
        let gone = "launchctl bootout system/com.mugvpn.helper 2>/dev/null; launchctl print system/com.mugvpn.helper >/dev/null 2>&1 && exit 1; "
        return gone + pf + "rm -rf " + paths.map { "'\($0)'" }.joined(separator: " ")
    }

    public static func userPaths(home: String, keepProfiles: Bool) -> [String] {
        var paths: [String] = []
        if !keepProfiles { paths.append(home + "/Library/Application Support/MugVPN") }
        paths.append(home + "/Library/Logs/MugVPN")
        paths.append(home + "/Library/Preferences/com.mugvpn.app.plist")
        return paths
    }
}

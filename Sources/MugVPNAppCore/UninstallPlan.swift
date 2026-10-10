import Foundation

/// What uninstalling removes for the user (the helper removes the system part).
public enum UninstallPlan {
    /// The system part, removed without the helper (one that does not answer): a command for an
    /// administrator (fixed paths, single-quoted: nothing for a shell to expand).
    public static func systemRemovalScript(keepProfiles: Bool) -> String {
        let support = "/Library/Application Support/MugVPN"
        var paths = [support + "/libexec", support + "/run", support + "/locks.json", "/Library/Logs/MugVPN",
                     "/Library/LaunchDaemons/com.mugvpn.helper.plist"]
        if !keepProfiles { paths.append(support) }
        return "launchctl bootout system/com.mugvpn.helper 2>/dev/null; rm -rf " + paths.map { "'\($0)'" }.joined(separator: " ")
    }

    public static func userPaths(home: String, keepProfiles: Bool) -> [String] {
        var paths: [String] = []
        if !keepProfiles { paths.append(home + "/Library/Application Support/MugVPN") }
        paths.append(home + "/Library/Logs/MugVPN")
        paths.append(home + "/Library/Preferences/com.mugvpn.app.plist")
        return paths
    }
}

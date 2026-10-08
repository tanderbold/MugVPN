import Foundation

/// What uninstalling removes for the user (the helper removes the system part).
public enum UninstallPlan {
    public static func userPaths(home: String, keepProfiles: Bool) -> [String] {
        var paths: [String] = []
        if !keepProfiles { paths.append(home + "/Library/Application Support/MugVPN") }
        paths.append(home + "/Library/Logs/MugVPN")
        paths.append(home + "/Library/Preferences/com.mugvpn.app.plist")
        return paths
    }
}

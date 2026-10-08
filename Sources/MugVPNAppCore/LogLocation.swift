import Foundation

/// Which openvpn log "View Log" opens for a profile.
public enum LogLocation {
    /// The live log while the helper runs the tunnel (moved to the logs
    /// folder only when it ends), else the last kept one; nil if neither exists.
    public static func path(profile: String, helperID: String?, uid: UInt32, runDir: String, logsDir: String,
                            exists: (String) -> Bool) -> String? {
        if let id = helperID {
            let live = "\(runDir)/\(id)/openvpn.log"
            if exists(live) { return live }
        }
        let kept = "\(logsDir)/\(profile).\(uid).log"
        return exists(kept) ? kept : nil
    }
}

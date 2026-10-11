import Foundation
import MugVPNCore

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

    /// The same for an app profile: its kept log by its id (same-named profiles keep their own); one kept by
    /// name alone (an older version's) only if no other profile has that name.
    public static func path(profile: String, id: String, nameIsUnique: Bool, helperID: String?, uid: UInt32, runDir: String,
                            logsDir: String, exists: (String) -> Bool) -> String? {
        if let id = helperID {
            let live = "\(runDir)/\(id)/openvpn.log"
            if exists(live) { return live }
        }
        let kept = "\(logsDir)/\(ProfileKey.logName(profile: profile, id: id, uid: uid)).log"
        if exists(kept) { return kept }
        let older = "\(logsDir)/\(safeLogName(profile)).\(uid).log"
        return nameIsUnique && exists(older) ? older : nil
    }
}

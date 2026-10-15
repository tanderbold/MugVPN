import Foundation

/// Why a backend refuses to start a connection, by a stable code (the interface says it in the user's language; its
/// English text is the catalogs' key). The App Store build's provider gives these; MugVPN's helper has none so far.
public enum BackendRefusal: String, Error, Codable, CustomStringConvertible, Sendable, CaseIterable {
    /// A kill switch connection runs alone (the system's strict mode is the whole tunnel's).
    case killSwitchRunsAlone
    /// Another connection cannot start while a kill switch connection is up.
    case killSwitchConnectionUp
    /// A kill switch's block holds: lifted first.
    case blockedByKillSwitch

    public var description: String {
        switch self {
        case .killSwitchRunsAlone: return "A connection that blocks traffic if it drops runs alone: disconnect the others first."
        case .killSwitchConnectionUp: return "While a connection that blocks traffic if it drops is up, no other connection can start."
        case .blockedByKillSwitch: return "The Internet is blocked since a connection dropped: unblock it first."
        }
    }
}

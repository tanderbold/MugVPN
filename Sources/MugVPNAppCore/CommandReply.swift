import Foundation

/// What the running app answers `--command`: one JSON line, sent once the command is carried out.
public struct CommandReply: Codable, Equatable, Sendable {
    public enum Code: Int, Codable, Sendable {
        case ok = 0
        case failed = 1
        case usage = 2
        case notRunning = 3
        case timedOut = 4
    }
    public var code: Code
    public var error: String?
    /// list and status.
    public var profiles: [ProfileState]?

    public init(code: Code = .ok, error: String? = nil, profiles: [ProfileState]? = nil) {
        self.code = code
        self.error = error
        self.profiles = profiles
    }
    public static let ok = CommandReply()
    public static func failed(_ s: String) -> CommandReply { CommandReply(code: .failed, error: s) }

    public struct ProfileState: Codable, Equatable, Sendable {
        /// As MugVPN shows it (unique); the command line accepts it.
        public var name: String
        public var path: String
        public var source: String
        public var status: String
        public var ip: String?
        public var ipv6: String?

        public init(_ p: Profile, _ s: ConnectionStatus?) {
            name = p.displayName
            path = p.path
            switch p.source {
            case .user: source = "user"
            case .system: source = "system"
            case .persistent: source = "persistent"
            }
            switch s {
            case nil, .disconnected?: status = "disconnected"
            case .connecting?: status = "connecting"
            case .waitingForWebAuth?: status = "waiting_for_web_auth"
            case .connected(let a, let b, _)?:
                status = "connected"
                ip = a.isEmpty ? nil : a
                ipv6 = b.isEmpty ? nil : b
            case .reconnecting?: status = "reconnecting"
            case .disconnecting?: status = "disconnecting"
            }
        }
    }

    /// The profile a command names: its path, the name MugVPN shows, or its own name when only one has it.
    public static func find(_ query: String, in profiles: [Profile]) -> Result<Profile, CommandReply> {
        if let p = profiles.first(where: { $0.path == query }) { return .success(p) }
        let shown = profiles.filter { $0.displayName == query }
        if shown.count == 1 { return .success(shown[0]) }
        let named = profiles.filter { $0.name == query }
        if named.count == 1 { return .success(named[0]) }
        if named.count > 1 {
            return .failure(.failed("\(query) names more than one profile: "
                                    + named.map(\.displayName).sorted().joined(separator: ", ")
                                    + " (use the name MugVPN shows, or the path)"))
        }
        return .failure(.failed("no profile \(query)"))
    }

    /// What `--wait` waits for.
    public enum Awaited: Equatable, Sendable {
        /// Up (a connection newer than `after`, for a reconnect).
        case connected(after: Date?)
        case gone
    }

    /// nil: not yet. A connection gone while one is awaited failed.
    public static func check(_ a: Awaited, name: String, status: ConnectionStatus?, connectedSince: Date?) -> CommandReply? {
        switch a {
        case .connected(let before):
            // Gone from the active ones: it ended (a new one is .disconnected until it starts).
            guard let status else { return .failed("\(name) did not connect (see its log)") }
            if case .connected = status, before == nil || connectedSince != before { return .ok }
            return nil
        case .gone:
            if status == nil || status == .disconnected { return .ok }
            return nil
        }
    }
}

/// A refusal is the reply itself.
extension CommandReply: Error {}

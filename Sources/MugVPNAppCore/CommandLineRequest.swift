import Foundation

/// Commands for a running MugVPN (`--command`).
public enum CLICommand: Equatable, Sendable {
    case connect(String)
    case disconnect(String)
    case reconnect(String)
    case disconnectAll
    case silentConnection(Bool)
    case exit
    case rescan
    case importFile(String)
}

public enum CommandLineRequest: Equatable, Sendable {
    case launch
    case connectOnStart(String)
    case launchAndImport(String)
    case command(CLICommand)
    case help
    case error(String)
    /// Remove MugVPN; without `confirmed` only say what would go.
    case uninstall(confirmed: Bool, keepProfiles: Bool)

    public static var usageText: String { usage }
    static let usage = """
    usage: MugVPN [--connect <profile>]
           MugVPN --command connect|disconnect|reconnect <profile>
           MugVPN --command disconnect_all | exit | rescan
           MugVPN --command silent_connection 0|1
           MugVPN --command import <path>
           MugVPN --uninstall [--keep-profiles] [--yes]
    """

    /// Drop what macOS and Foundation pass or read themselves: `-psn_…` and
    /// `-Key value` pairs (the arguments domain, e.g. -AppleLanguages (ru)).
    /// MugVPN's own options all start with "--".
    public static func ownArguments(_ args: [String]) -> [String] {
        var out: [String] = []
        var i = 0
        while i < args.count {
            let a = args[i]
            if a.hasPrefix("-psn_") { i += 1; continue }
            if a.hasPrefix("-"), !a.hasPrefix("--"), a.count > 1 { i += 2; continue }
            out.append(a)
            i += 1
        }
        return out
    }

    public static func parse(_ rawArgs: [String]) -> CommandLineRequest {
        let args = ownArguments(rawArgs)
        guard let first = args.first else { return .launch }
        switch first {
        case "--help": return .help
        case "--uninstall":
            let rest = Set(args.dropFirst())
            guard rest.isSubset(of: ["--yes", "--keep-profiles"]) else { return .error(usage) }
            return .uninstall(confirmed: rest.contains("--yes"), keepProfiles: rest.contains("--keep-profiles"))
        case "--connect":
            guard args.count == 2 else { return .error(usage) }
            return .connectOnStart(profileName(args[1]))
        case "--command":
            guard args.count >= 2 else { return .error(usage) }
            let rest = Array(args.dropFirst(2))
            func one() -> String? { rest.count == 1 ? rest[0] : nil }
            switch args[1] {
            case "connect": return one().map { .command(.connect(profileName($0))) } ?? .error(usage)
            case "disconnect": return one().map { .command(.disconnect(profileName($0))) } ?? .error(usage)
            case "reconnect": return one().map { .command(.reconnect(profileName($0))) } ?? .error(usage)
            case "disconnect_all": return rest.isEmpty ? .command(.disconnectAll) : .error(usage)
            case "exit": return rest.isEmpty ? .command(.exit) : .error(usage)
            case "rescan": return rest.isEmpty ? .command(.rescan) : .error(usage)
            case "import": return one().map { .command(.importFile($0)) } ?? .error(usage)
            case "silent_connection":
                switch one() {
                case "1": return .command(.silentConnection(true))
                case "0": return .command(.silentConnection(false))
                default: return .error(usage)
                }
            default: return .error("unknown command \(args[1])\n" + usage)
            }
        default:
            return .error("unknown option \(first)\n" + usage)
        }
    }

    /// With no MugVPN running: connect starts it and connects, import starts
    /// it and imports; the other commands have nothing to act on.
    public static func withoutInstance(_ c: CLICommand) -> CommandLineRequest? {
        switch c {
        case .connect(let p): return .connectOnStart(p)
        case .importFile(let p): return .launchAndImport(p)
        default: return nil
        }
    }

    /// "office.ovpn" and "office" name the same profile.
    static func profileName(_ s: String) -> String {
        (s as NSString).pathExtension.lowercased() == "ovpn" ? (s as NSString).deletingPathExtension : s
    }
}

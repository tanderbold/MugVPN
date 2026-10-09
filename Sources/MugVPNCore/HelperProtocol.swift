import Foundation

/// Names shared by the app and the privileged helper.
public enum MugVPNIDs {
    public static let appBundleID = "com.mugvpn.app"
    public static let helperLabel = "com.mugvpn.helper"
    public static let helperPlist = "com.mugvpn.helper.plist"
    /// Root-owned state: run directories, the DNS script, logs.
    public static let supportDir = "/Library/Application Support/MugVPN"
    public static let runDir = supportDir + "/run"
    public static let libexecDir = supportDir + "/libexec"
    /// Persistent profiles: started at boot by the helper.
    public static let autoDir = supportDir + "/config-auto"
    public static let helperVersion = "0.1.0"
}

/// The helper's XPC interface. Everything that crosses it is plain data: the
/// app reads the profile with the user's rights and sends its contents, so the
/// helper never opens a path the user names.
@objc public protocol MugVPNHelperProtocol {
    func version(reply: @escaping (String) -> Void)

    /// Start openvpn for one profile.
    /// - bundle: `ProfileBundle` encoded as JSON.
    /// - reply: (connection id, management socket path, error text or nil).
    func start(bundle: Data, reply: @escaping (String?, String?, String?) -> Void)

    func stop(connectionID: String, reply: @escaping (String?) -> Void)

    /// Start a persistent profile from config-auto again (administrators).
    /// - reply: (connection id, error text or nil).
    func startPersistent(name: String, reply: @escaping (String?, String?) -> Void)

    /// Stop everything and remove MugVPN's system part (administrators);
    /// replies when done, then the helper ends itself.
    func uninstall(keepProfiles: Bool, reply: @escaping (String?) -> Void)

    /// Running connections as JSON-encoded `[ConnectionInfo]`.
    func list(reply: @escaping (Data) -> Void)

    /// Profiles whose kill switch blocks traffic now (everyone may ask).
    func blocks(reply: @escaping ([String]) -> Void)

    /// Lift the blocks the caller may lift (their own; all for administrators).
    /// - reply: error text or nil.
    func unblock(reply: @escaping (String?) -> Void)
    /// Lift the caller's blocks for a while (seconds, at most a few minutes): to sign in to a network.
    func suspendBlocks(seconds: Int, reply: @escaping (String?) -> Void)

    /// A request of the caller's unprivileged openvpn (privilege separation): OPENTUN,
    /// IFCONFIG, ROUTE, DNSUP... The helper checks it against the connection.
    /// - reply: (the new utun for OPENTUN, error text or nil).
    func tunnelRequest(connectionID: String, kind: String, message: String,
                       reply: @escaping (FileHandle?, String?) -> Void)

    /// A persistent tunnel (administrators): the helper lets go of its management
    /// connection so the app can attach, and takes it back when the app leaves.
    /// - reply: error text or nil.
    func releaseManagement(connectionID: String, reply: @escaping (String?) -> Void)
}

/// Which protection a connection asks for (the helper decides what that means).
public struct ProtectionOptions: Codable, Equatable, Sendable {
    /// If a tunnel that takes all traffic drops unexpectedly, block traffic outside
    /// the tunnels until its owner reconnects or lifts the block.
    public var killSwitch: Bool
    /// While it takes all traffic, IPv6 outside the tunnels is blocked.
    public var blockIPv6: Bool
    /// While it takes all traffic, DNS outside the tunnels is blocked.
    public var dnsOnlyTunnel: Bool
    /// The local network stays reachable while blocked.
    public var allowLAN: Bool
    public init(killSwitch: Bool = false, blockIPv6: Bool = false, dnsOnlyTunnel: Bool = false, allowLAN: Bool = false) {
        self.killSwitch = killSwitch
        self.blockIPv6 = blockIPv6
        self.dnsOnlyTunnel = dnsOnlyTunnel
        self.allowLAN = allowLAN
    }
    public var any: Bool { killSwitch || blockIPv6 || dnsOnlyTunnel }
}

/// A persistent profile's settings: `<name>.json` beside it in config-auto, root's like the
/// profile (the app cannot apply settings to a tunnel the helper starts at boot).
public struct PersistentSettings: Equatable, Sendable {
    public var splitDNS = false
    public var protection = ProtectionOptions()
    public init() {}

    public static let keys = ["split_dns", "kill_switch", "block_ipv6", "dns_only_tunnel", "allow_lan"]

    /// Strict: an unknown key or a value that is not true/false is an error (a typo must not
    /// leave a tunnel without the kill switch its administrator meant).
    public static func parse(_ data: Data) throws -> PersistentSettings {
        guard let o = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw PersistentSettingsError("not a JSON object")
        }
        var s = PersistentSettings()
        for (k, v) in o {
            guard keys.contains(k) else { throw PersistentSettingsError("unknown setting \(k)") }
            guard let n = v as? NSNumber, CFGetTypeID(n) == CFBooleanGetTypeID() else {
                throw PersistentSettingsError("\(k) must be true or false")
            }
            let b = n.boolValue
            switch k {
            case "split_dns": s.splitDNS = b
            case "kill_switch": s.protection.killSwitch = b
            case "block_ipv6": s.protection.blockIPv6 = b
            case "dns_only_tunnel": s.protection.dnsOnlyTunnel = b
            default: s.protection.allowLAN = b
            }
        }
        return s
    }
}

public struct PersistentSettingsError: Error, CustomStringConvertible {
    public let description: String
    public init(_ s: String) { description = s }
}

/// A profile as the app sends it: the config text and the files it names
/// (ca, cert, key, tls-crypt...), keyed by the name used in the config.
public struct ProfileBundle: Codable, Sendable {
    public var name: String
    public var config: String
    public var files: [String: Data]
    /// Pushed DNS search domains become split domains (MugVPN's DNS script).
    public var splitDNS: Bool
    public var protection = ProtectionOptions()

    public init(name: String, config: String, files: [String: Data], splitDNS: Bool = false) {
        self.name = name
        self.config = config
        self.files = files
        self.splitDNS = splitDNS
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = try c.decode(String.self, forKey: .name)
        config = try c.decode(String.self, forKey: .config)
        files = try c.decode([String: Data].self, forKey: .files)
        splitDNS = try c.decodeIfPresent(Bool.self, forKey: .splitDNS) ?? false
        protection = try c.decodeIfPresent(ProtectionOptions.self, forKey: .protection) ?? ProtectionOptions()
    }
}

public struct ConnectionInfo: Codable, Sendable {
    public var id: String
    public var name: String
    public var pid: Int32
    public var managementSocket: String
    public var ownerUID: UInt32
    /// Started by the helper from config-auto (owner root, managed by admins).
    public var persistent: Bool
    /// The management password of a persistent connection, for administrators only.
    public var managementPassword: String?

    public init(id: String, name: String, pid: Int32, managementSocket: String, ownerUID: UInt32, persistent: Bool = false,
                managementPassword: String? = nil) {
        self.managementPassword = managementPassword
        self.id = id
        self.name = name
        self.pid = pid
        self.managementSocket = managementSocket
        self.ownerUID = ownerUID
        self.persistent = persistent
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        name = try c.decode(String.self, forKey: .name)
        pid = try c.decode(Int32.self, forKey: .pid)
        managementSocket = try c.decode(String.self, forKey: .managementSocket)
        ownerUID = try c.decode(UInt32.self, forKey: .ownerUID)
        persistent = try c.decodeIfPresent(Bool.self, forKey: .persistent) ?? false
        managementPassword = try c.decodeIfPresent(String.self, forKey: .managementPassword)
    }
}

/// A profile name made safe as a file name in /Library/Logs/MugVPN
/// (the helper names a log `<safe name>.<uid>.log`).
public func safeLogName(_ profile: String) -> String {
    let allowed = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._- ")
    let cleaned = String(profile.map { allowed.contains($0) ? $0 : "_" }.prefix(64))
        .trimmingCharacters(in: CharacterSet(charactersIn: ". "))
    return cleaned.isEmpty ? "profile" : cleaned
}

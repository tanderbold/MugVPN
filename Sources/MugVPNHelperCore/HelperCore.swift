import CryptoKit
import Foundation
import MugVPNCore

/// Everything the helper does to the system. The real implementation lives
/// in the MugVPNHelper executable only; tests use a fake, so the logic below
/// is checked without root and without touching the machine.
public protocol HelperSystem: AnyObject {
    func makeDirectory(_ path: String, mode: UInt16) throws
    func writeFile(_ path: String, _ data: Data, mode: UInt16) throws
    func readFile(_ path: String) -> Data?
    /// The last `maxBytes` of a file, without following a link.
    func readTail(_ path: String, maxBytes: Int) -> Data?
    func copyFile(_ from: String, _ to: String, mode: UInt16) throws
    func remove(_ path: String)
    func move(_ from: String, _ to: String)
    /// Put `from` in place of `to`; an error if that fails.
    func replace(_ from: String, _ to: String) throws
    func setOwner(_ path: String, uid: UInt32, gid: UInt32, mode: UInt16)
    /// Replace MugVPN's PF anchor with these rules ("" clears it and releases PF); false if pfctl refused.
    func applyPF(_ anchor: String) -> Bool
    /// PF is on and MugVPN's anchor holds these rules (someone may have run pfctl -d or flushed it).
    func pfIntact(_ anchor: String) -> Bool
    /// `route add` with these arguments (putting back a default route openvpn deleted).
    func addRoute(_ args: [String])
    /// A file from `offset` on (at most `maxBytes`), without following a link.
    func readFrom(_ path: String, offset: UInt64, maxBytes: Int) -> Data?
    /// Let `uid` read `path` (an ACL entry) without owning it.
    func grantRead(_ path: String, uid: UInt32)
    func list(_ dir: String) -> [String]
    /// Start a process with stdout and stderr appended to `logPath`.
    /// `onExit` must be delivered on the caller's serial queue.
    /// - user: run it as this user (nil: as root).
    func launch(_ path: String, _ args: [String], cwd: String, logPath: String, user: ServiceUser?,
                onExit: @escaping (ExitKind) -> Void) throws -> HelperProcess
    /// No user or group in the directory has this id (one for a connection's openvpn).
    func idIsFree(_ id: UInt32) -> Bool
    /// Stop every process running as one of these ids (whatever a compromised openvpn started).
    func killProcesses(uids: ClosedRange<UInt32>)
    /// The route is in the routing table as added (same destination, mask and way out).
    func routeExists(_ r: TunnelRoute) -> Bool
    /// The network interface (a utun) still exists.
    func interfaceExists(_ name: String) -> Bool
    /// Close the helper's own copy of a utun it handed out (its records are undone).
    func releaseDevice(_ name: String)
    /// Close a descriptor the helper passed on (openvpn holds its own copy).
    func closeDescriptor(_ fd: Int32)
    /// Connect to an openvpn management socket (persistent tunnels); lines come back on the
    /// helper's queue, "ENTER PASSWORD:" as a line of its own. nil if it does not answer.
    func connectManagement(_ path: String, peer pid: Int32, onLine: @escaping (String) -> Void,
                           onClose: @escaping () -> Void) -> ManagementChannel?
    /// IPv6 networks ("prefix/bits") of the Mac's interfaces other than utun.
    func localIPv6Networks() -> [String]
    /// IPv4 networks ("address/bits") of the Mac's interfaces other than utun and loopback.
    func localIPv4Networks() -> [String]
    /// The DNS servers the Mac itself uses (but those MugVPN set for that device); nil: not known.
    func systemDNSServers(excluding device: String) -> [String]?
    /// Seconds, for rationing requests.
    func now() -> TimeInterval
    /// A new utun device: its descriptor and name.
    func openUtun() throws -> (fd: Int32, name: String)
    /// /sbin/ifconfig or /sbin/route with these arguments (the first names which); false if it failed.
    func runNetwork(_ command: [String]) -> Bool
    /// The Mac's default route before any tunnel (its gateway and interface).
    func defaultGateway() -> DefaultGateway?
    /// Set a tunnel's DNS (split: its own resolver for some domains; else all names).
    func setDNS(_ plan: DNSPlan) -> Bool
    /// SIGKILL every process running the executable at `path`.
    func killStrayOpenVPN(path: String)
    func restoreDNS(device: String)
    func deleteRoute(_ args: [String])
    /// Run `f` after `seconds` on the caller's serial queue.
    func after(_ seconds: TimeInterval, _ f: @escaping () -> Void)
    func userName(uid: UInt32) -> String?
    /// Member of the admin group.
    func isAdmin(uid: UInt32) -> Bool
    /// Owner, permission bits and type, without following a symbolic link; nil if nothing is there.
    func fileInfo(_ path: String) -> FileInfo?
}

/// The helper's own management connection to an openvpn.
public protocol ManagementChannel: AnyObject {
    /// A line, with a descriptor for openvpn when given; false if it was not sent.
    @discardableResult func send(_ line: String, passing fd: Int32?) -> Bool
    func close()
}

/// The account an unprivileged openvpn runs as.
public struct ServiceUser: Equatable, Sendable {
    public var name: String
    public var uid: UInt32
    public var gid: UInt32
    public init(name: String, uid: UInt32, gid: UInt32) {
        self.name = name
        self.uid = uid
        self.gid = gid
    }
}

public struct FileInfo: Equatable, Sendable {
    public enum Kind: Sendable { case regular, directory, link, other }
    public var owner: UInt32
    public var mode: UInt16
    public var kind: Kind
    public init(owner: UInt32, mode: UInt16, kind: Kind) {
        self.owner = owner
        self.mode = mode
        self.kind = kind
    }
    /// Only root can change it: owned by root, no write for group or others.
    public var rootOnly: Bool { owner == 0 && mode & 0o022 == 0 }
}

/// gid of the staff and admin groups on macOS.
let staffGID: UInt32 = 20
let adminGID: UInt32 = 80

public protocol HelperProcess: AnyObject {
    var pid: Int32 { get }
    func signal(_ sig: Int32)
}

public enum ExitKind: Equatable, Sendable {
    case exited(Int32)
    case signaled(Int32)

    /// openvpn tears down routes and DNS itself on a clean exit only.
    public var needsCleanup: Bool { self != .exited(0) }
}

public struct HelperPaths: Sendable {
    /// openvpn built for privilege separation (asks for its tunnel).
    public var openvpn: String
    public var runDir: String
    public var logsDir: String
    public var autoDir: String
    public var libexecDir: String
    public var systemConfigDir: String
    /// A development install's plain LaunchDaemon (tools/stand/stand.sh helper).
    public var devDaemonPlist: String
    public var supportDir: String

    public init(openvpn: String, runDir: String, logsDir: String, autoDir: String = MugVPNIDs.autoDir,
                libexecDir: String = MugVPNIDs.libexecDir, systemConfigDir: String = MugVPNIDs.supportDir + "/config",
                devDaemonPlist: String = "/Library/LaunchDaemons/" + MugVPNIDs.helperPlist,
                supportDir: String = MugVPNIDs.supportDir) {
        self.supportDir = supportDir
        self.openvpn = openvpn
        self.runDir = runDir
        self.logsDir = logsDir
        self.autoDir = autoDir
        self.libexecDir = libexecDir
        self.systemConfigDir = systemConfigDir
        self.devDaemonPlist = devDaemonPlist
    }

    public static let standard = HelperPaths(openvpn: MugVPNIDs.libexecDir + "/openvpn",
                                             runDir: MugVPNIDs.runDir, logsDir: "/Library/Logs/MugVPN")
}

public enum HelperCoreError: Error, CustomStringConvertible {
    case message(String)
    public var description: String { if case .message(let m) = self { return m }; return "" }
}

/// What to undo after openvpn died without tearing down.
public enum CleanupPlan {
    /// - others: facts of connections still running; their device and routes stay.
    public static func make(_ facts: OpenVPNLogFacts, others: [OpenVPNLogFacts])
        -> (dnsDevice: String?, routes: [[String]]) {
        let device = facts.device.flatMap { dev in others.contains { $0.device == dev } ? nil : dev }
        let kept = Set(others.flatMap(\.routes))
        return (device, facts.routes.filter { !kept.contains($0) })
    }
}

/// The helper's logic: start, watch, stop and clean up after openvpn.
/// Not thread-safe: the caller runs every call, and the system's callbacks,
/// on one serial queue.
public final class HelperCore {
    public static let maxConnectionsPerUser = 16
    /// Over every user (each starts a root openvpn).
    public static let maxConnections = 64
    public static let maxBundleBytes = 4 << 20
    /// How long openvpn gets to tear down after SIGTERM before SIGKILL.
    public static let stopGrace: TimeInterval = 15

    final class Connection {
        let info: ConnectionInfo
        let process: HelperProcess
        let dir: String
        var stopping = false
        var exited = false
        var protection = ProtectionOptions()
        /// It has taken all traffic (the kill switch applies to it).
        var wasFull = false
        var splitDNS = false
        /// When it was started (a persistent tunnel up a long time starts again soon).
        var startedAt: TimeInterval = 0
        /// The id its openvpn runs as (privilege separation).
        var serviceID: UInt32?
        /// Persistent tunnels: the helper's management connection while no app holds it.
        var channel: ManagementChannel?
        var channelRetryPending = false
        /// Bumped when an administrator's app takes over: older retries give way.
        var channelGeneration = 0
        /// A standard user's (under the policy): its tunnel carries its owner's traffic only.
        var restricted = false
        /// Its last DNSUP.
        var lastDNSUp: TimeInterval?
        /// An administrator's policy for standard users, checked on its requests.
        var mayRouteAll = true
        var mayChangeDNS = true
        /// Public networks and DNS domains an administrator allows its (standard) user.
        var allowed = Allowances()
        /// What the helper set up for it: what it undoes.
        var tunnel = TunnelState()
        init(info: ConnectionInfo, process: HelperProcess, dir: String) {
            self.info = info
            self.process = process
            self.dir = dir
        }
    }

    /// A kill switch that fired: traffic stays blocked until its owner (or an
    /// administrator) lifts it or connects the profile again.
    struct Lock: Codable, Equatable {
        var name: String
        var owner: UInt32
        var allowLAN: Bool = false
        /// Armed: its tunnel is up; it fires if the helper starts again without it (a crash).
        var armed: Bool = false
        /// A persistent tunnel's: the whole Mac's traffic.
        var everyone: Bool = false

        init(name: String, owner: UInt32, allowLAN: Bool = false, armed: Bool = false, everyone: Bool = false) {
            self.name = name
            self.owner = owner
            self.allowLAN = allowLAN
            self.armed = armed
            self.everyone = everyone
        }
        init(from d: Decoder) throws {
            let c = try d.container(keyedBy: CodingKeys.self)
            name = try c.decode(String.self, forKey: .name)
            owner = try c.decode(UInt32.self, forKey: .owner)
            allowLAN = try c.decodeIfPresent(Bool.self, forKey: .allowLAN) ?? false
            armed = try c.decodeIfPresent(Bool.self, forKey: .armed) ?? false
            everyone = try c.decodeIfPresent(Bool.self, forKey: .everyone) ?? false
        }
    }
    /// Persistent tunnels that ended unasked, by name: each start again waits longer.
    private var persistentRestarts: [String: Int] = [:]
    public static let persistentRestartMax: TimeInterval = 300
    public static let maxLocksPerUser = 4
    private var locks: [Lock] = []
    private var appliedPF = ""
    private var refreshPending = false

    private let system: HelperSystem
    private let paths: HelperPaths
    private let newID: () -> String
    private let newSecret: () -> String
    /// Management passwords of persistent connections, by connection id.
    private var passwords: [String: String] = [:]
    private var connections: [String: Connection] = [:]

    public init(system: HelperSystem, paths: HelperPaths = .standard,
                newID: @escaping () -> String = { UUID().uuidString },
                newSecret: @escaping () -> String = { (UUID().uuidString + UUID().uuidString).replacingOccurrences(of: "-", with: "") }) {
        self.system = system
        self.paths = paths
        self.newID = newID
        self.newSecret = newSecret
    }

    public var isEmpty: Bool { connections.isEmpty }

    /// Called once uninstalling has removed everything: the helper exits.
    public var onUninstalled: () -> Void = {}
    private var uninstalling: (keepProfiles: Bool, Void)?
    private var uninstallReplies: [() -> Void] = []
    /// Uninstalling or shutting down: no new tunnels.
    private var closing = false

    /// Remove MugVPN's system part: stop every tunnel, then delete what the
    /// helper installed or wrote. Administrators only. `done` is called once
    /// it is removed (each accepted request gets its own call).
    public func uninstall(uid: UInt32, keepProfiles: Bool, done: @escaping () -> Void = {}) throws {
        guard uid == 0 || system.isAdmin(uid: uid) else {
            throw HelperCoreError.message("only an administrator can uninstall MugVPN")
        }
        if let u = uninstalling {
            // Keeping profiles only if every request asked to.
            uninstalling = (u.keepProfiles && keepProfiles, ())
        } else {
            uninstalling = (keepProfiles, ())
        }
        uninstallReplies.append(done)
        stopAll()
        if connections.isEmpty { finishUninstall() }
    }

    private func finishUninstall() {
        guard let u = uninstalling else { return }
        uninstalling = nil
        var gone = [paths.runDir, paths.libexecDir, paths.logsDir, paths.devDaemonPlist]
        if !u.keepProfiles { gone += [paths.systemConfigDir, paths.autoDir, paths.supportDir] }
        // Protection first: nothing of it may outlive the files (or come back with a reinstall).
        locks = []
        saveLocks()
        _ = system.applyPF("")
        appliedPF = ""
        gone.forEach(system.remove)
        let replies = uninstallReplies
        uninstallReplies = []
        replies.forEach { $0() }
        onUninstalled()
    }

    /// At helper start, before anything is installed or read: every directory
    /// the helper uses exists and is root's on every level of its path (owner
    /// root, no write for group or others, not a link). Missing ones are made.
    public func prepareDirectories() throws {
        for dir in [paths.supportDir, paths.libexecDir, paths.logsDir] {
            var path = ""
            for part in dir.split(separator: "/") {
                path += "/" + part
                if system.fileInfo(path) == nil { try system.makeDirectory(path, mode: 0o755) }
                guard let info = system.fileInfo(path), info.kind == .directory, info.rootOnly else {
                    throw HelperCoreError.message("\(path) must be a directory only root can change")
                }
            }
        }
    }

    /// At helper start: run directories still there belong to openvpn of a
    /// helper that died. Make sure none of them runs, undo what their logs
    /// say they set up, and start with an empty run directory.
    public func prepareRunDirectory() throws {
        let leftovers = system.list(paths.runDir)
        // Whatever ran as a connection's id outlived its helper.
        system.killProcesses(uids: HelperCore.serviceIDBase...(HelperCore.serviceIDBase + HelperCore.serviceIDCount - 1))
        if !leftovers.isEmpty {
            system.killStrayOpenVPN(path: paths.openvpn)
            system.killStrayOpenVPN(path: paths.openvpn + "-root") // an older version's
            for d in leftovers {
                // A privilege-separated run: the helper's own record of what it did.
                if let t = savedTunnel(in: paths.runDir + "/" + d) { undo(t, others: []); continue }
                // openvpn without root wrote that log: never a reason to change anything.
                if system.fileInfo(paths.runDir + "/" + d + "/sock") != nil { continue }
                cleanUp(after: facts(in: paths.runDir + "/" + d), others: [])
            }
        }
        system.remove(paths.runDir)
        try system.makeDirectory(paths.runDir, mode: 0o711)
        try? system.makeDirectory(paths.logsDir, mode: 0o755)
        // Whatever a previous helper left in PF is replaced: its blocks, or nothing.
        loadLocks()
        appliedPF = "\u{0}"
        refreshProtection()
    }

    public func start(bundle data: Data, uid: UInt32) throws -> (id: String, socket: String) {
        guard uid != UInt32.max, let user = system.userName(uid: uid) else {
            throw HelperCoreError.message("unknown caller")
        }
        guard !closing else { throw HelperCoreError.message("MugVPN's helper is closing") }
        guard data.count <= HelperCore.maxBundleBytes else { throw HelperCoreError.message("profile too large") }
        guard connections.count < HelperCore.maxConnections,
              connections.values.filter({ $0.info.ownerUID == uid }).count < HelperCore.maxConnectionsPerUser else {
            throw HelperCoreError.message("too many connections")
        }
        let bundle = try JSONDecoder().decode(ProfileBundle.self, from: data)
        // Connecting the profile again lifts the block its drop left.
        let lockName = HelperCore.lockName(bundle.name)
        // (A block that fired only: the arming of a tunnel of that name still up stays.)
        if locks.contains(where: { $0.name == lockName && $0.owner == uid && !$0.armed && !$0.everyone }) {
            locks.removeAll { $0.name == lockName && $0.owner == uid && !$0.armed && !$0.everyone }
            saveLocks()
        }
        let r = try launch(bundle, owner: uid, management: ["--management-client-user", user], persistent: false)
        connections[r.id]?.protection = bundle.protection
        refreshProtection()
        return r
    }

    // MARK: - persistent profiles (config-auto)

    /// At helper start: every profile in config-auto, if only root can change that folder.
    public func startPersistentProfiles() {
        guard trustedAutoDir() else { return }
        for f in system.list(paths.autoDir) where (f as NSString).pathExtension.lowercased() == "ovpn"
            && system.fileInfo(paths.autoDir + "/" + f)?.kind == .regular {
            _ = try? startPersistent(name: (f as NSString).deletingPathExtension, uid: 0)
        }
    }

    /// Start one persistent profile (again). Root or administrators only.
    public func startPersistent(name: String, uid: UInt32) throws -> String {
        guard uid == 0 || system.isAdmin(uid: uid) else {
            throw HelperCoreError.message("only an administrator can start persistent connections")
        }
        guard !closing else { throw HelperCoreError.message("MugVPN's helper is closing") }
        if let running = connections.values.first(where: { $0.info.persistent && $0.info.name == name }) {
            return running.info.id
        }
        // A name config-auto lists, checked before it is read.
        guard trustedAutoDir(), system.list(paths.autoDir).contains(name + ".ovpn") else {
            throw HelperCoreError.message("no persistent profile \(name)")
        }
        guard trustedInAutoDir(name + ".ovpn") else {
            throw HelperCoreError.message("\(name): the profile must be a file only root can change")
        }
        guard let data = system.readFile(paths.autoDir + "/" + name + ".ovpn") else {
            throw HelperCoreError.message("no persistent profile \(name)")
        }
        let text = String(decoding: data, as: UTF8.self)
        var files: [String: Data] = [:]
        for ref in ProfilePolicy.referencedFiles(try ConfigParser.parse(text)) {
            // Only files inside config-auto: it is the folder an administrator vouched for.
            guard !ref.hasPrefix("/"), !ref.split(separator: "/").contains(".."), trustedInAutoDir(ref),
                  let d = system.readFile(paths.autoDir + "/" + ref) else {
                throw HelperCoreError.message("\(name): \(ref) is not a file inside config-auto")
            }
            files[ref] = d
        }
        // Its settings: beside it, vouched for the same way.
        var settings = PersistentSettings()
        if system.list(paths.autoDir).contains(name + ".json") {
            guard trustedInAutoDir(name + ".json", readable: true), let d = system.readFile(paths.autoDir + "/" + name + ".json") else {
                throw HelperCoreError.message("\(name).json: the settings must be a file only root can change")
            }
            do { settings = try PersistentSettings.parse(d) } catch {
                throw HelperCoreError.message("\(name).json: \(error)")
            }
        }
        var bundle = ProfileBundle(name: name, config: text, files: files)
        bundle.splitDNS = settings.splitDNS
        // Not a client group: openvpn checks only the client's primary group,
        // and administrators' is staff. A password only the helper hands out instead.
        let id = try launch(bundle, owner: 0, management: [], persistent: true).id
        connections[id]?.protection = settings.protection
        refreshProtection()
        return id
    }

    private func trustedAutoDir() -> Bool {
        guard let info = system.fileInfo(paths.autoDir) else { return false }
        return info.kind == .directory && info.rootOnly
    }

    /// A file under config-auto that only root can have put there: every
    /// folder on the way and the file itself root-only, no symbolic links.
    /// - readable: others may read it (settings, not secrets); only root writes it either way.
    private func trustedInAutoDir(_ relative: String, readable: Bool = false) -> Bool {
        var path = paths.autoDir
        let parts = relative.split(separator: "/").map(String.init)
        for (i, part) in parts.enumerated() {
            path += "/" + part
            guard let info = system.fileInfo(path), info.rootOnly else { return false }
            guard info.kind == (i == parts.count - 1 ? .regular : .directory) else { return false }
            // Profiles and keys: nobody but root reads them either.
            if i == parts.count - 1, info.mode & (readable ? 0o022 : 0o077) != 0 { return false }
        }
        return !parts.isEmpty
    }

    /// What an administrator allows standard users (policy.json, root's alone). Absent,
    /// broken or not root's: neither all traffic nor DNS for all names (both are the whole Mac's).
    struct UserPolicy: Codable {
        var usersMayRouteAllTraffic: Bool?
        var usersMayChangeDNS: Bool?
        /// Users (short names) allowed both, as administrators are.
        var trustedUsers: [String]?
        /// Public networks ("203.0.113.0/24", "2001:db8::/32") standard users may route into a tunnel.
        var allowedNetworks: [String]?
        /// Domains (and their subdomains) standard users' tunnels may answer for.
        var allowedDomains: [String]?
    }

    /// What a standard user may route and resolve beyond private networks and names.
    struct Allowances {
        var networks4: [IPv4Net] = []
        var networks6: [String] = []
        var domains: [String] = []

        func allows(_ n: IPv4Net) -> Bool {
            TunnelState.privateBlock(of: n) != nil || networks4.contains { $0.prefix <= n.prefix && $0.contains(n.address) }
        }
        func allows6(_ net: String, bits: Int) -> Bool {
            if TunnelState.isULA(net), bits >= 7 { return true }
            return networks6.contains { a in
                guard let b = a.split(separator: "/").last.flatMap({ Int($0) }) else { return false }
                return b <= bits && TunnelState.overlap6(a, "\(net)/\(bits)")
            }
        }
        /// A domain an administrator listed (or under one). Private names too: one mDNSResponder
        /// asks for every user, so a resolver cannot be kept to its owner.
        func allows(domain: String) -> Bool {
            let d = domain.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
            return domains.contains { a in
                let a = a.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
                return d == a || d.hasSuffix("." + a)
            }
        }
    }

    private func userPolicy() -> UserPolicy {
        let path = paths.supportDir + "/policy.json"
        guard let info = system.fileInfo(path), info.kind == .regular, info.rootOnly, let d = system.readFile(path),
              let p = try? JSONDecoder().decode(UserPolicy.self, from: d) else { return UserPolicy() }
        return p
    }

    struct Limits {
        var restricted = false
        var mayRouteAll = true
        var mayChangeDNS = true
        var allowed = Allowances()
        /// Pushes openvpn is told to ignore.
        var ignored: [String] = []
    }

    /// For a standard user: whether routes for all traffic and DNS for all names are allowed.
    private func limits(for uid: UInt32, persistent: Bool) -> Limits {
        guard !persistent, uid != 0, !system.isAdmin(uid: uid) else { return Limits() }
        let p = userPolicy()
        if let name = system.userName(uid: uid), p.trustedUsers?.contains(name) == true { return Limits() }
        var l = Limits(restricted: true, mayRouteAll: p.usersMayRouteAllTraffic == true, mayChangeDNS: p.usersMayChangeDNS == true)
        for n in p.allowedNetworks ?? [] {
            let parts = n.split(separator: "/")
            if parts.count == 2, let a = TunnelState.ipv4(parts[0]), let b = Int(parts[1]), (0...32).contains(b) {
                l.allowed.networks4.append(IPv4Net(address: a, prefix: b))
            } else if parts.count == 2, TunnelState.ipv6(parts[0]), let b = Int(parts[1]), (0...128).contains(b) {
                l.allowed.networks6.append(n)
            }
        }
        l.allowed.domains = (p.allowedDomains ?? []).filter { TunnelState.isDomain($0) }
        if !l.mayRouteAll { l.ignored.append("redirect-gateway") }
        return l
    }

    private func launch(_ bundle: ProfileBundle, owner uid: UInt32, management: [String],
                        persistent: Bool) throws -> (id: String, socket: String) {
        let checked = try ProfilePolicy.check(try ConfigParser.parse(bundle.config),
                                              bundleFiles: Set(bundle.files.keys))
        let limit = limits(for: uid, persistent: persistent)
        func named(_ ds: [ConfigDirective]) -> [String] {
            ds.flatMap { d in d.name == "connection" ? named((try? ConfigParser.parse(d.inline ?? "")) ?? []) : [d.name] }
        }
        if !limit.mayRouteAll, let n = named(checked.directives).first(where: { $0 == "redirect-gateway" }) {
            throw HelperCoreError.message("\(n): an administrator does not let standard users change the whole Mac's routing or DNS")
        }
        for key in checked.files {
            for kind in checked.fileKinds[key] ?? [] {
                if let problem = ProfilePolicy.contentProblem(kind, bundle.files[key] ?? Data(), inline: false) {
                    throw HelperCoreError.message("\(kind) \(key): \(problem)")
                }
            }
        }

        // openvpn runs as an unprivileged id of its own and asks for what needs root
        // (privilege separation): user profiles and persistent ones alike.
        let user: ServiceUser? = try {
            let id = try allocateServiceID()
            return ServiceUser(name: "mugvpn-\(id)", uid: id, gid: id)
        }()
        let id = newID()
        let dir = paths.runDir + "/" + id
        let config = dir + "/config.ovpn"
        let socket = user == nil ? dir + "/m.sock" : dir + "/sock/m.sock"
        try system.makeDirectory(dir, mode: 0o711)
        do {
            /// Readable by openvpn's account (its group), by nobody else.
            func forOpenVPN(_ path: String) {
                if let user { system.setOwner(path, uid: 0, gid: user.gid, mode: 0o640) }
            }
            for (i, key) in checked.files.enumerated() {
                let f = dir + "/" + ProfilePolicy.runName(forIndex: i)
                try system.writeFile(f, bundle.files[key] ?? Data(), mode: 0o600)
                forOpenVPN(f)
            }
            try system.writeFile(config, Data(ConfigParser.serializeForOpenVPN(checked.directives).utf8), mode: 0o600)
            forOpenVPN(config)
            if let user {
                // openvpn creates its management socket here: the one place it may write.
                try system.makeDirectory(dir + "/sock", mode: 0o711)
                // A persistent tunnel's socket: its administrators' (the app attaches), nobody else's.
                system.setOwner(dir + "/sock", uid: user.uid, gid: persistent ? adminGID : user.gid,
                                mode: persistent ? 0o750 : 0o711)
            }
            var password: String?
            if persistent {
                password = newSecret()
                try system.writeFile(dir + "/m.pw", Data((password! + "\n").utf8), mode: 0o600)
                forOpenVPN(dir + "/m.pw")
            }
            if bundle.splitDNS {
                // MugVPN's DNS script runs in this directory and looks for it.
                try system.writeFile(dir + "/split-dns", Data(), mode: 0o600)
            }
            let process = try system.launch(paths.openvpn,
                                            HelperCore.openvpnArguments(config: config, dir: dir,
                                                                        socket: persistent ? [socket, "unix", dir + "/m.pw"] : [socket, "unix"],
                                                                        access: management, hold: !persistent,
                                                                        extraIgnored: limit.ignored)
                                                // In its sandbox it may write only there (openvpn checks its tmp-dir at start).
                                                + (user == nil ? [] : ["--tmp-dir", dir + "/sock"])
                                                // A profile that would take any certificate of its CA as the server.
                                                + (checked.needsServerCheck ? ["--remote-cert-tls", "server"] : []),
                                            cwd: dir, logPath: dir + "/openvpn.log", user: user) { [weak self] kind in
                self?.finished(id: id, kind: kind)
            }
            let info = ConnectionInfo(id: id, name: bundle.name, pid: process.pid, managementSocket: socket, ownerUID: uid,
                                      persistent: persistent)
            let c = Connection(info: info, process: process, dir: dir)
            c.startedAt = system.now()
            c.serviceID = user?.uid
            c.splitDNS = bundle.splitDNS
            c.mayRouteAll = limit.mayRouteAll
            c.mayChangeDNS = limit.mayChangeDNS
            c.allowed = limit.allowed
            c.restricted = limit.restricted
            connections[id] = c
            // From the start: after a crash, this run is undone from the record, never from
            // the log (an unprivileged openvpn writes that).
            try saveTunnel(c)
            passwords[id] = password
            giveLog(dir + "/openvpn.log", to: info)
            // A persistent tunnel has nobody to answer its requests at boot: the helper does,
            // once openvpn listens (the app of an administrator can take over).
            if persistent { scheduleManagement(id, after: 0.5) }
        } catch {
            // Nothing of a run that could not start properly stays: its openvpn, its id's processes.
            if let c = connections.removeValue(forKey: id) {
                c.exited = true
                c.process.signal(SIGKILL)
                if let sid = c.serviceID { system.killProcesses(uids: sid...sid) }
            }
            passwords[id] = nil
            system.remove(dir)
            throw error
        }
        return (id, socket)
    }

    /// Pushed options a server has no business sending. openvpn uses the first matching
    /// filter: these come before the profile.
    public static let ignoredPushes = ["verb ", "mute ", "lladdr ", "ifconfig-noexec", "route-ipv6-gateway ", "compat-mode ",
                                "providers ", "prng ", "tun-ipv6", "disable-dco", "client-nat ", "shaper "]

    public static func openvpnArguments(config: String, dir: String, socket: [String], access: [String],
                                        hold: Bool = true, extraIgnored: [String] = []) -> [String] {
        // The pull filters first; then the profile's options; the helper's own follow and win.
        var args: [String] = (ignoredPushes + extraIgnored).flatMap { ["--pull-filter", "ignore", $0] }
        args += ["--config", config, "--cd", dir, "--management"]
        args += socket
        args += access
        if hold { args.append("--management-hold") }
        args += ["--management-query-passwords", "--auth-retry", "interact", "--script-security", "1", "--verb", "3"]
        return args
    }

    /// Error text, or nil when the stop was sent.
    public func stop(id: String, uid: UInt32) -> String? {
        guard let c = connections[id] else { return "no such connection" }
        let allowed = uid == 0 || (c.info.persistent ? system.isAdmin(uid: uid) : c.info.ownerUID == uid)
        guard allowed else { return "not your connection" }
        terminate(c)
        return nil
    }

    public func list(uid: UInt32) -> [ConnectionInfo] {
        let admin = uid == 0 || system.isAdmin(uid: uid)
        return connections.values.map(\.info).filter { uid == 0 || $0.ownerUID == uid || $0.persistent }
            .map { i in
                var i = i
                i.managementPassword = admin ? passwords[i.id] : nil
                // Anyone who can reach a persistent tunnel's socket can hold its only management
                // slot, and the socket's path follows from the id: neither goes to non-admins.
                if i.persistent && !admin {
                    i.managementSocket = ""
                    i.id = "persistent:" + i.name
                }
                return i
            }
            .sorted { $0.id < $1.id }
    }

    /// Helper shutdown: stop every tunnel (the caller waits for isEmpty).
    public func stopAll() {
        closing = true
        connections.values.forEach(terminate)
    }

    /// SIGTERM lets openvpn tear down routes and DNS; if it is still running
    /// after the grace period, SIGKILL, and finished() cleans up instead.
    private func terminate(_ c: Connection) {
        guard !c.stopping else { return }
        c.stopping = true
        c.process.signal(SIGTERM)
        system.after(HelperCore.stopGrace) {
            if !c.exited { c.process.signal(SIGKILL) }
        }
    }

    private func finished(id: String, kind: ExitKind) {
        guard let c = connections.removeValue(forKey: id) else { return }
        passwords[id] = nil
        c.exited = true
        c.channel?.close()
        c.channel = nil
        let name = HelperCore.lockName(c.info.name)
        syncArming()
        let tookAll = c.tunnel.takesAllTraffic
        if let id = c.serviceID { system.killProcesses(uids: id...id) }
        do {
            let others = connections.values.filter { $0 !== c }.map(\.tunnel)
            undo(c.tunnel, others: others)
            release(c.tunnel, others: others)
        }
        if c.protection.killSwitch, !c.stopping, c.wasFull || tookAll {
            // Dropped without being asked to: keep its owner's traffic from going around the tunnel.
            addLock(Lock(name: name, owner: c.info.ownerUID, allowLAN: c.protection.allowLAN, everyone: c.info.persistent))
        }
        if c.info.persistent, !c.stopping, !closing {
            // Ended unasked: started again, after a wait that grows (a tunnel up a long time starts the count again).
            let n = system.now() - c.startedAt > 120 ? 0 : persistentRestarts[c.info.name] ?? 0
            persistentRestarts[c.info.name] = n + 1
            let wait = min(HelperCore.persistentRestartMax, 5 * pow(2, Double(min(n, 16))))
            let pname = c.info.name
            system.after(wait) { [weak self] in _ = try? self?.startPersistent(name: pname, uid: 0) }
        }
        saveLocks()
        let kept = paths.logsDir + "/" + HelperCore.logFileName(c.info.name, uid: c.info.ownerUID) + ".log"
        system.move(c.dir + "/openvpn.log", kept)
        giveLog(kept, to: c.info, live: false)
        // Bounded per user: names are the user's to choose.
        let mine = system.list(paths.logsDir).filter { $0.hasSuffix(".\(c.info.ownerUID).log") && paths.logsDir + "/" + $0 != kept }
        for old in mine.dropLast(max(0, HelperCore.keptLogsPerUser - 1)) { system.remove(paths.logsDir + "/" + old) }
        system.remove(c.dir)
        refreshProtection()
        if connections.isEmpty { finishUninstall() }
    }

    // MARK: - privilege separation: what openvpn asks for

    public struct TunnelReply { public var fd: Int32? }
    public static let noSuchConnection = "no such connection"
    /// Requests each user may still make now, refilled over time.
    private var requestTokens: [UInt32: (tokens: Double, at: TimeInterval)] = [:]
    /// Logs kept per user in the logs folder (oldest go first).
    public static let keptLogsPerUser = 20
    /// A connection's requests: this many at once, refilled at requestRate per second.
    public static let requestBurst = 600
    public static let requestRate = 20.0
    public static let hostsBesideFullTunnel = 2
    /// utun devices of one connection that may exist at once (a reconnect opens a new one).
    public static let maxOpenTunnels = 4
    /// Ids for openvpn: one per connection, never an account (the directory is checked).
    public static let serviceIDBase: UInt32 = PFRules.serviceIDs.lowerBound
    public static let serviceIDCount: UInt32 = PFRules.serviceIDs.upperBound - PFRules.serviceIDs.lowerBound
    /// Where id allocation starts: random, so a restarted helper does not hand out the same first id.
    public var nextServiceID: UInt32 = UInt32.random(in: 0..<HelperCore.serviceIDCount)

    private func allocateServiceID() throws -> UInt32 {
        let used = Set(connections.values.compactMap(\.serviceID))
        for i in 0..<HelperCore.serviceIDCount {
            let id = HelperCore.serviceIDBase + (nextServiceID + i) % HelperCore.serviceIDCount
            if !used.contains(id), system.idIsFree(id) {
                nextServiceID = (nextServiceID + i + 1) % HelperCore.serviceIDCount
                return id
            }
        }
        throw HelperCoreError.message("no free id to run openvpn as")
    }

    /// A request of an unprivileged openvpn, forwarded by its owner's app. Checked
    /// (TunnelState) and carried out; a refusal is an error.
    public func tunnelRequest(id: String, uid: UInt32, kind: String, message: String) throws -> TunnelReply {
        // openvpn's teardown requests can come after it ended (it does not wait for answers once stopped).
        guard let c = connections[id] else { throw HelperCoreError.message(HelperCore.noSuchConnection) }
        let allowed = uid == 0 || (c.info.persistent ? system.isAdmin(uid: uid) : uid == c.info.ownerUID)
        guard allowed else { throw HelperCoreError.message("not your connection") }
        // Rationed: a flood from one connection does not hold the helper (and everyone else) up.
        // Per user: more connections do not make more requests.
        let t = system.now()
        var bucket = requestTokens[c.info.ownerUID] ?? (Double(HelperCore.requestBurst), t)
        bucket.tokens = min(Double(HelperCore.requestBurst), bucket.tokens + max(0, t - bucket.at) * HelperCore.requestRate)
        bucket.at = t
        guard bucket.tokens >= 1 else {
            requestTokens[c.info.ownerUID] = bucket
            throw HelperCoreError.message("too many requests")
        }
        bucket.tokens -= 1
        requestTokens[c.info.ownerUID] = bucket
        var reply = TunnelReply()
        let others = connections.values.filter { $0 !== c }.map(\.tunnel)
        // All or nothing: a refused or failed request leaves the records as they were.
        let before = c.tunnel
        let wasFullBefore = c.wasFull
        do {
            try carryOut(c, kind, message, others: others, reply: &reply)
        } catch {
            // Nothing done: the record (written ahead) says so again; if it cannot, the
            // connection is undone and stopped rather than left with a record of the future.
            c.tunnel = before
            do { try saveTunnel(c) } catch { failClosed(c) }
            if let e = error as? TunnelRequestError { throw HelperCoreError.message(e.description) }
            throw error
        }
        /// Take back what this request did.
        func undoRequest() {
            for r in c.tunnel.cleanup() where !before.cleanup().contains(r) { remove(r, others: others) }
            if let dev = c.tunnel.device, dev == before.device {
                if let a = c.tunnel.local, a != before.local { _ = system.runNetwork(["ifconfig", dev, "inet", TunnelState.text(a), "delete"]) }
                if let n6 = c.tunnel.net6, n6 != before.net6, let a6 = n6.split(separator: "/").first {
                    _ = system.runNetwork(["ifconfig", dev, "inet6", String(a6), "delete"])
                }
            }
            if c.tunnel.dnsApplied, !before.dnsApplied, let dev = c.tunnel.device { system.restoreDNS(device: dev) }
            if let dev = c.tunnel.device, dev != before.device {
                takeDown(c.tunnel)
                system.releaseDevice(dev)
            }
            if let fd = reply.fd { system.closeDescriptor(fd) }
            c.tunnel = before
            try? saveTunnel(c)
        }
        // On disk before it counts: a change the helper could not undo after a crash is undone now.
        do {
            try saveTunnel(c)
        } catch {
            undoRequest()
            throw HelperCoreError.message("the helper could not record the change: \(error)")
        }
        // A standard user's tunnel takes traffic only while PF keeps it to its owner.
        let isolated = refreshProtection()
        if c.restricted, !isolated, ["ROUTE", "ROUTE6", "IFCONFIG", "IFCONFIG6"].contains(kind) {
            undoRequest()
            refreshProtection()
            throw HelperCoreError.message("the tunnel cannot be isolated to its user (PF): not set")
        }
        // All traffic with a kill switch only once its arming is on disk (it must outlive a helper crash).
        if c.protection.killSwitch, c.wasFull, !wasFullBefore, locksDirty {
            c.wasFull = false
            syncArming()
            undoRequest()
            refreshProtection()
            throw HelperCoreError.message("the kill switch could not be recorded: not taking all traffic")
        }
        return reply
    }

    private func carryOut(_ c: Connection, _ kind: String, _ message: String, others: [TunnelState],
                          reply: inout TunnelReply) throws {
        let policy = "an administrator does not let standard users change the whole Mac's routing or DNS"

        switch kind {
        case "OPENTUN":
            // Reconnects open a new one; many at once are not a reconnect.
            guard c.tunnel.opened.filter(system.interfaceExists).count < HelperCore.maxOpenTunnels else {
                throw HelperCoreError.message("too many tunnels open for one connection")
            }
            // The new one first: if it cannot be opened, the old one stays as it is.
            let (fd, name) = try system.openUtun()
            if let old = c.tunnel.device {
                if c.tunnel.dnsApplied {
                    system.restoreDNS(device: old)
                    c.tunnel.dnsApplied = false
                }
                for r in c.tunnel.dropDevice(old) { remove(r, others: others) }
                if old != name {
                    takeDown(c.tunnel)
                    system.releaseDevice(old)
                }
                c.tunnel.local = nil
                c.tunnel.net6 = nil
            }
            c.tunnel.device = name
            c.tunnel.subnet = nil
            c.tunnel.peer = nil
            c.tunnel.opened = (c.tunnel.opened.filter(system.interfaceExists) + [name]).suffix(16)
            reply.fd = fd
        case "IFCONFIG":
            let cmds = try c.tunnel.ifconfig(message)
            let theirs = otherNetworks(than: c, otherOwnersOnly: true).nets
            // Its own addresses (the Mac delivers traffic to them locally, routes to the peer):
            // never in the Mac's own networks, nor where another user's tunnel sends traffic
            // (its routes, its peer, gateways and DNS servers). The same 10.8.0.x on both ends of
            // two servers is common and harmless: both are local.
            let lan = system.localIPv4Networks().compactMap(HelperCore.ipv4Net)
            let otherUsers = connections.values.filter { $0 !== c && $0.info.ownerUID != c.info.ownerUID }
            let used = Set(otherUsers.flatMap { $0.tunnel.serverAddresses + $0.tunnel.outsideHosts })
            let routed = otherUsers.flatMap(\.tunnel.routedNetworks)
            for a in [c.tunnel.local, c.tunnel.peer].compactMap({ $0 }) {
                if lan.contains(where: { $0.contains(a) }) {
                    throw HelperCoreError.message("\(TunnelState.text(a)) is in a network of the Mac's own")
                }
                if used.contains(a) || routed.contains(where: { $0.contains(a) }) {
                    throw HelperCoreError.message("\(TunnelState.text(a)) is in another user's network")
                }
            }
            guard let first = cmds.first, system.runNetwork(first) else { throw HelperCoreError.message("ifconfig failed") }
            // The route to its own network: not essential (it may exist already, as a LAN of the same range).
            // Not when it lies in another user's networks (as narrow or narrower, it would take their traffic).
            if cmds.count > 1, let dev = c.tunnel.device, let net = c.tunnel.subnet,
               !theirs.contains(where: { $0.contains(net.address) && $0.prefix <= net.prefix }), system.runNetwork(cmds[1]) {
                c.tunnel.subnetRoute = TunnelRoute(kind: .tunnel, net: TunnelState.text(net.address),
                                                   mask: TunnelState.text(net.mask), via: dev)
            }
        case "IFCONFIG6":
            let cmds = try c.tunnel.ifconfig6(message)
            if let mine = c.tunnel.net6, !c.mayRouteAll {
                let p = mine.split(separator: "/")
                if p.count == 2, !c.allowed.allows6(String(p[0]), bits: Int(p[1]) ?? 0) {
                    throw HelperCoreError.message("IFCONFIG6 \(message): \(policy)")
                }
            }
            if let mine = c.tunnel.net6 {
                if system.localIPv6Networks().contains(where: { TunnelState.overlap6($0, mine) }) {
                    throw HelperCoreError.message("\(mine) is a network of the Mac's own")
                }
                let others = connections.values.filter { $0 !== c }.compactMap(\.tunnel.net6)
                if others.contains(where: { TunnelState.overlap6($0, mine) }) {
                    throw HelperCoreError.message("\(mine) is another tunnel's network")
                }
            }
            try runAll(cmds)
        case "ROUTE":
            let added = try c.tunnel.route(message, gateway: system.defaultGateway())
            // A standard user: private networks, and public ones an administrator lists; no host
            // around the tunnels (via the Mac's gateway, it would leave another user's tunnel).
            if !c.mayRouteAll, added.contains(where: { !$0.intoTunnel }) {
                throw HelperCoreError.message("\(kind) \(message): \(policy)")
            }
            if !c.mayRouteAll {
                for r in added {
                    guard let a = TunnelState.ipv4(Substring(r.net)), let m = TunnelState.ipv4(Substring(r.mask)),
                          let p = TunnelState.prefix(ofMask: m), c.allowed.allows(IPv4Net(address: a, prefix: p)) else {
                        throw HelperCoreError.message("\(kind) \(message): \(policy)")
                    }
                }
            }
            if c.restricted {
                // Nothing into the Mac's own networks (its LAN, its router, its DNS).
                let lan = system.localIPv4Networks().compactMap(HelperCore.ipv4Net)
                for r in added {
                    guard let a = TunnelState.ipv4(Substring(r.net)), let m = TunnelState.ipv4(Substring(r.mask)),
                          let p = TunnelState.prefix(ofMask: m) else { continue }
                    // As narrow as a network of the Mac's or narrower would win over it (wider does not).
                    if lan.contains(where: { $0.contains(a) && $0.prefix <= p }) {
                        throw HelperCoreError.message("\(r.net)/\(p) is a network of the Mac's own")
                    }
                }
            }
            // Between connections, whichever comes first: a host route via the Mac's gateway
            // must not cut into another's network, nor a network take another's host route.
            let (theirNets, theirHosts) = otherNetworks(than: c, otherOwnersOnly: false)
            let otherUsers = otherNetworks(than: c, otherOwnersOnly: true).nets
            for r in added {
                guard let a = TunnelState.ipv4(Substring(r.net)), let m = TunnelState.ipv4(Substring(r.mask)),
                      let p = TunnelState.prefix(ofMask: m) else { continue }
                if !r.intoTunnel, theirNets.contains(where: { $0.contains(a) }) {
                    throw HelperCoreError.message("\(r.net) is in another connection's tunnel")
                }
                if r.intoTunnel, p >= 8, theirHosts.contains(where: { IPv4Net(address: a, prefix: p).contains($0) }) {
                    throw HelperCoreError.message("\(r.net)/\(p) takes another connection's host route")
                }
                // As narrow as another user's network or narrower: the more specific route wins, and
                // their traffic would come here. (Wider takes only what their routes do not.)
                if r.intoTunnel, otherUsers.contains(where: { $0.contains(a) && $0.prefix <= p }) {
                    throw HelperCoreError.message("\(r.net)/\(p) is inside another user's tunnel")
                }
            }
            // While another user's tunnel takes all traffic, a hole or two (its server), no more.
            let fullElsewhere = connections.values.contains { $0 !== c && $0.info.ownerUID != c.info.ownerUID && $0.tunnel.takesAllTraffic }
            if fullElsewhere, c.tunnel.outsideHosts.count > HelperCore.hostsBesideFullTunnel {
                throw HelperCoreError.message("another user's tunnel takes all traffic: no more host routes around it")
            }
            // On disk before the change: after a crash the helper knows what it may have done.
            try record(c)
            for (i, r) in added.enumerated() where !system.runNetwork(r.add) {
                // Already there from another of our connections (the same server): shared.
                if !r.intoTunnel, others.contains(where: { $0.routes.contains(r) }) { continue }
                added.prefix(i).forEach { _ = system.runNetwork($0.delete) }
                throw HelperCoreError.message("route failed")
            }
        case "ROUTE6":
            let r = try c.tunnel.route6(message)
            // As narrow as another user's IPv6 network, or the Mac's own, or narrower: theirs would come here.
            let bits = Int(r.mask) ?? 0
            let theirs6 = connections.values.filter { $0 !== c && $0.info.ownerUID != c.info.ownerUID }
                .flatMap { o in (o.tunnel.net6.map { [$0] } ?? []) + o.tunnel.routes.filter { $0.kind == .tunnel6 }.map { "\($0.net)/\($0.mask)" } }
            for n in system.localIPv6Networks() + theirs6 {
                guard let b = n.split(separator: "/").last.flatMap({ Int($0) }), b <= bits,
                      TunnelState.overlap6(n, "\(r.net)/\(bits)") else { continue }
                throw HelperCoreError.message("\(r.net)/\(bits) is inside another network (\(n))")
            }
            if !c.mayRouteAll, !c.allowed.allows6(r.net, bits: Int(r.mask) ?? 0) {
                throw HelperCoreError.message("\(kind) \(message): \(policy)")
            }
            try record(c)
            if !system.runNetwork(r.add) { throw HelperCoreError.message("route failed") }
        case "ROUTEDEL":
            for r in try c.tunnel.deleteRoute(message, gateway: system.defaultGateway()) { remove(r, others: others) }
        case "ROUTE6DEL": remove(try c.tunnel.deleteRoute6(message), others: others)
        case "DNSVAR": try c.tunnel.dnsVar(message)
        case "DNSUP":
            let t = system.now()
            if let last = c.lastDNSUp, t - last < 1 { throw HelperCoreError.message("DNS changed too soon again") }
            c.lastDNSUp = t
            let plan = try c.tunnel.dnsPlan(device: message, splitMarker: c.splitDNS)
            // Its own domains are its business; all names are everyone's on the Mac.
            if !c.mayChangeDNS {
                // Its own private names, or the domains an administrator lists: a resolver is the whole Mac's.
                if !plan.split { throw HelperCoreError.message("DNS for all names: \(policy)") }
                if let d = plan.matchDomains.first(where: { !c.allowed.allows(domain: $0) }) {
                    throw HelperCoreError.message("DNS for \(d): \(policy)")
                }
            }
            // A standard user's DNS servers: inside its own tunnel, never the Mac's own resolvers or
            // networks (the system resolver would send everyone's queries there, whatever the name).
            if c.restricted {
                let lan = system.localIPv4Networks().compactMap(HelperCore.ipv4Net)
                let mine = c.tunnel.networks
                // (An administrator who lets users change the Mac's DNS lets them replace its resolvers too;
                // their own, set for all names, is then the Mac's.)
                var system = Set<UInt32>()
                if !c.mayChangeDNS {
                    guard let known = self.system.systemDNSServers(excluding: plan.device) else {
                        throw HelperCoreError.message("DNS not set: the Mac's own DNS servers are not known")
                    }
                    // As numbers: one address has more than one spelling.
                    system = Set(known.compactMap { TunnelState.ipv4(Substring($0)) })
                }
                for srv in plan.servers {
                    guard let a = TunnelState.ipv4(Substring(srv)), TunnelState.text(a) == srv, !system.contains(a),
                          !lan.contains(where: { $0.contains(a) }), mine.contains(where: { $0.contains(a) }) || c.tunnel.peer == a else {
                        throw HelperCoreError.message("DNS server \(srv): not inside this tunnel")
                    }
                }
            }
            // A domain another user's tunnel answers for, or a part of it: the more specific one wins.
            let theirDomains = connections.values.filter { $0 !== c && $0.info.ownerUID != c.info.ownerUID && $0.tunnel.dnsApplied }
                .flatMap(\.tunnel.dnsDomains)
            func norm(_ d: String) -> String { d.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ".")) }
            if let d = plan.matchDomains.first(where: { m in theirDomains.contains { norm(m) == norm($0) || norm(m).hasSuffix("." + norm($0)) } }) {
                throw HelperCoreError.message("DNS for \(d): another user's tunnel answers for it")
            }
            c.tunnel.dnsApplied = true
            c.tunnel.dnsDomains = plan.matchDomains
            c.tunnel.dnsServers = plan.servers
            try record(c)
            guard system.setDNS(plan) else { throw HelperCoreError.message("DNS not set") }
        case "DNSDOWN":
            if c.tunnel.dnsApplied, let dev = c.tunnel.device { system.restoreDNS(device: dev) }
            c.tunnel.dnsApplied = false
            c.tunnel.clearDNS()
        default:
            throw HelperCoreError.message("unknown request \(kind)")
        }
    }


    /// Take a route away: only while it is there as added, not while another connection shares
    /// it, and never on a device that is another connection's now.
    private func remove(_ r: TunnelRoute, others: [TunnelState]) {
        if !r.intoTunnel, others.contains(where: { $0.routes.contains(r) }) { return }
        if r.intoTunnel, others.contains(where: { $0.device == r.via }) { return }
        if system.routeExists(r) { _ = system.runNetwork(r.delete) }
    }

    /// At once, not after openvpn's grace: its routes, DNS and addresses go, then openvpn.
    /// Not asked for by its owner: a kill switch it armed fires (and stays on disk).
    private func failClosed(_ c: Connection) {
        let others = connections.values.filter { $0 !== c }.map(\.tunnel)
        if c.protection.killSwitch, c.wasFull || c.tunnel.takesAllTraffic {
            addLock(Lock(name: HelperCore.lockName(c.info.name), owner: c.info.ownerUID, allowLAN: c.protection.allowLAN,
                         everyone: c.info.persistent))
            saveLocks()
        }
        undo(c.tunnel, others: others)
        release(c.tunnel, others: others)
        c.tunnel = TunnelState()
        try? saveTunnel(c)
        c.stopping = true
        c.process.signal(SIGKILL)
    }

    /// Give back the utun devices of a tunnel that is gone (not one another connection has).
    private func release(_ t: TunnelState, others: [TunnelState]) {
        if let d = t.device, !others.contains(where: { $0.device == d }) { takeDown(t) }
        for d in Set(t.opened + (t.device.map { [$0] } ?? [])) where !others.contains(where: { $0.device == d }) {
            system.releaseDevice(d)
        }
    }

    /// No address or route of a utun stays when it is given back (its owner may keep a copy).
    private func takeDown(_ t: TunnelState) {
        guard let d = t.device else { return }
        if let a = t.local { _ = system.runNetwork(["ifconfig", d, "inet", TunnelState.text(a), "delete"]) }
        if let n6 = t.net6, let a6 = n6.split(separator: "/").first { _ = system.runNetwork(["ifconfig", d, "inet6", String(a6), "delete"]) }
        _ = system.runNetwork(["ifconfig", d, "down"])
    }

    static func ipv4Net(_ s: String) -> IPv4Net? {
        let p = s.split(separator: "/")
        guard p.count == 2, let a = TunnelState.ipv4(p[0]), let b = Int(p[1]), (0...32).contains(b) else { return nil }
        return IPv4Net(address: a & IPv4Net(address: 0, prefix: b).mask, prefix: b)
    }

    /// The other connections' networks and outside host routes, persistent tunnels (root
    /// openvpn, their logs are root's) included.
    private func otherNetworks(than c: Connection, otherOwnersOnly: Bool) -> (nets: [IPv4Net], hosts: [UInt32]) {
        var nets: [IPv4Net] = [], hosts: [UInt32] = []
        for o in connections.values where o !== c {
            if otherOwnersOnly, o.info.ownerUID == c.info.ownerUID { continue }
            nets += o.tunnel.networks
            hosts += o.tunnel.outsideHosts
        }
        return (nets, hosts)
    }

    private func runAll(_ cmds: [[String]]) throws {
        for cmd in cmds where !system.runNetwork(cmd) { throw HelperCoreError.message("\(cmd.first ?? "") failed") }
    }

    /// Take away what the helper set up for a tunnel that is gone: only routes still there
    /// as added (those into a closed utun went with it), none another connection shares.
    private func undo(_ t: TunnelState, others: [TunnelState]) {
        t.cleanup().forEach { remove($0, others: others) }
        if t.dnsApplied, let dev = t.device { system.restoreDNS(device: dev) }
    }

    private func record(_ c: Connection) throws {
        do { try saveTunnel(c) } catch { throw HelperCoreError.message("the helper could not record the change: \(error)") }
    }

    private func saveTunnel(_ c: Connection) throws {
        try system.writeFile(c.dir + "/state.json", try JSONEncoder().encode(c.tunnel), mode: 0o600)
    }

    /// Only a record root alone could have written counts.
    private func savedTunnel(in dir: String) -> TunnelState? {
        let path = dir + "/state.json"
        guard let info = system.fileInfo(path), info.kind == .regular, info.rootOnly, let d = system.readFile(path) else { return nil }
        return try? JSONDecoder().decode(TunnelState.self, from: d)
    }

    // MARK: - persistent tunnels: the helper as their management client

    private func scheduleManagement(_ id: String, after seconds: TimeInterval) {
        guard let c = connections[id], c.info.persistent, !c.channelRetryPending else { return }
        c.channelRetryPending = true
        let generation = c.channelGeneration
        system.after(seconds) { [weak self] in
            guard c.channelGeneration == generation else { return } // an app's turn came in between
            c.channelRetryPending = false
            self?.connectManagement(id)
        }
    }

    private func connectManagement(_ id: String) {
        guard let c = connections[id], c.channel == nil, !c.exited else { return }
        let ch = system.connectManagement(c.info.managementSocket, peer: c.info.pid, onLine: { [weak self] line in
            self?.managementLine(id, line)
        }, onClose: { [weak self, weak c] in
            guard let self, let c, !c.exited else { return }
            c.channel = nil
            self.scheduleManagement(id, after: 2)
        })
        guard let ch else { return scheduleManagement(id, after: 1) } // not listening yet
        c.channel = ch
    }

    private func managementLine(_ id: String, _ line: String) {
        guard let c = connections[id], let ch = c.channel else { return }
        if line.hasPrefix("ENTER PASSWORD:") {
            if let pw = passwords[id] { answer(c, ch, pw, nil) }
            return
        }
        // >NEED-OK:Need 'NAME' confirmation MSG:message
        guard line.hasPrefix(">NEED-OK:Need '"), let close = line.dropFirst(15).firstIndex(of: "'") else { return }
        let name = String(line[line.index(line.startIndex, offsetBy: 15)..<close])
        guard TunnelState.requestNames.contains(name) else { return } // for an administrator's app
        let rest = line[close...]
        let message = rest.range(of: "MSG:").map { String(rest[$0.upperBound...]) } ?? ""
        do {
            let r = try tunnelRequest(id: id, uid: 0, kind: name, message: message)
            answer(c, ch, "needok '\(name)' ok", r.fd)
            if let fd = r.fd { system.closeDescriptor(fd) }
        } catch {
            answer(c, ch, "needok '\(name)' cancel", nil)
        }
    }

    /// An openvpn that does not take its answers (it stopped reading, or went away) is
    /// not waited for: the helper lets go and ends that connection.
    private func answer(_ c: Connection, _ ch: ManagementChannel, _ line: String, _ fd: Int32?) {
        guard !ch.send(line, passing: fd) else { return }
        ch.close()
        c.channel = nil
        if !c.exited { terminate(c) }
    }

    /// An administrator's app attaches to a persistent tunnel: the helper lets go of the
    /// management connection, then waits in line for it (openvpn takes one client at a time).
    public func releaseManagement(id: String, uid: UInt32) -> String? {
        guard let c = connections[id], c.info.persistent else { return HelperCore.noSuchConnection }
        guard uid == 0 || system.isAdmin(uid: uid) else { return "only an administrator can attach to a persistent connection" }
        c.channel?.close()
        c.channel = nil
        c.channelGeneration += 1
        c.channelRetryPending = false
        scheduleManagement(id, after: 3)
        return nil
    }

    // MARK: - protection (PF)

    /// The tunnel takes all traffic: def1's two halves, or a replaced default route.
    static func takesAllTraffic(_ f: OpenVPNLogFacts) -> Bool {
        let halves = f.routes.filter { $0.count == 4 && $0[0] == "-net" && $0[3] == "128.0.0.0" }.map { $0[1] }
        let replaced = f.routes.contains { $0.count == 4 && $0[0] == "-net" && $0[1] == "0.0.0.0" && $0[3] == "0.0.0.0" }
        return (halves.contains("0.0.0.0") && halves.contains("128.0.0.0")) || replaced
    }
    private func takesAllTraffic(_ f: OpenVPNLogFacts) -> Bool { HelperCore.takesAllTraffic(f) }

    /// Block names: printable, at most 64 characters.
    static func lockName(_ s: String) -> String {
        String(s.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) }.map(Character.init).prefix(64))
    }

    /// Armings follow the tunnels up: one per name and user taking all traffic with a kill switch,
    /// the LAN open only if every such tunnel allows it. - Returns: whether they changed.
    @discardableResult
    private func syncArming() -> Bool {
        var want: [Lock] = []
        for c in connections.values.sorted(by: { $0.info.id < $1.info.id })
        where !c.exited && c.protection.killSwitch && c.wasFull {
            let name = HelperCore.lockName(c.info.name)
            if let i = want.firstIndex(where: { $0.name == name && $0.owner == c.info.ownerUID && $0.everyone == c.info.persistent }) {
                want[i].allowLAN = want[i].allowLAN && c.protection.allowLAN
            } else {
                want.append(Lock(name: name, owner: c.info.ownerUID, allowLAN: c.protection.allowLAN, armed: true,
                                 everyone: c.info.persistent))
            }
        }
        func key(_ l: Lock) -> String { "\(l.owner)/\(l.allowLAN)/\(l.everyone)/\(l.name)" }
        guard Set(locks.filter(\.armed).map(key)) != Set(want.map(key)) else { return false }
        locks.removeAll(where: \.armed)
        locks += want
        return true
    }

    /// Armed and fired are kept apart: one tunnel of a name dropping leaves another's arming.
    /// Blocks of one name merge to the stricter: the LAN stays open only if all of them allow it.
    private func addLock(_ l: Lock) {
        var l = l
        if let old = locks.first(where: { $0.name == l.name && $0.owner == l.owner && $0.armed == l.armed && $0.everyone == l.everyone }) {
            l.allowLAN = l.allowLAN && old.allowLAN
        }
        locks.removeAll { $0.name == l.name && $0.owner == l.owner && $0.armed == l.armed && $0.everyone == l.everyone }
        locks.append(l)
        // A user cannot pile blocks up: the oldest fired ones go (armings are bounded by connections).
        while locks.filter({ $0.owner == l.owner && !$0.armed }).count > HelperCore.maxLocksPerUser,
              let i = locks.firstIndex(where: { $0.owner == l.owner && !$0.armed }) {
            locks.remove(at: i)
        }
    }


    /// Recompute what PF must enforce from the helper's own knowledge; apply it if it
    /// changed, or if PF no longer holds it (pfctl -d, a flushed anchor).
    /// - Returns: whether PF now holds what it must (a failure is tried again later).
    @discardableResult
    public func refreshProtection() -> Bool {
        var s = ProtectionState()
        for c in connections.values {
            let full = c.tunnel.takesAllTraffic
            if let dev = c.tunnel.device {
                s.tunnels.append(dev)
                if c.restricted {
                    s.ownTraffic.append(ProtectionState.OwnTunnel(device: dev, owner: c.info.ownerUID,
                                                                  dnsServers: c.tunnel.dnsApplied ? c.tunnel.dnsServers : []))
                }
            }
            guard c.protection.any else { continue }
            if full, !c.wasFull { c.wasFull = true }
            // A persistent tunnel up again with all traffic: the block its drop left goes (nobody connects it by hand).
            if full, c.info.persistent, !c.exited {
                let name = HelperCore.lockName(c.info.name)
                if locks.contains(where: { $0.everyone && !$0.armed && $0.name == name }) {
                    locks.removeAll { $0.everyone && !$0.armed && $0.name == name }
                    saveLocks()
                }
            }
            if full {
                s.blockIPv6 = s.blockIPv6 || c.protection.blockIPv6
                s.dnsOnlyTunnels = s.dnsOnlyTunnels || c.protection.dnsOnlyTunnel
            }
        }
        // Armed on disk: if the helper dies with the tunnel, the next one blocks.
        if syncArming() { saveLocks() }
        let now = system.now()
        suspended = suspended.filter { $0.value > now }
        s.locks = locks.filter { !$0.armed && suspended[HelperCore.suspendKey($0)] == nil }.map { ProtectionState.Lock(owner: $0.owner, allowLAN: $0.allowLAN, everyone: $0.everyone) }
        let anchor = PFRules.anchor(s)
        let broken = !anchor.isEmpty && anchor == appliedPF && !system.pfIntact(anchor)
        if anchor != appliedPF || broken {
            // Remembered only once pfctl took it: a failure is tried again on the next look.
            appliedPF = system.applyPF(anchor) ? anchor : "\u{0}"
        }
        if locksDirty { saveLocks() }
        // PF gone and not to be put back: standard users' tunnels would take others' traffic.
        if appliedPF != anchor {
            for c in connections.values where c.restricted && c.tunnel.device != nil && !c.exited { failClosed(c) }
        }
        // Tunnels come up and change routes after start, and PF can be changed under us:
        // look again while protection is asked for or in force.
        if connections.values.contains(where: { $0.protection.any }) || !anchor.isEmpty, !refreshPending {
            refreshPending = true
            system.after(2) { [weak self] in
                self?.refreshPending = false
                self?.refreshProtection()
            }
        }
        return appliedPF == anchor
    }

    /// Names of the blocks in force (everyone may see why a user's traffic is blocked).
    /// Fired blocks the caller may see: an administrator all, a user their own (others are
    /// not blocked by them and need not learn their profile names).
    public func locks(uid: UInt32) -> [String] {
        let admin = uid == 0 || system.isAdmin(uid: uid)
        // A persistent tunnel's block is everyone's: everyone it blocks is told why (an administrator lifts it).
        return locks.filter { !$0.armed && (admin || $0.owner == uid || $0.everyone) }.map(\.name).sorted()
    }

    /// Nothing needs this helper to keep running: no connection of anyone's, no block (PF to watch).
    /// Then it may exit for launchd to start the one an updated app came with.
    public var idleForRestart: Bool { connections.isEmpty && locks.isEmpty && !closing }

    /// Fired blocks lifted for a while (to sign in to a network), until this time. Not on disk:
    /// a helper that starts again blocks again.
    private var suspended: [String: TimeInterval] = [:]
    public static let maxSuspend: TimeInterval = 300
    private static func suspendKey(_ l: Lock) -> String { "\(l.owner)/\(l.everyone)/\(l.name)" }

    /// Lift the caller's blocks (an administrator's: all) for at most `maxSuspend` seconds. Error text or nil.
    public func suspendBlocks(uid: UInt32, seconds: TimeInterval) -> String? {
        let admin = uid == 0 || system.isAdmin(uid: uid)
        let mine = locks.filter { !$0.armed && (admin || $0.owner == uid) }
        guard !mine.isEmpty || locks.allSatisfy(\.armed) else { return "only its owner or an administrator can lift the block" }
        let wait = min(max(seconds, 1), HelperCore.maxSuspend)
        let until = system.now() + wait
        for l in mine { suspended[HelperCore.suspendKey(l)] = until }
        system.after(wait) { [weak self] in self?.refreshProtection() }
        refreshProtection()
        return nil
    }

    /// Lift blocks: an administrator all of them, a user their own. Error text or nil.
    public func unblock(uid: UInt32) -> String? {
        let admin = uid == 0 || system.isAdmin(uid: uid)
        let fired = locks.filter { !$0.armed }
        guard admin || fired.contains(where: { $0.owner == uid }) || fired.isEmpty else {
            return "only its owner or an administrator can lift the block"
        }
        locks.removeAll { !$0.armed && (admin || $0.owner == uid) }
        saveLocks()
        refreshProtection()
        return nil
    }

    private var locksPath: String { paths.supportDir + "/locks.json" }

    /// A kill switch armed only in memory would not survive the helper: written again until it is.
    private var locksDirty = false
    private func saveLocks() {
        if locks.isEmpty { system.remove(locksPath); locksDirty = false; return }
        do {
            try system.writeFile(locksPath, try JSONEncoder().encode(locks), mode: 0o600)
            locksDirty = false
        } catch {
            locksDirty = true
        }
    }

    /// At start: blocks a previous helper left (only from a file root alone could
    /// write). Kill switches it had armed fire now: their tunnels died with it.
    private func loadLocks() {
        guard let info = system.fileInfo(locksPath), info.kind == .regular, info.rootOnly,
              let d = system.readFile(locksPath), let l = try? JSONDecoder().decode([Lock].self, from: d) else { return }
        locks = []
        for var x in l {
            x.name = HelperCore.lockName(x.name)
            x.armed = false
            addLock(x)
        }
        saveLocks()
    }

    /// Most routes one cleanup deletes, and how much of a log it reads.
    public static let maxCleanupRoutes = 256
    static let maxLogBytes = 8 << 20

    /// What a connection's log says it set up. Only a log root alone could have
    /// written counts: root acts on it.
    private func facts(in dir: String) -> OpenVPNLogFacts {
        let path = dir + "/openvpn.log"
        guard let info = system.fileInfo(path), info.kind == .regular, info.rootOnly,
              let data = system.readTail(path, maxBytes: HelperCore.maxLogBytes) else { return OpenVPNLogFacts.parse("") }
        return OpenVPNLogFacts.parse(String(decoding: data, as: UTF8.self))
    }

    private func cleanUp(after facts: OpenVPNLogFacts, others: [OpenVPNLogFacts]) {
        let plan = CleanupPlan.make(facts, others: others)
        if let dev = plan.dnsDevice { system.restoreDNS(device: dev) }
        // Routes through the dead utun are already gone; deleting them fails harmlessly.
        plan.routes.prefix(HelperCore.maxCleanupRoutes).map(OpenVPNLogFacts.deleteArguments).forEach(system.deleteRoute)
        // A default route openvpn took away (redirect-gateway without def1) goes back.
        facts.deletedDefaults.prefix(2).forEach(system.addRoute)
    }

    /// The live log stays root's (cleanup reads it) and its owner may read it;
    /// a kept log is the user's alone. Persistent ones are root's, readable by administrators.
    private func giveLog(_ path: String, to info: ConnectionInfo, live: Bool = true) {
        if info.persistent {
            system.setOwner(path, uid: 0, gid: adminGID, mode: 0o640)
        } else if live {
            system.setOwner(path, uid: 0, gid: staffGID, mode: 0o600)
            system.grantRead(path, uid: info.ownerUID)
        } else {
            system.setOwner(path, uid: info.ownerUID, gid: staffGID, mode: 0o600)
        }
    }

    /// `<profile>.<uid>`: users' profiles with the same name keep separate logs.
    public static func logFileName(_ profile: String, uid: UInt32) -> String {
        logFileName(profile) + ".\(uid)"
    }

    /// A profile name made safe as a file name in the logs directory.
    public static func logFileName(_ profile: String) -> String { safeLogName(profile) }

    /// Copy a file from the app bundle (which its user can write to) to a
    /// root-owned place, check the copy against its pin, and only then put it
    /// in place. Nothing is ever run from the bundle itself.
    public static func installPinned(from src: String, to dst: String, system: HelperSystem,
                                     check: (String) throws -> Void) throws {
        let tmp = dst + ".new"
        system.remove(tmp)
        try system.copyFile(src, tmp, mode: 0o755)
        do {
            // Only a regular file of root's: a link (to a copy its user can swap
            // later) would pass the pin check below and then be installed.
            guard let info = system.fileInfo(tmp), info.kind == .regular, info.rootOnly else {
                throw HelperCoreError.message("\(src) is not a regular file")
            }
            try check(tmp)
        } catch {
            system.remove(tmp)
            throw error
        }
        try system.replace(tmp, dst)
    }

    public static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

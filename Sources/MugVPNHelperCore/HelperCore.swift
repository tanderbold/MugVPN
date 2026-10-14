import CryptoKit
import Foundation
import MugVPNCore
import MugVPNPlanner

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
    /// - Returns: false when owner or mode could not be set.
    @discardableResult func setOwner(_ path: String, uid: UInt32, gid: UInt32, mode: UInt16) -> Bool
    /// Replace MugVPN's PF anchor with these rules ("" clears it and releases PF); false if pfctl refused.
    func applyPF(_ anchor: String) -> Bool
    /// PF is on and MugVPN's anchor holds these rules (someone may have run pfctl -d or flushed it).
    func pfIntact(_ anchor: String) -> Bool
    /// `route add` with these arguments (putting back a default route openvpn deleted).
    /// - Returns: false when it is not there afterwards (refused).
    @discardableResult func addRoute(_ args: [String]) -> Bool
    /// A file from `offset` on (at most `maxBytes`), without following a link.
    func readFrom(_ path: String, offset: UInt64, maxBytes: Int) -> Data?
    /// Let `uid` read `path` (an ACL entry) without owning it. False: not granted.
    @discardableResult func grantRead(_ path: String, uid: UInt32) -> Bool
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
    func setDNS(_ plan: DNSPlan) -> DNSSet
    /// SIGKILL every process running the executable at `path`.
    func killStrayOpenVPN(path: String)
    /// Its DNS taken off: all of it, all but the backup of the primary's DNS (its DNS is off; the backup
    /// still holds all names back), or not (some may still be in effect).
    @discardableResult func restoreDNS(device: String) -> DNSRestore
    /// Only the backup a restore left behind.
    func removeDNSBackup(device: String) -> Bool
    /// The helper runs from an app in the Trash (an uninstall to finish), not from an installed one.
    var runningFromTrash: Bool { get }
    /// Every user's home folder (wherever it is).
    var userHomes: [String] { get }
    /// Remove `name` (with all in it) in `home`/`folders`, each step opened from the last, never through a link nor
    /// into another volume.
    func removeInHome(_ home: String, through folders: [String], _ name: String) -> HomeRemoval
    /// A launchd job unloaded: true once launchd is known to have no such job.
    func unloadJob(_ label: String) -> Bool
    /// - Returns: false when it is still there (refused); a route already gone counts as deleted.
    @discardableResult func deleteRoute(_ args: [String]) -> Bool
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
    /// Last written (seconds since 1970).
    public var modified: TimeInterval
    public init(owner: UInt32, mode: UInt16, kind: Kind, modified: TimeInterval = 0) {
        self.owner = owner
        self.mode = mode
        self.kind = kind
        self.modified = modified
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

/// The app was dragged to the Trash: noticed by the helper (macOS tells nobody). Only once it has
/// been there a minute: an update replaces the app by moving the old one away and the new one in.
/// What removing in a user's home came to: gone (or never there); left, the way (or something in it) not one root
/// may take (a link, a mounted volume); or not removed.
public enum HomeRemoval: Sendable { case gone, skipped, failed }

public struct TrashWatch: Sendable {
    public static let grace: TimeInterval = 60
    private var since: TimeInterval?
    public init() {}

    /// - bundleInPlace: the app is where the helper started from. - runningFrom: the helper's path now.
    /// - Returns: true when it is time to take MugVPN's system part away.
    public mutating func look(bundleInPlace: Bool, runningFrom: String, now: TimeInterval) -> Bool {
        guard !bundleInPlace, HelperPaths.isInTrash(runningFrom) else { since = nil; return false }
        let start = since ?? now
        since = start
        return now - start >= TrashWatch.grace
    }
    /// In the Trash, its minute running.
    public var counting: Bool { since != nil }
}

/// A device's DNS taken off: all of it; all but the backup of the primary's DNS (its DNS is off, the
/// backup still holds all names back); or not (some may still be in effect).
public enum DNSRestore: Sendable { case done, backupLeft, failed }
/// DNS set, refused, or refused with the backup made for it left behind (it holds all names back).
public enum DNSSet: Sendable { case set, failed, failedBackupLeft }

public struct HelperPaths: Sendable {
    /// `<bundle>/Contents` for an executable at `<bundle>/Contents/MacOS/<name>`; nil for a relative
    /// path (launchd gives a registered service's argv[0] relative to its bundle) or one outside a bundle.
    public static func contentsDirectory(ofExecutable path: String) -> String? {
        guard path.hasPrefix("/") else { return nil }
        let macos = (path as NSString).deletingLastPathComponent
        guard (macos as NSString).lastPathComponent == "MacOS" else { return nil }
        let contents = (macos as NSString).deletingLastPathComponent
        return (contents as NSString).lastPathComponent == "Contents" ? contents : nil
    }

    /// This process's executable, from the kernel (not argv[0]), links resolved.
    public static func executablePath() -> String? {
        var buf = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
        guard proc_pidpath(getpid(), &buf, UInt32(buf.count)) > 0 else { return nil }
        return URL(fileURLWithPath: String(cString: buf)).resolvingSymlinksInPath().path
    }

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

    /// In a Trash: the home's (~/.Trash) or another volume's (/Volumes/<name>/.Trashes/<uid>).
    public static func isInTrash(_ path: String) -> Bool {
        let parts = path.split(separator: "/").map(String.init)
        for (i, p) in parts.enumerated() {
            if p == ".Trash" { return true }
            if p == ".Trashes", i + 1 < parts.count, !parts[i + 1].isEmpty, parts[i + 1].allSatisfy(\.isNumber) { return true }
        }
        return false
    }

    /// Run once at the next boot while the app is in the Trash (for its helper gone with an emptied Trash by then).
    public var cleanupDaemonPlist: String {
        (devDaemonPlist as NSString).deletingLastPathComponent + "/" + MugVPNIDs.cleanupLabel + ".plist"
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
    /// A kept log appended to is cut to its newest this much.
    public static let maxKeptLogBytes = 4 << 20

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
        /// The server's DNS only for these domains (the profile's options).
        var dnsDomains: [String] = []
        /// DNS for all names asked while another tunnel had them: next in line for them.
        var dnsWantsAll: DNSPlan?
        /// When it asked (in order: who has waited longest goes first).
        var dnsAskOrder = 0
        /// Routes a failed request added and could not take back (kept on record, the connection undone).
        var stuckRoutes: [TunnelRoute] = []
        /// A failed request left the Mac other than its record can say (a route it took away not back): undone.
        var mustFailClosed = false
        /// Its log is added to the kept one (not replacing it).
        var appendLog = false
        /// Started while the block of a dropped tunnel of its name was in force: lifts it once it takes all traffic.
        var liftsBlock = false
        /// DNS it left could not be put on record elsewhere: its own record (run directory) stays.
        var keepRecord = false
        /// Its DNS on the Mac now, whole (search domains too); nil: none of its own. Its record says the same.
        var appliedDNS: DNSPlan?
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
        /// The planner's view of its limits.
        var limits: ConnectionLimits {
            ConnectionLimits(restricted: restricted, mayRouteAll: mayRouteAll, mayChangeDNS: mayChangeDNS, allowed: allowed)
        }
        /// What the helper set up for it: what it undoes.
        var tunnel = TunnelState()
        init(info: ConnectionInfo, process: HelperProcess, dir: String) {
            self.info = info
            self.process = process
            self.dir = dir
        }
    }

    /// A kill switch's block (MugVPNPlanner decides on them).
    typealias Lock = ProtectionLock
    /// Persistent tunnels that ended unasked, by name: each start again waits longer.
    private var persistentRestarts: [String: Int] = [:]
    public static let persistentRestartMax: TimeInterval = 300
    public static let maxLocksPerUser = ProtectionPlanner.maxLocksPerUser
    private var locks: [Lock] = []
    private var appliedPF = ""
    private var refreshPending = false

    private let system: HelperSystem
    public let paths: HelperPaths
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
    /// Something worth the helper's log.
    public var onNote: (String) -> Void = { _ in }
    private var uninstalling: (keepProfiles: Bool, fromTrash: Bool)?
    /// An uninstall held back by DNS left (the app in the Trash): done once that is off (keeping profiles?).
    private var uninstallWhenDNSOff: Bool?
    private var uninstallPendingPath: String { paths.supportDir + "/uninstall-pending.json" }
    /// That wish not on disk yet (written again with the DNS retries).
    private var uninstallPendingUnsaved = false
    /// An uninstall stopped because that wish could not be removed: tried again.
    private var uninstallRetryNeeded = false

    private func saveUninstallPending() {
        guard let keep = uninstallWhenDNSOff else { return }
        let d = (try? JSONEncoder().encode(["keepProfiles": keep])) ?? Data()
        uninstallPendingUnsaved = (try? system.writeFile(uninstallPendingPath, d, mode: 0o600)) == nil
        if uninstallPendingUnsaved { retryDNSLeftLater() }
    }
    private var uninstallReplies: [(String?) -> Void] = []
    /// Uninstalling or shutting down: no new tunnels.
    private var closing = false

    /// Remove MugVPN's system part: stop every tunnel, then delete what the
    /// helper installed or wrote. Administrators only. `done` is called once
    /// it is removed (each accepted request gets its own call), or with why not.
    public func uninstall(uid: UInt32, keepProfiles: Bool, done: @escaping (String?) -> Void = { _ in }) throws {
        try uninstall(uid: uid, keepProfiles: keepProfiles, fromTrash: false, done: done)
    }

    private func uninstall(uid: UInt32, keepProfiles: Bool, fromTrash: Bool, done: @escaping (String?) -> Void) throws {
        // Before anything changes: a refused caller leaves every wish (and file) as it was.
        guard uid == 0 || system.isAdmin(uid: uid) else {
            throw HelperCoreError.message("only an administrator can uninstall MugVPN")
        }
        // The app went to the Trash: no one asks again, so the wish is on disk before anything is stopped
        // (a helper that starts again finishes it), and stays until it is done.
        // A request while one waits for DNS: one wish, keeping profiles only if every request asked to.
        if fromTrash || uninstallWhenDNSOff != nil {
            uninstallWhenDNSOff = (uninstallWhenDNSOff ?? true) && keepProfiles
            saveUninstallPending()
        }
        if let u = uninstalling {
            // Keeping profiles only if every request asked to.
            uninstalling = (u.keepProfiles && keepProfiles, u.fromTrash || fromTrash)
        } else {
            uninstalling = (keepProfiles, fromTrash)
        }
        uninstallReplies.append(done)
        stopAll()
        if connections.isEmpty { finishUninstall() }
    }

    /// The app went to the Trash: what MugVPN put on the Mac goes, with every user's logs and settings;
    /// profiles stay (administrators' and users' own, and policy.json), for a reinstall to find.
    /// (Those go with the rest of its files, checked, and tried again with the wish on disk.)
    public func uninstallMovedToTrash() {
        try? uninstall(uid: 0, keepProfiles: true, fromTrash: true) { _ in }
    }

    private var appLocationPath: String { paths.supportDir + "/app-location" }

    /// Where the app is installed (its Contents), for telling whether it is still there: recorded while the helper
    /// runs from it, read back when it runs from the Trash (started again after the app went there). Nil: not known
    /// (taken as not there). A Trash location is never recorded nor believed.
    public func appLocation(running contents: String) -> String? {
        func inTrash(_ p: String) -> Bool { HelperPaths.isInTrash(p) }
        if !inTrash(contents) {
            if system.readFile(appLocationPath).map({ String(decoding: $0, as: UTF8.self) }) != contents {
                try? system.writeFile(appLocationPath, Data(contents.utf8), mode: 0o600)
            }
            return contents
        }
        guard let info = system.fileInfo(appLocationPath), info.kind == .regular, info.rootOnly,
              let d = system.readFile(appLocationPath) else { return nil }
        let recorded = String(decoding: d, as: UTF8.self)
        return recorded.hasPrefix("/") && !inTrash(recorded) ? recorded : nil
    }

    /// While the app is in the Trash (from the helper's first sight of it there), a launch daemon of the system's own
    /// shell is kept for the next boot: should the Trash be emptied and the Mac restarted before the helper finishes,
    /// it takes MugVPN's system part away (left be while the helper or the app is still there: that finishes or keeps
    /// it). Out of the Trash: unloaded and removed. Said when not done (tried again on the next look).
    public func bootCleanup(armed: Bool, helper: String, app: String?) {
        let plist = paths.cleanupDaemonPlist
        guard armed else {
            if system.fileInfo(plist) != nil, !removeBootCleanup() { onNote("could not remove \(plist)") }
            return
        }
        let d = HelperCore.bootCleanupPlist(helper: helper, app: app, paths: paths)
        guard system.readFile(plist) != d else { return }
        if (try? system.writeFile(plist, d, mode: 0o644)) == nil { onNote("could not write \(plist)") }
    }

    /// The boot cleanup unloaded (launchd may have it from this boot), known gone from launchd, then its file.
    private func removeBootCleanup() -> Bool {
        guard system.unloadJob(MugVPNIDs.cleanupLabel) else { return false }
        system.remove(paths.cleanupDaemonPlist)
        return system.fileInfo(paths.cleanupDaemonPlist) == nil
    }

    /// The boot cleanup's launch daemon: the system's shell, nothing of MugVPN's (which may be gone by then).
    public static func bootCleanupPlist(helper: String, app: String?, paths: HelperPaths) -> Data {
        // The paths it looks at in its environment, not its arguments (process patterns see arguments only).
        var env = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "MUGVPN_HELPER": helper]
        if let app { env["MUGVPN_APP_INFO"] = app + "/Info.plist" }
        let p: [String: Any] = ["Label": MugVPNIDs.cleanupLabel, "RunAtLoad": true, "EnvironmentVariables": env,
                                "ProgramArguments": ["/bin/sh", "-c", bootCleanupScript(paths: paths)]]
        return (try? PropertyListSerialization.data(fromPropertyList: p, format: .xml, options: 0)) ?? Data()
    }

    /// After a boot nothing of a tunnel holds (routes, DNS, PF are the running system's): only files stay. Nothing is
    /// removed unless launchd is known to have no helper and none runs (113: launchctl's "no such service"); a removal
    /// that fails leaves it for the next boot. What it did, and what it leaves (it reaches no user's home: profiles,
    /// users' logs and settings, the Login Items entry only the app could take away), goes to the system log.
    public static let helperProcessPattern = ShellProcessCheck.helperPattern

    /// The paths it looks at come in its environment: MUGVPN_HELPER (the helper in the Trash), MUGVPN_APP_INFO (a
    /// replacement where it was installed), so that its own command line holds nothing a process pattern matches.
    /// Its own launch daemon file goes last, checked, before success is said (launchd then lets go of the job; not
    /// loaded again, its file gone).
    public static func bootCleanupScript(paths: HelperPaths) -> String {
        let q = ShellProcessCheck.quoted
        let s = paths.supportDir, h = "system/" + MugVPNIDs.helperLabel
        let helper = q(ShellProcessCheck.helperPattern), openvpn = q(ShellProcessCheck.pattern(paths.openvpn))
        // (Not told where the helper is: nothing is done.)
        return "[ -n \"$MUGVPN_HELPER\" ] || exit 1; [ -e \"$MUGVPN_HELPER\" ] && exit 0; "
            + "[ -n \"$MUGVPN_APP_INFO\" ] && [ -e \"$MUGVPN_APP_INFO\" ] && exit 0; "
            + "say() { logger -t MugVPN \"MugVPN boot cleanup: $1\"; }; "
            + ShellProcessCheck.noneLeftFunction(onError: "say 'could not tell which of its processes run: nothing removed, tried again at the next start'")
            + ShellProcessCheck.goneFromLaunchdFunction
            + "none_left \(helper) 0 || { say 'its helper runs: left to it'; exit 0; }; "
            + "launchctl bootout \(h) >/dev/null 2>&1; "
            + "gone_from_launchd \(MugVPNIDs.helperLabel) 30 || { say 'launchd still has its helper (or could not tell): nothing removed, tried again at the next start'; exit 1; }; "
            + "none_left \(helper) 20 || { say 'its helper still runs: nothing removed, tried again at the next start'; exit 1; }; "
            + "pkill -9 -f \(openvpn); [ $? -le 1 ] || { say 'could not stop its openvpn: nothing removed, tried again at the next start'; exit 1; }; "
            + "none_left \(openvpn) 5 || { say 'its openvpn still runs: nothing removed, tried again at the next start'; exit 1; }; "
            + "rm -rf " + [paths.runDir, paths.libexecDir, paths.logsDir, s + "/locks.json", s + "/app-location",
                           s + "/uninstall-pending.json", s + "/dns-left.json", s + "/pf.token", s + "/pf.release",
                           paths.devDaemonPlist].map(q).joined(separator: " ")
            + " || { say 'not all removed: tried again at the next start'; exit 1; }; "
            + "rm -f \(q(paths.cleanupDaemonPlist)); [ ! -e \(q(paths.cleanupDaemonPlist)) ] || "
            + "{ say 'the system part is removed, but not its own launch daemon file: it runs again at the next start'; exit 1; }; "
            + "say 'the system part is removed (the app left with the Trash emptied). Left: profiles, the MugVPN logs and settings in each home (Library/Logs/MugVPN, Library/Preferences/com.mugvpn.app.plist), and the entry in System Settings, General, Login Items'; "
            // (Let go, launchd ends this script; not let go, it is said: the finished job stays until the next restart,
            // never loaded again, its file gone.)
            + "launchctl bootout system/\(MugVPNIDs.cleanupLabel) >/dev/null 2>&1 || "
            + "say 'launchd keeps this finished job until the next restart (its file is gone: it does not run again)'; exit 0"
    }

    /// Not finished after the Trash (no one asked, no one is answered): said once per reason, for the system log.
    private var lastTrashNote: String?
    private func noteTrash(_ u: (keepProfiles: Bool, fromTrash: Bool), _ why: String) {
        guard u.fromTrash, why != lastTrashNote else { return }
        lastTrashNote = why
        onNote("uninstalling after the Trash is not finished yet (tried again): " + why)
    }

    private func finishUninstall() {
        guard let u = uninstalling else { return }
        // DNS a tunnel left that could not be taken off: the helper stays to take it off (its record and
        // retries would go with it). Said; asked again later.
        if !dnsLeft.isEmpty || !keptRuns.isEmpty { retryDNSLeftNow() }
        guard dnsLeft.isEmpty, keptRuns.isEmpty else {
            uninstalling = nil
            closing = false
            let replies = uninstallReplies
            uninstallReplies = []
            replies.forEach { $0(HelperRefusal.dnsCleanupPending) }
            noteTrash(u, HelperRefusal.dnsCleanupPending)
            // The app went to the Trash: no one asks again, so it is done once that DNS is off.
            if u.fromTrash, uninstallWhenDNSOff == nil { uninstallWhenDNSOff = u.keepProfiles }
            return
        }
        // Protection first: nothing of it may outlive the helper (or come back with a reinstall). PF that keeps
        // MugVPN's rules: the helper stays (gone, no one could lift a block).
        locks = []
        saveLocks()
        // (Blocks still on disk would come back with a reinstall: as much a refusal as PF's.)
        guard !locksDirty, system.applyPF("") else {
            uninstalling = nil
            closing = false
            let replies = uninstallReplies
            uninstallReplies = []
            replies.forEach { $0(HelperRefusal.pfPending) }
            noteTrash(u, HelperRefusal.pfPending)
            uninstallRetryNeeded = uninstallWhenDNSOff != nil
            retryDNSLeftLater()
            return
        }
        appliedPF = ""
        // After the Trash the wish to uninstall is on disk before anything goes, and stays until the very end: a
        // helper (or Mac) that stops halfway starts again and finishes. Not on disk: not started (tried again).
        if u.fromTrash, uninstallPendingUnsaved || system.fileInfo(uninstallPendingPath) == nil {
            uninstallWhenDNSOff = u.keepProfiles
            saveUninstallPending()
            guard !uninstallPendingUnsaved else {
                uninstalling = nil
                closing = false
                let replies = uninstallReplies
                uninstallReplies = []
                replies.forEach { $0(HelperRefusal.recordPending) }
                noteTrash(u, HelperRefusal.recordPending)
                uninstallRetryNeeded = true
                retryDNSLeftLater()
                return
            }
        }
        uninstalling = nil
        // Its files, all but that wish (the support folder's other entries when profiles go too).
        var gone = [paths.runDir, paths.libexecDir, paths.logsDir, appLocationPath]
        if !u.keepProfiles {
            gone += [paths.systemConfigDir, paths.autoDir]
            gone += system.list(paths.supportDir).map { paths.supportDir + "/" + $0 }
                .filter { $0 != uninstallPendingPath && !gone.contains($0) }
        }
        gone.forEach(system.remove)
        // After the Trash, every user's logs and settings (no app left to remove them): step by step from the home,
        // never by a path (a link the user swaps in on the way would point root anywhere).
        var userStayed: [String] = [], userSkipped: [String] = []
        if u.fromTrash {
            for home in system.userHomes {
                for (folders, name) in [(["Library", "Logs"], "MugVPN"), (["Library", "Preferences"], "com.mugvpn.app.plist")] {
                    let path = ([home] + folders + [name]).joined(separator: "/")
                    switch system.removeInHome(home, through: folders, name) {
                    case .gone: break
                    case .skipped: userSkipped.append(path)
                    case .failed: userStayed.append(path)
                    }
                }
            }
        }
        // Not one root may reach safely (a link, a mounted volume on the way): left, and said (its user's to remove;
        // tried again it would only be left again).
        if !userSkipped.isEmpty { onNote("left in place, not safe for root to remove: " + userSkipped.joined(separator: ", ")) }
        /// Not finished: said, the helper stays to try again (after the Trash on its own, the wish still on disk).
        func notFinished(_ answer: String) {
            closing = false
            let replies = uninstallReplies
            uninstallReplies = []
            replies.forEach { $0(answer) }
            noteTrash(u, answer)
            if u.fromTrash {
                uninstallWhenDNSOff = u.keepProfiles
                uninstallRetryNeeded = true
                retryDNSLeftLater()
            }
        }
        // Gone, or said. (Kept profiles: no record of DNS left may stay either, a reinstall would act on it.)
        let stayed = (gone + [dnsLeftPath]).filter { system.fileInfo($0) != nil } + userStayed
        guard stayed.isEmpty else { return notFinished(HelperRefusal.filesPending + stayed.joined(separator: ", ")) }
        // The boot cleanup (kept while the app was in the Trash): out of launchd, then its file.
        guard removeBootCleanup() else { return notFinished(HelperRefusal.filesPending + paths.cleanupDaemonPlist) }
        // The launch daemon next: one that stays is said.
        system.remove(paths.devDaemonPlist)
        guard system.fileInfo(paths.devDaemonPlist) == nil else { return notFinished(HelperRefusal.filesPending + paths.devDaemonPlist) }
        // Last, checked: profiles not kept, the support folder itself (the wish in it); kept, the wish alone. Until
        // then a helper started again finishes the uninstall; after, one started again from the Trash finds the app
        // gone on its own (and one from a reinstalled app is not to uninstall). Not gone: not finished, tried again.
        let last = u.keepProfiles ? uninstallPendingPath : paths.supportDir
        system.remove(last)
        guard system.fileInfo(last) == nil else { return notFinished(HelperRefusal.filesPending + last) }
        uninstallWhenDNSOff = nil
        uninstallPendingUnsaved = false
        uninstallRetryNeeded = false
        let replies = uninstallReplies
        uninstallReplies = []
        replies.forEach { $0(nil) }
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
        var kept = Set<String>()
        // The logs folder first: a dead run's log is kept there before its folder goes.
        try? system.makeDirectory(paths.logsDir, mode: 0o755)
        loadDNSLeft()
        if let info = system.fileInfo(uninstallPendingPath), info.kind == .regular, info.rootOnly,
           let d = system.readFile(uninstallPendingPath), let p = try? JSONDecoder().decode([String: Bool].self, from: d) {
            // Only while this helper runs from the app in the Trash: started from a reinstalled app, it is not to go.
            if system.runningFromTrash { uninstallWhenDNSOff = p["keepProfiles"] ?? true } else { system.remove(uninstallPendingPath) }
        }
        // Started from a reinstalled app (not the Trash): no boot cleanup is to take it away.
        if !system.runningFromTrash, !removeBootCleanup() { onNote("could not remove \(paths.cleanupDaemonPlist)") }
        // Whatever ran as a connection's id outlived its helper.
        system.killProcesses(uids: HelperCore.serviceIDBase...(HelperCore.serviceIDBase + HelperCore.serviceIDCount - 1))
        if !leftovers.isEmpty {
            system.killStrayOpenVPN(path: paths.openvpn)
            system.killStrayOpenVPN(path: paths.openvpn + "-root") // an older version's
            for d in leftovers {
                // A privilege-separated run: the helper's own record of what it did (kept while DNS it left
                // is on record nowhere else).
                if let t = savedTunnel(in: paths.runDir + "/" + d) {
                    if !undo(t, others: []) {
                        kept.insert(d)
                        keptRuns.insert(paths.runDir + "/" + d)   // tried again while the helper runs
                    }
                    continue
                }
                // openvpn without root wrote that log: never a reason to change anything.
                if system.fileInfo(paths.runDir + "/" + d + "/sock") != nil { continue }
                if !cleanUp(after: facts(in: paths.runDir + "/" + d), others: [], dir: paths.runDir + "/" + d) {
                    kept.insert(d)
                    keptRuns.insert(paths.runDir + "/" + d)   // tried again while the helper runs
                }
            }
        }
        // Their logs kept (they say why a tunnel died with the helper), or the folder stays.
        for d in leftovers where !kept.contains(d) && !salvageLog(paths.runDir + "/" + d) {
            kept.insert(d)
            keptRuns.insert(paths.runDir + "/" + d)   // its log tried again while the helper runs
        }
        retryDNSLeftNow()
        retryDNSLeftLater()
        if kept.isEmpty {
            system.remove(paths.runDir)
            try system.makeDirectory(paths.runDir, mode: 0o711)
        } else {
            for d in leftovers where !kept.contains(d) { system.remove(paths.runDir + "/" + d) }
        }
        try? system.makeDirectory(paths.logsDir, mode: 0o755)
        // Whatever a previous helper left in PF is replaced: its blocks, or nothing.
        loadLocks()
        appliedPF = "\u{0}"
        refreshProtection()
        // An uninstall held back by DNS left (the app went to the Trash): done now if that is off.
        if uninstallWhenDNSOff != nil { retryDNSLeft() }
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
        // The block its drop left stays while it connects again: lifted once it takes all traffic
        // (refreshProtection), not before (a start that fails would leave the user unprotected).
        let r = try launch(bundle, owner: uid, management: ["--management-client-user", user], persistent: false)
        connections[r.id]?.protection = bundle.protection
        // Started to replace a tunnel whose drop fired its block: it lifts that block once up.
        let lockName = HelperCore.lockKey(name: bundle.name, profileID: bundle.profileID)
        // (A block an older version left is keyed by the name alone.)
        let legacy = HelperCore.lockName(bundle.name)
        connections[r.id]?.liftsBlock = locks.contains { ($0.name == lockName || $0.name == legacy) && $0.owner == uid && !$0.armed && !$0.everyone }
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
        // Before anything is made or started: a refusal leaves nothing behind.
        guard bundle.profileID.map({ $0.utf8.count <= 1024 && !$0.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) }) ?? true else {
            throw HelperCoreError.message("profile id: not one")
        }
        guard bundle.dnsDomains.count <= ProfileBundle.maxDNSDomains else {
            throw HelperCoreError.message("DNS domains: at most \(ProfileBundle.maxDNSDomains)")
        }
        guard bundle.dnsDomains.allSatisfy(TunnelState.isDomain) else {
            throw HelperCoreError.message("DNS domains: not domain names")
        }
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
            /// Readable by openvpn's account (its group), by nobody else; not set: not started.
            func forOpenVPN(_ path: String) throws {
                if let user, !system.setOwner(path, uid: 0, gid: user.gid, mode: 0o640) {
                    throw HelperCoreError.message("the helper could not set who may read \((path as NSString).lastPathComponent)")
                }
            }
            for (i, key) in checked.files.enumerated() {
                let f = dir + "/" + ProfilePolicy.runName(forIndex: i)
                try system.writeFile(f, bundle.files[key] ?? Data(), mode: 0o600)
                try forOpenVPN(f)
            }
            try system.writeFile(config, Data(ConfigParser.serializeForOpenVPN(checked.directives).utf8), mode: 0o600)
            try forOpenVPN(config)
            if let user {
                // openvpn creates its management socket here: the one place it may write.
                try system.makeDirectory(dir + "/sock", mode: 0o711)
                // A persistent tunnel's socket: its administrators' (the app attaches), nobody else's.
                // Not set as asked (a persistent socket's folder open to others): not started.
                guard system.setOwner(dir + "/sock", uid: user.uid, gid: persistent ? adminGID : user.gid,
                                      mode: persistent ? 0o750 : 0o711) else {
                    throw HelperCoreError.message("the helper could not set who may reach the management socket")
                }
            }
            var password: String?
            if persistent {
                password = newSecret()
                try system.writeFile(dir + "/m.pw", Data((password! + "\n").utf8), mode: 0o600)
                try forOpenVPN(dir + "/m.pw")
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
            var info = ConnectionInfo(id: id, name: bundle.name, pid: process.pid, managementSocket: socket, ownerUID: uid,
                                      persistent: persistent)
            info.profileID = persistent ? nil : bundle.profileID
            let c = Connection(info: info, process: process, dir: dir)
            if !persistent {
                c.tunnel.profileName = bundle.name
                c.tunnel.profileID = bundle.profileID
                c.tunnel.ownerUID = uid
                c.tunnel.appendLog = bundle.appendLog
            }
            c.startedAt = system.now()
            c.serviceID = user?.uid
            c.splitDNS = bundle.splitDNS
            c.dnsDomains = bundle.dnsDomains
            c.appendLog = bundle.appendLog
            c.mayRouteAll = limit.mayRouteAll
            c.mayChangeDNS = limit.mayChangeDNS
            c.allowed = limit.allowed
            c.restricted = limit.restricted
            connections[id] = c
            // From the start: after a crash, this run is undone from the record, never from
            // the log (an unprivileged openvpn writes that).
            try saveTunnel(c)
            passwords[id] = password
            // Its owner could not read it (View Log would fail for no reason given): not started, said.
            guard giveLog(dir + "/openvpn.log", to: info) else {
                throw HelperCoreError.message("the helper could not let you read this connection's log")
            }
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
        // The sign-ins the app does (it opens a server's page, answers a challenge's text): servers that defer a
        // password to them refuse a client that does not say so.
        args += ["--setenv", "IV_SSO", "openurl,webauth,crtext"]
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
                if let c = connections[i.id] {
                    if c.dnsWantsAll != nil { i.dns = c.tunnel.dnsApplied ? "limited" : "waiting" }
                    else if c.tunnel.dnsApplied { i.dns = c.tunnel.dnsDomains.isEmpty ? "all" : "split" }
                    if admin || c.info.ownerUID == uid, c.tunnel.dnsApplied, !c.tunnel.dnsDomains.isEmpty { i.dnsDomains = c.tunnel.dnsDomains }
                }
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
        let name = HelperCore.lockKey(c.info)
        syncArming()
        let tookAll = c.tunnel.takesAllTraffic
        if let id = c.serviceID { system.killProcesses(uids: id...id) }
        var recorded = true
        do {
            let others = connections.values.filter { $0 !== c }.map(\.tunnel)
            recorded = undo(c.tunnel, others: others)
            release(c.tunnel, others: others)
        }
        if c.protection.killSwitch, !c.stopping, c.wasFull || tookAll {
            // Dropped without being asked to: keep its owner's traffic from going around the tunnel.
            addLock(Lock(name: name, owner: c.info.ownerUID, allowLAN: c.protection.allowLAN, everyone: c.info.persistent))
        }
        // It had all names: the next in line gets them.
        if c.tunnel.dnsApplied && c.tunnel.dnsDomains.isEmpty { reassignAllNames() }
        if c.info.persistent, !c.stopping, !closing {
            // Ended unasked: started again, after a wait that grows (a tunnel up a long time starts the count again).
            let n = system.now() - c.startedAt > 120 ? 0 : persistentRestarts[c.info.name] ?? 0
            persistentRestarts[c.info.name] = n + 1
            let wait = min(HelperCore.persistentRestartMax, 5 * pow(2, Double(min(n, 16))))
            let pname = c.info.name
            system.after(wait) { [weak self] in _ = try? self?.startPersistent(name: pname, uid: 0) }
        }
        saveLocks()
        let kept = paths.logsDir + "/" + ProfileKey.logName(profile: c.info.name, id: c.info.profileID, uid: c.info.ownerUID) + ".log"
        // (Not all done: its run folder stays, tried again.)
        let info = c.info
        if !keepLog(of: c.dir, at: kept, append: c.appendLog, own: { giveLog(kept, to: info, live: false) }) { c.keepRecord = true }
        // Bounded per user: names are the user's to choose.
        // The oldest go (by when they were written).
        let mine = system.list(paths.logsDir).filter { $0.hasSuffix(".\(c.info.ownerUID).log") && paths.logsDir + "/" + $0 != kept }
            .sorted { (system.fileInfo(paths.logsDir + "/" + $0)?.modified ?? 0) < (system.fileInfo(paths.logsDir + "/" + $1)?.modified ?? 0) }
        for old in mine.dropLast(max(0, HelperCore.keptLogsPerUser - 1)) { system.remove(paths.logsDir + "/" + old) }
        // DNS left behind and not on record elsewhere: its own record stays for the next helper.
        if recorded, !c.keepRecord { system.remove(c.dir) }
        // Still there (kept on purpose, or its removal refused): tried again.
        if system.fileInfo(c.dir) != nil {
            // Something of it still to undo (a route still there, DNS on record nowhere else): tried again.
            keptRuns.insert(c.dir)
            retryDNSLeftLater()
        }
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
        reassignAfterRequest = false
        handedOver = nil
        /// All names another tunnel gave up for this request: back to it once this request's own DNS is undone.
        func giveBackHandedOver() {
            guard let y = handedOver else { return }
            handedOver = nil
            giveBackAllNames(y.owner, y.all, y.record)
        }
        let others = connections.values.filter { $0 !== c }.map(\.tunnel)
        // All or nothing: a refused or failed request leaves the records as they were.
        var before = c.tunnel
        let wasFullBefore = c.wasFull
        let dnsBefore = c.appliedDNS
        let queueBefore = (c.dnsWantsAll, c.dnsAskOrder)
        /// Its DNS on the Mac as before the request (the new one off, the old one back); the record
        /// says what is set whatever could not be.
        /// - on: the tunnel as it is on the Mac after the rollback (its routes back, or not).
        func putDNSBack(on topology: TunnelState) {
            if c.appliedDNS != dnsBefore {
                // Not back where it would no longer pass on the tunnel as it now is.
                let back = dnsBefore.flatMap { system.interfaceExists($0.device) && (try? checkDNS(c, $0, policy: "", on: topology)) != nil ? $0 : nil }
                replaceDNS(c, with: back)
            }
            before.dnsBackupLeft = c.tunnel.dnsBackupLeft ?? before.dnsBackupLeft
            before.dnsApplied = c.appliedDNS != nil
            before.dnsServers = c.appliedDNS?.servers ?? []
            before.dnsDomains = c.appliedDNS?.matchDomains ?? []
        }
        do {
            try carryOut(c, kind, message, others: others, reply: &reply)
        } catch {
            // Nothing done: the record (written ahead) says so again; if it cannot, the
            // connection is undone and stopped rather than left with a record of the future.
            // A route it took away that would not come back: its DNS is not put back (its server may now be reached
            // around the tunnel), it is taken off; the connection is undone below.
            if c.mustFailClosed {
                replaceDNS(c, with: nil)
                before.dnsBackupLeft = c.tunnel.dnsBackupLeft ?? before.dnsBackupLeft
                before.dnsApplied = c.appliedDNS != nil
                before.dnsServers = c.appliedDNS?.servers ?? []
                before.dnsDomains = c.appliedDNS?.matchDomains ?? []
            } else {
                putDNSBack(on: before)
            }
            c.tunnel = before
            // Routes it added that would not go back (or took away that would not come back): on record, and the
            // connection undone with them.
            if !c.stuckRoutes.isEmpty || c.mustFailClosed {
                c.mustFailClosed = false
                c.tunnel.keep(c.stuckRoutes)
                c.stuckRoutes = []
                // On disk as it now is (what stays to undo), before it is undone.
                try? saveTunnel(c)
                failClosed(c)
                throw error
            }
            // Asked for all names while another has them: in line for them (that is the answer, not a failure).
            if !(error is DNSWaiting) { (c.dnsWantsAll, c.dnsAskOrder) = queueBefore }
            do { try saveTunnel(c) } catch { failClosed(c) }
            giveBackHandedOver()
            if let e = error as? TunnelRequestError { throw HelperCoreError.message(e.description) }
            if let e = error as? DNSWaiting { throw HelperCoreError.message(e.description) }
            throw error
        }
        /// Take back what this request did.
        func undoRequest() {
            // Its new routes go, and those it took away (ROUTEDEL) come back, as the record says; one that cannot
            // leaves the record wrong (DNS checks trust it), so the connection is undone and stopped instead.
            var routesBack = true
            var stuck: [TunnelRoute] = []
            for r in c.tunnel.cleanup() where !before.cleanup().contains(r) && !remove(r, others: others) { stuck.append(r) }
            if !stuck.isEmpty { routesBack = false }
            for r in before.cleanup() where !c.tunnel.cleanup().contains(r) && !system.routeExists(r) {
                if !system.runNetwork(r.add) { routesBack = false }
            }
            if let dev = c.tunnel.device, dev == before.device {
                if let a = c.tunnel.local, a != before.local { _ = system.runNetwork(["ifconfig", dev, "inet", TunnelState.text(a), "delete"]) }
                if let n6 = c.tunnel.net6, n6 != before.net6, let a6 = n6.split(separator: "/").first {
                    _ = system.runNetwork(["ifconfig", dev, "inet6", String(a6), "delete"])
                }
            }
            putDNSBack(on: routesBack ? before : c.tunnel)
            (c.dnsWantsAll, c.dnsAskOrder) = queueBefore
            giveBackHandedOver()
            if let dev = c.tunnel.device, dev != before.device {
                takeDown(c.tunnel)
                system.releaseDevice(dev)
            }
            if let fd = reply.fd { system.closeDescriptor(fd) }
            c.tunnel = before
            // Its new routes that would not go stay on record (undone with the connection).
            c.tunnel.keep(stuck)
            // Undone but not recorded: a record of what is no longer there is not kept running.
            do { try saveTunnel(c) } catch { return failClosed(c) }
            if !routesBack { failClosed(c) }
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
        // Done: what another tunnel gave up stays given.
        handedOver = nil
        // Recorded: all names it let go of go to the next in line now.
        if reassignAfterRequest {
            reassignAfterRequest = false
            reassignAllNames()
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
                    let heldAll = c.tunnel.dnsDomains.isEmpty
                    guard replaceDNS(c, with: nil) else {
                        system.releaseDevice(name)
                        system.closeDescriptor(fd)
                        throw HelperCoreError.message("the DNS it had could not be taken off")
                    }
                    c.tunnel.dnsApplied = false
                    c.tunnel.clearDNS()
                    // All names free while it reconnects: the next in line gets them (its own DNSUP may not come).
                    if heldAll { reassignAfterRequest = true }
                }
                // Into the old utun: gone with it, unless it is the same one again (then still on record if they stay).
                let dropped = c.tunnel.dropDevice(old)
                let stayed = dropped.filter { !remove($0, others: others) }
                if old == name { c.tunnel.keep(stayed) }
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
            try checked { try NetworkPolicy.checkAddresses(c.tunnel, owner: c.info.ownerUID, others: otherConnections(than: c), lan4: lan4) }
            // Its DNS server may not be inside the new network: off before the change.
            try dropDNSNoLongerAllowed(c)
            guard let first = cmds.first, system.runNetwork(first) else { throw HelperCoreError.message("ifconfig failed") }
            // The route to its own network: not essential (it may exist already, as a LAN of the same range).
            // Not when it lies in another user's networks (as narrow or narrower, it would take their traffic).
            if cmds.count > 1, let dev = c.tunnel.device, let net = c.tunnel.subnet,
               NetworkPolicy.subnetRouteAllowed(net, owner: c.info.ownerUID, others: otherConnections(than: c)), system.runNetwork(cmds[1]) {
                c.tunnel.subnetRoute = TunnelRoute(kind: .tunnel, net: TunnelState.text(net.address),
                                                   mask: TunnelState.text(net.mask), via: dev)
            }
        case "IFCONFIG6":
            let cmds = try c.tunnel.ifconfig6(message)
            if let mine = c.tunnel.net6 {
                try checked { try NetworkPolicy.checkNetwork6(mine, limits: c.limits, others: otherConnections(than: c),
                                                             lan6: system.localIPv6Networks(), message: message) }
            }
            try runAll(cmds)
        case "ROUTE":
            let added = try c.tunnel.route(message, gateway: system.defaultGateway())
            try checked { try NetworkPolicy.checkRoutes(added, tunnel: c.tunnel, owner: c.info.ownerUID, limits: c.limits,
                                                       others: otherConnections(than: c), lan4: lan4, message: message) }
            // A host route around the tunnel may take its DNS server with it: off before the change.
            try dropDNSNoLongerAllowed(c)
            // On disk before the change: after a crash the helper knows what it may have done.
            try record(c)
            for (i, r) in added.enumerated() where !system.runNetwork(r.add) {
                // Already there from another of our connections (the same server): shared.
                if !r.intoTunnel, others.contains(where: { $0.routes.contains(r) }) { continue }
                // Those added just now taken back; one that stays keeps its record and the connection is undone.
                let stuck = added.prefix(i).filter { !system.runNetwork($0.delete) && system.routeExists($0) }
                if !stuck.isEmpty { c.stuckRoutes = Array(stuck) }
                throw HelperCoreError.message("route failed")
            }
        case "ROUTE6":
            let r = try c.tunnel.route6(message)
            try checked { try NetworkPolicy.checkRoute6(r, owner: c.info.ownerUID, limits: c.limits, others: otherConnections(than: c),
                                                       lan6: system.localIPv6Networks(), message: message) }
            try record(c)
            if !system.runNetwork(r.add) { throw HelperCoreError.message("route failed") }
        case "ROUTEDEL":
            let deleted = try c.tunnel.deleteRoute(message, gateway: system.defaultGateway())
            // (The record goes back with the request's if this fails.)
            // Its DNS server may have been inside the tunnel only through that route: off before it goes.
            try dropDNSNoLongerAllowed(c)
            for (i, r) in deleted.enumerated() where !remove(r, others: others) {
                // Still there: refused, as recorded (the ones already gone put back). One that will not come back
                // leaves the record wrong (its DNS may go around the tunnel): the connection is undone.
                if deleted.prefix(i).contains(where: { !system.runNetwork($0.add) && !system.routeExists($0) }) { c.mustFailClosed = true }
                throw HelperCoreError.message("route delete failed")
            }
        case "ROUTE6DEL":
            // Still there: refused, as recorded.
            guard remove(try c.tunnel.deleteRoute6(message), others: others) else { throw HelperCoreError.message("route delete failed") }
        case "DNSVAR": try c.tunnel.dnsVar(message)
        case "DNSUP":
            let t = system.now()
            if let last = c.lastDNSUp, t - last < 1 { throw HelperCoreError.message("DNS changed too soon again") }
            c.lastDNSUp = t
            var plan = try c.tunnel.dnsPlan(device: message, splitMarker: c.splitDNS)
            // The user's own list of domains for the server's DNS: split on those.
            if !c.dnsDomains.isEmpty {
                plan = DNSPlan(device: plan.device, servers: plan.servers, matchDomains: c.dnsDomains,
                               searchDomains: plan.searchDomains, split: true)
            }
            try checkDNS(c, plan, policy: policy)
            let heldAll = c.tunnel.dnsApplied && c.tunnel.dnsDomains.isEmpty
            // All names asked by a tunnel with no domains of its own, held by one of the same user's that has its
            // server's: that one goes to those domains (in line for all names again), this one gets all names, so
            // that the order of connecting does not decide. Refused at any step: as it was, this one in line.
            // (Part of this request: undone with it, whatever undoes it.)
            if !plan.split, plan.searchDomains.isEmpty,
               let owner = connections.values.first(where: { $0 !== c && !$0.exited && $0.tunnel.dnsApplied && $0.tunnel.dnsDomains.isEmpty }) {
                handedOver = yieldAllNames(owner, to: c)
            }
            // All names are one tunnel's at a time. Asked while another has them: its own domains, split, if
            // it has some, or nothing yet; either way it is next in line when the owner lets go (not the
            // order of connecting).
            c.dnsWantsAll = nil
            if !plan.split, connections.values.contains(where: { $0 !== c && !$0.exited && $0.tunnel.dnsApplied && $0.tunnel.dnsDomains.isEmpty }) {
                c.dnsWantsAll = plan
                dnsAsks += 1
                c.dnsAskOrder = dnsAsks
                guard !plan.searchDomains.isEmpty else { throw DNSWaiting() }
                plan = DNSPlan(device: plan.device, servers: plan.servers, matchDomains: plan.searchDomains,
                               searchDomains: plan.searchDomains, split: true)
            }
            // A domain another user's tunnel answers for, or a part of it: the more specific one wins.
            if let d = NetworkPolicy.domainAnsweredByAnotherUser(plan.matchDomains, owner: c.info.ownerUID, others: otherConnections(than: c)) {
                throw HelperCoreError.message("DNS for \(d): another user's tunnel answers for it")
            }
            c.tunnel.dnsApplied = true
            c.tunnel.dnsDomains = plan.matchDomains
            c.tunnel.dnsServers = plan.servers
            try record(c)
            guard replaceDNS(c, with: plan) else { throw HelperCoreError.message("DNS not set") }
            // All names it had, now split: free for the next in line.
            if heldAll, plan.split { reassignAfterRequest = true }
        case "DNSDOWN":
            let heldAll = c.tunnel.dnsApplied && c.tunnel.dnsDomains.isEmpty
            guard replaceDNS(c, with: nil) else { throw HelperCoreError.message("the DNS it had could not be taken off") }
            c.tunnel.dnsApplied = false
            c.tunnel.clearDNS()
            c.dnsWantsAll = nil
            if heldAll { reassignAfterRequest = true }
        default:
            throw HelperCoreError.message("unknown request \(kind)")
        }
    }


    /// A request freed all names: handed on once its own change is recorded (not before: a rollback
    /// of it must not leave two owners).
    private var reassignAfterRequest = false
    /// All names another tunnel gave up during the request being carried out.
    private var handedOver: (owner: Connection, all: DNSPlan, record: TunnelState)?
    /// Asked for all names while another tunnel has them: in line (the request's answer, not a failure).
    private struct DNSWaiting: Error, CustomStringConvertible {
        var description: String { "DNS for all names is already another tunnel's" }
    }
    /// The connection's DNS on the Mac made `plan` (nil: none of its own): the old one taken off first
    /// (split and all names are different keys), then the new one set; refused, the old one back.
    /// `appliedDNS` says what is set afterwards, whatever happened.
    @discardableResult private func replaceDNS(_ c: Connection, with plan: DNSPlan?) -> Bool {
        let old = c.appliedDNS
        if plan == old { return true }
        if let old {
            switch system.restoreDNS(device: old.device) {
            case .failed: return false
            // Off, its backup left: on record (dns-left, or else the tunnel's own record).
            case .backupLeft: if !leaveDNS(old.device, .backup) { c.tunnel.dnsBackupLeft = old.device }
            case .done: break
            }
            c.appliedDNS = nil
        }
        guard let plan else { return true }
        let result = system.setDNS(plan)
        guard result == .set else {
            // A backup made for it left behind: on record (dns-left, or else the tunnel's own record).
            if result == .failedBackupLeft, !leaveDNS(plan.device, .backup) { c.tunnel.dnsBackupLeft = plan.device }
            if let old, system.setDNS(old) == .set {
                c.appliedDNS = old
                if !old.split { adoptBackup(c, old.device) }
            }
            return false
        }
        c.appliedDNS = plan
        if !plan.split { adoptBackup(c, plan.device) }
        return true
    }

    /// All names set again on a device whose backup was left: that backup is this DNS's own again (what to
    /// put back when it ends), no longer one to remove.
    private func adoptBackup(_ c: Connection, _ dev: String) {
        if c.tunnel.dnsBackupLeft == dev { c.tunnel.dnsBackupLeft = nil }
        if dnsLeft[dev] == .backup {
            dnsLeft[dev] = nil
            saveDNSLeft()
        }
    }

    /// Its tunnel changed (a route gone): DNS that no longer passes the checks is taken off (a standard user's
    /// server would be reached outside the tunnel), and a request in line for all names dropped.
    private func dropDNSNoLongerAllowed(_ c: Connection) throws {
        if let w = c.dnsWantsAll, (try? checkDNS(c, w, policy: "")) == nil { c.dnsWantsAll = nil }
        guard let p = c.appliedDNS, (try? checkDNS(c, p, policy: "")) == nil else { return }
        // Off first, then recorded so (a record of DNS set that is not is undone harmlessly after a crash;
        // one of DNS off that is not would be left).
        guard replaceDNS(c, with: nil) else {
            throw HelperCoreError.message("its DNS server would be outside the tunnel, and its DNS could not be taken off")
        }
        c.tunnel.dnsApplied = false
        c.tunnel.dnsDomains = []
        c.tunnel.dnsServers = []
        if !p.split { reassignAfterRequest = true }
    }

    /// May `c` have `plan` set now (asked for, or its turn come): the policy, and a standard user's
    /// servers inside its own tunnel as it is now.
    private func checkDNS(_ c: Connection, _ plan: DNSPlan, policy _: String, on topology: TunnelState? = nil) throws {
        try checked {
            try NetworkPolicy.checkDNS(plan, tunnel: topology ?? c.tunnel, limits: c.limits, lan4: lan4,
                                       systemResolvers: { self.system.systemDNSServers(excluding: plan.device) })
        }
    }

    /// `owner` (all names) to the domains its server gave, for `to` that has none: only between one user's own
    /// tunnels (never another user's, nor a persistent one), with what passes the checks (a standard user's: as
    /// the administrator's policy lets it). Its
    /// record first, the Mac after; nil (nothing changed) when any of it is refused.
    private func yieldAllNames(_ owner: Connection, to c: Connection) -> (owner: Connection, all: DNSPlan, record: TunnelState)? {
        guard owner.info.ownerUID == c.info.ownerUID, !owner.info.persistent, !c.info.persistent,
              let all = owner.appliedDNS, !all.split, !all.searchDomains.isEmpty, owner.dnsDomains.isEmpty else { return nil }
        let split = DNSPlan(device: all.device, servers: all.servers, matchDomains: all.searchDomains,
                            searchDomains: all.searchDomains, split: true)
        guard (try? checkDNS(owner, split, policy: "")) != nil else { return nil }
        // Domains another user's tunnel answers for stay theirs.
        guard !answeredByAnotherUser(owner, split.matchDomains) else { return nil }
        let record = owner.tunnel
        owner.tunnel.dnsDomains = split.matchDomains
        owner.tunnel.dnsServers = split.servers
        guard (try? saveTunnel(owner)) != nil else { owner.tunnel = record; return nil }
        guard replaceDNS(owner, with: split) else {
            // Refused: what is set now (its all names put back, or none) on record.
            owner.tunnel = record
            owner.tunnel.dnsApplied = owner.appliedDNS != nil
            owner.tunnel.dnsServers = owner.appliedDNS?.servers ?? []
            owner.tunnel.dnsDomains = owner.appliedDNS?.matchDomains ?? []
            // Not even its all names back: no DNS of its own, its domains would go to whoever has all names (another
            // tunnel's servers): undone and stopped instead.
            if (try? saveTunnel(owner)) == nil || owner.appliedDNS == nil { failClosed(owner) }
            return nil
        }
        owner.dnsWantsAll = all
        dnsAsks += 1
        owner.dnsAskOrder = dnsAsks
        return (owner, all, record)
    }

    /// The tunnel that gave up all names for one that did not get them: all names back (its record first).
    /// Refused: its split stays (in line); a record that cannot say what is set: failed closed.
    private func giveBackAllNames(_ owner: Connection, _ all: DNSPlan, _ record: TunnelState) {
        guard !owner.exited, owner.appliedDNS?.split == true, owner.tunnel.device == all.device else { return }
        let split = owner.tunnel
        owner.tunnel.dnsDomains = record.dnsDomains
        owner.tunnel.dnsServers = record.dnsServers
        // Its record not written: its split stays (as on record), in line, tried again.
        guard (try? saveTunnel(owner)) != nil else { owner.tunnel = split; return reassignLater() }
        if replaceDNS(owner, with: all) {
            owner.dnsWantsAll = nil
            return
        }
        owner.tunnel.dnsApplied = owner.appliedDNS != nil
        owner.tunnel.dnsServers = owner.appliedDNS?.servers ?? []
        owner.tunnel.dnsDomains = owner.appliedDNS?.matchDomains ?? []
        // Neither its all names nor its split: no DNS of its own (its domains would go astray): stopped.
        if (try? saveTunnel(owner)) == nil || owner.appliedDNS == nil { return failClosed(owner) }
        reassignLater()
    }

    /// One of `domains`, or a part of one, another user's tunnel answers for (the more specific one wins).
    private func answeredByAnotherUser(_ c: Connection, _ domains: [String]) -> Bool {
        NetworkPolicy.domainAnsweredByAnotherUser(domains, owner: c.info.ownerUID, others: otherConnections(than: c)) != nil
    }

    private var reassignPending = false
    /// No tunnel has all names while one is in line for them (a hand-over or its undoing refused): tried again
    /// later, until one has them or none waits.
    private func reassignLater() {
        guard !reassignPending else { return }
        reassignPending = true
        system.after(HelperCore.dnsLeftRetry) { [weak self] in
            guard let self else { return }
            self.reassignPending = false
            self.reassignAllNames()
            let held = self.connections.values.contains { !$0.exited && $0.tunnel.dnsApplied && $0.tunnel.dnsDomains.isEmpty }
            if !held, self.connections.values.contains(where: { !$0.exited && $0.dnsWantsAll != nil }) { self.reassignLater() }
        }
    }

    private var dnsAsks = 0
    /// DNS for all names free again: to the tunnel that has asked for them longest (its split DNS, if it
    /// had its own domains meanwhile, taken off first).
    private func reassignAllNames() {
        guard !connections.values.contains(where: { !$0.exited && $0.tunnel.dnsApplied && $0.tunnel.dnsDomains.isEmpty }),
              !dnsLeftHoldsAllNames, !connections.values.contains(where: { $0.tunnel.dnsBackupLeft != nil }) else { return }
        // Those with nothing (no domains of their own) before those that have their domains meanwhile; then who
        // asked first.
        let next = NetworkPolicy.allNamesOrder(connections.values.filter { !$0.exited && $0.tunnel.device != nil }
            .compactMap { c in c.dnsWantsAll.map { (item: c, plan: $0, order: c.dnsAskOrder) } })
        for c in next {
            guard let plan = c.dnsWantsAll, plan.device == c.tunnel.device else { continue }
            // Asked a while ago: the checks again, on its tunnel as it is now.
            guard (try? checkDNS(c, plan, policy: "")) != nil else { c.dnsWantsAll = nil; continue }
            let before = c.tunnel
            // The record first (what a helper that dies meanwhile undoes), the system after.
            c.tunnel.dnsApplied = true
            c.tunnel.dnsDomains = []
            c.tunnel.dnsServers = plan.servers
            do { try saveTunnel(c) } catch { c.tunnel = before; continue }
            guard replaceDNS(c, with: plan) else {
                // Refused: its split DNS back (or, if that cannot be, none), and the record with it.
                c.tunnel = before
                c.tunnel.dnsApplied = c.appliedDNS != nil
                c.tunnel.dnsServers = c.appliedDNS?.servers ?? []
                c.tunnel.dnsDomains = c.appliedDNS?.matchDomains ?? []
                if (try? saveTunnel(c)) == nil { failClosed(c) }
                continue
            }
            c.dnsWantsAll = nil
            refreshProtection()
            return
        }
        // In line, none could have them now: tried again.
        if next.contains(where: { $0.dnsWantsAll != nil }) { reassignLater() }
    }


    /// Take a route away: only while it is there as added, not while another connection shares
    /// it, and never on a device that is another connection's now.
    /// - Returns: false when it is still there (its record must stay).
    @discardableResult private func remove(_ r: TunnelRoute, others: [TunnelState]) -> Bool {
        if !r.intoTunnel, others.contains(where: { $0.routes.contains(r) }) { return true }
        if r.intoTunnel, others.contains(where: { $0.device == r.via }) { return true }
        guard system.routeExists(r) else { return true }
        return system.runNetwork(r.delete) || !system.routeExists(r)
    }

    /// At once, not after openvpn's grace: its routes, DNS and addresses go, then openvpn.
    /// Not asked for by its owner: a kill switch it armed fires (and stays on disk).
    private func failClosed(_ c: Connection) {
        let others = connections.values.filter { $0 !== c }.map(\.tunnel)
        if c.protection.killSwitch, c.wasFull || c.tunnel.takesAllTraffic {
            addLock(Lock(name: HelperCore.lockKey(c.info), owner: c.info.ownerUID, allowLAN: c.protection.allowLAN,
                         everyone: c.info.persistent))
            saveLocks()
        }
        let recorded = undo(c.tunnel, others: others)
        release(c.tunnel, others: others)
        if recorded {
            c.tunnel = TunnelState()
            try? saveTunnel(c)
        } else {
            c.keepRecord = true
        }
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
    /// The other connections, as the planner's rules see them.
    private func otherConnections(than c: Connection) -> [OtherConnection] {
        connections.values.filter { $0 !== c }.map { OtherConnection(owner: $0.info.ownerUID, exited: $0.exited, tunnel: $0.tunnel) }
    }

    /// A planner rule's refusal, as the helper's.
    private func checked(_ check: () throws -> Void) throws {
        do { try check() } catch let r as PolicyRefusal { throw HelperCoreError.message(r.description) }
    }

    private var lan4: [IPv4Net] { system.localIPv4Networks().compactMap(HelperCore.ipv4Net) }

    private func runAll(_ cmds: [[String]]) throws {
        for cmd in cmds where !system.runNetwork(cmd) { throw HelperCoreError.message("\(cmd.first ?? "") failed") }
    }

    /// Take away what the helper set up for a tunnel that is gone: only routes still there
    /// as added (those into a closed utun went with it), none another connection shares.
    /// DNS that could not be taken off is put on record (tried again; all names not handed on meanwhile).
    /// - Returns: false when that record could not be written (the tunnel's own record is then kept).
    @discardableResult private func undo(_ t: TunnelState, others: [TunnelState]) -> Bool {
        // A route still there keeps the record (tried again).
        var recorded = t.cleanup().map { remove($0, others: others) }.allSatisfy { $0 }
        // A utun a live connection has again, with DNS of its own: its keys are that one's now (its end takes them off).
        // (By `others`: never the tunnel being undone itself.)
        let reused = t.device.map { dev in others.contains { $0.device == dev && $0.dnsApplied } } ?? false
        // Its DNS first (a backup it still uses is what that puts back), then a backup left on its own.
        if t.dnsApplied, !reused, let dev = t.device {
            switch system.restoreDNS(device: dev) {
            case .done: break
            case .backupLeft: recorded = leaveDNS(dev, .backup) && recorded
            case .failed: recorded = leaveDNS(dev, t.dnsDomains.isEmpty ? .all : .split) && recorded
            }
        }
        // Never the backup of all names set on that device: it is theirs (put back by restoring them, done
        // or still to do), whatever the restore did.
        let usedByItsDNS = t.dnsApplied && t.dnsDomains.isEmpty && t.device == t.dnsBackupLeft
        // Nor a backup on a utun another live tunnel has DNS on: its own then.
        let backupReused = t.dnsBackupLeft.map { dev in others.contains { $0.device == dev && $0.dnsApplied } } ?? false
        if let dev = t.dnsBackupLeft, !usedByItsDNS, !backupReused, !system.removeDNSBackup(device: dev) {
            recorded = leaveDNS(dev, .backup) && recorded
        }
        return recorded
    }

    /// What of a gone tunnel's DNS is left: its resolver, the primary's DNS for all names, or only the
    /// backup of the primary's DNS (it holds all names back).
    enum DNSLeft: String, Codable { case split, all, backup }
    /// By device. On record, so a new helper tries too; tried again meanwhile.
    private var dnsLeft: [String: DNSLeft] = [:]
    private var dnsLeftPath: String { paths.supportDir + "/dns-left.json" }
    private var dnsLeftRetryPending = false
    /// An older version's run whose routes are not all gone yet (more than one pass takes, or refused): those left.
    private var legacyRemaining: [String: Set<[String]>] = [:]
    /// dns-left.json not as it should be (an emptied one not removed): written again with the retries.
    private var dnsLeftUnsaved = false
    /// Run directories of gone tunnels kept because something of theirs is not undone yet (their record says what).
    private var keptRuns: Set<String> = []
    static let dnsLeftRetry: TimeInterval = 30
    /// All names held back while some may be left.
    private var dnsLeftHoldsAllNames: Bool { dnsLeft.values.contains { $0 != .split } }

    @discardableResult private func leaveDNS(_ dev: String, _ what: DNSLeft) -> Bool {
        // The more there is to undo wins (all names over a backup over a resolver).
        let rank: [DNSLeft: Int] = [.split: 0, .backup: 1, .all: 2]
        if let had = dnsLeft[dev], rank[had]! > rank[what]! {} else { dnsLeft[dev] = what }
        retryDNSLeftLater()
        return saveDNSLeft()
    }

    @discardableResult private func saveDNSLeft() -> Bool {
        if dnsLeft.isEmpty {
            system.remove(dnsLeftPath)
            // A record that stays would be acted on again by the next helper: written again later.
            dnsLeftUnsaved = system.fileInfo(dnsLeftPath) != nil
            return !dnsLeftUnsaved
        }
        guard let d = try? JSONEncoder().encode(dnsLeft), (try? system.writeFile(dnsLeftPath, d, mode: 0o600)) != nil else { return false }
        return true
    }

    private func loadDNSLeft() {
        guard let info = system.fileInfo(dnsLeftPath), info.kind == .regular, info.rootOnly, let d = system.readFile(dnsLeftPath),
              let left = try? JSONDecoder().decode([String: DNSLeft].self, from: d) else { return }
        // Device names only: what is read is used in store keys.
        for (dev, what) in left.prefix(64) where dev.hasPrefix("utun") && dev.count > 4 && dev.dropFirst(4).allSatisfy(\.isNumber) {
            dnsLeft[dev] = what
        }
    }

    /// A log still in a run folder about to go (it could not be kept when its tunnel ended): kept as
    /// recovered-<run>.log. - Returns: false when it is still there only.
    /// A dead run's log (its tunnel died with a helper, or its log could not be kept when it ended), kept as its
    /// profile's (its user's; View Log finds it) or, whose not known, recovered-<run>.log for administrators.
    private func salvageLog(_ dir: String) -> Bool {
        let t = savedTunnel(in: dir)
        let to: String
        if let name = t?.profileName, let owner = t?.ownerUID {
            to = paths.logsDir + "/" + ProfileKey.logName(profile: name, id: t?.profileID, uid: owner) + ".log"
        } else {
            to = paths.logsDir + "/recovered-" + (dir as NSString).lastPathComponent + ".log"
        }
        return keepLog(of: dir, at: to, append: t?.appendLog == true) {
            t?.ownerUID.map { self.system.setOwner(to, uid: $0, gid: staffGID, mode: 0o600) }
                ?? self.system.setOwner(to, uid: 0, gid: adminGID, mode: 0o640)
        }
    }

    /// A run's log into its kept place, the one way for a tunnel that ended and for one found dead: in steps a stop
    /// between cannot repeat. The whole new log staged in the run's own folder (openvpn.log.new: no other run's),
    /// the run's copy marked moved (openvpn.log.kept), the staged one put in place in one rename, the owner set (`own`).
    /// A later try finishes from the step it finds: never appended twice, never another run's.
    /// - Returns: false when it is not (all) done (the run folder stays, tried again).
    private func keepLog(of dir: String, at to: String, append: Bool, own: () -> Bool) -> Bool {
        let log = dir + "/openvpn.log", moved = dir + "/openvpn.log.kept", staged = dir + "/openvpn.log.new"
        // The phase is what files there are, never what a log says: the copy marked moved with a staged log beside
        // it, not yet in place (built again from what is in place now: another run may have written there since);
        // the copy alone, in place already (only its owner left). The one step that puts it in place is a rename,
        // which removes the staged log at once; a refused rename leaves things as they were, tried again.
        func stageAndPlace(_ raw: Data) -> Bool {
            var text = raw
            if append, system.fileInfo(to) != nil {
                guard let there = system.readTail(to, maxBytes: HelperCore.maxKeptLogBytes) else { return false }
                text = Data((there + raw).suffix(HelperCore.maxKeptLogBytes))
            }
            guard (try? system.writeFile(staged, text, mode: 0o600)) != nil else { return false }
            if system.fileInfo(moved) == nil {
                guard (try? system.replace(log, moved)) != nil else { return false }   // (its place untouched so far)
            }
            return (try? system.replace(staged, to)) != nil
        }
        if system.fileInfo(moved) != nil {
            if system.fileInfo(staged) != nil {
                guard let raw = system.readTail(moved, maxBytes: HelperCore.maxKeptLogBytes), stageAndPlace(raw) else { return false }
            }
        } else {
            guard system.fileInfo(log) != nil else { return true }
            guard let now = system.readTail(log, maxBytes: HelperCore.maxKeptLogBytes), stageAndPlace(now) else { return false }
        }
        guard own() else { return false }
        system.remove(moved)
        return true
    }

    private func retryDNSLeftLater() {
        guard !dnsLeftRetryPending, !dnsLeft.isEmpty || !keptRuns.isEmpty || uninstallPendingUnsaved || uninstallRetryNeeded || dnsLeftUnsaved
        else { return }
        dnsLeftRetryPending = true
        system.after(HelperCore.dnsLeftRetry) { [weak self] in
            self?.dnsLeftRetryPending = false
            self?.retryDNSLeft()
        }
    }

    /// Once, without handing anything on or finishing an uninstall (called from there).
    private func retryDNSLeftNow() {
        let live = connections.values.map(\.tunnel)
        for dir in keptRuns.sorted() {
            if let t = savedTunnel(in: dir) {
                if !undo(t, others: live) { continue }
            } else if system.fileInfo(dir + "/sock") == nil, !cleanUp(after: facts(in: dir), others: [], live: live, dir: dir) {
                continue   // an older version's run, by its log
            }
            guard salvageLog(dir) else { continue }
            system.remove(dir)
            // Off the list only once it is really gone.
            if system.fileInfo(dir) == nil { keptRuns.remove(dir) }
        }
        for c in connections.values {
            // Never under all names set on that device (the backup is theirs then).
            guard let dev = c.tunnel.dnsBackupLeft, c.appliedDNS.map({ $0.split || $0.device != dev }) ?? true,
                  system.removeDNSBackup(device: dev) else { continue }
            c.tunnel.dnsBackupLeft = nil
            try? saveTunnel(c)
        }
        for (dev, what) in dnsLeft where !connections.values.contains(where: { $0.tunnel.device == dev && $0.appliedDNS != nil }) {
            if what == .backup {
                if system.removeDNSBackup(device: dev) { dnsLeft[dev] = nil }
                continue
            }
            switch system.restoreDNS(device: dev) {
            case .done: dnsLeft[dev] = nil
            case .backupLeft: dnsLeft[dev] = .backup
            case .failed: break
            }
        }
        saveDNSLeft()
    }

    private func retryDNSLeft() {
        if uninstallPendingUnsaved { saveUninstallPending() }
        retryDNSLeftNow()
        retryDNSLeftLater()
        reassignAllNames()
        if dnsLeft.isEmpty, let keep = uninstallWhenDNSOff {
            uninstallWhenDNSOff = nil
            try? uninstall(uid: 0, keepProfiles: keep, fromTrash: true) { _ in }
        }
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

    /// A block's key: its profile's name and, for the app's profiles, its id (names repeat). Shown by name.
    static func lockKey(name: String, profileID: String?) -> String {
        lockName(name) + (profileID.map { "~" + ProfileKey.short($0) } ?? "")
    }
    static func lockKey(_ info: ConnectionInfo) -> String { lockKey(name: info.name, profileID: info.profileID) }
    /// The name a block is shown by.
    static func lockLabel(_ key: String) -> String {
        guard let i = key.lastIndex(of: "~"), key[key.index(after: i)...].count == 12,
              key[key.index(after: i)...].allSatisfy(\.isHexDigit) else { return key }
        return String(key[..<i])
    }

    /// Armings follow the tunnels up (MugVPNPlanner). - Returns: whether they changed.
    @discardableResult
    private func syncArming() -> Bool {
        guard let synced = ProtectionPlanner.syncing(locks, to: ProtectionPlanner.arming(protectionFacts())) else { return false }
        locks = synced
        return true
    }

    private func addLock(_ l: Lock) {
        locks = ProtectionPlanner.adding(l, to: locks)
    }

    /// The connections as protection sees them.
    private func protectionFacts() -> [ProtectionFacts] {
        connections.values.map { c in
            ProtectionFacts(id: c.info.id, lockKey: HelperCore.lockKey(c.info), lockNames: [HelperCore.lockKey(c.info), HelperCore.lockName(c.info.name)],
                            owner: c.info.ownerUID, persistent: c.info.persistent, exited: c.exited, protection: c.protection,
                            takesAllTraffic: c.tunnel.takesAllTraffic, wasFull: c.wasFull, liftsBlock: c.liftsBlock,
                            device: c.tunnel.device, restricted: c.restricted,
                            dnsServers: c.tunnel.dnsApplied ? c.tunnel.dnsServers : [])
        }
    }

    /// Recompute what PF must enforce from the helper's own knowledge; apply it if it
    /// changed, or if PF no longer holds it (pfctl -d, a flushed anchor).
    /// - Returns: whether PF now holds what it must (a failure is tried again later).
    @discardableResult
    public func refreshProtection() -> Bool {
        let plan = ProtectionPlanner.plan(protectionFacts(), locks: locks, suspended: suspended, now: system.now())
        for id in plan.nowFull { connections[id]?.wasFull = true }
        for id in plan.liftDone { connections[id]?.liftsBlock = false }
        locks = plan.locks
        suspended = plan.suspended
        if plan.locksChanged { saveLocks() }
        let s = plan.state
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
        return locks.filter { !$0.armed && (admin || $0.owner == uid || $0.everyone) }.map { HelperCore.lockLabel($0.name) }.sorted()
    }

    /// Nothing needs this helper to keep running: no connection of anyone's, no block (PF to watch).
    /// Then it may exit for launchd to start the one an updated app came with.
    public var idleForRestart: Bool { connections.isEmpty && locks.isEmpty && !closing }

    public enum RestartDecision: Equatable, Sendable { case restart, inUse, notNewer }
    /// This helper's version (a test build may pretend to be older, to be updated on the stand).
    public var runningVersion = MugVPNIDs.helperVersion

    /// Idle, and closed in the same step: no start gets in before the exit. Only for a newer helper
    /// on disk (`installed`: the version of the app bundle it comes from): an older app asking does not
    /// stop a newer helper in a loop.
    public func beginRestartIfIdle(installed: String?) -> RestartDecision {
        guard let installed, Self.newer(installed, than: runningVersion) else { return .notNewer }
        guard idleForRestart else { return .inUse }
        closing = true
        return .restart
    }

    static func newer(_ a: String, than b: String) -> Bool {
        let x = a.split(separator: ".").map { Int($0) ?? -1 }, y = b.split(separator: ".").map { Int($0) ?? -1 }
        guard !x.contains(-1), !y.contains(-1) else { return false }
        for i in 0..<max(x.count, y.count) {
            let l = i < x.count ? x[i] : 0, r = i < y.count ? y[i] : 0
            if l != r { return l > r }
        }
        return false
    }

    /// Fired blocks lifted for a while (to sign in to a network), until this time. Not on disk:
    /// a helper that starts again blocks again.
    private var suspended: [String: TimeInterval] = [:]
    public static let maxSuspend = ProtectionPlanner.maxSuspend
    private static func suspendKey(_ l: Lock) -> String { ProtectionPlanner.suspendKey(l) }

    /// Lift the caller's blocks (an administrator's: all) for at most `maxSuspend` seconds. Error text or nil.
    public func suspendBlocks(uid: UInt32, seconds: TimeInterval) -> String? {
        let admin = uid == 0 || system.isAdmin(uid: uid)
        // Every block on the caller, or none: a page behind one still in force would not load.
        let mine: [Lock]
        switch ProtectionPlanner.suspension(locks, uid: uid, admin: admin) {
        case .success(let m): mine = m
        case .failure(let why): return why.description
        }
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
        switch ProtectionPlanner.unblocking(locks, uid: uid, admin: admin) {
        case .success(let staying): locks = staying
        case .failure(let why): return why.description
        }
        saveLocks()
        refreshProtection()
        return nil
    }

    private var locksPath: String { paths.supportDir + "/locks.json" }

    /// A kill switch armed only in memory would not survive the helper: written again until it is.
    private var locksDirty = false
    private func saveLocks() {
        if locks.isEmpty {
            system.remove(locksPath)
            // Still there: dirty (written again), never taken as gone.
            locksDirty = system.fileInfo(locksPath) != nil
            return
        }
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
            // A name and its profile's key (printable, bounded).
            x.name = String(x.name.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) }.map(Character.init).prefix(80))
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

    /// A route as `route add` arguments (openvpn's log forms, or the helper's own), compared exactly.
    public struct RouteKey: Hashable, Sendable {
        public var destination: String
        public var mask: String
        public var via: String
    }
    public static func routeKey(_ args: [String]) -> RouteKey? {
        let a = args.first == "-cloning" ? Array(args.dropFirst()) : args
        func after(_ flag: String) -> String? { a.firstIndex(of: flag).flatMap { $0 + 1 < a.count ? a[$0 + 1] : nil } }
        guard a.count >= 3 else { return nil }
        if a[0] == "-net" {
            if a.count == 4, !a.contains(where: { $0.hasPrefix("-") && $0 != "-net" }) {
                return RouteKey(destination: a[1], mask: a[3], via: a[2])        // -net dst gw mask
            }
            guard let m = after("-netmask"), let i = after("-interface") else { return nil }
            return RouteKey(destination: a[1], mask: m, via: i)                  // -net dst -netmask m -interface if
        }
        if a[0] == "-inet6", let n = after("-prefixlen") {
            let via = after("-iface") ?? a.last!
            return RouteKey(destination: a[1], mask: n, via: via)                // -inet6 dst -prefixlen n gw|-iface if
        }
        return nil
    }

    /// - Returns: false when DNS it left is on record nowhere (its directory is then kept).
    /// - live: tunnels up now (a utun of theirs, a route they hold too, is theirs: left alone).
    private func cleanUp(after facts: OpenVPNLogFacts, others: [OpenVPNLogFacts], live: [TunnelState] = [], dir: String? = nil) -> Bool {
        var plan = CleanupPlan.make(facts, others: others)
        let liveDevices = Set(live.compactMap(\.device))
        // The same route exactly (destination, mask or prefix, and the way out), in any of openvpn's forms.
        let liveRoutes = Set(live.flatMap(\.routes).compactMap { HelperCore.routeKey(Array($0.add.dropFirst(3))) })
        plan.routes = plan.routes.filter { r in
            guard let k = HelperCore.routeKey(r) else { return true }
            return !liveRoutes.contains(k) && !liveDevices.contains(k.via)
        }
        // DNS of that utun is a live tunnel's only if it set DNS there.
        if let dev = plan.dnsDevice, live.contains(where: { $0.device == dev && $0.dnsApplied }) { plan.dnsDevice = nil }
        var recorded = true
        if let dev = plan.dnsDevice {
            switch system.restoreDNS(device: dev) {
            case .done: break
            case .backupLeft: recorded = leaveDNS(dev, .backup)
            case .failed: recorded = leaveDNS(dev, .all)
            }
        }
        // Routes through the dead utun are already gone (counted as deleted); one that stays keeps the folder. Many:
        // a batch each pass (the folder kept until the last).
        // What is still to delete, by the routes themselves (not a position: the ones a live tunnel holds now are
        // left out each pass); one that would not go stays in it for the next pass.
        var remaining = dir.flatMap { legacyRemaining[$0] }.map { left in plan.routes.filter { left.contains($0) } } ?? plan.routes
        let batch = Array(remaining.prefix(HelperCore.maxCleanupRoutes))
        let done = batch.filter { system.deleteRoute(OpenVPNLogFacts.deleteArguments($0)) }
        remaining.removeAll { done.contains($0) }
        if !remaining.isEmpty { recorded = false }
        if let dir { legacyRemaining[dir] = remaining.isEmpty ? nil : Set(remaining) }
        // A default route openvpn took away (redirect-gateway without def1) goes back.
        for r in facts.deletedDefaults.prefix(2) where !system.addRoute(r) { recorded = false }
        return recorded
    }

    /// The live log stays root's (cleanup reads it) and its owner may read it;
    /// a kept log is the user's alone. Persistent ones are root's, readable by administrators.
    /// - Returns: false when its owner or mode could not be set.
    @discardableResult private func giveLog(_ path: String, to info: ConnectionInfo, live: Bool = true) -> Bool {
        if info.persistent {
            return system.setOwner(path, uid: 0, gid: adminGID, mode: 0o640)
        } else if live {
            return system.setOwner(path, uid: 0, gid: staffGID, mode: 0o600) && system.grantRead(path, uid: info.ownerUID)
        } else {
            return system.setOwner(path, uid: info.ownerUID, gid: staffGID, mode: 0o600)
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

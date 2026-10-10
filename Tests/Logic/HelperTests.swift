import Foundation
import MugVPNCore
import MugVPNHelperCore

// MARK: - Fake system: records what the helper asks for, does nothing real.

final class FakeProcess: HelperProcess {
    let pid: Int32
    var signals: [Int32] = []
    let onExit: (ExitKind) -> Void
    init(pid: Int32, onExit: @escaping (ExitKind) -> Void) {
        self.pid = pid
        self.onExit = onExit
    }
    func signal(_ sig: Int32) { signals.append(sig) }
}

final class FakeChannel: ManagementChannel {
    let path: String
    let onLine: (String) -> Void
    let onClose: () -> Void
    var sent: [(line: String, fd: Int32?)] = []
    var closed = false
    /// The other end stopped taking lines.
    var stalled = false
    init(path: String, onLine: @escaping (String) -> Void, onClose: @escaping () -> Void) {
        self.path = path
        self.onLine = onLine
        self.onClose = onClose
    }
    func send(_ line: String, passing fd: Int32?) -> Bool {
        if stalled { return false }
        sent.append((line, fd))
        return true
    }
    func close() { closed = true }
}

final class FakeSystem: HelperSystem {
    var dirs: [String: UInt16] = [:]
    var files: [String: (data: Data, mode: UInt16)] = [:]
    var launched: [(path: String, args: [String], cwd: String, log: String, user: ServiceUser?, process: FakeProcess)] = []
    /// The first id a connection's openvpn runs as.
    static let serviceUser = ServiceUser(name: "mugvpn-\(HelperCore.serviceIDBase)", uid: HelperCore.serviceIDBase,
                                         gid: HelperCore.serviceIDBase)
    /// ifconfig/route commands run, in order.
    var commands: [[String]] = []
    var commandFails = false
    /// The routing table as `route add` arguments: an add of one that is there fails, like the kernel's.
    var routeTable: Set<[String]> = []
    /// Ids the directory has (a user or group).
    var takenIDs: Set<UInt32> = []
    func idIsFree(_ id: UInt32) -> Bool { !takenIDs.contains(id) }
    var killedUIDs: [ClosedRange<UInt32>] = []
    func killProcesses(uids: ClosedRange<UInt32>) { killedUIDs.append(uids) }
    func routeExists(_ r: TunnelRoute) -> Bool { routeTable.contains(r.add) }
    /// utun devices that are gone (their descriptor closed).
    var closedDevices: Set<String> = []
    func interfaceExists(_ name: String) -> Bool { !closedDevices.contains(name) }
    var dnsSet: [DNSPlan] = []
    var gateway: DefaultGateway? = DefaultGateway(address: "192.168.64.1", interface: "en0")
    /// Management connections the helper opened (persistent tunnels), in order.
    var channels: [FakeChannel] = []
    var channelFails = false
    var closedFDs: [Int32] = []
    func closeDescriptor(_ fd: Int32) { closedFDs.append(fd) }
    func connectManagement(_ path: String, peer pid: Int32, onLine: @escaping (String) -> Void,
                           onClose: @escaping () -> Void) -> ManagementChannel? {
        if channelFails { return nil }
        let c = FakeChannel(path: path, onLine: onLine, onClose: onClose)
        channels.append(c)
        return c
    }
    var utunName = "utun7"
    /// IPv6 networks of the Mac's own interfaces.
    var localIPv6: [String] = []
    /// IPv4 networks of the Mac's own interfaces (the stand's LAN by default).
    var localIPv4: [String] = ["192.168.64.0/24"]
    func localIPv4Networks() -> [String] { localIPv4 }
    /// Writes that fail (disk full...), by path suffix.
    var failWrites: Set<String> = []
    /// Every write fails after this many more succeed (nil: none fail).
    var failAfterWrites: Int?
    /// The Mac's own DNS servers.
    var systemDNS: [String]? = []
    /// The Mac's resolvers, with what MugVPN's own tunnels set (but the excluded one's).
    func systemDNSServers(excluding device: String) -> [String]? {
        systemDNS.map { $0 + dnsSet.filter { $0.device != device && !dnsRestored.contains($0.device) }.flatMap(\.servers) }
    }
    func localIPv6Networks() -> [String] { localIPv6 }
    var clock: TimeInterval = 1000
    func now() -> TimeInterval { clock }
    var openUtunFails = false
    /// utun devices the helper keeps open (its own copy), so their names are not reused.
    var heldDevices: [String] = []
    var releasedDevices: [String] = []
    func openUtun() throws -> (fd: Int32, name: String) {
        if openUtunFails { throw CocoaError(.featureUnsupported) }
        heldDevices.append(utunName)
        return (99, utunName)
    }
    func releaseDevice(_ name: String) {
        releasedDevices.append(name)
        heldDevices.removeAll { $0 == name }
    }
    var onCommand: ([String]) -> Void = { _ in }
    func runNetwork(_ command: [String]) -> Bool {
        onCommand(command)
        commands.append(command)
        guard !commandFails else { return false }
        if command.count > 3, command[0] == "route" {
            var key = command
            if key[2] == "delete" {
                key[2] = "add"
                let had = routeTable.remove(key) != nil
                var cloning = key
                cloning.insert("-cloning", at: 3)
                return routeTable.remove(cloning) != nil || had
            }
            return routeTable.insert(command).inserted
        }
        return true
    }
    func defaultGateway() -> DefaultGateway? { gateway }
    func setDNS(_ plan: DNSPlan) -> Bool {
        dnsSet.append(plan)
        return true
    }
    var dnsRestored: [String] = []
    var routesDeleted: [[String]] = []
    var strayKills: [String] = []
    var timers: [(seconds: TimeInterval, f: () -> Void)] = []
    var users: [UInt32: String] = [0: "root", 501: "tester", 502: "tester2"]
    var admins: Set<UInt32> = [501]
    /// Owner and mode of paths; anything not listed is root-owned 0755.
    var infos: [String: (owner: UInt32, mode: UInt16)] = [:]
    var links: Set<String> = []
    /// Read access given through an ACL: path -> uid.
    var readGrants: [String: UInt32] = [:]
    /// PF anchors applied, in order ("" = cleared).
    var pf: [String] = []
    var pfApplyFails = false
    var pfIntactAnswer = true
    var pfClearedBeforeRemoval: Bool?
    func applyPF(_ anchor: String) -> Bool {
        pf.append(anchor)
        if anchor.isEmpty, pfClearedBeforeRemoval == nil { pfClearedBeforeRemoval = !removedPaths.contains("/L/libexec") }
        return !pfApplyFails
    }
    func pfIntact(_ anchor: String) -> Bool { pfIntactAnswer }
    var routesAdded: [[String]] = []
    func addRoute(_ args: [String]) { routesAdded.append(args) }
    func grantRead(_ path: String, uid: UInt32) { readGrants[path] = uid }
    var launchFails = false
    var nextPID: Int32 = 1000

    func makeDirectory(_ path: String, mode: UInt16) throws {
        guard dirs[path] == nil else { throw CocoaError(.fileWriteFileExists) }
        dirs[path] = mode
    }
    func writeFile(_ path: String, _ data: Data, mode: UInt16) throws {
        if failWrites.contains(where: { path.hasSuffix($0) }) { throw CocoaError(.fileWriteOutOfSpace) }
        if let n = failAfterWrites {
            if n <= 0 { throw CocoaError(.fileWriteOutOfSpace) }
            failAfterWrites = n - 1
        }
        files[path] = (data, mode)
    }
    func readFile(_ path: String) -> Data? { files[path]?.data }
    func readTail(_ path: String, maxBytes: Int) -> Data? { files[path].map { $0.data.suffix(maxBytes) } }
    func readFrom(_ path: String, offset: UInt64, maxBytes: Int) -> Data? {
        guard let d = files[path]?.data else { return nil }
        // A rewritten (shorter) file in a test starts over.
        guard offset <= UInt64(d.count) else { return d.prefix(maxBytes) }
        return d.dropFirst(Int(offset)).prefix(maxBytes)
    }
    func copyFile(_ from: String, _ to: String, mode: UInt16) throws {
        guard let f = files[from] else { throw CocoaError(.fileNoSuchFile) }
        files[to] = (f.data, mode)
        // What FileManager.copyItem does with a link: copies the link.
        if links.contains(from) { links.insert(to) }
        if let i = copiedInfo { infos[to] = i }
    }
    /// Owner and mode a copy ends up with, to model a copy that is not root's.
    var copiedInfo: (owner: UInt32, mode: UInt16)?
    var removedPaths: [String] = []
    func remove(_ path: String) {
        removedPaths.append(path)
        files = files.filter { !($0.key == path || $0.key.hasPrefix(path + "/")) }
        dirs = dirs.filter { !($0.key == path || $0.key.hasPrefix(path + "/")) }
    }
    var owners: [String: (uid: UInt32, gid: UInt32)] = [:]
    var failMoves: Set<String> = []
    func move(_ from: String, _ to: String) {
        if let f = files.removeValue(forKey: from) { files[to] = f }
    }
    func replace(_ from: String, _ to: String) throws {
        if failMoves.contains(to) { throw CocoaError(.fileWriteNoPermission) }
        move(from, to)
    }
    /// Modes set with setOwner (directories included).
    var modes: [String: UInt16] = [:]
    func setOwner(_ path: String, uid: UInt32, gid: UInt32, mode: UInt16) {
        owners[path] = (uid, gid)
        modes[path] = mode
        if let f = files[path] { files[path] = (f.data, mode) }
    }
    func exists(_ path: String) -> Bool {
        files[path] != nil || dirs[path] != nil || files.keys.contains { $0.hasPrefix(path + "/") }
    }
    func list(_ dir: String) -> [String] {
        let prefix = dir + "/"
        let names = (Array(dirs.keys) + Array(files.keys)).filter { $0.hasPrefix(prefix) }
            .map { String($0.dropFirst(prefix.count).split(separator: "/")[0]) }
        return Array(Set(names)).sorted()
    }
    func launch(_ path: String, _ args: [String], cwd: String, logPath: String, user: ServiceUser?,
                onExit: @escaping (ExitKind) -> Void) throws -> HelperProcess {
        if launchFails { throw CocoaError(.executableNotLoadable) }
        nextPID += 1
        let p = FakeProcess(pid: nextPID, onExit: onExit)
        launched.append((path, args, cwd, logPath, user, p))
        return p
    }
    func killStrayOpenVPN(path: String) { strayKills.append(path) }
    func restoreDNS(device: String) { dnsRestored.append(device) }
    func deleteRoute(_ args: [String]) { routesDeleted.append(args) }
    func after(_ seconds: TimeInterval, _ f: @escaping () -> Void) { timers.append((seconds, f)) }
    func userName(uid: UInt32) -> String? { users[uid] }
    func isAdmin(uid: UInt32) -> Bool { admins.contains(uid) }
    func fileInfo(_ path: String) -> FileInfo? {
        guard files[path] != nil || dirs[path] != nil || links.contains(path) else { return nil }
        let i = infos[path] ?? (0, files[path]?.mode ?? 0o755)
        let kind: FileInfo.Kind = links.contains(path) ? .link : dirs[path] != nil ? .directory : .regular
        return FileInfo(owner: i.owner, mode: i.mode, kind: kind)
    }

    /// Fire every pending timer (once).
    func fireTimers() {
        let t = timers
        timers = []
        t.forEach { $0.f() }
    }
}

let testPaths = HelperPaths(openvpn: "/L/libexec/openvpn", runDir: "/L/run", logsDir: "/Logs", autoDir: "/L/auto",
                            libexecDir: "/L/libexec", systemConfigDir: "/L/config",
                            devDaemonPlist: "/LD/com.mugvpn.helper.plist", supportDir: "/L")

/// A certificate as the policy expects one (POL-36).
let testCA = "-----BEGIN CERTIFICATE-----\nQ0E=\n-----END CERTIFICATE-----\n"

func makeHelper(_ sys: FakeSystem) -> HelperCore {
    var n = 0, k = 0
    let h = HelperCore(system: sys, paths: testPaths, newID: { n += 1; return "ID\(n)" },
                       newSecret: { k += 1; return "SECRET\(k)" })
    h.nextServiceID = 0
    return h
}

func bundle(_ name: String = "office", config: String = "client\ndev tun\nremote a 1194",
            files: [String: Data] = [:]) -> Data {
    try! JSONEncoder().encode(ProfileBundle(name: name, config: config, files: files))
}

/// A log as openvpn writes it on macOS, for a tunnel with routes outside it.
func sampleLog(device: String = "utun5", server: String = "203.0.113.7", gateway: String = "192.168.64.1",
               net: Int = 84) -> String {
    """
    2026-10-06 05:46:44 PUSH: Received control message: 'PUSH_REPLY,route 10.94.0.0 255.255.255.0,redirect-gateway def1'
    2026-10-06 05:46:44 Opened utun device \(device)
    2026-10-06 05:46:44 /sbin/ifconfig \(device) 10.\(net).0.2 10.\(net).0.2 netmask 255.255.255.0 mtu 1500 up
    2026-10-06 05:46:44 /sbin/route add -net 10.\(net).0.0 10.\(net).0.2 255.255.255.0
    2026-10-06 05:46:44 /sbin/route add -net \(server) \(gateway) 255.255.255.255
    2026-10-06 05:46:44 /sbin/route add -net 0.0.0.0 10.\(net).0.1 128.0.0.0
    2026-10-06 05:46:44 /sbin/route add -net 128.0.0.0 10.\(net).0.1 128.0.0.0
    2026-10-06 05:46:44 Initialization Sequence Completed
    """
}

// MARK: - L-LOG

func registerLogTests() {
    test("LOG-01", "utun device") {
        expectEqual(OpenVPNLogFacts.parse(sampleLog()).device, "utun5")
    }
    test("LOG-02", "IPv4 routes") {
        expectEqual(OpenVPNLogFacts.parse(sampleLog()).routes, [
            ["-net", "10.84.0.0", "10.84.0.2", "255.255.255.0"],
            ["-net", "203.0.113.7", "192.168.64.1", "255.255.255.255"],
            ["-net", "0.0.0.0", "10.84.0.1", "128.0.0.0"],
            ["-net", "128.0.0.0", "10.84.0.1", "128.0.0.0"],
        ])
    }
    test("LOG-03", "IPv6 and on-link routes, as openvpn 2.7 on macOS writes them") {
        // the forms of route.c (TARGET_DARWIN), not made-up ones.
        let log = """
        2026-10-06 05:46:44 /sbin/route add -inet6 fd00:1:: -prefixlen 64 fe80::1
        2026-10-06 05:46:44 /sbin/route add -inet6 2000:: -prefixlen 3 -iface utun5
        2026-10-06 05:46:44 /sbin/route add -cloning -net 10.10.0.1 -netmask 255.255.255.255 -interface en0
        """
        let f = OpenVPNLogFacts.parse(log)
        expectEqual(f.routes, [["-inet6", "fd00:1::", "-prefixlen", "64", "fe80::1"],
                               ["-inet6", "2000::", "-prefixlen", "3", "-iface", "utun5"],
                               ["-cloning", "-net", "10.10.0.1", "-netmask", "255.255.255.255", "-interface", "en0"]])
        expectEqual(OpenVPNLogFacts.deleteArguments(f.routes[2]), ["-net", "10.10.0.1", "-netmask", "255.255.255.255", "-interface", "en0"])
        expectEqual(OpenVPNLogFacts.deleteArguments(f.routes[0]), f.routes[0])
    }
    test("LOG-04", "lines without a timestamp ignored") {
        let log = "/sbin/route add -net 1.2.3.4 5.6.7.8 255.255.255.255\nOpened utun device utun9"
        expectEqual(OpenVPNLogFacts.parse(log), OpenVPNLogFacts())
    }
    test("LOG-05", "server text cannot pose as a route") {
        let log = "2026-10-06 05:46:44 PUSH: Received control message: '/sbin/route add -net 1.2.3.4 5.6.7.8 255.255.255.255'\n"
            + "2026-10-06 05:46:44 AUTH: Received control message: Opened utun device utun9"
        expectEqual(OpenVPNLogFacts.parse(log), OpenVPNLogFacts())
    }
    test("LOG-06", "invalid values ignored") {
        let bad = ["-net 1.2.3 5.6.7.8 255.255.255.255", "-net 1.2.3.4 5.6.7.8", "-net 1.2.3.4 5.6.7.8 255.255.255.255 x",
                   "-net 1.2.3.4 ;rm 255.255.255.255", "-host 1.2.3.4 5.6.7.8 255.255.255.255",
                   "-inet6 fd00:: -prefixlen 129 fe80::1", "-inet6 2000:: -prefixlen 3 -iface en0",
                   "-inet6 2000:: -prefixlen x fe80::1", "-cloning -net 10.0.0.1 -netmask 255.255.255.255 -interface en0;x",
                   "-cloning -net 10.0.0.1 -netmask 255.255.255.255 -interface utun"]
        let log = bad.map { "2026-10-06 05:46:44 /sbin/route add \($0)" }.joined(separator: "\n")
            + "\n2026-10-06 05:46:44 Opened utun device utun5;x\n2026-10-06 05:46:44 Opened utun device en0"
        expectEqual(OpenVPNLogFacts.parse(log), OpenVPNLogFacts())
    }
    test("LOG-08", "a route add that failed is not a fact") {
        let log = """
        2026-10-06 05:46:44 /sbin/route add -net 0.0.0.0 192.168.64.1 0.0.0.0
        route: writing to routing socket: File exists
        add net 0.0.0.0: gateway 192.168.64.1: File exists
        2026-10-06 05:46:44 ERROR: OS X route add command failed: external program exited with error status: 1
        2026-10-06 05:46:44 /sbin/route add -net 10.9.0.0 10.8.0.1 255.255.255.0
        add net 10.9.0.0: gateway 10.8.0.1
        2026-10-06 05:46:44 /sbin/route add -inet6 fd00:: -prefixlen 64 fe80::1
        2026-10-06 05:46:44 ERROR: MacOS X route add -inet6 command failed: external program exited with error status: 1
        2026-10-06 05:46:45 /sbin/route add -net 10.10.0.0 10.8.0.1 255.255.255.0
        """
        expectEqual(OpenVPNLogFacts.parse(log).routes, [["-net", "10.9.0.0", "10.8.0.1", "255.255.255.0"],
                                                       ["-net", "10.10.0.0", "10.8.0.1", "255.255.255.0"]])
    }
    test("LOG-09", "routes of an openvpn without root (MugVPN's privsep lines), for the app's warnings") {
        let log = """
        2026-10-06 05:46:44 Opened utun device utun5
        2026-10-06 05:46:44 MugVPN: route add 0.0.0.0 128.0.0.0 10.84.0.1
        2026-10-06 05:46:44 MugVPN: route add 203.0.113.7 255.255.255.255 192.168.64.1 dev en0
        2026-10-06 05:46:44 MugVPN: route add 198.51.100.0 255.255.255.0 192.168.64.1
        2026-10-06 05:46:44 MugVPN: the helper refused route 198.51.100.0 255.255.255.0 192.168.64.1
        2026-10-06 05:46:44 MugVPN: route add -inet6 fd00:84::/64 utun5
        2026-10-06 05:46:44 MugVPN: route add 10.9.0.0 255.255.255.0 10.84.0.1; rm -rf /
        """
        let f = OpenVPNLogFacts.parse(log)
        expectEqual(f.device, "utun5")
        expectEqual(f.routes, [["-net", "0.0.0.0", "10.84.0.1", "128.0.0.0"],
                               ["-cloning", "-net", "203.0.113.7", "-netmask", "255.255.255.255", "-interface", "en0"],
                               ["-inet6", "fd00:84::", "-prefixlen", "64", "-iface", "utun5"]])
    }
    test("LOG-07", "the last device wins") {
        expectEqual(OpenVPNLogFacts.parse(sampleLog(device: "utun4") + "\n" + sampleLog(device: "utun6")).device, "utun6")
    }
}

// MARK: - L-CLN

func registerCleanupTests() {
    let dead = OpenVPNLogFacts.parse(sampleLog(device: "utun5", server: "203.0.113.7"))
    test("CLN-01", "DNS of a free device restored") {
        expectEqual(CleanupPlan.make(dead, others: []).dnsDevice, "utun5")
    }
    test("CLN-02", "device reused by a live connection keeps its DNS") {
        let live = OpenVPNLogFacts(device: "utun5")
        expectEqual(CleanupPlan.make(dead, others: [live]).dnsDevice, nil)
    }
    test("CLN-03", "routes deleted except those of live connections") {
        let live = OpenVPNLogFacts.parse(sampleLog(device: "utun7", server: "203.0.113.7", net: 85))
        let plan = CleanupPlan.make(dead, others: [live])
        expectEqual(plan.routes, [["-net", "10.84.0.0", "10.84.0.2", "255.255.255.0"],
                                  ["-net", "0.0.0.0", "10.84.0.1", "128.0.0.0"],
                                  ["-net", "128.0.0.0", "10.84.0.1", "128.0.0.0"]],
                    "the server route the live connection shares stays")
        expectEqual(CleanupPlan.make(dead, others: []).routes, dead.routes)
    }
    test("CLN-04", "only an unclean exit needs cleanup") {
        expect(!ExitKind.exited(0).needsCleanup)
        expect(ExitKind.exited(1).needsCleanup)
        expect(ExitKind.signaled(9).needsCleanup)
        expect(ExitKind.signaled(15).needsCleanup)
    }
    test("CLN-05", "no device, no DNS step") {
        expectEqual(CleanupPlan.make(OpenVPNLogFacts(), others: []).dnsDevice, nil)
    }
    test("CLN-06", "leftovers of a previous helper") {
        let sys = FakeSystem()
        try sys.makeDirectory("/L/run", mode: 0o711)
        try sys.makeDirectory("/L/run/OLD1", mode: 0o711)
        try sys.writeFile("/L/run/OLD1/openvpn.log", Data(sampleLog(device: "utun3").utf8), mode: 0o644)
        try sys.makeDirectory("/L/run/OLD2", mode: 0o711)
        let h = makeHelper(sys)
        try h.prepareRunDirectory()
        expectEqual(sys.strayKills, ["/L/libexec/openvpn", "/L/libexec/openvpn-root"], "stray openvpn (an older version's root one too) killed first")
        expectEqual(sys.dnsRestored, ["utun3"])
        expectEqual(sys.routesDeleted.count, 4)
        expect(sys.list("/L/run").isEmpty, "run directory emptied")
        expectEqual(sys.dirs["/L/run"], 0o711)
        expectEqual(sys.dirs["/Logs"], 0o755)
        let quiet = FakeSystem()
        try makeHelper(quiet).prepareRunDirectory()
        expect(quiet.strayKills.isEmpty, "nothing to kill without leftovers")
    }
}

// MARK: - L-HLP

func registerHelperTests() {
    test("HLP-37", "the app in the Trash for a minute (not put back, not replaced by an update): time to go") {
        var w = TrashWatch()
        let trash = "/Users/u/.Trash/MugVPN.app/Contents/MacOS/MugVPNHelper"
        expect(!w.look(bundleInPlace: true, runningFrom: "/Applications/MugVPN.app/Contents/MacOS/MugVPNHelper", now: 0))
        expect(!w.look(bundleInPlace: false, runningFrom: trash, now: 10), "just moved: an update may put a new one back")
        expect(!w.look(bundleInPlace: true, runningFrom: trash, now: 40), "replaced by an update: stays")
        expect(!w.look(bundleInPlace: false, runningFrom: trash, now: 50))
        expect(!w.look(bundleInPlace: false, runningFrom: trash, now: 100))
        expect(w.look(bundleInPlace: false, runningFrom: trash, now: 111), "a minute in the Trash")
        var m = TrashWatch()
        expect(!m.look(bundleInPlace: false, runningFrom: "/Users/u/Applications/MugVPN.app/Contents/MacOS/MugVPNHelper", now: 0))
        expect(!m.look(bundleInPlace: false, runningFrom: "/Users/u/Applications/MugVPN.app/Contents/MacOS/MugVPNHelper", now: 500),
               "moved elsewhere, not to the Trash: not an uninstall")
    }
    test("HLP-38", "moved to the Trash: the system part and every user's logs and settings go; profiles stay") {
        let sys = FakeSystem()
        for d in ["/L", "/L/run", "/L/libexec", "/Logs", "/L/config", "/L/auto",
                  "/Users/a/Library/Logs/MugVPN", "/Users/a/Library/Application Support/MugVPN",
                  "/Users/b/Library/Logs/MugVPN"] {
            try sys.makeDirectory(d, mode: 0o755)
        }
        try sys.writeFile("/L/policy.json", Data("{}".utf8), mode: 0o644)
        try sys.writeFile("/Users/a/Library/Preferences/com.mugvpn.app.plist", Data(), mode: 0o600)
        let h = makeHelper(sys)
        var gone = false
        h.onUninstalled = { gone = true }
        _ = try h.start(bundle: bundle(), uid: 501)
        h.uninstallMovedToTrash(homes: ["/Users/a", "/Users/b"])
        sys.launched[0].process.onExit(.exited(0))
        expect(gone, "the service leaves launchd")
        for p in ["/L/run", "/L/libexec", "/Logs", "/Users/a/Library/Logs/MugVPN", "/Users/b/Library/Logs/MugVPN",
                  "/Users/a/Library/Preferences/com.mugvpn.app.plist"] {
            expect(sys.fileInfo(p) == nil, "\(p) gone")
        }
        for p in ["/L/config", "/L/auto", "/L/policy.json", "/Users/a/Library/Application Support/MugVPN"] {
            expect(sys.fileInfo(p) != nil, "\(p) stays")
        }
    }
    test("HLP-36", "the helper's bundle from its own path, as launchd gives it (relative for a registered service)") {
        expectEqual(HelperPaths.contentsDirectory(ofExecutable: "/Applications/MugVPN.app/Contents/MacOS/MugVPNHelper"),
                    "/Applications/MugVPN.app/Contents")
        expectEqual(HelperPaths.contentsDirectory(ofExecutable: "Contents/MacOS/MugVPNHelper"), nil,
                    "SMAppService's argv[0] (found in 0.2.2: it became /Contents): never used")
        expectEqual(HelperPaths.contentsDirectory(ofExecutable: "/usr/local/bin/MugVPNHelper"), nil, "not inside a bundle")
        let mine = HelperPaths.executablePath()
        expect(mine?.hasPrefix("/") == true, "the running process's real path: \(mine ?? "nil")")
    }
    test("HLP-35", "exits for an update only if the helper on disk is newer than the one running") {
        let h = makeHelper(FakeSystem())
        expectEqual(h.beginRestartIfIdle(installed: MugVPNIDs.helperVersion), .notNewer, "the same: an older app asked")
        expectEqual(h.beginRestartIfIdle(installed: "0.0.1"), .notNewer)
        expectEqual(h.beginRestartIfIdle(installed: nil), .notNewer, "cannot tell: stays")
        expectEqual(h.beginRestartIfIdle(installed: "99.0.0"), .restart)
    }
    test("HLP-34", "deciding to exit for an update and closing are one step: no tunnel starts in between") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: bundle(), uid: 502)
        expectEqual(h.beginRestartIfIdle(installed: "99.0.0"), .inUse)
        sys.launched[0].process.onExit(.exited(0))
        _ = id
        expectEqual(h.beginRestartIfIdle(installed: "99.0.0"), .restart)
        expectThrows("closing", matching: "closing") { _ = try h.start(bundle: bundle(), uid: 501) }
        expectThrows("persistent too", matching: "closing") { _ = try h.startPersistent(name: "site", uid: 0) }
    }
    test("HLP-33", "started again for an update only when nobody's connection or block needs it") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        expect(h.idleForRestart, "nothing at all")
        let (id, _) = try h.start(bundle: bundle(), uid: 502)
        expect(!h.idleForRestart, "another user's tunnel")
        sys.launched[0].process.onExit(.exited(0))
        expect(h.idleForRestart)
        var b = ProfileBundle(name: "office", config: "client\ndev tun\nremote a 1194", files: [:])
        b.protection = ProtectionOptions(killSwitch: true)
        let (k, _) = try h.start(bundle: try JSONEncoder().encode(b), uid: 501)
        try bringUp(sys, h, k, uid: 501)
        sys.launched[1].process.onExit(.signaled(9))
        expect(!h.idleForRestart, "a block in force: PF is watched while it lasts")
        _ = id
    }
    test("HLP-01", "openvpn arguments") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, sock) = try h.start(bundle: bundle(), uid: 501)
        expectEqual(id, "ID1")
        expectEqual(sock, "/L/run/ID1/sock/m.sock")
        let l = sys.launched[0]
        expectEqual(l.path, "/L/libexec/openvpn")
        expectEqual(l.cwd, "/L/run/ID1")
        expectEqual(l.log, "/L/run/ID1/openvpn.log")
        // The helper's pull filters, then the profile, then the helper's own options (HLP-25).
        let c = l.args.firstIndex(of: "--config")!
        expectEqual(l.args[c + 1], "/L/run/ID1/config.ovpn")
        expect(l.args[..<c].allSatisfy { $0 == "--pull-filter" || $0 == "ignore" || HelperCore.ignoredPushes.contains($0) })
        let forced = Array(l.args[(c + 2)...])
        for (opt, val) in [("--cd", ["/L/run/ID1"]), ("--management", ["/L/run/ID1/sock/m.sock", "unix"]),
                           ("--management-client-user", ["tester"]), ("--auth-retry", ["interact"]),
                           ("--script-security", ["1"])] {
            guard let i = forced.firstIndex(of: opt) else { expect(false, "missing \(opt)"); continue }
            expectEqual(Array(forced[(i + 1)...].prefix(val.count)), val, opt)
        }
        expect(forced.contains("--management-hold") && forced.contains("--management-query-passwords"))
    }
    test("HLP-17", "the helper never writes a config openvpn would read differently") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let long = String(repeating: "D", count: 200)
        expectThrows("long serialized line", matching: "long") {
            _ = try h.start(bundle: bundle(config: "client\ndev tun\nremote a 1194\nsetenv-safe X \(long) \(long)"), uid: 501)
        }
        expect(sys.launched.isEmpty, "nothing started")
        expect(!sys.files.keys.contains { $0.hasSuffix("config.ovpn") }, "nothing written")
    }
    test("HLP-18", "a pinned install takes only a regular root-owned file") {
        let linked = FakeSystem()
        try linked.writeFile("/App/openvpn", Data("bin".utf8), mode: 0o755)
        linked.links.insert("/App/openvpn")
        expectThrows("a link", matching: "regular") {
            try HelperCore.installPinned(from: "/App/openvpn", to: "/L/libexec/openvpn", system: linked) { _ in }
        }
        expect(linked.files["/L/libexec/openvpn"] == nil && linked.files["/L/libexec/openvpn.new"] == nil)
        let foreign = FakeSystem()
        try foreign.writeFile("/App/openvpn", Data("bin".utf8), mode: 0o755)
        foreign.copiedInfo = (501, 0o755)
        expectThrows("not root's", matching: "regular") {
            try HelperCore.installPinned(from: "/App/openvpn", to: "/L/libexec/openvpn", system: foreign) { _ in }
        }
        expect(foreign.files["/L/libexec/openvpn"] == nil)
    }
    test("HLP-25", "the helper's own pull filters come before the profile's") {
        // openvpn uses the first matching filter, profile rules would win otherwise.
        let args = HelperCore.openvpnArguments(config: "/c", dir: "/d", socket: ["/s", "unix"], access: [])
        let firstConfig = args.firstIndex(of: "--config")!
        let filters = args.indices.filter { args[$0] == "--pull-filter" }
        expect(!filters.isEmpty && filters.allSatisfy { $0 < firstConfig }, "\(args)")
        let ignored = filters.map { args[$0 + 2] }
        for name in ["verb ", "mute ", "lladdr ", "ifconfig-noexec", "route-ipv6-gateway ", "compat-mode ", "providers ",
                     "prng ", "tun-ipv6", "disable-dco", "client-nat ", "shaper "] {
            expect(ignored.contains(name), name)
        }
        expect(filters.allSatisfy { args[$0 + 1] == "ignore" })
    }
    test("HLP-26", "files in a bundle hold what the directive naming them expects") {
        // The same content checks for files sent beside the profile.
        let sys = FakeSystem()
        let h = makeHelper(sys)
        expectThrows(matching: "ca") {
            _ = try h.start(bundle: bundle(config: "client\ndev tun\nremote a 1194\nca ca.crt",
                                           files: ["ca.crt": Data("not a certificate\n".utf8)]), uid: 501)
        }
        expect(sys.launched.isEmpty)
        _ = try h.start(bundle: bundle(config: "client\ndev tun\nremote a 1194\nca ca.crt",
                                       files: ["ca.crt": Data("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".utf8)]), uid: 501)
        _ = try h.start(bundle: bundle(config: "client\ndev tun\nremote a 1194\npkcs12 me.p12",
                                       files: ["me.p12": Data([0x30, 0x82, 0x01, 0x00])]), uid: 501)
    }
    test("HLP-28", "a bundle file named by two directives must suit both") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        expectThrows(matching: "key") {
            _ = try h.start(bundle: bundle(config: "client\ndev tun\nremote a 1194\nauth-user-pass f\nkey f",
                                           files: ["f": Data("user\npass\n".utf8)]), uid: 501)
        }
    }
    test("HLP-29", "standard users: no route for all traffic, no DNS for all names, unless an administrator allows it") {
        // Routes and DNS are the whole Mac's. Without a policy (or with a broken one) the answer is no.
        let sys = FakeSystem()
        sys.admins = []
        let h = makeHelper(sys)
        expectThrows("redirect in the profile", matching: "administrator") {
            _ = try h.start(bundle: bundle(config: "client\ndev tun\nremote a 1194\nredirect-gateway def1"), uid: 502)
        }
        _ = try h.start(bundle: bundle(config: "client\ndev tun\nremote a 1194\ndhcp-option DOMAIN corp.example.com"), uid: 502)
        let a = sys.launched.last!.args
        let ignored = a.indices.filter { a[$0] == "--pull-filter" && a[$0 + 1] == "ignore" }.map { a[$0 + 2] }
        expect(ignored.contains("redirect-gateway"), "a server cannot push it either")
        expect(a.firstIndex(of: "--config")! > a.lastIndex(of: "--pull-filter")!, "before the profile")
        // Administrators are not limited.
        sys.admins = [501]
        _ = try h.start(bundle: bundle(config: "client\ndev tun\nremote a 1194\nredirect-gateway def1"), uid: 501)
        // An administrator's policy: for everyone, or for named users; only a root-owned file counts.
        try sys.makeDirectory("/L", mode: 0o755)
        try sys.writeFile("/L/policy.json", Data(#"{"usersMayRouteAllTraffic": true}"#.utf8), mode: 0o644)
        _ = try h.start(bundle: bundle(config: "client\ndev tun\nremote a 1194\nredirect-gateway def1"), uid: 502)
        try sys.writeFile("/L/policy.json", Data(#"{"trustedUsers": ["tester2"]}"#.utf8), mode: 0o644)
        _ = try h.start(bundle: bundle(config: "client\ndev tun\nremote a 1194\nredirect-gateway def1"), uid: 502)
        sys.infos["/L/policy.json"] = (502, 0o644)
        expectThrows("a policy file that is not root's", matching: "administrator") {
            _ = try h.start(bundle: bundle(config: "client\ndev tun\nremote a 1194\nredirect-gateway def1"), uid: 502)
        }
        try sys.writeFile("/L/policy.json", Data("{broken".utf8), mode: 0o644)
        sys.infos["/L/policy.json"] = nil
        expectThrows("a broken policy", matching: "administrator") {
            _ = try h.start(bundle: bundle(config: "client\ndev tun\nremote a 1194\nredirect-gateway def1"), uid: 502)
        }
    }
    test("HLP-31", "a profile that does not check the server's role gets remote-cert-tls server") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        _ = try h.start(bundle: bundle(config: "client\ndev tun\nremote a 1194\nca ca.crt", files: ["ca.crt": Data(testCA.utf8)]), uid: 501)
        let a = sys.launched[0].args
        expectEqual(a.firstIndex(of: "--remote-cert-tls").map { a[$0 + 1] }, "server")
        expect(a.firstIndex(of: "--remote-cert-tls")! > a.firstIndex(of: "--config")!, "after the profile")
        _ = try h.start(bundle: bundle(config: "client\ndev tun\nremote a 1194\nca ca.crt\nverify-x509-name vpn.example.com name",
                                       files: ["ca.crt": Data(testCA.utf8)]), uid: 501)
        expect(!sys.launched[1].args.contains("--remote-cert-tls"), "its own check is kept")
    }
    test("HLP-32", "kept logs of one user are bounded") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        for i in 0..<(HelperCore.keptLogsPerUser + 5) {
            let (id, _) = try h.start(bundle: bundle("p\(i)"), uid: 501)
            try sys.writeFile("/L/run/\(id)/openvpn.log", Data("log".utf8), mode: 0o600)
            sys.launched.last!.process.onExit(.exited(0))
        }
        let kept = sys.files.keys.filter { $0.hasPrefix("/Logs/") && $0.hasSuffix(".501.log") }
        expectEqual(kept.count, HelperCore.keptLogsPerUser)
    }
    test("HLP-02", "run directory contents") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        _ = try h.start(bundle: bundle(config: "client\ndev tun\nca \"my ca.crt\"\nsetenv opt frob 1",
                                       files: ["my ca.crt": Data(testCA.utf8), "unused": Data("U".utf8)]), uid: 501)
        expectEqual(sys.dirs["/L/run/ID1"], 0o711)
        expectEqual(sys.files["/L/run/ID1/file0"]?.data, Data(testCA.utf8))
        expectEqual(sys.files["/L/run/ID1/file0"]?.mode, 0o640, "readable by openvpn's group only")
        expect(sys.files["/L/run/ID1/file1"] == nil, "files the config does not use are not written")
        let config = String(decoding: sys.files["/L/run/ID1/config.ovpn"]?.data ?? Data(), as: UTF8.self)
        expectEqual(config, "client\ndev \"tun\"\nca \"file0\"\n")
        expectEqual(sys.files["/L/run/ID1/config.ovpn"]?.mode, 0o640)
    }
    test("HLP-03", "unknown caller") {
        let sys = FakeSystem()
        expectThrows(matching: "unknown caller") { _ = try makeHelper(sys).start(bundle: bundle(), uid: 777) }
        expectThrows(matching: "unknown caller") { _ = try makeHelper(sys).start(bundle: bundle(), uid: UInt32.max) }
        expect(sys.launched.isEmpty)
    }
    test("HLP-04", "bundle too large") {
        let sys = FakeSystem()
        let big = bundle(files: ["x": Data(count: HelperCore.maxBundleBytes)])
        expectThrows(matching: "too large") { _ = try makeHelper(sys).start(bundle: big, uid: 501) }
        expect(sys.launched.isEmpty && sys.dirs.isEmpty)
    }
    test("HLP-05", "connections per user") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        for _ in 0..<HelperCore.maxConnectionsPerUser { _ = try h.start(bundle: bundle(), uid: 501) }
        expectThrows(matching: "too many") { _ = try h.start(bundle: bundle(), uid: 501) }
        expect((try? h.start(bundle: bundle(), uid: 502)) != nil, "another user still can")
    }
    test("HLP-19", "connections in all: a cap over every user") {
        let sys = FakeSystem()
        for u in UInt32(600)..<UInt32(610) { sys.users[u] = "user\(u)" }
        let h = makeHelper(sys)
        var started = 0
        outer: for u in UInt32(600)..<UInt32(610) {
            for _ in 0..<HelperCore.maxConnectionsPerUser {
                guard (try? h.start(bundle: bundle(), uid: u)) != nil else { break outer }
                started += 1
            }
        }
        expectEqual(started, HelperCore.maxConnections)
        expectThrows(matching: "too many") { _ = try h.start(bundle: bundle(), uid: 501) }
    }
    test("HLP-06", "stop: only the owner or root") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: bundle(), uid: 501)
        expectEqual(h.stop(id: id, uid: 502), "not your connection")
        expect(sys.launched[0].process.signals.isEmpty)
        expectEqual(h.stop(id: "nope", uid: 501), "no such connection")
        expectEqual(h.stop(id: id, uid: 0), nil)
        expectEqual(sys.launched[0].process.signals, [SIGTERM])
    }
    test("HLP-07", "list: own connections, root sees all") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        _ = try h.start(bundle: bundle("a"), uid: 501)
        _ = try h.start(bundle: bundle("b"), uid: 502)
        expectEqual(h.list(uid: 501).map(\.name), ["a"])
        expectEqual(h.list(uid: 502).map(\.name), ["b"])
        expectEqual(Set(h.list(uid: 0).map(\.name)), ["a", "b"])
        expectEqual(h.list(uid: 501).first?.managementSocket, "/L/run/ID1/sock/m.sock")
    }
    test("HLP-08", "stop escalates to SIGKILL after the grace period") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: bundle(), uid: 501)
        _ = h.stop(id: id, uid: 501)
        _ = h.stop(id: id, uid: 501)
        let p = sys.launched[0].process
        expectEqual(p.signals, [SIGTERM], "a second stop sends nothing")
        expectEqual(sys.timers.map(\.seconds), [HelperCore.stopGrace])
        sys.fireTimers()
        expectEqual(p.signals, [SIGTERM, SIGKILL])
        // Exits in time: the timer finds it gone and does nothing.
        let (id2, _) = try h.start(bundle: bundle(), uid: 501)
        _ = h.stop(id: id2, uid: 501)
        sys.launched[1].process.onExit(.exited(0))
        sys.fireTimers()
        expectEqual(sys.launched[1].process.signals, [SIGTERM])
    }
    test("HLP-09", "stopAll terminates every connection") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        _ = try h.start(bundle: bundle(), uid: 501)
        _ = try h.start(bundle: bundle(), uid: 502)
        h.stopAll()
        expect(sys.launched.allSatisfy { $0.process.signals == [SIGTERM] })
        expect(!h.isEmpty)
        sys.launched.forEach { $0.process.onExit(.exited(0)) }
        expect(h.isEmpty)
    }
    test("HLP-10", "log kept under a safe name") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        _ = try h.start(bundle: bundle("../../etc/My VPN:1"), uid: 501)
        try sys.writeFile("/L/run/ID1/openvpn.log", Data("log".utf8), mode: 0o644)
        sys.launched[0].process.onExit(.exited(0))
        expectEqual(sys.files["/Logs/.._.._etc_My VPN_1.501.log"]?.data, nil, "dots at the ends trimmed")
        expectEqual(sys.files["/Logs/_.._etc_My VPN_1.501.log"]?.data, Data("log".utf8))
        expect(sys.dirs["/L/run/ID1"] == nil, "run directory removed")
        expectEqual(HelperCore.logFileName("a/b"), "a_b")
        expectEqual(HelperCore.logFileName(".."), "profile")
        expectEqual(HelperCore.logFileName(String(repeating: "x", count: 100)).count, 64)
        expectEqual(HelperCore.logFileName("tab\there\u{7}"), "tab_here_")
    }
    test("HLP-11", "pinned install") {
        let sys = FakeSystem()
        try sys.writeFile("/App/openvpn", Data("bin".utf8), mode: 0o755)
        try HelperCore.installPinned(from: "/App/openvpn", to: "/L/libexec/openvpn", system: sys) { _ in }
        expectEqual(sys.files["/L/libexec/openvpn"]?.data, Data("bin".utf8))
        expectEqual(sys.files["/L/libexec/openvpn"]?.mode, 0o755)
        expect(sys.files["/L/libexec/openvpn.new"] == nil)
        let bad = FakeSystem()
        try bad.writeFile("/App/openvpn", Data("evil".utf8), mode: 0o755)
        expectThrows(matching: "pin") {
            try HelperCore.installPinned(from: "/App/openvpn", to: "/L/libexec/openvpn", system: bad) { _ in
                throw HelperCoreError.message("does not match its pin")
            }
        }
        expect(bad.files["/L/libexec/openvpn"] == nil && bad.files["/L/libexec/openvpn.new"] == nil,
               "nothing installed, temporary copy removed")
        expectEqual(HelperCore.sha256Hex(Data("abc".utf8)),
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }
    test("HLP-12", "bad bundles refused without a crash") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        expectThrows { _ = try h.start(bundle: Data("{".utf8), uid: 501) }
        expectThrows(matching: "runs a program") { _ = try h.start(bundle: bundle(config: "up /bin/sh"), uid: 501) }
        expectThrows(matching: "unterminated") { _ = try h.start(bundle: bundle(config: "ca \"x"), uid: 501) }
        expect(sys.launched.isEmpty && sys.dirs.isEmpty, "nothing created for refused bundles")
    }
    test("HLP-13", "launch failure leaves nothing behind") {
        let sys = FakeSystem()
        sys.launchFails = true
        let h = makeHelper(sys)
        expectThrows { _ = try h.start(bundle: bundle(), uid: 501) }
        expect(sys.dirs.isEmpty && sys.files.isEmpty && h.isEmpty)
    }
    test("HLP-15", "split DNS marker for the DNS script") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let split = try JSONEncoder().encode(ProfileBundle(name: "s", config: "client\ndev tun", files: [:], splitDNS: true))
        _ = try h.start(bundle: split, uid: 501)
        expectEqual(sys.files["/L/run/ID1/split-dns"]?.mode, 0o600)
        _ = try h.start(bundle: bundle(), uid: 501)
        expect(sys.files["/L/run/ID2/split-dns"] == nil)
        let old = Data(#"{"name":"o","config":"client\ndev tun","files":{}}"#.utf8)
        expect((try? h.start(bundle: old, uid: 501)) != nil, "a bundle without the field still reads")
    }
    test("HLP-16", "logs per owner, owned by them, private") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        _ = try h.start(bundle: bundle("Work"), uid: 501)
        _ = try h.start(bundle: bundle("Work"), uid: 502)
        expectEqual(sys.launched[0].log, "/L/run/ID1/openvpn.log")
        try sys.writeFile("/L/run/ID1/openvpn.log", Data("a".utf8), mode: 0o644)
        try sys.writeFile("/L/run/ID2/openvpn.log", Data("b".utf8), mode: 0o644)
        sys.launched[0].process.onExit(.exited(0))
        sys.launched[1].process.onExit(.exited(0))
        expectEqual(sys.files["/Logs/Work.501.log"]?.data, Data("a".utf8))
        expectEqual(sys.files["/Logs/Work.502.log"]?.data, Data("b".utf8), "users do not overwrite each other")
        expect(sys.owners["/Logs/Work.501.log"]! == (501, 20) && sys.files["/Logs/Work.501.log"]?.mode == 0o600)
        expect(sys.owners["/L/run/ID1/openvpn.log"]?.uid == 0, "the live log stays root's")
        expectEqual(sys.readGrants["/L/run/ID1/openvpn.log"], 501, "its owner may read it")
        try autoProfile(sys, "site")
        h.startPersistentProfiles()
        let pid = h.list(uid: 0).first { $0.persistent }!.id
        try sys.writeFile("/L/run/\(pid)/openvpn.log", Data(), mode: 0o644)
        sys.launched.last!.process.onExit(.exited(0))
        expect(sys.owners["/Logs/site.0.log"]! == (0, 80) && sys.files["/Logs/site.0.log"]?.mode == 0o640,
               "persistent logs: root, readable by admins")
        expectEqual(HelperCore.logFileName("Work", uid: 501), "Work.501")
    }
    test("HLP-11b", "a pinned copy that cannot be put in place is an error") {
        let sys = FakeSystem()
        try sys.writeFile("/App/openvpn", Data("bin".utf8), mode: 0o755)
        sys.failMoves = ["/L/libexec/openvpn"]
        expectThrows { try HelperCore.installPinned(from: "/App/openvpn", to: "/L/libexec/openvpn", system: sys) { _ in } }
    }
}

func registerLogTrustTests() {
    test("HLP-23", "the helper's directories are root's all the way up") {
        let fresh = FakeSystem()
        try makeHelper(fresh).prepareDirectories()
        for d in ["/L", "/L/libexec", "/Logs"] { expectEqual(fresh.dirs[d], 0o755, d) }
        let foreign = FakeSystem()
        try foreign.makeDirectory("/L", mode: 0o755)
        foreign.infos["/L"] = (501, 0o755)
        expectThrows("not root's", matching: "/L") { try makeHelper(foreign).prepareDirectories() }
        let open = FakeSystem()
        try open.makeDirectory("/Logs", mode: 0o777)
        open.infos["/Logs"] = (0, 0o777)
        expectThrows("writable by others", matching: "/Logs") { try makeHelper(open).prepareDirectories() }
        let linked = FakeSystem()
        linked.links.insert("/L")
        expectThrows("a link", matching: "/L") { try makeHelper(linked).prepareDirectories() }
    }
    test("HLP-22", "a persistent tunnel's id stays with administrators") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        if sys.dirs["/L/auto"] == nil { try sys.makeDirectory("/L/auto", mode: 0o755) }
        try sys.writeFile("/L/auto/site.ovpn", Data("client\ndev tun\nremote a 1194\n".utf8), mode: 0o600)
        h.startPersistentProfiles()
        let real = h.list(uid: 501).first { $0.persistent }!
        let seen = h.list(uid: 502).first { $0.persistent }!
        expect(sys.launched.last!.args.contains { $0.contains(real.id) }, "admins see the real id")
        expect(!seen.id.isEmpty && seen.id != real.id && seen.managementSocket.isEmpty, "\(seen)")
        expectEqual(seen.name, "site")
    }
    test("HLP-20", "cleanup believes only a log root alone could write") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        _ = try h.start(bundle: bundle("a"), uid: 501)
        try sys.writeFile("/L/run/ID1/openvpn.log", Data(sampleLog(device: "utun5").utf8), mode: 0o644)
        sys.infos["/L/run/ID1/openvpn.log"] = (501, 0o600)
        sys.launched[0].process.onExit(.signaled(9))
        expect(sys.routesDeleted.isEmpty && sys.dnsRestored.isEmpty, "a log that is not root's is not acted on")
        // Leftovers at helper start, the same.
        let left = FakeSystem()
        try left.makeDirectory("/L/run", mode: 0o711)
        try left.writeFile("/L/run/OLD/openvpn.log", Data(sampleLog(device: "utun7").utf8), mode: 0o600)
        left.infos["/L/run/OLD/openvpn.log"] = (501, 0o600)
        try makeHelper(left).prepareRunDirectory()
        expect(left.routesDeleted.isEmpty && left.dnsRestored.isEmpty)
        expectEqual(left.strayKills.count, 2, "stray openvpn (both builds) is still stopped")
    }
    test("HLP-21", "cleanup does a bounded amount of work") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        _ = try h.start(bundle: bundle("a"), uid: 501)
        var log = sampleLog(device: "utun5")
        for i in 0..<2000 { log += "\n2026-10-06 05:46:44 /sbin/route add -net 10.\(i / 250).\(i % 250).0 10.84.0.1 255.255.255.0" }
        try sys.writeFile("/L/run/ID1/openvpn.log", Data(log.utf8), mode: 0o644)
        sys.launched[0].process.onExit(.signaled(9))
        expect(sys.routesDeleted.count <= HelperCore.maxCleanupRoutes, "\(sys.routesDeleted.count)")
    }
}

// MARK: - L-PER (helper side)

private func autoProfile(_ sys: FakeSystem, _ name: String, _ text: String = "client\ndev tun\nremote a 1194\n") throws {
    if sys.dirs["/L/auto"] == nil { try sys.makeDirectory("/L/auto", mode: 0o755) }
    try sys.writeFile("/L/auto/\(name).ovpn", Data(text.utf8), mode: 0o600)
}

func registerPersistentHelperTests() {
    test("PER-01", "persistent profiles start with the helper, from a trusted folder only") {
        let sys = FakeSystem()
        try autoProfile(sys, "site")
        try autoProfile(sys, "lab")
        try sys.writeFile("/L/auto/readme.txt", Data(), mode: 0o644)
        let h = makeHelper(sys)
        try h.prepareRunDirectory()
        h.startPersistentProfiles()
        expectEqual(h.list(uid: 0).map(\.name).sorted(), ["lab", "site"])
        let unsafe = FakeSystem()
        try autoProfile(unsafe, "site")
        unsafe.infos["/L/auto"] = (0, 0o777)
        let u = makeHelper(unsafe)
        u.startPersistentProfiles()
        expect(u.isEmpty, "a folder others can write to is not trusted")
        let owned = FakeSystem()
        try autoProfile(owned, "site")
        owned.infos["/L/auto"] = (501, 0o755)
        let o = makeHelper(owned)
        o.startPersistentProfiles()
        expect(o.isEmpty, "nor one a user owns")
        let none = FakeSystem()
        let n = makeHelper(none)
        n.startPersistentProfiles()
        expect(n.isEmpty, "no folder, nothing to do")
    }
    test("PER-02", "files only from inside config-auto; the same policy") {
        let sys = FakeSystem()
        try autoProfile(sys, "good", "client\ndev tun\nca keys/ca.crt\n")
        try sys.makeDirectory("/L/auto/keys", mode: 0o755)
        try sys.writeFile("/L/auto/keys/ca.crt", Data(testCA.utf8), mode: 0o600)
        try autoProfile(sys, "abs", "client\ndev tun\nca /etc/ssl/x.crt\n")
        try autoProfile(sys, "up", "client\ndev tun\nca ../run/x\n")
        try autoProfile(sys, "evil", "client\ndev tun\nup /bin/sh\n")
        let h = makeHelper(sys)
        h.startPersistentProfiles()
        expectEqual(h.list(uid: 0).map(\.name), ["good"])
        let id = h.list(uid: 0)[0].id
        expectEqual(sys.files["/L/run/\(id)/file0"]?.data, Data(testCA.utf8))
    }
    test("PER-03", "owned by root, management for the admin group") {
        let sys = FakeSystem()
        try autoProfile(sys, "site")
        let h = makeHelper(sys)
        h.startPersistentProfiles()
        let info = h.list(uid: 0)[0]
        expectEqual(info.ownerUID, 0)
        expect(info.persistent)
        let args = sys.launched[0].args
        expect(!args.contains("--management-client-user") && !args.contains("--management-client-group"))
        guard let i = args.firstIndex(of: "--management") else { return expect(false, "\(args)") }
        expectEqual(Array(args[(i + 1)...].prefix(3)), ["/L/run/\(info.id)/sock/m.sock", "unix", "/L/run/\(info.id)/m.pw"])
        expectEqual(sys.files["/L/run/\(info.id)/m.pw"]?.mode, 0o640, "its openvpn's group reads it, nobody else")
        expectEqual(String(decoding: sys.files["/L/run/\(info.id)/m.pw"]?.data ?? Data(), as: UTF8.self), "SECRET1\n")
        expect(!args.contains("--management-hold"), "nobody is there to release a hold at boot")
        _ = try h.start(bundle: bundle(), uid: 501)
        expect(sys.launched[1].args.contains("--management-hold"), "user tunnels still wait for the app")
    }
    test("PER-04", "every user sees persistent connections") {
        let sys = FakeSystem()
        try autoProfile(sys, "site")
        let h = makeHelper(sys)
        h.startPersistentProfiles()
        _ = try h.start(bundle: bundle("mine"), uid: 501)
        expectEqual(h.list(uid: 502).map(\.name), ["site"])
        expectEqual(Set(h.list(uid: 501).map(\.name)), ["site", "mine"])
    }
    test("PER-04b", "the management password only for administrators") {
        let sys = FakeSystem()
        try autoProfile(sys, "site")
        let h = makeHelper(sys)
        h.startPersistentProfiles()
        expectEqual(h.list(uid: 0)[0].managementPassword, "SECRET1")
        expectEqual(h.list(uid: 501)[0].managementPassword, "SECRET1")
        expectEqual(h.list(uid: 502)[0].managementPassword, nil)
        _ = try h.start(bundle: bundle("mine"), uid: 502)
        expectEqual(h.list(uid: 502).first { $0.name == "mine" }?.managementPassword, nil, "user tunnels have none")
    }
    test("PER-04c", "the management socket of persistent tunnels only for administrators") {
        let sys = FakeSystem()
        try autoProfile(sys, "site")
        let h = makeHelper(sys)
        h.startPersistentProfiles()
        expect(!h.list(uid: 501)[0].managementSocket.isEmpty)
        expectEqual(h.list(uid: 502)[0].managementSocket, "")
        _ = try h.start(bundle: bundle("mine"), uid: 502)
        expect(!(h.list(uid: 502).first { $0.name == "mine" }?.managementSocket.isEmpty ?? true), "own tunnels keep it")
    }
    test("PER-12", "a persistent tunnel's openvpn runs without root too") {
        let sys = FakeSystem()
        try autoProfile(sys, "site")
        let h = makeHelper(sys)
        h.startPersistentProfiles()
        expectEqual(sys.launched[0].path, "/L/libexec/openvpn")
        expect((sys.launched[0].user?.uid ?? 0) >= HelperCore.serviceIDBase, "its own unprivileged id")
    }
    test("PER-13", "with nobody else attached, the helper is its management client and answers its tunnel requests") {
        let sys = FakeSystem()
        try autoProfile(sys, "site")
        let h = makeHelper(sys)
        h.startPersistentProfiles()
        sys.fireTimers()
        let id = h.list(uid: 0)[0].id
        guard let ch = sys.channels.first else { return expect(false, "no management connection") }
        expectEqual(ch.path, "/L/run/\(id)/sock/m.sock")
        ch.onLine("ENTER PASSWORD:")
        expectEqual(ch.sent.map(\.line), ["SECRET1"])
        ch.onLine(">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info")
        ch.onLine(">NEED-OK:Need 'OPENTUN' confirmation MSG:tun")
        expectEqual(ch.sent.last?.line, "needok 'OPENTUN' ok")
        expectEqual(ch.sent.last?.fd, 99, "the utun goes with the answer")
        ch.onLine(">NEED-OK:Need 'ROUTE' confirmation MSG:198.51.100.0 255.255.255.0 192.168.64.1")
        expectEqual(ch.sent.last?.line, "needok 'ROUTE' cancel", "checked like any other tunnel's")
        ch.onLine(">NEED-OK:Need 'token-insertion-request' confirmation MSG:Insert the token")
        expectEqual(ch.sent.count, 3, "anything else waits for an administrator's app")
    }
    test("PER-14", "an administrator's app takes the management connection over; the helper takes it back later") {
        let sys = FakeSystem()
        try autoProfile(sys, "site")
        let h = makeHelper(sys)
        h.startPersistentProfiles()
        sys.fireTimers()
        let id = h.list(uid: 0)[0].id
        expectEqual(h.releaseManagement(id: id, uid: 502), "only an administrator can attach to a persistent connection")
        expect(!sys.channels[0].closed)
        expectEqual(h.releaseManagement(id: id, uid: 501), nil)
        expect(sys.channels[0].closed, "the slot is free for the app")
        sys.fireTimers()
        expectEqual(sys.channels.count, 2, "queued again: it gets the slot when the app leaves")
        // Its requests while the app is attached: the app forwards them, as an administrator.
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "OPENTUN", message: "tun")
        expectThrows("a standard user", matching: "not your") { _ = try h.tunnelRequest(id: id, uid: 502, kind: "OPENTUN", message: "tun") }
    }
    test("PER-15", "the helper's management connection comes back when openvpn drops it, and ends with the tunnel") {
        let sys = FakeSystem()
        try autoProfile(sys, "site")
        let h = makeHelper(sys)
        h.startPersistentProfiles()
        sys.channelFails = true
        sys.fireTimers()
        sys.channelFails = false
        sys.fireTimers()
        expectEqual(sys.channels.count, 1, "tried again until openvpn listens")
        sys.channels[0].onClose()
        sys.fireTimers()
        expectEqual(sys.channels.count, 2)
        sys.launched[0].process.onExit(.exited(0))
        expect(sys.channels[1].closed)
        sys.fireTimers()
        expectEqual(sys.channels.count, 2, "no connection to a tunnel that is gone")
    }
    test("PER-16", "a persistent profile and its files are root's to read too (keys inside)") {
        let sys = FakeSystem()
        try autoProfile(sys, "site")
        sys.files["/L/auto/site.ovpn"]!.mode = 0o644
        let h = makeHelper(sys)
        h.startPersistentProfiles()
        expect(h.isEmpty, "a profile everyone can read is refused")
        sys.files["/L/auto/site.ovpn"]!.mode = 0o600
        h.startPersistentProfiles()
        expectEqual(h.list(uid: 0).count, 1)
    }
    test("PER-17", "a persistent tunnel's management socket: administrators only") {
        let sys = FakeSystem()
        try autoProfile(sys, "site")
        let h = makeHelper(sys)
        h.startPersistentProfiles()
        let id = h.list(uid: 0)[0].id
        expectEqual(sys.owners["/L/run/\(id)/sock"]?.gid, 80, "group admin")
        expectEqual(sys.modes["/L/run/\(id)/sock"], 0o750, "nobody else reaches the socket")
    }
    test("PER-18", "a persistent openvpn that stops taking answers is let go of and stopped, not waited for") {
        let sys = FakeSystem()
        try autoProfile(sys, "site")
        let h = makeHelper(sys)
        h.startPersistentProfiles()
        sys.fireTimers()
        sys.channels[0].stalled = true
        sys.channels[0].onLine(">NEED-OK:Need 'DNSDOWN' confirmation MSG:utun7")
        expect(sys.channels[0].closed)
        expectEqual(sys.launched[0].process.signals, [SIGTERM], "its connection ends")
    }
    test("PER-11", "config-auto: root-owned regular files only") {
        func setup(_ tweak: (FakeSystem) throws -> Void) throws -> HelperCore {
            let sys = FakeSystem()
            try autoProfile(sys, "site", "client\ndev tun\nca keys/ca.crt\n")
            try sys.makeDirectory("/L/auto/keys", mode: 0o755)
            try sys.writeFile("/L/auto/keys/ca.crt", Data(testCA.utf8), mode: 0o600)
            try tweak(sys)
            let h = makeHelper(sys)
            h.startPersistentProfiles()
            return h
        }
        expectEqual(try setup { _ in }.list(uid: 0).count, 1, "all root-owned: starts")
        expect(try setup { $0.infos["/L/auto/site.ovpn"] = (501, 0o644) }.isEmpty, "profile owned by a user")
        expect(try setup { $0.infos["/L/auto/site.ovpn"] = (0, 0o666) }.isEmpty, "profile writable by others")
        expect(try setup { $0.infos["/L/auto/keys"] = (501, 0o755) }.isEmpty, "a folder on the way owned by a user")
        expect(try setup { $0.infos["/L/auto/keys/ca.crt"] = (0, 0o664) }.isEmpty, "a file writable by the group")
        expect(try setup { s in s.files["/L/auto/keys/ca.crt"] = nil; s.links.insert("/L/auto/keys/ca.crt") }.isEmpty,
               "a symbolic link")
    }
    test("PER-05", "only admins stop persistent connections") {
        let sys = FakeSystem()
        try autoProfile(sys, "site")
        let h = makeHelper(sys)
        h.startPersistentProfiles()
        let id = h.list(uid: 0)[0].id
        expectEqual(h.stop(id: id, uid: 502), "not your connection")
        expect(sys.launched[0].process.signals.isEmpty)
        expectEqual(h.stop(id: id, uid: 501), nil)
        expectEqual(sys.launched[0].process.signals, [SIGTERM])
    }
    test("PER-06", "start a persistent profile again") {
        let sys = FakeSystem()
        try autoProfile(sys, "site")
        let h = makeHelper(sys)
        h.startPersistentProfiles()
        expectThrows(matching: "administrator") { _ = try h.startPersistent(name: "site", uid: 502) }
        let first = h.list(uid: 0)[0].id
        expectEqual(try h.startPersistent(name: "site", uid: 501), first, "already running: the same one")
        sys.launched[0].process.onExit(.exited(0))
        let again = try h.startPersistent(name: "site", uid: 501)
        expect(again != first)
        expectEqual(sys.launched.count, 2)
        expectThrows(matching: "no persistent profile") { _ = try h.startPersistent(name: "nope", uid: 501) }
        expectThrows(matching: "no persistent profile") { _ = try h.startPersistent(name: "../run/x", uid: 501) }
    }
    test("PER-19", "a persistent profile's settings: beside it in config-auto, root's, strict") {
        let sys = FakeSystem()
        try autoProfile(sys, "site")
        try sys.writeFile("/L/auto/site.json", Data(#"{"kill_switch": true, "block_ipv6": true, "split_dns": true}"#.utf8), mode: 0o644)
        let h = makeHelper(sys)
        h.startPersistentProfiles()
        let id = h.list(uid: 0)[0].id
        try bringUp(sys, h, id, uid: 0)
        expect((sys.pf.last ?? "").contains("block return out quick inet6 all"), "IPv6 blocked: \(sys.pf.last ?? "")")
        for v in ["dns_server_1_address_1=10.8.0.53", "dns_server_1_resolve_domain_1=corp.internal"] {
            _ = try h.tunnelRequest(id: id, uid: 0, kind: "DNSVAR", message: v)
        }
        _ = try h.tunnelRequest(id: id, uid: 0, kind: "DNSUP", message: "utun5")
        expectEqual(sys.dnsSet.last?.split, true, "split DNS")
        for (bad, why) in [(#"{"kill_switch": "yes"}"#, "a string"), (#"{"killswitch": true}"#, "a typo"), ("[]", "not an object")] {
            let s2 = FakeSystem()
            try autoProfile(s2, "site")
            try s2.writeFile("/L/auto/site.json", Data(bad.utf8), mode: 0o644)
            let h2 = makeHelper(s2)
            expectThrows(why, matching: "site.json") { _ = try h2.startPersistent(name: "site", uid: 0) }
        }
        let s3 = FakeSystem()
        try autoProfile(s3, "site")
        try s3.writeFile("/L/auto/site.json", Data(#"{"kill_switch": false}"#.utf8), mode: 0o644)
        s3.infos["/L/auto/site.json"] = (501, 0o644)
        expectThrows("not root's", matching: "site.json") { _ = try makeHelper(s3).startPersistent(name: "site", uid: 0) }
        s3.infos["/L/auto/site.json"] = (0, 0o666)
        expectThrows("others may write it", matching: "site.json") { _ = try makeHelper(s3).startPersistent(name: "site", uid: 0) }
    }
    test("PER-20", "a persistent tunnel's kill switch blocks the whole Mac; it holds over its restart until it is up again") {
        let sys = FakeSystem()
        try autoProfile(sys, "site")
        try sys.writeFile("/L/auto/site.json", Data(#"{"kill_switch": true}"#.utf8), mode: 0o644)
        let h = makeHelper(sys)
        h.startPersistentProfiles()
        try bringUp(sys, h, h.list(uid: 0)[0].id, uid: 0)
        sys.launched[0].process.onExit(.signaled(9))
        let blocked = "block return out quick proto { tcp udp } all"
        expectEqual((sys.pf.last ?? "").split(separator: "\n").last.map(String.init), blocked, sys.pf.last ?? "")
        sys.fireTimers()                                          // started again
        expectEqual(sys.launched.count, 2)
        expect((sys.pf.last ?? "").contains(blocked), "still blocked while it connects again")
        try bringUp(sys, h, h.list(uid: 0)[0].id, uid: 0, device: "utun6")
        expect(!(sys.pf.last ?? "").contains(blocked), "lifted once it takes all traffic again")
        // The helper dies with it up: the next one blocks.
        sys.pf = []
        try makeHelper(sys).prepareRunDirectory()
        expect((sys.pf.last ?? "").contains(blocked))
    }
    test("PER-22", "a persistent tunnel's block is everyone's: every user sees it, only an administrator lifts it") {
        let sys = FakeSystem()
        try autoProfile(sys, "site")
        try sys.writeFile("/L/auto/site.json", Data(#"{"kill_switch": true}"#.utf8), mode: 0o644)
        let h = makeHelper(sys)
        h.startPersistentProfiles()
        try bringUp(sys, h, h.list(uid: 0)[0].id, uid: 0)
        sys.timers = []
        sys.launched[0].process.onExit(.signaled(9))
        expectEqual(h.locks(uid: 502), ["site"], "a standard user is blocked by it: told why")
        expectEqual(h.unblock(uid: 502), "only its owner or an administrator can lift the block")
        expectEqual(h.suspendBlocks(uid: 502, seconds: 120), "only its owner or an administrator can lift the block")
        expectEqual(h.locks(uid: 502), ["site"])
        expectEqual(h.unblock(uid: 501), nil, "an administrator can")
        expectEqual(h.locks(uid: 502), [])
    }
    test("PER-21", "a persistent tunnel that ends unasked starts again, waiting longer each time") {
        let sys = FakeSystem()
        try autoProfile(sys, "site")
        let h = makeHelper(sys)
        h.startPersistentProfiles()
        var waits: [TimeInterval] = []
        for i in 0..<8 {
            sys.timers = []
            sys.launched[i].process.onExit(.exited(1))
            waits.append(sys.timers.map(\.seconds).max() ?? 0)
            sys.fireTimers()
        }
        expectEqual(waits, [5, 10, 20, 40, 80, 160, 300, 300])
        sys.clock += 600                                          // up a long time: back to a short wait
        sys.timers = []
        sys.launched[8].process.onExit(.exited(1))
        expectEqual(sys.timers.map(\.seconds).max(), 5)
        sys.fireTimers()
        _ = h.stop(id: h.list(uid: 0)[0].id, uid: 501)            // stopped by an administrator: stays stopped
        sys.timers = []
        sys.launched[9].process.onExit(.exited(0))
        sys.fireTimers()
        expectEqual(sys.launched.count, 10)
    }
}

// MARK: - L-UNI (helper side)

func registerUninstallHelperTests() {
    func installed() throws -> (FakeSystem, HelperCore) {
        let sys = FakeSystem()
        try sys.makeDirectory("/L/libexec", mode: 0o755)
        try sys.writeFile("/L/libexec/openvpn", Data("bin".utf8), mode: 0o755)
        try sys.makeDirectory("/L/config", mode: 0o755)
        try sys.writeFile("/L/config/corp.ovpn", Data(), mode: 0o644)
        try sys.makeDirectory("/L/auto", mode: 0o755)
        try sys.writeFile("/L/auto/site.ovpn", Data("client\ndev tun\nremote a 1194\n".utf8), mode: 0o600)
        try sys.makeDirectory("/Logs", mode: 0o755)
        try sys.writeFile("/Logs/x.log", Data(), mode: 0o644)
        try sys.writeFile("/LD/com.mugvpn.helper.plist", Data(), mode: 0o644)
        let h = makeHelper(sys)
        try h.prepareRunDirectory()
        h.startPersistentProfiles()
        _ = try h.start(bundle: bundle(), uid: 502)
        return (sys, h)
    }
    test("UNI-01", "only administrators uninstall") {
        let (sys, h) = try installed()
        expectThrows(matching: "administrator") { try h.uninstall(uid: 502, keepProfiles: false) }
        expect(sys.launched.allSatisfy { $0.process.signals.isEmpty })
        expect(sys.files["/L/libexec/openvpn"] != nil)
    }
    test("UNI-02", "stops everything, removes the system part") {
        let (sys, h) = try installed()
        try h.uninstall(uid: 501, keepProfiles: false)
        expect(sys.launched.allSatisfy { $0.process.signals == [SIGTERM] }, "every tunnel stopped, persistent too")
        sys.launched.forEach { $0.process.onExit(.exited(0)) }
        for gone in ["/L", "/L/run", "/L/libexec", "/Logs", "/L/config", "/L/auto", "/LD/com.mugvpn.helper.plist"] {
            expect(!sys.exists(gone), "\(gone) removed")
        }
        let (keep, k) = try installed()
        try k.uninstall(uid: 0, keepProfiles: true)
        keep.launched.forEach { $0.process.onExit(.exited(0)) }
        expect(keep.exists("/L/config/corp.ovpn") && keep.exists("/L/auto/site.ovpn"), "profiles kept on request")
        expect(!keep.exists("/L/libexec") && !keep.exists("/Logs"))
    }
    test("UNI-05", "while uninstalling or shutting down, nothing new starts") {
        let (_, h) = try installed()
        try h.uninstall(uid: 501, keepProfiles: false)
        expectThrows("start", matching: "closing") { _ = try h.start(bundle: bundle(), uid: 502) }
        expectThrows("persistent", matching: "closing") { _ = try h.startPersistent(name: "site", uid: 501) }
        let (_, s) = try installed()
        s.stopAll()
        expectThrows("after stopAll", matching: "closing") { _ = try s.start(bundle: bundle(), uid: 502) }
    }
    test("UNI-06", "each uninstall request gets its own answer; a refused one changes nothing") {
        let (sys, h) = try installed()
        var answers: [String] = []
        try h.uninstall(uid: 501, keepProfiles: false) { answers.append("admin") }
        expectThrows { try h.uninstall(uid: 502, keepProfiles: false) { answers.append("user") } }
        try h.uninstall(uid: 0, keepProfiles: false) { answers.append("root") }
        sys.launched.forEach { $0.process.onExit(.exited(0)) }
        expectEqual(answers, ["admin", "root"])
    }
    test("UNI-03", "the helper ends itself after the tunnels") {
        let (sys, h) = try installed()
        var ended = false
        h.onUninstalled = { ended = true }
        try h.uninstall(uid: 501, keepProfiles: false)
        expect(!ended, "not while tunnels are still going down")
        sys.launched.forEach { $0.process.onExit(.exited(0)) }
        expect(ended)
    }
}

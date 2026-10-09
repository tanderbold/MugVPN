import Darwin
import Foundation
import MugVPNCore
import MugVPNHelperCore
import MugVPNSys
import SystemConfiguration

/// The helper's real effects on the machine. No decisions here: HelperCore
/// (tested with a fake of this) decides; this only carries them out.
/// Callbacks come back on `queue`, the queue HelperCore runs on.
final class RealSystem: HelperSystem {
    let queue: DispatchQueue
    private let fm = FileManager.default
    private let rootOwned: [FileAttributeKey: Any] = [.ownerAccountID: 0, .groupOwnerAccountID: 0]

    init(queue: DispatchQueue) { self.queue = queue }

    func makeDirectory(_ path: String, mode: UInt16) throws {
        try fm.createDirectory(atPath: path, withIntermediateDirectories: false,
                               attributes: rootOwned.merging([.posixPermissions: mode]) { $1 })
    }

    /// All or nothing, and on disk when it returns: a temporary file, synced, renamed over.
    func writeFile(_ path: String, _ data: Data, mode: UInt16) throws {
        let tmp = path + ".mugvpn-new"
        unlink(tmp)
        let fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(mode))
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        var ok = fchown(fd, 0, 0) == 0 && fchmod(fd, mode_t(mode)) == 0
        if ok {
            ok = data.withUnsafeBytes { raw -> Bool in
                var off = 0
                while off < raw.count {
                    let n = Darwin.write(fd, raw.baseAddress! + off, raw.count - off)
                    if n <= 0 { return false }
                    off += n
                }
                return true
            }
        }
        ok = ok && fsync(fd) == 0
        close(fd)
        guard ok, rename(tmp, path) == 0 else {
            let e = errno
            unlink(tmp)
            throw POSIXError(POSIXErrorCode(rawValue: e) ?? .EIO)
        }
    }

    func readFile(_ path: String) -> Data? { fm.contents(atPath: path) }

    func readTail(_ path: String, maxBytes: Int) -> Data? {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        let h = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        guard let end = try? h.seekToEnd() else { return nil }
        try? h.seek(toOffset: end > UInt64(maxBytes) ? end - UInt64(maxBytes) : 0)
        return try? h.readToEnd() ?? Data()
    }

    func grantRead(_ path: String, uid: UInt32) {
        guard let name = userName(uid: uid) else { return }
        _ = run("/bin/chmod", ["-h", "+a", "user:\(name) allow read", path])
    }

    /// Copy the bytes of a regular file. The source is opened without
    /// following a link, the copy is created new (never through a link) and
    /// owned and moded through its descriptor: a link in the app bundle can
    /// neither be installed nor make root change the file it points to.
    func copyFile(_ from: String, _ to: String, mode: UInt16) throws {
        func fail(_ what: String) -> Error {
            CocoaError(.fileReadUnknown, userInfo: [NSFilePathErrorKey: from, "reason": "\(what): errno \(errno)"])
        }
        let src = open(from, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard src >= 0 else {
            if errno == ELOOP { throw HelperCoreError.message("\(from) is not a regular file (a link)") }
            throw fail("open")
        }
        defer { close(src) }
        var st = stat()
        guard fstat(src, &st) == 0, st.st_mode & S_IFMT == S_IFREG, st.st_size <= 256 << 20 else {
            throw HelperCoreError.message("\(from) is not a regular file")
        }
        let dst = open(to, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o700)
        guard dst >= 0 else { throw fail("create") }
        var ok = false
        defer {
            close(dst)
            if !ok { unlink(to) }
        }
        var buffer = [UInt8](repeating: 0, count: 1 << 16)
        while true {
            let n = read(src, &buffer, buffer.count)
            if n == 0 { break }
            guard n > 0 else { throw fail("read") }
            var off = 0
            while off < n {
                let w = buffer.withUnsafeBytes { write(dst, $0.baseAddress! + off, n - off) }
                guard w > 0 else { throw fail("write") }
                off += w
            }
        }
        guard fchown(dst, 0, 0) == 0, fchmod(dst, mode_t(mode)) == 0 else { throw fail("owner") }
        ok = true
    }

    func remove(_ path: String) { try? fm.removeItem(atPath: path) }

    func move(_ from: String, _ to: String) {
        guard fm.fileExists(atPath: from) else { return }
        try? fm.removeItem(atPath: to)
        try? fm.moveItem(atPath: from, toPath: to)
    }

    func replace(_ from: String, _ to: String) throws {
        // rename(2) replaces atomically, or fails: never a silent half-update.
        guard rename(from, to) == 0 else {
            throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: to, "errno": errno])
        }
    }

    func setOwner(_ path: String, uid: UInt32, gid: UInt32, mode: UInt16) {
        // lchown/lchmod: never follow a link someone put in the logs directory.
        lchown(path, uid, gid)
        lchmod(path, mode_t(mode))
    }

    func list(_ dir: String) -> [String] { (try? fm.contentsOfDirectory(atPath: dir)) ?? [] }

    func launch(_ path: String, _ args: [String], cwd: String, logPath: String, user: ServiceUser?,
                onExit: @escaping (ExitKind) -> Void) throws -> HelperProcess {
        fm.createFile(atPath: logPath, contents: nil, attributes: rootOwned.merging([.posixPermissions: 0o600]) { $1 })
        let log = try FileHandle(forWritingTo: URL(fileURLWithPath: logPath))
        if let user { return try launch(path, args, cwd: cwd, log: log, as: user, onExit: onExit) }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        p.currentDirectoryURL = URL(fileURLWithPath: cwd)
        // Nothing of the helper's own environment (OPENSSL_CONF, OPENSSL_MODULES,
        // TMPDIR...) reaches a root openvpn.
        p.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        p.standardInput = FileHandle.nullDevice
        p.standardOutput = log
        p.standardError = log
        let queue = self.queue
        p.terminationHandler = { proc in
            let kind: ExitKind = proc.terminationReason == .exit ? .exited(proc.terminationStatus)
                                                                  : .signaled(proc.terminationStatus)
            queue.async { onExit(kind) }
        }
        try p.run()
        return RealProcess(pid: p.processIdentifier, path: path)
    }

    /// openvpn without root (privilege separation): it gets only the log descriptor;
    /// the log file stays root's.
    private func launch(_ path: String, _ args: [String], cwd: String, log: FileHandle, as user: ServiceUser,
                        onExit: @escaping (ExitKind) -> Void) throws -> HelperProcess {
        // In a sandbox: it may write only its management socket's folder, and start nothing
        // (whatever ran as this id could otherwise outlive it or leave files for the next
        // connection given the id).
        func quoted(_ s: String) -> String {
            "\"" + s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
        }
        // Allowed: its network, reading system files and its own run folder, the few system
        // services name lookups need. Not: other users' files, MugVPN's other runs, writing
        // anywhere but its socket folder, starting anything (also through launchd), IPC,
        // hardware, preferences.
        let profile = """
            (version 1)
            (allow default)
            (deny file-write* (require-not (require-any (subpath \(quoted(cwd + "/sock"))) (literal "/dev/null") (literal "/dev/dtracehelper"))))
            (deny file-read* (subpath "/Users") (subpath "/Library/Application Support/MugVPN") (subpath "/Library/Keychains")
                (subpath "/private/var/root") (subpath "/Library/Logs"))
            (allow file-read* (subpath \(quoted(cwd))) (literal \(quoted(path))))
            (deny process-fork)
            (deny process-exec (require-not (literal \(quoted(path)))))
            (deny job-creation)
            (deny iokit-open)
            (deny ipc-posix*)
            (deny ipc-sysv*)
            (deny user-preference-write)
            (deny mach-register)
            (deny mach-lookup (require-not (require-any \(HelperLookups.allowed.map { "(global-name \(quoted($0)))" }.joined(separator: " ")))))
            (deny network-outbound (remote unix-socket (subpath "/Library/Application Support/MugVPN")))
            (deny network-bind (local unix-socket (require-not (subpath \(quoted(cwd + "/sock"))))))
            """
        let full = ["/usr/bin/sandbox-exec", "-p", profile, path] + args
        let cArgs: [UnsafeMutablePointer<CChar>?] = full.map { strdup($0) } + [nil]
        let cEnv: [UnsafeMutablePointer<CChar>?] = [strdup("PATH=/usr/bin:/bin:/usr/sbin:/sbin"), nil]
        defer { (cArgs + cEnv).forEach { free($0) } }
        let pid = mugvpn_spawn_as("/usr/bin/sandbox-exec", cArgs, cEnv, cwd, log.fileDescriptor, user.uid, user.gid)
        try? log.close()
        guard pid > 0 else { throw CocoaError(.executableNotLoadable) }
        let source = DispatchSource.makeProcessSource(identifier: pid, eventMask: .exit, queue: queue)
        source.setEventHandler {
            var status: Int32 = 0
            guard waitpid(pid, &status, WNOHANG) == pid else { return }
            source.cancel()
            let signaled = status & 0x7f != 0
            onExit(signaled ? .signaled(status & 0x7f) : .exited((status >> 8) & 0xff))
        }
        source.activate()
        // An exit before the source was armed.
        var status: Int32 = 0
        if waitpid(pid, &status, WNOHANG) == pid {
            source.cancel()
            let signaled = status & 0x7f != 0
            queue.async { onExit(signaled ? .signaled(status & 0x7f) : .exited((status >> 8) & 0xff)) }
        }
        return RealProcess(pid: pid, path: path)
    }

    // MARK: - privilege separation

    /// Neither a user nor a group has this id, and nothing runs as it.
    func idIsFree(_ id: UInt32) -> Bool {
        getpwuid(id) == nil && getgrgid(id) == nil && !runningUIDs().contains(id)
    }

    private func runningUIDs() -> Set<UInt32> {
        let count = proc_listallpids(nil, 0)
        guard count > 0 else { return [] }
        var pids = [pid_t](repeating: 0, count: Int(count) + 64)
        let n = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<pid_t>.size))
        var uids = Set<UInt32>()
        for pid in pids.prefix(Int(max(n, 0))) where pid > 1 {
            var info = proc_bsdinfo()
            guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size)) > 0 else { continue }
            uids.insert(info.pbi_uid)
            uids.insert(info.pbi_ruid)
        }
        return uids
    }

    /// Every process of each id in the range that no account has, including ones it forks
    /// meanwhile: a child as that id signals them all (kill -1) until none is left.
    func killProcesses(uids: ClosedRange<UInt32>) {
        for uid in runningUIDs() where uids.contains(uid) && getpwuid(uid) == nil {
            if mugvpn_kill_uid(uid) != 0 { log("processes of id \(uid) did not all end") }
        }
    }

    /// `route -n get` of exactly this destination and mask, going out where it was added.
    func routeExists(_ r: TunnelRoute) -> Bool {
        let args: [String]
        switch r.kind {
        case .tunnel6: args = ["-n", "get", "-inet6", r.net, "-prefixlen", r.mask]
        default: args = ["-n", "get", "-net", r.net, "-netmask", r.mask]
        }
        let out = run("/sbin/route", args, input: nil)
        return out.status == 0 && RouteGet.matches(out.output, r)
    }

    func now() -> TimeInterval { ProcessInfo.processInfo.systemUptime }

    func systemDNSServers(excluding device: String) -> [String]? {
        guard let store = SCDynamicStoreCreate(nil, "MugVPNHelper" as CFString, nil, nil),
              let keys = SCDynamicStoreCopyKeyList(store, "State:/Network/Service/.*/DNS" as CFString) as? [String] else { return nil }
        let own = "State:/Network/Service/openvpn-\(device)/DNS"
        var servers: [String] = []
        if let g = SCDynamicStoreCopyValue(store, "State:/Network/Global/DNS" as CFString) as? [String: Any] {
            servers += g["ServerAddresses"] as? [String] ?? []
        }
        // Every service's own (a resolver scoped to an interface, a supplemental one).
        for key in keys where key != own {
            if let d = SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any] { servers += d["ServerAddresses"] as? [String] ?? [] }
        }
        return Array(Set(servers))
    }

    /// "address/bits" of every IPv4 address on an interface that is not a utun or loopback.
    func localIPv4Networks() -> [String] {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return [] }
        defer { freeifaddrs(list) }
        var nets: [String] = []
        for p in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let ifa = p.pointee
            let name = String(cString: ifa.ifa_name)
            guard !name.hasPrefix("utun"), !name.hasPrefix("lo"), let addr = ifa.ifa_addr, addr.pointee.sa_family == UInt8(AF_INET),
                  let mask = ifa.ifa_netmask else { continue }
            let a = addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
            let m = mask.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
            nets.append("\(TunnelState.text(a))/\(m.nonzeroBitCount)")
        }
        return nets
    }

    /// "prefix/bits" of every IPv6 address on an interface that is not a utun, loopback or link-local.
    func localIPv6Networks() -> [String] {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return [] }
        defer { freeifaddrs(list) }
        var nets: [String] = []
        for p in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let ifa = p.pointee
            let name = String(cString: ifa.ifa_name)
            guard !name.hasPrefix("utun"), !name.hasPrefix("lo"), let addr = ifa.ifa_addr, addr.pointee.sa_family == UInt8(AF_INET6),
                  let mask = ifa.ifa_netmask else { continue }
            var a = addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_addr }
            let m = mask.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_addr }
            let bytes = withUnsafeBytes(of: a) { Array($0) }
            if bytes[0] == 0xFE && bytes[1] & 0xC0 == 0x80 { continue }
            let bits = withUnsafeBytes(of: m) { $0.reduce(0) { $0 + $1.nonzeroBitCount } }
            var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard inet_ntop(AF_INET6, &a, &buf, socklen_t(buf.count)) != nil else { continue }
            nets.append("\(String(cString: buf))/\(bits)")
        }
        return nets
    }

    func closeDescriptor(_ fd: Int32) { close(fd) }

    func connectManagement(_ path: String, peer pid: Int32, onLine: @escaping (String) -> Void,
                           onClose: @escaping () -> Void) -> ManagementChannel? {
        RealManagementChannel(path: path, peer: pid, queue: queue, onLine: onLine, onClose: onClose)
    }

    func interfaceExists(_ name: String) -> Bool { if_nametoindex(name) != 0 }

    /// MugVPN's note in a DNS backup: which service it came from.
    static let backupServiceKey = "MugVPNService"

    /// The helper's own copy of every utun it handed out: while it has records of a
    /// device, the kernel cannot give that name to another connection.
    private var held: [String: Int32] = [:]

    func openUtun() throws -> (fd: Int32, name: String) {
        var name = [CChar](repeating: 0, count: 32)
        let fd = mugvpn_open_utun(&name, UInt32(name.count))
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let copy = fcntl(fd, F_DUPFD_CLOEXEC, 3)
        guard copy >= 0 else {
            close(fd)
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        let n = String(cString: name)
        if let old = held.updateValue(copy, forKey: n) { close(old) }
        return (fd, n)
    }

    func releaseDevice(_ name: String) {
        if let fd = held.removeValue(forKey: name) { close(fd) }
    }

    func runNetwork(_ command: [String]) -> Bool {
        let tools = ["ifconfig": "/sbin/ifconfig", "route": "/sbin/route"]
        guard let first = command.first, let tool = tools[first] else { return false }
        let r = run(tool, Array(command.dropFirst()), input: nil)
        if r.status != 0 { log("\(command.joined(separator: " ")): \(r.output.prefix(200))") }
        return r.status == 0
    }

    func defaultGateway() -> DefaultGateway? {
        let out = run("/sbin/route", ["-n", "get", "default"], input: nil).output
        var gateway: String?, interface: String?
        for line in out.split(separator: "\n") {
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard parts.count == 2 else { continue }
            if parts[0] == "gateway" { gateway = parts[1] }
            if parts[0] == "interface" { interface = parts[1] }
        }
        guard let gateway, let interface else { return nil }
        return DefaultGateway(address: gateway, interface: interface)
    }

    /// What openvpn's macos-dns-updown.sh does, without a shell: split DNS as a
    /// supplemental resolver for the tunnel; all names by replacing the primary
    /// service's DNS (kept to restore) — for one tunnel at a time.
    func setDNS(_ plan: DNSPlan) -> Bool {
        guard let store = SCDynamicStoreCreate(nil, "MugVPNHelper" as CFString, nil, nil) else { return false }
        let base = "State:/Network/Service/openvpn-\(plan.device)"
        defer { run("/usr/bin/dscacheutil", ["-flushcache"]); run("/usr/bin/killall", ["-HUP", "mDNSResponder"]) }
        if plan.split {
            let dns: [String: Any] = ["ServerAddresses": plan.servers, "SupplementalMatchDomains": plan.matchDomains,
                                      "SupplementalMatchDomainsNoSearch": 1]
            return SCDynamicStoreSetValue(store, "\(base)/DNS" as CFString, dns as CFDictionary)
        }
        let others = SCDynamicStoreCopyKeyList(store, "State:/Network/Service/openvpn-.*/DnsBackup" as CFString) as? [String] ?? []
        guard others.allSatisfy({ $0 == "\(base)/DnsBackup" }) else {
            log("DNS for all names is already another tunnel's: not set for \(plan.device)")
            return false
        }
        guard let ipv4 = SCDynamicStoreCopyValue(store, "State:/Network/Global/IPv4" as CFString) as? [String: Any],
              let primary = ipv4["PrimaryService"] as? String else { return false }
        let key = "Setup:/Network/Service/\(primary)/DNS" as CFString
        let backupKey = "\(base)/DnsBackup" as CFString
        if others.isEmpty {
            // An empty backup: the primary service had no DNS of its own (it came from DHCP).
            // The service it belongs to goes with it: the primary may change before it is restored.
            var backup = SCDynamicStoreCopyValue(store, key) as? [String: Any] ?? [:]
            backup[RealSystem.backupServiceKey] = primary
            guard SCDynamicStoreSetValue(store, backupKey, backup as CFDictionary) else { return false }
        }
        var dns: [String: Any] = ["ServerAddresses": plan.servers, "SearchOrder": 5000]
        if !plan.searchDomains.isEmpty { dns["SearchDomains"] = plan.searchDomains }
        guard SCDynamicStoreSetValue(store, key, dns as CFDictionary) else {
            // Nothing set: no backup to hold the next tunnel back.
            SCDynamicStoreRemoveValue(store, backupKey)
            return false
        }
        return true
    }

    /// Every process whose executable is exactly `path` (no pattern matching).
    func killStrayOpenVPN(path: String) {
        let count = proc_listallpids(nil, 0)
        guard count > 0 else { return }
        var pids = [pid_t](repeating: 0, count: Int(count) + 64)
        let n = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<pid_t>.size))
        for pid in pids.prefix(Int(max(n, 0))) where pid > 1 && executablePath(of: pid) == path {
            kill(pid, SIGKILL)
        }
    }

    /// The reverse of openvpn's macos-dns-updown.sh for one device.
    func restoreDNS(device dev: String) {
        guard let store = SCDynamicStoreCreate(nil, "MugVPNHelper" as CFString, nil, nil) else { return }
        let base = "State:/Network/Service/openvpn-\(dev)"
        SCDynamicStoreRemoveValue(store, "\(base)/DNS" as CFString)
        let backupKey = "\(base)/DnsBackup" as CFString
        if var backup = SCDynamicStoreCopyValue(store, backupKey) as? [String: Any],
           let primary = backup.removeValue(forKey: RealSystem.backupServiceKey) as? String
               ?? (SCDynamicStoreCopyValue(store, "State:/Network/Global/IPv4" as CFString) as? [String: Any])?["PrimaryService"] as? String {
            // The service whose DNS was replaced, even if another is primary now.
            let key = "Setup:/Network/Service/\(primary)/DNS" as CFString
            // An empty backup: there was no DNS of the service's own before.
            if backup.isEmpty {
                SCDynamicStoreRemoveValue(store, key)
            } else {
                SCDynamicStoreSetValue(store, key, backup as CFDictionary)
            }
            log("restored the primary DNS from \(dev)'s backup")
        }
        SCDynamicStoreRemoveValue(store, backupKey)
        run("/usr/bin/dscacheutil", ["-flushcache"])
        run("/usr/bin/killall", ["-HUP", "mDNSResponder"])
    }

    func deleteRoute(_ args: [String]) {
        run("/sbin/route", ["-n", "delete"] + args)
    }

    func after(_ seconds: TimeInterval, _ f: @escaping () -> Void) {
        queue.asyncAfter(deadline: .now() + seconds, execute: f)
    }

    func userName(uid: UInt32) -> String? {
        guard let pw = getpwuid(uid) else { return nil }
        return String(cString: pw.pointee.pw_name)
    }

    func isAdmin(uid: UInt32) -> Bool {
        guard let pw = getpwuid(uid), let admin = getgrnam("admin") else { return false }
        let adminGID = admin.pointee.gr_gid
        var count: Int32 = 64
        var groups = [Int32](repeating: 0, count: Int(count))
        guard getgrouplist(pw.pointee.pw_name, Int32(bitPattern: pw.pointee.pw_gid), &groups, &count) != -1 else { return false }
        return groups.prefix(Int(count)).contains(Int32(bitPattern: adminGID))
    }

    func fileInfo(_ path: String) -> FileInfo? {
        var st = stat()
        guard lstat(path, &st) == 0 else { return nil }
        let kind: FileInfo.Kind
        switch st.st_mode & S_IFMT {
        case S_IFREG: kind = .regular
        case S_IFDIR: kind = .directory
        case S_IFLNK: kind = .link
        default: kind = .other
        }
        return FileInfo(owner: st.st_uid, mode: UInt16(st.st_mode & 0o7777), kind: kind)
    }

    /// Run a system tool and wait for it, but never for long: the helper's
    /// queue must not stop because one command hangs. waitUntilExit is not
    /// used: on a GCD thread it can miss the exit and wait forever.
    @discardableResult
    private func run(_ path: String, _ args: [String], timeout: TimeInterval = 10) -> Int32 {
        run(path, args, input: nil, timeout: timeout).status
    }

    /// With `input` on stdin; returns stdout and stderr together.
    private func run(_ path: String, _ args: [String], input: Data?, timeout: TimeInterval = 10) -> (status: Int32, output: String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        p.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        let out = Pipe(), inp = Pipe()
        p.standardOutput = out
        p.standardError = out
        p.standardInput = input == nil ? FileHandle.nullDevice : inp
        var collected = Data()
        let reading = DispatchGroup()
        reading.enter()
        DispatchQueue.global().async {
            collected = out.fileHandleForReading.readDataToEndOfFile()
            reading.leave()
        }
        let done = DispatchSemaphore(value: 0)
        p.terminationHandler = { _ in done.signal() }
        do { try p.run() } catch { return (-1, "") }
        if let input {
            inp.fileHandleForWriting.write(input)
            try? inp.fileHandleForWriting.close()
        }
        if done.wait(timeout: .now() + timeout) == .timedOut {
            log("\(path) \(args.joined(separator: " ")) took more than \(Int(timeout)) s; stopped it")
            kill(p.processIdentifier, SIGKILL)
            return (-1, "")
        }
        _ = reading.wait(timeout: .now() + 2)
        return (p.terminationStatus, String(decoding: collected, as: UTF8.self))
    }

    // MARK: - PF

    /// The reference pfctl -E gave us (PF stays on while anyone holds one), with
    /// the boot it belongs to: after a restart of the Mac it means nothing.
    private let tokenFile = MugVPNIDs.supportDir + "/pf.token"

    private func bootTime() -> String {
        var tv = timeval()
        var size = MemoryLayout<timeval>.size
        sysctlbyname("kern.boottime", &tv, &size, nil, 0)
        return String(tv.tv_sec)
    }

    /// Our token if it is from this boot.
    private func currentToken() -> String? {
        guard let text = try? String(contentsOfFile: tokenFile, encoding: .utf8) else { return nil }
        let parts = text.split(separator: " ").map(String.init)
        guard parts.count == 2, parts[0] == bootTime(), parts[1].allSatisfy(\.isNumber) else {
            try? fm.removeItem(atPath: tokenFile)
            return nil
        }
        return parts[1]
    }

    private func pfEnabled() -> Bool {
        run("/sbin/pfctl", ["-s", "info"], input: nil).output.contains("Status: Enabled")
    }

    func applyPF(_ anchor: String) -> Bool {
        let pfctl = "/sbin/pfctl"
        if anchor.isEmpty {
            let r = run(pfctl, ["-a", PFRules.anchorName, "-F", "all"], input: nil)
            if let token = currentToken() { run(pfctl, ["-X", token]) }
            try? fm.removeItem(atPath: tokenFile)
            return r.status == 0
        }
        let r = run(pfctl, ["-a", PFRules.anchorName, "-f", "-"], input: Data(anchor.utf8))
        guard r.status == 0 else {
            log("pfctl refused MugVPN's rules: \(r.output)")
            return false
        }
        if currentToken() == nil || !pfEnabled() {
            let e = run(pfctl, ["-E"], input: nil)
            guard let m = e.output.range(of: #"Token : (\d+)"#, options: .regularExpression) else {
                // Without its token PF could not be given back at the end: not on these terms.
                log("pfctl -E gave no token: \(e.output.prefix(200))")
                run(pfctl, ["-a", PFRules.anchorName, "-F", "all"], input: nil)
                return false
            }
            let token = e.output[m].split(separator: ":").last!.trimmingCharacters(in: .whitespaces)
            try? writeFile(tokenFile, Data("\(bootTime()) \(token)".utf8), mode: 0o600)
        }
        return pfEnabled()
    }

    func pfIntact(_ anchor: String) -> Bool {
        guard pfEnabled() else { return false }
        let loaded = run("/sbin/pfctl", ["-a", PFRules.anchorName, "-s", "rules"], input: nil).output
        // Each block or pass of ours shows up in pfctl's listing.
        let ours = anchor.split(separator: "\n").filter { $0.hasPrefix("block") || $0.hasPrefix("pass") }.count
        let there = loaded.split(separator: "\n").filter { $0.hasPrefix("block") || $0.hasPrefix("pass") }.count
        return there >= ours
    }

    func addRoute(_ args: [String]) {
        run("/sbin/route", ["-n", "add"] + args)
    }

    func readFrom(_ path: String, offset: UInt64, maxBytes: Int) -> Data? {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        let h = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        guard (try? h.seek(toOffset: offset)) != nil else { return nil }
        return try? h.read(upToCount: maxBytes) ?? Data()
    }
}

final class RealProcess: HelperProcess {
    let pid: Int32
    let path: String
    init(pid: Int32, path: String) {
        self.pid = pid
        self.path = path
    }
    /// Only while the pid is still our openvpn: a reaped pid may already be someone else's.
    func signal(_ sig: Int32) {
        if executablePath(of: pid) == path { kill(pid, sig) }
    }
}

/// The executable a process runs, or nil if there is no such process.
func executablePath(of pid: pid_t) -> String? {
    var buf = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
    let n = proc_pidpath(pid, &buf, UInt32(buf.count))
    return n > 0 ? String(cString: buf) : nil
}

/// System services openvpn may look up in its sandbox: name and user lookups, DNS, logging.
enum HelperLookups {
    static let allowed = ["com.apple.system.opendirectoryd.libinfo", "com.apple.dnssd.service",
                          "com.apple.system.notification_center", "com.apple.system.logger", "com.apple.logd",
                          "com.apple.diagnosticd", "com.apple.SystemConfiguration.configd",
                          "com.apple.system.DirectoryService.libinfo_v1"]
}

/// The helper's connection to a persistent tunnel's openvpn management socket. Reads on the
/// helper's queue; a line at most 64 KB (what openvpn sends is short).
final class RealManagementChannel: ManagementChannel {
    private let fd: Int32
    private let source: DispatchSourceRead
    private var buffer = Data()
    private var closed = false

    /// - peer: the openvpn it must be (a path can be made to lead elsewhere).
    init?(path: String, peer pid: Int32, queue: DispatchQueue, onLine: @escaping (String) -> Void, onClose: @escaping () -> Void) {
        let sock = socket(AF_UNIX, SOCK_STREAM, 0)
        guard sock >= 0 else { return nil }
        _ = fcntl(sock, F_SETFD, FD_CLOEXEC)
        setNoSigPipe(sock)
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else { Darwin.close(sock); return nil }
        withUnsafeMutableBytes(of: &addr.sun_path) { $0.copyBytes(from: bytes) }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(sock, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard rc == 0, let who = socketPeer(sock), who.pid == pid else { Darwin.close(sock); return nil }
        // Never blocks the helper's queue: an openvpn that stops reading is let go of.
        _ = fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK)
        fd = sock
        source = DispatchSource.makeReadSource(fileDescriptor: sock, queue: queue)
        source.setEventHandler { [weak self] in
            guard let self, !self.closed else { return }
            var chunk = [UInt8](repeating: 0, count: 8192)
            let n = read(sock, &chunk, chunk.count)
            if n < 0, errno == EAGAIN || errno == EINTR { return }
            guard n > 0 else {
                self.close()
                onClose()
                return
            }
            self.buffer.append(contentsOf: chunk[0..<n])
            let prompt = Data("ENTER PASSWORD:".utf8)
            var start = self.buffer.startIndex
            while !self.closed {
                if let nl = self.buffer[start...].firstIndex(of: 0x0A) {
                    var line = self.buffer[start..<nl]
                    if line.last == 0x0D { line = line.dropLast() }
                    start = self.buffer.index(after: nl)
                    onLine(String(decoding: line, as: UTF8.self))
                } else if self.buffer[start...].starts(with: prompt) {
                    start += prompt.count
                    onLine("ENTER PASSWORD:")
                } else {
                    break
                }
            }
            self.buffer = Data(self.buffer[start...])
            if self.buffer.count > 65536 {
                self.close()
                onClose()
            }
        }
        source.setCancelHandler { Darwin.close(sock) }
        source.resume()
    }

    /// Whole or not at all: a partial write means openvpn is not reading.
    @discardableResult func send(_ line: String, passing passed: Int32?) -> Bool {
        guard !closed else { return false }
        let data = Data((line + "\n").utf8)
        if let passed { return sendWithDescriptor(socket: fd, data, passing: passed) }
        return data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) } == data.count
    }

    func close() {
        guard !closed else { return }
        closed = true
        source.cancel()
    }
}

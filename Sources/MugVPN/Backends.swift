import Foundation
import MugVPNAppCore
import MugVPNCore
import Security
import ServiceManagement

// The real implementations of MugVPNAppCore's protocols. No decisions here:
// the logic lives in MugVPNAppCore and is tested there with fakes.

final class XPCHelperClient: HelperClient {
    private var connection: NSXPCConnection?

    private func proxy(_ onError: @escaping (Error) -> Void) -> MugVPNHelperProtocol? {
        if connection == nil {
            let c = NSXPCConnection(machServiceName: MugVPNIDs.helperLabel, options: .privileged)
            c.remoteObjectInterface = NSXPCInterface(with: MugVPNHelperProtocol.self)
            c.invalidationHandler = { [weak self] in DispatchQueue.main.async { self?.connection = nil } }
            c.resume()
            connection = c
        }
        return connection?.remoteObjectProxyWithErrorHandler { e in DispatchQueue.main.async { onError(e) } }
            as? MugVPNHelperProtocol
    }

    func start(_ bundle: ProfileBundle, reply: @escaping (Result<(id: String, socket: String), Error>) -> Void) {
        guard let data = try? JSONEncoder().encode(bundle) else {
            return reply(.failure(ProfileError("cannot encode the profile")))
        }
        proxy({ reply(.failure($0)) })?.start(bundle: data) { id, sock, err in
            DispatchQueue.main.async {
                if let id, let sock { reply(.success((id, sock))) } else { reply(.failure(ProfileError(err ?? "the helper refused"))) }
            }
        }
    }

    func stop(_ id: String, reply: @escaping (String?) -> Void) {
        proxy({ reply("\($0.localizedDescription)") })?.stop(connectionID: id) { err in DispatchQueue.main.async { reply(err) } }
    }

    func startPersistent(_ name: String, reply: @escaping (Result<String, Error>) -> Void) {
        proxy({ reply(.failure($0)) })?.startPersistent(name: name) { id, err in
            DispatchQueue.main.async {
                if let id { reply(.success(id)) } else { reply(.failure(ProfileError(err ?? "the helper refused"))) }
            }
        }
    }

    func uninstall(keepProfiles: Bool, reply: @escaping (String?) -> Void) {
        proxy({ reply("\($0.localizedDescription)") })?.uninstall(keepProfiles: keepProfiles) { err in
            DispatchQueue.main.async { reply(err) }
        }
    }

    /// nil when the helper does not answer (an older one has no version call): at most 5 s.
    func version(reply: @escaping (String?) -> Void) {
        var done = false
        let once: (String?) -> Void = { v in DispatchQueue.main.async { if !done { done = true; reply(v) } } }
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) { once(nil) }
        guard let p = proxy({ _ in once(nil) }) else { return once(nil) }
        p.version { once($0) }
    }

    /// No answer: .unavailable (an older helper without the call looks the same from here).
    func restartIfIdle(reply: @escaping (HelperRestart) -> Void) {
        var done = false
        let once: (HelperRestart) -> Void = { v in DispatchQueue.main.async { if !done { done = true; reply(v) } } }
        // What the failure means (an older helper, or a passing one) is for the caller to find out.
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) { once(.unavailable) }
        guard let p = proxy({ _ in once(.unavailable) }) else { return once(.unavailable) }
        p.restartIfIdle { err in
            if err == nil { return once(.restarting) }
            once(err?.hasPrefix("not newer") == true ? .notNewer : .inUse)
        }
    }

    /// A call every helper version has (blocks), within 5 s.
    func reachable(reply: @escaping (Bool) -> Void) {
        var done = false
        let once: (Bool) -> Void = { v in DispatchQueue.main.async { if !done { done = true; reply(v) } } }
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) { once(false) }
        guard let p = proxy({ _ in once(false) }) else { return once(false) }
        p.blocks { _ in once(true) }
    }

    func blocks(reply: @escaping ([String]) -> Void) {
        proxy({ _ in reply([]) })?.blocks { names in DispatchQueue.main.async { reply(names) } }
    }

    func unblock(reply: @escaping (String?) -> Void) {
        proxy({ reply("\($0.localizedDescription)") })?.unblock { err in DispatchQueue.main.async { reply(err) } }
    }

    func suspendBlocks(seconds: Int, reply: @escaping (String?) -> Void) {
        proxy({ reply("\($0.localizedDescription)") })?.suspendBlocks(seconds: seconds) { err in DispatchQueue.main.async { reply(err) } }
    }

    func releaseManagement(_ id: String, reply: @escaping (String?) -> Void) {
        proxy({ reply("\($0.localizedDescription)") })?.releaseManagement(connectionID: id) { err in
            DispatchQueue.main.async { reply(err) }
        }
    }

    func tunnelRequest(_ id: String, kind: String, message: String, reply: @escaping (Result<FileHandle?, Error>) -> Void) {
        proxy({ reply(.failure($0)) })?.tunnelRequest(connectionID: id, kind: kind, message: message) { fd, err in
            DispatchQueue.main.async {
                if let err { reply(.failure(ProfileError(err))) } else { reply(.success(fd)) }
            }
        }
    }

    func list(reply: @escaping ([ConnectionInfo]) -> Void) {
        proxy({ _ in reply([]) })?.list { data in
            let l = (try? JSONDecoder().decode([ConnectionInfo].self, from: data)) ?? []
            DispatchQueue.main.async { reply(l) }
        }
    }
}

/// A management socket; reads on a background queue, delivers on main.
final class UnixSocketLink: ManagementLink {
    /// The ids the helper runs openvpn as (HelperCore.serviceIDBase, serviceIDCount).
    static let serviceIDs: ClosedRange<uid_t> = 470_000_000...(470_000_000 + 4095)
    private let fd: Int32
    private let source: DispatchSourceRead
    /// Writes in order, off the main thread: an openvpn that stops reading cannot freeze the app.
    private let writes = DispatchQueue(label: "mugvpn.management.write")
    private var closed = false   // on `writes`; the descriptor is closed only once this is set (by the read source's end)
    private let onClose: () -> Void
    static let writeDeadline: TimeInterval = 5

    init?(path: String, onData: @escaping (Data) -> Void, onClose: @escaping () -> Void) {
        let sock = socket(AF_UNIX, SOCK_STREAM, 0)
        guard sock >= 0 else { return nil }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else { Darwin.close(sock); return nil }
        withUnsafeMutableBytes(of: &addr.sun_path) { $0.copyBytes(from: bytes) }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(sock, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard rc == 0 else { Darwin.close(sock); return nil }
        // openvpn of MugVPN's (one of its own ids), not whatever a path was made to lead to.
        setNoSigPipe(sock)
        guard let peer = socketPeer(sock), (UnixSocketLink.serviceIDs).contains(peer.uid) else { Darwin.close(sock); return nil }
        // Non-blocking: neither a read nor a write waits on openvpn.
        _ = fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK)
        fd = sock
        self.onClose = onClose
        source = DispatchSource.makeReadSource(fileDescriptor: sock, queue: .global())
        source.setEventHandler { [weak self] in
            var buf = [UInt8](repeating: 0, count: 16384)
            let n = read(sock, &buf, buf.count)
            if n < 0, errno == EAGAIN || errno == EINTR { return }
            if n > 0 {
                let d = Data(buf[0..<n])
                DispatchQueue.main.async { onData(d) }
            } else {
                // Ended: closed through the write queue (no write after this reaches the descriptor).
                self?.writes.async { self?.closeOnQueue(notify: true) }
            }
        }
        // After the last read handler (the source's guarantee); writes stopped already (closed is set first).
        source.setCancelHandler { Darwin.close(sock) }
        source.resume()
    }

    func write(_ data: Data) {
        writes.async { [self] in
            guard !closed else { return }
            let deadline = Date().addingTimeInterval(Self.writeDeadline)
            var off = 0
            data.withUnsafeBytes { raw in
                while off < raw.count {
                    let n = Darwin.write(fd, raw.baseAddress! + off, raw.count - off)
                    if n > 0 { off += n; continue }
                    // Full: wait for room, up to the deadline.
                    guard n < 0, errno == EAGAIN || errno == EINTR, Date() < deadline else { break }
                    var p = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
                    _ = poll(&p, 1, 100)
                }
            }
            // Not taken in time (or gone): the link is dropped, as when openvpn closes it.
            if off < data.count { closeOnQueue(notify: true) }
        }
    }

    func write(_ data: Data, passing passed: Int32, done: @escaping (Bool) -> Void) {
        writes.async { [self] in
            var ok = false
            if !closed {
                // Room for it first (bounded: it is one short line).
                var p = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
                _ = poll(&p, 1, 2000)
                ok = sendWithDescriptor(socket: fd, data, passing: passed)
            }
            DispatchQueue.main.async { done(ok) }
        }
    }

    /// After the writes already asked for (the descriptor closes with the read source).
    func close() { writes.async { [self] in closeOnQueue(notify: false) } }

    /// On `writes` only. - notify: it ended on its own (openvpn gone, or not reading): said like openvpn's close.
    private func closeOnQueue(notify: Bool) {
        guard !closed else { return }
        closed = true
        source.cancel()
        if notify { DispatchQueue.main.async(execute: onClose) }
    }
}

final class UnixSocketTransport: ManagementTransport {
    func open(_ socket: String, onData: @escaping (Data) -> Void, onClose: @escaping () -> Void) -> ManagementLink? {
        UnixSocketLink(path: socket, onData: onData, onClose: onClose)
    }
}

final class MainScheduler: Scheduler {
    func after(_ seconds: TimeInterval, _ f: @escaping () -> Void) {
        DispatchQueue.main.asyncAfter(deadline: .now() + seconds, execute: f)
    }
}

/// Saved passwords in the login keychain, one generic password per profile and key.
final class KeychainStore: SecretStore {
    private let service = "MugVPN"
    private func account(_ p: String, _ k: SecretKey) -> String { "\(p)/\(k.rawValue)" }

    func get(_ profile: String, _ key: SecretKey) -> String? {
        var out: CFTypeRef?
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                kSecAttrAccount as String: account(profile, key), kSecReturnData as String: true]
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return nil }
        return String(data: d, encoding: .utf8)
    }

    /// Updated in place (the old one is never removed first); added if there is none.
    @discardableResult func set(_ profile: String, _ key: SecretKey, _ value: String) -> Bool {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                kSecAttrAccount as String: account(profile, key)]
        let update = SecItemUpdate(q as CFDictionary, [kSecValueData as String: Data(value.utf8)] as CFDictionary)
        guard update == errSecItemNotFound else { return update == errSecSuccess }
        var add = q
        add[kSecValueData as String] = Data(value.utf8)
        add[kSecAttrLabel as String] = "MugVPN: \(profile)"
        return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
    }

    func remove(_ profile: String, _ key: SecretKey) {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                kSecAttrAccount as String: account(profile, key)]
        SecItemDelete(q as CFDictionary)
    }

    func removeAll(_ profile: String) {
        for k in [SecretKey.username, .password, .keyPassword, .proxyUsername, .proxyPassword] { remove(profile, k) }
    }

    /// Every MugVPN item, for uninstalling. - Returns: false when some are still there.
    @discardableResult func removeEverything() -> Bool {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service]
        var status = SecItemDelete(q as CFDictionary)
        while status == errSecSuccess { status = SecItemDelete(q as CFDictionary) }
        return status == errSecItemNotFound
    }
}

final class MemorySecrets: SecretStore {
    var items: [String: String] = [:]
    func get(_ p: String, _ k: SecretKey) -> String? { items["\(p)|\(k.rawValue)"] }
    func set(_ p: String, _ k: SecretKey, _ v: String) -> Bool { items["\(p)|\(k.rawValue)"] = v; return true }
    func remove(_ p: String, _ k: SecretKey) { items["\(p)|\(k.rawValue)"] = nil }
    func removeAll(_ p: String) { items = items.filter { !$0.key.hasPrefix(p + "|") } }
}

/// UserDefaults for the user's choices; managed preferences for forced ones.
final class DefaultsBackend: SettingsBackend {
    let defaults: UserDefaults
    let forced: [String: Any]

    init(defaults: UserDefaults, forced: [String: Any] = [:]) {
        self.defaults = defaults
        self.forced = forced
    }

    func value(_ key: String) -> Any? { forced[key] ?? defaults.object(forKey: key) }
    func set(_ key: String, _ value: Any?) { defaults.set(value, forKey: key) }
    func isForced(_ key: String) -> Bool { forced[key] != nil || defaults.objectIsForced(forKey: key) }
}

final class DefaultsActiveMemory: ActiveMemory {
    let defaults: UserDefaults
    init(defaults: UserDefaults) { self.defaults = defaults }
    var remembered: [String] {
        get { defaults.stringArray(forKey: "reconnect_on_start") ?? [] }
        set { defaults.set(newValue, forKey: "reconnect_on_start") }
    }
}

final class DiskFileSystem: ProfileFileSystem {
    let fm = FileManager.default
    func contents(of dir: String) -> [(name: String, isDirectory: Bool)] {
        ((try? fm.contentsOfDirectory(atPath: dir)) ?? []).filter { !$0.hasPrefix(".") }.map { name in
            var isDir: ObjCBool = false
            fm.fileExists(atPath: dir + "/" + name, isDirectory: &isDir)
            return (name, isDir.boolValue)
        }
    }
    /// A regular file of at most 8 MB (a device or FIFO would hang the app).
    func read(_ path: String) -> Data? {
        guard let a = try? fm.attributesOfItem(atPath: path), a[.type] as? FileAttributeType == .typeRegular,
              (a[.size] as? NSNumber)?.intValue ?? .max <= 8 << 20 else { return nil }
        return fm.contents(atPath: path)
    }
    func exists(_ path: String) -> Bool { fm.fileExists(atPath: path) }
    func realPath(_ path: String) -> String {
        guard let r = Darwin.realpath(path, nil) else { return path }
        defer { free(r) }
        return String(cString: r)
    }
    func write(_ path: String, _ data: Data) throws { try data.write(to: URL(fileURLWithPath: path), options: .atomic) }
    func makeDirectory(_ path: String) throws { try fm.createDirectory(atPath: path, withIntermediateDirectories: false) }
    func move(_ from: String, _ to: String) throws {
        // A rename that only changes letter case: through a temporary name on case-insensitive disks.
        if from.lowercased() == to.lowercased() {
            let tmp = to + ".mugvpn-rename"
            try fm.moveItem(atPath: from, toPath: tmp)
            do {
                try fm.moveItem(atPath: tmp, toPath: to)
            } catch {
                // Back under its old name: no temporary one left behind.
                try? fm.moveItem(atPath: tmp, toPath: from)
                throw error
            }
        } else {
            try fm.moveItem(atPath: from, toPath: to)
        }
    }
    func remove(_ path: String) throws { try fm.removeItem(atPath: path) }
}

/// Reads a profile and the files it names with the user's own rights.
final class DiskBundleReader: ProfileBundleReader {
    let fs: ProfileFileSystem
    init(fs: ProfileFileSystem) { self.fs = fs }
    func bundle(for p: Profile) throws -> ProfileBundle {
        guard let data = fs.read(p.path) else { throw ProfileError("cannot read \(p.path)") }
        let text = String(decoding: data, as: UTF8.self)
        let dir = (p.path as NSString).deletingLastPathComponent
        var files: [String: Data] = [:]
        let directives: [ConfigDirective]
        do { directives = try ConfigParser.parse(text) } catch { throw ProfileError("\(p.name): \(error)") }
        for ref in ProfilePolicy.referencedFiles(directives) {
            let path = ref.hasPrefix("/") ? ref : (dir as NSString).appendingPathComponent(ref)
            guard let d = fs.read(path) else { throw ProfileError("cannot read \(ref), named in \(p.name)") }
            files[ref] = d
        }
        return ProfileBundle(name: p.name, config: text, files: files)
    }
}

enum HelperState: String { case enabled, requiresApproval, notRegistered }

extension HelperSetup {
    var isTestDouble: Bool { false }
}

protocol HelperSetup: AnyObject {
    var state: HelperState { get }
    /// Unregister, then (once launchd has stopped the running helper) register again; the error or nil.
    func reregister(completion: @escaping (Error?) -> Void)
    /// The test mode's stand-in (a testing build only).
    var isTestDouble: Bool { get }
    func register()
    func openLoginItems()
    func unregister()
}

final class SMHelperSetup: HelperSetup {
    let service = SMAppService.daemon(plistName: MugVPNIDs.helperPlist)
    /// A development install (tools/stand/stand.sh helper) is a plain
    /// LaunchDaemon; then the app must not register its own copy.
    var devInstall: Bool { FileManager.default.fileExists(atPath: "/Library/LaunchDaemons/\(MugVPNIDs.helperPlist)") }
    var state: HelperState {
        if devInstall { return .enabled }
        switch service.status {
        case .enabled: return .enabled
        case .requiresApproval: return .requiresApproval
        default: return .notRegistered
        }
    }
    func register() { if !devInstall { try? service.register() } }
    func unregister() { try? service.unregister() }
    /// Register again only from unregister's completion: the running daemon is gone by then.
    func reregister(completion: @escaping (Error?) -> Void) {
        if devInstall { return completion(ProfileError("a development install: run tools/stand/stand.sh helper")) }
        service.unregister { [service] err in
            DispatchQueue.main.async {
                if let err { return completion(err) }
                do { try service.register(); completion(nil) } catch { completion(error) }
            }
        }
    }
    func openLoginItems() { SMAppService.openSystemSettingsLoginItems() }
}

/// The system's HTTP proxy for a host (the "system" proxy setting).
func systemProxy(for host: String) -> (host: String, port: Int)? {
    guard let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue(),
          let url = URL(string: "https://\(host)") else { return nil }
    let proxies = CFNetworkCopyProxiesForURL(url as CFURL, settings).takeRetainedValue() as? [[String: Any]] ?? []
    for p in proxies where (p[kCFProxyTypeKey as String] as? String) == (kCFProxyTypeHTTPS as String)
        || (p[kCFProxyTypeKey as String] as? String) == (kCFProxyTypeHTTP as String) {
        if let h = p[kCFProxyHostNameKey as String] as? String, let port = p[kCFProxyPortNumberKey as String] as? Int {
            return (h, port)
        }
    }
    return nil
}

/// The user's scripts, run as the user with /bin/sh; output to the plan's log. Each in a process group of
/// its own: past its timeout the whole group goes (SIGTERM, then SIGKILL), whatever it started too.
final class ProcessScriptExecutor: ScriptExecutor {
    static let killGrace: TimeInterval = 2

    func run(_ plan: ScriptRunner.Plan, env: [String: String], completion: @escaping (ScriptRunner.Exit) -> Void) {
        let fm = FileManager.default
        try? fm.createDirectory(atPath: (plan.logPath as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        fm.createFile(atPath: plan.logPath, contents: nil)
        var done = false
        let finish: (ScriptRunner.Exit) -> Void = { e in
            DispatchQueue.main.async {
                guard !done else { return }
                done = true
                completion(e)
            }
        }
        let environment = ScriptRunner.processEnvironment(home: NSHomeDirectory(), user: NSUserName(), extra: env)
        guard let pid = Self.spawn(plan.path, log: plan.logPath, cwd: (plan.path as NSString).deletingLastPathComponent,
                                   env: environment) else { return finish(.exited(127)) }
        // Reaped when it ends (its status), whether it is waited for or not.
        let exit = DispatchSource.makeProcessSource(identifier: pid, eventMask: .exit, queue: .global())
        exit.setEventHandler {
            var status: Int32 = 0
            waitpid(pid, &status, 0)
            exit.cancel()
            let code = (status & 0x7f) == 0 ? (status >> 8) & 0xff : 128 + (status & 0x7f)
            finish(.exited(code))
        }
        exit.resume()
        guard plan.waitForExit else { return finish(.exited(0)) }
        DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(plan.timeout)) {
            guard !done else { return }
            finish(.timedOut)
            kill(-pid, SIGTERM)
            // Only a group still there (one gone could have its id again: nothing to kill then).
            DispatchQueue.global().asyncAfter(deadline: .now() + Self.killGrace) { if kill(-pid, 0) == 0 { kill(-pid, SIGKILL) } }
        }
    }

    /// /bin/sh `path` in a new process group (its id: the pid), stdout and stderr to `log`, no stdin.
    private static func spawn(_ path: String, log: String, cwd: String, env: [String: String]) -> pid_t? {
        var actions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&actions)
        defer { posix_spawn_file_actions_destroy(&actions) }
        posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0)
        posix_spawn_file_actions_addopen(&actions, 1, log, O_WRONLY | O_APPEND | O_CREAT, 0o644)
        posix_spawn_file_actions_adddup2(&actions, 1, 2)
        posix_spawn_file_actions_addchdir_np(&actions, cwd)
        var attr: posix_spawnattr_t?
        posix_spawnattr_init(&attr)
        defer { posix_spawnattr_destroy(&attr) }
        posix_spawnattr_setflags(&attr, Int16(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT))
        posix_spawnattr_setpgroup(&attr, 0)
        let argv: [UnsafeMutablePointer<CChar>?] = [strdup("/bin/sh"), strdup(path), nil]
        let envp: [UnsafeMutablePointer<CChar>?] = env.map { strdup("\($0.key)=\($0.value)") } + [nil]
        defer { (argv + envp).forEach { free($0) } }
        var pid: pid_t = 0
        guard posix_spawn(&pid, "/bin/sh", &actions, &attr, argv, envp) == 0 else { return nil }
        return pid
    }
}

/// Profile downloads: https GET with basic authentication.
final class URLSessionFetcher: NSObject, HTTPFetcher, URLSessionDataDelegate {
    private lazy var session = URLSession(configuration: .ephemeral, delegate: self, delegateQueue: nil)
    private struct Pending { var data = Data(); var completion: (Result<HTTPResponse, Error>) -> Void }
    private var pending: [Int: Pending] = [:]
    private let lock = NSLock()

    /// The user's password goes to the server they named, never to another
    /// host a redirect points at.
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        // Only to https: a profile (and the credentials sent for it) never in clear.
        guard request.url?.scheme?.lowercased() == "https" else { return completionHandler(nil) }
        var r = request
        let from = task.originalRequest?.url
        if r.url?.host?.lowercased() != from?.host?.lowercased() || r.url?.scheme != "https" || r.url?.port != from?.port {
            r.setValue(nil, forHTTPHeaderField: "Authorization")
        }
        completionHandler(r)
    }

    /// A profile is small: anything announced or arriving beyond the limit is cut off
    /// while it comes, not after it filled memory.
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        completionHandler(response.expectedContentLength > Int64(ProfileDownloader.maxBytes) ? .cancel : .allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        lock.lock()
        pending[dataTask.taskIdentifier]?.data.append(data)
        let tooBig = (pending[dataTask.taskIdentifier]?.data.count ?? 0) > ProfileDownloader.maxBytes
        lock.unlock()
        if tooBig { dataTask.cancel() }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        lock.lock()
        let p = pending.removeValue(forKey: task.taskIdentifier)
        lock.unlock()
        guard let p else { return }
        let h = task.response as? HTTPURLResponse
        DispatchQueue.main.async {
            if p.data.count > ProfileDownloader.maxBytes || (h?.expectedContentLength ?? 0) > Int64(ProfileDownloader.maxBytes) {
                return p.completion(.failure(ProfileError("the profile the server sent is too large")))
            }
            if let error { return p.completion(.failure(ProfileError(error.localizedDescription))) }
            p.completion(.success(HTTPResponse(status: h?.statusCode ?? 0, body: p.data,
                                               contentDisposition: h?.value(forHTTPHeaderField: "Content-Disposition"))))
        }
    }

    func get(_ url: URL, username: String, password: String, completion: @escaping (Result<HTTPResponse, Error>) -> Void) {
        var r = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 30)
        if !username.isEmpty {
            r.setValue("Basic " + Data("\(username):\(password)".utf8).base64EncodedString(), forHTTPHeaderField: "Authorization")
        }
        let task = session.dataTask(with: r)
        lock.lock()
        pending[task.taskIdentifier] = Pending(completion: completion)
        lock.unlock()
        task.resume()
    }
}

/// netstat, scutil and route as the user runs them (read-only).
final class RealNetworkProbe: NetworkProbe {
    let available = true
    /// At most 5 s per command (a hung one must not stall the checks).
    private func output(_ path: String, _ args: [String]) -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        let done = DispatchSemaphore(value: 0)
        p.terminationHandler = { _ in done.signal() }
        guard (try? p.run()) != nil else { return "" }
        var data = Data()
        let reading = DispatchGroup()
        reading.enter()
        DispatchQueue.global().async {
            data = pipe.fileHandleForReading.readDataToEndOfFile()
            reading.leave()
        }
        if done.wait(timeout: .now() + 5) == .timedOut { p.terminate(); return "" }
        _ = reading.wait(timeout: .now() + 1)
        return String(decoding: data, as: UTF8.self)
    }
    func netstat6() -> String { output("/usr/sbin/netstat", ["-rn", "-f", "inet6"]) }
    func netstat() -> String { output("/usr/sbin/netstat", ["-rn", "-f", "inet"]) }
    func scutilDNS() -> String { output("/usr/sbin/scutil", ["--dns"]) }
    func interface(for ip: String) -> String? {
        let family = ip.contains(":") ? "-inet6" : "-inet"
        return output("/sbin/route", ["-n", "get", family, ip]).components(separatedBy: "\n")
            .first { $0.contains("interface:") }?.components(separatedBy: ":").last?.trimmingCharacters(in: .whitespaces)
    }
}

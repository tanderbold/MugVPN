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

    /// An older helper has no such call: the XPC error (or no answer within 5 s) says so.
    func restartIfIdle(reply: @escaping (HelperRestart) -> Void) {
        var done = false
        let once: (HelperRestart) -> Void = { v in DispatchQueue.main.async { if !done { done = true; reply(v) } } }
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) { once(.unsupported) }
        guard let p = proxy({ _ in once(.unsupported) }) else { return once(.unsupported) }
        p.restartIfIdle { once($0 == nil ? .restarting : .inUse) }
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
        fd = sock
        source = DispatchSource.makeReadSource(fileDescriptor: sock, queue: .global())
        source.setEventHandler { [source] in
            var buf = [UInt8](repeating: 0, count: 16384)
            let n = read(sock, &buf, buf.count)
            if n > 0 {
                let d = Data(buf[0..<n])
                DispatchQueue.main.async { onData(d) }
            } else {
                source.cancel()
                DispatchQueue.main.async { onClose() }
            }
        }
        source.setCancelHandler { Darwin.close(sock) }
        source.resume()
    }

    func write(_ data: Data) {
        data.withUnsafeBytes { raw in
            var off = 0
            while off < raw.count {
                let n = Darwin.write(fd, raw.baseAddress! + off, raw.count - off)
                if n <= 0 { break }
                off += n
            }
        }
    }

    func write(_ data: Data, passing passed: Int32) -> Bool {
        sendWithDescriptor(socket: fd, data, passing: passed)
    }

    func close() { source.cancel() }
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

    func set(_ profile: String, _ key: SecretKey, _ value: String) {
        remove(profile, key)
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                kSecAttrAccount as String: account(profile, key), kSecValueData as String: Data(value.utf8),
                                kSecAttrLabel as String: "MugVPN: \(profile)"]
        SecItemAdd(q as CFDictionary, nil)
    }

    func remove(_ profile: String, _ key: SecretKey) {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                kSecAttrAccount as String: account(profile, key)]
        SecItemDelete(q as CFDictionary)
    }

    func removeAll(_ profile: String) {
        for k in [SecretKey.username, .password, .keyPassword, .proxyUsername, .proxyPassword] { remove(profile, k) }
    }

    /// Every MugVPN item, for uninstalling.
    func removeEverything() {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service]
        while SecItemDelete(q as CFDictionary) == errSecSuccess {}
    }
}

final class MemorySecrets: SecretStore {
    var items: [String: String] = [:]
    func get(_ p: String, _ k: SecretKey) -> String? { items["\(p)|\(k.rawValue)"] }
    func set(_ p: String, _ k: SecretKey, _ v: String) { items["\(p)|\(k.rawValue)"] = v }
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
            try fm.moveItem(atPath: tmp, toPath: to)
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

/// The user's scripts, run as the user with /bin/sh; output to the plan's log.
final class ProcessScriptExecutor: ScriptExecutor {
    func run(_ plan: ScriptRunner.Plan, env: [String: String], completion: @escaping (ScriptRunner.Exit) -> Void) {
        let fm = FileManager.default
        try? fm.createDirectory(atPath: (plan.logPath as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        fm.createFile(atPath: plan.logPath, contents: nil)
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/sh")
        p.arguments = [plan.path]
        p.currentDirectoryURL = URL(fileURLWithPath: (plan.path as NSString).deletingLastPathComponent)
        p.environment = ScriptRunner.processEnvironment(home: NSHomeDirectory(), user: NSUserName(), extra: env)
        let log = FileHandle(forWritingAtPath: plan.logPath)
        p.standardOutput = log
        p.standardError = log
        p.standardInput = FileHandle.nullDevice
        var done = false
        let finish: (ScriptRunner.Exit) -> Void = { e in
            DispatchQueue.main.async {
                guard !done else { return }
                done = true
                completion(e)
            }
        }
        p.terminationHandler = { proc in finish(.exited(proc.terminationStatus)) }
        do { try p.run() } catch { return finish(.exited(127)) }
        guard plan.waitForExit else { return finish(.exited(0)) }
        DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(plan.timeout)) {
            guard !done, p.isRunning else { return }
            p.terminate()
            finish(.timedOut)
        }
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

import Foundation
import MugVPNAppCore
import MugVPNCore
import MugVPNUI
import ServiceManagement

// MugVPN's own backend: the privileged helper over XPC, openvpn's management sockets, the helper's registration.

final class XPCHelperClient: HelperClient {
    #if MUGVPN_TESTING
    /// The helper's own interface, for the test build's command line (an error ends it).
    static func devProxy() -> MugVPNHelperProtocol {
        let c = NSXPCConnection(machServiceName: MugVPNIDs.helperLabel, options: .privileged)
        c.remoteObjectInterface = NSXPCInterface(with: MugVPNHelperProtocol.self)
        c.resume()
        guard let proxy = c.remoteObjectProxyWithErrorHandler({ fail("helper: \($0.localizedDescription)") })
                as? MugVPNHelperProtocol else { fail("no helper proxy") }
        return proxy
    }
    #endif

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
    @discardableResult func unregister() -> Bool {
        (try? service.unregister()) != nil || service.status == .notRegistered || service.status == .notFound
    }
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


import Foundation
import MugVPNAppCore
import MugVPNCore
import ServiceManagement

#if MUGVPN_TESTING

// The developer command line: drives the helper directly, so the
// integration tests (Tests/Integration) can check tunnels over ssh in the
// stand VM without the interface. `MugVPN register|status|connect|...`.

/// Subcommands that select this mode.
let devCommands: Set<String> = ["register", "unregister", "status", "connect", "disconnect", "list", "parse", "serve"]

func fail(_ s: String) -> Never {
    FileHandle.standardError.write(Data("mugvpn: \(s)\n".utf8))
    exit(1)
}

let daemon = SMAppService.daemon(plistName: MugVPNIDs.helperPlist)

func statusText(_ s: SMAppService.Status) -> String {
    switch s {
    case .notRegistered: return "not registered"
    case .enabled: return "enabled"
    case .requiresApproval: return "requires approval (System Settings > General > Login Items)"
    case .notFound: return "not found"
    @unknown default: return "unknown (\(s.rawValue))"
    }
}

func helper() -> MugVPNHelperProtocol {
    let c = NSXPCConnection(machServiceName: MugVPNIDs.helperLabel, options: .privileged)
    c.remoteObjectInterface = NSXPCInterface(with: MugVPNHelperProtocol.self)
    c.resume()
    guard let proxy = c.remoteObjectProxyWithErrorHandler({ fail("helper: \($0.localizedDescription)") })
            as? MugVPNHelperProtocol else { fail("no helper proxy") }
    return proxy
}

/// Run an async XPC call and wait for its reply.
func wait<T>(_ body: (@escaping (T) -> Void) -> Void) -> T {
    let sem = DispatchSemaphore(value: 0)
    var result: T?
    body { result = $0; sem.signal() }
    if sem.wait(timeout: .now() + 30) == .timedOut { fail("helper did not answer") }
    return result!
}

/// Read a profile and the files it names, with the user's own rights.
func loadBundle(_ path: String) -> ProfileBundle {
    let url = URL(fileURLWithPath: path)
    guard let text = try? String(contentsOf: url, encoding: .utf8) else { fail("cannot read \(path)") }
    let directives: [ConfigDirective]
    do { directives = try ConfigParser.parse(text) } catch { fail("\(path): \(error)") }
    var files: [String: Data] = [:]
    for name in ProfilePolicy.referencedFiles(directives) {
        let f = name.hasPrefix("/") ? URL(fileURLWithPath: name) : url.deletingLastPathComponent().appendingPathComponent(name)
        guard let data = try? Data(contentsOf: f) else { fail("cannot read \(f.path), named in the profile") }
        files[name] = data
    }
    return ProfileBundle(name: url.deletingPathExtension().lastPathComponent, config: text, files: files)
}

/// Drive one connection over management until it is up (or fails).
/// Credentials for tests come from MUGVPN_USER / MUGVPN_PASS.
/// - serve: keep answering (openvpn's tunnel requests, passwords) until openvpn goes away.
func bringUp(socket: String, connectionID: String? = nil, timeout: TimeInterval, serve: Bool = false) -> Bool {
    var mgmt: ManagementConnection?
    let deadline = Date().addingTimeInterval(timeout)
    while mgmt == nil {
        mgmt = try? ManagementConnection(socketPath: socket, password: nil)
        if mgmt == nil {
            if Date() > deadline { fail("cannot open management socket \(socket)") }
            usleep(100_000)
        }
    }
    let m = mgmt!
    do {
        if serve {
            while let line = try m.readLine() { _ = try answer(m, line, connectionID: connectionID) }
            return true
        }
        try m.send("state on")
        try m.send("log on")
        // Reconnects (SIGUSR1) must not wait for the app: it may be gone by then.
        try m.send("hold off")
        try m.send("hold release")
        while let line = try m.readLine() {
            if Date() > deadline { print("timeout"); return false }
            switch ManagementMessage.parse(line) {
            case .realtime("STATE", let payload):
                guard let st = ManagementState(payload: payload) else { break }
                print("state: \(st.name) \(st.localIP)")
                if st.name == "CONNECTED" {
                    print(st.description == "SUCCESS" ? "connected, ip \(st.localIP)" : "connected with errors")
                    return st.description == "SUCCESS"
                }
                if st.name == "EXITING" { return false }
            case .realtime("PASSWORD", let payload):
                if payload.hasPrefix("Need 'Auth'") {
                    let env = ProcessInfo.processInfo.environment
                    try m.send("username \"Auth\" \(managementQuote(env["MUGVPN_USER"] ?? ""))")
                    try m.send("password \"Auth\" \(managementQuote(env["MUGVPN_PASS"] ?? ""))")
                } else if payload.hasPrefix("Verification Failed") {
                    print("auth failed: \(payload)")
                    return false
                } else {
                    print("password request not handled yet: \(payload)")
                    return false
                }
            case .realtime("LOG", let payload):
                if ProcessInfo.processInfo.environment["MUGVPN_VERBOSE"] != nil { print("log: \(payload)") }
            case .realtime("HOLD", _):
                try m.send("hold release")
            case .realtime("NEED-OK", _):
                guard try answer(m, line, connectionID: connectionID) else { return false }
            default:
                break
            }
        }
    } catch {
        print("management: \(error)")
    }
    return false
}

/// Answer openvpn's requests that need no decision here: false if one could not be.
func answer(_ m: ManagementConnection, _ line: String, connectionID: String?) throws -> Bool {
    switch ManagementMessage.parse(line) {
    case .realtime("NEED-OK", let payload):
        // The unprivileged openvpn's requests (OPENTUN, ROUTE...), through the helper.
        guard case .needOK(let name, let msg) = ManagementEvent.parse(type: "NEED-OK", payload: payload),
              ConnectionController.tunnelRequestNames.contains(name), let id = connectionID else {
            print("request not handled: \(payload)")
            return false
        }
        let (fd, err): (FileHandle?, String?) = wait { done in
            helper().tunnelRequest(connectionID: id, kind: name, message: msg) { done(($0, $1)) }
        }
        if let err { print("refused: \(name) \(msg): \(err)") }
        if let fd, err == nil {
            try m.send("needok '\(name)' ok", passing: fd.fileDescriptor)
        } else {
            try m.send("needok '\(name)' \(err == nil && name != "OPENTUN" ? "ok" : "cancel")")
        }
    case .realtime("PASSWORD", let payload) where payload.hasPrefix("Need 'Auth'"):
        let env = ProcessInfo.processInfo.environment
        try m.send("username \"Auth\" \(managementQuote(env["MUGVPN_USER"] ?? ""))")
        try m.send("password \"Auth\" \(managementQuote(env["MUGVPN_PASS"] ?? ""))")
    case .realtime("HOLD", _):
        try m.send("hold release")
    default:
        break
    }
    return true
}

func runDevCLI(_ args: [String]) -> Never {
switch args.first {
case "register":
    do { try daemon.register() } catch { print("register failed: \(error)") }
    print("helper: \(statusText(daemon.status))")
case "unregister":
    do { try daemon.unregister() } catch { print("unregister failed: \(error)") }
    print("helper: \(statusText(daemon.status))")
case "status":
    print("helper: \(statusText(daemon.status))")
    if daemon.status == .enabled || args.contains("--xpc") {
        print("helper version: \(wait { helper().version(reply: $0) })")
    }
case "connect":
    // --no-wait: start the tunnel and return without driving it (tests).
    let noWait = args.contains("--no-wait")
    let rest = args.dropFirst().filter { $0 != "--no-wait" && $0 != "--split-dns" }
    guard let profile = rest.first else { fail("usage: connect [--no-wait] [--split-dns] <profile.ovpn>") }
    var bundle = loadBundle(profile)
    bundle.splitDNS = args.contains("--split-dns")
    let data = try! JSONEncoder().encode(bundle)
    let (id, sock, err): (String?, String?, String?) = wait { done in
        helper().start(bundle: data) { done(($0, $1, $2)) }
    }
    if let err { fail("refused: \(err)") }
    print("id: \(id!)")
    if noWait { exit(0) }
    let up = bringUp(socket: sock!, connectionID: id, timeout: 60)
    // openvpn without root needs its management client after this too (reconnects,
    // teardown): a detached `serve` takes over, as the app would.
    var attr: posix_spawnattr_t?
    posix_spawnattr_init(&attr)
    posix_spawnattr_setflags(&attr, Int16(POSIX_SPAWN_SETSID))
    var actions: posix_spawn_file_actions_t?
    posix_spawn_file_actions_init(&actions)
    for fd: Int32 in 0...2 { posix_spawn_file_actions_addopen(&actions, fd, "/dev/null", fd == 0 ? O_RDONLY : O_WRONLY, 0) }
    let me = CommandLine.arguments[0]
    let argv: [UnsafeMutablePointer<CChar>?] = [strdup(me), strdup("serve"), strdup(sock!), strdup(id!), nil]
    var pid: pid_t = 0
    if up { _ = posix_spawn(&pid, me, &actions, &attr, argv, environ) }
    exit(up ? 0 : 2)
case "serve":
    guard args.count == 3 else { fail("usage: serve <socket> <id>") }
    // The connecting command may still hold the socket for a moment.
    usleep(300_000)
    _ = bringUp(socket: args[1], connectionID: args[2], timeout: 10, serve: true)
case "disconnect":
    guard args.count >= 2 else { fail("usage: disconnect <id>") }
    if let err = wait({ helper().stop(connectionID: args[1], reply: $0) }) { fail(err) }
    print("stopping \(args[1])")
case "parse":
    // For Tests/Integration/test_cfg_diff.py: our reading of a profile, as JSON.
    guard args.count >= 2, let text = try? String(contentsOfFile: args[1], encoding: .utf8) else { fail("usage: parse <file>") }
    var out: [String: Any] = [:]
    do {
        let d = try ConfigParser.parse(text)
        out = ["ok": true, "serialized": ConfigParser.serialize(d),
               "directives": d.map { ["name": $0.name, "args": $0.args, "inline": $0.inline as Any] }]
    } catch {
        out = ["ok": false, "error": "\(error)"]
    }
    print(String(decoding: try! JSONSerialization.data(withJSONObject: out, options: [.sortedKeys]), as: UTF8.self))
case "list":
    let data = wait { helper().list(reply: $0) }
    let list = (try? JSONDecoder().decode([ConnectionInfo].self, from: data)) ?? []
    for c in list { print("\(c.id)  \(c.name)  pid \(c.pid)") }
default:
    print("""
    usage: MugVPN register | unregister | status [--xpc]
           MugVPN connect [--no-wait] <profile.ovpn> | disconnect <id> | list
    """)
}
exit(0)
}
#endif

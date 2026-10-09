import Foundation
import MugVPNCore
import MugVPNHelperCore
import Security

/// MugVPN's privileged helper: a LaunchDaemon that starts and stops openvpn
/// for the signed MugVPN app. The decisions are HelperCore's; this file wires
/// it to XPC, the real system and the pinned binaries.

func log(_ s: String) {
    FileHandle.standardError.write(Data("[helper] \(s)\n".utf8))
}

// A socket whose other end is gone gives an error, never a signal that ends the helper.
signal(SIGPIPE, SIG_IGN)
let queue = DispatchQueue(label: "mugvpn.helper")
let system = RealSystem(queue: queue)
let core = HelperCore(system: system)
// Once uninstalled (every request answered): leave launchd's list too (a
// development install has no SMAppService to do it) and exit.
core.onUninstalled = {
    queue.asyncAfter(deadline: .now() + 0.5) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        p.arguments = ["bootout", "system/" + MugVPNIDs.helperLabel]
        try? p.run()
        exit(0)
    }
}

/// The helper's own bundle: Contents/MacOS/MugVPNHelper -> Contents.
let contentsDir = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath()
    .deletingLastPathComponent().deletingLastPathComponent()

func checkSignature(_ requirement: String) -> (String) throws -> Void {
    return { path in
        var code: SecStaticCode?
        var req: SecRequirement?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess, let code,
              SecRequirementCreateWithString(requirement as CFString, [], &req) == errSecSuccess, let req else {
            throw HelperCoreError.message("cannot read the signature of \(path)")
        }
        // Strict: without it, data appended after the signature goes unnoticed.
        let rc = SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate), req)
        guard rc == errSecSuccess else { throw HelperCoreError.message("\(path) failed its signature check (\(rc))") }
    }
}

final class Service: NSObject, MugVPNHelperProtocol {
    private var caller: UInt32 { NSXPCConnection.current()?.effectiveUserIdentifier ?? UInt32.max }

    func version(reply: @escaping (String) -> Void) {
        reply(MugVPNIDs.helperVersion)
    }

    func start(bundle: Data, reply: @escaping (String?, String?, String?) -> Void) {
        let uid = caller
        queue.async {
            do {
                let (id, sock) = try core.start(bundle: bundle, uid: uid)
                log("started \(id) for uid \(uid)")
                reply(id, sock, nil)
            } catch {
                log("start refused for uid \(uid): \(error)")
                reply(nil, nil, "\(error)")
            }
        }
    }

    func stop(connectionID: String, reply: @escaping (String?) -> Void) {
        let uid = caller
        queue.async { reply(core.stop(id: connectionID, uid: uid)) }
    }

    func startPersistent(name: String, reply: @escaping (String?, String?) -> Void) {
        let uid = caller
        queue.async {
            do { reply(try core.startPersistent(name: name, uid: uid), nil) } catch { reply(nil, "\(error)") }
        }
    }

    func uninstall(keepProfiles: Bool, reply: @escaping (String?) -> Void) {
        let uid = caller
        queue.async {
            do {
                try core.uninstall(uid: uid, keepProfiles: keepProfiles) {
                    log("uninstalled by uid \(uid)")
                    reply(nil)
                }
            } catch {
                reply("\(error)")
            }
        }
    }

    func list(reply: @escaping (Data) -> Void) {
        let uid = caller
        queue.async { reply((try? JSONEncoder().encode(core.list(uid: uid))) ?? Data("[]".utf8)) }
    }

    func blocks(reply: @escaping ([String]) -> Void) {
        let uid = caller
        queue.async { reply(core.locks(uid: uid)) }
    }

    func unblock(reply: @escaping (String?) -> Void) {
        let uid = caller
        queue.async { reply(core.unblock(uid: uid)) }
    }

    func suspendBlocks(seconds: Int, reply: @escaping (String?) -> Void) {
        let uid = caller
        queue.async { reply(core.suspendBlocks(uid: uid, seconds: TimeInterval(seconds))) }
    }

    func releaseManagement(connectionID: String, reply: @escaping (String?) -> Void) {
        let uid = caller
        queue.async { reply(core.releaseManagement(id: connectionID, uid: uid)) }
    }

    func tunnelRequest(connectionID: String, kind: String, message: String,
                       reply: @escaping (FileHandle?, String?) -> Void) {
        let uid = caller
        queue.async {
            do {
                let r = try core.tunnelRequest(id: connectionID, uid: uid, kind: kind, message: message)
                // XPC passes a copy of the descriptor; ours is closed with the handle.
                reply(r.fd.map { FileHandle(fileDescriptor: $0, closeOnDealloc: true) }, nil)
            } catch {
                if "\(error)" != HelperCore.noSuchConnection { log("\(kind) refused for \(connectionID) (uid \(uid)): \(error)") }
                reply(nil, "\(error)")
            }
        }
    }
}

final class ListenerDelegate: NSObject, NSXPCListenerDelegate {
    let service = Service()
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection c: NSXPCConnection) -> Bool {
        c.exportedInterface = NSXPCInterface(with: MugVPNHelperProtocol.self)
        c.exportedObject = service
        c.resume()
        return true
    }
}

do {
    try queue.sync {
        try core.prepareDirectories()
        try HelperCore.installPinned(from: contentsDir.appendingPathComponent("Helpers/openvpn").path,
                                     to: HelperPaths.standard.openvpn, system: system,
                                     check: checkSignature(BuildPins.openvpnRequirement))
        // What older versions installed and nothing runs any more.
        for old in ["openvpn-root", "dns-updown"] { system.remove(MugVPNIDs.libexecDir + "/" + old) }
        try core.prepareRunDirectory()
        core.startPersistentProfiles()
    }
} catch {
    log("cannot prepare: \(error)")
    // A clean exit: KeepAlive restarts only crashes, and a refusal (a tampered
    // bundle, a foreign directory) would only repeat itself.
    exit(0)
}

// launchd stops the helper with SIGTERM: stop every tunnel first.
signal(SIGTERM, SIG_IGN)
let termSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .global())
termSource.setEventHandler {
    queue.sync { core.stopAll() }
    let deadline = Date().addingTimeInterval(HelperCore.stopGrace + 2)
    while Date() < deadline, queue.sync(execute: { !core.isEmpty }) { usleep(100_000) }
    log("shut down")
    exit(0)
}
termSource.resume()

let delegate = ListenerDelegate()
let listener = NSXPCListener(machServiceName: MugVPNIDs.helperLabel)
// Only the MugVPN app may talk to the helper (checked by the system per connection).
listener.setConnectionCodeSigningRequirement(BuildPins.clientRequirement)
listener.delegate = delegate
listener.resume()
log("listening as \(MugVPNIDs.helperLabel), version \(MugVPNIDs.helperVersion)")
dispatchMain()

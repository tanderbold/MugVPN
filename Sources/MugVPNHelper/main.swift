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
#if MUGVPN_TESTING
// The stand: a version to pretend to run (root's file), so that an update can be tried (INT-46).
let pretend = MugVPNIDs.supportDir + "/test-running-version"
if let info = system.fileInfo(pretend), info.rootOnly, let d = system.readFile(pretend) {
    core.runningVersion = String(decoding: d, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
}
#endif
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

/// The helper's own bundle: <app>/Contents/MacOS/MugVPNHelper -> <app>/Contents, from the process's real
/// path (launchd gives a registered service a relative argv[0]: that made it /Contents in 0.2.2).
let contentsDir = URL(fileURLWithPath: HelperPaths.executablePath().flatMap(HelperPaths.contentsDirectory(ofExecutable:)) ?? {
    // Not inside a bundle: nothing to install from.
    FileHandle.standardError.write(Data("[helper] cannot find its own bundle\n".utf8))
    exit(0)
}())

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

    func restartIfIdle(reply: @escaping (String?) -> Void) {
        // The version of the bundle the helper comes from, as it is on disk now (an update replaced it).
        let installed = (NSDictionary(contentsOf: contentsDir.appendingPathComponent("Info.plist")) as? [String: Any])?["CFBundleShortVersionString"] as? String
        queue.async {
            switch core.beginRestartIfIdle(installed: installed) {
            case .notNewer: return reply("not newer: the helper on disk is not newer than this one")
            case .inUse: return reply("in use: it is updated once no connection or block needs it")
            case .restart: break
            }
            reply(nil)
            log("idle: exiting so that the updated helper starts")
            // A clean exit: launchd starts the helper again on the next call (from the app's bundle).
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.5) { exit(0) }
        }
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

// Dragged to the Trash: the system part goes with it (macOS runs no uninstaller). Looked at every 15 s.
var trashWatch = TrashWatch()
let trashTimer = DispatchSource.makeTimerSource(queue: queue)
trashTimer.schedule(deadline: .now() + 15, repeating: 15)
trashTimer.setEventHandler {
    let inPlace = FileManager.default.fileExists(atPath: contentsDir.appendingPathComponent("Info.plist").path)
    guard trashWatch.look(bundleInPlace: inPlace, runningFrom: HelperPaths.executablePath() ?? "",
                          now: ProcessInfo.processInfo.systemUptime) else { return }
    trashTimer.cancel()
    log("the app is in the Trash: removing MugVPN's system part (profiles stay)")
    let homes = ((try? FileManager.default.contentsOfDirectory(atPath: "/Users")) ?? [])
        .filter { !$0.hasPrefix(".") && $0 != "Shared" }.map { "/Users/" + $0 }
    core.uninstallMovedToTrash(homes: homes)
}
trashTimer.resume()
log("listening as \(MugVPNIDs.helperLabel), version \(MugVPNIDs.helperVersion)")
dispatchMain()

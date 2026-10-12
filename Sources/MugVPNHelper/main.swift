import Foundation
import OSLog
import ServiceManagement
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
// Once uninstalled (every request answered, everything removed and checked): launchd lets go of the helper. Its
// registration through SMAppService (the app's) goes, so that launchd does not start it again at boot (the app may be
// in the Trash, unable to do it), then launchd's list (a development install has no registration). Off the helper's
// queue (launchd's SIGTERM, which may come meanwhile, waits on that queue). Not done, or not known to be done: the
// helper stays and tries again a minute later (started again before that from the Trash, it finds the app gone).
let helperService = SMAppService.daemon(plistName: MugVPNIDs.helperPlist)
enum LaunchdJob { case absent, present, unknown }
func launchdJob() -> LaunchdJob {
    let r = system.run("/bin/launchctl", ["print", "system/" + MugVPNIDs.helperLabel], input: nil, timeout: 10)
    if r.status == 0 { return .present }
    // 113: no such service (said so); anything else (not run, timed out, another error) tells nothing.
    if r.status == 113 || r.output.contains("Could not find service") { return .absent }
    return .unknown
}
func leaveLaunchd() {
    func again(_ why: String) {
        log("\(why), trying again in a minute")
        DispatchQueue.global().asyncAfter(deadline: .now() + 60, execute: leaveLaunchd)
    }
    if helperService.status == .enabled || helperService.status == .requiresApproval {
        do { try helperService.unregister() } catch { return again("could not unregister: \(error)") }
    }
    if launchdJob() != .absent {
        // (Gone from the list, launchd ends this process with SIGTERM before this returns.)
        _ = system.run("/bin/launchctl", ["bootout", "system/" + MugVPNIDs.helperLabel], input: nil, timeout: 30)
        switch launchdJob() {
        case .absent: break
        case .present: return again("launchd still lists the helper")
        case .unknown: return again("could not ask launchd whether it still lists the helper")
        }
    }
    exit(0)
}
// Also to the system log, which keeps it (the helper's own log may be gone with an uninstall).
let systemLog = Logger(subsystem: MugVPNIDs.helperLabel, category: "helper")
core.onNote = { note in
    log(note)
    systemLog.notice("MugVPN: \(note, privacy: .public)")
}
/// Uninstalled (everything removed and checked): nothing is armed again on the way out.
var uninstalled = false
core.onUninstalled = {
    uninstalled = true
    DispatchQueue.global().asyncAfter(deadline: .now() + 0.5, execute: leaveLaunchd)
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
                try core.uninstall(uid: uid, keepProfiles: keepProfiles) { refusal in
                    log(refusal.map { "not uninstalled: \($0)" } ?? "uninstalled by uid \(uid)")
                    reply(refusal)
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

/// Where the app is installed: recorded while the helper runs from it, read back when it runs from the Trash.
var appContents: String?
/// Where the helper runs now, and whether the app is (still, or again) where it was installed (started again from
/// the Trash: where it was installed, a replacement there keeps it).
func whereabouts() -> (running: String, inPlace: Bool) {
    (HelperPaths.executablePath() ?? "", appContents.map { FileManager.default.fileExists(atPath: $0 + "/Info.plist") } ?? false)
}

// launchd stops the helper with SIGTERM: stop every tunnel first. Armed before anything is prepared (a tunnel
// started there, or an uninstall finished, must not meet the default action).
signal(SIGTERM, SIG_IGN)
let termSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .global())
termSource.setEventHandler {
    // Stopped (a restart, a shutdown) with the app in the Trash: the boot cleanup is kept before anything else.
    let w = whereabouts()
    queue.sync {
        if !uninstalled, HelperPaths.isInTrash(w.running), !w.inPlace { core.bootCleanup(armed: true, helper: w.running, app: appContents) }
    }
    queue.sync { core.stopAll() }
    let deadline = Date().addingTimeInterval(HelperCore.stopGrace + 2)
    while Date() < deadline, queue.sync(execute: { !core.isEmpty }) { usleep(100_000) }
    log("shut down")
    exit(0)
}
termSource.resume()
do {
    try queue.sync {
        try core.prepareDirectories()
        appContents = core.appLocation(running: contentsDir.path)
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


let delegate = ListenerDelegate()
let listener = NSXPCListener(machServiceName: MugVPNIDs.helperLabel)
// Only the MugVPN app may talk to the helper (checked by the system per connection).
listener.setConnectionCodeSigningRequirement(BuildPins.clientRequirement)
listener.delegate = delegate
listener.resume()

// Dragged to the Trash: the system part goes with it (macOS runs no uninstaller). Looked at when the bundle is
// moved or deleted, at start, and every 15 s.
var bundleWatchKept: DispatchSourceFileSystemObject?
var trashWatch = TrashWatch()
let trashTimer = DispatchSource.makeTimerSource(queue: queue)
var trashDone = false
func lookAtTrash() {
    guard !trashDone, !uninstalled else { return }
    let w = whereabouts()
    let due = trashWatch.look(bundleInPlace: w.inPlace, runningFrom: w.running, now: ProcessInfo.processInfo.systemUptime)
    // From its first sight in the Trash: kept for the next boot (an emptied Trash takes the helper with it).
    core.bootCleanup(armed: trashWatch.counting, helper: w.running, app: appContents)
    guard due else { return }
    trashDone = true
    trashTimer.cancel()
    log("the app is in the Trash: removing MugVPN's system part (profiles stay)")
    core.uninstallMovedToTrash()
}
trashTimer.schedule(deadline: .now() + 15, repeating: 15)
trashTimer.setEventHandler(handler: lookAtTrash)
trashTimer.resume()
queue.async(execute: lookAtTrash)
// The bundle's own folder: a move (to the Trash) or deletion is seen at once.
let bundleFD = open(contentsDir.deletingLastPathComponent().path, O_EVTONLY)
if bundleFD >= 0 {
    let bundleWatch = DispatchSource.makeFileSystemObjectSource(fileDescriptor: bundleFD, eventMask: [.rename, .delete], queue: queue)
    bundleWatch.setEventHandler(handler: lookAtTrash)
    bundleWatch.resume()
    bundleWatchKept = bundleWatch
}
log("listening as \(MugVPNIDs.helperLabel), version \(MugVPNIDs.helperVersion)")
dispatchMain()

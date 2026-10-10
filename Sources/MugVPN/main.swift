import AppKit
import MugVPNAppCore
import SystemConfiguration
import MugVPNCore

// MugVPN: a menu bar app (the interface) or, with a developer subcommand,
// a command-line driver for the helper (DevCLI.swift).

/// The test build (tools/build.sh with MUGVPN_TESTING=1): the E2E socket and
/// the developer subcommands exist only there. A release build ignores them,
/// whatever its environment says.
#if MUGVPN_TESTING
let testingBuild = true
#else
let testingBuild = false
#endif

let rawArgs = Array(CommandLine.arguments.dropFirst())
#if MUGVPN_TESTING
if let first = rawArgs.first, devCommands.contains(first) { runDevCLI(rawArgs) }
#endif

/// Hand a --command to the running app (through its own user's socket) and report what it did.
/// - Returns: the exit code (CommandReply.Code).
func sendCommand(_ args: [String], answerWithin: TimeInterval = 30) -> Int32 {
    guard let r = CommandChannel.send(args, answerWithin: answerWithin) else {
        FileHandle.standardError.write(Data("MugVPN did not answer\n".utf8))
        return Int32(CommandReply.Code.notRunning.rawValue)
    }
    if let p = r.profiles {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let d = try? enc.encode(p) { print(String(decoding: d, as: UTF8.self)) }
    }
    if let e = r.error { FileHandle.standardError.write(Data("MugVPN: \(e)\n".utf8)) }
    return Int32(r.code.rawValue)
}
let env = ProcessInfo.processInfo.environment
let e2e = testingBuild && env["MUGVPN_E2E"] == "1"

var startRequest = CommandLineRequest.parse(rawArgs)
switch startRequest {
case .help:
    print(CommandLineRequest.usageText)
    exit(0)
case .error(let msg):
    FileHandle.standardError.write(Data((msg + "\n").utf8))
    exit(2)
case .uninstall(let confirmed, let keep):
    let user = UninstallPlan.userPaths(home: NSHomeDirectory(), keepProfiles: keep)
    // Built step by step: the one-expression form crashed in release builds (Swift optimizer, 2026-10-07).
    var listed: [String] = [MugVPNIDs.runDir, MugVPNIDs.libexecDir, "/Library/Logs/MugVPN",
                            "/Library/LaunchDaemons/" + MugVPNIDs.helperPlist]
    if !keep { listed.append(MugVPNIDs.supportDir) }
    listed.append(contentsOf: user)
    listed.append("saved passwords (Keychain)")
    listed.append(Bundle.main.bundlePath + " (to the Trash)")
    guard confirmed else {
        print("MugVPN --uninstall would stop every tunnel and remove:\n  " + listed.joined(separator: "\n  ")
              + "\nRun it again with --yes to go ahead" + (keep ? "." : ", or add --keep-profiles to keep your profiles."))
        exit(1)
    }
    let others = NSRunningApplication.runningApplications(withBundleIdentifier: MugVPNIDs.appBundleID)
        .filter { $0.processIdentifier != ProcessInfo.processInfo.processIdentifier }
    if !others.isEmpty { _ = CommandChannel.send(["exit"], answerWithin: 30) }
    let services = RealServices()
    var result: String??
    // Kept until it answers: the reply comes on its connection.
    let client = XPCHelperClient()
    client.uninstall(keepProfiles: keep) { result = .some($0) }
    let deadline = Date().addingTimeInterval(60)
    while result == nil && Date() < deadline { RunLoop.main.run(until: Date().addingTimeInterval(0.1)) }
    withExtendedLifetime(client) {}
    if let err = result ?? "the helper did not answer" {
        FileHandle.standardError.write(Data(("MugVPN: cannot uninstall: \(err)\n"
            + "To remove MugVPN's system part without the helper, as an administrator:\n  sudo sh -c \""
            + UninstallPlan.systemRemovalScript(keepProfiles: keep) + "\"\n").utf8))
        exit(1)
    }
    services.helperSetup.unregister()
    services.removeUserData(user)
    services.moveAppToTrash()
    print("MugVPN is uninstalled.")
    exit(0)
case .command(let c, let wait):
    let others = NSRunningApplication.runningApplications(withBundleIdentifier: MugVPNIDs.appBundleID)
        .filter { $0.processIdentifier != ProcessInfo.processInfo.processIdentifier }
    if others.isEmpty {
        switch CommandLineRequest.withoutInstance(c) {
        case .done: exit(0)
        case .notRunning:
            FileHandle.standardError.write(Data("MugVPN is not running\n".utf8))
            exit(Int32(CommandReply.Code.notRunning.rawValue))
        case .launchFirst:
            // Started on its own (this process only reports): the command then goes to it.
            let cfg = NSWorkspace.OpenConfiguration()
            cfg.activates = false
            cfg.createsNewApplicationInstance = true
            var launched = false
            NSWorkspace.shared.openApplication(at: Bundle.main.bundleURL, configuration: cfg) { _, _ in launched = true }
            let until = Date().addingTimeInterval(15)
            while !launched && Date() < until { RunLoop.main.run(until: Date().addingTimeInterval(0.1)) }
        }
    }
    // An import waits for its owner's answer in MugVPN.
    let within: TimeInterval
    if case .importFile = c { within = 600 } else { within = (wait ?? 20) + 10 }
    exit(sendCommand(Array(CommandLineRequest.ownArguments(rawArgs).dropFirst()), answerWithin: within))
default:
    // Already running (one app per user: a second would take the command socket over): hand it on.
    // (Not the test mode's app: tests run it beside a real one.)
    if !e2e, let forward = CommandLineRequest.forwardedToRunning(startRequest),
       !NSRunningApplication.runningApplications(withBundleIdentifier: MugVPNIDs.appBundleID)
           .filter({ $0.processIdentifier != ProcessInfo.processInfo.processIdentifier }).isEmpty {
        if forward.isEmpty { exit(0) }
        exit(sendCommand(forward, answerWithin: forward.first == "import" ? 600 : 30))
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    var controller: AppController!

    /// However the app is asked to end (logging out, a restart, terminate from elsewhere): tunnels
    /// are disconnected and remembered first, as the Quit item does.
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let controller, !controller.quitApproved else { return .terminateNow }
        controller.manager.appQuitting { [weak controller] in
            controller?.quitApproved = true
            // After .terminateLater has been returned (appQuitting may be done at once).
            DispatchQueue.main.async { NSApp.reply(toApplicationShouldTerminate: true) }
        }
        return .terminateLater
    }
    #if MUGVPN_TESTING
    var e2eServer: E2EServer?
    #endif

    func applicationDidFinishLaunching(_ note: Notification) {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let defaults: UserDefaults
        let services: Services
        let helper: HelperClient
        let transport: ManagementTransport
        let secrets: SecretStore
        var forced: [String: Any] = [:]
        var userDir = home + "/Library/Application Support/MugVPN/config"
        var systemDir = MugVPNIDs.supportDir + "/config"
        var autoDir = MugVPNIDs.autoDir
        var logText: (ActiveConnection) -> String = { c in
            guard let id = c.helperID else { return "" }
            return (try? String(contentsOfFile: "\(MugVPNIDs.runDir)/\(id)/openvpn.log", encoding: .utf8)) ?? ""
        }
        #if MUGVPN_TESTING
        var backend: E2EBackend?
        #endif
        if e2e {
            #if MUGVPN_TESTING
            // Screenshots in either appearance, whatever the VM's own is.
            switch env["MUGVPN_E2E_APPEARANCE"] {
            case "Light": NSApp.appearance = NSAppearance(named: .aqua)
            case "Dark": NSApp.appearance = NSAppearance(named: .darkAqua)
            default: break
            }
            let b = E2EBackend()
            let s = E2EServices(backend: b)
            backend = b
            services = s
            let real = env["MUGVPN_E2E_BACKEND"] == "real"
            helper = real ? XPCHelperClient() : b
            transport = real ? UnixSocketTransport() : b
            secrets = MemorySecrets()
            defaults = UserDefaults(suiteName: "com.mugvpn.app.e2e")!
            if let json = env["MUGVPN_E2E_FORCED"], let d = try? JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any] {
                forced = d
            }
            let e2eHome = env["MUGVPN_E2E_HOME"] ?? NSTemporaryDirectory()
            userDir = e2eHome + "/config"
            systemDir = e2eHome + "/system-config"
            autoDir = e2eHome + "/config-auto"
            logText = { [b] c in b.logs[c.profile.name] ?? "" }
            if env["MUGVPN_E2E_BACKEND"] == "real" {
                // Journeys (Tests/UI/test_journeys.py): the interface driven by the test socket,
                // tunnels by the real helper. URLs and notifications are still only logged.
                s.realHelperSetup = SMHelperSetup()
                logText = { c in
                    guard let id = c.helperID else { return "" }
                    return (try? String(contentsOfFile: "\(MugVPNIDs.runDir)/\(id)/openvpn.log", encoding: .utf8)) ?? ""
                }
            }
            #else
            fatalError("no test mode in this build")
            #endif
        } else {
            services = RealServices()
            helper = XPCHelperClient()
            transport = UnixSocketTransport()
            secrets = KeychainStore()
            defaults = .standard
        }
        try? FileManager.default.createDirectory(atPath: userDir, withIntermediateDirectories: true)
        let settingsStore = SettingsStore(backend: DefaultsBackend(defaults: defaults, forced: forced))
        let fs = DiskFileSystem()
        let store = ProfileStore(fs: fs, userDir: userDir, systemDir: systemDir, autoDir: autoDir,
                                 ext: settingsStore.settings.configExt)
        var controllerRef: AppController?
        let manager = ConnectionManager(
            helper: helper, transport: transport, reader: DiskBundleReader(fs: fs), scheduler: MainScheduler(),
            secrets: secrets, settings: { settingsStore.settings.connectionSettings },
            ui: { p in PromptUI(profile: p, canSave: { settingsStore.settings.connectionSettings.savePasswordsAllowed },
                                services: controllerRef?.services ?? services) },
            memory: DefaultsActiveMemory(defaults: defaults),
            scripts: ScriptSupport(executor: ProcessScriptExecutor(), settings: { settingsStore.settings },
                                   logsDir: home + "/Library/Logs/MugVPN",
                                   entries: { (try? FileManager.default.contentsOfDirectory(atPath: $0)) ?? [] }))
        controller = AppController(services: services, settingsStore: settingsStore, store: store, manager: manager,
                                   secrets: secrets,
                                   logsDir: e2e && env["MUGVPN_E2E_BACKEND"] != "real"
                                       ? (env["MUGVPN_E2E_HOME"] ?? NSTemporaryDirectory()) + "/logs" : "/Library/Logs/MugVPN")
        controllerRef = controller
        manager.persistentMode = { settingsStore.settings.persistentConnections }
        controller.logText = logText
        controller.options = ProfileOptionsStore(backend: DefaultsBackend(defaults: defaults))
        #if MUGVPN_TESTING
        if e2e, env["MUGVPN_E2E_BACKEND"] != "real", let h = env["MUGVPN_E2E_HOME"] {
            controller.runDir = h + "/run"
            controller.probe = FakeNetworkProbe() // no routing table until a test sets one (fake_network)
        }
        if let backend, let path = env["MUGVPN_E2E_SOCKET"], let s = services as? E2EServices {
            e2eServer = E2EServer(path: path, backend: backend, services: s)
            e2eServer?.app = controller
            e2eServer?.start()
        }
        #endif
        commandServer = CommandChannel.Server { [weak self] args, reply in
            guard let self else { return reply(.failed("MugVPN is quitting")) }
            let r = CommandLineRequest.parse(["--command"] + args)
            if case .error(let e) = r { return reply(CommandReply(code: .usage, error: e)) }
            self.handle(r, reply: reply)
        }
        commandServer?.start()
        if !e2e { watchSystem() }
        manager.appStarted()
        handle(startRequest)
    }

    /// Sleep, wake and network changes (in E2E mode the test sends them).
    func watchSystem() {
        let ws = NSWorkspace.shared.notificationCenter
        ws.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) { [weak self] _ in
            self?.controller.systemEvent(.willSleep)
        }
        ws.addObserver(forName: NSWorkspace.didWakeNotification, object: nil, queue: .main) { [weak self] _ in
            self?.controller.systemEvent(.didWake)
        }
        watchNetwork()
    }

    // MARK: - network changes

    private var networkStore: SCDynamicStore?
    private var networkDetector = NetworkChangeDetector()
    private var networkLookPending = false

    /// Told of every change of the network state (addresses, routers, DHCP leases, links);
    /// a look a second later decides whether the Mac is on another network.
    private func watchNetwork() {
        var ctx = SCDynamicStoreContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(),
                                        retain: nil, release: nil, copyDescription: nil)
        guard let store = SCDynamicStoreCreate(nil, "MugVPN" as CFString, { _, _, info in
            guard let info else { return }
            Unmanaged<AppDelegate>.fromOpaque(info).takeUnretainedValue().networkMayHaveChanged()
        }, &ctx) else { return }
        SCDynamicStoreSetNotificationKeys(store, ["State:/Network/Global/IPv4", "State:/Network/Global/IPv6"] as CFArray,
                                          ["State:/Network/Service/.*/IPv4", "State:/Network/Service/.*/IPv6",
                                           "State:/Network/Service/.*/DHCP", "State:/Network/Interface/.*/Link"] as CFArray)
        SCDynamicStoreSetDispatchQueue(store, .main)
        networkStore = store
        if let now = currentNetwork() { _ = networkDetector.update(now) }
    }

    private func networkMayHaveChanged() {
        guard !networkLookPending else { return }
        networkLookPending = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { [weak self] in
            guard let self else { return }
            self.networkLookPending = false
            guard let now = self.currentNetwork() else { return }
            if self.networkDetector.update(now) { self.controller.systemEvent(.networkChanged) }
        }
    }

    /// nil: a tunnel is the primary interface for a moment (not a network of the Mac's: no look).
    private func currentNetwork() -> NetworkIdentity?? {
        guard let s = networkStore else { return nil }
        func get(_ k: String) -> [String: Any]? { SCDynamicStoreCopyValue(s, k as CFString) as? [String: Any] }
        let g4 = get("State:/Network/Global/IPv4"), g6 = get("State:/Network/Global/IPv6")
        if ((g4 ?? g6)?["PrimaryInterface"] as? String)?.hasPrefix("utun") == true { return nil }
        let service = (g4?["PrimaryService"] ?? g6?["PrimaryService"]) as? String ?? ""
        let base = "State:/Network/Service/\(service)/"
        return .some(NetworkIdentity.from(global4: g4, global6: g6, service4: get(base + "IPv4"),
                                          service6: get(base + "IPv6"), dhcp: get(base + "DHCP")))
    }

    /// Files handed to the app ("Open With", a double click, `open -a`): each asked about,
    /// as any program can hand files over.
    func application(_ application: NSApplication, open urls: [URL]) {
        for u in urls { controller?.confirmImport(u.path) }
    }

    private var commandServer: CommandChannel.Server?

    func handle(_ r: CommandLineRequest, reply: @escaping (CommandReply) -> Void = { _ in }) {
        let m = controller.manager
        controller.rescan() // a profile added since the last scan must be found
        func profile(_ name: String) -> Profile? {
            switch CommandReply.find(name, in: m.profiles) {
            case .success(let p): return p
            case .failure(let e): reply(e); return nil
            }
        }
        func state(_ p: Profile) -> CommandReply.ProfileState { .init(p, m.active[p.id]?.controller.status) }
        func waitFor(_ p: Profile, _ a: CommandReply.Awaited, within: TimeInterval?) {
            guard let within else { return reply(.ok) }
            let deadline = Date().addingTimeInterval(within)
            func look() {
                let c = m.active[p.id]?.controller
                if let r = CommandReply.check(a, name: p.displayName, status: c?.status, connectedSince: c?.connectedSince) { return reply(r) }
                guard Date() < deadline else {
                    return reply(CommandReply(code: .timedOut, error: "\(p.displayName): still \(state(p).status) after \(Int(within)) s"))
                }
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { look() }
            }
            look()
        }
        switch r {
        case .connectOnStart(let n): if let p = profile(n) { controller.connect(p) }
        case .launchAndImport(let path): controller.confirmImport(path)
        case .command(let c, let wait):
            switch c {
            case .connect(let n):
                guard let p = profile(n) else { return }
                if m.active[p.id] != nil {
                    controller.showStatus(p)
                    return waitFor(p, .connected(after: nil), within: wait)
                }
                controller.connect(p) {
                    guard m.active[p.id] != nil else { return reply(.failed("\(p.displayName) was not started (see MugVPN)")) }
                    waitFor(p, .connected(after: nil), within: wait)
                }
            case .disconnect(let n):
                guard let p = profile(n) else { return }
                controller.disconnect(p)
                waitFor(p, .gone, within: wait)
            case .reconnect(let n):
                guard let p = profile(n) else { return }
                guard let c = m.active[p.id]?.controller else { return reply(.failed("\(p.displayName) is not connected")) }
                let before = c.connectedSince
                m.reconnect(p.id)
                waitFor(p, .connected(after: before), within: wait)
            case .disconnectAll:
                controller.disconnectEverything()
                reply(.ok)
            case .silentConnection(let on):
                do {
                    try controller.settingsStore.update { $0.silentConnection = on }
                    reply(.ok)
                } catch {
                    reply(.failed("\(error)"))
                }
            case .exit:
                reply(.ok)
                // The answer goes out first.
                m.appQuitting { [weak controller] in
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { controller?.onQuit() }
                }
            case .rescan:
                reply(.ok)
            case .importFile(let path):
                controller.confirmImport(path) { reply($0.map(CommandReply.failed) ?? .ok) }
            case .list:
                reply(CommandReply(profiles: m.profiles.map(state)))
            case .status(let n):
                if let n {
                    guard let p = profile(n) else { return }
                    reply(CommandReply(profiles: [state(p)]))
                } else {
                    reply(CommandReply(profiles: m.profiles.filter { m.active[$0.id] != nil }.map(state)))
                }
            }
        default: break
        }
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()

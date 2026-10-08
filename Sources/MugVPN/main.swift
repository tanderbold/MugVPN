import AppKit
import MugVPNAppCore
import Network
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
if testingBuild, let first = rawArgs.first, devCommands.contains(first) { runDevCLI(rawArgs) }

let commandNotification = Notification.Name("com.mugvpn.command")
let commandAck = Notification.Name("com.mugvpn.command.ack")

/// Hand a --command to the running app. It may still be starting, so the
/// command is posted again until the app confirms it (by token), up to 10 s.
func sendCommand(_ args: [String]) -> Int32 {
    let token = UUID().uuidString
    let center = DistributedNotificationCenter.default()
    var acked = false
    let observer = center.addObserver(forName: commandAck, object: nil, queue: .main) { n in
        if n.userInfo?["token"] as? String == token { acked = true }
    }
    let deadline = Date().addingTimeInterval(10)
    while !acked && Date() < deadline {
        center.postNotificationName(commandNotification, object: nil, userInfo: ["args": args, "token": token],
                                    deliverImmediately: true)
        RunLoop.main.run(until: Date().addingTimeInterval(0.3))
    }
    center.removeObserver(observer)
    if !acked { FileHandle.standardError.write(Data("MugVPN is running but did not answer\n".utf8)) }
    return acked ? 0 : 1
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
    if !others.isEmpty { _ = sendCommand(["exit"]) }
    let services = RealServices()
    var result: String??
    XPCHelperClient().uninstall(keepProfiles: keep) { result = .some($0) }
    let deadline = Date().addingTimeInterval(60)
    while result == nil && Date() < deadline { RunLoop.main.run(until: Date().addingTimeInterval(0.1)) }
    if let err = result ?? "the helper did not answer" {
        FileHandle.standardError.write(Data("MugVPN: cannot uninstall: \(err)\n".utf8))
        exit(1)
    }
    services.helperSetup.unregister()
    services.removeUserData(user)
    services.moveAppToTrash()
    print("MugVPN is uninstalled.")
    exit(0)
case .command(let c):
    let others = NSRunningApplication.runningApplications(withBundleIdentifier: MugVPNIDs.appBundleID)
        .filter { $0.processIdentifier != ProcessInfo.processInfo.processIdentifier }
    if !others.isEmpty { exit(sendCommand(Array(CommandLineRequest.ownArguments(rawArgs).dropFirst()))) }
    guard let r = CommandLineRequest.withoutInstance(c) else { exit(0) }
    startRequest = r
default:
    break
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    var controller: AppController!
    var e2eServer: E2EServer?

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
        var backend: E2EBackend?
        if e2e {
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
        if e2e, env["MUGVPN_E2E_BACKEND"] != "real", let h = env["MUGVPN_E2E_HOME"] {
            controller.runDir = h + "/run"
            controller.probe = FakeNetworkProbe() // no routing table until a test sets one (fake_network)
        }
        if let backend, let path = env["MUGVPN_E2E_SOCKET"], let s = services as? E2EServices {
            e2eServer = E2EServer(path: path, backend: backend, services: s)
            e2eServer?.app = controller
            e2eServer?.start()
        }
        DistributedNotificationCenter.default().addObserver(self, selector: #selector(command(_:)), name: commandNotification, object: nil)
        if !e2e { watchSystem() }
        manager.appStarted()
        handle(startRequest)
    }

    private let pathMonitor = NWPathMonitor()

    /// Sleep, wake and network changes (in E2E mode the test sends them).
    func watchSystem() {
        let ws = NSWorkspace.shared.notificationCenter
        ws.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) { [weak self] _ in
            self?.controller.systemEvent(.willSleep)
        }
        ws.addObserver(forName: NSWorkspace.didWakeNotification, object: nil, queue: .main) { [weak self] _ in
            self?.controller.systemEvent(.didWake)
        }
        var last: NWPath?
        pathMonitor.pathUpdateHandler = { [weak self] path in
            DispatchQueue.main.async {
                defer { last = path }
                // Our own utun interfaces come and go with the tunnels: only real network changes count.
                let real = { (p: NWPath) in p.availableInterfaces.filter { $0.type != .other }.map(\.name) }
                guard let prev = last, path.status == .satisfied,
                      real(prev) != real(path) || prev.status != path.status else { return }
                self?.controller.systemEvent(.networkChanged)
            }
        }
        pathMonitor.start(queue: .global())
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        controller?.importFiles(urls.map(\.path))
    }

    private var seenTokens: Set<String> = []

    @objc func command(_ n: Notification) {
        guard let args = n.userInfo?["args"] as? [String], let token = n.userInfo?["token"] as? String else { return }
        DistributedNotificationCenter.default().postNotificationName(commandAck, object: nil, userInfo: ["token": token],
                                                                     deliverImmediately: true)
        // The sender repeats until it sees the answer: act on each command once.
        guard seenTokens.insert(token).inserted else { return }
        handle(CommandLineRequest.parse(["--command"] + args))
    }

    func handle(_ r: CommandLineRequest) {
        let m = controller.manager
        controller.rescan() // a profile added since the last scan must be found
        func profile(_ name: String) -> Profile? { m.profiles.first { $0.name == name || $0.displayName == name } }
        switch r {
        case .connectOnStart(let n): if let p = profile(n) { controller.connect(p) }
        case .launchAndImport(let path): controller.confirmImport(path)
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
    if !others.isEmpty { _ = sendCommand(["exit"]) }
    let services = RealServices()
    var result: String??
    XPCHelperClient().uninstall(keepProfiles: keep) { result = .some($0) }
    let deadline = Date().addingTimeInterval(60)
    while result == nil && Date() < deadline { RunLoop.main.run(until: Date().addingTimeInterval(0.1)) }
    if let err = result ?? "the helper did not answer" {
        FileHandle.standardError.write(Data("MugVPN: cannot uninstall: \(err)\n".utf8))
        exit(1)
    }
    services.helperSetup.unregister()
    services.removeUserData(user)
    services.moveAppToTrash()
    print("MugVPN is uninstalled.")
    exit(0)
case .command(let c):
            switch c {
            case .connect(let n):
                if let p = profile(n) {
                    if m.active[p.id] != nil { controller.showStatus(p) } else { controller.connect(p) }
                }
            case .disconnect(let n): if let p = profile(n) { m.disconnect(p.id) }
            case .reconnect(let n): if let p = profile(n) { m.reconnect(p.id) }
            case .disconnectAll: m.disconnectAll()
            case .silentConnection(let on): try? controller.settingsStore.update { $0.silentConnection = on }
            case .exit: m.appQuitting { NSApp.terminate(nil) }
            case .rescan: controller.rescan()
            case .importFile(let path): controller.confirmImport(path)
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

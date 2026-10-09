import Foundation
import MugVPNCore

/// The helper as the app sees it (XPC in the app, a fake in tests).
public protocol HelperClient: AnyObject {
    /// The helper's version (MugVPNIDs.helperVersion of the build it came with).
    func version(reply: @escaping (String?) -> Void)
    /// Exit if no connection or block of anyone's needs it (launchd then starts the helper the
    /// app came with); nil when it does, or why not.
    func restartIfIdle(reply: @escaping (String?) -> Void)
    func start(_ bundle: ProfileBundle, reply: @escaping (Result<(id: String, socket: String), Error>) -> Void)
    func stop(_ id: String, reply: @escaping (String?) -> Void)
    func list(reply: @escaping ([ConnectionInfo]) -> Void)
    /// Start a persistent profile from config-auto; replies with its connection id.
    func startPersistent(_ name: String, reply: @escaping (Result<String, Error>) -> Void)
    /// Remove MugVPN's system part; replies when done (nil) or with an error.
    func uninstall(keepProfiles: Bool, reply: @escaping (String?) -> Void)
    /// Profiles whose kill switch blocks traffic now.
    func blocks(reply: @escaping ([String]) -> Void)
    /// Lift the blocks this user may lift; an error text or nil.
    func unblock(reply: @escaping (String?) -> Void)
    /// Lift them for a while (to sign in to a network); an error text or nil.
    func suspendBlocks(seconds: Int, reply: @escaping (String?) -> Void)
    /// A persistent tunnel: the helper lets go of its management connection for the app.
    func releaseManagement(_ id: String, reply: @escaping (String?) -> Void)
    /// What an unprivileged openvpn asks for (privilege separation); the utun for OPENTUN.
    func tunnelRequest(_ id: String, kind: String, message: String, reply: @escaping (Result<FileHandle?, Error>) -> Void)
}

public protocol ManagementLink: AnyObject {
    func write(_ data: Data)
    /// With a descriptor for openvpn (SCM_RIGHTS); false if it was not sent.
    func write(_ data: Data, passing fd: Int32) -> Bool
    func close()
}

/// Opens a management socket; nil when it cannot (yet).
public protocol ManagementTransport: AnyObject {
    func open(_ socket: String, onData: @escaping (Data) -> Void, onClose: @escaping () -> Void) -> ManagementLink?
}

public protocol Scheduler: AnyObject {
    func after(_ seconds: TimeInterval, _ f: @escaping () -> Void)
}

/// Reads a profile and the files it names, with the user's rights.
public protocol ProfileBundleReader: AnyObject {
    func bundle(for profile: Profile) throws -> ProfileBundle
}

/// Profiles that were connected when the app quit.
public protocol ActiveMemory: AnyObject {
    var remembered: [String] { get set }
}

public enum SystemEvent: Equatable, Sendable {
    case willSleep
    case didWake
    case networkChanged
}

public final class ActiveConnection {
    public let profile: Profile
    public let controller: ConnectionController
    public internal(set) var helperID: String?
    var proto = ManagementProtocol()
    var link: ManagementLink?
    var stopRequested = false
    var upScriptRan = false
    /// Management password (persistent connections).
    var password: String?
    /// The profile text, for the scripts' environment.
    var config = ""

    init(profile: Profile, controller: ConnectionController) {
        self.profile = profile
        self.controller = controller
    }
}

/// Ties the helper, the management sockets and the connection controllers
/// together. Everything runs on the main queue in the app.
public final class ConnectionManager {
    public static let socketRetryInterval: TimeInterval = 0.2
    public static let socketAttempts = 50

    public var profiles: [Profile] = []
    /// The "persistent connections" setting: auto, manual or disable.
    public var persistentMode: () -> PersistentConnections = { .auto }
    /// Profiles to connect when the app starts.
    public var autoConnect: (Profile) -> Bool = { _ in false }
    /// A profile's own connection settings (general ones with its overrides), if set.
    public var profileSettings: ((Profile) -> ConnectionSettings)?
    /// Profiles whose pushed DNS domains become split domains (NET-04).
    public var splitDNS: (Profile) -> Bool = { _ in false }
    /// The protection a connection asks the helper for.
    public var protection: (Profile) -> ProtectionOptions = { _ in ProtectionOptions() }
    public private(set) var active: [String: ActiveConnection] = [:] {
        didSet { if active.isEmpty, !oldValue.isEmpty { restartOutdatedHelper() } }
    }
    public private(set) var lastError: [String: String] = [:]
    public var onChange: () -> Void = {}
    /// The helper's version when it is not the app's (an update not yet taken by the running helper).
    public private(set) var helperVersionMismatch: String?
    private var helperRestartAsked = false

    /// nil (no answer: an older helper has no version call) counts as another version.
    private func checkHelperVersion() {
        helper.version { [weak self] v in
            guard let self else { return }
            let now: String? = v == MugVPNIDs.helperVersion ? nil : (v ?? "unknown")
            guard now != self.helperVersionMismatch else { return }
            self.helperVersionMismatch = now
            self.onChange()
            self.restartOutdatedHelper()
        }
    }

    /// Another helper version, and nothing of this app's uses it: it is asked to start again
    /// (it does only if no one's connection or block needs it), then asked its version again.
    private func restartOutdatedHelper() {
        guard helperVersionMismatch != nil, active.isEmpty, !helperRestartAsked else { return }
        helperRestartAsked = true
        helper.restartIfIdle { [weak self] err in
            guard let self else { return }
            if err != nil { self.helperRestartAsked = false; return }
            self.scheduler.after(2) { [weak self] in
                self?.helperRestartAsked = false
                self?.checkHelperVersion()
            }
        }
    }

    private let helper: HelperClient
    public var helperClient: HelperClient { helper }
    private let transport: ManagementTransport
    private let reader: ProfileBundleReader
    private let scheduler: Scheduler
    private let secrets: SecretStore
    private let settings: () -> ConnectionSettings
    private let ui: (Profile) -> ConnectionUI
    private let memory: ActiveMemory
    private let scripts: ScriptSupport?
    private var quitDone: (() -> Void)?
    /// Stopped for sleep: connect again on wake.
    private var sleptProfiles: [String] = []
    /// To connect again once their old tunnel has ended.
    private var connectWhenEnded: Set<String> = []
    private var networkTimerPending = false
    /// Network changes come in bursts; one reconnect per burst.
    public static let networkDebounce: TimeInterval = 2

    public init(helper: HelperClient, transport: ManagementTransport, reader: ProfileBundleReader, scheduler: Scheduler,
                secrets: SecretStore, settings: @escaping () -> ConnectionSettings, ui: @escaping (Profile) -> ConnectionUI,
                memory: ActiveMemory, scripts: ScriptSupport? = nil) {
        self.scripts = scripts
        self.helper = helper
        self.transport = transport
        self.reader = reader
        self.scheduler = scheduler
        self.secrets = secrets
        self.settings = settings
        self.ui = ui
        self.memory = memory
    }

    // MARK: - commands

    public func connect(_ profile: Profile) {
        guard active[profile.id] == nil else { return }
        lastError[profile.id] = nil
        if profile.source == .persistent { return connectPersistent(profile) }
        var bundle: ProfileBundle
        do { bundle = try reader.bundle(for: profile) } catch {
            return fail(profile.id, "\(error)")
        }
        bundle.splitDNS = splitDNS(profile)
        bundle.protection = protection(profile)
        let c = makeConnection(profile)
        c.config = bundle.config
        active[profile.id] = c
        onChange()
        guard let scripts, let pre = scripts.plan(profile, .pre) else { return start(c, bundle) }
        scripts.executor.run(pre, env: environment(c)) { [weak self] exit in
            guard let self, self.active[profile.id] === c else { return }
            if ScriptRunner.outcome(.pre, exit) == .proceed {
                self.start(c, bundle)
            } else {
                self.active[profile.id] = nil
                self.fail(profile.id, "the pre-connect script failed")
            }
        }
    }

    /// A persistent tunnel belongs to the helper: attach to it if it runs, else ask the helper to start it.
    private func connectPersistent(_ profile: Profile) {
        let c = makeConnection(profile)
        active[profile.id] = c
        onChange()
        let attach: () -> Void = { [weak self] in
            self?.helper.list { running in
                guard let self, self.active[profile.id] === c else { return }
                guard let info = running.first(where: { $0.persistent && $0.name == profile.name }) else {
                    self.active[profile.id] = nil
                    return self.fail(profile.id, "the persistent connection is not running")
                }
                c.helperID = info.id
                c.password = info.managementPassword
                self.attachPersistent(c, socket: info.managementSocket)
            }
        }
        helper.list { [weak self] running in
            guard let self else { return }
            if running.contains(where: { $0.persistent && $0.name == profile.name }) { return attach() }
            self.helper.startPersistent(profile.name) { result in
                switch result {
                case .success: attach()
                case .failure(let e):
                    self.active[profile.id] = nil
                    self.fail(profile.id, "\(e)")
                }
            }
        }
    }

    /// openvpn takes one management client: the helper holds it while no app does.
    private func attachPersistent(_ c: ActiveConnection, socket: String) {
        guard let id = c.helperID else { return }
        helper.releaseManagement(id) { [weak self, weak c] err in
            guard let self, let c, self.active[c.profile.id] === c else { return }
            if let err {
                self.active[c.profile.id] = nil
                return self.fail(c.profile.id, err)
            }
            self.open(c, socket: socket, attempt: 1)
        }
    }

    private func start(_ c: ActiveConnection, _ bundle: ProfileBundle) {
        let profile = c.profile
        helper.start(bundle) { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let r):
                c.helperID = r.id
                if c.stopRequested {
                    // Stopped before the helper answered: no socket will close for it.
                    self.helper.stop(r.id) { _ in }
                    return self.ended(c)
                }
                self.open(c, socket: r.socket, attempt: 1)
            case .failure(let e):
                self.active[profile.id] = nil
                self.fail(profile.id, "\(e)")
            }
        }
    }

    public func disconnect(_ id: String) {
        active[id]?.controller.disconnect()
    }

    public func reconnect(_ id: String) {
        active[id]?.controller.reconnect()
    }

    public func disconnectAll() {
        active.values.forEach { $0.controller.disconnect() }
    }

    public func handle(_ event: SystemEvent, disconnectOnSleep: Bool) {
        handle(event, disconnectOnSleep: { _ in disconnectOnSleep })
    }

    /// - disconnectOnSleep: per profile (its own choice or the general one).
    public func handle(_ event: SystemEvent, disconnectOnSleep: (Profile) -> Bool) {
        switch event {
        case .willSleep:
            let going = active.values.filter { $0.profile.source != .persistent && disconnectOnSleep($0.profile) }
            guard !going.isEmpty else { return }
            sleptProfiles = going.map(\.profile.id).sorted()
            going.forEach { $0.controller.disconnect() }
        case .didWake:
            if !sleptProfiles.isEmpty {
                for id in sleptProfiles {
                    if active[id] != nil { connectWhenEnded.insert(id) }
                    else if let p = profiles.first(where: { $0.id == id }) { connect(p) }
                }
                sleptProfiles = []
            }
            reconnectLive()
        case .networkChanged:
            guard !networkTimerPending, !active.isEmpty else { return }
            networkTimerPending = true
            scheduler.after(ConnectionManager.networkDebounce) { [weak self] in
                self?.networkTimerPending = false
                self?.reconnectLive()
            }
        }
    }

    /// SIGUSR1 to tunnels that are up or trying: a fresh start beats waiting for ping-restart.
    private func reconnectLive() {
        for c in active.values {
            switch c.controller.status {
            case .connected, .reconnecting: c.controller.reconnect()
            default: break
            }
        }
    }

    /// At app start: pick up tunnels the helper still runs (the app had
    /// crashed), stop those for profiles that are gone, then reconnect the
    /// ones that were up when the app last quit.
    public func appStarted() {
        checkHelperVersion()
        helper.list { [weak self] running in
            guard let self else { return }
            for info in running {
                if info.persistent {
                    // The helper's own tunnels: attach only if the setting says so, never stop them.
                    guard self.persistentMode() == .auto,
                          let p = self.profiles.first(where: { $0.source == .persistent && $0.name == info.name }),
                          self.active[p.id] == nil else { continue }
                    let c = self.makeConnection(p)
                    c.helperID = info.id
                    c.password = info.managementPassword
                    self.active[p.id] = c
                    self.attachPersistent(c, socket: info.managementSocket)
                    continue
                }
                guard let p = self.profiles.first(where: { $0.source != .persistent && $0.name == info.name }),
                      self.active[p.id] == nil else {
                    self.helper.stop(info.id) { _ in }
                    continue
                }
                let c = self.makeConnection(p)
                c.helperID = info.id
                self.active[p.id] = c
                self.open(c, socket: info.managementSocket, attempt: 1)
            }
            let again = self.memory.remembered
            self.memory.remembered = []
            for id in again {
                if let p = self.profiles.first(where: { $0.id == id }) { self.connect(p) }
            }
            for p in self.profiles where p.source != .persistent && self.autoConnect(p) && self.active[p.id] == nil {
                self.connect(p)
            }
            self.onChange()
        }
    }

    /// At quit: remember what is up, stop it, and call `done` when all ended.
    public func appQuitting(done: @escaping () -> Void) {
        // Persistent tunnels belong to the helper: detach, do not stop or remember them.
        for c in active.values where c.profile.source == .persistent {
            c.stopRequested = true
            c.link?.close()
            active[c.profile.id] = nil
        }
        memory.remembered = active.keys.sorted()
        guard !active.isEmpty else { return done() }
        quitDone = done
        disconnectAll()
        // Not for ever: an openvpn that does not end is the helper's to stop.
        scheduler.after(ConnectionManager.quitDeadline) { [weak self] in self?.quitIfDone(force: true) }
    }

    /// How long quitting waits for the connections to end.
    public static let quitDeadline: TimeInterval = 20

    private func quitIfDone(force: Bool = false) {
        guard active.isEmpty || force, let done = quitDone else { return }
        quitDone = nil
        done()
    }

    // MARK: - plumbing

    private func makeConnection(_ p: Profile) -> ActiveConnection {
        let controller = ConnectionController(profile: p.secretsKey, ui: ui(p), secrets: secrets,
                                              settings: profileSettings?(p) ?? settings())
        controller.displayName = p.displayName
        let c = ActiveConnection(profile: p, controller: controller)
        controller.send = { [weak c] cmd in
            guard let c else { return }
            c.link?.write(c.proto.command(cmd))
        }
        controller.sendWithFD = { [weak c] cmd, fd in
            guard let c, let link = c.link else { return false }
            return link.write(c.proto.command(cmd), passing: fd.fileDescriptor)
        }
        controller.tunnelRequest = { [weak self, weak c] kind, message, reply in
            guard let self, let id = c?.helperID else { return reply(.failure(ProfileError("not connected"))) }
            self.helper.tunnelRequest(id, kind: kind, message: message, reply: reply)
        }
        controller.onStop = { [weak self, weak c] in
            guard let self, let c else { return }
            c.stopRequested = true
            let stop = { [weak self] in
                if let id = c.helperID { self?.helper.stop(id) { _ in } }
            }
            // The disconnect script runs while the tunnel is still up.
            if c.link != nil, let scripts = self.scripts, let down = scripts.plan(c.profile, .down) {
                scripts.executor.run(down, env: self.environment(c)) { _ in stop() }
            } else {
                stop()
            }
        }
        controller.onChange = { [weak self, weak c] in
            guard let self, let c else { return }
            if case .connected = c.controller.status, !c.upScriptRan {
                c.upScriptRan = true
                if let scripts = self.scripts, let up = scripts.plan(c.profile, .up) {
                    scripts.executor.run(up, env: self.environment(c)) { [weak c] exit in
                        if ScriptRunner.outcome(.up, exit) == .connectedWithErrors { c?.controller.markScriptFailed() }
                    }
                }
            }
            self.onChange()
        }
        return c
    }

    private func open(_ c: ActiveConnection, socket: String, attempt: Int) {
        let link = transport.open(socket, onData: { [weak self, weak c] data in
            guard let c else { return }
            for e in c.proto.received(data) { c.controller.handle(e) }
            self?.onChange()
        }, onClose: { [weak self, weak c] in
            guard let self, let c else { return }
            c.proto.closed().forEach(c.controller.handle)
            self.ended(c)
        })
        if let link {
            c.link = link
            // openvpn reads the first line as the password.
            if let pw = c.password { link.write(c.proto.command(pw)) }
            c.controller.attached()
            return
        }
        guard attempt < ConnectionManager.socketAttempts else {
            // A persistent tunnel is the Mac's: left running, only not shown here.
            if c.profile.source != .persistent, let id = c.helperID { helper.stop(id) { _ in } }
            active[c.profile.id] = nil
            return fail(c.profile.id, "cannot reach openvpn's management socket")
        }
        scheduler.after(ConnectionManager.socketRetryInterval) { [weak self, weak c] in
            guard let self, let c, self.active[c.profile.id] === c else { return }
            self.open(c, socket: socket, attempt: attempt + 1)
        }
    }

    private func ended(_ c: ActiveConnection) {
        guard active[c.profile.id] === c else { return }
        active[c.profile.id] = nil
        if !c.stopRequested {
            lastError[c.profile.id] = "the connection ended unexpectedly"
        }
        onChange()
        if connectWhenEnded.remove(c.profile.id) != nil { connect(c.profile) }
        quitIfDone()
    }

    private func environment(_ c: ActiveConnection) -> [String: String] {
        if c.config.isEmpty, let b = try? reader.bundle(for: c.profile) { c.config = b.config }
        var ip = "", ip6 = ""
        if case .connected(let a, let a6, _) = c.controller.status { ip = a; ip6 = a6 }
        return ScriptRunner.environment(profile: c.profile, directives: (try? ConfigParser.parse(c.config)) ?? [],
                                        pushed: c.controller.pushedEnvironment, localIP: ip, localIPv6: ip6)
    }

    private func fail(_ id: String, _ message: String) {
        lastError[id] = message
        onChange()
        quitIfDone() // a connection that went this way is not waited for either
    }
}

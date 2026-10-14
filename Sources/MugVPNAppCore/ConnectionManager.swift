import Foundation
import MugVPNCore

/// The helper as the app sees it (XPC in the app, a fake in tests).
/// What the helper says to "start again for an update".
public enum HelperRestart: Equatable, Sendable {
    case restarting
    /// A connection or block of someone's needs it now.
    case inUse
    /// It has no such call (an older helper).
    case unsupported
    /// It does not answer at all (not running, not registered, a passing failure).
    case unavailable
    /// The helper on disk is not newer than the running one: nothing to start again into.
    case notNewer
}

/// The connections themselves: what every product's backend does.
public protocol VPNConnectionBackend: AnyObject {
    func start(_ bundle: ProfileBundle, reply: @escaping (Result<(id: String, socket: String), Error>) -> Void)
    func stop(_ id: String, reply: @escaping (String?) -> Void)
    func list(reply: @escaping ([ConnectionInfo]) -> Void)
}

/// Kill switches' blocks.
public protocol ProtectionBackend: AnyObject {
    /// Profiles whose kill switch blocks traffic now.
    func blocks(reply: @escaping ([String]) -> Void)
    /// Lift the blocks this user may lift; an error text or nil.
    func unblock(reply: @escaping (String?) -> Void)
    /// Lift them for a while (to sign in to a network); an error text or nil.
    func suspendBlocks(seconds: Int, reply: @escaping (String?) -> Void)
}

/// The backend's own install: its version, updating it, removing it.
public protocol InstallationLifecycle: AnyObject {
    /// The helper's version (MugVPNIDs.helperVersion of the build it came with).
    func version(reply: @escaping (String?) -> Void)
    /// Exit if no connection or block of anyone's needs it (launchd then starts the helper the
    /// app came with); nil when it does, or why not.
    func restartIfIdle(reply: @escaping (HelperRestart) -> Void)
    /// Whether it answers a call every helper version has (an old one does; none that is not there).
    func reachable(reply: @escaping (Bool) -> Void)
    /// Remove MugVPN's system part; replies when done (nil) or with an error.
    func uninstall(keepProfiles: Bool, reply: @escaping (String?) -> Void)
}

/// Persistent connections (started by the helper from config-auto, the Mac's).
public protocol PersistentConnectionBackend: AnyObject {
    /// Start a persistent profile from config-auto; replies with its connection id.
    func startPersistent(_ name: String, reply: @escaping (Result<String, Error>) -> Void)
    /// A persistent tunnel: the helper lets go of its management connection for the app.
    func releaseManagement(_ id: String, reply: @escaping (String?) -> Void)
}

/// What an unprivileged openvpn asks its management client for (privilege separation).
public protocol PrivilegedTunnelRequests: AnyObject {
    /// The utun for OPENTUN; routes, DNS...
    func tunnelRequest(_ id: String, kind: String, message: String, reply: @escaping (Result<FileHandle?, Error>) -> Void)
}

/// MugVPN's privileged helper: every part.
public typealias HelperClient = VPNConnectionBackend & ProtectionBackend & InstallationLifecycle & PersistentConnectionBackend
    & PrivilegedTunnelRequests

/// What a product does (the interface shows what this says, nothing else decides it).
public struct BackendCapabilities: Equatable, Sendable {
    /// Profile scripts (_pre/_up/_down.sh) run.
    public var scripts: Bool
    /// Persistent connections (the Mac's, at boot).
    public var persistentConnections: Bool
    /// A helper of its own: installed, updated, removed with an administrator's password when it does not answer.
    public var systemHelper: Bool
    /// DNS outside the tunnels blocked even when sent straight to a server (not only the system's resolver).
    public var directDNSBlocking: Bool
    /// A kill switch's block kept across a restart of the Mac.
    public var protectionAcrossRestart: Bool
    /// An administrator's policy for standard users.
    public var adminPolicy: Bool
    /// A connection with a kill switch runs alone, nothing outside the VPN while it is up (the system's strict mode).
    public var killSwitchRunsAlone: Bool

    public init(scripts: Bool, persistentConnections: Bool, systemHelper: Bool, directDNSBlocking: Bool,
                protectionAcrossRestart: Bool, adminPolicy: Bool, killSwitchRunsAlone: Bool = false) {
        self.killSwitchRunsAlone = killSwitchRunsAlone
        self.scripts = scripts
        self.persistentConnections = persistentConnections
        self.systemHelper = systemHelper
        self.directDNSBlocking = directDNSBlocking
        self.protectionAcrossRestart = protectionAcrossRestart
        self.adminPolicy = adminPolicy
    }

    /// MugVPN's privileged helper.
    public static let helper = BackendCapabilities(scripts: true, persistentConnections: true, systemHelper: true,
                                                   directDNSBlocking: true, protectionAcrossRestart: true, adminPolicy: true)
    /// A packet tunnel provider (Network Extension).
    public static let packetTunnel = BackendCapabilities(scripts: false, persistentConnections: false, systemHelper: false,
                                                         directDNSBlocking: false, protectionAcrossRestart: false, adminPolicy: false,
                                                         killSwitchRunsAlone: true)
}

/// A product's backend: its parts (the optional ones only where it has them) and what it does.
public struct Backend {
    public let connections: VPNConnectionBackend
    public let protection: ProtectionBackend
    public let lifecycle: InstallationLifecycle
    public let persistent: PersistentConnectionBackend?
    public let tunnelRequests: PrivilegedTunnelRequests?
    public let capabilities: BackendCapabilities

    public init(connections: VPNConnectionBackend, protection: ProtectionBackend, lifecycle: InstallationLifecycle,
                persistent: PersistentConnectionBackend?, tunnelRequests: PrivilegedTunnelRequests?, capabilities: BackendCapabilities) {
        self.connections = connections
        self.protection = protection
        self.lifecycle = lifecycle
        self.persistent = persistent
        self.tunnelRequests = tunnelRequests
        self.capabilities = capabilities
    }

    /// MugVPN's helper (it does everything).
    public init(helper: HelperClient) {
        self.init(connections: helper, protection: helper, lifecycle: helper, persistent: helper, tunnelRequests: helper,
                  capabilities: .helper)
    }
}

public protocol ManagementLink: AnyObject {
    func write(_ data: Data)
    /// With a descriptor for openvpn (SCM_RIGHTS); `done(false)` if it was not sent. Off the caller's thread:
    /// `done` comes on the main queue (the descriptor must stay open until then).
    func write(_ data: Data, passing fd: Int32, done: @escaping (Bool) -> Void)
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
    var link: TunnelLink?
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
    /// The domains a profile's options list for the server's DNS.
    public var dnsDomains: (Profile) -> [String] = { _ in [] }
    /// Settings > Append to the log.
    public var appendLog: () -> Bool = { false }
    /// The protection a connection asks the helper for.
    public var protection: (Profile) -> ProtectionOptions = { _ in ProtectionOptions() }
    public private(set) var active: [String: ActiveConnection] = [:] {
        didSet { if active.isEmpty, !oldValue.isEmpty { restartOutdatedHelper() } }
    }
    public private(set) var lastError: [String: String] = [:]
    public var onChange: () -> Void = {}
    /// A connection's private key password as it is sent (to read a PKCS#12's end with it).
    public var onKeyPassword: (Profile, String) -> Void = { _, _ in }
    /// The helper's version when it is not the app's (an update not yet taken by the running helper).
    public private(set) var helperVersionMismatch: String?
    /// The helper does not answer at all (said once): its service may be registered but not loaded.
    public var onHelperUnreachable: () -> Void = {}
    private var unreachableTold = false
    private var helperRestartAsked = false
    /// Restart calls an older helper did not answer although it answered its version.
    private var silentRestarts = 0
    public static let silentRestartsBeforeHand = 3
    /// An older helper that cannot start itself again: the user puts the new one in place (re-registering it).
    public private(set) var helperNeedsManualUpdate = false
    /// The next wait before asking a helper in use again.
    private var helperRestartWait: TimeInterval = 60
    public static let helperRestartMaxWait: TimeInterval = 1800

    /// The user put the new helper in place by hand: asked again shortly (the same old one: offered again).
    public func helperReplaced() {
        helperNeedsManualUpdate = false
        helperVersionMismatch = nil
        onChange()
        scheduler.after(3) { [weak self] in self?.checkHelperVersion() }
    }

    private func needsManualUpdate() {
        helperNeedsManualUpdate = true
        onChange()
    }

    /// The helper is newer than the app (another user's newer MugVPN): the app is what to update.
    public var helperIsNewer: Bool {
        helperVersionMismatch.map { !ConnectionManager.isOlder($0, than: MugVPNIDs.helperVersion) } ?? false
    }

    /// "a.b.c" against "a.b.c", numerically; "unknown" (a helper without a version call) is the oldest.
    public static func isOlder(_ a: String, than b: String) -> Bool {
        func parts(_ s: String) -> [Int]? {
            let p = s.split(separator: ".").map { Int($0) }
            return p.isEmpty || p.contains(nil) ? nil : p.compactMap { $0 }
        }
        guard let y = parts(b) else { return false }
        guard let x = parts(a) else { return true }
        for i in 0..<max(x.count, y.count) {
            let l = i < x.count ? x[i] : 0, r = i < y.count ? y[i] : 0
            if l != r { return l < r }
        }
        return false
    }

    /// No version answer: an old helper (it answers its older calls) or none at all (asked again later).
    private func checkHelperVersion() {
        backend.lifecycle.version { [weak self] v in
            guard let self else { return }
            guard let v else {
                return self.backend.lifecycle.reachable { [weak self] up in
                    guard let self else { return }
                    if up { return self.versionKnown("unknown") }
                    if !self.unreachableTold {
                        self.unreachableTold = true
                        self.onHelperUnreachable()
                    }
                    self.retryLater { [weak self] in self?.checkHelperVersion() }
                }
            }
            self.versionKnown(v)
        }
    }

    private func versionKnown(_ v: String) {
        let now: String? = v == MugVPNIDs.helperVersion ? nil : v
        guard now != helperVersionMismatch else { return }
        helperVersionMismatch = now
        onChange()
        restartOutdatedHelper()
    }

    private func retryLater(_ f: @escaping () -> Void) {
        let wait = helperRestartWait
        helperRestartWait = min(wait * 2, ConnectionManager.helperRestartMaxWait)
        scheduler.after(wait, f)
    }

    /// Another helper version, and nothing of this app's uses it: it is asked to start again
    /// (it does only if no one's connection or block needs it), then asked its version again.
    private func restartOutdatedHelper() {
        // Only an older one: a newer helper (another user's newer MugVPN) is not this app's to stop.
        guard let v = helperVersionMismatch, ConnectionManager.isOlder(v, than: MugVPNIDs.helperVersion),
              active.isEmpty, !helperRestartAsked, !helperNeedsManualUpdate else { return }
        helperRestartAsked = true
        backend.lifecycle.restartIfIdle { [weak self] answer in
            guard let self else { return }
            switch answer {
            case .restarting:
                self.helperRestartWait = 60
                self.scheduler.after(2) { [weak self] in
                    self?.helperRestartAsked = false
                    self?.checkHelperVersion()
                }
            case .inUse:
                // Someone else's tunnel or block, or no answer: nothing here says when that ends, so ask again later.
                self.retryLater { [weak self] in
                    self?.helperRestartAsked = false
                    self?.restartOutdatedHelper()
                }
            case .unavailable:
                // No answer: asked its version again before anything is concluded (a new helper may be up by now).
                self.backend.lifecycle.version { [weak self] v in
                    guard let self else { return }
                    if let v {
                        self.helperRestartAsked = false
                        // The same older version again: it has no restart call (0.1.0 answers version,
                        // not restartIfIdle). A few tries (it may have been passing), then by hand.
                        if v == self.helperVersionMismatch, ConnectionManager.isOlder(v, than: MugVPNIDs.helperVersion) {
                            self.silentRestarts += 1
                            if self.silentRestarts >= ConnectionManager.silentRestartsBeforeHand { return self.needsManualUpdate() }
                            return self.retryLater { [weak self] in self?.restartOutdatedHelper() }
                        }
                        return self.versionKnown(v)
                    }
                    self.backend.lifecycle.reachable { [weak self] up in
                        guard let self else { return }
                        self.helperRestartAsked = false
                        if up { self.needsManualUpdate() } else { self.retryLater { [weak self] in self?.restartOutdatedHelper() } }
                    }
                }
            case .unsupported, .notNewer:
                // An older helper without the call, or one whose bundle on disk is old too (the service was
                // registered from an older copy of the app): registering it again from this copy is the way.
                self.helperRestartAsked = false
                self.needsManualUpdate()
            }
        }
    }

    public let backend: Backend
    private let transport: TunnelTransport
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

    public convenience init(helper: HelperClient, transport: ManagementTransport, reader: ProfileBundleReader, scheduler: Scheduler,
                            secrets: SecretStore, settings: @escaping () -> ConnectionSettings, ui: @escaping (Profile) -> ConnectionUI,
                            memory: ActiveMemory, scripts: ScriptSupport? = nil) {
        self.init(backend: Backend(helper: helper), transport: ManagementTunnelTransport(transport), reader: reader,
                  scheduler: scheduler, secrets: secrets, settings: settings, ui: ui, memory: memory, scripts: scripts)
    }

    public init(backend: Backend, transport: TunnelTransport, reader: ProfileBundleReader, scheduler: Scheduler,
                secrets: SecretStore, settings: @escaping () -> ConnectionSettings, ui: @escaping (Profile) -> ConnectionUI,
                memory: ActiveMemory, scripts: ScriptSupport? = nil) {
        self.scripts = scripts
        self.backend = backend
        self.transport = transport
        self.reader = reader
        self.scheduler = scheduler
        self.secrets = secrets
        self.settings = settings
        self.ui = ui
        self.memory = memory
    }

    // MARK: - commands

    /// Asked before any start (the app checks the certificate: an expired one is said before openvpn is
    /// refused); `done` once it is through. Every way of connecting comes here.
    public var preflight: (Profile, @escaping () -> Void) -> Void = { _, done in done() }
    private var pending = PendingStarts()
    private var pendingThens: [String: [() -> Void]] = [:]
    /// Asked for, its preflight not done yet.
    public func isPending(_ id: String) -> Bool { pending.isPending(id) }

    /// - then: once it was asked to start, or could not be, or was disconnected while checked.
    public func connect(_ profile: Profile, then: @escaping () -> Void = {}) {
        guard active[profile.id] == nil else { return then() }
        pendingThens[profile.id, default: []].append(then)
        // A second ask while the first is checked waits for the same check.
        guard pending.begin(profile.id) else { return }
        onChange()
        preflight(profile) { [weak self] in
            self?.helperTakes(profile) { [weak self] refusal in
                guard let self else { return }
                if self.pending.finish(profile.id) == true {
                    if let refusal { self.fail(profile.id, refusal) } else { self.startConnection(profile) }
                }
                self.pendingThens.removeValue(forKey: profile.id)?.forEach { $0() }
                self.onChange()
            }
        }
    }

    /// The first helper that sets the server's DNS for the domains a profile lists (older ones ignore them). 0.2.5's
    /// did too, but builds from before it that ignore them also said 0.2.5: none of them is taken for one that does.
    public static let dnsDomainsHelper = "0.2.6"
    public static let helperTooOldForDNSDomains =
        "the running helper is older and would ignore the domains for the server's DNS: connect again once it has updated"

    /// Does the running helper report each connection's DNS (and take domains for the server's DNS)?
    /// Unknown yet: taken to.
    public var helperKnowsDNSDomains: Bool {
        !(helperVersionMismatch.map { ConnectionManager.isOlder($0, than: ConnectionManager.dnsDomainsHelper) } ?? false)
    }

    /// Domains for the server's DNS go only to a helper that knows them (an older one would set DNS for all
    /// names, or none, without a word): its version asked now (the one seen at launch may be old news),
    /// while the start is still pending. - done: why not (nil: go ahead).
    private func helperTakes(_ profile: Profile, done: @escaping (String?) -> Void) {
        guard !dnsDomains(profile).isEmpty else { return done(nil) }
        backend.lifecycle.version { [weak self] v in
            guard let self else { return }
            if let v { self.versionKnown(v) }
            done(ConnectionManager.isOlder(v ?? "unknown", than: ConnectionManager.dnsDomainsHelper)
                 ? ConnectionManager.helperTooOldForDNSDomains : nil)
        }
    }

    private func startConnection(_ profile: Profile) {
        guard active[profile.id] == nil else { return }
        lastError[profile.id] = nil
        if profile.source == .persistent { return connectPersistent(profile) }
        var bundle: ProfileBundle
        do { bundle = try reader.bundle(for: profile) } catch {
            return fail(profile.id, "\(error)")
        }
        bundle.splitDNS = splitDNS(profile)
        bundle.dnsDomains = dnsDomains(profile)
        bundle.profileID = profile.id
        bundle.appendLog = appendLog()
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
            self?.backend.connections.list { running in
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
        backend.connections.list { [weak self] running in
            guard let self else { return }
            if running.contains(where: { $0.persistent && $0.name == profile.name }) { return attach() }
            guard let persistent = self.backend.persistent else {
                self.active[profile.id] = nil
                return self.fail(profile.id, "persistent connections are not available in this version")
            }
            persistent.startPersistent(profile.name) { result in
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
        guard let id = c.helperID, let persistent = backend.persistent else { return }
        persistent.releaseManagement(id) { [weak self, weak c] err in
            guard let self, let c, self.active[c.profile.id] === c else { return }
            if let err {
                self.active[c.profile.id] = nil
                return self.fail(c.profile.id, err)
            }
            self.open(c, socket: socket, attempt: 1)
        }
    }

    /// How long the helper may take to answer a start (one that does not start at all never answers).
    public static let helperStartTimeout: TimeInterval = 30

    private func start(_ c: ActiveConnection, _ bundle: ProfileBundle) {
        let profile = c.profile
        var answered = false, gaveUp = false
        scheduler.after(ConnectionManager.helperStartTimeout) { [weak self] in
            guard let self, !answered, self.active[profile.id] === c else { return }
            gaveUp = true
            self.active[profile.id] = nil
            self.fail(profile.id, "MugVPN's helper does not answer (its log: /Library/Logs/MugVPN/helper.log)")
        }
        backend.connections.start(bundle) { [weak self] result in
            guard let self else { return }
            answered = true
            if gaveUp {
                // Too late: given up on already; a tunnel it started anyway is stopped.
                if case .success(let r) = result { self.backend.connections.stop(r.id) { _ in } }
                return
            }
            switch result {
            case .success(let r):
                c.helperID = r.id
                if c.stopRequested {
                    // Stopped before the helper answered: no socket will close for it.
                    self.backend.connections.stop(r.id) { _ in }
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
        pending.cancel(id)
        active[id]?.controller.disconnect()
    }

    public func reconnect(_ id: String) {
        active[id]?.controller.reconnect()
    }

    public func disconnectAll() {
        pending.cancelAll()
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
        backend.connections.list { [weak self] running in
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
                // By the profile's id; a tunnel without one (an older helper's) by name only if one profile has
                // it: never another profile's (it would get that one's passwords).
                let mine = self.profiles.filter { $0.source != .persistent }
                // (Names as the disk compares them: Office and office are one.)
                let named = mine.filter { $0.name.caseInsensitiveCompare(info.name) == .orderedSame }
                let match = info.profileID.map { id in mine.first { $0.id == id } } ?? (named.count == 1 ? named.first : nil)
                guard let p = match, self.active[p.id] == nil else {
                    self.backend.connections.stop(info.id) { _ in }
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
        pending.cancelAll()
        // Persistent tunnels belong to the helper: detach, do not stop or remember them.
        for c in active.values where c.profile.source == .persistent {
            c.stopRequested = true
            c.link?.close()
            active[c.profile.id] = nil
        }
        memory.remembered = active.keys.sorted()
        // A start the helper has not answered: nothing to stop or wait for yet (a late answer stops it).
        for c in active.values where c.helperID == nil && c.link == nil {
            c.stopRequested = true
            active[c.profile.id] = nil
        }
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
        controller.onKeyPassword = { [weak self] pw in self?.onKeyPassword(p, pw) }
        let c = ActiveConnection(profile: p, controller: controller)
        controller.send = { [weak c] cmd in c?.link?.send(cmd) }
        controller.sendWithFD = { [weak c] cmd, fd, done in
            guard let c, let link = c.link else { return done(false) }
            // The handle kept until it is sent.
            link.send(cmd, passing: fd.fileDescriptor) { ok in withExtendedLifetime(fd) { done(ok) } }
        }
        controller.tunnelRequest = { [weak self, weak c] kind, message, reply in
            guard let self, let id = c?.helperID else { return reply(.failure(ProfileError("not connected"))) }
            guard let requests = self.backend.tunnelRequests else { return reply(.failure(ProfileError("not used by this backend"))) }
            requests.tunnelRequest(id, kind: kind, message: message, reply: reply)
        }
        controller.onStop = { [weak self, weak c] in
            guard let self, let c else { return }
            c.stopRequested = true
            let stop = { [weak self] in
                if let id = c.helperID { self?.backend.connections.stop(id) { _ in } }
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
        let link = transport.open(socket, onEvent: { [weak self, weak c] e in
            guard let c else { return }
            c.controller.handle(e)
            self?.onChange()
        }, onClose: { [weak self, weak c] in
            guard let self, let c else { return }
            self.ended(c)
        })
        if let link {
            c.link = link
            // openvpn reads the first line as the password.
            if let pw = c.password { link.send(.managementPassword(pw)) }
            c.controller.attached()
            return
        }
        guard attempt < ConnectionManager.socketAttempts else {
            // A persistent tunnel is the Mac's: left running, only not shown here.
            if c.profile.source != .persistent, let id = c.helperID { backend.connections.stop(id) { _ in } }
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

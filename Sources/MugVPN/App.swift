import AppKit
import MugVPNAppCore
import MugVPNCore
import ServiceManagement
import UserNotifications

/// What the system's routing and DNS look like, as any user sees them (LeakCheck).
protocol NetworkProbe: AnyObject {
    func netstat() -> String
    func scutilDNS() -> String
    /// The interface the system reaches `ip` through.
    func interface(for ip: String) -> String?
    func netstat6() -> String
    /// false: no routing table to look at (the E2E fake before a test sets one).
    var available: Bool { get }
}

/// What the app does to the outside world, so E2E mode can log it instead.
protocol Services: AnyObject {
    func open(_ url: String)
    func notify(title: String, text: String)
    func showMessage(profile: String, title: String, text: String)
    /// Show a file in Finder.
    func reveal(_ path: String)
    /// Ask for a file to import; nil on Cancel.
    func chooseFile() -> String?
    var helperSetup: HelperSetup { get }
    var http: HTTPFetcher { get }
    /// MugVPN starts at login (the system's login item for it).
    var launchAtLogin: Bool { get }
    func setLaunchAtLogin(_ on: Bool) throws
    /// Ask where to save a file; nil on Cancel.
    func chooseSaveLocation(suggested: String) -> String?
    /// Uninstalling: the user's files, settings and passwords; then the app itself.
    func removeUserData(_ paths: [String])
    func moveAppToTrash()
}

final class RealServices: Services {
    let helperSetup: HelperSetup = SMHelperSetup()
    let http: HTTPFetcher = URLSessionFetcher()
    var launchAtLogin: Bool { SMAppService.mainApp.status == .enabled }
    func setLaunchAtLogin(_ on: Bool) throws {
        if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
    }

    func removeUserData(_ paths: [String]) {
        paths.forEach { try? FileManager.default.removeItem(atPath: $0) }
        UserDefaults.standard.removePersistentDomain(forName: MugVPNIDs.appBundleID)
        KeychainStore().removeEverything()
    }

    func moveAppToTrash() {
        try? FileManager.default.trashItem(at: Bundle.main.bundleURL, resultingItemURL: nil)
    }

    init() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert]) { _, _ in }
    }

    func open(_ url: String) {
        if let u = URL(string: url) { NSWorkspace.shared.open(u) }
    }

    func notify(title: String, text: String) {
        let c = UNMutableNotificationContent()
        c.title = title
        c.body = text
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: UUID().uuidString, content: c, trigger: nil))
    }

    func showMessage(profile: String, title: String, text: String) {
        showMessageWindow(profile: profile, title: title, text: text)
    }

    func reveal(_ path: String) {
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }

    func chooseSaveLocation(suggested: String) -> String? {
        let p = NSSavePanel()
        p.nameFieldStringValue = suggested
        NSApp.activate(ignoringOtherApps: true)
        return p.runModal() == .OK ? p.url?.path : nil
    }

    func chooseFile() -> String? {
        let p = NSOpenPanel()
        p.allowedContentTypes = []
        p.allowsOtherFileTypes = true
        p.canChooseDirectories = true // .tblk folders
        p.treatsFilePackagesAsDirectories = false
        NSApp.activate(ignoringOtherApps: true)
        return p.runModal() == .OK ? p.url?.path : nil
    }
}

func showMessageWindow(profile: String, title: String, text body: String) {
    let t = Form.label(body, id: "text")
    // The window says whose message it is: a server's text cannot pass for a system dialog.
    showForm(kind: "message", profile: profile, title: profile.isEmpty ? L("MugVPN") : windowTitle(profile), views: [Form.label(title, id: "title_text", bold: true), t],
             cancelTitle: nil, ok: { _ in true })
}

func showError(_ text: String, profile: String = "") {
    showForm(kind: "error", profile: profile, title: L("MugVPN"), views: [Form.label(text, id: "text")],
             cancelTitle: nil, ok: { _ in true })
}

/// The app: menu bar item, menus, windows; the logic is in MugVPNAppCore.
final class AppController: NSObject, NSMenuDelegate {
    let services: Services
    let settingsStore: SettingsStore
    let store: ProfileStore
    let manager: ConnectionManager
    let secrets: SecretStore
    let logsDir: String
    var runDir = MugVPNIDs.runDir
    let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    let menu = NSMenu()
    /// Status windows shown automatically while connecting (closed once up).
    private var autoStatus: Set<String> = []
    private var notified: Set<String> = []
    private var conflictsShown: [NetworkConflict] = []
    private(set) var leaksShown: [LeakFinding] = []
    /// Profiles whose kill switch blocks traffic (the helper's word).
    private(set) var blockedBy: [String] = []

    /// Ask the helper which kill switches block traffic now.
    func refreshBlocks() {
        manager.helperClient.blocks { [weak self] names in
            guard let self, names != self.blockedBy else { return }
            if !names.isEmpty, self.blockedBy.isEmpty {
                self.services.notify(title: L("MugVPN"), text: L("Internet blocked: %@ dropped. Reconnect it or unblock.", names.joined(separator: ", ")))
                self.probeCaptivePortal()
            }
            self.blockedBy = names
            self.rebuildMenu()
        }
    }

    /// The network asks for a sign-in first (captive.apple.com answers with another page);
    /// nil: no answer to tell by (a kill switch's block keeps the probe out too).
    private(set) var captivePortal: Bool? = false
    /// Offered when a sign-in page answers, or while blocked and nothing could be asked.
    var offerSignIn: Bool { captivePortal == true || (captivePortal == nil && !blockedBy.isEmpty) }

    /// Asked as macOS asks; the answer (or none) is kept until the next network change.
    func probeCaptivePortal() {
        services.http.get(CaptivePortal.probeURL, username: "", password: "") { [weak self] r in
            guard let self else { return }
            let v = CaptivePortal.verdict(r)
            guard v != self.captivePortal else { return }
            self.captivePortal = v
            if v == true { self.services.notify(title: L("MugVPN"), text: L("This network asks you to sign in first.")) }
            self.rebuildMenu()
        }
    }

    /// The sign-in page; a kill switch's block is lifted for a while so it can load.
    @objc func signInToNetwork() {
        let open: () -> Void = { [weak self] in self?.services.open(CaptivePortal.probeURL.absoluteString) }
        guard !blockedBy.isEmpty else { return open() }
        manager.helperClient.suspendBlocks(seconds: CaptivePortal.signInSeconds) { [weak self] err in
            if let err { return showError(err) }
            open()
            // Lifted: now the probe can tell whether there is anything to sign in to.
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) { self?.probeCaptivePortal() }
        }
    }

    /// An older helper cannot start itself again: registering the service again puts the app's in
    /// place. launchd stops the old one, and with it every user's tunnels: asked first.
    @objc func updateHelper() {
        showForm(kind: "confirm", profile: "", title: L("Update MugVPN's Helper"),
                 views: [Form.label(L("The running helper is an older one that cannot update itself. Putting the new one in place stops every MugVPN connection on this Mac, of every user. Go ahead?"),
                                    id: "prompt_text")],
                 okTitle: L("Update"), ok: { [weak self] _ in
            DispatchQueue.main.async {
                guard let self else { return }
                self.manager.disconnectAll()
                self.services.helperSetup.reregister { [weak self] err in
                    guard let self else { return }
                    if let err { return showError(L("MugVPN's helper was not updated: %@", "\(err)")) }
                    self.manager.helperReplaced()
                    self.services.notify(title: L("MugVPN"), text: L("MugVPN's helper was updated."))
                }
            }
            return true
        })
    }

    @objc func unblockInternet() {
        manager.helperClient.unblock { [weak self] err in
            if let err { showError(err) }
            self?.refreshBlocks()
        }
    }
    var probe: NetworkProbe = RealNetworkProbe()
    private var leakTimer: Timer?
    var logText: (ActiveConnection) -> String = { _ in "" }
    /// Each connection's own settings (Connections window).
    var options = ProfileOptionsStore(backend: DefaultsBackend(defaults: .standard)) {
        didSet { wireOptions() }
    }
    private var connectionsWindow: ConnectionsWindow?
    // After the current event: quitting can be triggered from inside a callback.
    var onQuit: () -> Void = { DispatchQueue.main.async { NSApp.terminate(nil) } }

    init(services: Services, settingsStore: SettingsStore, store: ProfileStore, manager: ConnectionManager,
         secrets: SecretStore, logsDir: String) {
        self.services = services
        self.settingsStore = settingsStore
        self.store = store
        self.manager = manager
        self.secrets = secrets
        self.logsDir = logsDir
        super.init()
        menu.delegate = self
        menu.autoenablesItems = false
        statusItem.menu = menu
        statusItem.button?.setAccessibilityIdentifier("mugvpn_status_item")
        manager.onChange = { [weak self] in self?.changed() }
        wireOptions()
        rescan()
        changed()
    }

    private func wireOptions() {
        manager.splitDNS = { [weak self] p in self?.options.options(p.id).splitDNS ?? false }
        // Before any start, whichever way it comes (menu, command line, auto-connect, wake): the certificate.
        manager.preflight = { [weak self] p, done in
            guard let self else { return done() }
            self.warnCertificate(p, then: done)
        }
        // A PKCS#12's key password as typed: its end can be read now.
        manager.onKeyPassword = { [weak self] p, pw in self?.warnCertificate(p, password: pw) }
        manager.protection = { [weak self] p in
            guard let self else { return ProtectionOptions() }
            return EffectiveSettings.protection(self.settingsStore.settings, self.options.options(p.id))
        }
        manager.autoConnect = { [weak self] p in self?.options.options(p.id).autoConnect ?? false }
        manager.profileSettings = { [weak self] p in
            guard let self else { return ConnectionSettings() }
            return EffectiveSettings.connection(self.settingsStore.settings, self.options.options(p.id))
        }
    }

    // MARK: - state

    func rescan() {
        let hidePersistent = settingsStore.settings.persistentConnections == .disable
        manager.profiles = store.scan().filter { !(hidePersistent && $0.source == .persistent) }
        rebuildMenu()
        connectionsWindow?.profilesChanged()
    }

    enum Icon: String { case idle, connecting, connected }

    var icon: Icon {
        let states = manager.active.values.map(\.controller.status)
        if states.contains(where: { if case .connected = $0 { return true }; return false }) { return .connected }
        return states.isEmpty ? .idle : .connecting
    }

    var tooltip: String {
        let lines = manager.active.values.sorted { $0.profile.displayName < $1.profile.displayName }.map { c in
            "\(c.profile.displayName): \(describe(c.controller.status))"
        }
        return (["MugVPN"] + lines).joined(separator: "\n")
    }

    func describe(_ s: ConnectionStatus) -> String {
        switch s {
        case .disconnected: return L("Disconnected")
        case .connecting(let st): return st.isEmpty ? L("Connecting") : L("Connecting (%@)", st.lowercased())
        case .waitingForWebAuth: return L("Waiting for web authentication")
        case .connected(let ip, _, let errors): return errors ? L("Connected with errors (%@)", ip) : L("Connected (%@)", ip)
        case .reconnecting: return L("Reconnecting")
        case .disconnecting: return L("Disconnecting")
        }
    }

    private func changed() {
        let button = statusItem.button
        // MugVPN's own monochrome icon (Resources/menubar); macOS tints the template.
        let name = "MenuIcon-\(icon.rawValue)"
        let image = NSImage(named: name) // named and cached by AppKit (Resources/MenuIcon-*.png)
        image?.isTemplate = true
        image?.size = NSSize(width: 18, height: 18)
        image?.accessibilityDescription = L("MugVPN: %@", icon == .idle ? L("not connected") : icon == .connected ? L("connected") : L("connecting"))
        button?.image = image
        button?.toolTip = tooltip
        for c in manager.active.values {
            let id = c.profile.id
            guard case .connected(let ip, _, _) = c.controller.status else {
                wasConnected.remove(id)
                continue
            }
            guard wasConnected.insert(id).inserted else { continue } // already up: no change
            warnCertificate(c.profile)
            if autoStatus.remove(id) != nil {
                WindowRegistry.shared.of(kind: "status", profile: c.profile.displayName).forEach { $0.close() }
            }
            // show_balloon: 0 never, 1 the first time, 2 after reconnects too.
            let mode = settingsStore.settings.showBalloon
            if mode == .always || (mode == .initial && notified.insert(id).inserted) {
                services.notify(title: c.profile.displayName, text: L("Connected, %@", ip))
            }
        }
        for id in notified.union(wasConnected) where manager.active[id] == nil {
            notified.remove(id)
            wasConnected.remove(id)
        }
        for (id, err) in manager.lastError where !shownErrors.contains(id + err) {
            shownErrors.insert(id + err)
            let name = manager.profiles.first { $0.id == id }?.displayName ?? id
            showError(name + ": " + localizedCore(err), profile: name)
        }
        if let v = manager.helperVersionMismatch, !helperVersionShown {
            helperVersionShown = true
            if manager.helperIsNewer {
                services.notify(title: L("MugVPN"), text: L("MugVPN's helper is version %@, newer than this app (%@): update MugVPN.",
                                                          v, MugVPNIDs.helperVersion))
            } else {
                services.notify(title: L("MugVPN"), text: L("MugVPN's helper is version %@, not this app's %@: it is updated once no connection uses it (or after a restart).",
                                                          v, MugVPNIDs.helperVersion))
            }
        }
        updateStatusWindows()
        // Conflicts, leaks and blocks are looked at when connections change state,
        // not on every log line or byte count (each check runs processes).
        let statuses = manager.active.values.map { "\($0.profile.id)=\($0.controller.status)" }.sorted().joined(separator: ";")
        if statuses != lastCheckedStatuses {
            lastCheckedStatuses = statuses
            checkConflicts()
            checkLeaks()
            refreshBlocks()
        }
        rebuildMenu()
    }
    private var wasConnected: Set<String> = []
    private var helperVersionShown = false
    /// Profiles warned about their certificate since MugVPN started.
    private var certificateWarned: Set<String> = []

    /// A client certificate that ends within 30 days, or has ended: said once a run, on connecting.
    /// - then: called once the check is done (a PKCS#12 is read off the main thread, within its deadline).
    private func warnCertificate(_ p: Profile, password: String? = nil, then: @escaping () -> Void = {}) {
        guard !certificateWarned.contains(p.id), let config = store.config(of: p) else { return then() }
        let dir = (p.path as NSString).deletingLastPathComponent
        func path(_ f: String) -> String { f.hasPrefix("/") ? f : (dir as NSString).appendingPathComponent(f) }
        if let end = CertificateExpiry.clientCertificate(config: config, read: { try? String(contentsOfFile: path($0), encoding: .utf8) })
            .flatMap(CertificateExpiry.notAfter(pem:)) {
            warn(p, end)
            return then()
        }
        // PKCS#12: read by openssl off the main thread, with the key password (saved, or as typed).
        let data: Data?
        switch CertificateExpiry.clientPKCS12(config: config) {
        case .file(let f)?: data = FileManager.default.contents(atPath: path(f))
        case .inline(let d)?: data = d
        case nil: data = nil
        }
        guard let data else { return then() }
        // A check already running (one after the key password was typed): wait for its result.
        certificateWaiters[p.id, default: []].append(then)
        guard certificateChecking.insert(p.id).inserted else { return }
        let pw = password ?? secrets.get(p.secretsKey, .keyPassword), tool = pkcs12Tool
        DispatchQueue.global().async { [weak self] in
            let end = CertificateExpiry.notAfter(pkcs12: data, password: pw, openssl: tool)
            DispatchQueue.main.async {
                guard let self else { return }
                self.certificateChecking.remove(p.id)
                if let end { self.warn(p, end) }
                self.certificateWaiters.removeValue(forKey: p.id)?.forEach { $0() }
            }
        }
    }
    private var certificateChecking: Set<String> = []
    private var certificateWaiters: [String: [() -> Void]] = [:]
    /// The openssl that reads PKCS#12 (a test build may slow it down: MUGVPN_E2E_OPENSSL).
    private var pkcs12Tool: String {
        testingBuild ? ProcessInfo.processInfo.environment["MUGVPN_E2E_OPENSSL"] ?? "/usr/bin/openssl" : "/usr/bin/openssl"
    }

    private func warn(_ p: Profile, _ end: Date) {
        guard !certificateWarned.contains(p.id), let w = CertificateExpiry.warning(notAfter: end, now: Date()) else { return }
        certificateWarned.insert(p.id)
        let day = DateFormatter.localizedString(from: end, dateStyle: .medium, timeStyle: .none)
        switch w {
        case .expired: services.notify(title: p.displayName, text: L("Its certificate expired on %@: ask for a new one.", day))
        case .expiresSoon: services.notify(title: p.displayName, text: L("Its certificate expires on %@: ask for a new one in time.", day))
        }
    }
    private var shownErrors: Set<String> = []

    private func checkConflicts() {
        let up = manager.active.values.filter { if case .connected = $0.controller.status { return true }; return false }
            .sorted { $0.profile.displayName < $1.profile.displayName }
        let found = NetworkConflicts.find(up.map { c in
            let log = logText(c)
            return (c.profile.displayName, OpenVPNLogFacts.parse(log), log)
        })
        for c in found where !conflictsShown.contains(c) {
            services.notify(title: L("MugVPN"), text: conflictText(c))
        }
        conflictsShown = found
    }

    /// Connections that take all traffic: their utun devices, their servers' addresses,
    /// and whether IPv6 is blocked (as the helper does it).
    private func fullTunnels() -> (devices: Set<String>, servers: [String], ipv6Blocked: Bool) {
        var devices = Set<String>(), servers: [String] = [], protections: [ProtectionOptions] = []
        for c in manager.active.values {
            guard case .connected = c.controller.status else { continue }
            let log = logText(c)
            let f = OpenVPNLogFacts.parse(log)
            let halves = f.routes.filter { $0.count == 4 && $0[0] == "-net" && $0[3] == "128.0.0.0" }.map { $0[1] }
            let replaced = f.routes.contains { $0.count == 4 && $0[0] == "-net" && $0[1] == "0.0.0.0" && $0[3] == "0.0.0.0" }
            guard (halves.contains("0.0.0.0") && halves.contains("128.0.0.0")) || replaced, let dev = f.device else { continue }
            devices.insert(dev)
            servers += LeakCheck.serverAddresses(log: log)
            protections.append(c.profile.source == .persistent ? persistentSettings(c.profile).protection
                                : EffectiveSettings.protection(settingsStore.settings, options.options(c.profile.id)))
        }
        return (devices, servers, LeakCheck.ipv6Blocked(protections))
    }

    /// A persistent profile's settings, as the helper reads them (beside it in config-auto).
    func persistentSettings(_ p: Profile) -> PersistentSettings {
        let path = ((p.path as NSString).deletingLastPathComponent as NSString).appendingPathComponent(p.name + ".json")
        guard let d = FileManager.default.contents(atPath: path) else { return PersistentSettings() }
        return (try? PersistentSettings.parse(d)) ?? PersistentSettings()
    }

    /// Statuses of the connections: checks run again when these change, not on every log line.
    private var lastCheckedStatuses = ""
    private var leakGeneration = 0
    private var leakRunning = false

    /// Does the system really send everything into the tunnels that should carry it all?
    /// Read-only (netstat, scutil, route get); off the main thread unless `now`.
    func checkLeaks(now: Bool = false) {
        let (devices, servers, ipv6Blocked) = fullTunnels()
        if devices.isEmpty || !probe.available {
            leakTimer?.invalidate()
            leakTimer = nil
            if !leaksShown.isEmpty { leaksShown = []; rebuildMenu() }
            return
        }
        if leakTimer == nil {
            // DHCP can hand out routes later (TunnelVision): look again now and then.
            leakTimer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in self?.checkLeaks() }
        }
        let probe = self.probe
        let work = {
            let routes = LeakCheck.routes(netstat: probe.netstat())
            let dns = LeakCheck.primaryDNS(scutil: probe.scutilDNS()).map { ($0, probe.interface(for: $0)) }
            return LeakCheck.findings(routes: routes, tunnels: devices, dns: dns, servers: servers)
                + LeakCheck.ipv6Findings(defaults: LeakCheck.ipv6Defaults(netstat: probe.netstat6()), tunnels: devices,
                                         blocked: ipv6Blocked)
                + (ipv6Blocked ? [] : LeakCheck.ipv6Bypass(netstat: probe.netstat6(), tunnels: devices))
        }
        // One check at a time; an older result never replaces a newer one.
        leakGeneration += 1
        let generation = leakGeneration
        let show = { [weak self] (found: [LeakFinding]) in
            guard let self else { return }
            self.leakRunning = false
            guard generation == self.leakGeneration else { return self.checkLeaks() }
            for f in found where !self.leaksShown.contains(f) { self.services.notify(title: L("MugVPN"), text: self.leakText(f)) }
            if found != self.leaksShown {
                self.leaksShown = found
                self.rebuildMenu()
            }
        }
        if now { return show(work()) }
        guard !leakRunning else { return }   // the running one sees it's stale and runs again
        leakRunning = true
        DispatchQueue.global(qos: .utility).async {
            let found = work()
            DispatchQueue.main.async { show(found) }
        }
    }

    func leakText(_ f: LeakFinding) -> String {
        switch f {
        case .defaultOutside: return L("Not all traffic goes through the VPN: the tunnel does not hold the default route")
        case .bypass(let net, let iface): return L("Traffic to %@ goes around the VPN (through %@)", net, iface)
        case .dnsOutside(let server, let iface): return L("DNS server %@ is reached outside the VPN (through %@)", server, iface)
        case .unverified(let server): return L("Cannot check how DNS server %@ is reached", server)
        case .ipv6Outside(let iface): return L("IPv6 traffic goes around the VPN (through %@)", iface)
        }
    }

    func conflictText(_ c: NetworkConflict) -> String {
        switch c {
        case .bothTakeDefaultRoute(let a, let b): return L("%@ and %@ both route all traffic", a, b)
        case .overlappingRoutes(let a, let b, let net): return L("%@ and %@ both route %@", a, b, net)
        case .dnsTakenByAnother(let a): return L("%@ could not set its DNS: another tunnel already redirects all DNS", a)
        }
    }

    func systemEvent(_ e: SystemEvent) {
        if e == .networkChanged || e == .didWake {
            checkLeaks()
            probeCaptivePortal()
        }
        manager.handle(e, disconnectOnSleep: { [weak self] p in
            guard let self else { return false }
            return EffectiveSettings.disconnectOnSleep(self.settingsStore.settings, self.options.options(p.id))
        })
    }

    // MARK: - menu

    func menuNeedsUpdate(_ menu: NSMenu) {
        rescan()
        refreshBlocks()
    }

    func rebuildMenu() {
        menu.removeAllItems()
        for c in conflictsShown {
            let i = NSMenuItem(title: "⚠︎ " + conflictText(c), action: nil, keyEquivalent: "")
            i.isEnabled = false
            menu.addItem(i)
        }
        if !blockedBy.isEmpty {
            let i = NSMenuItem(title: "⛔︎ " + L("Internet blocked: %@ dropped. Reconnect it or unblock.", blockedBy.joined(separator: ", ")),
                               action: nil, keyEquivalent: "")
            i.isEnabled = false
            menu.addItem(i)
            menu.addItem(action(L("Unblock Internet"), #selector(unblockInternet)))
        }
        for f in leaksShown {
            let i = NSMenuItem(title: "⚠︎ " + leakText(f), action: nil, keyEquivalent: "")
            i.isEnabled = false
            menu.addItem(i)
        }
        if offerSignIn { menu.addItem(action(L("Sign in to This Network…"), #selector(signInToNetwork))) }
        if manager.helperNeedsManualUpdate { menu.addItem(action(L("Update MugVPN's Helper…"), #selector(updateHelper))) }
        if !conflictsShown.isEmpty || !leaksShown.isEmpty || !blockedBy.isEmpty || offerSignIn || manager.helperNeedsManualUpdate {
            menu.addItem(.separator())
        }
        let profiles = manager.profiles
        if profiles.isEmpty {
            let i = NSMenuItem(title: L("No profiles yet"), action: nil, keyEquivalent: "")
            i.isEnabled = false
            menu.addItem(i)
        } else if profiles.count == 1 {
            profileItems(profiles[0]).forEach(menu.addItem)
        } else {
            for node in ProfileStore.menu(profiles, mode: settingsStore.settings.menuView) { menu.addItem(item(node)) }
        }
        if manager.active.count >= 2 {
            menu.addItem(.separator())
            menu.addItem(action(L("Disconnect All"), #selector(disconnectAll)))
        }
        menu.addItem(.separator())
        menu.addItem(action(L("Connections…"), #selector(openConnections)))
        let imp = NSMenuItem(title: L("Import"), action: nil, keyEquivalent: "")
        imp.submenu = NSMenu()
        imp.submenu?.autoenablesItems = false
        imp.submenu?.addItem(action(L("Import File…"), #selector(importFile)))
        imp.submenu?.addItem(action(L("Import from Access Server…"), #selector(importAccessServer)))
        imp.submenu?.addItem(action(L("Import from URL…"), #selector(importURL)))
        menu.addItem(imp)
        menu.addItem(action(L("Settings…"), #selector(openSettings)))
        menu.addItem(action(L("Export Diagnostics…"), #selector(exportDiagnostics)))
        menu.addItem(action(L("About MugVPN"), #selector(about)))
        menu.addItem(action(L("Quit MugVPN"), #selector(quit)))
    }

    @objc func disconnectAll() { disconnectEverything() }

    private func action(_ title: String, _ sel: Selector, _ obj: Any? = nil, enabled: Bool = true) -> NSMenuItem {
        let i = NSMenuItem(title: title, action: sel, keyEquivalent: "")
        i.target = self
        i.representedObject = obj
        i.isEnabled = enabled
        return i
    }

    private func item(_ node: MenuNode) -> NSMenuItem {
        switch node {
        case .folder(let name, let children):
            let i = NSMenuItem(title: name, action: nil, keyEquivalent: "")
            i.submenu = NSMenu()
            i.submenu?.autoenablesItems = false
            children.forEach { i.submenu?.addItem(item($0)) }
            return i
        case .profile(let p):
            let i = NSMenuItem(title: p.displayName, action: nil, keyEquivalent: "")
            i.submenu = NSMenu()
            i.submenu?.autoenablesItems = false
            profileItems(p).forEach { i.submenu?.addItem($0) }
            if case .connected = manager.active[p.id]?.controller.status { i.state = .on }
            return i
        }
    }

    /// In groups, as on Windows; then this connection's settings.
    private func profileItems(_ p: Profile) -> [NSMenuItem] {
        let active = manager.active[p.id] != nil
        return [action(L("Connect"), #selector(connectItem), p, enabled: !active),
                action(L("Disconnect"), #selector(disconnectItem), p, enabled: active || manager.isPending(p.id)),
                action(L("Reconnect"), #selector(reconnectItem), p, enabled: active),
                action(L("Show Status"), #selector(showStatusItem), p, enabled: active),
                .separator(),
                action(L("View Log"), #selector(viewLog), p),
                action(L("Edit Config"), #selector(editConfig), p),
                action(L("Clear Saved Passwords"), #selector(clearPasswords), p, enabled: secrets.hasSaved(p.secretsKey)),
                .separator(),
                action(L("Connection Settings…"), #selector(connectionSettings), p)]
    }

    @objc func openConnections() { showConnections(select: nil) }

    @objc func connectionSettings(_ sender: NSMenuItem) {
        showConnections(select: sender.representedObject as? Profile)
    }

    func showConnections(select p: Profile?) {
        if connectionsWindow == nil || WindowRegistry.shared.find(connectionsWindow!.window.windowID) == nil {
            let c = ConnectionsWindow(app: self)
            c.window.onClose = { [weak self] in self?.connectionsWindow = nil }
            connectionsWindow = c
        }
        connectionsWindow?.show(select: p)
    }

    // MARK: - actions

    @objc func connectItem(_ sender: NSMenuItem) {
        guard let p = sender.representedObject as? Profile else { return }
        connect(p)
    }

    /// Before it starts: a server refuses an expired certificate long before anything is up.
    /// - then: once it was asked to start (or could not be, or was disconnected while checked).
    /// The certificate check before it is the manager's preflight (every way of connecting).
    func connect(_ p: Profile, then: @escaping () -> Void = {}) {
        let setup = services.helperSetup
        if setup.state == .notRegistered {
            if HelperRegistration.problem(bundlePath: Bundle.main.bundlePath) != nil, !setup.isTestDouble {
                showError(L("Move MugVPN to the Applications folder, open it from there and connect again."))
                return then()
            }
            setup.register()
        }
        guard setup.state == .enabled else {
            showHelperSetup()
            return then()
        }
        manager.connect(p) { [weak self] in
            guard let self else { return then() }
            if self.manager.active[p.id] != nil, !EffectiveSettings.silent(self.settingsStore.settings, self.options.options(p.id)) {
                self.autoStatus.insert(p.id)
                self.showStatus(p)
            }
            then()
        }
    }

    /// Disconnect, a connection still being checked included (it then does not start).
    func disconnect(_ p: Profile) { manager.disconnect(p.id) }

    func disconnectEverything() { manager.disconnectAll() }

    @objc func disconnectItem(_ sender: NSMenuItem) {
        guard let p = sender.representedObject as? Profile else { return }
        disconnect(p)
    }

    @objc func reconnectItem(_ sender: NSMenuItem) {
        guard let p = sender.representedObject as? Profile else { return }
        manager.reconnect(p.id)
    }

    @objc func showStatusItem(_ sender: NSMenuItem) {
        guard let p = sender.representedObject as? Profile else { return }
        autoStatus.remove(p.id)
        showStatus(p)
    }

    /// A zip for a bug report or an administrator: versions, the network's state, the profiles
    /// without their secrets, the logs (Diagnostics).
    @objc func exportDiagnostics() {
        let stamp = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
        guard let dest = services.chooseSaveLocation(suggested: "MugVPN Diagnostics \(stamp).zip") else { return }
        let profiles = manager.profiles.map { ($0.displayName, store.config(of: $0) ?? "") }
        let logs: [(String, String)] = manager.profiles.compactMap { p in
            let path = LogLocation.path(profile: safeLogName(p.name), helperID: manager.active[p.id]?.helperID,
                                        uid: getuid(), runDir: runDir, logsDir: logsDir,
                                        exists: { FileManager.default.isReadableFile(atPath: $0) })
            return path.flatMap { try? String(contentsOfFile: $0, encoding: .utf8) }.map { (p.displayName, String($0.suffix(1 << 20))) }
        }
        let appVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "dev"
        let os = ProcessInfo.processInfo.operatingSystemVersionString
        let connected = manager.active.values.map { "\($0.profile.displayName): \($0.controller.status)" }.sorted()
        manager.helperClient.version { [weak self] helperVersion in
            DispatchQueue.global().async {
                func run(_ tool: String, _ args: [String]) -> String {
                    let p = Process()
                    p.executableURL = URL(fileURLWithPath: tool)
                    p.arguments = args
                    let out = Pipe()
                    p.standardOutput = out
                    p.standardError = out
                    guard (try? p.run()) != nil else { return "(\(tool) did not run)" }
                    let d = out.fileHandleForReading.readDataToEndOfFile()
                    p.waitUntilExit()
                    return String(decoding: d, as: UTF8.self)
                }
                let openvpn = run(MugVPNIDs.libexecDir + "/openvpn", ["--version"]).components(separatedBy: "\n").first ?? ""
                let files = Diagnostics.files(
                    summary: ["MugVPN": appVersion, "helper": helperVersion ?? "not answering", "openvpn": openvpn, "macOS": os,
                              "connections": connected.isEmpty ? "none" : connected.joined(separator: "; ")],
                    commands: ["routes.txt": run("/usr/sbin/netstat", ["-rn"]), "dns.txt": run("/usr/sbin/scutil", ["--dns"]),
                               "interfaces.txt": run("/sbin/ifconfig", [])],
                    profiles: profiles, logs: logs)
                let dir = FileManager.default.temporaryDirectory.appendingPathComponent("MugVPN Diagnostics \(stamp)")
                try? FileManager.default.removeItem(at: dir)
                for f in files {
                    let url = dir.appendingPathComponent(f.name)
                    try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
                    try? Data(f.text.utf8).write(to: url)
                }
                try? FileManager.default.removeItem(atPath: dest)
                let zipped = run("/usr/bin/ditto", ["-c", "-k", "--keepParent", dir.path, dest])
                try? FileManager.default.removeItem(at: dir)
                DispatchQueue.main.async {
                    guard let self else { return }
                    if FileManager.default.fileExists(atPath: dest) { self.services.reveal(dest) }
                    else { showError(L("Cannot export diagnostics: %@", zipped)) }
                }
            }
        }
    }

    @objc func viewLog(_ sender: NSMenuItem) {
        guard let p = sender.representedObject as? Profile else { return }
        let path = LogLocation.path(profile: safeLogName(p.name), helperID: manager.active[p.id]?.helperID,
                                    uid: getuid(), runDir: runDir, logsDir: logsDir,
                                    exists: { FileManager.default.isReadableFile(atPath: $0) })
        guard let path else {
            return services.showMessage(profile: p.displayName, title: p.displayName, text: L("No log for %@ yet.", p.displayName))
        }
        services.open(URL(fileURLWithPath: path).absoluteString)
    }

    @objc func editConfig(_ sender: NSMenuItem) {
        guard let p = sender.representedObject as? Profile else { return }
        services.open(URL(fileURLWithPath: p.path).absoluteString)
    }

    @objc func clearPasswords(_ sender: NSMenuItem) {
        guard let p = sender.representedObject as? Profile else { return }
        secrets.removeAll(p.secretsKey)
        rebuildMenu()
    }

    func showHelperSetup() {
        let setup = services.helperSetup
        let actions = FormActions()
        let open = Form.button("open_settings", L("Open System Settings"), key: "\r", target: actions, action: #selector(FormActions.okPressed))
        let w = showForm(kind: "helper_setup", profile: "", title: L("MugVPN"),
                         views: [Form.label(L("MugVPN needs its helper to start tunnels."), bold: true),
                                 Form.label(L("Turn on MugVPN in System Settings > General > Login Items, then connect again.")),
                                 open], okTitle: L("Later"), cancelTitle: nil, ok: { _ in true })
        objc_setAssociatedObject(w, "open", actions, .OBJC_ASSOCIATION_RETAIN)
        actions.ok = { setup.openLoginItems() }
    }

    // MARK: - status window

    private var statusWindows: [String: (AppWindow, StatusView)] = [:]

    func showStatus(_ p: Profile) {
        if let (w, _) = statusWindows[p.id], WindowRegistry.shared.find(w.windowID) != nil {
            w.present()
            return
        }
        let v = StatusView(
            onConnect: { [weak self] in self?.connect(p) },
            onDisconnect: { [weak self] in self?.disconnect(p) },
            onReconnect: { [weak self] in self?.manager.reconnect(p.id) })
        let w = AppWindow(kind: "status", profile: p.displayName, title: windowTitle(p.displayName), content: v.view)
        v.onHide = { [weak w] in w?.close() }
        v.apply(settingsStore.settings.logTheme)
        v.onTheme = { [weak self] theme in try? self?.settingsStore.update { $0.logTheme = theme } }
        w.onClose = { [weak self] in self?.statusWindows[p.id] = nil; self?.autoStatus.remove(p.id) }
        statusWindows[p.id] = (w, v)
        updateStatusWindows()
        w.present()
    }

    private func updateStatusWindows() {
        for (id, (_, v)) in statusWindows {
            guard let c = manager.active[id] else {
                v.update(state: L("Disconnected"), ip: "", bytesIn: 0, bytesOut: 0, log: nil, active: false)
                continue
            }
            var ip = ""
            if case .connected(let a, let a6, _) = c.controller.status { ip = [a, a6].filter { !$0.isEmpty }.joined(separator: ", ") }
            v.update(state: describe(c.controller.status), ip: ip, bytesIn: c.controller.bytesIn,
                     bytesOut: c.controller.bytesOut, log: c.controller.log, total: c.controller.logTotal, active: true)
        }
    }

    // MARK: - import

    @objc func importFile() {
        guard let path = services.chooseFile() else { return }
        importFiles([path])
    }

    /// An import another program asked for (`--command import`): the user says yes first.
    /// - finished: nil once imported, or why not.
    func confirmImport(_ path: String, finished: ((String?) -> Void)? = nil) {
        showForm(kind: "confirm", profile: "", title: L("Import"),
                 views: [Form.label(L("A program asked MugVPN to import %@. Import it?", ProfileDownloader.visible(path)), id: "prompt_text")],
                 okTitle: L("Import"), ok: { [weak self] _ in
            DispatchQueue.main.async {
                self?.importOne(path, downloaded: false, allowOutside: false, finished: finished)
                self?.rescan()
            }
            return true
        }, cancel: { finished?("not imported: declined") })
    }

    /// - downloaded: from a URL or an Access Server; such a profile may not
    ///   name files on this Mac at all.
    func importFiles(_ paths: [String], downloaded: Bool = false) {
        for path in paths { importOne(path, downloaded: downloaded, allowOutside: false) }
        rescan()
    }

    /// - name: the new profile's name (Duplicate); `done` gets the imported profile.
    func importOne(_ path: String, downloaded: Bool, allowOutside: Bool, as name: String? = nil,
                   done: ((Profile) -> Void)? = nil, finished: ((String?) -> Void)? = nil) {
        let file = (path as NSString).lastPathComponent
        do {
            let skipped = path.lowercased().hasSuffix(".tblk")
                ? try store.importTunnelblick(at: path, allowOutside: allowOutside, secrets: secrets, options: options).flatMap(\.skipped)
                : try { () throws -> [String] in
                    let r = try store.importProfile(at: path, as: name, allowOutside: allowOutside, secrets: secrets, options: options)
                    rescan()
                    done?(r.profile)
                    return r.skipped
                }()
            if !skipped.isEmpty {
                services.showMessage(profile: "", title: L("Imported"),
                                     text: L("Not imported (MugVPN does not run profile scripts as root): %@", skipped.joined(separator: ", ")))
            }
            finished?(nil)
        } catch let e as ImportNeedsConsent {
            let list = e.outside.joined(separator: "\n")
            if downloaded {
                finished?("a downloaded profile cannot name files on this Mac")
                return showError(L("Cannot import %@: a downloaded profile cannot name files on this Mac:\n%@", file, list))
            }
            // Read with the user's rights and sent to the server: the user decides.
            showForm(kind: "confirm", profile: "", title: L("Import"),
                     views: [Form.label(L("%@ names files outside its folder. Copy them into the profile? The VPN server may receive their contents.\n\n%@", file, list),
                                        id: "prompt_text")],
                     okTitle: L("Copy and Import"), ok: { [weak self] _ in
                DispatchQueue.main.async {
                    self?.importOne(path, downloaded: false, allowOutside: true, as: name, done: done, finished: finished)
                    self?.rescan()
                }
                return true
            }, cancel: { finished?("not imported: declined") })
        } catch {
            finished?("\(error)")
            showError(L("Cannot import %@: %@", file, "\(error)"))
        }
    }

    @objc func importAccessServer() {
        showForm(kind: "import_as", profile: "", title: L("Import from Access Server"),
                 views: [Form.row(L("Server:"), Form.field("server", placeholder: "vpn.example.com")),
                         Form.row(L("Username:"), Form.field("username")),
                         Form.row(L("Password:"), Form.field("password", secure: true)),
                         Form.checkbox("autologin", L("Autologin profile (no password when connecting)"))],
                 okTitle: L("Import"), ok: { [weak self] w in
            self?.download(.accessServer(host: text(w, "server"), autologin: checked(w, "autologin")),
                           username: text(w, "username"), password: text(w, "password"))
            return true
        })
    }

    @objc func importURL() {
        showForm(kind: "import_url", profile: "", title: L("Import from URL"),
                 views: [Form.row(L("URL:"), Form.field("url", placeholder: "https://vpn.example.com/profile.ovpn")),
                         Form.row(L("Username:"), Form.field("username")),
                         Form.row(L("Password:"), Form.field("password", secure: true))],
                 okTitle: L("Import"), ok: { [weak self] w in
            self?.download(.url(text(w, "url")), username: text(w, "username"), password: text(w, "password"))
            return true
        })
    }

    private func download(_ source: ImportSource, username: String, password: String) {
        ProfileDownloader(http: services.http).download(source, username: username, password: password, askChallenge: { ch, reply in
            showForm(kind: "challenge", profile: "", title: L("MugVPN"),
                     views: [Form.label(ch.text, id: "prompt_text", bold: true),
                             Form.field("response", secure: !ch.echo, placeholder: L("Response"))],
                     ok: { w in reply(text(w, "response")); return true }, cancel: { reply(nil) })
        }) { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let e): showError(L("Cannot import: %@", "\(e)"))
            case .success(let p):
                let dir = NSTemporaryDirectory() + "mugvpn-import-" + UUID().uuidString
                try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
                let file = "\(dir)/\(p.name).ovpn"
                FileManager.default.createFile(atPath: file, contents: Data(p.text.utf8))
                self.importFiles([file], downloaded: true)
                try? FileManager.default.removeItem(atPath: dir)
            }
        }
    }

    // MARK: - settings, about, quit

    @objc func openSettings() {
        SettingsWindow.show(store: settingsStore, services: services) { [weak self] in self?.rescan() }
    }

    @objc func about() {
        let v = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "dev"
        showForm(kind: "about", profile: "", title: L("About MugVPN"),
                 views: [Form.label(["MugVPN", v].joined(separator: " "), id: "version", bold: true),
                         {
                             let actions = FormActions()
                             actions.ok = { [weak self] in self?.confirmUninstall() }
                             let b = Form.button("uninstall", L("Uninstall MugVPN…"), target: actions, action: #selector(FormActions.okPressed))
                             objc_setAssociatedObject(b, "actions", actions, .OBJC_ASSOCIATION_RETAIN)
                             return b
                         }(),
                         Form.label(L("A client for OpenVPN profiles that keeps several connections up at once. MIT License."), id: "about_text"),
                         {
                             let actions = FormActions()
                             actions.ok = { [weak self] in
                                 if let url = Bundle.main.url(forResource: "THIRD-PARTY-NOTICES", withExtension: "txt") {
                                     self?.services.open(url.absoluteString)
                                 }
                             }
                             let b = Form.button("third_party", L("Third-Party Notices"), target: actions, action: #selector(FormActions.okPressed))
                             objc_setAssociatedObject(b, "actions", actions, .OBJC_ASSOCIATION_RETAIN)
                             return b
                         }(),
                         Form.label(L("OpenVPN is a registered trademark of OpenVPN Inc."))],
                 cancelTitle: nil, ok: { _ in true })
    }

    func confirmUninstall() {
        showForm(kind: "uninstall", profile: "", title: L("Uninstall MugVPN"),
                 views: [Form.label(L("MugVPN, its helper, logs, settings and saved passwords will be removed. Tunnels are disconnected."),
                                    id: "prompt_text"),
                         Form.checkbox("keep_profiles", L("Keep my profiles"))],
                 okTitle: L("Uninstall"), ok: { [weak self] w in
            self?.uninstall(keepProfiles: checked(w, "keep_profiles")) { err in
                if let err { showError(L("Cannot uninstall: %@", err)) } else { self?.onQuit() }
            }
            return true
        })
    }

    /// The helper removes the system part (and stops every tunnel), then the app the user's part.
    func uninstall(keepProfiles: Bool, done: @escaping (String?) -> Void) {
        manager.disconnectAll()   // a connection still being checked does not start meanwhile
        manager.helperClient.uninstall(keepProfiles: keepProfiles) { [weak self] err in
            guard let self else { return }
            if let err { return done(err) }
            self.services.helperSetup.unregister()
            self.services.removeUserData(UninstallPlan.userPaths(home: NSHomeDirectory(), keepProfiles: keepProfiles))
            self.services.moveAppToTrash()
            done(nil)
        }
    }

    @objc func quit() {
        let up = manager.active.values.map(\.profile.displayName).sorted()
        // Nothing up: still through the manager, which drops connections waiting for their check.
        guard !up.isEmpty else { return manager.appQuitting { [weak self] in self?.onQuit() } }
        showForm(kind: "confirm", profile: "", title: L("Quit MugVPN"),
                 views: [Form.label(L("Disconnect %@ and quit? They connect again the next time MugVPN starts.", up.joined(separator: ", ")),
                                    id: "prompt_text")], okTitle: L("Disconnect and Quit"), ok: { [weak self] _ in
            self?.manager.appQuitting { self?.onQuit() }
            return true
        })
    }
}

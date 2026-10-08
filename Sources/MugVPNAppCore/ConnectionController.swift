import Foundation
import MugVPNCore

public struct CredentialsAnswer: Equatable, Sendable {
    public var username: String
    public var password: String
    /// The static challenge response, when one was asked for.
    public var response: String?
    public var save: Bool
    public init(username: String, password: String, response: String? = nil, save: Bool) {
        self.username = username
        self.password = password
        self.response = response
        self.save = save
    }
}

public struct SecretAnswer: Equatable, Sendable {
    public var secret: String
    public var save: Bool
    public init(secret: String, save: Bool) {
        self.secret = secret
        self.save = save
    }
}

/// What a connection asks of the user. The app shows windows; tests answer
/// through a fake. A nil answer means Cancel.
public protocol ConnectionUI: AnyObject {
    func askCredentials(type: String, username: String?, challenge: StaticChallenge?, error: String?,
                        reply: @escaping (CredentialsAnswer?) -> Void)
    func askSecret(type: String, error: String?, reply: @escaping (SecretAnswer?) -> Void)
    func askChallenge(text: String, echo: Bool, reply: @escaping (String?) -> Void)
    func askConfirmation(message: String, reply: @escaping (Bool) -> Void)
    func askString(message: String, reply: @escaping (String?) -> Void)
    func choosePKCS11(_ entries: [PKCS11Entry], reply: @escaping (String?) -> Void)
    func openURL(_ url: String)
    func showMessage(title: String, text: String)
    func notify(title: String, text: String)
}

public enum SecretKey: String, Sendable {
    case username, password, keyPassword, proxyUsername, proxyPassword
}

/// Saved secrets per profile (Keychain in the app).
public protocol SecretStore: AnyObject {
    func get(_ profile: String, _ key: SecretKey) -> String?
    func set(_ profile: String, _ key: SecretKey, _ value: String)
    func remove(_ profile: String, _ key: SecretKey)
    func removeAll(_ profile: String)
}

public extension SecretStore {
    /// Anything saved for the profile that "Clear Saved Passwords" would remove.
    func hasSaved(_ profile: String) -> Bool {
        [SecretKey.password, .keyPassword, .proxyPassword, .username, .proxyUsername].contains { get(profile, $0) != nil }
    }
}

public enum ProxySetting: Equatable, Sendable {
    case system
    case manual(host: String, port: Int)
    case none
}

public struct ConnectionSettings: Equatable, Sendable {
    public var proxy: ProxySetting
    public var savePasswordsAllowed: Bool
    /// Messages a server sends (msg-window, msg-notify) are not shown.
    public var ignoreServerMessages: Bool
    /// The same message is shown again only after this many hours (0: always).
    public var muteHours: Int
    public init(proxy: ProxySetting = .system, savePasswordsAllowed: Bool = true, ignoreServerMessages: Bool = false,
                muteHours: Int = 0) {
        self.proxy = proxy
        self.savePasswordsAllowed = savePasswordsAllowed
        self.ignoreServerMessages = ignoreServerMessages
        self.muteHours = muteHours
    }
}

public enum ConnectionStatus: Equatable, Sendable {
    case disconnected
    /// The openvpn state name while connecting ("" before the first one).
    case connecting(String)
    case waitingForWebAuth
    case connected(ip: String, ipv6: String, withErrors: Bool)
    case reconnecting
    case disconnecting
}

/// One connection's logic, driven by management events. It decides what to
/// send and what to ask; the caller owns the socket and the helper.
public final class ConnectionController {
    public let profile: String
    /// How messages are titled (the profile's name).
    public var displayName: String
    /// Writes one management command. A command with a line break or NUL in it
    /// (from a server-supplied value) is dropped: it would be several commands.
    public var send: (String) -> Void {
        get {
            { [weak self] cmd in
                guard let self else { return }
                guard !cmd.unicodeScalars.contains(where: { $0 == "\n" || $0 == "\r" || $0 == "\0" }) else {
                    self.addLog("MugVPN: dropped a management command with a line break")
                    return
                }
                self.write(cmd)
            }
        }
        set { write = newValue }
    }
    private var write: (String) -> Void = { _ in }
    /// openvpn without root asks for its tunnel (OPENTUN, routes, DNS): the helper
    /// checks and does it. nil: no helper takes them (a root openvpn), refused.
    public var tunnelRequest: ((_ kind: String, _ message: String, _ reply: @escaping (Result<FileHandle?, Error>) -> Void) -> Void)?
    /// Writes a command together with a descriptor (the utun for OPENTUN); false if it was not sent.
    public var sendWithFD: (String, FileHandle) -> Bool = { _, _ in false }
    /// openvpn's requests that only the helper answers.
    public static let tunnelRequestNames: Set<String> = ["OPENTUN", "IFCONFIG", "IFCONFIG6", "ROUTE", "ROUTE6", "ROUTEDEL",
                                                         "ROUTE6DEL", "DNSVAR", "DNSUP", "DNSDOWN"]
    /// Ask the helper to stop this connection.
    public var onStop: () -> Void = {}
    /// The management socket went away without a clean exit.
    public var onLost: () -> Void = {}
    public var onChange: () -> Void = {}

    public private(set) var status: ConnectionStatus = .disconnected { didSet { onChange() } }
    public private(set) var bytesIn: UInt64 = 0
    public private(set) var bytesOut: UInt64 = 0
    public private(set) var connectedSince: Date?
    public private(set) var log: [String] = []
    /// `echo setenv NAME value` from the server, for the user's scripts.
    public private(set) var pushedEnvironment: [(String, String)] = []

    private let ui: ConnectionUI
    private let secrets: SecretStore
    private let settings: ConnectionSettings
    private let systemProxy: (String) -> (host: String, port: Int)?
    private var lastError: [String: String] = [:]
    private var dynamicChallenge: (challenge: DynamicChallenge, response: String)?
    private var echoBuffer = ""
    private var pkcs11Expected = 0
    private var pkcs11Entries: [PKCS11Entry] = []
    static let maxLog = 5000
    /// Lines ever added to `log` (it keeps only the last maxLog).
    public private(set) var logTotal = 0

    private func addLog(_ line: String) {
        log.append(line)
        logTotal += 1
        if log.count > ConnectionController.maxLog { log.removeFirst(log.count - ConnectionController.maxLog) }
    }

    public init(profile: String, ui: ConnectionUI, secrets: SecretStore, settings: ConnectionSettings = ConnectionSettings(),
                systemProxy: @escaping (String) -> (host: String, port: Int)? = { _ in nil }) {
        self.profile = profile
        self.displayName = profile
        self.ui = ui
        self.secrets = secrets
        self.settings = settings
        self.systemProxy = systemProxy
    }

    public var canSavePasswords: Bool { settings.savePasswordsAllowed }

    /// The management socket is open.
    public func attached() {
        status = .connecting("")
        ["state on", "log on all", "bytecount 5",
         // Reconnects must not wait for the app, which may be gone by then.
         "hold off", "hold release"].forEach(send)
    }

    /// Stop requested, or openvpn gone: nothing left to stop.
    private var finished = false

    public func disconnect() {
        guard !finished else { return }
        finished = true
        status = .disconnecting
        onStop()
    }

    /// The connect script failed: still up, but with errors.
    public func markScriptFailed() {
        if case .connected(let ip, let ip6, _) = status { status = .connected(ip: ip, ipv6: ip6, withErrors: true) }
    }

    private func handleTunnelRequest(_ name: String, _ msg: String) {
        guard let tunnelRequest else {
            addLog("MugVPN: refused openvpn's \(name) request (no helper takes it)")
            return send("needok '\(name)' cancel")
        }
        tunnelRequest(name, msg) { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let fd?) where name == "OPENTUN":
                // openvpn waits for an answer: without the descriptor, a refusal.
                if !self.sendWithFD("needok '\(name)' ok", fd) {
                    self.addLog("MugVPN: could not hand the tunnel to openvpn")
                    self.send("needok '\(name)' cancel")
                }
            case .success(nil) where name != "OPENTUN":
                self.send("needok '\(name)' ok")
            case .success:
                self.addLog("MugVPN: the helper answered \(name) without a tunnel")
                self.send("needok '\(name)' cancel")
            case .failure(let e):
                self.addLog("MugVPN: the helper refused \(name) \(msg): \((e as? ProfileError)?.description ?? e.localizedDescription)")
                self.send("needok '\(name)' cancel")
            }
        }
    }

    public func reconnect() {
        send("signal SIGUSR1")
    }

    public func handle(_ event: ManagementEvent) {
        switch event {
        case .state(let s): handleState(s)
        case .password(let p): handlePassword(p)
        case .hold: send("hold release")
        case .log(let l): append(l)
        case .byteCount(let i, let o):
            bytesIn = i
            bytesOut = o
            onChange()
        case .echo(let e): handleEcho(e)
        case .info(let i): handleInfo(i)
        case .needOK(let name, let msg) where ConnectionController.tunnelRequestNames.contains(name):
            handleTunnelRequest(name, msg)
        case .needOK(let name, let msg):
            ui.askConfirmation(message: msg) { [weak self] ok in
                self?.send("needok '\(name)' \(ok ? "ok" : "cancel")")
            }
        case .needString(let name, let msg):
            if name == "pkcs11-id-request" {
                pkcs11Entries = []
                send("pkcs11-id-count")
            } else {
                ui.askString(message: msg) { [weak self] s in
                    guard let self else { return }
                    guard let s else { return self.disconnect() }
                    self.send("needstr '\(name)' \(managementQuote(s))")
                }
            }
        case .pkcs11Count(let n):
            pkcs11Expected = n
            if n == 0 { send("needstr 'pkcs11-id-request' \"\"") }
            (0..<max(n, 0)).forEach { send("pkcs11-id-get \($0)") }
        case .pkcs11Entry(let i, let id, let cert):
            pkcs11Entries.append(PKCS11Entry(index: i, id: id, certificate: cert))
            if pkcs11Entries.count == pkcs11Expected {
                ui.choosePKCS11(pkcs11Entries.sorted { $0.index < $1.index }) { [weak self] id in
                    guard let self else { return }
                    guard let id else { return self.disconnect() }
                    self.send("needstr 'pkcs11-id-request' \(managementQuote(id))")
                }
            }
        case .proxy(_, let proto, let host): answerProxy(proto: proto, host: host)
        case .fatal(let f): append("FATAL: " + f)
        case .disconnected:
            let wasStopping = status == .disconnecting
            finished = true
            status = .disconnected
            if !wasStopping { onLost() }
        case .passwordPrompt, .other: break
        }
    }

    // MARK: - states

    private func handleState(_ s: ManagementState) {
        switch s.name {
        case "CONNECTED":
            connectedSince = Date(timeIntervalSince1970: TimeInterval(s.time))
            status = .connected(ip: s.localIP, ipv6: s.localIPv6, withErrors: s.description != "SUCCESS")
        case "RECONNECTING":
            pushedEnvironment = []  // the server sends them again
            if status != .disconnecting { status = .reconnecting }
        case "EXITING":
            finished = true
            status = .disconnected
        default:
            if status != .disconnecting { status = .connecting(s.name) }
        }
    }

    // MARK: - passwords

    private func handlePassword(_ p: PasswordRequest) {
        switch p {
        case .credentials(let type, let sc): answerCredentials(type: type, staticChallenge: sc)
        case .secret(let type): answerSecret(type: type)
        case .failed(let type, let challenge):
            if let challenge {
                ui.askChallenge(text: challenge.text, echo: challenge.echo) { [weak self] response in
                    guard let self else { return }
                    guard let response else { return self.disconnect() }
                    self.dynamicChallenge = (challenge, response)
                }
                return
            }
            if type == "Private Key" {
                secrets.remove(profile, .keyPassword)
                lastError[type] = "Wrong password"
            } else {
                secrets.remove(profile, type == "HTTP Proxy" ? .proxyPassword : .password)
                lastError[type] = "Authentication failed"
            }
        case .authToken, .other: break
        }
    }

    private func keys(_ type: String) -> (user: SecretKey, pass: SecretKey) {
        type == "HTTP Proxy" ? (.proxyUsername, .proxyPassword) : (.username, .password)
    }

    private func answerCredentials(type: String, staticChallenge sc: StaticChallenge?) {
        if type == "Auth", let dc = dynamicChallenge {
            dynamicChallenge = nil
            sendCredentials(type: type, username: dc.challenge.username,
                            password: "CRV1::\(dc.challenge.stateID)::\(dc.response)")
            return
        }
        let k = keys(type)
        let savedUser = secrets.get(profile, k.user)
        let savedPass = settings.savePasswordsAllowed ? secrets.get(profile, k.pass) : nil
        let error = lastError.removeValue(forKey: type)
        if sc == nil, error == nil, let u = savedUser, let p = savedPass {
            return sendCredentials(type: type, username: u, password: p)
        }
        ui.askCredentials(type: type, username: savedUser, challenge: sc, error: error) { [weak self] a in
            guard let self else { return }
            guard let a else { return self.disconnect() }
            self.secrets.set(self.profile, k.user, a.username)
            if a.save && self.settings.savePasswordsAllowed { self.secrets.set(self.profile, k.pass, a.password) }
            var password = a.password
            if let sc {
                let r = a.response ?? ""
                password = sc.concat ? a.password + r
                    : "SCRV1:\(Data(a.password.utf8).base64EncodedString()):\(Data(r.utf8).base64EncodedString())"
            }
            self.sendCredentials(type: type, username: a.username, password: password)
        }
    }

    private func sendCredentials(type: String, username: String, password: String) {
        send("username \(managementQuote(type)) \(managementQuote(username))")
        send("password \(managementQuote(type)) \(managementQuote(password))")
    }

    private func answerSecret(type: String) {
        let error = lastError.removeValue(forKey: type)
        if error == nil, settings.savePasswordsAllowed, let saved = secrets.get(profile, .keyPassword) {
            return send("password \(managementQuote(type)) \(managementQuote(saved))")
        }
        ui.askSecret(type: type, error: error) { [weak self] a in
            guard let self else { return }
            guard let a else { return self.disconnect() }
            if a.save && self.settings.savePasswordsAllowed { self.secrets.set(self.profile, .keyPassword, a.secret) }
            self.send("password \(managementQuote(type)) \(managementQuote(a.secret))")
        }
    }

    // MARK: - messages

    /// The longest message text kept from a server.
    public static let maxMessageBytes = 16 << 10
    /// When each message (title and text) was last shown, over every connection.
    nonisolated(unsafe) public static var shownMessages: [String: Date] = [:]
    nonisolated(unsafe) public static var clock: () -> Date = Date.init

    /// The most messages remembered for muting.
    public static let maxShownMessages = 256
    /// A server's windows, notifications and sign-in pages: at most a few in this many seconds.
    public static let messageInterval: TimeInterval = 30
    public static let messagesPerInterval = 3
    private var recent: [String: [Date]] = [:]

    /// Not a flood: a few of a kind in a while.
    private func paced(_ kind: String) -> Bool {
        let t = ConnectionController.clock()
        let times = (recent[kind] ?? []).filter { t.timeIntervalSince($0) < ConnectionController.messageInterval }
        guard times.count < ConnectionController.messagesPerInterval else { recent[kind] = times; return false }
        recent[kind] = times + [t]
        return true
    }

    /// Show a server's message unless the settings say otherwise (or a flood of them comes).
    private func shouldShow(_ kind: String, _ title: String, _ text: String) -> Bool {
        guard !settings.ignoreServerMessages else { return false }
        if ConnectionController.shownMessages.count >= ConnectionController.maxShownMessages {
            ConnectionController.shownMessages.removeAll()
        }
        guard settings.muteHours > 0 else { return paced(kind) }
        let key = profile + "\u{0}" + title + "\u{0}" + text
        let now = ConnectionController.clock()
        if let last = ConnectionController.shownMessages[key], now.timeIntervalSince(last) < Double(settings.muteHours) * 3600 {
            return false
        }
        ConnectionController.shownMessages[key] = now
        return paced(kind)
    }

    private func handleEcho(_ e: EchoMessage) {
        switch e {
        case .append(let t), .appendLine(let t):
            if case .appendLine = e { echoBuffer += t + "\n" } else { echoBuffer += t }
            if echoBuffer.utf8.count > ConnectionController.maxMessageBytes {
                echoBuffer = String(echoBuffer.utf8.prefix(ConnectionController.maxMessageBytes)) ?? ""
            }
        case .window(let title):
            // (Its window names the profile; a notification does not, so its title does.)
            if shouldShow("window", title, echoBuffer) { ui.showMessage(title: title, text: echoBuffer) }
            echoBuffer = ""
        case .notify(let title):
            if shouldShow("notify", title, echoBuffer) { ui.notify(title: "\(displayName): \(title)", text: echoBuffer) }
            echoBuffer = ""
        case .forgetPasswords: secrets.removeAll(profile)
        case .other(let text):
            let f = text.split(separator: " ", maxSplits: 2).map(String.init)
            guard f.count == 3, f[0] == "setenv" else { break }
            if let i = pushedEnvironment.firstIndex(where: { $0.0 == f[1] }) {
                pushedEnvironment[i].1 = f[2]
            } else if pushedEnvironment.count < ScriptRunner.maxPushed {
                pushedEnvironment.append((f[1], f[2]))
            }
        }
    }

    private func handleInfo(_ i: InfoMessage) {
        switch i {
        case .webAuth(_, let url):
            // Credentials go there: never in clear.
            guard let u = URL(string: url), u.scheme?.lowercased() == "https", u.host?.isEmpty == false else {
                return append("ignored a web authentication URL that is not https: \(url)")
            }
            status = .waitingForWebAuth
            guard paced("webauth") else { return append("ignored another web authentication page so soon: \(url)") }
            ui.openURL(url)
        case .crText(let echo, _, let text):
            ui.askChallenge(text: text, echo: echo) { [weak self] r in
                guard let self else { return }
                guard let r else { return self.disconnect() }
                self.send("cr-response \(Data(r.utf8).base64EncodedString())")
            }
        case .text(let t): append(t)
        }
    }

    /// A host name or an IP address, nothing a management command could misread.
    public static func isHost(_ h: String) -> Bool {
        !h.isEmpty && h.count <= 253 && h.unicodeScalars.allSatisfy {
            CharacterSet.alphanumerics.contains($0) && $0.isASCII || ".-:[]_".unicodeScalars.contains($0)
        }
    }

    private func answerProxy(proto: String, host: String) {
        // An HTTP proxy carries TCP only.
        guard proto == "TCP" else { return send("proxy NONE") }
        switch settings.proxy {
        case .none: send("proxy NONE")
        case .manual(let h, let p):
            send(ConnectionController.isHost(h) && (1...65535).contains(p) ? "proxy HTTP \(h) \(p)" : "proxy NONE")
        case .system:
            // PAC/WPAD come from the network: the answer is checked like a typed one.
            if let p = systemProxy(host), ConnectionController.isHost(p.host), (1...65535).contains(p.port) {
                send("proxy HTTP \(p.host) \(p.port)")
            } else {
                send("proxy NONE")
            }
        }
    }

    private func append(_ line: String) {
        addLog(line)
        onChange()
    }
}

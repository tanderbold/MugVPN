import Foundation
import MugVPNAppCore
import MugVPNCore

// MARK: - Fakes

/// Records every question; answers come from the test through `answer...`.
final class FakeUI: ConnectionUI {
    enum Ask: Equatable {
        case credentials(type: String, username: String?, challenge: StaticChallenge?, error: String?)
        case secret(type: String, error: String?)
        case challenge(text: String, echo: Bool)
        case confirm(String)
        case string(String)
        case pkcs11([PKCS11Entry])
    }
    var asked: [Ask] = []
    var opened: [String] = []
    var messages: [(title: String, text: String)] = []
    var notes: [(title: String, text: String)] = []
    var credentialsReply: ((CredentialsAnswer?) -> Void)?
    var secretReply: ((SecretAnswer?) -> Void)?
    var challengeReply: ((String?) -> Void)?
    var confirmReply: ((Bool) -> Void)?
    var stringReply: ((String?) -> Void)?
    var pkcs11Reply: ((String?) -> Void)?

    func askCredentials(type: String, username: String?, challenge: StaticChallenge?, error: String?,
                        reply: @escaping (CredentialsAnswer?) -> Void) {
        asked.append(.credentials(type: type, username: username, challenge: challenge, error: error))
        credentialsReply = reply
    }
    func askSecret(type: String, error: String?, reply: @escaping (SecretAnswer?) -> Void) {
        asked.append(.secret(type: type, error: error))
        secretReply = reply
    }
    func askChallenge(text: String, echo: Bool, reply: @escaping (String?) -> Void) {
        asked.append(.challenge(text: text, echo: echo))
        challengeReply = reply
    }
    func askConfirmation(message: String, reply: @escaping (Bool) -> Void) {
        asked.append(.confirm(message))
        confirmReply = reply
    }
    func askString(message: String, reply: @escaping (String?) -> Void) {
        asked.append(.string(message))
        stringReply = reply
    }
    func choosePKCS11(_ entries: [PKCS11Entry], reply: @escaping (String?) -> Void) {
        asked.append(.pkcs11(entries))
        pkcs11Reply = reply
    }
    func openURL(_ url: String) { opened.append(url) }
    func showMessage(title: String, text: String) { messages.append((title, text)) }
    func notify(title: String, text: String) { notes.append((title, text)) }
}

final class FakeSecrets: SecretStore {
    var items: [String: String] = [:] // "profile|key"
    func get(_ profile: String, _ key: SecretKey) -> String? { items["\(profile)|\(key.rawValue)"] }
    func set(_ profile: String, _ key: SecretKey, _ value: String) { items["\(profile)|\(key.rawValue)"] = value }
    func remove(_ profile: String, _ key: SecretKey) { items["\(profile)|\(key.rawValue)"] = nil }
    func removeAll(_ profile: String) { items = items.filter { !$0.key.hasPrefix(profile + "|") } }
}

final class Harness {
    let ui = FakeUI()
    let secrets = FakeSecrets()
    var sent: [String] = []
    var stops = 0
    var lost = 0
    let c: ConnectionController

    init(settings: ConnectionSettings = ConnectionSettings(),
         systemProxy: @escaping (String) -> (host: String, port: Int)? = { _ in nil }) {
        c = ConnectionController(profile: "office", ui: ui, secrets: secrets, settings: settings, systemProxy: systemProxy)
        c.send = { [unowned self] in self.sent.append($0) }
        c.onStop = { [unowned self] in self.stops += 1 }
        c.onLost = { [unowned self] in self.lost += 1 }
    }

    func line(_ ls: String...) { ls.forEach(one) }
    func one(_ l: String) {
        guard case .realtime(let type, let payload) = ManagementMessage.parse(l) else { return }
        c.handle(ManagementEvent.parse(type: type, payload: payload))
    }
    func takeSent() -> [String] { defer { sent = [] }; return sent }
}

private func b64(_ s: String) -> String { Data(s.utf8).base64EncodedString() }

// MARK: - L-CON

func registerConnectionTests() {
    test("CON-01", "attach sends the start commands") {
        let h = Harness()
        h.c.attached()
        expectEqual(h.takeSent(), ["state on", "log on all", "bytecount 5", "hold off", "hold release"])
        expectEqual(h.c.status, .connecting(""))
    }
    test("CON-02", "openvpn states to UI states") {
        let h = Harness()
        let cases: [(String, ConnectionStatus)] = [
            ("CONNECTING,,", .connecting("CONNECTING")), ("WAIT,,", .connecting("WAIT")), ("AUTH,,", .connecting("AUTH")),
            ("GET_CONFIG,,", .connecting("GET_CONFIG")), ("ASSIGN_IP,,10.8.0.2", .connecting("ASSIGN_IP")),
            ("ADD_ROUTES,,", .connecting("ADD_ROUTES")), ("TCP_CONNECT,,", .connecting("TCP_CONNECT")),
            ("RESOLVE,,", .connecting("RESOLVE")),
            ("CONNECTED,SUCCESS,10.8.0.2,1.2.3.4,1194,,", .connected(ip: "10.8.0.2", ipv6: "", withErrors: false)),
            ("RECONNECTING,ping-restart,,,,,", .reconnecting),
            ("CONNECTED,ERROR,10.8.0.2,1.2.3.4,1194,,", .connected(ip: "10.8.0.2", ipv6: "", withErrors: true)),
            ("EXITING,SIGTERM,,,,,", .disconnected),
        ]
        for (payload, want) in cases {
            h.line(">STATE:1700000000,\(payload)")
            expectEqual(h.c.status, want, payload)
        }
    }
    test("CON-03", "assigned addresses") {
        let h = Harness()
        h.line(">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,1.2.3.4,1194,,fd00::2")
        expectEqual(h.c.status, .connected(ip: "10.8.0.2", ipv6: "fd00::2", withErrors: false))
    }
    test("CON-04", "username and password: asked, saved, reused") {
        let h = Harness()
        h.line(">PASSWORD:Need 'Auth' username/password")
        expectEqual(h.ui.asked, [.credentials(type: "Auth", username: nil, challenge: nil, error: nil)])
        h.ui.credentialsReply?(CredentialsAnswer(username: "alice", password: "p\"w", save: true))
        expectEqual(h.takeSent(), ["username \"Auth\" \"alice\"", "password \"Auth\" \"p\\\"w\""])
        expectEqual(h.secrets.get("office", .username), "alice")
        expectEqual(h.secrets.get("office", .password), "p\"w")
        // Next time: no question.
        let h2 = Harness()
        h2.secrets.set("office", .username, "bob")
        h2.secrets.set("office", .password, "pw")
        h2.line(">PASSWORD:Need 'Auth' username/password")
        expect(h2.ui.asked.isEmpty)
        expectEqual(h2.takeSent(), ["username \"Auth\" \"bob\"", "password \"Auth\" \"pw\""])
        // Saved username only: asked, with it filled in; not saved without consent.
        let h3 = Harness()
        h3.secrets.set("office", .username, "carol")
        h3.line(">PASSWORD:Need 'Auth' username/password")
        expectEqual(h3.ui.asked, [.credentials(type: "Auth", username: "carol", challenge: nil, error: nil)])
        h3.ui.credentialsReply?(CredentialsAnswer(username: "carol", password: "x", save: false))
        expectEqual(h3.secrets.get("office", .password), nil)
    }
    test("CON-05", "verification failed: saved password dropped, asked again with an error") {
        let h = Harness()
        h.secrets.set("office", .username, "bob")
        h.secrets.set("office", .password, "old")
        h.line(">PASSWORD:Verification Failed: 'Auth'")
        expectEqual(h.secrets.get("office", .password), nil)
        expectEqual(h.secrets.get("office", .username), "bob", "the username stays")
        h.line(">PASSWORD:Need 'Auth' username/password")
        expectEqual(h.ui.asked, [.credentials(type: "Auth", username: "bob", challenge: nil, error: "Authentication failed")])
    }
    test("CON-06", "private key password") {
        let h = Harness()
        h.line(">PASSWORD:Need 'Private Key' password")
        expectEqual(h.ui.asked, [.secret(type: "Private Key", error: nil)])
        h.ui.secretReply?(SecretAnswer(secret: "k", save: true))
        expectEqual(h.takeSent(), ["password \"Private Key\" \"k\""])
        expectEqual(h.secrets.get("office", .keyPassword), "k")
        h.line(">PASSWORD:Verification Failed: 'Private Key'")
        expectEqual(h.secrets.get("office", .keyPassword), nil)
        h.line(">PASSWORD:Need 'Private Key' password")
        expectEqual(h.ui.asked.last, .secret(type: "Private Key", error: "Wrong password"))
    }
    test("CON-07", "static challenge") {
        let h = Harness()
        h.line(">PASSWORD:Need 'Auth' username/password SC:1,PIN")
        expectEqual(h.ui.asked, [.credentials(type: "Auth", username: nil,
                                              challenge: StaticChallenge(echo: true, concat: false, text: "PIN"), error: nil)])
        h.ui.credentialsReply?(CredentialsAnswer(username: "u", password: "p", response: "1234", save: true))
        expectEqual(h.takeSent(), ["username \"Auth\" \"u\"", "password \"Auth\" \"SCRV1:\(b64("p")):\(b64("1234"))\""])
        expectEqual(h.secrets.get("office", .password), "p", "the response is never saved")
        // With a saved password the user is still asked: the response changes each time.
        h.line(">PASSWORD:Need 'Auth' username/password SC:2,OTP")
        expectEqual(h.ui.asked.count, 2)
        h.ui.credentialsReply?(CredentialsAnswer(username: "u", password: "p", response: "99", save: true))
        expectEqual(h.takeSent(), ["username \"Auth\" \"u\"", "password \"Auth\" \"p99\""], "concat flag")
    }
    test("CON-08", "dynamic challenge") {
        let h = Harness()
        h.line(">PASSWORD:Verification Failed: 'Auth' ['CRV1:R,E:sid:\(b64("alice")):Enter OTP']")
        expectEqual(h.ui.asked, [.challenge(text: "Enter OTP", echo: true)])
        h.ui.challengeReply?("424242")
        expect(h.takeSent().isEmpty, "the answer goes with the next Need 'Auth'")
        h.line(">PASSWORD:Need 'Auth' username/password")
        expectEqual(h.takeSent(), ["username \"Auth\" \"alice\"", "password \"Auth\" \"CRV1::sid::424242\""])
        expectEqual(h.ui.asked.count, 1, "no credentials dialog for the challenge round")
    }
    test("CON-24", "no line break reaches the management socket") {
        let h = Harness()
        h.line(">PASSWORD:Verification Failed: 'Auth' ['CRV1:R,E:sid:\(b64("x\nsignal SIGTERM\nforget-passwords")):OTP']")
        h.ui.challengeReply?("1")
        h.line(">PASSWORD:Need 'Auth' username/password")
        let sent = h.takeSent()
        expect(!sent.contains { $0.contains("\n") || $0.contains("\r") || $0.contains("\0") }, "\(sent)")
        expect(!sent.contains("signal SIGTERM") && !sent.contains("forget-passwords"), "\(sent)")
        expect(!sent.contains { $0.hasPrefix("username") }, "the command with the break is not sent")
    }
    test("CON-25", "a proxy host that is not a host name is not sent") {
        let bad = Harness(settings: ConnectionSettings(proxy: .manual(host: "p.lan\nsignal SIGTERM", port: 3128)))
        bad.line(">PROXY:1,TCP,vpn.example.com")
        expectEqual(bad.takeSent(), ["proxy NONE"])
        let store = SettingsStore(backend: FakeSettingsBackend())
        expectThrows("settings refuse it", matching: "host name") { try store.update { $0.proxy = .manual(host: "a b", port: 1) } }
        let good = Harness(settings: ConnectionSettings(proxy: .manual(host: "proxy.lan", port: 3128)))
        good.line(">PROXY:1,TCP,vpn.example.com")
        expectEqual(good.takeSent(), ["proxy HTTP proxy.lan 3128"])
    }
    test("CON-29", "a system proxy (from PAC/WPAD on the network) is checked like a manual one") {
        let h = Harness(settings: ConnectionSettings(proxy: .system), systemProxy: { _ in ("p.lan pass", 3128) })
        h.line(">PROXY:1,TCP,vpn.example.com")
        expectEqual(h.takeSent(), ["proxy NONE"])
        let ok = Harness(settings: ConnectionSettings(proxy: .system), systemProxy: { _ in ("p.lan", 3128) })
        ok.line(">PROXY:1,TCP,vpn.example.com")
        expectEqual(ok.takeSent(), ["proxy HTTP p.lan 3128"])
    }
    test("CON-09", "CR_TEXT") {
        let h = Harness()
        h.line(">INFOMSG:CR_TEXT:R:Approve on your phone, then type the code")
        expectEqual(h.ui.asked, [.challenge(text: "Approve on your phone, then type the code", echo: false)])
        h.ui.challengeReply?("77")
        expectEqual(h.takeSent(), ["cr-response \(b64("77"))"])
    }
    test("CON-10", "web authentication") {
        let h = Harness()
        h.line(">INFOMSG:WEB_AUTH::https://sso.example.com/x")
        expectEqual(h.ui.opened, ["https://sso.example.com/x"])
        expectEqual(h.c.status, .waitingForWebAuth)
        h.line(">INFOMSG:WEB_AUTH::javascript:alert(1)")
        expectEqual(h.ui.opened.count, 1, "only http(s) URLs are opened")
    }
    test("CON-11", "other INFOMSG goes to the log") {
        let h = Harness()
        h.line(">INFOMSG:hello world")
        expect(h.c.log.last?.contains("hello world") == true)
    }
    test("CON-12", "ECHO messages") {
        let h = Harness()
        h.line(">ECHO:1,msg Part one,")
        h.line(">ECHO:1,msg-n  part two")
        h.line(">ECHO:1,msg-window Notice")
        expectEqual(h.ui.messages.map(\.title), ["Notice"], "its window names the profile")
        expectEqual(h.ui.messages.map(\.text), ["Part one, part two\n"])
        h.line(">ECHO:1,msg Short")
        h.line(">ECHO:1,msg-notify Heads up")
        expectEqual(h.ui.notes.map(\.title), ["office: Heads up"])
        expectEqual(h.ui.notes.map(\.text), ["Short"])
        h.secrets.set("office", .password, "x")
        h.line(">ECHO:1,forget-passwords")
        expectEqual(h.secrets.items, [:])
    }
    test("CON-26", "messages from servers can be turned off") {
        let h = Harness(settings: ConnectionSettings(ignoreServerMessages: true))
        h.line(">ECHO:1,msg Buy now", ">ECHO:1,msg-window Urgent", ">ECHO:1,msg x", ">ECHO:1,msg-notify Urgent")
        expect(h.ui.messages.isEmpty && h.ui.notes.isEmpty)
    }
    test("CON-27", "a repeated message is muted for the set hours") {
        var now = Date(timeIntervalSince1970: 1_000_000)
        ConnectionController.clock = { now }
        defer { ConnectionController.clock = Date.init }
        ConnectionController.shownMessages = [:]
        let a = Harness(settings: ConnectionSettings(muteHours: 2))
        a.line(">ECHO:1,msg Maintenance tonight", ">ECHO:1,msg-window Notice")
        let b = Harness(settings: ConnectionSettings(muteHours: 2))  // a reconnect: a new controller
        b.line(">ECHO:1,msg Maintenance tonight", ">ECHO:1,msg-window Notice")
        b.line(">ECHO:1,msg Something else", ">ECHO:1,msg-window Notice")
        expectEqual(a.ui.messages.count + b.ui.messages.count, 2, "the repeat is muted, a new one is not")
        now += 2 * 3600 + 1
        b.line(">ECHO:1,msg Maintenance tonight", ">ECHO:1,msg-window Notice")
        expectEqual(b.ui.messages.count, 2, "shown again after the interval")
        let zero = Harness(settings: ConnectionSettings(muteHours: 0))
        zero.line(">ECHO:1,msg Maintenance tonight", ">ECHO:1,msg-window Notice")
        expectEqual(zero.ui.messages.count, 1, "0 hours: never muted")
    }
    test("CON-28", "a server cannot grow a message without bound") {
        let h = Harness()
        let chunk = String(repeating: "x", count: 1000)
        for _ in 0..<200 { h.line(">ECHO:1,msg \(chunk)") }
        h.line(">ECHO:1,msg-window T")
        expect((h.ui.messages.first?.text.count ?? 0) <= ConnectionController.maxMessageBytes)
    }
    test("CON-13", "NEED-OK and NEED-STR") {
        let h = Harness()
        h.line(">NEED-OK:Need 'token-insertion-request' confirmation MSG:Insert the token")
        expectEqual(h.ui.asked, [.confirm("Insert the token")])
        h.ui.confirmReply?(true)
        h.line(">NEED-OK:Need 'x' confirmation MSG:Again")
        h.ui.confirmReply?(false)
        expectEqual(h.takeSent(), ["needok 'token-insertion-request' ok", "needok 'x' cancel"])
        h.line(">NEED-STR:Need 'name' input MSG:Your name")
        h.ui.stringReply?("A \"B\"")
        expectEqual(h.takeSent(), ["needstr 'name' \"A \\\"B\\\"\""])
    }
    test("CON-32", "web sign-in only over https") {
        let h = Harness()
        h.line(">INFOMSG:WEB_AUTH::http://sso.example.com/login")
        expectEqual(h.ui.opened, [])
        h.line(">INFOMSG:WEB_AUTH::https://sso.example.com/login")
        expectEqual(h.ui.opened, ["https://sso.example.com/login"])
    }
    test("CON-33", "pushed variables: bounded, and gone with a reconnect") {
        let h = Harness()
        for i in 0..<200 { h.line(">ECHO:1,setenv V\(i) x") }
        expect(h.c.pushedEnvironment.count <= ScriptRunner.maxPushed)
        h.line(">STATE:1,RECONNECTING,ping-restart,,,,,")
        expectEqual(h.c.pushedEnvironment.count, 0)
    }
    test("CON-34", "a server's messages: under its profile's name, and not in a flood") {
        let h = Harness()
        var now = Date(timeIntervalSince1970: 1_000_000)
        ConnectionController.clock = { now }
        defer { ConnectionController.clock = Date.init }
        h.line(">ECHO:1,msg Your account is locked", ">ECHO:1,msg-notify Internet blocked")
        expectEqual(h.ui.notes.map(\.title), ["office: Internet blocked"])
        for i in 0..<6 { h.line(">ECHO:2,msg A\(i)", ">ECHO:2,msg-window W\(i)") }
        expectEqual(h.ui.messages.map(\.title), ["W0", "W1", "W2"], "a few in a while, not a flood")
        now += 31
        h.line(">ECHO:4,msg C", ">ECHO:4,msg-window W9")
        expectEqual(h.ui.messages.count, 4)
        for i in 0..<2000 { ConnectionController.shownMessages["k\(i)"] = now }
        h.line(">ECHO:5,msg D", ">ECHO:5,msg-window W4")
        expect(ConnectionController.shownMessages.count <= ConnectionController.maxShownMessages + 1)
    }
    test("CON-35", "web sign-in pages: not opened again and again") {
        let h = Harness()
        var now = Date(timeIntervalSince1970: 1_000_000)
        ConnectionController.clock = { now }
        defer { ConnectionController.clock = Date.init }
        for i in 0..<6 { h.line(">INFOMSG:WEB_AUTH::https://sso.example.com/\(i)") }
        expectEqual(h.ui.opened.count, 3, "a few in a while, not a flood")
        now += 31
        h.line(">INFOMSG:WEB_AUTH::https://sso.example.com/c")
        expectEqual(h.ui.opened.count, 4)
    }
    test("CON-30", "openvpn's tunnel requests go to the helper, never to the user") {
        let h = Harness()
        var asked: [(String, String)] = []
        var answer: Result<FileHandle?, Error> = .success(nil)
        var withFD: [(String, Int32)] = []
        h.c.tunnelRequest = { kind, msg, reply in
            asked.append((kind, msg))
            reply(answer)
        }
        h.c.sendWithFD = { cmd, fh in
            withFD.append((cmd, fh.fileDescriptor))
            return true
        }
        answer = .success(FileHandle(fileDescriptor: 42, closeOnDealloc: false))
        h.line(">NEED-OK:Need 'OPENTUN' confirmation MSG:tun")
        expectEqual(withFD.map(\.0), ["needok 'OPENTUN' ok"])
        expectEqual(withFD.map(\.1), [42], "the utun descriptor goes with the answer")
        answer = .success(nil)
        h.line(">NEED-OK:Need 'IFCONFIG' confirmation MSG:10.8.0.2 255.255.255.0 1500 subnet")
        expectEqual(h.takeSent(), ["needok 'IFCONFIG' ok"])
        answer = .failure(ProfileError("a route must go through the tunnel"))
        h.line(">NEED-OK:Need 'ROUTE' confirmation MSG:198.51.100.0 255.255.255.0 192.168.64.1")
        expectEqual(h.takeSent(), ["needok 'ROUTE' cancel"])
        expect(h.c.log.contains { $0.contains("a route must go through the tunnel") }, "the refusal is in the log")
        expectEqual(asked.map(\.0), ["OPENTUN", "IFCONFIG", "ROUTE"])
        expectEqual(h.ui.asked, [], "nothing asked of the user")
    }
    test("CON-31", "tunnel requests without a helper to take them are refused, not asked") {
        let h = Harness()
        h.line(">NEED-OK:Need 'OPENTUN' confirmation MSG:tun", ">NEED-OK:Need 'DNSUP' confirmation MSG:utun7")
        expectEqual(h.takeSent(), ["needok 'OPENTUN' cancel", "needok 'DNSUP' cancel"])
        expectEqual(h.ui.asked, [])
        let h2 = Harness()
        h2.c.tunnelRequest = { _, _, reply in reply(.success(nil)) }
        h2.line(">NEED-OK:Need 'OPENTUN' confirmation MSG:tun")
        expectEqual(h2.takeSent(), ["needok 'OPENTUN' cancel"], "a tunnel without its descriptor")
    }
    test("CON-14", "PKCS#11 certificate choice") {
        let h = Harness()
        h.line(">NEED-STR:Need 'pkcs11-id-request' input MSG:Please specify PKCS#11 id to use")
        expectEqual(h.takeSent(), ["pkcs11-id-count"])
        h.line(">PKCS11ID-COUNT:2")
        expectEqual(h.takeSent(), ["pkcs11-id-get 0", "pkcs11-id-get 1"])
        h.line(">PKCS11ID-ENTRY:'0', ID:'id0', BLOB:'B0'")
        expect(h.ui.asked.isEmpty, "wait for every entry")
        h.line(">PKCS11ID-ENTRY:'1', ID:'id1', BLOB:'B1'")
        expectEqual(h.ui.asked, [.pkcs11([PKCS11Entry(index: 0, id: "id0", certificate: "B0"),
                                          PKCS11Entry(index: 1, id: "id1", certificate: "B1")])])
        h.ui.pkcs11Reply?("id1")
        expectEqual(h.takeSent(), ["needstr 'pkcs11-id-request' \"id1\""])
        let none = Harness()
        none.line(">NEED-STR:Need 'pkcs11-id-request' input MSG:x")
        none.line(">PKCS11ID-COUNT:0")
        expectEqual(none.takeSent(), ["pkcs11-id-count", "needstr 'pkcs11-id-request' \"\""], "no certificates: empty answer")
    }
    test("CON-15", "proxy") {
        let none = Harness(settings: ConnectionSettings(proxy: .none))
        none.line(">PROXY:1,TCP,vpn.example.com")
        expectEqual(none.takeSent(), ["proxy NONE"])
        let manual = Harness(settings: ConnectionSettings(proxy: .manual(host: "p.lan", port: 3128)))
        manual.line(">PROXY:1,TCP,vpn.example.com")
        expectEqual(manual.takeSent(), ["proxy HTTP p.lan 3128"])
        manual.line(">PROXY:1,UDP,vpn.example.com")
        expectEqual(manual.takeSent(), ["proxy NONE"], "HTTP proxies carry TCP only")
        let system = Harness(settings: ConnectionSettings(proxy: .system), systemProxy: { host in
            host == "vpn.example.com" ? ("sys.lan", 8080) : nil
        })
        system.line(">PROXY:1,TCP,vpn.example.com")
        system.line(">PROXY:1,TCP,other.example.com")
        expectEqual(system.takeSent(), ["proxy HTTP sys.lan 8080", "proxy NONE"])
        system.line(">PASSWORD:Need 'HTTP Proxy' username/password")
        expectEqual(system.ui.asked, [.credentials(type: "HTTP Proxy", username: nil, challenge: nil, error: nil)])
        system.ui.credentialsReply?(CredentialsAnswer(username: "pu", password: "pp", save: true))
        expectEqual(system.takeSent(), ["username \"HTTP Proxy\" \"pu\"", "password \"HTTP Proxy\" \"pp\""])
        expectEqual(system.secrets.get("office", .proxyPassword), "pp")
        expectEqual(system.secrets.get("office", .password), nil, "proxy and VPN secrets are separate")
    }
    test("CON-16", "traffic and connection time") {
        let h = Harness()
        h.line(">BYTECOUNT:1024,2048")
        expectEqual(h.c.bytesIn, 1024)
        expectEqual(h.c.bytesOut, 2048)
        h.line(">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,1.2.3.4,1194,,")
        expectEqual(h.c.connectedSince, Date(timeIntervalSince1970: 1700000000))
        h.line(">STATE:1700000100,RECONNECTING,ping-restart,,,,,")
        h.line(">STATE:1700000200,CONNECTED,SUCCESS,10.8.0.2,1.2.3.4,1194,,")
        expectEqual(h.c.connectedSince, Date(timeIntervalSince1970: 1700000200), "reset by a reconnect")
    }
    test("CON-17", "user disconnects") {
        let h = Harness()
        h.line(">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,1.2.3.4,1194,,")
        h.c.disconnect()
        expectEqual(h.stops, 1)
        expectEqual(h.c.status, .disconnecting)
        h.line(">STATE:1700000001,EXITING,SIGTERM,,,,,")
        expectEqual(h.c.status, .disconnected)
        h.c.disconnect()
        expectEqual(h.stops, 1, "nothing to stop any more")
    }
    test("CON-18", "management socket lost") {
        let h = Harness()
        h.line(">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,1.2.3.4,1194,,")
        h.c.handle(.disconnected)
        expectEqual(h.c.status, .disconnected)
        expectEqual(h.lost, 1)
    }
    test("CON-19", "cancel in a dialog disconnects") {
        let h = Harness()
        h.line(">PASSWORD:Need 'Auth' username/password")
        h.ui.credentialsReply?(nil)
        expectEqual(h.stops, 1)
        expect(h.takeSent().isEmpty)
        let k = Harness()
        k.line(">PASSWORD:Need 'Private Key' password")
        k.ui.secretReply?(nil)
        expectEqual(k.stops, 1)
    }
    test("CON-20", "reconnect") {
        let h = Harness()
        h.line(">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,1.2.3.4,1194,,")
        h.c.reconnect()
        expectEqual(h.takeSent(), ["signal SIGUSR1"])
    }
    test("CON-23", "variables pushed for the scripts") {
        let h = Harness()
        h.line(">ECHO:1,setenv SITE berlin")
        h.line(">ECHO:1,setenv TEAM ops")
        h.line(">ECHO:1,setenv SITE paris")
        h.line(">ECHO:1,setenv BROKEN")
        expectEqual(h.c.pushedEnvironment.map { "\($0.0)=\($0.1)" }, ["SITE=paris", "TEAM=ops"])
    }
    test("CON-22", "saving passwords disabled by policy") {
        let h = Harness(settings: ConnectionSettings(savePasswordsAllowed: false))
        h.secrets.set("office", .password, "stale")
        h.line(">PASSWORD:Need 'Auth' username/password")
        expectEqual(h.ui.asked.count, 1, "saved passwords are not used either")
        h.ui.credentialsReply?(CredentialsAnswer(username: "u", password: "p", save: true))
        expectEqual(h.secrets.get("office", .password), "stale", "nothing saved")
        expect(!h.c.canSavePasswords)
    }
}

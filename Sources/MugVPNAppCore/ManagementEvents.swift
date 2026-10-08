import Foundation
import MugVPNCore

/// `SC:<flags>,<text>` after a username/password request (static challenge).
public struct StaticChallenge: Equatable, Sendable {
    public var echo: Bool
    /// The response is appended to the password instead of SCRV1 encoding.
    public var concat: Bool
    public var text: String
    public init(echo: Bool, concat: Bool, text: String) {
        self.echo = echo
        self.concat = concat
        self.text = text
    }
}

/// `CRV1:<flags>:<state id>:<username base64>:<text>` (dynamic challenge).
public struct DynamicChallenge: Equatable, Sendable {
    public var echo: Bool
    public var responseRequired: Bool
    public var stateID: String
    public var username: String
    public var text: String
    public init(echo: Bool, responseRequired: Bool, stateID: String, username: String, text: String) {
        self.echo = echo
        self.responseRequired = responseRequired
        self.stateID = stateID
        self.username = username
        self.text = text
    }
}

public enum PasswordRequest: Equatable, Sendable {
    case credentials(type: String, staticChallenge: StaticChallenge?)
    case secret(type: String)
    case failed(type: String, challenge: DynamicChallenge?)
    case authToken(String)
    case other(String)
}

public enum InfoMessage: Equatable, Sendable {
    case webAuth(flags: String, url: String)
    case crText(echo: Bool, responseRequired: Bool, text: String)
    case text(String)
}

public enum EchoMessage: Equatable, Sendable {
    case append(String)
    case appendLine(String)
    case window(String)
    case notify(String)
    case forgetPasswords
    case other(String)
}

public struct PKCS11Entry: Equatable, Sendable {
    public var index: Int
    public var id: String
    public var certificate: String
    public init(index: Int, id: String, certificate: String) {
        self.index = index
        self.id = id
        self.certificate = certificate
    }
}

/// A real-time notification from openvpn, decoded.
public enum ManagementEvent: Equatable, Sendable {
    case state(ManagementState)
    case password(PasswordRequest)
    case hold
    case log(String)
    case byteCount(input: UInt64, output: UInt64)
    case echo(EchoMessage)
    case info(InfoMessage)
    case needOK(name: String, message: String)
    case needString(name: String, message: String)
    case pkcs11Count(Int)
    case pkcs11Entry(index: Int, id: String, certificate: String)
    case proxy(index: Int, proto: String, host: String)
    case fatal(String)
    /// openvpn asks for the management password (no newline after it).
    case passwordPrompt
    /// The management socket closed.
    case disconnected
    case other(type: String, payload: String)

    public static func parse(type: String, payload: String) -> ManagementEvent {
        switch type {
        case "STATE":
            return ManagementState(payload: payload).map(ManagementEvent.state) ?? .other(type: type, payload: payload)
        case "PASSWORD": return .password(parsePassword(payload))
        case "HOLD": return .hold
        case "LOG":
            // time,flags,message — the message may itself contain commas.
            let f = payload.split(separator: ",", maxSplits: 2, omittingEmptySubsequences: false)
            return .log(f.count == 3 ? String(f[2]) : payload)
        case "BYTECOUNT":
            let f = payload.split(separator: ",")
            guard f.count == 2, let i = UInt64(f[0]), let o = UInt64(f[1]) else { return .other(type: type, payload: payload) }
            return .byteCount(input: i, output: o)
        case "ECHO":
            guard let comma = payload.firstIndex(of: ",") else { return .other(type: type, payload: payload) }
            return .echo(parseEcho(String(payload[payload.index(after: comma)...])))
        case "INFOMSG": return .info(parseInfo(payload))
        case "NEED-OK", "NEED-STR":
            guard let (name, msg) = parseNeed(payload) else { return .other(type: type, payload: payload) }
            return type == "NEED-OK" ? .needOK(name: name, message: msg) : .needString(name: name, message: msg)
        case "PKCS11ID-COUNT":
            return Int(payload).map(ManagementEvent.pkcs11Count) ?? .other(type: type, payload: payload)
        case "PKCS11ID-ENTRY":
            // '<index>', ID:'<id>', BLOB:'<cert>'
            let q = quoted(payload)
            guard q.count == 3, let i = Int(q[0]) else { return .other(type: type, payload: payload) }
            return .pkcs11Entry(index: i, id: q[1], certificate: q[2])
        case "PROXY":
            let f = payload.split(separator: ",", maxSplits: 2).map(String.init)
            guard f.count == 3, let i = Int(f[0]) else { return .other(type: type, payload: payload) }
            return .proxy(index: i, proto: f[1], host: f[2])
        case "FATAL": return .fatal(payload)
        default: return .other(type: type, payload: payload)
        }
    }

    static func parsePassword(_ p: String) -> PasswordRequest {
        if p.hasPrefix("Auth-Token:") { return .authToken(String(p.dropFirst("Auth-Token:".count))) }
        if p.hasPrefix("Verification Failed: '"), let type = quoted(p).first {
            var challenge: DynamicChallenge?
            if let r = p.range(of: "['CRV1:"), let end = p.range(of: "']", options: .backwards), r.upperBound <= end.lowerBound {
                challenge = parseCRV1(String(p[r.upperBound..<end.lowerBound]))
            }
            return .failed(type: type, challenge: challenge)
        }
        if p.hasPrefix("Need '"), let type = quoted(p).first {
            if p.contains("username/password") {
                var sc: StaticChallenge?
                if let r = p.range(of: " SC:") {
                    let rest = p[r.upperBound...]
                    if let comma = rest.firstIndex(of: ","), let flags = Int(rest[..<comma]) {
                        sc = StaticChallenge(echo: flags & 1 != 0, concat: flags & 2 != 0,
                                             text: String(rest[rest.index(after: comma)...]))
                    }
                }
                return .credentials(type: type, staticChallenge: sc)
            }
            if p.contains("password") { return .secret(type: type) }
        }
        return .other(p)
    }

    /// `<flags>:<state id>:<username b64>:<text>`; the text may contain colons.
    static func parseCRV1(_ s: String) -> DynamicChallenge? {
        let f = s.split(separator: ":", maxSplits: 3, omittingEmptySubsequences: false).map(String.init)
        guard f.count == 4 else { return nil }
        let flags = Set(f[0].split(separator: ",").map(String.init))
        let user = Data(base64Encoded: f[2]).map { String(decoding: $0, as: UTF8.self) } ?? ""
        return DynamicChallenge(echo: flags.contains("E"), responseRequired: flags.contains("R"),
                                stateID: f[1], username: user, text: f[3])
    }

    static func parseEcho(_ s: String) -> EchoMessage {
        func arg(_ cmd: String) -> String? {
            if s == cmd { return "" }
            return s.hasPrefix(cmd + " ") ? String(s.dropFirst(cmd.count + 1)) : nil
        }
        if let t = arg("msg-window") { return .window(t) }
        if let t = arg("msg-notify") { return .notify(t) }
        if let t = arg("msg-n") { return .appendLine(t) }
        if let t = arg("msg") { return .append(t) }
        if s == "forget-passwords" { return .forgetPasswords }
        return .other(s)
    }

    static func parseInfo(_ s: String) -> InfoMessage {
        for prefix in ["WEB_AUTH:", "OPEN_URL:"] where s.hasPrefix(prefix) {
            let rest = String(s.dropFirst(prefix.count))
            if prefix == "OPEN_URL:" { return .webAuth(flags: "", url: rest) }
            guard let colon = rest.firstIndex(of: ":") else { return .text(s) }
            return .webAuth(flags: String(rest[..<colon]), url: String(rest[rest.index(after: colon)...]))
        }
        if s.hasPrefix("CR_TEXT:") {
            let rest = s.dropFirst("CR_TEXT:".count)
            guard let colon = rest.firstIndex(of: ":") else { return .text(s) }
            let flags = Set(rest[..<colon].split(separator: ",").map(String.init))
            return .crText(echo: flags.contains("E"), responseRequired: flags.contains("R"),
                           text: String(rest[rest.index(after: colon)...]))
        }
        return .text(s)
    }

    /// `Need '<name>' ... MSG:<message>`
    static func parseNeed(_ s: String) -> (String, String)? {
        guard let name = quoted(s).first, let r = s.range(of: "MSG:") else { return nil }
        return (name, String(s[r.upperBound...]))
    }

    /// The contents of each '...' in order.
    static func quoted(_ s: String) -> [String] {
        var out: [String] = []
        var current: String?
        for ch in s {
            if ch == "'" {
                if let c = current { out.append(c); current = nil } else { current = "" }
            } else if current != nil {
                current!.append(ch)
            }
        }
        return out
    }
}

/// A reply to one command.
public enum ManagementReply: Equatable, Sendable {
    case success(String)
    case error(String)
    case lines([String])
}

/// The management protocol without the socket: bytes in, events out;
/// commands queued and matched to their replies in order.
public final class ManagementProtocol {
    private struct Pending {
        let multiline: Bool
        let done: (ManagementReply) -> Void
    }
    private var buffer = Data()
    private var pending: [Pending] = []
    private var collected: [String] = []
    /// openvpn caps a line at a few KB; anything far longer is garbage.
    static let maxLine = 64 * 1024

    public init() {}

    /// Queue a command; returns the bytes to write.
    public func command(_ text: String, multiline: Bool = false,
                        completion: @escaping (ManagementReply) -> Void = { _ in }) -> Data {
        pending.append(Pending(multiline: multiline, done: completion))
        return Data((text + "\n").utf8)
    }

    public func received(_ data: Data) -> [ManagementEvent] {
        buffer.append(data)
        var events: [ManagementEvent] = []
        while true {
            if let nl = buffer.firstIndex(of: 0x0A) {
                var line = buffer[buffer.startIndex..<nl]
                buffer.removeSubrange(buffer.startIndex...nl)
                if line.last == 0x0D { line = line.dropLast() }
                if let e = handle(String(decoding: line, as: UTF8.self)) { events.append(e) }
                continue
            }
            let prompt = Data("ENTER PASSWORD:".utf8)
            if buffer.starts(with: prompt) {
                buffer.removeSubrange(buffer.startIndex..<buffer.startIndex + prompt.count)
                events.append(.passwordPrompt)
                continue
            }
            if buffer.count > ManagementProtocol.maxLine { buffer.removeAll() }
            return events
        }
    }

    public func closed() -> [ManagementEvent] {
        let p = pending
        pending.removeAll()
        p.forEach { $0.done(.error("disconnected")) }
        return [.disconnected]
    }

    private func handle(_ line: String) -> ManagementEvent? {
        let msg = ManagementMessage.parse(line)
        if case .realtime(let type, let payload) = msg {
            if type == "INFO" { return nil } // banner
            return ManagementEvent.parse(type: type, payload: payload)
        }
        guard let first = pending.first else { return nil }
        if first.multiline {
            if line == "END" {
                pending.removeFirst()
                let lines = collected
                collected = []
                first.done(.lines(lines))
            } else if case .error(let e) = msg, collected.isEmpty {
                pending.removeFirst()
                first.done(.error(e))
            } else {
                collected.append(line)
            }
            return nil
        }
        switch msg {
        case .success(let s): pending.removeFirst(); first.done(.success(s))
        case .error(let e): pending.removeFirst(); first.done(.error(e))
        default: break
        }
        return nil
    }
}

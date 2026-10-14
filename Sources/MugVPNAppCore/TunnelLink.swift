import Foundation
import MugVPNCore

/// What the app tells a connection's engine, typed: openvpn 2's management interface is one way to say it
/// (ManagementTunnelTransport), a product's own channel another.
public enum TunnelCommand: Equatable, Sendable {
    /// What the app is told: state changes, the log (what came before too), byte counts every so many seconds.
    case watchState
    case watchLog
    case byteCount(seconds: Int)
    /// Reconnects do not wait for the app; the first start is let go.
    case holdOff
    case releaseHold
    /// A NEED-OK request answered, or a NEED-STR one.
    case confirm(name: String, ok: Bool)
    case answer(name: String, value: String)
    /// PKCS#11: how many certificates there are, then each.
    case countPKCS11
    case getPKCS11(Int)
    case username(type: String, value: String)
    case password(type: String, value: String)
    /// A CR_TEXT challenge's response (as typed).
    case challengeResponse(String)
    case proxyNone
    case proxyHTTP(host: String, port: Int)
    /// Connect again (the session goes on).
    case reconnect
    /// The management interface's own password (its first line).
    case managementPassword(String)

    /// A value carries a line break or NUL: in openvpn 2's interface it would be several commands.
    public var hasLineBreak: Bool {
        let values: [String]
        switch self {
        case .confirm(let n, _): values = [n]
        case .answer(let n, let v), .username(let n, let v), .password(let n, let v): values = [n, v]
        case .challengeResponse(let r): values = [r]
        case .proxyHTTP(let h, _): values = [h]
        case .managementPassword(let p): values = [p]
        default: values = []
        }
        return values.contains { $0.unicodeScalars.contains { $0 == "\n" || $0 == "\r" || $0 == "\0" } }
    }

    /// openvpn 2's management command.
    public var managementText: String {
        switch self {
        case .watchState: return "state on"
        case .watchLog: return "log on all"
        case .byteCount(let s): return "bytecount \(s)"
        case .holdOff: return "hold off"
        case .releaseHold: return "hold release"
        case .confirm(let n, let ok): return "needok '\(n)' \(ok ? "ok" : "cancel")"
        case .answer(let n, let v): return "needstr '\(n)' \(managementQuote(v))"
        case .countPKCS11: return "pkcs11-id-count"
        case .getPKCS11(let i): return "pkcs11-id-get \(i)"
        case .username(let t, let v): return "username \(managementQuote(t)) \(managementQuote(v))"
        case .password(let t, let v): return "password \(managementQuote(t)) \(managementQuote(v))"
        case .challengeResponse(let r): return "cr-response \(Data(r.utf8).base64EncodedString())"
        case .proxyNone: return "proxy NONE"
        case .proxyHTTP(let h, let p): return "proxy HTTP \(h) \(p)"
        case .reconnect: return "signal SIGUSR1"
        case .managementPassword(let p): return p
        }
    }
}

/// One connection's engine as the app drives it: its events in, the app's commands out.
public protocol TunnelLink: AnyObject {
    func send(_ command: TunnelCommand)
    /// With a descriptor for the engine (the utun, for OPENTUN); `done(false)` if it was not sent. `done` comes on
    /// the main queue (the descriptor must stay open until then).
    func send(_ command: TunnelCommand, passing fd: Int32, done: @escaping (Bool) -> Void)
    func close()
}

/// Opens a connection's link (its management socket, or a product's channel); nil when it cannot (yet). `onEvent`
/// gets what the engine says; `onClose` once it went (after a `.disconnected` event).
public protocol TunnelTransport: AnyObject {
    func open(_ socket: String, onEvent: @escaping (ManagementEvent) -> Void, onClose: @escaping () -> Void) -> TunnelLink?
}

/// openvpn 2's management interface over a byte transport (its socket): lines in, typed events out; typed
/// commands written as its commands.
public final class ManagementTunnelTransport: TunnelTransport {
    private let bytes: ManagementTransport
    public init(_ bytes: ManagementTransport) { self.bytes = bytes }

    public func open(_ socket: String, onEvent: @escaping (ManagementEvent) -> Void, onClose: @escaping () -> Void) -> TunnelLink? {
        let proto = ManagementProtocol()
        guard let link = bytes.open(socket, onData: { data in proto.received(data).forEach(onEvent) },
                                    onClose: { proto.closed().forEach(onEvent); onClose() }) else { return nil }
        return ManagementTunnelLink(link: link, proto: proto)
    }
}

final class ManagementTunnelLink: TunnelLink {
    private let link: ManagementLink
    private let proto: ManagementProtocol
    init(link: ManagementLink, proto: ManagementProtocol) {
        self.link = link
        self.proto = proto
    }
    func send(_ command: TunnelCommand) { link.write(proto.command(command.managementText)) }
    func send(_ command: TunnelCommand, passing fd: Int32, done: @escaping (Bool) -> Void) {
        link.write(proto.command(command.managementText), passing: fd, done: done)
    }
    func close() { link.close() }
}

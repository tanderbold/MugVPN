import Foundation
import MugVPNCore

/// Where a connection's DNS comes from.
public struct DNSChoice: Equatable, Sendable {
    public enum Mode: String, Equatable, Sendable, CaseIterable {
        /// As the VPN server pushes it.
        case server
        /// These servers (for these domains only, or for all names); the server's DNS is ignored.
        case own
        /// The server's DNS is ignored and the Mac's DNS stays as it is.
        case none
    }
    public var mode: Mode
    public var servers: [String]
    public var domains: [String]
    public init(mode: Mode = .server, servers: [String] = [], domains: [String] = []) {
        self.mode = mode
        self.servers = servers
        self.domains = domains
    }

    /// openvpn's limit on addresses per DNS server entry.
    public static let maxServers = 8
    static let filters = ["dns ", "dhcp-option"]
}

/// The connection settings form: what the "Connections" window shows of a
/// profile, and the edits it writes back. Only the lines of the settings that
/// changed are rewritten; comments, order and everything else stay as typed.
public struct ConnectionDraft: Equatable, Sendable {
    public enum Proto: String, Equatable, Sendable, CaseIterable { case udp, tcp }
    public enum Device: String, Equatable, Sendable, CaseIterable { case tun, tap }

    public struct Server: Equatable, Sendable {
        public var host: String
        public var port: Int
        public var proto: Proto
        public init(host: String, port: Int = 1194, proto: Proto = .udp) {
            self.host = host
            self.port = port
            self.proto = proto
        }
    }

    /// A certificate or key: a file next to the profile, or the text itself.
    public enum Material: Equatable, Sendable {
        case file(String)
        case inline(String)
    }

    public var servers: [Server] = []
    public var device = Device.tun
    public var ca: Material?
    public var cert: Material?
    public var key: Material?
    public var tlsAuth: Material?
    public var tlsCrypt: Material?
    public var askPassword = false
    public var allTraffic = false
    public var dns = DNSChoice()
    /// pkcs12, peer-fingerprint, a token...: stands for the CA and certificate fields.
    public private(set) var otherCredentials = false
    /// False when the servers are in <connection> blocks: edited in the text only.
    public private(set) var serversEditable = true

    public init() {}

    public init(config: String) throws {
        let ds = try ConfigParser.parse(config)
        var port = 1194, proto = Proto.udp
        for d in ds {
            if d.name == "port" || d.name == "rport", let p = d.args.first.flatMap(Int.init) { port = p }
            if d.name == "proto", let p = d.args.first { proto = ConnectionDraft.proto(p) ?? proto }
        }
        func server(_ d: ConfigDirective, port: Int, proto: Proto) -> Server {
            Server(host: d.args.first ?? "", port: d.args.count > 1 ? Int(d.args[1]) ?? port : port,
                   proto: d.args.count > 2 ? ConnectionDraft.proto(d.args[2]) ?? proto : proto)
        }
        var dnsEntries: [Int: ([String], [String])] = [:]
        var ignoresDNS = false
        for d in ds {
            switch d.name {
            case "remote": servers.append(server(d, port: port, proto: proto))
            case "connection":
                serversEditable = false
                let inner = (try? ConfigParser.parse(d.inline ?? "")) ?? []
                var p = port, pr = proto
                for i in inner {
                    if i.name == "port" || i.name == "rport", let x = i.args.first.flatMap(Int.init) { p = x }
                    if i.name == "proto", let x = i.args.first { pr = ConnectionDraft.proto(x) ?? pr }
                }
                servers += inner.filter { $0.name == "remote" }.map { server($0, port: p, proto: pr) }
            case "dev": device = d.args.first?.hasPrefix("tap") == true ? .tap : .tun
            case "ca": ca = ConnectionDraft.material(d)
            case "cert": cert = ConnectionDraft.material(d)
            case "key": key = ConnectionDraft.material(d)
            case "tls-auth": tlsAuth = ConnectionDraft.material(d)
            case "tls-crypt": tlsCrypt = ConnectionDraft.material(d)
            case "auth-user-pass": askPassword = true
            case "redirect-gateway": allTraffic = true
            case "dns":
                if d.args.count >= 3, d.args[0] == "server", let n = Int(d.args[1]) {
                    dnsEntries[n, default: ([], [])].0 += d.args[2] == "address" ? Array(d.args.dropFirst(3)) : []
                    dnsEntries[n, default: ([], [])].1 += d.args[2] == "resolve-domains" ? Array(d.args.dropFirst(3)) : []
                }
            case "pull-filter":
                if d.args.count == 2, d.args[0] == "ignore", DNSChoice.filters.contains(d.args[1]) { ignoresDNS = true }
            case "pkcs12", "peer-fingerprint", "pkcs11-id", "pkcs11-id-management", "management-external-key",
                 "management-external-cert":
                otherCredentials = true
            default: break
            }
        }
        readDNS(dnsEntries, ignores: ignoresDNS)
    }

    private mutating func readDNS(_ entries: [Int: ([String], [String])], ignores: Bool) {
        if let first = entries.keys.filter({ !entries[$0]!.0.isEmpty }).min() {
            dns = DNSChoice(mode: .own, servers: entries[first]!.0, domains: entries[first]!.1)
        } else if ignores {
            dns = DNSChoice(mode: .none)
        }
    }

    static func proto(_ s: String) -> Proto? {
        s.hasPrefix("udp") ? .udp : s.hasPrefix("tcp") ? .tcp : nil
    }

    static func material(_ d: ConfigDirective) -> Material? {
        if let t = d.inline { return .inline(t) }
        return d.args.first.map { .file($0) }
    }

    // MARK: - checking

    /// What keeps the form from being saved, in words for the user.
    public var problems: [String] {
        var out: [String] = []
        if servers.isEmpty { out.append("add at least one server") }
        for (i, s) in servers.enumerated() {
            let bad = CharacterSet.whitespacesAndNewlines.union(CharacterSet(charactersIn: "#;\"'\\"))
            if s.host.isEmpty || s.host.unicodeScalars.contains(where: bad.contains) {
                out.append("server \(i + 1): enter a host name or address")
            }
            if !(1...65535).contains(s.port) { out.append("server \(i + 1): the port must be 1–65535") }
        }
        if dns.mode == .own {
            if dns.servers.isEmpty { out.append("enter at least one DNS server") }
            if dns.servers.count > DNSChoice.maxServers { out.append("at most 8 DNS servers") }
            for a in dns.servers where !ConnectionDraft.isIP(a) { out.append("DNS server \(a) is not an IP address") }
            for d in dns.domains where !ConnectionDraft.isDomain(d) { out.append("\(d) is not a domain name") }
        }
        if ca == nil && !otherCredentials { out.append("choose the server's CA certificate") }
        if cert != nil && key == nil { out.append("the client certificate needs its private key") }
        if key != nil && cert == nil { out.append("the private key needs its client certificate") }
        if cert == nil && key == nil && !askPassword && !otherCredentials {
            out.append("sign in needs a client certificate or a password")
        }
        return out
    }

    /// The problems this form has that `was` (the profile as saved) did not:
    /// a profile that works without what the form expects can still be edited.
    public func problems(since was: ConnectionDraft?) -> [String] {
        guard let was else { return problems }
        let old = Set(was.problems)
        return problems.filter { !old.contains($0) }
    }

    static func isIP(_ s: String) -> Bool {
        var v4 = in_addr(), v6 = in6_addr()
        return inet_pton(AF_INET, s, &v4) == 1 || inet_pton(AF_INET6, s, &v6) == 1
    }

    public static func isDomain(_ s: String) -> Bool {
        let name = s.hasSuffix(".") ? String(s.dropLast()) : s
        guard !name.isEmpty, name.count <= 253 else { return false }
        let ok = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")
        return name.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { l in
            !l.isEmpty && l.count <= 63 && !l.hasPrefix("-") && !l.hasSuffix("-") && l.unicodeScalars.allSatisfy(ok.contains)
        }
    }

    /// Items separated by commas, spaces or new lines.
    public static func parseList(_ text: String) -> [String] {
        text.split(whereSeparator: { $0 == "," || $0 == " " || $0 == "\n" || $0 == "\t" || $0 == ";" }).map(String.init)
    }

    /// The text of a certificate or key file the user chose, fit to embed;
    /// nil when it is not PEM text or could change the config around it.
    public static func materialText(_ data: Data) -> String? {
        guard data.count <= 1 << 20, !data.contains(0), var text = String(data: data, encoding: .utf8) else { return nil }
        text = text.replacingOccurrences(of: "\r\n", with: "\n")
        guard text.contains("-----BEGIN ") else { return nil }
        for line in text.components(separatedBy: "\n") {
            guard line.utf8.count <= ConfigParser.maxLineBytes, !line.drop(while: { " \t\u{0B}\u{0C}\r".contains($0) }).hasPrefix("<") else {
                return nil
            }
        }
        return text.hasSuffix("\n") ? text : text + "\n"
    }

    // MARK: - servers as text

    /// "host [port] [udp|tcp]" or "host:port" per line.
    public static func parseServers(_ text: String) -> ([Server], [String]) {
        var out: [Server] = [], errors: [String] = []
        for (n, raw) in text.components(separatedBy: "\n").enumerated() {
            var parts = raw.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard !parts.isEmpty else { continue }
            if parts.count == 1, let c = parts[0].lastIndex(of: ":"), parts[0].filter({ $0 == ":" }).count == 1 {
                parts = [String(parts[0][..<c]), String(parts[0][parts[0].index(after: c)...])]
            }
            var s = Server(host: parts[0])
            var bad = parts.count > 3
            if parts.count > 1 {
                if let p = Int(parts[1]) { s.port = p } else { bad = true }
            }
            if parts.count > 2 {
                if let p = proto(parts[2].lowercased()) { s.proto = p } else { bad = true }
            }
            if bad {
                errors.append("line \(n + 1): write a server as: host port udp|tcp")
            } else {
                out.append(s)
            }
        }
        return (out, errors)
    }

    public static func formatServers(_ servers: [Server]) -> String {
        servers.map { "\($0.host) \($0.port) \($0.proto.rawValue)" }.joined(separator: "\n")
    }

    // MARK: - writing

    public static let template = """
        client
        dev tun
        nobind
        persist-key
        persist-tun
        resolv-retry infinite
        remote-cert-tls server
        verb 3

        """

    /// The config of a new connection with these settings.
    public func newConfig() throws -> String { try apply(to: ConnectionDraft.template) }

    /// `config` with this form's settings, changing only what differs.
    public func apply(to config: String) throws -> String {
        let was = try ConnectionDraft(config: config)
        if !was.serversEditable && servers != was.servers {
            throw ProfileError("this profile keeps its servers in <connection> blocks: change them in the config text")
        }
        let crlf = config.contains("\r\n")
        var lines: [String?] = config.replacingOccurrences(of: "\r\n", with: "\n")
            .components(separatedBy: "\n").map { $0 }
        let ds = try ConfigParser.parse(config)
        // Where new lines go when there is nothing to replace: before the trailing blank lines.
        var end = lines.count
        while end > 0, lines[end - 1]?.trimmingCharacters(in: .whitespaces).isEmpty == true { end -= 1 }
        var inserts: [Int: [String]] = [:]

        /// Remove the directives named `names`; put `new` where the first one was.
        func replace(_ names: Set<String>, with new: [String]) {
            replace(where: { names.contains($0.name) }, with: new)
        }
        func replace(where match: (ConfigDirective) -> Bool, with new: [String]) {
            var at: Int?
            for d in ds where match(d) {
                let first = d.line - 1
                let count = d.inline.map { $0.isEmpty ? 2 : $0.components(separatedBy: "\n").count + 1 } ?? 1
                if at == nil { at = first }
                for i in first..<min(first + count, lines.count) { lines[i] = nil }
            }
            if !new.isEmpty { inserts[at ?? end, default: []] += new }
        }

        if servers != was.servers {
            replace(["remote"], with: servers.map {
                "remote \(ConnectionDraft.token($0.host)) \($0.port) \($0.proto.rawValue)"
            })
        }
        if device != was.device { replace(["dev"], with: ["dev \(device.rawValue)"]) }
        func material(_ name: String, _ m: Material?, _ old: Material?) {
            guard m != old else { return }
            replace([name], with: m.map { ConnectionDraft.render(name, $0) } ?? [])
        }
        material("ca", ca, was.ca)
        material("cert", cert, was.cert)
        material("key", key, was.key)
        material("tls-crypt", tlsCrypt, was.tlsCrypt)
        if tlsAuth != was.tlsAuth {
            var new = tlsAuth.map { ConnectionDraft.render("tls-auth", $0) } ?? []
            let hasDirection = ds.contains { $0.name == "key-direction" }
            if tlsAuth == nil {
                replace(["key-direction"], with: [])
            } else if case .inline = tlsAuth, !hasDirection {
                new.append("key-direction 1")
            }
            replace(["tls-auth"], with: new)
        }
        if askPassword != was.askPassword { replace(["auth-user-pass"], with: askPassword ? ["auth-user-pass"] : []) }
        if dns != was.dns {
            var new: [String] = []
            if dns.mode != .server { new += DNSChoice.filters.map { "pull-filter ignore \"\($0)\"" } }
            if dns.mode == .own {
                new.append("dns server 1 address " + dns.servers.map(ConnectionDraft.token).joined(separator: " "))
                if !dns.domains.isEmpty {
                    new.append("dns server 1 resolve-domains " + dns.domains.map(ConnectionDraft.token).joined(separator: " "))
                }
            }
            replace(where: { d in
                d.name == "dns"
                    || (d.name == "pull-filter" && d.args.count == 2 && d.args[0] == "ignore" && DNSChoice.filters.contains(d.args[1]))
                    || (d.name == "dhcp-option" && ["DNS", "DNS6", "DOMAIN", "DOMAIN-SEARCH"].contains(d.args.first ?? ""))
            }, with: new)
        }
        if allTraffic != was.allTraffic {
            replace(["redirect-gateway"], with: allTraffic ? ["redirect-gateway def1"] : [])
        }

        var out: [String] = []
        for i in 0...lines.count {
            out += inserts[i] ?? []
            if i < lines.count, let l = lines[i] { out.append(l) }
        }
        return out.joined(separator: crlf ? "\r\n" : "\n")
    }

    static func render(_ name: String, _ m: Material) -> [String] {
        switch m {
        case .file(let f): return ["\(name) \(token(f))"]
        case .inline(let t):
            let body = t.hasSuffix("\n") || t.isEmpty ? t : t + "\n"
            return ["<\(name)>"] + body.components(separatedBy: "\n").dropLast() + ["</\(name)>"]
        }
    }

    /// A parameter as is when openvpn reads it that way, else quoted.
    static func token(_ s: String) -> String {
        let plain = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "._-:/@+=,[]"))
        if !s.isEmpty, s.unicodeScalars.allSatisfy(plain.contains) { return s }
        return "\"" + s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }
}

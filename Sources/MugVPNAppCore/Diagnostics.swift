import Foundation
import MugVPNCore

/// What MugVPN puts into a diagnostics archive (for a bug report or an administrator):
/// versions, the system's network state, the profiles without secrets, the logs.
public enum Diagnostics {
    public struct File: Equatable, Sendable {
        public var name: String
        public var text: String
    }

    /// Directives known to carry nothing secret: kept with their arguments. Every other one is
    /// kept by name only (setenv values, proxy headers, challenges, file names of keys, the unknown).
    static let safe: Set<String> = [
        "client", "dev", "dev-type", "proto", "remote", "port", "rport", "lport", "bind", "nobind", "float",
        "resolv-retry", "persist-key", "persist-tun", "remote-random", "remote-random-hostname", "connect-retry",
        "connect-retry-max", "connect-timeout", "server-poll-timeout", "explicit-exit-notify", "keepalive", "ping",
        "ping-restart", "ping-exit", "inactive", "tun-mtu", "link-mtu", "mssfix", "fragment", "sndbuf", "rcvbuf",
        "txqueuelen", "topology", "ifconfig", "ifconfig-ipv6", "route", "route-ipv6", "route-gateway", "route-metric",
        "route-delay", "route-nopull", "redirect-gateway", "redirect-private", "block-ipv6", "pull", "pull-filter",
        "dhcp-option", "dns", "register-dns", "block-outside-dns", "cipher", "data-ciphers", "data-ciphers-fallback",
        "ncp-ciphers", "auth", "tls-client", "tls-version-min", "tls-version-max", "tls-cipher", "tls-ciphersuites",
        "tls-groups", "ecdh-curve", "remote-cert-tls", "remote-cert-ku", "remote-cert-eku", "verify-x509-name",
        "ns-cert-type", "key-direction", "comp-lzo", "compress", "allow-compression", "verb", "mute",
        "mute-replay-warnings", "auth-nocache", "auth-retry", "ca", "cert", "extra-certs", "crl-verify", "dh",
        "peer-fingerprint", "machine-readable-output", "script-security", "tls-timeout",
        "hand-window", "reneg-sec", "tran-window", "replay-window",
    ]
    /// Proxies: where they are, not how to sign in to them.
    static let firstTwo: Set<String> = ["http-proxy", "socks-proxy"]
    /// Inline blocks whose text is public (certificates) or a block of directives itself.
    static let safeBlocks: Set<String> = ["ca", "cert", "extra-certs", "crl-verify", "dh", "peer-fingerprint"]

    /// The profile as MugVPN reads it, comments left out and every argument not known to be safe
    /// removed; one MugVPN cannot read is left out (it could hide anything).
    public static func sanitize(config: String) -> String {
        guard let ds = try? ConfigParser.parse(config) else { return "[a profile MugVPN cannot read: left out]" }
        return render(ds)
    }

    static func render(_ ds: [ConfigDirective]) -> String {
        func quote(_ a: String) -> String {
            a.contains(where: { $0.isWhitespace || $0 == "\"" || $0 == "'" || $0 == "#" || $0 == ";" })
                ? "\"" + a.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\"" : a
        }
        var out: [String] = []
        for d in ds {
            let name = d.name.lowercased()
            if let inline = d.inline {
                let body: String
                if name == "connection" {
                    body = (try? ConfigParser.parse(inline)).map(render) ?? "[removed]"
                } else {
                    body = safeBlocks.contains(name) ? inline.trimmingCharacters(in: .newlines) : "[removed]"
                }
                out.append("<\(d.name)>\n\(body)\n</\(d.name)>")
            } else if safe.contains(name) {
                out.append(([d.name] + d.args.map(quote)).joined(separator: " "))
            } else if firstTwo.contains(name) {
                out.append(([d.name] + d.args.prefix(2).map(quote) + (d.args.count > 2 ? ["[removed]"] : [])).joined(separator: " "))
            } else {
                out.append(d.name + (d.args.isEmpty ? "" : " [removed]"))
            }
        }
        return out.joined(separator: "\n")
    }

    /// The archive's files. Names come from profiles: kept inside their folder.
    public static func files(summary: [String: String], commands: [String: String],
                             profiles: [(name: String, config: String)], logs: [(name: String, text: String)]) -> [File] {
        func safe(_ s: String) -> String { s.replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: ":", with: "_") }
        var out = [File(name: "summary.txt", text: summary.sorted { $0.key < $1.key }.map { "\($0.key): \($0.value)" }.joined(separator: "\n") + "\n")]
        out += commands.sorted { $0.key < $1.key }.map { File(name: safe($0.key), text: $0.value) }
        out += profiles.map { File(name: "profiles/" + safe($0.name) + ".ovpn", text: sanitize(config: $0.config)) }
        out += logs.map { File(name: "logs/" + safe($0.name) + ".log", text: $0.text) }
        return out
    }
}

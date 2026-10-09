import Foundation
import MugVPNCore

/// What MugVPN puts into a diagnostics archive (for a bug report or an administrator):
/// versions, the system's network state, the profiles without secrets, the logs.
public enum Diagnostics {
    public struct File: Equatable, Sendable {
        public var name: String
        public var text: String
    }

    /// Inline blocks that hold secrets: their text never leaves the Mac.
    static let secretBlocks: Set<String> = ["key", "tls-auth", "tls-crypt", "tls-crypt-v2", "secret", "pkcs12",
                                            "auth-user-pass", "http-proxy-user-pass", "extra-certs-key"]

    /// The profile as it is, but the secrets' text; one MugVPN cannot read is left out (it could hide anything).
    public static func sanitize(config: String) -> String {
        guard (try? ConfigParser.parse(config)) != nil else { return "[a profile MugVPN cannot read: left out]" }
        var out: [String] = []
        var inSecret: String?
        for line in config.components(separatedBy: "\n") {
            let t = line.trimmingCharacters(in: .whitespaces).lowercased()
            if let name = inSecret {
                if t == "</\(name)>" { out.append(line); inSecret = nil }
                continue
            }
            if t.hasPrefix("<"), t.hasSuffix(">"), !t.hasPrefix("</") {
                let name = String(t.dropFirst().dropLast())
                if secretBlocks.contains(name) {
                    out.append(line)
                    out.append("[removed]")
                    inSecret = name
                    continue
                }
            }
            out.append(line)
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

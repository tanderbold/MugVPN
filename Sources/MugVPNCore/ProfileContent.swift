import Foundation

/// What a certificate, key or credentials block may hold, by the directive
/// that names it. openvpn hands these to
/// OpenSSL as root: anything that is not the expected kind of PEM block is
/// refused before it gets there. Text outside PEM blocks (the `openssl x509
/// -text` dump many CA files carry) is allowed: OpenSSL skips it.
extension ProfilePolicy {
    public static let maxContentBytes = 64 << 10
    /// A PKCS#12 file (binary) may be larger: it bundles the chain.
    public static let maxPKCS12Bytes = 1 << 20

    /// Why `data` cannot be what `kind` names, or nil. `inline`: the text of a
    /// `<kind>` block rather than a file sent with the profile.
    public static func contentProblem(_ kind: String, _ data: Data, inline: Bool) -> String? {
        if kind == "pkcs12" && !inline {
            return data.count <= maxPKCS12Bytes ? nil : "too large for a PKCS#12 file"
        }
        guard data.count <= (kind == "pkcs12" ? maxPKCS12Bytes : maxContentBytes) else {
            return "too large for a \(kind) block"
        }
        guard !data.contains(0), let text = String(data: data, encoding: .utf8) else { return "not text" }
        let lines = text.replacingOccurrences(of: "\r\n", with: "\n").components(separatedBy: "\n")
        switch kind {
        case "ca", "extra-certs", "cert":
            return blocks(lines, allowed: { $0 == "CERTIFICATE" || $0 == "TRUSTED CERTIFICATE" }, count: 1...)
        case "key":
            return blocks(lines, allowed: { $0.hasSuffix("PRIVATE KEY") }, count: 1...1)
        case "crl-verify":
            return blocks(lines, allowed: { $0 == "X509 CRL" }, count: 1...)
        case "tls-auth", "tls-crypt", "secret":
            if let p = blocks(lines, allowed: { $0 == "OpenVPN Static key V1" }, count: 1...1) { return p }
            let body = inside(lines).filter { !$0.isEmpty }
            return body.allSatisfy { $0.count == 32 && $0.allSatisfy(\.isHexDigit) } ? nil : "not an OpenVPN static key"
        case "tls-crypt-v2":
            return blocks(lines, allowed: { $0 == "OpenVPN tls-crypt-v2 client key" }, count: 1...1)
        case "pkcs12":
            let b64 = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/= \t")
            return lines.allSatisfy { $0.unicodeScalars.allSatisfy(b64.contains) } ? nil : "not base64"
        case "peer-fingerprint":
            for l in lines.map({ $0.trimmingCharacters(in: .whitespaces) }) where !l.isEmpty && !l.hasPrefix("#") {
                let bytes = l.split(separator: ":", omittingEmptySubsequences: false)
                guard [32, 48, 64].contains(bytes.count), bytes.allSatisfy({ $0.count == 2 && $0.allSatisfy(\.isHexDigit) }) else {
                    return "not a list of certificate fingerprints"
                }
            }
            return nil
        case "auth-user-pass", "http-proxy-user-pass", "http-proxy", "socks-proxy", "askpass":
            let used = lines.filter { !$0.isEmpty }
            guard used.count <= 2, used.allSatisfy({ $0.utf8.count <= 256 }) else {
                return "a username and a password (two lines) at most"
            }
            return nil
        default:
            return nil
        }
    }

    /// PEM blocks in `lines`: their types must pass `allowed`, their number lie in `count`.
    private static func blocks(_ lines: [String], allowed: (String) -> Bool, count: some RangeExpression<Int>) -> String? {
        var found = 0
        var open: String?
        for l in lines {
            let t = l.trimmingCharacters(in: .whitespaces)
            if let type = marker(t, "BEGIN") {
                guard open == nil else { return "a PEM block inside another" }
                guard allowed(type) else { return "a \(type) block is not expected here" }
                open = type
            } else if let type = marker(t, "END") {
                guard type == open else { return "an unmatched END line" }
                open = nil
                found += 1
            } else if open != nil {
                // Base64, or RFC 1421 headers of an encrypted key (Proc-Type, DEK-Info).
                let ok = t.isEmpty || t.contains(":") || t.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || "+/=".contains($0)) }
                guard ok else { return "not base64 inside a PEM block" }
            }
        }
        guard open == nil else { return "an unfinished PEM block" }
        return count.contains(found) ? nil : (found == 0 ? "no PEM block" : "too many PEM blocks")
    }

    private static func marker(_ line: String, _ word: String) -> String? {
        let head = "-----\(word) ", tail = "-----"
        guard line.hasPrefix(head), line.hasSuffix(tail), line.count > head.count + tail.count else { return nil }
        return String(line.dropFirst(head.count).dropLast(tail.count))
    }

    /// The lines between BEGIN and END markers.
    private static func inside(_ lines: [String]) -> [String] {
        var out: [String] = [], open = false
        for l in lines.map({ $0.trimmingCharacters(in: .whitespaces) }) {
            if marker(l, "BEGIN") != nil { open = true } else if marker(l, "END") != nil { open = false } else if open { out.append(l) }
        }
        return out
    }
}

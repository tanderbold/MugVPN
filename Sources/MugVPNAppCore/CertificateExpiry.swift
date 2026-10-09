import Foundation
import MugVPNCore

/// A warning before a profile's client certificate stops working (the server then refuses it).
public enum CertificateExpiry {
    public enum Warning: Equatable, Sendable {
        case expiresSoon(days: Int)
        case expired
    }
    public static let warnDays = 30

    public static func warning(notAfter: Date, now: Date) -> Warning? {
        if notAfter <= now { return .expired }
        let days = Int((notAfter.timeIntervalSince(now) / 86_400).rounded(.down))
        return days < warnDays ? .expiresSoon(days: days) : nil
    }

    /// The profile's own certificate (`cert`): inline, or the file it names (read relative to the profile).
    public static func clientCertificate(config: String, read: (String) -> String?) -> String? {
        guard let d = (try? ConfigParser.parse(config))?.last(where: { $0.name == "cert" }) else { return nil }
        if let inline = d.inline { return inline }
        return d.args.first.flatMap(read)
    }

    /// The end of the first certificate of a PEM text (its validity's notAfter).
    public static func notAfter(pem: String) -> Date? {
        let begin = "-----BEGIN CERTIFICATE-----", end = "-----END CERTIFICATE-----"
        guard let b = pem.range(of: begin), let e = pem.range(of: end, range: b.upperBound..<pem.endIndex),
              let der = Data(base64Encoded: String(pem[b.upperBound..<e.lowerBound]), options: .ignoreUnknownCharacters)
        else { return nil }
        var r = DER(Array(der))
        // Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { [0] version?, serial, signature, issuer, validity, ... } }
        guard var cert = r.enter(0x30), var tbs = cert.enter(0x30) else { return nil }
        if tbs.peek == 0xA0 { _ = tbs.skip() }
        for _ in 0..<3 { guard tbs.skip() else { return nil } }   // serial, signature, issuer
        guard var validity = tbs.enter(0x30), validity.skip(), let (tag, body) = validity.next(),
              let text = String(bytes: body, encoding: .ascii) else { return nil }
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        switch tag {
        case 0x17: f.dateFormat = "yyMMddHHmmss'Z'"   // UTCTime: 1950-2049
            guard let d = f.date(from: text) else { return nil }
            // DateFormatter's two-digit years pivot elsewhere: RFC 5280's is 50.
            let y = Int(text.prefix(2)) ?? 0
            let year = Calendar(identifier: .gregorian).dateComponents(in: TimeZone(identifier: "UTC")!, from: d).year ?? 0
            let want = y >= 50 ? 1900 + y : 2000 + y
            return Calendar(identifier: .gregorian).date(byAdding: .year, value: want - year, to: d)
        case 0x18: f.dateFormat = "yyyyMMddHHmmss'Z'"
            return f.date(from: text)
        default: return nil
        }
    }
}

/// Just enough DER to walk to a certificate's validity.
private struct DER {
    var bytes: [UInt8]
    var at = 0
    init(_ b: [UInt8]) { bytes = b }

    var peek: UInt8? { at < bytes.count ? bytes[at] : nil }

    mutating func next() -> (UInt8, [UInt8])? {
        guard at + 2 <= bytes.count else { return nil }
        let tag = bytes[at]
        var len = Int(bytes[at + 1])
        var i = at + 2
        if len & 0x80 != 0 {
            let n = len & 0x7F
            guard n >= 1, n <= 4, i + n <= bytes.count else { return nil }
            len = bytes[i..<i + n].reduce(0) { $0 << 8 | Int($1) }
            i += n
        }
        guard len >= 0, i + len <= bytes.count else { return nil }
        at = i + len
        return (tag, Array(bytes[i..<i + len]))
    }

    mutating func skip() -> Bool { next() != nil }

    mutating func enter(_ tag: UInt8) -> DER? {
        guard let (t, body) = next(), t == tag else { return nil }
        return DER(body)
    }
}

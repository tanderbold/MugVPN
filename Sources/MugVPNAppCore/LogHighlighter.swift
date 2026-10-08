import Foundation

/// Marks what matters in a line of openvpn's log: the status window colours
/// the marks; the rules live here so they are tested without a window.
public enum LogHighlighter {
    public enum Kind: String, Sendable { case timestamp, error, warning, success, address, keyword }

    public struct Span: Equatable {
        public var range: Range<String.Index>
        public var kind: Kind
    }

    static let errors = ["ERROR:", "FATAL", "AUTH_FAILED", "Verification Failed", "Exiting due to fatal error",
                         "TLS Error", "Connection refused"]
    static let warnings = ["WARNING:", "DEPRECATED", "NOTE:"]
    static let successes = ["Initialization Sequence Completed", "Peer Connection Initiated", "CONNECTED,SUCCESS"]

    static let timestamp = try! NSRegularExpression(pattern: #"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"#)
    static let keywords = try! NSRegularExpression(
        pattern: #"\bPUSH_REPLY\b|\broute (?:add|delete)\b|\bdns\b|\bDNS\b|\bSIG(?:TERM|USR1|HUP|INT)\b|\bRECONNECTING\b|\brestarting\b|TUN/TAP|\butun\d+\b"#)
    static let ipv4 = try! NSRegularExpression(pattern: #"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?![\d.])"#)
    static let ipv6 = try! NSRegularExpression(
        pattern: #"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?(?![0-9A-Fa-f:])|(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}(?![0-9A-Fa-f:])"#)

    public static func spans(_ line: String) -> [Span] {
        let all = NSRange(line.startIndex..., in: line)
        var out: [Span] = []
        var bodyStart = line.startIndex
        if let m = timestamp.firstMatch(in: line, range: all), let r = Range(m.range, in: line) {
            out.append(Span(range: r, kind: .timestamp))
            bodyStart = line.index(r.upperBound, offsetBy: line[r.upperBound...].first == " " ? 1 : 0)
        }
        let body = bodyStart..<line.endIndex
        // An error or a warning colours the whole message.
        if !body.isEmpty {
            if errors.contains(where: { line[body].contains($0) }) { return out + [Span(range: body, kind: .error)] }
            if warnings.contains(where: { line[body].contains($0) }) { return out + [Span(range: body, kind: .warning)] }
        }
        var candidates: [Span] = []
        for phrase in successes {
            var from = bodyStart
            while let r = line.range(of: phrase, range: from..<line.endIndex) {
                candidates.append(Span(range: r, kind: .success))
                from = r.upperBound
            }
        }
        let bodyRange = NSRange(body, in: line)
        for (re, kind) in [(keywords, Kind.keyword), (ipv4, .address), (ipv6, .address)] {
            for m in re.matches(in: line, range: bodyRange) {
                if let r = Range(m.range, in: line), !r.isEmpty { candidates.append(Span(range: r, kind: kind)) }
            }
        }
        // Earlier first, longer first; drop what overlaps a span already taken.
        candidates.sort {
            $0.range.lowerBound != $1.range.lowerBound ? $0.range.lowerBound < $1.range.lowerBound
                : line.distance(from: $0.range.lowerBound, to: $0.range.upperBound)
                    > line.distance(from: $1.range.lowerBound, to: $1.range.upperBound)
        }
        var end = bodyStart
        for c in candidates where c.range.lowerBound >= end {
            out.append(c)
            end = c.range.upperBound
        }
        return out
    }
}

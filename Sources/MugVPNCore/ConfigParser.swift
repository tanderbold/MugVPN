import Foundation

/// One directive of an OpenVPN config: `name arg1 arg2 ...`, or an inline
/// block `<name>...</name>` whose text is kept in `inline`.
public struct ConfigDirective: Equatable, Sendable {
    public var name: String
    public var args: [String]
    public var inline: String?
    public var line: Int

    public init(name: String, args: [String] = [], inline: String? = nil, line: Int = 0) {
        self.name = name
        self.args = args
        self.inline = inline
        self.line = line
    }
}

public struct ConfigParseError: Error, Equatable, CustomStringConvertible {
    public var line: Int
    public var message: String
    public var description: String { "line \(line): \(message)" }
}

/// Tokenizer that follows openvpn's own `parse_line` (options_parse.c):
/// whitespace-separated tokens, "double quotes" with backslash escapes,
/// 'single quotes' taken literally, `#`/`;` starting a token begins a comment,
/// a leading `--` on the directive is dropped. Anything openvpn would warn
/// about or read differently is an error here, so the helper never passes on
/// a config whose meaning is in doubt.
public enum ConfigParser {
    /// openvpn's OPTION_PARM_SIZE is 256 including the terminator.
    static let maxTokenLength = 255
    static let maxArgs = 16
    /// openvpn reads config lines, inline blocks included, in pieces of at most
    /// OPTION_LINE_SIZE (256) bytes; inside a block a longer line splits
    /// silently and its tail is read as a line of its own. Stay well below.
    public static let maxLineBytes = 254

    /// C isspace() in openvpn's locale: what openvpn skips and splits on.
    static func isSpace(_ c: Character) -> Bool {
        c == " " || c == "\t" || c == "\u{0B}" || c == "\u{0C}" || c == "\r"
    }

    /// The same on Unicode scalars. openvpn works on bytes: everything that
    /// decides a token, a quote or a tag is compared per scalar, never per
    /// grapheme (a combining mark would merge with the quote before it).
    static func isSpace(_ c: Unicode.Scalar) -> Bool {
        c == " " || c == "\t" || c == "\u{0B}" || c == "\u{0C}" || c == "\r"
    }

    /// `line` (after leading isspace) starts with `tag`, compared per scalar; the rest after it.
    static func afterTag(_ line: Substring, _ tag: String) -> String.UnicodeScalarView.SubSequence? {
        let s = line.unicodeScalars.drop(while: isSpace)
        guard s.starts(with: tag.unicodeScalars) else { return nil }
        return s.dropFirst(tag.unicodeScalars.count)
    }

    public static func parse(_ text: String) throws -> [ConfigDirective] {
        if text.contains("\0") {
            throw ConfigParseError(line: 0, message: "NUL byte in config")
        }
        // Files saved by Windows editors often start with a byte order mark.
        let body = text.hasPrefix("\u{FEFF}") ? String(text.dropFirst()) : text
        let lines = body.replacingOccurrences(of: "\r\n", with: "\n").components(separatedBy: "\n")
        var result: [ConfigDirective] = []
        var i = 0
        for (n, l) in lines.enumerated() where l.utf8.count > maxLineBytes {
            throw ConfigParseError(line: n + 1, message: "line longer than \(maxLineBytes) bytes")
        }
        while i < lines.count {
            let lineNo = i + 1
            var tokens = try tokenize(lines[i], line: lineNo)
            i += 1
            guard !tokens.isEmpty else { continue }
            if tokens[0].unicodeScalars.starts(with: "--".unicodeScalars) && tokens[0].unicodeScalars.count >= 3 {
                tokens[0] = String(tokens[0].unicodeScalars.dropFirst(2))
            }
            let first = tokens[0]
            let fs = first.unicodeScalars
            if fs.first == "<" && fs.last == ">" && !fs.starts(with: "</".unicodeScalars) && fs.count > 2 {
                guard tokens.count == 1 else {
                    throw ConfigParseError(line: lineNo, message: "text after inline tag \(first)")
                }
                let name = String(String.UnicodeScalarView(fs.dropFirst().dropLast()))
                let close = "</\(name)>"
                var body: [String] = []
                var closed = false
                while i < lines.count {
                    let l = lines[i]
                    i += 1
                    // Where openvpn's read_inline_file ends the block: after any leading isspace().
                    if let rest = afterTag(Substring(l), close) {
                        guard rest.allSatisfy(isSpace) else {
                            throw ConfigParseError(line: i, message: "text after \(close)")
                        }
                        closed = true
                        break
                    }
                    body.append(l)
                }
                guard closed else {
                    throw ConfigParseError(line: lineNo, message: "missing \(close)")
                }
                let text = body.isEmpty ? "" : body.joined(separator: "\n") + "\n"
                result.append(ConfigDirective(name: name, inline: text, line: lineNo))
                continue
            }
            if fs.first == "<" {
                throw ConfigParseError(line: lineNo, message: "stray tag \(first)")
            }
            guard tokens.count <= maxArgs else {
                throw ConfigParseError(line: lineNo, message: "too many parameters")
            }
            result.append(ConfigDirective(name: first, args: Array(tokens.dropFirst()), line: lineNo))
        }
        return result
    }

    static func tokenize(_ line: String, line lineNo: Int) throws -> [String] {
        enum State { case initial, unquoted, dquoted, squoted }
        var state = State.initial
        var tokens: [String] = []
        var current = String.UnicodeScalarView()
        var backslash = false

        func finish() throws {
            // openvpn's limit is in bytes.
            guard String(current).utf8.count <= maxTokenLength else {
                throw ConfigParseError(line: lineNo, message: "parameter longer than \(maxTokenLength) characters")
            }
            tokens.append(String(current))
            current = String.UnicodeScalarView()
            state = .initial
        }

        for ch in line.unicodeScalars {
            if !backslash && ch == "\\" && state != .squoted {
                backslash = true
                continue
            }
            var out: Unicode.Scalar?
            switch state {
            case .initial:
                if isSpace(ch) {
                    // Between tokens a space is skipped, escaped or not (openvpn's parse_line).
                } else if ch == "#" || ch == ";" {
                    if backslash { throw ConfigParseError(line: lineNo, message: "bad backslash") }
                    return tokens
                } else if !backslash && ch == "\"" {
                    state = .dquoted
                } else if !backslash && ch == "'" {
                    state = .squoted
                } else {
                    out = ch
                    state = .unquoted
                }
            case .unquoted:
                if !backslash && isSpace(ch) {
                    try finish()
                } else {
                    out = ch
                }
            case .dquoted:
                if !backslash && ch == "\"" {
                    try finish()
                } else {
                    out = ch
                }
            case .squoted:
                if ch == "'" {
                    try finish()
                } else {
                    out = ch
                }
            }
            if backslash, let o = out, !(o == "\\" || o == "\"" || isSpace(o)) {
                throw ConfigParseError(line: lineNo, message: "bad backslash")
            }
            backslash = false
            if let o = out { current.append(o) }
        }
        switch state {
        case .initial:
            if backslash { throw ConfigParseError(line: lineNo, message: "bad backslash") }
        case .unquoted:
            if backslash { throw ConfigParseError(line: lineNo, message: "bad backslash") }
            try finish()
        case .dquoted, .squoted:
            throw ConfigParseError(line: lineNo, message: "unterminated quote")
        }
        return tokens
    }

    /// Writes directives back in a form openvpn reads unambiguously: every
    /// parameter in double quotes with `\` and `"` escaped.
    public static func serialize(_ directives: [ConfigDirective]) -> String {
        var out = ""
        for d in directives {
            if let inline = d.inline {
                out += "<\(d.name)>\n\(inline)</\(d.name)>\n"
            } else {
                out += ([d.name] + d.args.map(quote)).joined(separator: " ") + "\n"
            }
        }
        return out
    }

    /// serialize(), for the file openvpn reads: refused unless openvpn reads
    /// it exactly as these directives (no line over the limit, no close tag
    /// inside a block's text).
    public static func serializeForOpenVPN(_ directives: [ConfigDirective]) throws -> String {
        let text = serialize(directives)
        for l in text.components(separatedBy: "\n") where l.utf8.count > maxLineBytes {
            throw ConfigParseError(line: 0, message: "a line of the config would be longer than \(maxLineBytes) bytes")
        }
        for d in directives {
            guard let inline = d.inline else { continue }
            for l in inline.components(separatedBy: "\n") where afterTag(Substring(l), "</\(d.name)>") != nil {
                throw ConfigParseError(line: d.line, message: "the text of <\(d.name)> holds its close tag")
            }
        }
        return text
    }

    /// Escaped per scalar: a combining mark after a quote must not hide it.
    static func quote(_ s: String) -> String {
        var out = String.UnicodeScalarView()
        out.append("\"")
        for c in s.unicodeScalars {
            if c == "\\" || c == "\"" { out.append("\\") }
            out.append(c)
        }
        out.append("\"")
        return String(out)
    }
}

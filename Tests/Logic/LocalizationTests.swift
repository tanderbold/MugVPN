import Foundation

// L-LOC: the app's string catalogs, checked against the source code.

private let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
private let appSources = repo.appendingPathComponent("Sources/MugVPN")
private let resources = repo.appendingPathComponent("Resources")
let languages = ["en", "cs", "de", "da", "el", "es", "fa", "fi", "fr", "it", "ja", "ko", "nl", "nb", "pl", "pt-BR",
                 "ru", "sv", "tr", "uk", "zh-Hans", "zh-Hant"]

private func sources() -> [(String, String)] {
    ((try? FileManager.default.contentsOfDirectory(atPath: appSources.path)) ?? []).filter { $0.hasSuffix(".swift") }.sorted()
        .map { ($0, (try? String(contentsOf: appSources.appendingPathComponent($0), encoding: .utf8)) ?? "") }
}

/// Every string literal passed to L("...") in the app.
func usedKeys() -> Set<String> {
    var keys = Set<String>()
    let re = try! NSRegularExpression(pattern: #"\bL\("((?:[^"\\]|\\.)*)""#)
    for (_, text) in sources() {
        for m in re.matches(in: text, range: NSRange(text.startIndex..., in: text)) {
            let raw = String(text[Range(m.range(at: 1), in: text)!])
            keys.insert(raw.replacingOccurrences(of: "\\\"", with: "\"").replacingOccurrences(of: "\\n", with: "\n")
                .replacingOccurrences(of: "\\\\", with: "\\"))
        }
    }
    return keys
}

func catalog(_ lang: String) -> [String: String]? {
    let url = resources.appendingPathComponent("\(lang).lproj/Localizable.strings")
    guard let data = try? Data(contentsOf: url) else { return nil }
    return (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: String]
}

func placeholders(_ s: String) -> [String] {
    let re = try! NSRegularExpression(pattern: #"%(\d+\$)?[@dlu]|%%"#)
    return re.matches(in: s, range: NSRange(s.startIndex..., in: s)).map { String(s[Range($0.range, in: s)!]) }
        .filter { $0 != "%%" }.map { $0.replacingOccurrences(of: #"\d+\$"#, with: "", options: .regularExpression) }.sorted()
}

func registerLocalizationTests() {
    test("LOC-01", "every key in every catalog, nothing stale") {
        let keys = usedKeys()
        expect(keys.count > 50, "found \(keys.count) keys in the app")
        for lang in languages {
            guard let cat = catalog(lang) else { expect(false, "\(lang): no catalog"); continue }
            let missing = keys.subtracting(cat.keys)
            let stale = Set(cat.keys).subtracting(keys)
            expect(missing.isEmpty, "\(lang) misses \(missing.count): \(missing.sorted().prefix(5))")
            expect(stale.isEmpty, "\(lang) has stale \(stale.sorted().prefix(5))")
            expect(cat.values.allSatisfy { !$0.trimmingCharacters(in: .whitespaces).isEmpty }, "\(lang): empty values")
        }
    }
    test("LOC-02", "placeholders match") {
        for lang in languages {
            for (k, v) in catalog(lang) ?? [:] where placeholders(k) != placeholders(v) {
                expect(false, "\(lang): \"\(k)\" -> \"\(v)\"")
            }
        }
    }
    test("LOC-04", "no user-visible literals around L()") {
        let pattern = #"(Form\.(label|row)\(|Form\.(checkbox|button)\("[a-z_]+", |NSMenuItem\(title: |\baction\(|title: |okTitle: |cancelTitle: |showError\(|placeholder: |toolTip = |stringValue = |Title: String\?? = |state: |text: )"[A-Za-z]"#
        let re = try! NSRegularExpression(pattern: pattern)
        for (file, text) in sources() where file != "E2E.swift" && file != "DevCLI.swift" {
            // Example addresses and URLs in placeholders are not words to translate.
            let address = try! NSRegularExpression(pattern: #"(placeholder: )"[^" ]*(\.|://)[^" ]*""#)
            for (n, line) in text.components(separatedBy: "\n").enumerated() {
                let rest = address.stringByReplacingMatches(in: line, range: NSRange(line.startIndex..., in: line), withTemplate: "$1x")
                if re.firstMatch(in: rest, range: NSRange(rest.startIndex..., in: rest)) != nil {
                    expect(false, "\(file):\(n + 1): \(line.trimmingCharacters(in: .whitespaces))")
                }
            }
        }
    }
    test("THEME-01", "no fixed colors in the interface code") {
        let re = try! NSRegularExpression(pattern: #"NSColor\((red|white|calibratedRed|srgbRed|deviceRed)|NSColor\.(white|black|red|blue|green|gray|darkGray|lightGray|yellow|orange)\b|\.(white|black)\b.*Color"#)
        for (file, text) in sources() {
            for (n, line) in text.components(separatedBy: "\n").enumerated()
                where re.firstMatch(in: line, range: NSRange(line.startIndex..., in: line)) != nil {
                expect(false, "\(file):\(n + 1): \(line.trimmingCharacters(in: .whitespaces))")
            }
        }
    }
    test("LOC-05", "catalogs are valid UTF-8 .strings") {
        for lang in languages {
            let url = resources.appendingPathComponent("\(lang).lproj/Localizable.strings")
            guard let data = try? Data(contentsOf: url) else { expect(false, "\(lang) missing"); continue }
            expect(String(data: data, encoding: .utf8) != nil, "\(lang) not UTF-8")
            expect(catalog(lang) != nil, "\(lang) does not parse")
        }
    }
}

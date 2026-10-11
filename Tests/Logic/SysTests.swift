import Foundation
import MugVPNSys

func registerSysTests() {
    test("SYS-01", "removing in a user's home: each step opened from the last, never through a link (swapped in at any time)") {
        // Under /var/folders: reached through /var, the system's own link (root's, in /).
        let root = NSTemporaryDirectory() + "mugvpn-sys-\(UUID().uuidString)"
        let fm = FileManager.default
        defer { try? fm.removeItem(atPath: root) }
        func mk(_ p: String) throws { try fm.createDirectory(atPath: root + p, withIntermediateDirectories: true) }
        func put(_ p: String) { fm.createFile(atPath: root + p, contents: Data("x".utf8)) }
        func exists(_ p: String) -> Bool { (try? fm.attributesOfItem(atPath: root + p)) != nil }
        func remove(_ home: String, _ dirs: [String], _ name: String) -> Int32 {
            var c = dirs.map { strdup($0) }
            defer { c.forEach { free($0) } }
            return c.withUnsafeMutableBufferPointer { b in
                b.baseAddress!.withMemoryRebound(to: UnsafePointer<CChar>?.self, capacity: b.count) {
                    mugvpn_remove_beneath(root + home, $0, Int32(dirs.count), name)
                }
            }
        }
        // a: a real tree, with a link inside pointing elsewhere.
        try mk("/a/Library/Logs/MugVPN/sub")
        put("/a/Library/Logs/MugVPN/sub/x.log")
        try mk("/elsewhere/MugVPN")
        put("/elsewhere/MugVPN/keep")
        try fm.createSymbolicLink(atPath: root + "/a/Library/Logs/MugVPN/sub/out", withDestinationPath: root + "/elsewhere")
        expectEqual(remove("/a", ["Library", "Logs"], "MugVPN"), 0)
        expect(!exists("/a/Library/Logs/MugVPN"), "removed with all in it")
        expect(exists("/elsewhere/MugVPN/keep"), "a link inside: the link goes, not what it points to")
        // b: its Logs a link: nothing followed, nothing to remove.
        try mk("/b/Library")
        try fm.createSymbolicLink(atPath: root + "/b/Library/Logs", withDestinationPath: root + "/elsewhere")
        expectEqual(remove("/b", ["Library", "Logs"], "MugVPN"), 1, "left: not a way root may take (said, not taken for gone)")
        expect(exists("/elsewhere/MugVPN/keep"), "not through a link on the way")
        // c: the name itself a link: the link goes.
        try mk("/c/Library/Preferences")
        try fm.createSymbolicLink(atPath: root + "/c/Library/Preferences/com.mugvpn.app.plist", withDestinationPath: root + "/elsewhere/MugVPN/keep")
        expectEqual(remove("/c", ["Library", "Preferences"], "com.mugvpn.app.plist"), 0)
        expect(!exists("/c/Library/Preferences/com.mugvpn.app.plist") && exists("/elsewhere/MugVPN/keep"))
        // d: the home itself a link.
        try fm.createSymbolicLink(atPath: root + "/d", withDestinationPath: root + "/a")
        try mk("/a/Library/Logs/MugVPN")
        expectEqual(remove("/d", ["Library", "Logs"], "MugVPN"), 1)
        expect(exists("/a/Library/Logs/MugVPN"), "not through a home that is a link")
        expectEqual(remove("/none", ["Library", "Logs"], "MugVPN"), 0, "nothing there: gone")
        // f: a link of the user's on the way to the home (in a folder the user controls): not followed.
        try mk("/f-real/home/Library/Logs/MugVPN")
        try fm.createSymbolicLink(atPath: root + "/flink", withDestinationPath: root + "/f-real")
        expectEqual(remove("/flink/home", ["Library", "Logs"], "MugVPN"), 1)
        expect(exists("/f-real/home/Library/Logs/MugVPN"), "not through a link on the way to the home")
        expectEqual(remove("/f-real/../f-real/home", ["Library", "Logs"], "MugVPN"), 1)
        expect(exists("/f-real/home/Library/Logs/MugVPN"), "no .. on the way")
        expectEqual(remove("/f-real/home", ["Library", "Logs"], "MugVPN"), 0)
        expect(!exists("/f-real/home/Library/Logs/MugVPN"), "a home reached through the system's own links (/var here): removed")
        // The same through /private (where /var points): the same home.
        try mk("/f-real/home/Library/Logs/MugVPN")
        let priv = (root.hasPrefix("/var/") ? "/private" : "") + root
        var c = [strdup("Library"), strdup("Logs")]
        defer { c.forEach { free($0) } }
        let r = c.withUnsafeMutableBufferPointer { b in
            b.baseAddress!.withMemoryRebound(to: UnsafePointer<CChar>?.self, capacity: 2) {
                mugvpn_remove_beneath(priv + "/f-real/home", $0, 2, "MugVPN")
            }
        }
        expectEqual(r, 0)
        expect(!exists("/f-real/home/Library/Logs/MugVPN"), "through /private")
        // e: one that cannot go is said.
        try mk("/e/Library/Logs/MugVPN")
        put("/e/Library/Logs/MugVPN/f")
        chmod(root + "/e/Library/Logs/MugVPN", 0o500)
        defer { chmod(root + "/e/Library/Logs/MugVPN", 0o755) }
        if getuid() != 0 { expectEqual(remove("/e", ["Library", "Logs"], "MugVPN"), -1, "not removed: said") }
    }
}

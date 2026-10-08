import Foundation

private let iconRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()

/// The element types inside an .icns file.
func icnsTypes(_ data: Data) -> [String] {
    guard data.count > 8, String(decoding: data.prefix(4), as: UTF8.self) == "icns" else { return [] }
    var types: [String] = []
    var off = 8
    while off + 8 <= data.count {
        let type = String(decoding: data[off..<off + 4], as: UTF8.self)
        let len = data[off + 4..<off + 8].reduce(0) { $0 << 8 | Int($1) }
        guard len >= 8 else { break }
        types.append(type)
        off += len
    }
    return types
}

func registerIconTests() {
    test("ICON-01", "the app icon in every size, named and bundled") {
        let data = (try? Data(contentsOf: iconRoot.appendingPathComponent("Resources/AppIcon.icns"))) ?? Data()
        let types = Set(icnsTypes(data))
        // 16 and 32 px may be PNG (icp4, icp5) or ARGB (ic04, ic05, what iconutil writes).
        let sizes: [(String, Set<String>)] = [("16", ["icp4", "ic04"]), ("32", ["icp5", "ic05"]), ("128", ["ic07"]),
                                              ("256", ["ic08"]), ("512", ["ic09"]), ("1024", ["ic10"])]
        for (px, alternatives) in sizes { expect(!types.isDisjoint(with: alternatives), "AppIcon.icns has \(px) px") }
        let plist = (try? String(contentsOf: iconRoot.appendingPathComponent("Resources/Info.plist"), encoding: .utf8)) ?? ""
        expect(plist.contains("<key>CFBundleIconFile</key>") && plist.contains("<string>AppIcon</string>"))
        let build = (try? String(contentsOf: iconRoot.appendingPathComponent("tools/build.sh"), encoding: .utf8)) ?? ""
        expect(build.contains("AppIcon.icns"))
    }
}

func pngSize(_ data: Data) -> (Int, Int)? {
    guard data.count > 24, data.prefix(8) == Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) else { return nil }
    let w = data[16..<20].reduce(0) { $0 << 8 | Int($1) }, h = data[20..<24].reduce(0) { $0 << 8 | Int($1) }
    return (w, h)
}

func registerMenuIconTests() {
    test("ICON-02", "our menu bar icon in three states") {
        for state in ["idle", "connecting", "connected"] {
            for (suffix, px) in [("", 18), ("@2x", 36)] {
                let name = "Resources/menubar/MenuIcon-\(state)\(suffix).png"
                let data = (try? Data(contentsOf: iconRoot.appendingPathComponent(name))) ?? Data()
                expect(pngSize(data).map { $0 == (px, px) } ?? false, "\(name) is \(px)x\(px)")
            }
        }
        let build = (try? String(contentsOf: iconRoot.appendingPathComponent("tools/build.sh"), encoding: .utf8)) ?? ""
        expect(build.contains("Resources/menubar"))
    }
}

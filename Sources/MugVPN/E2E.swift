import AppKit
import MugVPNAppCore
import MugVPNCore

#if MUGVPN_TESTING

// E2E mode (MUGVPN_E2E=1): the interface tests' socket and a fake backend.
// See Tests/UI/PROTOCOL.md. Nothing here runs in a normal launch.

final class FakeLink: ManagementLink {
    let profile: String
    let onData: (Data) -> Void
    let onClose: () -> Void
    var sent: [String] = []
    init(profile: String, onData: @escaping (Data) -> Void, onClose: @escaping () -> Void) {
        self.profile = profile
        self.onData = onData
        self.onClose = onClose
    }
    func write(_ data: Data) { sent += String(decoding: data, as: UTF8.self).split(separator: "\n").map(String.init) }
    func write(_ data: Data, passing fd: Int32) -> Bool {
        write(data)
        return true
    }
    func close() {}
}

final class E2EBackend: HelperClient, ManagementTransport, HelperSetup {
    var isTestDouble: Bool { true }
    var starts: [String] = []
    var bundles: [String: [String: Any]] = [:]
    var stops: [String] = []
    var refuse: String?
    var links: [String: FakeLink] = [:]
    var logs: [String: String] = [:]
    var state: HelperState = .enabled
    var services: E2EServices?

    func start(_ bundle: ProfileBundle, reply: @escaping (Result<(id: String, socket: String), Error>) -> Void) {
        if let r = refuse {
            refuse = nil
            return reply(.failure(ProfileError(r)))
        }
        starts.append(bundle.name)
        let p = bundle.protection
        bundles[bundle.name] = ["split_dns": bundle.splitDNS,
                                "protection": ["killSwitch": p.killSwitch, "blockIPv6": p.blockIPv6,
                                               "dnsOnlyTunnel": p.dnsOnlyTunnel, "allowLAN": p.allowLAN]]
        reply(.success(("F-\(bundle.name)", "fake:\(bundle.name)")))
    }
    func stop(_ id: String, reply: @escaping (String?) -> Void) {
        stops.append(String(id.dropFirst(2)))
        reply(nil)
    }
    func list(reply: @escaping ([ConnectionInfo]) -> Void) { reply([]) }
    var blocked: [String] = []
    var unblocks = 0
    func blocks(reply: @escaping ([String]) -> Void) { reply(blocked) }
    func unblock(reply: @escaping (String?) -> Void) { unblocks += 1; blocked = []; reply(nil) }
    func tunnelRequest(_ id: String, kind: String, message: String, reply: @escaping (Result<FileHandle?, Error>) -> Void) {
        reply(.failure(ProfileError("no tunnels in E2E mode")))
    }
    func releaseManagement(_ id: String, reply: @escaping (String?) -> Void) { reply(nil) }
    var uninstallRequests: [[String: Any]] = []
    func uninstall(keepProfiles: Bool, reply: @escaping (String?) -> Void) {
        uninstallRequests.append(["keepProfiles": keepProfiles])
        reply(nil)
    }
    func unregister() {}
    func startPersistent(_ name: String, reply: @escaping (Result<String, Error>) -> Void) {
        reply(.failure(ProfileError("no persistent connections in E2E mode")))
    }
    func open(_ socket: String, onData: @escaping (Data) -> Void, onClose: @escaping () -> Void) -> ManagementLink? {
        let name = String(socket.dropFirst("fake:".count))
        let l = FakeLink(profile: name, onData: onData, onClose: onClose)
        links[name] = l
        return l
    }
    func register() {}
    func openLoginItems() { services?.urls.append("x-apple.systempreferences:com.apple.LoginItems-Settings.extension") }
}

final class FakeNetworkProbe: NetworkProbe {
    var available = false
    var netstatText = ""
    var scutilText = ""
    var interfaces: [String: String] = [:]
    var netstat6Text = ""
    func netstat6() -> String { netstat6Text }
    func netstat() -> String { netstatText }
    func scutilDNS() -> String { scutilText }
    func interface(for ip: String) -> String? { interfaces[ip] }
}

final class FakeHTTP: HTTPFetcher {
    var responses: [HTTPResponse] = []
    var requests: [[String: String]] = []
    func get(_ url: URL, username: String, password: String, completion: @escaping (Result<HTTPResponse, Error>) -> Void) {
        requests.append(["url": url.absoluteString, "username": username, "password": password])
        let r = responses.isEmpty ? HTTPResponse(status: 503, body: Data(), contentDisposition: nil) : responses.removeFirst()
        DispatchQueue.main.async { completion(.success(r)) }
    }
}

final class E2EServices: Services {
    let http: HTTPFetcher = FakeHTTP()
    var removed: [String] = []
    var trashed = ""
    func removeUserData(_ paths: [String]) { removed += paths }
    func moveAppToTrash() {
        trashed = Bundle.main.bundlePath
        // The app quits right after this: leave the record for the test in its home.
        let home = ProcessInfo.processInfo.environment["MUGVPN_E2E_HOME"] ?? NSTemporaryDirectory()
        let record: [String: Any] = ["helper": backend.uninstallRequests, "removed": removed, "trashed": trashed]
        if let d = try? JSONSerialization.data(withJSONObject: record) {
            FileManager.default.createFile(atPath: home + "/uninstall.json", contents: d)
        }
    }
    var urls: [String] = []
    var notes: [[String: String]] = []
    var nextFile: String??
    let backend: E2EBackend
    var realHelperSetup: HelperSetup?
    var helperSetup: HelperSetup { realHelperSetup ?? backend }

    init(backend: E2EBackend) {
        self.backend = backend
        backend.services = self
    }
    func open(_ url: String) { urls.append(url) }
    func notify(title: String, text: String) { notes.append(["title": title, "text": text]) }
    func showMessage(profile: String, title: String, text: String) { showMessageWindow(profile: profile, title: title, text: text) }
    func reveal(_ path: String) { urls.append("reveal:" + path) }
    var panels = 0
    func chooseFile() -> String? {
        panels += 1 // the real app shows an open panel here
        defer { nextFile = nil }
        return nextFile ?? nil
    }
}

final class E2EServer {
    let path: String
    let backend: E2EBackend
    let services: E2EServices
    weak var app: AppController?

    init(path: String, backend: E2EBackend, services: E2EServices) {
        self.path = path
        self.backend = backend
        self.services = services
    }

    func start() {
        unlink(path)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &addr.sun_path) { $0.copyBytes(from: Array(path.utf8).prefix(103)) }
        _ = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        chmod(path, 0o600)
        listen(fd, 4)
        Thread.detachNewThread { [self] in
            while true {
                let c = accept(fd, nil, nil)
                if c < 0 { continue }
                Thread.detachNewThread { self.serve(c) }
            }
        }
    }

    private func serve(_ c: Int32) {
        let input = FileHandle(fileDescriptor: c, closeOnDealloc: true)
        var buffer = Data()
        while true {
            let chunk = input.availableData
            if chunk.isEmpty { return }
            buffer.append(chunk)
            while let nl = buffer.firstIndex(of: 0x0A) {
                let line = buffer[buffer.startIndex..<nl]
                buffer.removeSubrange(buffer.startIndex...nl)
                var reply: [String: Any] = [:]
                var quitAfter = false
                DispatchQueue.main.sync {
                    do {
                        guard let req = try JSONSerialization.jsonObject(with: line) as? [String: Any],
                              let cmd = req["cmd"] as? String else { throw E2EError("bad request") }
                        reply = try handle(cmd, req)
                        reply["ok"] = true
                        quitAfter = cmd == "quit"
                    } catch {
                        reply = ["ok": false, "error": "\(error)"]
                    }
                }
                var out = (try? JSONSerialization.data(withJSONObject: reply)) ?? Data("{\"ok\":false}".utf8)
                out.append(0x0A)
                input.write(out)
                if quitAfter { DispatchQueue.main.async { exit(0) } }
            }
        }
    }

    struct E2EError: Error, CustomStringConvertible {
        let description: String
        init(_ d: String) { description = d }
    }

    private func handle(_ cmd: String, _ r: [String: Any]) throws -> [String: Any] {
        guard let app else { throw E2EError("the app is not ready") }
        func str(_ k: String) throws -> String {
            guard let v = r[k] as? String else { throw E2EError("missing \(k)") }
            return v
        }
        func window() throws -> AppWindow {
            guard let w = WindowRegistry.shared.find(try str("window")) else { throw E2EError("no window \(r["window"] ?? "")") }
            return w
        }
        func control(_ w: AppWindow) throws -> NSView {
            guard let v = w.control(try str("control")) else { throw E2EError("no control \(r["control"] ?? "")") }
            return v
        }
        switch cmd {
        case "ping": return [:]
        case "status":
            var pixels = 0
            if let img = app.statusItem.button?.image, let tiff = img.tiffRepresentation, let rep = NSBitmapImageRep(data: tiff) {
                for x in 0..<rep.pixelsWide { for y in 0..<rep.pixelsHigh where (rep.colorAt(x: x, y: y)?.alphaComponent ?? 0) > 0.5 { pixels += 1 } }
            }
            return ["icon": app.icon.rawValue, "tooltip": app.tooltip, "image": app.statusItem.button?.image?.name() ?? "",
                    "button_width": Double(app.statusItem.button?.frame.width ?? 0), "image_pixels": pixels]
        case "rescan":
            app.rescan()
            return [:]
        case "menu":
            app.menuNeedsUpdate(app.menu)
            return ["items": describe(app.menu)]
        case "click_menu":
            guard let path = r["path"] as? [String] else { throw E2EError("missing path") }
            app.menuNeedsUpdate(app.menu)
            var menu: NSMenu? = app.menu
            var item: NSMenuItem?
            for title in path {
                item = menu?.items.first { $0.title == title }
                guard item != nil else { throw E2EError("no menu item \(title)") }
                menu = item?.submenu
            }
            guard let i = item, let action = i.action, i.isEnabled else { throw E2EError("menu item \(path) is not actionable") }
            NSApp.sendAction(action, to: i.target, from: i)
            return [:]
        case "windows":
            return ["windows": WindowRegistry.shared.windows.filter(\.isVisible).map(describe)]
        case "set":
            let v = try control(try window())
            let value = r["value"]
            switch v {
            case let p as NSPopUpButton:
                guard let s = value as? String, let i = p.itemArray.firstIndex(where: { $0.identifier?.rawValue == s }) else {
                    throw E2EError("no popup value \(value ?? "")")
                }
                p.selectItem(at: i)
                if let a = p.action { NSApp.sendAction(a, to: p.target, from: p) }
            case let l as ListView:
                guard let s = value as? String, let i = l.titles.firstIndex(of: s) else { throw E2EError("no row \(value ?? "")") }
                l.pick(i)
            case let t as NSTabView:
                guard let s = value as? String, t.tabViewItems.contains(where: { $0.identifier as? String == s }) else {
                    throw E2EError("no tab \(value ?? "")")
                }
                t.selectTabViewItem(withIdentifier: s)
            case let b as Checkbox:
                // As a click: the window hears about it.
                b.state = (value as? Bool ?? false) ? .on : .off
                if let a = b.action { NSApp.sendAction(a, to: b.target, from: b) }
            case let f as NSTextField:
                f.stringValue = value as? String ?? ""
                f.delegate?.controlTextDidChange?(Notification(name: NSControl.textDidChangeNotification, object: f))
            case let t as NSTextView:
                t.string = value as? String ?? ""
                t.didChangeText()
            default: throw E2EError("cannot set \(type(of: v))")
            }
            return [:]
        case "press":
            guard let b = try control(try window()) as? NSButton, b.isEnabled else { throw E2EError("not an enabled button") }
            b.performClick(nil)
            return [:]
        case "key":
            let w = try window()
            let key = try str("key") == "escape" ? "\u{1b}" : "\r"
            func buttons(_ v: NSView) -> [NSButton] { ((v as? NSButton).map { [$0] } ?? []) + v.subviews.flatMap(buttons) }
            guard let b = w.contentView.map(buttons)?.first(where: { $0.keyEquivalent == key && $0.isEnabled }) else {
                throw E2EError("no button for \(key == "\r" ? "Return" : "Escape")")
            }
            b.performClick(nil)
            return [:]
        case "close":
            try window().performClose(nil)
            return [:]
        case "fake_feed":
            guard let l = backend.links[try str("profile")], let lines = r["lines"] as? [String] else { throw E2EError("no link") }
            l.onData(Data((lines.joined(separator: "\n") + "\n").utf8))
            return [:]
        case "fake_sent":
            return ["lines": backend.links[try str("profile")]?.sent ?? []]
        case "fake_close":
            backend.links.removeValue(forKey: try str("profile"))?.onClose()
            return [:]
        case "fake_helper": return ["starts": backend.starts, "stops": backend.stops, "bundles": backend.bundles,
                                    "unblocks": backend.unblocks]
        case "snapshot":
            // A window as it looks on screen, frame and shadow included (an app may capture its own windows).
            let w = try window()
            w.displayIfNeeded()
            guard let img = CGWindowListCreateImage(.null, .optionIncludingWindow, CGWindowID(w.windowNumber), [.bestResolution]) else {
                throw E2EError("cannot capture the window")
            }
            try NSBitmapImageRep(cgImage: img).representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: try str("path")))
            return ["width": img.width, "height": img.height]
        case "snapshot_menu":
            // Open the status menu, capture its window, close it.
            let path = try str("path")
            let menu = app.menu
            app.menuNeedsUpdate(menu)
            var result: [String: Any] = [:]
            let capture = Timer(timeInterval: 0.8, repeats: false) { _ in
                let mine = (CGWindowListCopyWindowInfo([.optionOnScreenOnly], kCGNullWindowID) as? [[String: Any]] ?? []).filter {
                    ($0[kCGWindowOwnerPID as String] as? Int32) == ProcessInfo.processInfo.processIdentifier
                        && (($0[kCGWindowLayer as String] as? Int) ?? 0) > 20
                }
                if let n = mine.compactMap({ $0[kCGWindowNumber as String] as? UInt32 }).first,
                   let img = CGWindowListCreateImage(.null, .optionIncludingWindow, n, [.bestResolution]) {
                    try? NSBitmapImageRep(cgImage: img).representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: path))
                    result = ["width": img.width, "height": img.height]
                }
                menu.cancelTracking()
            }
            RunLoop.main.add(capture, forMode: .common)
            app.statusItem.button?.performClick(nil)
            return result
        case "fake_blocks":
            backend.blocked = r["names"] as? [String] ?? []
            app.refreshBlocks()
            return [:]
        case "fake_refuse":
            backend.refuse = r["message"] as? String
            return [:]
        case "fake_log":
            backend.logs[try str("profile")] = try str("text")
            return [:]
        case "fake_network":
            let p = app.probe as? FakeNetworkProbe ?? FakeNetworkProbe()
            p.available = true
            p.netstatText = r["netstat"] as? String ?? ""
            p.scutilText = r["scutil"] as? String ?? ""
            p.interfaces = r["interfaces"] as? [String: String] ?? [:]
            p.netstat6Text = r["netstat6"] as? String ?? ""
            app.probe = p
            return [:]
        case "leak_check":
            app.checkLeaks(now: true)
            return ["findings": app.leaksShown.map { app.leakText($0) }]
        case "fake_helper_status":
            backend.state = HelperState(rawValue: try str("status")) ?? .enabled
            return [:]
        case "answer_open_panel":
            services.nextFile = .some(r["path"] as? String)
            return [:]
        case "command_import":
            // What `MugVPN --command import <path>` from another program does.
            app.confirmImport(try str("path"))
            return [:]
        case "open_files":
            app.importFiles(r["paths"] as? [String] ?? [])
            return [:]
        case "system_event":
            let e: SystemEvent
            switch try str("event") {
            case "willSleep": e = .willSleep
            case "didWake": e = .didWake
            case "networkChanged": e = .networkChanged
            default: throw E2EError("unknown event")
            }
            app.systemEvent(e)
            return [:]
        case "fake_http":
            let fake = services.http as! FakeHTTP
            fake.responses += (r["responses"] as? [[String: Any]] ?? []).map {
                HTTPResponse(status: $0["status"] as? Int ?? 200, body: Data(($0["body"] as? String ?? "").utf8),
                             contentDisposition: $0["disposition"] as? String)
            }
            return [:]
        case "http_requests": return ["requests": (services.http as! FakeHTTP).requests]
        case "uninstall_log":
            return ["helper": backend.uninstallRequests, "removed": services.removed, "trashed": services.trashed]
        case "opened_urls": return ["urls": services.urls, "panels": services.panels]
        case "notifications": return ["items": services.notes]
        case "quit": return [:]
        default: throw E2EError("unknown command \(cmd)")
        }
    }

    private func describe(_ menu: NSMenu) -> [[String: Any]] {
        menu.items.filter { !$0.isSeparatorItem }.map { i in
            var d: [String: Any] = ["title": i.title, "enabled": i.isEnabled, "checked": i.state == .on]
            if let s = i.submenu { d["children"] = describe(s) }
            return d
        }
    }

    /// The control's text does not fit its frame, or the control sticks out of the window.
    private func clipped(_ v: NSView, in w: AppWindow) -> Bool {
        guard let content = w.contentView, !v.isHiddenOrHasHiddenAncestor else { return false }
        let inWindow = v.convert(v.bounds, to: content)
        if !content.bounds.insetBy(dx: -1, dy: -1).contains(inWindow) { return true }
        guard let control = v as? NSControl, let cell = control.cell else { return false }
        if let f = control as? NSTextField, f.isEditable { return false }
        let bounds = control.bounds
        if let f = control as? NSTextField, f.cell?.wraps == true || f.maximumNumberOfLines != 1 {
            let need = cell.cellSize(forBounds: NSRect(x: 0, y: 0, width: bounds.width, height: .greatestFiniteMagnitude))
            return need.height > bounds.height + 1
        }
        if let f = control as? NSTextField, f.lineBreakMode == .byTruncatingMiddle || f.lineBreakMode == .byTruncatingTail {
            return false // shortened on purpose (file names)
        }
        if let p = control as? NSPopUpButton {
            // A popup's cellSize includes its bezel insets; its intrinsic size is what it needs.
            return p.intrinsicContentSize.width > bounds.width + 1
        }
        return cell.cellSize.width > bounds.width + 1
    }

    private func describe(_ w: AppWindow) -> [String: Any] {
        var controls: [[String: Any]] = []
        func walk(_ v: NSView) {
            let id = v.accessibilityIdentifier()
            if !id.isEmpty, id != "mugvpn_status_item" {
                var c: [String: Any] = ["id": id, "visible": !v.isHiddenOrHasHiddenAncestor]
                switch v {
                case let l as ListView:
                    c["type"] = "list"; c["items"] = l.titles; c["enabled"] = l.isEnabled
                    c["value"] = l.selectedRow >= 0 && l.selectedRow < l.titles.count ? l.titles[l.selectedRow] : ""
                    c["label"] = l.accessibilityLabel() ?? ""
                case let t as NSTabView:
                    c["type"] = "tabs"; c["items"] = t.tabViewItems.compactMap { $0.identifier as? String }
                    c["value"] = t.selectedTabViewItem?.identifier as? String ?? ""; c["enabled"] = true
                    c["label"] = t.accessibilityLabel() ?? ""
                case let p as NSPopUpButton:
                    c["type"] = "popup"; c["value"] = p.selectedItem?.identifier?.rawValue ?? ""; c["enabled"] = p.isEnabled
                    c["label"] = p.accessibilityLabel() ?? ""
                case let b as Checkbox:
                    c["type"] = "checkbox"; c["value"] = b.state == .on; c["enabled"] = b.isEnabled
                    c["label"] = (b.title) + (b.toolTip.map { " (\($0))" } ?? "")
                case let b as NSButton:
                    c["type"] = "button"; c["value"] = b.title; c["enabled"] = b.isEnabled; c["label"] = b.title
                case let f as NSSecureTextField:
                    c["type"] = "secure"; c["value"] = f.stringValue; c["enabled"] = f.isEnabled; c["label"] = f.accessibilityLabel() ?? ""
                case let f as NSTextField:
                    c["type"] = f.isEditable ? "text" : "label"; c["value"] = f.stringValue; c["enabled"] = f.isEnabled
                    c["label"] = f.accessibilityLabel() ?? ""
                case let t as NSTextView:
                    c["type"] = "text"; c["value"] = t.string; c["enabled"] = t.isEditable; c["label"] = t.accessibilityLabel() ?? ""
                    var kinds = Set<String>()
                    if let storage = t.textStorage {
                        storage.enumerateAttribute(StatusView.kindKey, in: NSRange(location: 0, length: storage.length)) { v, _, _ in
                            if let k = v as? String { kinds.insert(k) }
                        }
                    }
                    c["highlights"] = kinds.sorted()
                    c["theme"] = t.effectiveAppearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua ? "dark" : "light"
                default:
                    c["type"] = "view"; c["value"] = ""; c["enabled"] = true; c["label"] = ""
                }
                c["clipped"] = clipped(v, in: w)
                if let content = w.contentView, !v.isHiddenOrHasHiddenAncestor {
                    let f = v.convert(v.bounds, to: content)
                    c["frame"] = [Double(f.minX), Double(f.minY), Double(f.width), Double(f.height)]
                }
                controls.append(c)
            }
            v.subviews.forEach(walk)
        }
        if let v = w.contentView { walk(v) }
        // Texts without an id (row labels, headings) must fit too.
        func unnamed(_ v: NSView) -> [String] {
            var out: [String] = []
            if v.accessibilityIdentifier().isEmpty, let f = v as? NSTextField, !f.isEditable, !f.stringValue.isEmpty,
               clipped(f, in: w) { out.append(f.stringValue) }
            return out + v.subviews.flatMap(unnamed)
        }
        if let v = w.contentView {
            for text in unnamed(v) {
                controls.append(["id": "(label)", "type": "label", "value": text, "visible": true, "enabled": true,
                                 "label": text, "clipped": true])
            }
        }
        let dark = w.effectiveAppearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
        return ["id": w.windowID, "kind": w.kind, "title": w.title, "profile": w.profile,
                "appearance": dark ? "darkAqua" : "aqua", "controls": controls]
    }
}
#endif

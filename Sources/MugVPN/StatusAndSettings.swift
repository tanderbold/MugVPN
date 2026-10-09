import AppKit
import MugVPNAppCore

/// The connection's status window: state, address, traffic, log.
final class StatusView: NSObject {
    let view: NSView
    private let state = Form.label("", id: "state_text", bold: true, wraps: false)
    private let ip = Form.label("", id: "ip_text", wraps: false)
    private let bytesIn = Form.label("", id: "bytes_in", wraps: false)
    private let bytesOut = Form.label("", id: "bytes_out", wraps: false)
    private let logView = NSTextView()
    private let scroll = NSScrollView()
    private var themePopup: NSPopUpButton!
    var onTheme: (LogTheme) -> Void = { _ in }
    private let onConnect: () -> Void
    private let onDisconnect: () -> Void
    private let onReconnect: () -> Void
    private var connectButton: NSButton!
    private var disconnectButton: NSButton!
    private var reconnectButton: NSButton!
    var onHide: () -> Void = {}
    /// Lines of the connection shown so far (counting those since dropped).
    private var shownLines = 0
    /// Lines in the view now; the oldest go beyond 5000.
    private var viewLines = 0
    private static let maxViewLines = 5000

    private func trimShown() {
        guard viewLines > StatusView.maxViewLines, let storage = logView.textStorage else { return }
        let text = storage.string as NSString
        var cut = 0, drop = viewLines - StatusView.maxViewLines
        while drop > 0 {
            let r = text.range(of: "\n", range: NSRange(location: cut, length: text.length - cut))
            guard r.location != NSNotFound else { break }
            cut = r.location + 1
            drop -= 1
        }
        storage.deleteCharacters(in: NSRange(location: 0, length: cut))
        viewLines = StatusView.maxViewLines + drop
    }

    init(onConnect: @escaping () -> Void, onDisconnect: @escaping () -> Void, onReconnect: @escaping () -> Void) {
        self.onConnect = onConnect
        self.onDisconnect = onDisconnect
        self.onReconnect = onReconnect
        logView.isEditable = false
        logView.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        logView.setAccessibilityIdentifier("log")
        scroll.documentView = logView
        scroll.hasVerticalScroller = true
        logView.autoresizingMask = [.width]
        scroll.widthAnchor.constraint(equalToConstant: 560).isActive = true
        scroll.heightAnchor.constraint(equalToConstant: 260).isActive = true
        themePopup = Form.popup("log_theme", [("system", L("Automatic")), ("light", L("Light")), ("dark", L("Dark"))],
                                selected: "system")
        let stack = Form.column([state, Form.row(L("Address:"), ip), Form.row(L("Received:"), bytesIn),
                                 Form.row(L("Sent:"), bytesOut), Form.row(L("Log theme:"), themePopup), scroll])
        view = stack
        super.init()
        connectButton = Form.button("connect", L("Connect"), target: self, action: #selector(connect))
        disconnectButton = Form.button("disconnect", L("Disconnect"), target: self, action: #selector(disconnect))
        reconnectButton = Form.button("reconnect", L("Reconnect"), target: self, action: #selector(reconnect))
        let buttons = Form.buttons([connectButton, disconnectButton, reconnectButton,
                                    Form.button("hide", L("Hide"), key: "\u{1b}", target: self, action: #selector(hide))])
        stack.addArrangedSubview(buttons)
        themePopup.target = self
        themePopup.action = #selector(themeChanged)
        logView.drawsBackground = true
        logView.backgroundColor = .textBackgroundColor
    }

    @objc private func themeChanged() {
        let theme = LogTheme(rawValue: themePopup.selectedItem?.identifier?.rawValue ?? "") ?? .system
        apply(theme)
        onTheme(theme)
    }

    /// The log's own appearance; its colours are the system's adaptive ones.
    func apply(_ theme: LogTheme) {
        if let i = themePopup.itemArray.firstIndex(where: { $0.identifier?.rawValue == theme.rawValue }) {
            themePopup.selectItem(at: i)
        }
        switch theme {
        case .system: scroll.appearance = nil
        case .light: scroll.appearance = NSAppearance(named: .aqua)
        case .dark: scroll.appearance = NSAppearance(named: .darkAqua)
        }
        logView.needsDisplay = true
    }

    static let kindKey = NSAttributedString.Key("MugVPNLogKind")

    /// A log line with its marks coloured (LogHighlighter decides what is what).
    func coloured(_ line: String) -> NSAttributedString {
        let font = logView.font ?? .monospacedSystemFont(ofSize: 11, weight: .regular)
        let out = NSMutableAttributedString(string: line + "\n", attributes: [.font: font, .foregroundColor: NSColor.textColor])
        for span in LogHighlighter.spans(line) {
            let color: NSColor
            switch span.kind {
            case .timestamp: color = .secondaryLabelColor
            case .error: color = .systemRed
            case .warning: color = .systemOrange
            case .success: color = .systemGreen
            case .address: color = .systemBlue
            case .keyword: color = .systemPurple
            }
            var attrs: [NSAttributedString.Key: Any] = [.foregroundColor: color, StatusView.kindKey: span.kind.rawValue]
            if span.kind == .error || span.kind == .success {
                attrs[.font] = NSFont.monospacedSystemFont(ofSize: font.pointSize, weight: .semibold)
            }
            out.addAttributes(attrs, range: NSRange(span.range, in: line))
        }
        return out
    }

    @objc private func connect() { onConnect() }
    @objc private func disconnect() { onDisconnect() }
    @objc private func reconnect() { onReconnect() }
    @objc private func hide() { onHide() }

    /// - log: nil keeps what the window shows (the last connection's lines).
    /// - total: lines the connection ever logged (`log` keeps the last ones).
    func update(state s: String, ip a: String, bytesIn i: UInt64, bytesOut o: UInt64, log: [String]?, total: Int = 0,
                active: Bool) {
        connectButton.isEnabled = !active
        disconnectButton.isEnabled = active
        reconnectButton.isEnabled = active
        state.stringValue = s
        ip.stringValue = a
        bytesIn.stringValue = StatusView.size(i)
        bytesOut.stringValue = StatusView.size(o)
        guard let log else { return }
        let total = max(total, log.count)
        // A new connection, or more new lines than are kept: show what is kept, afresh.
        if total < shownLines || total - shownLines > log.count {
            logView.string = ""
            shownLines = total - log.count
            viewLines = 0
        }
        if total > shownLines {
            let chunk = NSMutableAttributedString()
            log[(log.count - (total - shownLines))...].forEach { chunk.append(coloured($0)) }
            logView.textStorage?.append(chunk)
            viewLines += total - shownLines
            shownLines = total
            trimShown()
            logView.scrollToEndOfDocument(nil)
        }
    }

    /// Bytes as B, KB, MB, GB with one decimal.
    static func size(_ n: UInt64) -> String {
        let units = ["B", "KB", "MB", "GB", "TB"]
        var v = Double(n)
        var u = 0
        while v >= 1024 && u < units.count - 1 { v /= 1024; u += 1 }
        return u == 0 ? "\(n) B" : String(format: "%.1f %@", v, units[u])
    }
}

enum SettingsWindow {
    static func show(store: SettingsStore, services: Services, changed: @escaping () -> Void) {
        if let w = WindowRegistry.shared.of(kind: "settings").first { return w.present() }
        let s = store.settings
        func lock(_ v: NSControl, _ k: SettingKey) -> NSControl {
            if store.isLocked(k) {
                v.isEnabled = false
                v.toolTip = L("Set by your administrator")
                v.setAccessibilityLabel(L("%@ (set by your administrator)", v.accessibilityLabel() ?? ""))
            }
            return v
        }
        let proxy = Form.popup("proxy_source", [("system", L("Use the system proxy settings")), ("manual", L("Manual")),
                                                ("none", L("No proxy"))],
                               selected: { switch s.proxy { case .system: return "system"; case .manual: return "manual"; case .none: return "none" } }())
        var host = "", port = ""
        if case .manual(let h, let p) = s.proxy { host = h; port = String(p) }
        let hostField = Form.field("proxy_host", value: host, placeholder: "proxy.example.com")
        let portField = Form.field("proxy_port", value: port, placeholder: "8080")
        let proxyActions = ProxyToggle(hostField: hostField, portField: portField)
        proxy.target = proxyActions
        proxy.action = #selector(ProxyToggle.changed(_:))
        proxyActions.changed(proxy)
        let anyLocked = SettingKey.allCases.contains(where: store.isLocked)
        let note = Form.label(L("Some settings are set by your administrator."), id: "locked_note")
        note.isHidden = !anyLocked
        let err = Form.label("", id: "error_text")
        err.textColor = .systemRed
        err.isHidden = true

        let views: [NSView] = [
            Form.label(L("General"), bold: true),
            Form.checkbox("launch_at_login", L("Open MugVPN at login"), on: services.launchAtLogin),
            lock(Form.checkbox("silent_connection", L("Connect silently (no status window)"), on: s.silentConnection), .silentConnection),
            Form.row(L("Notify when connected:"), lock(Form.popup("show_balloon", [("0", L("Never")), ("1", L("The first time")), ("2", L("Every time"))],
                                                               selected: String(s.showBalloon.rawValue)), .showBalloon)),
            Form.row(L("Profile menu:"), lock(Form.popup("menu_view", [("auto", L("Automatic")), ("flat", L("Flat")), ("nested", L("By folder"))],
                                                      selected: "\(s.menuView)"), .menuView)),
            lock(Form.checkbox("disable_popups", L("Ignore messages from servers"), on: s.disablePopupMessages), .disablePopupMessages),
            lock(Form.checkbox("disconnect_on_sleep", L("Disconnect when the Mac sleeps, connect again on wake"), on: s.disconnectOnSleep), .disconnectOnSleep),
            lock(Form.checkbox("allow_lan_when_blocked", L("While MugVPN blocks the Internet, allow the local network"), on: s.allowLANWhenBlocked), .allowLANWhenBlocked),
            Form.row(L("Mute repeated messages (h):"), lock(Form.field("popup_mute", value: String(s.popupMuteHours)), .popupMuteHours)),
            Form.label(L("Proxy"), bold: true),
            Form.row(L("Proxy:"), lock(proxy, .proxy)),
            Form.row(L("Address:"), lock(hostField, .proxy)), Form.row(L("Port:"), lock(portField, .proxy)),
            Form.label(L("Advanced"), bold: true),
            lock(Form.checkbox("log_append", L("Append to the log instead of replacing it"), on: s.logAppend), .logAppend),
            Form.row(L("Pre-connect script (s):"), lock(Form.field("preconnect_timeout", value: String(s.preconnectScriptTimeout)), .preconnectScriptTimeout)),
            Form.row(L("Connect script (s):"), lock(Form.field("connect_timeout", value: String(s.connectScriptTimeout)), .connectScriptTimeout)),
            Form.row(L("Disconnect script (s):"), lock(Form.field("disconnect_timeout", value: String(s.disconnectScriptTimeout)), .disconnectScriptTimeout)),
            Form.row(L("Persistent connections:"), lock(Form.popup("persistent", [("auto", L("Attach automatically")), ("manual", L("List only")), ("disable", L("Off"))],
                                                                selected: s.persistentConnections.rawValue), .persistentConnections)),
            note, err,
        ]
        let w = showForm(kind: "settings", profile: "", title: L("MugVPN Settings"), views: views, ok: { w in
            func popup(_ id: String) -> String { (w.control(id) as? NSPopUpButton)?.selectedItem?.identifier?.rawValue ?? "" }
            func int(_ id: String) -> Int? { Int(text(w, id).trimmingCharacters(in: .whitespaces)) }
            do {
                try store.update { n in
                    n.silentConnection = checked(w, "silent_connection")
                    n.showBalloon = BalloonMode(rawValue: Int(popup("show_balloon")) ?? 1) ?? .initial
                    n.menuView = ["flat": .flat, "nested": .nested][popup("menu_view")] ?? .auto
                    n.disablePopupMessages = checked(w, "disable_popups")
                    n.disconnectOnSleep = checked(w, "disconnect_on_sleep")
                    n.allowLANWhenBlocked = checked(w, "allow_lan_when_blocked")
                    n.popupMuteHours = int("popup_mute") ?? -1
                    switch popup("proxy_source") {
                    case "manual": n.proxy = .manual(host: text(w, "proxy_host"), port: int("proxy_port") ?? 0)
                    case "none": n.proxy = .none
                    default: n.proxy = .system
                    }
                    n.logAppend = checked(w, "log_append")
                    n.preconnectScriptTimeout = int("preconnect_timeout") ?? -1
                    n.connectScriptTimeout = int("connect_timeout") ?? -1
                    n.disconnectScriptTimeout = int("disconnect_timeout") ?? -1
                    n.persistentConnections = PersistentConnections(rawValue: popup("persistent")) ?? .auto
                }
                let login = checked(w, "launch_at_login")
                if login != services.launchAtLogin { try services.setLaunchAtLogin(login) }
            } catch {
                let e = w.control("error_text") as? NSTextField
                e?.stringValue = "\(error)"
                e?.isHidden = false
                return false
            }
            changed()
            return true
        })
        objc_setAssociatedObject(w, "proxy", proxyActions, .OBJC_ASSOCIATION_RETAIN)
    }
}

final class ProxyToggle: NSObject {
    let hostField: NSTextField
    let portField: NSTextField
    init(hostField: NSTextField, portField: NSTextField) {
        self.hostField = hostField
        self.portField = portField
    }
    @objc func changed(_ sender: NSPopUpButton) {
        let manual = sender.selectedItem?.identifier?.rawValue == "manual" && sender.isEnabled
        hostField.isEnabled = manual
        portField.isEnabled = manual
    }
}

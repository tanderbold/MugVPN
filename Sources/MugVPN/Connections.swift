import AppKit
import MugVPNAppCore
import MugVPNCore

/// The list of connections in the Connections window.
final class ListView: NSTableView {
    var titles: [String] = []
    /// Select a row the way a click does (the window may ask about unsaved changes first).
    func pick(_ row: Int) {
        guard delegate?.tableView?(self, shouldSelectRow: row) ?? true else { return }
        selectRowIndexes([row], byExtendingSelection: false)
        delegate?.tableViewSelectionDidChange?(Notification(name: NSTableView.selectionDidChangeNotification, object: self))
    }
}

/// A multi-line text control with an id (servers, config) in a scroll view.
final class TextBox {
    let scroll = NSScrollView()
    let text = NSTextView()
    init(_ id: String, label: String, mono: Bool = false, width: CGFloat, height: CGFloat) {
        text.setAccessibilityIdentifier(id)
        text.setAccessibilityLabel(label)
        text.isRichText = false
        text.isAutomaticQuoteSubstitutionEnabled = false
        text.isAutomaticDashSubstitutionEnabled = false
        text.isAutomaticTextReplacementEnabled = false
        text.isAutomaticSpellingCorrectionEnabled = false
        text.font = mono ? .monospacedSystemFont(ofSize: NSFont.smallSystemFontSize, weight: .regular) : .systemFont(ofSize: NSFont.systemFontSize)
        text.isVerticallyResizable = true
        text.autoresizingMask = [.width]
        text.textContainer?.widthTracksTextView = true
        scroll.documentView = text
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.widthAnchor.constraint(equalToConstant: width).isActive = true
        scroll.heightAnchor.constraint(equalToConstant: height).isActive = true
    }
    var string: String {
        get { text.string }
        set { text.string = newValue }
    }
    var editable: Bool {
        get { text.isEditable }
        set {
            text.isEditable = newValue
            text.textColor = newValue ? .textColor : .secondaryLabelColor
        }
    }
}

/// Settings of each connection, adding and removing connections: one window,
/// a list on the left and the selected connection's settings on the right.
final class ConnectionsWindow: NSObject, NSTableViewDataSource, NSTableViewDelegate, NSTabViewDelegate,
                               NSTextViewDelegate, NSTextFieldDelegate, NSSearchFieldDelegate {
    enum Row: Equatable {
        case profile(Profile)
        case new
        var profile: Profile? { if case .profile(let p) = self { return p }; return nil }
    }

    private unowned let app: AppController
    private var rows: [Row] = []
    private let search = NSSearchField()
    private var current = -1
    let window: AppWindow

    // What is saved for the selected row.
    private var savedText = ""
    private var savedDraft: ConnectionDraft?
    private var savedOptions = ProfileOptions()
    private var savedName = ""
    /// The config text the form is applied to (the Advanced tab's text once edited there).
    private var baseText = ""
    private var baseDraft = ConnectionDraft()
    private var materials: [String: ConnectionDraft.Material?] = [:]

    // Controls.
    private let list = ListView()
    private let add = NSPopUpButton(frame: .zero, pullsDown: true)
    private let remove: NSButton
    private let tabs = NSTabView()
    private let name = Form.field("name")
    private let servers = TextBox("servers", label: L("Servers"), width: 300, height: 70)
    private let allTraffic = Form.checkbox("all_traffic", L("Send all traffic through the VPN"))
    private let note = Form.label("", id: "note_text")
    private let askPassword = Form.checkbox("ask_password", L("Ask for a username and password"))
    private let savedText_ = Form.label("", id: "saved_text", wraps: false)
    private let clearPasswords: NSButton
    private let otherNote = Form.label(L("This profile also signs in another way (PKCS#12 or a certificate fingerprint): see Advanced."), id: "other_text")
    private var materialLabels: [String: NSTextField] = [:]
    private var materialButtons: [NSButton] = []
    private let autoConnect = Form.checkbox("auto_connect", L("Connect when MugVPN starts"))
    private let splitDNS = Form.checkbox("split_dns", L("Split DNS by Domain: only the server's domains go to its DNS"))
    private let silent = Form.popup("silent", [("global", L("As in Settings")), ("on", L("Connect silently")),
                                               ("off", L("Show the status window"))], selected: "global")
    private let sleep = Form.popup("sleep", [("global", L("As in Settings")), ("disconnect", L("Disconnect")),
                                             ("stay", L("Stay connected"))], selected: "global")
    private let proxy = Form.popup("proxy", [("global", L("As in Settings")), ("none", L("No proxy")),
                                             ("manual", L("Manual"))], selected: "global")
    private let killSwitch = Form.checkbox("kill_switch", L("If it drops unexpectedly, block the Internet until I reconnect"))
    private let blockIPv6 = Form.checkbox("block_ipv6", L("Block IPv6 outside the VPN"))
    private let dnsOnly = Form.checkbox("dns_only", L("Send DNS only through the VPN"))
    private let dnsMode = Form.popup("dns_mode", [("server", L("From the VPN server")), ("own", L("These DNS servers")),
                                                  ("none", L("Don't change DNS"))], selected: "server")
    private let dnsServers = Form.field("dns_servers", placeholder: "10.0.0.53, 10.0.0.54")
    private let dnsDomains = Form.field("dns_domains", placeholder: L("empty: all names"))
    private let proxyHost = Form.field("proxy_host", placeholder: "proxy.example.com")
    private let proxyPort = Form.field("proxy_port", placeholder: "8080")
    private let config = TextBox("config", label: L("Configuration"), mono: true, width: 470, height: 250)
    private let path = Form.label("", id: "path_text", wraps: false)
    private let readOnly = Form.label(L("Installed by an administrator: only its MugVPN options can be changed here."), id: "readonly_text")
    private let error = Form.label("", id: "error_text")
    private let revert: NSButton
    private let save: NSButton

    static let materialKinds: [(id: String, title: String, directive: String)] = [
        ("ca", L("CA certificate:"), "ca"), ("cert", L("Certificate:"), "cert"), ("key", L("Private key:"), "key"),
        ("tls_auth", L("TLS auth key:"), "tls-auth"), ("tls_crypt", L("TLS crypt key:"), "tls-crypt"),
    ]

    init(app: AppController) {
        self.app = app
        let target = Target()
        remove = Form.button("remove", "−", target: target, action: #selector(Target.fire(_:)))
        clearPasswords = Form.button("clear_passwords", L("Clear Saved Passwords"), target: target, action: #selector(Target.fire(_:)))
        revert = Form.button("revert", L("Revert"), target: target, action: #selector(Target.fire(_:)))
        save = Form.button("save", L("Save"), key: "\r", target: target, action: #selector(Target.fire(_:)))
        window = AppWindow(kind: "connections", profile: "", title: L("Connections"), content: NSView())
        super.init()
        target.handler = { [weak self] id in self?.pressed(id) }
        objc_setAssociatedObject(window, "target", target, .OBJC_ASSOCIATION_RETAIN)
        build(target)
    }

    /// Buttons call back with their id.
    final class Target: NSObject {
        var handler: (String) -> Void = { _ in }
        @objc func fire(_ sender: NSView) { handler(sender.accessibilityIdentifier()) }
    }

    // MARK: - layout

    /// Wide enough for "None", "Embedded" (in this language) and a usual file
    /// name such as client.crt; longer names are shortened, the tooltip has them whole.
    private var valueWidth: CGFloat {
        let widest = [L("None"), L("Embedded"), "client-01.crt"].map { NSTextField(labelWithString: $0).fittingSize.width }.max() ?? 0
        return ceil(widest) + 4
    }

    private func build(_ target: Target) {
        // The list with + and − under it.
        let column = NSTableColumn(identifier: .init("name"))
        column.width = 180
        list.addTableColumn(column)
        list.headerView = nil
        list.dataSource = self
        list.delegate = self
        list.setAccessibilityIdentifier("list")
        list.setAccessibilityLabel(L("Connections"))
        let listScroll = NSScrollView()
        listScroll.documentView = list
        listScroll.hasVerticalScroller = true
        listScroll.borderType = .bezelBorder
        listScroll.translatesAutoresizingMaskIntoConstraints = false
        listScroll.widthAnchor.constraint(equalToConstant: 200).isActive = true
        listScroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 380).isActive = true

        add.addItem(withTitle: "+")
        for (id, title) in [("new", L("New Connection…")), ("file", L("Import File…")), ("url", L("Import from URL…")),
                            ("as", L("Import from Access Server…")), ("duplicate", L("Duplicate"))] {
            add.addItem(withTitle: title)
            add.lastItem?.identifier = .init(id)
        }
        add.setAccessibilityIdentifier("add")
        add.setAccessibilityLabel(L("Add a connection"))
        add.target = self
        add.action = #selector(addChosen)
        remove.setAccessibilityLabel(L("Delete the connection"))
        let listButtons = NSStackView(views: [add, remove])
        listButtons.orientation = .horizontal
        search.placeholderString = L("Search")
        search.setAccessibilityIdentifier("search")
        search.setAccessibilityLabel(L("Search"))
        search.delegate = self
        let left = NSStackView(views: [search, listScroll, listButtons])
        left.orientation = .vertical
        left.alignment = .leading

        // The tabs.
        servers.text.delegate = self
        config.text.delegate = self
        name.delegate = self
        proxyHost.delegate = self
        proxyPort.delegate = self
        for c in [allTraffic, askPassword, autoConnect, splitDNS, killSwitch, blockIPv6, dnsOnly] {
            c.target = self
            c.action = #selector(changed)
        }
        dnsServers.delegate = self
        dnsDomains.delegate = self
        for p in [silent, sleep, proxy, dnsMode] {
            p.target = self
            p.action = #selector(changed)
        }
        let serversHint = Form.label(L("One server per line: host port udp|tcp"), wraps: false)
        serversHint.textColor = .secondaryLabelColor
        let general = page([
            Form.row(L("Name:"), name),
            Form.row(L("Servers:"), servers.scroll),
            Form.row("", serversHint),
            Form.row("", allTraffic),
            note,
        ])

        var materialRows: [NSView] = []
        for m in ConnectionsWindow.materialKinds {
            let value = Form.label(L("None"), id: "\(m.id)_value", wraps: false)
            // A fixed width, so the buttons beside it stay put whatever it says.
            value.lineBreakMode = .byTruncatingMiddle
            value.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
            value.widthAnchor.constraint(equalToConstant: valueWidth).isActive = true
            value.setAccessibilityLabel(m.title.trimmingCharacters(in: CharacterSet(charactersIn: ":： ")))
            materialLabels[m.id] = value
            let choose = Form.button("\(m.id)_choose", L("Choose"), target: target, action: #selector(Target.fire(_:)))
            let drop = Form.button("\(m.id)_remove", L("Remove"), target: target, action: #selector(Target.fire(_:)))
            materialButtons += [choose, drop]
            let line = NSStackView(views: [value, choose, drop])
            line.orientation = .horizontal
            materialRows.append(Form.row(m.title, line))
        }
        let savedLine = NSStackView(views: [savedText_, clearPasswords])
        savedLine.orientation = .horizontal
        let auth = page([Form.row("", askPassword), Form.row(L("Saved:"), savedLine)] + materialRows + [otherNote])

        let dnsHint = NSTextField(wrappingLabelWithString: L("Several connections can each serve their own domains; only one at a time can take all names."))
        dnsHint.preferredMaxLayoutWidth = 320
        dnsHint.widthAnchor.constraint(equalToConstant: 320).isActive = true
        dnsHint.setContentCompressionResistancePriority(.required, for: .vertical)
        dnsHint.textColor = .secondaryLabelColor
        let options = page([
            Form.row("", autoConnect),
            Form.row(L("DNS:"), dnsMode),
            Form.row("", splitDNS),
            Form.row(L("DNS servers:"), dnsServers),
            Form.row(L("Only for domains:"), dnsDomains),
            Form.row("", dnsHint),
            Form.row(L("When all traffic goes through it:"), killSwitch),
            Form.row("", blockIPv6),
            Form.row("", dnsOnly),
            Form.row(L("While connecting:"), silent),
            Form.row(L("When the Mac sleeps:"), sleep),
            Form.row(L("Proxy:"), proxy),
            Form.row(L("Address:"), proxyHost),
            Form.row(L("Port:"), proxyPort),
        ])

        let reveal = Form.button("reveal", L("Show in Finder"), target: target, action: #selector(Target.fire(_:)))
        let external = Form.button("edit_external", L("Open in Text Editor"), target: target, action: #selector(Target.fire(_:)))
        let fileLine = NSStackView(views: [path, reveal, external])
        fileLine.orientation = .horizontal
        path.lineBreakMode = .byTruncatingMiddle
        path.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        let advanced = page([config.scroll, fileLine])

        for (id, title, view) in [("general", L("General"), general), ("auth", L("Authentication"), auth),
                                  ("options", L("Options"), options), ("advanced", L("Advanced"), advanced)] {
            let item = NSTabViewItem(identifier: id)
            item.label = title
            item.view = view
            tabs.addTabViewItem(item)
        }
        tabs.delegate = self
        tabs.setAccessibilityIdentifier("tabs")
        tabs.setAccessibilityLabel(L("Connection settings"))
        tabs.translatesAutoresizingMaskIntoConstraints = false
        // As wide as the widest tab needs in this language (a tab's view is not in the window until shown).
        let widest = [general, auth, options, advanced].map { $0.fittingSize.width }.max() ?? 0
        tabs.widthAnchor.constraint(greaterThanOrEqualToConstant: max(560, ceil(widest) + 24)).isActive = true
        let tallest = [general, auth, options, advanced].map { $0.fittingSize.height }.max() ?? 0
        tabs.heightAnchor.constraint(greaterThanOrEqualToConstant: ceil(tallest) + 40).isActive = true
        tabs.heightAnchor.constraint(greaterThanOrEqualToConstant: 340).isActive = true

        error.textColor = .systemRed
        readOnly.textColor = .secondaryLabelColor
        let right = NSStackView(views: [tabs, readOnly, error, Form.buttons([revert, save])])
        right.orientation = .vertical
        right.alignment = .leading
        let all = NSStackView(views: [left, right])
        all.orientation = .horizontal
        all.alignment = .top
        all.spacing = 16
        Form.alignRows(in: all)

        // The whole window takes profiles dropped on it: the user's own act, imported without asking.
        let container = DropView()
        container.onDrop = { [weak app] paths in
            let take = ProfileStore.importable(paths)
            if !take.isEmpty { DispatchQueue.main.async { app?.importFiles(take) } }
            return take
        }
        window.contentView = container
        // The list has the keyboard first (arrows pick a connection); the search field when clicked.
        window.initialFirstResponder = list
        all.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(all)
        NSLayoutConstraint.activate([
            all.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 20),
            all.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -20),
            all.topAnchor.constraint(equalTo: container.topAnchor, constant: 20),
            all.bottomAnchor.constraint(equalTo: container.bottomAnchor, constant: -20),
        ])
        window.setContentSize(container.fittingSize)
        window.delegate = closer
        closer.shouldClose = { [weak self] in self?.mayLeave { self?.window.close() } ?? true }
    }

    private let closer = Closer()
    final class Closer: NSObject, NSWindowDelegate {
        var shouldClose: () -> Bool = { true }
        func windowShouldClose(_ sender: NSWindow) -> Bool { shouldClose() }
    }

    private func page(_ views: [NSView]) -> NSView {
        let s = NSStackView(views: views)
        // Each tab lines up its own rows: a tab's view is not in the window until shown.
        Form.alignRows(in: s)
        s.orientation = .vertical
        s.alignment = .leading
        s.spacing = 10
        s.edgeInsets = NSEdgeInsets(top: 16, left: 16, bottom: 16, right: 16)
        let holder = NSView()
        s.translatesAutoresizingMaskIntoConstraints = false
        holder.addSubview(s)
        NSLayoutConstraint.activate([
            s.leadingAnchor.constraint(equalTo: holder.leadingAnchor),
            s.topAnchor.constraint(equalTo: holder.topAnchor),
            s.trailingAnchor.constraint(lessThanOrEqualTo: holder.trailingAnchor),
            s.bottomAnchor.constraint(lessThanOrEqualTo: holder.bottomAnchor),
        ])
        return holder
    }

    // MARK: - showing

    /// - tab: the tab to show ("options" for a warning about the connection's DNS).
    func show(select profile: Profile?, tab: String? = nil) {
        // Asked for by name: a search that hides it is cleared (else another one's options would show).
        if let profile, !ProfileStore.matching(app.manager.profiles, search.stringValue).contains(where: { $0.id == profile.id }) {
            search.stringValue = ""
        }
        reloadRows()
        if let profile, let i = rows.firstIndex(where: { $0.profile?.id == profile.id }) {
            if i != current {
                list.pick(i)
            } else {
                // reloadData clears NSTableView's selection even though our model selection is unchanged.
                list.selectRowIndexes([i], byExtendingSelection: false)
            }
        } else if current < 0, !rows.isEmpty {
            list.pick(0)
        }
        if let tab { tabs.selectTabViewItem(withIdentifier: tab) }
        window.present()
    }

    /// The profiles on disk changed (import, rescan): keep the selection.
    func profilesChanged() {
        let selected = current >= 0 && current < rows.count ? rows[current] : nil
        let before = rows
        reloadRows()
        guard rows != before else {
            // The same rows: the selection (reloading drops it) stays where it was.
            if current >= 0, current < rows.count { list.selectRowIndexes([current], byExtendingSelection: false) }
            return
        }
        if let selected, let i = rows.firstIndex(where: { sameRow($0, selected) }) {
            current = i
            list.selectRowIndexes([i], byExtendingSelection: false)
        } else if !rows.isEmpty {
            current = -1
            list.pick(0)
        } else {
            current = -1
            fill()
        }
    }

    private func sameRow(_ a: Row, _ b: Row) -> Bool {
        switch (a, b) {
        case (.new, .new): return true
        case (.profile(let x), .profile(let y)): return x.id == y.id
        default: return false
        }
    }

    private func reloadRows() {
        let hasNew = rows.contains(.new)
        // The one being edited stays listed whatever the search: what was typed into it is not dropped.
        let found = Set(ProfileStore.matching(app.manager.profiles, search.stringValue).map(\.id))
        let keep = dirty ? selected?.profile?.id : nil
        rows = app.manager.profiles.filter { found.contains($0.id) || $0.id == keep }.map { .profile($0) } + (hasNew ? [.new] : [])
        list.titles = rows.map(title)
        list.reloadData()
    }

    private func title(_ r: Row) -> String {
        switch r {
        case .profile(let p): return p.displayName
        case .new: return L("New Connection")
        }
    }

    func numberOfRows(in tableView: NSTableView) -> Int { rows.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        let f = NSTextField(labelWithString: title(rows[row]))
        f.lineBreakMode = .byTruncatingTail
        f.setAccessibilityIdentifier("")
        return f
    }

    func tableView(_ tableView: NSTableView, shouldSelectRow row: Int) -> Bool {
        if row == current || !dirty { return true }
        _ = mayLeave { [weak self] in
            guard let self else { return }
            self.dropNewRow(except: row)
            self.current = -1
            self.list.pick(self.rows.indices.contains(row) ? row : 0)
        }
        return false
    }

    func tableViewSelectionDidChange(_ notification: Notification) {
        let row = list.selectedRow
        guard row != current else { return }
        current = row
        load()
    }

    /// Ask before unsaved changes are lost; `then` runs if the user agrees.
    /// Returns true when there is nothing to ask about.
    private func mayLeave(then: @escaping () -> Void) -> Bool {
        guard dirty else { return true }
        let shownName = current >= 0 && current < rows.count ? title(rows[current]) : ""
        showForm(kind: "confirm", profile: shownName, title: L("Connections"),
                 views: [Form.label(L("Discard the changes to %@?", shownName), id: "prompt_text")],
                 okTitle: L("Discard"), parent: window, ok: { _ in DispatchQueue.main.async(execute: then); return true })
        return false
    }

    private func dropNewRow(except keep: Int) {
        if let i = rows.firstIndex(of: .new), i != keep {
            rows.remove(at: i)
            list.titles = rows.map(title)
            list.reloadData()
        }
    }

    // MARK: - the selected connection

    private var selected: Row? { current >= 0 && current < rows.count ? rows[current] : nil }
    private var editable: Bool { selected.map { $0 == .new || $0.profile?.source == .user } ?? false }

    private func load() {
        error.isHidden = true
        switch selected {
        case .profile(let p)?:
            savedText = app.store.config(of: p) ?? ""
            savedDraft = try? ConnectionDraft(config: savedText)
            savedOptions = app.options.options(p.id)
            if p.source == .persistent {
                // The helper applies these at boot, from beside the profile: shown, not changed here.
                savedOptions = savedOptions.applying(app.persistentSettings(p))
            } else {
                // What an administrator requires counts as saved (no "unsaved changes" for it).
                if app.settingsStore.settings.requireKillSwitch { savedOptions.killSwitch = true }
                if app.settingsStore.settings.requireLeakProtection { savedOptions.blockIPv6 = true; savedOptions.dnsOnlyTunnel = true }
            }
            savedName = p.name
        case .new?:
            savedText = ConnectionDraft.template
            savedDraft = nil
            savedOptions = ProfileOptions()
            savedName = ""
        case nil:
            savedText = ""
            savedDraft = nil
            savedOptions = ProfileOptions()
            savedName = ""
        }
        setBase(savedText)
        fill()
    }

    private func setBase(_ text: String) {
        baseText = text
        baseDraft = (try? ConnectionDraft(config: text)) ?? ConnectionDraft()
        materials = [:]
        for m in ConnectionsWindow.materialKinds { materials[m.id] = material(baseDraft, m.id) }
    }

    private func material(_ d: ConnectionDraft, _ id: String) -> ConnectionDraft.Material? {
        switch id {
        case "ca": return d.ca
        case "cert": return d.cert
        case "key": return d.key
        case "tls_auth": return d.tlsAuth
        default: return d.tlsCrypt
        }
    }

    /// Put the base text, the saved options and the name into the controls.
    private func fill() {
        let d = baseDraft
        name.stringValue = savedName
        servers.string = ConnectionDraft.formatServers(d.servers)
        allTraffic.state = d.allTraffic ? .on : .off
        select(dnsMode, d.dns.mode.rawValue)
        dnsServers.stringValue = d.dns.servers.joined(separator: ", ")
        // Own servers: their domains are the profile's; the server's DNS: the domains are MugVPN's option.
        dnsDomains.stringValue = (d.dns.mode == .server ? savedOptions.serverDNSDomains : d.dns.domains).joined(separator: ", ")
        askPassword.state = d.askPassword ? .on : .off
        config.string = baseText
        let o = savedOptions
        autoConnect.state = o.autoConnect ? .on : .off
        splitDNS.state = o.splitDNS ? .on : .off
        killSwitch.state = o.killSwitch ? .on : .off
        blockIPv6.state = o.blockIPv6 ? .on : .off
        dnsOnly.state = o.dnsOnlyTunnel ? .on : .off
        select(silent, o.silent.map { $0 ? "on" : "off" } ?? "global")
        select(sleep, o.disconnectOnSleep.map { $0 ? "disconnect" : "stay" } ?? "global")
        switch o.proxy {
        case .global: select(proxy, "global"); proxyHost.stringValue = ""; proxyPort.stringValue = ""
        case .none: select(proxy, "none"); proxyHost.stringValue = ""; proxyPort.stringValue = ""
        case .manual(let h, let p): select(proxy, "manual"); proxyHost.stringValue = h; proxyPort.stringValue = String(p)
        }
        let p = selected?.profile
        path.stringValue = p?.path ?? ""
        refresh()
    }

    private func select(_ p: NSPopUpButton, _ value: String) {
        if let i = p.itemArray.firstIndex(where: { $0.identifier?.rawValue == value }) { p.selectItem(at: i) }
    }

    private func popup(_ p: NSPopUpButton) -> String { p.selectedItem?.identifier?.rawValue ?? "" }

    /// The form as a draft (without the servers when they do not parse).
    private func formDraft() -> (ConnectionDraft, [String]) {
        var d = baseDraft
        var problems: [String] = []
        if d.serversEditable {
            let (s, errs) = ConnectionDraft.parseServers(servers.string)
            d.servers = s
            problems += errs
        }
        d.allTraffic = allTraffic.state == .on
        d.askPassword = askPassword.state == .on
        let mode = DNSChoice.Mode(rawValue: popup(dnsMode)) ?? .server
        // Fields of another mode are not written (and stay in the form until saved).
        d.dns = mode == .own ? DNSChoice(mode: .own, servers: ConnectionDraft.parseList(dnsServers.stringValue),
                                         domains: ConnectionDraft.parseList(dnsDomains.stringValue))
                             : DNSChoice(mode: mode)
        if d.dns == DNSChoice(mode: .server), baseDraft.dns.mode == .server { d.dns = baseDraft.dns }
        d.ca = materials["ca"] ?? nil
        d.cert = materials["cert"] ?? nil
        d.key = materials["key"] ?? nil
        d.tlsAuth = materials["tls_auth"] ?? nil
        d.tlsCrypt = materials["tls_crypt"] ?? nil
        return (d, problems)
    }

    private var onAdvanced: Bool { tabs.selectedTabViewItem?.identifier as? String == "advanced" }

    /// The config text as the window would save it.
    private func composed() throws -> String {
        if onAdvanced { return config.string }
        return try formDraft().0.apply(to: baseText)
    }

    private func formOptions() -> ProfileOptions {
        var o = ProfileOptions()
        o.autoConnect = autoConnect.state == .on
        o.splitDNS = splitDNS.state == .on
        o.killSwitch = killSwitch.state == .on
        o.blockIPv6 = blockIPv6.state == .on
        o.dnsOnlyTunnel = dnsOnly.state == .on
        o.serverDNSDomains = popup(dnsMode) == "server" ? ConnectionDraft.parseList(dnsDomains.stringValue) : []
        switch popup(silent) { case "on": o.silent = true; case "off": o.silent = false; default: o.silent = nil }
        switch popup(sleep) {
        case "disconnect": o.disconnectOnSleep = true
        case "stay": o.disconnectOnSleep = false
        default: o.disconnectOnSleep = nil
        }
        switch popup(proxy) {
        case "none": o.proxy = .none
        case "manual":
            o.proxy = .manual(host: proxyHost.stringValue.trimmingCharacters(in: .whitespaces),
                              port: Int(proxyPort.stringValue.trimmingCharacters(in: .whitespaces)) ?? 0)
        default: o.proxy = .global
        }
        return o
    }

    private var dirty: Bool {
        guard let s = selected else { return false }
        if s == .new { return true }
        if formOptions() != savedOptions { return true }
        guard editable else { return false }
        if name.stringValue != savedName { return true }
        return ((try? composed()) ?? "") != savedText
    }

    /// Enable what can be used now.
    private func refresh() {
        let has = selected != nil
        let canEdit = editable
        let isUser = selected?.profile?.source == .user
        for v in [name, allTraffic, askPassword] as [NSControl] { v.isEnabled = canEdit }
        servers.editable = canEdit && baseDraft.serversEditable
        config.editable = canEdit
        materialButtons.forEach { $0.isEnabled = canEdit }
        for m in ConnectionsWindow.materialKinds {
            let label = materialLabels[m.id]!
            switch materials[m.id] ?? nil {
            case nil: label.stringValue = L("None")
            case .inline?: label.stringValue = L("Embedded")
            case .file(let f)?: label.stringValue = (f as NSString).lastPathComponent
            }
            label.toolTip = label.stringValue
            materialButtons.first { $0.accessibilityIdentifier() == "\(m.id)_remove" }?.isEnabled =
                canEdit && (materials[m.id] ?? nil) != nil
        }
        otherNote.isHidden = !baseDraft.otherCredentials
        let persistent = selected?.profile?.source == .persistent
        for v in [autoConnect, silent, sleep, proxy, killSwitch, blockIPv6, dnsOnly] as [NSControl] { v.isEnabled = has }
        // Required by an administrator: shown on, not to be turned off.
        let g = app.settingsStore.settings
        if g.requireKillSwitch, !persistent { killSwitch.state = .on; killSwitch.isEnabled = false }
        if g.requireLeakProtection, !persistent {
            blockIPv6.state = .on; blockIPv6.isEnabled = false
            dnsOnly.state = .on; dnsOnly.isEnabled = false
        }
        // Persistent: the helper starts it at boot with the settings beside it.
        if persistent { for v in [sleep, proxy, killSwitch, blockIPv6, dnsOnly] as [NSControl] { v.isEnabled = false } }
        dnsMode.isEnabled = canEdit
        let ownDNS = popup(dnsMode) == "own"
        dnsServers.isEnabled = canEdit && ownDNS
        // Domains: with own servers (the profile's), or for the server's DNS (an option, any profile).
        dnsDomains.isEnabled = (canEdit && ownDNS) || (has && !persistent && popup(dnsMode) == "server")
        // Empty means what the mode does without it: own servers for all names; the server's DNS as it
        // sends it (and Split DNS by Domain decides).
        dnsDomains.placeholderString = ownDNS ? L("empty: all names") : L("empty: as the server sends it")
        splitDNS.isEnabled = has && !persistent && popup(dnsMode) == "server"
        let manual = popup(proxy) == "manual" && has
        proxyHost.isEnabled = manual
        proxyPort.isEnabled = manual
        remove.isEnabled = has && (selected == .new || isUser)
        readOnly.isHidden = !has || canEdit
        if let p = selected?.profile, persistent {
            readOnly.stringValue = L("Started by the system at boot: its connection settings are set by an administrator in %@.",
                                     ((p.path as NSString).deletingLastPathComponent as NSString).appendingPathComponent(p.name + ".json"))
        } else {
            readOnly.stringValue = L("Installed by an administrator: only its MugVPN options can be changed here.")
        }
        add.itemArray.first { $0.identifier?.rawValue == "duplicate" }?.isEnabled = selected?.profile != nil
        if let p = selected?.profile {
            let user = app.secrets.get(p.secretsKey, .username)
            savedText_.stringValue = user.map { L("username %@", $0) } ?? (app.secrets.hasSaved(p.secretsKey) ? L("passwords") : L("nothing"))
            clearPasswords.isEnabled = app.secrets.hasSaved(p.secretsKey)
            note.stringValue = app.manager.active[p.id] != nil ? L("Connected: changes apply the next time it connects.") : ""
        } else {
            savedText_.stringValue = L("nothing")
            clearPasswords.isEnabled = false
            note.stringValue = ""
        }
        note.isHidden = note.stringValue.isEmpty
        let d = dirty
        save.isEnabled = d
        revert.isEnabled = d && selected != .new
    }

    @objc private func changed() { refresh() }
    func controlTextDidChange(_ obj: Notification) {
        if (obj.object as? NSSearchField) === search { return profilesChanged() }
        refresh()
    }
    func textDidChange(_ notification: Notification) { refresh() }

    private func showError(_ text: String) {
        error.stringValue = text
        error.isHidden = text.isEmpty
    }

    // MARK: - tabs

    func tabView(_ tabView: NSTabView, shouldSelect item: NSTabViewItem?) -> Bool {
        let to = item?.identifier as? String
        if onAdvanced, to != "advanced" {
            // Back to the form: it shows what the text now says.
            do {
                _ = try ConnectionDraft(config: config.string)
            } catch {
                showError(L("The configuration cannot be read: %@", "\(error)"))
                return false
            }
            setBase(config.string)
            let keepName = name.stringValue
            let opts = formOptions()
            fillForm(keepName: keepName, options: opts)
        } else if !onAdvanced, to == "advanced" {
            do {
                config.string = try formDraft().0.apply(to: baseText)
            } catch {
                showError("\(error)")
                return false
            }
        }
        showError("")
        return true
    }

    func tabView(_ tabView: NSTabView, didSelect tabViewItem: NSTabViewItem?) {
        Form.alignRows(in: tabViewItem?.view ?? NSView())
        refresh()
    }

    /// fill() for the config part only: the name and options typed stay.
    private func fillForm(keepName: String, options: ProfileOptions) {
        let saved = (savedName, savedOptions)
        savedName = keepName
        savedOptions = options
        fill()
        (savedName, savedOptions) = saved
        refresh()
    }

    // MARK: - actions

    private func pressed(_ id: String) {
        switch id {
        case "save": saveSelected()
        case "revert": load()
        case "remove": removeSelected()
        case "clear_passwords":
            if let p = selected?.profile { app.secrets.removeAll(p.secretsKey) }
            refresh()
        case "reveal":
            if let p = selected?.profile { app.services.reveal(p.path) }
        case "edit_external":
            if let p = selected?.profile { app.services.open(URL(fileURLWithPath: p.path).absoluteString) }
        default:
            if id.hasSuffix("_choose") { chooseMaterial(String(id.dropLast("_choose".count))) }
            if id.hasSuffix("_remove") {
                materials[String(id.dropLast("_remove".count))] = .some(nil)
                refresh()
            }
        }
    }

    private func chooseMaterial(_ id: String) {
        guard let file = app.services.chooseFile() else { return }
        guard let a = try? FileManager.default.attributesOfItem(atPath: file), a[.type] as? FileAttributeType == .typeRegular,
              (a[.size] as? NSNumber)?.intValue ?? .max <= 1 << 20,
              let data = FileManager.default.contents(atPath: file), let text = ConnectionDraft.materialText(data) else {
            return showError(L("%@ is not a text file (PEM).", (file as NSString).lastPathComponent))
        }
        materials[id] = .some(.inline(text))
        showError("")
        refresh()
    }

    @objc private func addChosen() {
        let choice = add.selectedItem?.identifier?.rawValue ?? ""
        add.selectItem(at: 0)
        let go = { [weak self] in
            guard let self else { return }
            switch choice {
            case "new":
                self.dropNewRow(except: -1)
                self.rows.append(.new)
                self.list.titles = self.rows.map(self.title)
                self.list.reloadData()
                self.current = -1
                self.list.pick(self.rows.count - 1)
                self.tabs.selectTabViewItem(withIdentifier: "general")
                self.window.makeFirstResponder(self.name)
            case "file":
                let before = Set(self.app.manager.profiles.map(\.id))
                self.app.importFile()
                self.selectFirstNew(since: before)
            case "url": self.app.importURL()
            case "as": self.app.importAccessServer()
            case "duplicate":
                guard let p = self.selected?.profile else { return }
                // Through the same consent as any import: files outside the folder are asked about.
                self.app.importOne(p.path, downloaded: false, allowOutside: false, as: L("%@ copy", p.name)) { [weak self] copy in
                    self?.selectPath(copy.path)
                }
            default: break
            }
        }
        if ["new", "duplicate"].contains(choice) {
            if mayLeave(then: go) { go() }
        } else {
            go()
        }
    }

    private func selectFirstNew(since before: Set<String>) {
        app.rescan()
        if let p = app.manager.profiles.first(where: { !before.contains($0.id) }) { selectPath(p.path) }
    }

    private func selectPath(_ path: String) {
        reloadRows()
        if let i = rows.firstIndex(where: { $0.profile?.path == path }) {
            current = -1
            list.pick(i)
        }
    }

    private func saveSelected() {
        guard let s = selected else { return }
        let opts = formOptions()
        if case .manual(let h, let p) = opts.proxy, !ConnectionController.isHost(h) || !(1...65535).contains(p) {
            return showError(L("Enter the proxy's address and a port from 1 to 65535."))
        }
        if let bad = opts.serverDNSDomains.first(where: { !ConnectionDraft.isDomain($0) }) {
            return showError(L("%@ is not a domain name.", bad))
        }
        if opts.serverDNSDomains.count > ProfileBundle.maxDNSDomains {
            return showError(L("At most %d domains for the server's DNS.", ProfileBundle.maxDNSDomains))
        }
        do {
            switch s {
            case .new:
                let text = try composed()
                if let problems = try problems(text, since: nil) { return showError(problems) }
                let p = try app.store.create(name: name.stringValue, config: text, secrets: app.secrets, options: app.options)
                app.options.set(p.id, opts)
                rows.removeAll { $0 == .new }
                app.rescan()
                selectPath(p.path)
            case .profile(var p):
                if editable {
                    let text = try composed()
                    let newName = name.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
                    if newName != p.name, app.manager.active[p.id] != nil {
                        return showError(L("Disconnect %@ before renaming it.", p.displayName))
                    }
                    if text != savedText {
                        if let problems = try problems(text, since: savedDraft) { return showError(problems) }
                        try app.store.save(p, config: text)
                    }
                    app.options.set(p.id, opts)
                    if newName != p.name {
                        p = try app.store.rename(p, to: newName, active: Set(app.manager.active.keys),
                                                 secrets: app.secrets, options: app.options)
                    }
                } else {
                    app.options.set(p.id, opts)
                }
                app.rescan()
                selectPath(p.path)
                if current >= 0 { load() }
            }
            showError("")
        } catch {
            showError("\(error)")
            refresh()
        }
    }

    /// What the form would break, or nil when the text is fine to save.
    private func problems(_ text: String, since was: ConnectionDraft?) throws -> String? {
        var found: [String] = []
        if !onAdvanced { found += formDraft().1 }
        found += try ConnectionDraft(config: text).problems(since: was)
        return found.isEmpty ? nil : found.map(localizedProblem).joined(separator: "\n")
    }

    /// ConnectionDraft's problems in the user's language.
    private func localizedProblem(_ p: String) -> String {
        if let colon = p.range(of: ": ") {
            let head = p[..<colon.lowerBound].split(separator: " ")
            if head.count == 2, ["server", "line"].contains(head[0]), Int(head[1]) != nil {
                let rest = localizedProblem(String(p[colon.upperBound...]))
                return head[0] == "server" ? L("Server %@: %@", String(head[1]), rest) : L("Line %@: %@", String(head[1]), rest)
            }
        }
        switch p {
        case "add at least one server": return L("Add at least one server.")
        case "enter at least one DNS server": return L("Enter at least one DNS server.")
        case "at most 8 DNS servers": return L("Enter at most 8 DNS servers.")
        case "enter a host name or address": return L("enter a host name or address")
        case "the port must be 1–65535": return L("the port must be 1–65535")
        case "write a server as: host port udp|tcp": return L("write a server as: host port udp|tcp")
        case "choose the server's CA certificate": return L("Choose the server's CA certificate.")
        case "the client certificate needs its private key": return L("The client certificate needs its private key.")
        case "the private key needs its client certificate": return L("The private key needs its client certificate.")
        case "sign in needs a client certificate or a password":
            return L("Signing in needs a client certificate or a password.")
        default:
            if p.hasPrefix("DNS server "), p.hasSuffix(" is not an IP address") {
                return L("DNS server %@ is not an IP address.", String(p.dropFirst(11).dropLast(21)))
            }
            if p.hasSuffix(" is not a domain name") { return L("%@ is not a domain name.", String(p.dropLast(21))) }
            return p
        }
    }

    private func removeSelected() {
        guard let s = selected else { return }
        if s == .new {
            rows.removeAll { $0 == .new }
            reloadRows()
            current = -1
            if !rows.isEmpty { list.pick(0) } else { fill() }
            return
        }
        guard let p = s.profile else { return }
        showForm(kind: "confirm", profile: p.displayName, title: L("Connections"),
                 views: [Form.label(L("Delete %@? Its files, settings and saved passwords are removed.", p.displayName), id: "prompt_text")],
                 okTitle: L("Delete"), parent: window, ok: { [weak self] _ in
            guard let self else { return true }
            do {
                try self.app.store.delete(p, active: Set(self.app.manager.active.keys), secrets: self.app.secrets,
                                          options: self.app.options)
                self.current = -1
                self.app.rescan()
                self.reloadRows()
                if !self.rows.isEmpty { self.list.pick(0) } else { self.load() }
            } catch {
                self.showError("\(error)")
            }
            return true
        })
    }
}

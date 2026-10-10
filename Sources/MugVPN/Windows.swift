import AppKit
import MugVPNAppCore

/// A localized string: the key is the English text (Resources/<lang>.lproj/Localizable.strings).
func L(_ key: String, _ args: CVarArg...) -> String {
    let s = Bundle.main.localizedString(forKey: key, value: key, table: nil)
    return args.isEmpty ? s : String(format: s, arguments: args)
}

/// Messages from MugVPNAppCore that people see, in their language.
/// Anything else (policy details, system errors) stays as it came.
func localizedCore(_ s: String) -> String {
    switch s {
    case "Authentication failed": return L("Authentication failed")
    case "Wrong password": return L("Wrong password")
    case "the connection ended unexpectedly": return L("the connection ended unexpectedly")
    case "cannot reach openvpn's management socket": return L("cannot reach openvpn's management socket")
    case "the persistent connection is not running": return L("the persistent connection is not running")
    case "the pre-connect script failed": return L("the pre-connect script failed")
    case ConnectionManager.helperTooOldForDNSDomains: return L("the running helper is older and would ignore the domains for the server's DNS: connect again once it has updated")
    default: return s
    }
}

func windowTitle(_ profile: String) -> String { "MugVPN — " + profile }

/// Every MugVPN window: what it is and which profile it belongs to. The E2E
/// socket finds windows and their controls through this.
/// A window's content that takes files dropped on it.
final class DropView: NSView {
    /// The paths dropped; returns those it takes.
    var onDrop: ([String]) -> [String] = { _ in [] }

    override init(frame: NSRect) {
        super.init(frame: frame)
        registerForDraggedTypes([.fileURL])
    }
    required init?(coder: NSCoder) { fatalError() }

    private func paths(_ info: NSDraggingInfo) -> [String] {
        (info.draggingPasteboard.readObjects(forClasses: [NSURL.self], options: [.urlReadingFileURLsOnly: true]) as? [URL] ?? [])
            .map(\.path)
    }
    override func draggingEntered(_ sender: NSDraggingInfo) -> NSDragOperation {
        ProfileStore.importable(paths(sender)).isEmpty ? [] : .copy
    }
    override func performDragOperation(_ sender: NSDraggingInfo) -> Bool { !onDrop(paths(sender)).isEmpty }
}

final class AppWindow: NSWindow {
    /// Windows that ask something and wait for the answer.
    static let dialogKinds: Set<String> = ["confirm", "error", "message", "warning", "credentials", "secret", "challenge", "string",
                                           "pkcs11", "uninstall", "import_as", "import_url", "helper_setup"]
    /// Questions a connection waits on (it looks stuck while one is hidden): kept above MugVPN's other windows.
    static let waitingKinds: Set<String> = ["credentials", "secret", "challenge", "string", "pkcs11"]
    let kind: String
    let profile: String
    /// Placed on the screen once: shown again, it stays where the user put it.
    private var placed = false

    private func keepDialogsAbove() {
        guard !AppWindow.waitingKinds.contains(kind) else { return }
        for d in WindowRegistry.shared.windows where d !== self && d.isVisible && d.sheetParent == nil
            && AppWindow.waitingKinds.contains(d.kind) {
            d.order(.above, relativeTo: windowNumber)
        }
    }

    /// An ordinary window coming forward (Connections opened from the menu) keeps a connection's standing
    /// question (a password prompt) above it: within MugVPN, not over other apps.
    override func becomeKey() {
        super.becomeKey()
        // AppKit can finish ordering the new key window after this callback. Repeat on the next
        // main-loop turn so a click on an existing ordinary window cannot cover a standing prompt.
        DispatchQueue.main.async { [weak self] in self?.keepDialogsAbove() }
    }
    var onClose: () -> Void = {}
    private static var counter = 0
    let windowID: String

    init(kind: String, profile: String, title: String, content: NSView) {
        self.kind = kind
        self.profile = profile
        AppWindow.counter += 1
        windowID = "w\(AppWindow.counter)"
        super.init(contentRect: NSRect(x: 0, y: 0, width: 420, height: 200),
                   styleMask: [.titled, .closable], backing: .buffered, defer: false)
        self.title = title
        isReleasedWhenClosed = false
        // The form sits in a container with 20 pt margins on every side; a stack
        // view's own trailing inset is not kept when its rows align leading.
        let container = NSView()
        content.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(content)
        NSLayoutConstraint.activate([
            content.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 20),
            content.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -20),
            content.topAnchor.constraint(equalTo: container.topAnchor, constant: 20),
            content.bottomAnchor.constraint(equalTo: container.bottomAnchor, constant: -20),
        ])
        contentView = container
        setContentSize(container.fittingSize)
        WindowRegistry.shared.add(self)
    }

    func present() {
        fitToContent()
        if !placed {
            center()
            placed = true
        }
        NSApp.activate(ignoringOtherApps: true)
        makeKeyAndOrderFront(nil)
        // This covers windows opened through our own menu without waiting for another event-loop turn.
        keepDialogsAbove()
    }

    /// Size to the laid-out content: translations and filled-in values make it grow (a sheet too).
    func fitToContent() {
        if let content = contentView {
            // fittingSize can come out a little short (a row of buttons with a minimum width ignores the
            // right margin), so grow to what the laid-out controls really cover, plus the margin.
            var size = content.fittingSize
            for _ in 0..<3 {
                setContentSize(size)
                content.layoutSubtreeIfNeeded()
                func extent(_ v: NSView) -> CGFloat {
                    v.subviews.reduce(v === content ? 0 : v.convert(v.bounds, to: content).maxX) { max($0, extent($1)) }
                }
                let needed = ceil(extent(content)) + 20
                guard needed > size.width else { break }
                size.width = needed
            }
            contentMinSize = size
        }
    }

    override func close() {
        WindowRegistry.shared.remove(self)
        super.close()
        onClose()
        onClose = {}
    }

    /// A control by its id (= accessibility identifier).
    func control(_ id: String) -> NSView? {
        func find(_ v: NSView) -> NSView? {
            if v.accessibilityIdentifier() == id { return v }
            for s in v.subviews { if let f = find(s) { return f } }
            return nil
        }
        return contentView.flatMap(find)
    }
}

final class WindowRegistry {
    static let shared = WindowRegistry()
    private(set) var windows: [AppWindow] = []
    func add(_ w: AppWindow) { windows.append(w) }
    func remove(_ w: AppWindow) { windows.removeAll { $0 === w } }
    func find(_ id: String) -> AppWindow? { windows.first { $0.windowID == id } }
    func of(kind: String, profile: String? = nil) -> [AppWindow] {
        windows.filter { $0.kind == kind && (profile == nil || $0.profile == profile) }
    }
}

/// A row of a form: a right-aligned label and its control.
final class RowStack: NSStackView {
    weak var label: NSTextField?
}

/// A check box (so tools can tell it from a push button).
final class Checkbox: NSButton {}

// MARK: - form building

enum Form {
    /// The width of wrapping text in forms; windows are at least this plus margins.
    static let textWidth: CGFloat = 400

    static func label(_ text: String, id: String? = nil, bold: Bool = false, wraps: Bool = true) -> NSTextField {
        let l = wraps ? NSTextField(wrappingLabelWithString: text) : NSTextField(labelWithString: text)
        if bold { l.font = .boldSystemFont(ofSize: NSFont.systemFontSize) }
        if let id { l.setAccessibilityIdentifier(id) }
        if wraps {
            // A fixed width, so the text's height is measured for the width it really gets.
            l.preferredMaxLayoutWidth = Form.textWidth
            l.widthAnchor.constraint(equalToConstant: Form.textWidth).isActive = true
            l.setContentCompressionResistancePriority(.required, for: .vertical)
        } else {
            l.setContentCompressionResistancePriority(.required, for: .horizontal)
        }
        return l
    }

    static func field(_ id: String, value: String = "", secure: Bool = false, placeholder: String = "") -> NSTextField {
        let f: NSTextField = secure ? NSSecureTextField() : NSTextField()
        f.stringValue = value
        f.placeholderString = placeholder
        f.setAccessibilityIdentifier(id)
        if !placeholder.isEmpty { f.setAccessibilityLabel(placeholder) } // a row's label wins (Form.row)
        f.widthAnchor.constraint(greaterThanOrEqualToConstant: 240).isActive = true
        return f
    }

    static func checkbox(_ id: String, _ title: String, on: Bool = false) -> NSButton {
        let b = Checkbox(checkboxWithTitle: title, target: nil, action: nil)
        b.setContentCompressionResistancePriority(.required, for: .horizontal)
        b.state = on ? .on : .off
        b.setAccessibilityIdentifier(id)
        return b
    }

    /// A popup whose items carry `values` as their identifiers.
    static func popup(_ id: String, _ items: [(value: String, title: String)], selected: String) -> NSPopUpButton {
        let p = NSPopUpButton()
        for i in items {
            p.addItem(withTitle: i.title)
            p.lastItem?.identifier = NSUserInterfaceItemIdentifier(i.value)
        }
        if let idx = items.firstIndex(where: { $0.value == selected }) { p.selectItem(at: idx) }
        p.setAccessibilityIdentifier(id)
        p.setContentCompressionResistancePriority(.required, for: .horizontal)
        return p
    }

    static func button(_ id: String, _ title: String, key: String = "", target: AnyObject?, action: Selector) -> NSButton {
        let b = NSButton(title: title, target: target, action: action)
        b.keyEquivalent = key
        b.setAccessibilityIdentifier(id)
        b.setContentCompressionResistancePriority(.required, for: .horizontal)
        return b
    }

    static func row(_ label: String, _ view: NSView) -> NSStackView {
        // VoiceOver reads the row's label for the control beside it.
        let spoken = label.trimmingCharacters(in: CharacterSet(charactersIn: ":： "))
        if !spoken.isEmpty { view.setAccessibilityLabel(spoken) }
        let l = NSTextField(labelWithString: label)
        l.alignment = .right
        l.setContentCompressionResistancePriority(.required, for: .horizontal)
        let s = RowStack(views: [l, view])
        s.label = l
        s.orientation = .horizontal
        s.alignment = .firstBaseline
        return s
    }

    /// Give every row label in `root` the width of the longest one, so the
    /// controls line up whatever the language.
    static func alignRows(in root: NSView) {
        func rows(_ v: NSView) -> [RowStack] { ((v as? RowStack).map { [$0] } ?? []) + v.subviews.flatMap(rows) }
        let all = rows(root)
        let width = max(130, all.compactMap { $0.label?.fittingSize.width }.max() ?? 0)
        for r in all { r.label?.widthAnchor.constraint(equalToConstant: ceil(width)).isActive = true }
    }

    static func column(_ views: [NSView], spacing: CGFloat = 10) -> NSStackView {
        let s = NSStackView(views: views)
        s.orientation = .vertical
        s.alignment = .leading
        s.spacing = spacing
        s.edgeInsets = NSEdgeInsets(top: 0, left: 0, bottom: 0, right: 0) // margins: AppWindow's container
        alignRows(in: s)
        return s
    }

    static func buttons(_ bs: [NSButton]) -> NSStackView {
        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let s = NSStackView(views: [spacer] + bs)
        s.orientation = .horizontal
        s.widthAnchor.constraint(greaterThanOrEqualToConstant: Form.textWidth).isActive = true
        return s
    }
}

/// Target for a window's OK/Cancel buttons and its close box.
final class FormActions: NSObject, NSWindowDelegate {
    var ok: () -> Void = {}
    var cancel: () -> Void = {}
    @objc func okPressed(_ sender: Any?) { ok() }
    @objc func cancelPressed(_ sender: Any?) { cancel() }
    func windowShouldClose(_ sender: NSWindow) -> Bool { cancel(); return false }
}

/// Builds and shows a modal-ish form; `ok` returns false to keep it open.
@discardableResult
/// - parent: the window the question is about: shown as its sheet (it cannot go behind it, and the
///   parent waits while the rest of the app and other apps stay usable).
func showForm(kind: String, profile: String, title: String, views: [NSView], okTitle: String = L("OK"),
              cancelTitle: String? = L("Cancel"), parent: NSWindow? = nil, ok: @escaping (AppWindow) -> Bool,
              cancel: @escaping () -> Void = {}) -> AppWindow {
    let actions = FormActions()
    var bs: [NSButton] = []
    if let cancelTitle { bs.append(Form.button("cancel", cancelTitle, key: "\u{1b}", target: actions, action: #selector(FormActions.cancelPressed))) }
    bs.append(Form.button("ok", okTitle, key: "\r", target: actions, action: #selector(FormActions.okPressed)))
    let content = Form.column(views + [Form.buttons(bs)])
    let w = AppWindow(kind: kind, profile: profile, title: title, content: content)
    w.delegate = actions
    objc_setAssociatedObject(w, "actions", actions, .OBJC_ASSOCIATION_RETAIN)
    var finished = false
    func dismiss(_ w: AppWindow) {
        w.sheetParent?.endSheet(w)
        w.close()
    }
    actions.ok = { [weak w] in
        guard let w, !finished else { return }
        if ok(w) { finished = true; dismiss(w) }
    }
    actions.cancel = { [weak w] in
        guard let w, !finished else { return }
        finished = true
        dismiss(w)
        cancel()
    }
    if let parent, parent.isVisible {
        w.fitToContent()
        parent.beginSheet(w)
    } else {
        w.present()
    }
    return w
}

func text(_ w: AppWindow, _ id: String) -> String { (w.control(id) as? NSTextField)?.stringValue ?? "" }
func checked(_ w: AppWindow, _ id: String) -> Bool { (w.control(id) as? NSButton)?.state == .on }

// MARK: - what openvpn asks

/// The windows behind ConnectionUI for one profile.
final class PromptUI: ConnectionUI {
    let profile: Profile
    let canSave: () -> Bool
    let services: Services

    init(profile: Profile, canSave: @escaping () -> Bool, services: Services) {
        self.profile = profile
        self.canSave = canSave
        self.services = services
    }

    private var name: String { profile.displayName }

    func askCredentials(type: String, username: String?, challenge: StaticChallenge?, error: String?,
                        reply: @escaping (CredentialsAnswer?) -> Void) {
        let isProxy = type == "HTTP Proxy"
        let err = Form.label(error.map(localizedCore) ?? "", id: "error_text")
        err.textColor = .systemRed
        err.isHidden = error == nil
        let prompt = Form.label(challenge?.text ?? "", id: "prompt_text")
        prompt.isHidden = challenge == nil
        let response = Form.field("response", secure: !(challenge?.echo ?? false), placeholder: L("Response"))
        response.isHidden = challenge == nil
        let save = Form.checkbox("save", L("Save password"))
        save.isEnabled = canSave()
        var views: [NSView] = [Form.label(isProxy ? L("The proxy for %@ needs a username and password.", name)
                                                  : L("Connecting to %@.", name), bold: true), err,
                               Form.row(L("Username:"), Form.field("username", value: username ?? "")),
                               Form.row(L("Password:"), Form.field("password", secure: true))]
        views += [prompt, Form.row("", response), save]
        let w = showForm(kind: "credentials", profile: name, title: windowTitle(name), views: views, ok: { w in
            reply(CredentialsAnswer(username: text(w, "username"), password: text(w, "password"),
                                    response: challenge == nil ? nil : text(w, "response"), save: checked(w, "save")))
            return true
        }, cancel: { reply(nil) })
        w.makeFirstResponder(w.control((username ?? "").isEmpty ? "username" : "password"))
    }

    func askSecret(type: String, error: String?, reply: @escaping (SecretAnswer?) -> Void) {
        let err = Form.label(error.map(localizedCore) ?? "", id: "error_text")
        err.textColor = .systemRed
        err.isHidden = error == nil
        let save = Form.checkbox("save", L("Save password"))
        save.isEnabled = canSave()
        let w = showForm(kind: "secret", profile: name, title: windowTitle(name),
                         views: [Form.label("\(name): the private key needs its password.", bold: true), err,
                                 Form.row(L("Password:"), Form.field("password", secure: true)), save], ok: { w in
            reply(SecretAnswer(secret: text(w, "password"), save: checked(w, "save")))
            return true
        }, cancel: { reply(nil) })
        w.makeFirstResponder(w.control("password"))
    }

    func askChallenge(text prompt: String, echo: Bool, reply: @escaping (String?) -> Void) {
        let w = showForm(kind: "challenge", profile: name, title: windowTitle(name),
                         views: [Form.label(prompt, id: "prompt_text", bold: true),
                                 Form.field("response", secure: !echo, placeholder: L("Response"))], ok: { w in
            reply(text(w, "response"))
            return true
        }, cancel: { reply(nil) })
        w.makeFirstResponder(w.control("response"))
    }

    func askConfirmation(message: String, reply: @escaping (Bool) -> Void) {
        showForm(kind: "confirm", profile: name, title: windowTitle(name),
                 views: [Form.label(message, id: "prompt_text")], ok: { _ in reply(true); return true },
                 cancel: { reply(false) })
    }

    func askString(message: String, reply: @escaping (String?) -> Void) {
        showForm(kind: "string", profile: name, title: windowTitle(name),
                 views: [Form.label(message, id: "prompt_text"), Form.field("response", placeholder: L("Response"))], ok: { w in
            reply(text(w, "response"))
            return true
        }, cancel: { reply(nil) })
    }

    func choosePKCS11(_ entries: [PKCS11Entry], reply: @escaping (String?) -> Void) {
        let items = entries.map { (value: String($0.index), title: certificateTitle($0)) }
        showForm(kind: "pkcs11", profile: name, title: windowTitle(name),
                 views: [Form.label(L("Choose the certificate for %@:", name), bold: true),
                         {
                             let p = Form.popup("certificates", items, selected: items.first?.value ?? "")
                             p.setAccessibilityLabel(L("Certificate"))
                             return p
                         }()], ok: { w in
            let sel = (w.control("certificates") as? NSPopUpButton)?.selectedItem?.identifier?.rawValue
            reply(entries.first { String($0.index) == sel }?.id)
            return true
        }, cancel: { reply(nil) })
    }

    func openURL(_ url: String) { services.open(url) }

    func showMessage(title: String, text: String) {
        services.showMessage(profile: name, title: title, text: text)
    }

    func notify(title: String, text: String) { services.notify(title: title, text: text) }

    private func certificateTitle(_ e: PKCS11Entry) -> String {
        if let d = Data(base64Encoded: e.certificate), let cert = SecCertificateCreateWithData(nil, d as CFData),
           let summary = SecCertificateCopySubjectSummary(cert) as String? {
            return summary
        }
        return e.id
    }
}

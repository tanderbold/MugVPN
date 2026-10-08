import Foundation

/// Where settings live: UserDefaults for the user's choices, managed
/// preferences (MDM, /Library/Managed Preferences) for forced ones.
public protocol SettingsBackend: AnyObject {
    func value(_ key: String) -> Any?
    func set(_ key: String, _ value: Any?)
    /// Set by an administrator: wins and cannot be changed in the app.
    func isForced(_ key: String) -> Bool
}

public enum BalloonMode: Int, Equatable, Sendable { case never = 0, initial = 1, always = 2 }
public enum PersistentConnections: String, Equatable, Sendable { case auto, manual, disable }
/// The status window's log colours: follow the system, or always light or dark.
public enum LogTheme: String, Equatable, Sendable { case system, light, dark }

/// The settings of the General, Proxy and Advanced sections. The keys are
/// also the names administrators use in managed preferences.
public struct Settings: Equatable, Sendable {
    public var silentConnection = false
    public var showBalloon = BalloonMode.initial
    public var logAppend = false
    public var menuView = MenuMode.auto
    public var popupMuteHours = 24
    public var disablePopupMessages = false
    public var preconnectScriptTimeout = 10
    public var connectScriptTimeout = 30
    public var disconnectScriptTimeout = 10
    public var configExt = "ovpn"
    public var proxy = ProxySetting.system
    public var persistentConnections = PersistentConnections.auto
    public var disableSavePasswords = false
    /// Off by default: tunnels stay up over sleep and reconnect on wake.
    public var disconnectOnSleep = false
    public var logTheme = LogTheme.system
    /// While MugVPN blocks traffic (kill switch), the local network stays reachable.
    public var allowLANWhenBlocked = false
    /// Administrators (managed preferences): every connection uses its kill switch.
    public var requireKillSwitch = false
    /// Administrators: every connection blocks IPv6 and DNS outside the VPN while it carries all traffic.
    public var requireLeakProtection = false

    public init() {}

    public var connectionSettings: ConnectionSettings {
        ConnectionSettings(proxy: proxy, savePasswordsAllowed: !disableSavePasswords,
                           ignoreServerMessages: disablePopupMessages, muteHours: popupMuteHours)
    }
}

public enum SettingKey: String, CaseIterable, Sendable {
    case silentConnection = "silent_connection"
    case showBalloon = "show_balloon"
    case logAppend = "log_append"
    case menuView = "config_menu_view"
    case popupMuteHours = "popup_mute_interval"
    case disablePopupMessages = "disable_popup_messages"
    case preconnectScriptTimeout = "preconnectscript_timeout"
    case connectScriptTimeout = "connectscript_timeout"
    case disconnectScriptTimeout = "disconnectscript_timeout"
    case configExt = "config_ext"
    case proxy = "proxy"
    case persistentConnections = "persistent_connections"
    case disableSavePasswords = "disable_save_passwords"
    case disconnectOnSleep = "disconnect_on_sleep"
    case logTheme = "log_theme"
    case allowLANWhenBlocked = "allow_lan_when_blocked"
    case requireKillSwitch = "require_kill_switch"
    case requireLeakProtection = "require_leak_protection"
}

public struct SettingsError: Error, CustomStringConvertible {
    public var description: String
}

public final class SettingsStore {
    private let backend: SettingsBackend
    public private(set) var settings: Settings

    public init(backend: SettingsBackend) {
        self.backend = backend
        settings = SettingsStore.load(backend)
    }

    public func isLocked(_ key: SettingKey) -> Bool {
        key == .proxy ? ["proxy_source", "proxy_http_address", "proxy_http_port"].contains(where: backend.isForced)
                      : backend.isForced(key.rawValue)
    }

    /// Apply a change: refused as a whole if it touches a locked setting or
    /// leaves a value out of range.
    public func update(_ change: (inout Settings) -> Void) throws {
        var new = settings
        change(&new)
        for key in SettingKey.allCases where SettingsStore.differs(key, settings, new) && isLocked(key) {
            throw SettingsError(description: "\(key.rawValue) is set by your administrator")
        }
        try SettingsStore.validate(new)
        SettingsStore.store(new, old: settings, backend)
        settings = new
    }

    static func validate(_ s: Settings) throws {
        func check(_ ok: Bool, _ what: String) throws { if !ok { throw SettingsError(description: what) } }
        try check((1...99).contains(s.preconnectScriptTimeout), "the pre-connect script timeout must be 1 to 99 seconds")
        try check((0...99).contains(s.connectScriptTimeout), "the connect script timeout must be 0 to 99 seconds")
        try check((1...99).contains(s.disconnectScriptTimeout), "the disconnect script timeout must be 1 to 99 seconds")
        try check(s.popupMuteHours >= 0, "the mute interval cannot be negative")
        try check(!s.configExt.isEmpty && s.configExt.allSatisfy { $0.isLetter || $0.isNumber }, "bad config extension")
        if case .manual(let host, let port) = s.proxy {
            try check(!host.trimmingCharacters(in: .whitespaces).isEmpty, "the proxy needs an address")
            try check(ConnectionController.isHost(host), "the proxy address must be a host name or an IP address")
            try check((1...65535).contains(port), "the proxy port must be 1 to 65535")
        }
    }

    static func differs(_ k: SettingKey, _ a: Settings, _ b: Settings) -> Bool {
        switch k {
        case .silentConnection: return a.silentConnection != b.silentConnection
        case .showBalloon: return a.showBalloon != b.showBalloon
        case .logAppend: return a.logAppend != b.logAppend
        case .menuView: return a.menuView != b.menuView
        case .popupMuteHours: return a.popupMuteHours != b.popupMuteHours
        case .disablePopupMessages: return a.disablePopupMessages != b.disablePopupMessages
        case .preconnectScriptTimeout: return a.preconnectScriptTimeout != b.preconnectScriptTimeout
        case .connectScriptTimeout: return a.connectScriptTimeout != b.connectScriptTimeout
        case .disconnectScriptTimeout: return a.disconnectScriptTimeout != b.disconnectScriptTimeout
        case .configExt: return a.configExt != b.configExt
        case .proxy: return a.proxy != b.proxy
        case .persistentConnections: return a.persistentConnections != b.persistentConnections
        case .disableSavePasswords: return a.disableSavePasswords != b.disableSavePasswords
        case .disconnectOnSleep: return a.disconnectOnSleep != b.disconnectOnSleep
        case .logTheme: return a.logTheme != b.logTheme
        case .allowLANWhenBlocked: return a.allowLANWhenBlocked != b.allowLANWhenBlocked
        case .requireKillSwitch: return a.requireKillSwitch != b.requireKillSwitch
        case .requireLeakProtection: return a.requireLeakProtection != b.requireLeakProtection
        }
    }

    static func load(_ b: SettingsBackend) -> Settings {
        var s = Settings()
        func bool(_ k: SettingKey) -> Bool? {
            switch b.value(k.rawValue) {
            case let v as Bool: return v
            case let v as Int: return v != 0
            case let v as String: return v == "1" ? true : v == "0" ? false : nil
            default: return nil
            }
        }
        func int(_ k: String) -> Int? {
            switch b.value(k) {
            case let v as Int: return v
            case let v as String: return Int(v)
            default: return nil
            }
        }
        func str(_ k: String) -> String? { b.value(k) as? String }
        func valid(_ t: Settings) -> Bool { (try? validate(t)) != nil }
        func take<T>(_ path: WritableKeyPath<Settings, T>, _ v: T?) {
            guard let v else { return }
            var t = s
            t[keyPath: path] = v
            if valid(t) { s = t }
        }
        take(\.silentConnection, bool(.silentConnection))
        take(\.showBalloon, int(SettingKey.showBalloon.rawValue).flatMap(BalloonMode.init(rawValue:)))
        take(\.logAppend, bool(.logAppend))
        take(\.menuView, int(SettingKey.menuView.rawValue).flatMap { [0: MenuMode.auto, 1: .flat, 2: .nested][$0] })
        take(\.popupMuteHours, int(SettingKey.popupMuteHours.rawValue))
        take(\.disablePopupMessages, bool(.disablePopupMessages))
        take(\.preconnectScriptTimeout, int(SettingKey.preconnectScriptTimeout.rawValue))
        take(\.connectScriptTimeout, int(SettingKey.connectScriptTimeout.rawValue))
        take(\.disconnectScriptTimeout, int(SettingKey.disconnectScriptTimeout.rawValue))
        take(\.configExt, str(SettingKey.configExt.rawValue))
        take(\.persistentConnections, str(SettingKey.persistentConnections.rawValue).flatMap(PersistentConnections.init(rawValue:)))
        take(\.disableSavePasswords, bool(.disableSavePasswords))
        take(\.disconnectOnSleep, bool(.disconnectOnSleep))
        take(\.logTheme, str(SettingKey.logTheme.rawValue).flatMap(LogTheme.init(rawValue:)))
        take(\.allowLANWhenBlocked, bool(.allowLANWhenBlocked))
        take(\.requireKillSwitch, bool(.requireKillSwitch))
        take(\.requireLeakProtection, bool(.requireLeakProtection))
        switch str("proxy_source") {
        case "none": take(\.proxy, ProxySetting.none)
        case "manual":
            if let h = str("proxy_http_address"), let p = int("proxy_http_port") { take(\.proxy, .manual(host: h, port: p)) }
        default: break
        }
        return s
    }

    static func store(_ s: Settings, old: Settings, _ b: SettingsBackend) {
        for k in SettingKey.allCases where differs(k, old, s) {
            switch k {
            case .silentConnection: b.set(k.rawValue, s.silentConnection)
            case .showBalloon: b.set(k.rawValue, s.showBalloon.rawValue)
            case .logAppend: b.set(k.rawValue, s.logAppend)
            case .menuView: b.set(k.rawValue, [MenuMode.auto: 0, .flat: 1, .nested: 2][s.menuView]!)
            case .popupMuteHours: b.set(k.rawValue, s.popupMuteHours)
            case .disablePopupMessages: b.set(k.rawValue, s.disablePopupMessages)
            case .preconnectScriptTimeout: b.set(k.rawValue, s.preconnectScriptTimeout)
            case .connectScriptTimeout: b.set(k.rawValue, s.connectScriptTimeout)
            case .disconnectScriptTimeout: b.set(k.rawValue, s.disconnectScriptTimeout)
            case .configExt: b.set(k.rawValue, s.configExt)
            case .persistentConnections: b.set(k.rawValue, s.persistentConnections.rawValue)
            case .disableSavePasswords: b.set(k.rawValue, s.disableSavePasswords)
            case .disconnectOnSleep: b.set(k.rawValue, s.disconnectOnSleep)
            case .logTheme: b.set(k.rawValue, s.logTheme.rawValue)
            case .allowLANWhenBlocked: b.set(k.rawValue, s.allowLANWhenBlocked)
            case .requireKillSwitch: b.set(k.rawValue, s.requireKillSwitch)
            case .requireLeakProtection: b.set(k.rawValue, s.requireLeakProtection)
            case .proxy:
                switch s.proxy {
                case .system: b.set("proxy_source", "system")
                case .none: b.set("proxy_source", "none")
                case .manual(let h, let p):
                    b.set("proxy_source", "manual")
                    b.set("proxy_http_address", h)
                    b.set("proxy_http_port", p)
                }
            }
        }
    }
}

/// Saved secrets follow a profile's name.
public enum ProfileSecrets {
    public static func renamed(_ store: SecretStore, from old: String, to new: String) {
        for k in [SecretKey.username, .password, .keyPassword, .proxyUsername, .proxyPassword] {
            if let v = store.get(old, k) { store.set(new, k, v) }
        }
        store.removeAll(old)
    }

    public static func deleted(_ store: SecretStore, _ profile: String) {
        store.removeAll(profile)
    }
}

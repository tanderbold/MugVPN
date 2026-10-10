import Foundation
import MugVPNCore

/// A profile's own proxy choice.
public enum ProfileProxy: Codable, Equatable, Sendable {
    case global
    case none
    case manual(host: String, port: Int)
}

/// Settings of one connection; nil / .global means "as in the general settings".
public struct ProfileOptions: Codable, Equatable, Sendable {
    public var autoConnect = false
    public var splitDNS = false
    public var silent: Bool?
    public var proxy = ProfileProxy.global
    public var disconnectOnSleep: Bool?
    /// If the connection (taking all traffic) drops unexpectedly, block traffic outside the VPN.
    public var killSwitch = false
    /// While it takes all traffic: no IPv6 outside the VPN.
    public var blockIPv6 = true
    /// While it takes all traffic: no DNS outside the VPN.
    public var dnsOnlyTunnel = true
    /// The server's DNS only for these domains (empty: as the server says).
    public var serverDNSDomains: [String] = []
    public init() {}

    enum CodingKeys: String, CodingKey {
        case autoConnect, splitDNS, silent, proxy, disconnectOnSleep, killSwitch, blockIPv6, dnsOnlyTunnel, serverDNSDomains
    }

    /// A persistent profile: what the helper applies (its settings beside it in config-auto) in
    /// place of the options only the app could apply; the app's own (auto-connect, silent) stay.
    public func applying(_ s: PersistentSettings) -> ProfileOptions {
        var o = self
        o.splitDNS = s.splitDNS
        o.killSwitch = s.protection.killSwitch
        o.blockIPv6 = s.protection.blockIPv6
        o.dnsOnlyTunnel = s.protection.dnsOnlyTunnel
        o.proxy = .global
        o.disconnectOnSleep = false
        return o
    }

    /// Options saved by an older version read as the defaults for what they lack.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = ProfileOptions()
        autoConnect = try c.decodeIfPresent(Bool.self, forKey: .autoConnect) ?? d.autoConnect
        splitDNS = try c.decodeIfPresent(Bool.self, forKey: .splitDNS) ?? d.splitDNS
        silent = try c.decodeIfPresent(Bool.self, forKey: .silent)
        proxy = try c.decodeIfPresent(ProfileProxy.self, forKey: .proxy) ?? d.proxy
        disconnectOnSleep = try c.decodeIfPresent(Bool.self, forKey: .disconnectOnSleep)
        killSwitch = try c.decodeIfPresent(Bool.self, forKey: .killSwitch) ?? d.killSwitch
        blockIPv6 = try c.decodeIfPresent(Bool.self, forKey: .blockIPv6) ?? d.blockIPv6
        serverDNSDomains = try c.decodeIfPresent([String].self, forKey: .serverDNSDomains) ?? []
        dnsOnlyTunnel = try c.decodeIfPresent(Bool.self, forKey: .dnsOnlyTunnel) ?? d.dnsOnlyTunnel
    }
}

/// Per-profile settings, kept in the settings backend under `profile_options`.
public final class ProfileOptionsStore {
    private let backend: SettingsBackend
    private static let key = "profile_options"
    private var all: [String: ProfileOptions]

    public init(backend: SettingsBackend) {
        self.backend = backend
        if let data = backend.value(ProfileOptionsStore.key) as? Data,
           let decoded = try? JSONDecoder().decode([String: ProfileOptions].self, from: data) {
            all = decoded
        } else {
            all = [:]
        }
        // Before this store, "Split DNS by Domain" was a list of profile ids.
        if let old = backend.value("split_dns_profiles") as? [String] {
            for id in old { all[id, default: ProfileOptions()].splitDNS = true }
            backend.set("split_dns_profiles", nil)
            save()
        }
    }

    public func options(_ id: String) -> ProfileOptions { all[id] ?? ProfileOptions() }

    public func set(_ id: String, _ o: ProfileOptions) {
        all[id] = o == ProfileOptions() ? nil : o
        save()
    }

    public func move(from old: String, to new: String) {
        guard let o = all.removeValue(forKey: old) else { return }
        all[new] = o
        save()
    }

    public func remove(_ id: String) {
        all[id] = nil
        save()
    }

    private func save() {
        backend.set(ProfileOptionsStore.key, all.isEmpty ? nil : try? JSONEncoder().encode(all))
    }
}

/// The general settings with a profile's own choices on top.
public enum EffectiveSettings {
    public static func connection(_ g: Settings, _ o: ProfileOptions) -> ConnectionSettings {
        var c = g.connectionSettings
        switch o.proxy {
        case .global: break
        case .none: c.proxy = .none
        case .manual(let h, let p): c.proxy = .manual(host: h, port: p)
        }
        return c
    }

    public static func silent(_ g: Settings, _ o: ProfileOptions) -> Bool { o.silent ?? g.silentConnection }

    public static func protection(_ g: Settings, _ o: ProfileOptions) -> ProtectionOptions {
        ProtectionOptions(killSwitch: o.killSwitch || g.requireKillSwitch, blockIPv6: o.blockIPv6 || g.requireLeakProtection,
                          dnsOnlyTunnel: o.dnsOnlyTunnel || g.requireLeakProtection, allowLAN: g.allowLANWhenBlocked)
    }

    public static func disconnectOnSleep(_ g: Settings, _ o: ProfileOptions) -> Bool {
        o.disconnectOnSleep ?? g.disconnectOnSleep
    }
}

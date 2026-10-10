import Foundation
import MugVPNAppCore
import MugVPNCore

func registerProfileOptionsTests() {
    test("POPT-01", "defaults") {
        let o = ProfileOptionsStore(backend: FakeSettingsBackend()).options("/cfg/a.ovpn")
        expectEqual(o, ProfileOptions())
        expect(!o.autoConnect && !o.splitDNS && o.silent == nil && o.proxy == .global && o.disconnectOnSleep == nil)
    }
    test("POPT-02", "stored per profile; split_dns_profiles migrated") {
        let b = FakeSettingsBackend()
        b.values["split_dns_profiles"] = ["/cfg/b.ovpn"]
        let st = ProfileOptionsStore(backend: b)
        expect(st.options("/cfg/b.ovpn").splitDNS, "migrated")
        expect(b.values["split_dns_profiles"] == nil, "the old key is gone")
        var o = ProfileOptions()
        o.autoConnect = true
        o.proxy = .manual(host: "p.lan", port: 3128)
        o.silent = true
        st.set("/cfg/a.ovpn", o)
        let again = ProfileOptionsStore(backend: b)
        expectEqual(again.options("/cfg/a.ovpn"), o)
        expect(again.options("/cfg/b.ovpn").splitDNS)
        expectEqual(again.options("/cfg/c.ovpn"), ProfileOptions())
    }
    test("POPT-06", "protection options per connection; LAN while blocked is the general setting") {
        var o = ProfileOptions()
        expect(!o.killSwitch, "off unless asked")
        expect(o.blockIPv6 && o.dnsOnlyTunnel, "leak protection on by default for connections that take all traffic")
        o.killSwitch = true
        o.blockIPv6 = false
        let st = ProfileOptionsStore(backend: FakeSettingsBackend())
        st.set("/cfg/a.ovpn", o)
        expectEqual(st.options("/cfg/a.ovpn"), o)
        var g = Settings()
        g.allowLANWhenBlocked = true
        expectEqual(EffectiveSettings.protection(g, o), ProtectionOptions(killSwitch: true, blockIPv6: false, dnsOnlyTunnel: true, allowLAN: true))
        // Options saved before these existed read as the defaults.
        let b = FakeSettingsBackend()
        b.values["profile_options"] = try JSONSerialization.data(withJSONObject: ["/cfg/x.ovpn": ["autoConnect": true, "splitDNS": false, "proxy": ["global": [:]]]])
        expect(ProfileOptionsStore(backend: b).options("/cfg/x.ovpn").dnsOnlyTunnel)
    }
    test("POPT-07", "an administrator can require the protection") {
        var g = Settings()
        g.requireKillSwitch = true
        g.requireLeakProtection = true
        var o = ProfileOptions()
        o.killSwitch = false
        o.blockIPv6 = false
        o.dnsOnlyTunnel = false
        expectEqual(EffectiveSettings.protection(g, o), ProtectionOptions(killSwitch: true, blockIPv6: true, dnsOnlyTunnel: true, allowLAN: false))
        let b = FakeSettingsBackend()
        b.forced = ["require_kill_switch": true, "require_leak_protection": true]
        let st = SettingsStore(backend: b)
        expect(st.settings.requireKillSwitch && st.settings.requireLeakProtection && st.isLocked(.requireKillSwitch))
    }
    test("POPT-03", "effective settings") {
        var g = Settings()
        g.proxy = .manual(host: "global.lan", port: 8080)
        g.silentConnection = false
        g.disconnectOnSleep = false
        var o = ProfileOptions()
        expectEqual(EffectiveSettings.connection(g, o).proxy, .manual(host: "global.lan", port: 8080))
        o.proxy = .none
        expectEqual(EffectiveSettings.connection(g, o).proxy, ProxySetting.none)
        o.proxy = .manual(host: "own.lan", port: 3128)
        expectEqual(EffectiveSettings.connection(g, o).proxy, .manual(host: "own.lan", port: 3128))
        expect(!EffectiveSettings.silent(g, o))
        o.silent = true
        expect(EffectiveSettings.silent(g, o))
        o.disconnectOnSleep = true
        expect(EffectiveSettings.disconnectOnSleep(g, o))
        g.disableSavePasswords = true
        expect(!EffectiveSettings.connection(g, o).savePasswordsAllowed, "only the administrator decides that")
    }
    test("POPT-04", "rename a user profile") {
        let fs = MemFS()
        fs.add("\(userDir)/work/work.ovpn", "client\nremote w 1194\nca ca.crt\n")
        fs.add("\(userDir)/work/ca.crt", "CA")
        fs.add("\(userDir)/loose.ovpn", "client\nremote l 1194\n")
        fs.add("\(userDir)/team/one.ovpn", "client\nremote o 1194\n")
        let store = ProfileStore(fs: fs, userDir: userDir, systemDir: systemDir)
        func p(_ name: String) -> Profile { store.scan().first { $0.name == name }! }
        let renamed = try store.rename(p("work"), to: "Office", active: [])
        expectEqual(renamed.path, "\(userDir)/Office/Office.ovpn")
        expectEqual(fs.text("\(userDir)/Office/ca.crt"), "CA", "its files go with it")
        expect(!fs.exists("\(userDir)/work"))
        expectEqual(try store.rename(p("loose"), to: "Loose 2", active: []).path, "\(userDir)/Loose 2.ovpn")
        expectEqual(try store.rename(p("one"), to: "uno", active: []).path, "\(userDir)/team/uno.ovpn")
        expectThrows("taken", matching: "already") { _ = try store.rename(p("uno"), to: "Office", active: []) }
        expectThrows("empty") { _ = try store.rename(p("uno"), to: "  ", active: []) }
        expectThrows("slash") { _ = try store.rename(p("uno"), to: "a/b", active: []) }
        expectThrows("connected", matching: "connected") { _ = try store.rename(p("uno"), to: "x", active: [p("uno").id]) }
        fs.add("\(systemDir)/corp.ovpn", "client\nremote c 1194\n")
        expectThrows("system", matching: "administrator") { _ = try store.rename(p("corp"), to: "mine", active: []) }
        // Saved passwords and options follow the new name.
        let secrets = FakeSecrets()
        secrets.set(p("Office").secretsKey, .password, "pw")
        let opts = ProfileOptionsStore(backend: FakeSettingsBackend())
        var o = ProfileOptions(); o.autoConnect = true
        opts.set(p("Office").id, o)
        let moved = try store.rename(p("Office"), to: "HQ", active: [], secrets: secrets, options: opts)
        expectEqual(secrets.get(moved.secretsKey, .password), "pw")
        expect(opts.options(moved.id).autoConnect)
    }
    test("POPT-08", "a persistent profile shows what the helper applies: its settings beside it") {
        var mine = ProfileOptions()
        mine.autoConnect = true
        mine.killSwitch = true
        mine.proxy = .none
        mine.disconnectOnSleep = true
        var s = PersistentSettings()
        s.splitDNS = true
        s.protection = ProtectionOptions(killSwitch: false, blockIPv6: false, dnsOnlyTunnel: true)
        let o = mine.applying(s)
        expect(o.autoConnect, "the app's own stays")
        expect(!o.killSwitch && !o.blockIPv6 && o.dnsOnlyTunnel && o.splitDNS)
        expectEqual(o.proxy, .global)
        expectEqual(o.disconnectOnSleep, false, "persistent tunnels stay over sleep")
        expectEqual(try PersistentSettings.parse(Data(#"{"allow_lan": true, "kill_switch": true}"#.utf8)).protection,
                    ProtectionOptions(killSwitch: true, allowLAN: true))
        expectThrows { _ = try PersistentSettings.parse(Data(#"{"kill_switch": 1}"#.utf8)) }
    }
    test("POPT-09", "domains for the server's DNS are kept with the profile's options; older options read without them") {
        var o = ProfileOptions()
        o.serverDNSDomains = ["cprserv.lan", "corp.example"]
        let back = try JSONDecoder().decode(ProfileOptions.self, from: try JSONEncoder().encode(o))
        expectEqual(back.serverDNSDomains, ["cprserv.lan", "corp.example"])
        let old = try JSONDecoder().decode(ProfileOptions.self, from: Data(#"{"autoConnect": true}"#.utf8))
        expectEqual(old.serverDNSDomains, [])
    }
    test("POPT-05", "delete a user profile") {
        let fs = MemFS()
        fs.add("\(userDir)/work/work.ovpn", "client\nremote w 1194\n")
        fs.add("\(userDir)/work/ca.crt", "CA")
        fs.add("\(systemDir)/corp.ovpn", "client\nremote c 1194\n")
        let store = ProfileStore(fs: fs, userDir: userDir, systemDir: systemDir)
        func p(_ name: String) -> Profile { store.scan().first { $0.name == name }! }
        let secrets = FakeSecrets()
        let workKey = p("work").secretsKey
        secrets.set(workKey, .password, "pw")
        let opts = ProfileOptionsStore(backend: FakeSettingsBackend())
        var o = ProfileOptions(); o.autoConnect = true
        opts.set(p("work").id, o)
        expectThrows("connected", matching: "connected") { try store.delete(p("work"), active: [p("work").id]) }
        let id = p("work").id
        try store.delete(p("work"), active: [], secrets: secrets, options: opts)
        expect(!fs.exists("\(userDir)/work"), "the folder with its files is gone")
        expectEqual(secrets.get(workKey, .password), nil)
        expectEqual(opts.options(id), ProfileOptions())
        expectThrows("system", matching: "administrator") { try store.delete(p("corp"), active: []) }
    }
}

func registerProfileOptionsManagerTests() {
    test("MAN-17", "auto-connect at start") {
        let h = ManagerHarness()
        h.m.autoConnect = { $0.name == "b" }
        h.m.appStarted()
        expectEqual(h.helper.starts.map(\.name), ["b"])
        let twice = ManagerHarness()
        twice.m.autoConnect = { _ in true }
        twice.memory.remembered = ["/cfg/a.ovpn"]
        twice.m.appStarted()
        expectEqual(twice.helper.starts.map(\.name).sorted(), ["a", "b"], "remembered and auto: each once")
    }
    test("PWR-07", "per-profile sleep choice") {
        let h = ManagerHarness()
        h.m.connect(h.a)
        h.m.connect(h.b)
        h.m.handle(.willSleep, disconnectOnSleep: { $0.name == "a" })
        expectEqual(h.helper.stops, ["H1"])
    }
}

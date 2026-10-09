import Foundation
import MugVPNAppCore
import MugVPNCore

final class FakeSettingsBackend: SettingsBackend {
    var values: [String: Any] = [:]
    var forced: [String: Any] = [:]
    func value(_ key: String) -> Any? { forced[key] ?? values[key] }
    func set(_ key: String, _ value: Any?) { values[key] = value }
    func isForced(_ key: String) -> Bool { forced[key] != nil }
}

func registerAppLogicTests() {
    test("REG-01", "the helper is registered only from /Applications") {
        expectEqual(HelperRegistration.problem(bundlePath: "/Applications/MugVPN.app"), nil)
        for p in ["/Volumes/MugVPN 0.1.0/MugVPN.app", "/Users/u/Downloads/MugVPN.app", "/Users/u/Applications/MugVPN.app",
                  "/Applications/Tools/MugVPN.app", "/Applications/../tmp/MugVPN.app", "/private/var/folders/x/AppTranslocation/y/d/MugVPN.app"] {
            expect(HelperRegistration.problem(bundlePath: p)?.contains("Applications") == true, p)
        }
    }
    // MARK: L-SEC
    test("SEC-01", "save, read, clear") {
        let s = FakeSecrets()
        s.set("office", .username, "u")
        s.set("office", .password, "p")
        s.set("home", .password, "h")
        expectEqual(s.get("office", .password), "p")
        s.removeAll("office")
        expectEqual(s.get("office", .username), nil)
        expectEqual(s.get("home", .password), "h", "other profiles untouched")
    }
    test("SEC-02", "the key password is its own entry") {
        let s = FakeSecrets()
        s.set("office", .password, "p")
        s.set("office", .keyPassword, "k")
        s.remove("office", .password)
        expectEqual(s.get("office", .keyPassword), "k")
    }
    test("SEC-03", "policy: no saving") {
        // Covered for the connection in CON-22; here the setting comes from a forced value.
        let b = FakeSettingsBackend()
        b.forced["disable_save_passwords"] = true
        let st = SettingsStore(backend: b)
        expect(st.settings.disableSavePasswords)
        expect(!st.settings.connectionSettings.savePasswordsAllowed)
    }
    test("SEC-04", "secrets follow a renamed profile and go with a deleted one") {
        let s = FakeSecrets()
        s.set("old", .username, "u")
        s.set("old", .keyPassword, "k")
        ProfileSecrets.renamed(s, from: "old", to: "new")
        expectEqual(s.get("new", .username), "u")
        expectEqual(s.get("new", .keyPassword), "k")
        expectEqual(s.get("old", .username), nil)
        ProfileSecrets.deleted(s, "new")
        expectEqual(s.items, [:])
    }

    // MARK: L-SET
    test("SET-01", "defaults") {
        let s = SettingsStore(backend: FakeSettingsBackend()).settings
        expectEqual(s.silentConnection, false)
        expectEqual(s.showBalloon, .initial)
        expectEqual(s.logAppend, false)
        expectEqual(s.menuView, .auto)
        expectEqual(s.popupMuteHours, 24)
        expectEqual(s.disablePopupMessages, false)
        expectEqual(s.preconnectScriptTimeout, 10)
        expectEqual(s.connectScriptTimeout, 30)
        expectEqual(s.disconnectScriptTimeout, 10)
        expectEqual(s.configExt, "ovpn")
        expectEqual(s.proxy, .system)
        expectEqual(s.persistentConnections, .auto)
        expectEqual(s.disableSavePasswords, false)
    }
    test("PWR-06", "disconnect on sleep setting") {
        let b = FakeSettingsBackend()
        let st = SettingsStore(backend: b)
        expect(!st.settings.disconnectOnSleep)
        try st.update { $0.disconnectOnSleep = true }
        expectEqual(b.values["disconnect_on_sleep"] as? Bool, true)
    }
    test("SET-02", "forced values win and are locked") {
        let b = FakeSettingsBackend()
        b.values["silent_connection"] = false
        b.forced["silent_connection"] = true
        let st = SettingsStore(backend: b)
        expect(st.settings.silentConnection)
        expect(st.isLocked(.silentConnection))
        expect(!st.isLocked(.logAppend))
        expectThrows(matching: "administrator") { try st.update { $0.silentConnection = false } }
        expect(st.settings.silentConnection)
        try st.update { $0.logAppend = true }
        expectEqual(b.values["log_append"] as? Bool, true)
        expect(SettingsStore(backend: b).settings.logAppend, "persisted")
    }
    test("SET-03", "invalid values refused") {
        let st = SettingsStore(backend: FakeSettingsBackend())
        expectThrows { try st.update { $0.disconnectScriptTimeout = 0 } }
        expectThrows { try st.update { $0.preconnectScriptTimeout = 100 } }
        expectThrows { try st.update { $0.connectScriptTimeout = -1 } }
        try st.update { $0.connectScriptTimeout = 0 }
        expectThrows { try st.update { $0.proxy = .manual(host: "", port: 8080) } }
        expectThrows { try st.update { $0.proxy = .manual(host: "p", port: 70000) } }
        expectThrows { try st.update { $0.configExt = "o/vpn" } }
        let b = FakeSettingsBackend()
        b.values["popup_mute_interval"] = "garbage"
        expectEqual(SettingsStore(backend: b).settings.popupMuteHours, 24, "unreadable stored values fall back to defaults")
    }

    // MARK: L-CLI
    test("CLI-01", "--command") {
        expectEqual(CommandLineRequest.parse(["--command", "connect", "office"]), .command(.connect("office")))
        expectEqual(CommandLineRequest.parse(["--command", "disconnect", "office.ovpn"]), .command(.disconnect("office")))
        expectEqual(CommandLineRequest.parse(["--command", "reconnect", "x"]), .command(.reconnect("x")))
        expectEqual(CommandLineRequest.parse(["--command", "disconnect_all"]), .command(.disconnectAll))
        expectEqual(CommandLineRequest.parse(["--command", "silent_connection", "1"]), .command(.silentConnection(true)))
        expectEqual(CommandLineRequest.parse(["--command", "silent_connection", "0"]), .command(.silentConnection(false)))
        expectEqual(CommandLineRequest.parse(["--command", "exit"]), .command(.exit))
        expectEqual(CommandLineRequest.parse(["--command", "rescan"]), .command(.rescan))
        expectEqual(CommandLineRequest.parse(["--command", "import", "/tmp/a.ovpn"]), .command(.importFile("/tmp/a.ovpn")))
    }
    test("CLI-02", "--connect") {
        expectEqual(CommandLineRequest.parse(["--connect", "office.ovpn"]), .connectOnStart("office"))
        expectEqual(CommandLineRequest.parse(["--connect", "office"]), .connectOnStart("office"))
        expectEqual(CommandLineRequest.parse([]), .launch)
    }
    test("CLI-03", "no running instance: connect and import start it first, exit is done, the rest fail") {
        expectEqual(CommandLineRequest.withoutInstance(.connect("office")), .launchFirst)
        expectEqual(CommandLineRequest.withoutInstance(.importFile("/a.ovpn")), .launchFirst)
        expectEqual(CommandLineRequest.withoutInstance(.exit), .done)
        for c in [CLICommand.disconnect("x"), .reconnect("x"), .disconnectAll, .rescan, .silentConnection(true), .list, .status(nil)] {
            expectEqual(CommandLineRequest.withoutInstance(c), .notRunning, "\(c)")
        }
    }
    test("CLI-06", "list, status, --wait and --timeout") {
        expectEqual(CommandLineRequest.parse(["--command", "list"]), .command(.list))
        expectEqual(CommandLineRequest.parse(["--command", "status"]), .command(.status(nil)))
        expectEqual(CommandLineRequest.parse(["--command", "status", "office.ovpn"]), .command(.status("office")))
        expectEqual(CommandLineRequest.parse(["--command", "connect", "office", "--wait"]),
                    .command(.connect("office"), wait: CommandLineRequest.defaultWait))
        expectEqual(CommandLineRequest.parse(["--command", "disconnect", "--timeout", "15", "office"]),
                    .command(.disconnect("office"), wait: 15))
        for bad in [["--command", "list", "x"], ["--command", "connect", "office", "--timeout", "0"],
                    ["--command", "connect", "office", "--timeout"], ["--command", "rescan", "--wait"],
                    ["--command", "connect", "office", "--timeout", "abc"]] {
            if case .error = CommandLineRequest.parse(bad) {} else { expect(false, "\(bad) should be an error") }
        }
    }
    test("CLI-07", "one profile per name; a shared name is refused with the names to use") {
        var a = Profile(name: "office", path: "/u/office/office.ovpn", source: .user, folder: "office")
        var b = Profile(name: "office", path: "/s/office.ovpn", source: .system, folder: "")
        a.displayName = "office (office)"
        b.displayName = "office (system)"
        let c = Profile(name: "home", path: "/u/home.ovpn", source: .user, folder: "")
        let all = [a, b, c]
        expectEqual(try? CommandReply.find("home", in: all).get(), c)
        expectEqual(try? CommandReply.find("office (system)", in: all).get(), b)
        expectEqual(try? CommandReply.find("/u/office/office.ovpn", in: all).get(), a)
        guard case .failure(let r) = CommandReply.find("office", in: all) else { return expect(false, "ambiguous") }
        expect(r.code == .failed && (r.error ?? "").contains("office (office), office (system)"), "\(r)")
        guard case .failure(let n) = CommandReply.find("nope", in: all) else { return expect(false, "missing") }
        expectEqual(n.code, .failed)
    }
    test("CLI-08", "the reply: a JSON line with an exit code and the profiles' states") {
        let p = Profile(name: "home", path: "/u/home.ovpn", source: .user, folder: "")
        let r = CommandReply(profiles: [CommandReply.ProfileState(p, .connected(ip: "10.8.0.2", ipv6: "", withErrors: false)),
                                        CommandReply.ProfileState(p, nil)])
        let back = try JSONDecoder().decode(CommandReply.self, from: try JSONEncoder().encode(r))
        expectEqual(back, r)
        expectEqual(back.profiles?.map(\.status), ["connected", "disconnected"])
        expectEqual(back.profiles?.first?.ip, "10.8.0.2")
        expectEqual(back.profiles?.first?.ipv6, nil)
        expectEqual(CommandReply.failed("x").code.rawValue, 1)
        expectEqual(CommandReply.Code.timedOut.rawValue, 4)
    }
    test("CLI-09", "--wait: what counts as done") {
        let up = ConnectionStatus.connected(ip: "10.8.0.2", ipv6: "", withErrors: false)
        let t0 = Date(timeIntervalSince1970: 100), t1 = Date(timeIntervalSince1970: 200)
        expectEqual(CommandReply.check(.connected(after: nil), name: "a", status: .connecting("WAIT"), connectedSince: nil), nil)
        expectEqual(CommandReply.check(.connected(after: nil), name: "a", status: up, connectedSince: t0), .ok)
        expectEqual(CommandReply.check(.connected(after: nil), name: "a", status: nil, connectedSince: nil)?.code, .failed)
        expectEqual(CommandReply.check(.connected(after: nil), name: "a", status: .disconnected, connectedSince: nil), nil,
                    "a connection not started yet (found in INT-27d)")
        expectEqual(CommandReply.check(.connected(after: t0), name: "a", status: up, connectedSince: t0), nil, "the old connection")
        expectEqual(CommandReply.check(.connected(after: t0), name: "a", status: up, connectedSince: t1), .ok, "reconnected")
        expectEqual(CommandReply.check(.gone, name: "a", status: .disconnecting, connectedSince: nil), nil)
        expectEqual(CommandReply.check(.gone, name: "a", status: nil, connectedSince: nil), .ok)
    }
    test("CLI-04", "errors") {
        for bad in [["--command"], ["--command", "frob"], ["--command", "connect"], ["--command", "silent_connection", "2"],
                    ["--frob"], ["--connect"]] {
            if case .error(let msg) = CommandLineRequest.parse(bad) {
                expect(msg.contains("usage") || msg.contains("unknown"), "\(bad): \(msg)")
            } else {
                expect(false, "\(bad) should be an error")
            }
        }
        expectEqual(CommandLineRequest.parse(["--help"]), .help)
    }

    test("CLI-05", "macOS argument pairs are skipped") {
        expectEqual(CommandLineRequest.parse(["-AppleLanguages", "(ru)"]), .launch)
        expectEqual(CommandLineRequest.parse(["-AppleInterfaceStyle", "Dark", "--connect", "office"]), .connectOnStart("office"))
        expectEqual(CommandLineRequest.parse(["-psn_0_12345"]), .launch)
        expectEqual(CommandLineRequest.parse(["--command", "connect", "office", "-NSDocumentRevisionsDebugMode", "YES"]),
                    .command(.connect("office")))
    }

    // MARK: L-SCR
    let profile = Profile(name: "office", path: "/cfg/office/office.ovpn", source: .user, folder: "office")
    let present: (String) -> [String] = { $0 == "/cfg/office" ? ["office.ovpn", "office_pre.sh", "office_up.sh"] : [] }
    test("SCR-01", "scripts next to the profile") {
        expectEqual(ScriptRunner.plan(profile, .pre, settings: Settings(), logsDir: "/logs", entries: present)?.path,
                    "/cfg/office/office_pre.sh")
        expectEqual(ScriptRunner.plan(profile, .up, settings: Settings(), logsDir: "/logs", entries: present)?.path,
                    "/cfg/office/office_up.sh")
        expect(ScriptRunner.plan(profile, .down, settings: Settings(), logsDir: "/logs", entries: present) == nil)
    }
    test("SCR-02", "environment") {
        let d = try ConfigParser.parse("setenv CORP_SITE berlin\nsetenv opt block-outside-dns\nsetenv FORWARD_COMPATIBLE 1")
        let env = ScriptRunner.environment(profile: profile, directives: d, pushed: [("SERVER_VAR", "x")],
                                           localIP: "10.8.0.2", localIPv6: "")
        expectEqual(env["CORP_SITE"], "berlin")
        expectEqual(env["PUSHED_SERVER_VAR"], "x", "what a server sends comes under a name of its own")
        expect(env["SERVER_VAR"] == nil)
        expectEqual(env["config"], "office.ovpn")
        expectEqual(env["profile"], "office")
        expectEqual(env["ifconfig_local"], "10.8.0.2")
        expect(env["opt"] == nil && env["FORWARD_COMPATIBLE"] == "1")
        let unsafe = ScriptRunner.environment(profile: profile, directives: [], pushed: [("PATH", "/evil"), ("DYLD_INSERT_LIBRARIES", "x"), ("ok_name", "1"), ("bad-name", "2")],
                                              localIP: "", localIPv6: "")
        expect(unsafe["PATH"] == nil && unsafe["DYLD_INSERT_LIBRARIES"] == nil && unsafe["PUSHED_bad-name"] == nil,
               "the server cannot set PATH, DYLD_*, or odd names")
        expectEqual(unsafe["PUSHED_ok_name"], "1")
    }
    test("SCR-06", "no variable that changes how a shell or program runs") {
        // SHELLOPTS=xtrace with PS4='$(...)' runs code in any /bin/sh script.
        let bad = ["SHELLOPTS", "BASHOPTS", "PS4", "PS1", "PROMPT_COMMAND", "CDPATH", "GLOBIGNORE", "ZDOTDIR",
                   "PERL5OPT", "PERL5LIB", "PYTHONPATH", "PYTHONSTARTUP", "RUBYOPT", "NODE_OPTIONS", "BASH_FUNC_x%%",
                   "GIT_SSH_COMMAND", "SSH_ASKPASS", "OPENSSL_CONF", "LOGNAME", "HISTFILE", "MAIL", "TERMINFO"]
        let pushed = ScriptRunner.environment(profile: profile, directives: [], pushed: bad.map { ($0, "x") },
                                              localIP: "", localIPv6: "")
        for b in bad { expect(pushed[b] == nil, "pushed \(b)") }
        let d = try ConfigParser.parse(bad.filter { !$0.contains("%") }.map { "setenv \($0) x" }.joined(separator: "\n") + "\nsetenv BASH_ENV /tmp/x\nsetenv PATH /tmp")
        let own = ScriptRunner.environment(profile: profile, directives: d, pushed: [], localIP: "", localIPv6: "")
        for b in bad + ["BASH_ENV", "PATH"] { expect(own[b] == nil, "profile setenv \(b)") }
    }
    test("SCR-07", "scripts start from a clean environment") {
        let env = ScriptRunner.processEnvironment(home: "/Users/u", user: "u", extra: ["CORP": "1"])
        expectEqual(env, ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/Users/u", "USER": "u", "LOGNAME": "u",
                          "SHELL": "/bin/sh", "TMPDIR": "/tmp", "LANG": "en_US.UTF-8", "CORP": "1"])
        expectEqual(ScriptRunner.processEnvironment(home: "/h", user: "u", extra: ["PATH": "/evil"])["PATH"],
                    "/usr/bin:/bin:/usr/sbin:/sbin", "the base wins")
    }
    test("SCR-03", "timeouts") {
        var s = Settings()
        s.preconnectScriptTimeout = 5
        s.connectScriptTimeout = 0
        s.disconnectScriptTimeout = 7
        let all: (String) -> [String] = { _ in ["office_pre.sh", "office_up.sh", "office_down.sh"] }
        expectEqual(ScriptRunner.plan(profile, .pre, settings: s, logsDir: "/l", entries: all)?.timeout, 5)
        expectEqual(ScriptRunner.plan(profile, .up, settings: s, logsDir: "/l", entries: all)?.waitForExit, false,
                    "connect timeout 0: do not wait")
        expectEqual(ScriptRunner.plan(profile, .down, settings: s, logsDir: "/l", entries: all)?.timeout, 7)
    }
    test("SCR-04", "logs") {
        let all: (String) -> [String] = { _ in ["office_pre.sh", "office_up.sh", "office_down.sh"] }
        expectEqual(ScriptRunner.plan(profile, .pre, settings: Settings(), logsDir: "/l", entries: all)?.logPath, "/l/office_pre.log")
        expectEqual(ScriptRunner.plan(profile, .down, settings: Settings(), logsDir: "/l", entries: all)?.logPath, "/l/office_down.log")
    }
    test("SCR-08", "a script runs only under its exact name, not one the disk merely treats as the same") {
        let p = Profile(name: "evil", path: "/cfg/evil/evil.ovpn", source: .user, folder: "evil")
        expect(ScriptRunner.plan(p, .pre, settings: Settings(), logsDir: "/l", entries: { _ in ["evil.ovpn", "evil_pre.\u{17F}h"] }) == nil)
        expect(ScriptRunner.plan(p, .pre, settings: Settings(), logsDir: "/l", entries: { _ in ["evil.ovpn", "EVIL_PRE.SH"] }) == nil)
        expect(ScriptRunner.plan(p, .pre, settings: Settings(), logsDir: "/l", entries: { _ in ["evil.ovpn", "evil_pre.sh"] }) != nil)
    }
    test("SCR-09", "a server cannot steer the user's scripts to its own hosts or credentials") {
        let p = Profile(name: "a", path: "/cfg/a/a.ovpn", source: .user, folder: "a")
        let pushed = [("DOCKER_HOST", "tcp://evil"), ("ALL_PROXY", "x"), ("all_proxy", "x"), ("NO_PROXY", "*"),
                      ("REQUESTS_CA_BUNDLE", "/tmp/ca"), ("KUBECONFIG", "/tmp/k"), ("AWS_ACCESS_KEY_ID", "k"),
                      ("GNUPGHOME", "/tmp"), ("XDG_CONFIG_HOME", "/tmp"), ("LUA_INIT", "x"), ("PHPRC", "/tmp"),
                      ("LESSOPEN", "|x"), ("TCLLIBPATH", "/tmp"), ("SITE", "office")]
        let env = ScriptRunner.environment(profile: p, directives: [], pushed: pushed, localIP: "", localIPv6: "")
        let names = env.keys.filter { !["config", "profile"].contains($0) }
        expect(names.allSatisfy { $0.hasPrefix("PUSHED_") }, "\(names.sorted())")
        expectEqual(env["PUSHED_SITE"], "office")
        let many = ScriptRunner.environment(profile: p, directives: [], pushed: (0..<500).map { ("V\($0)", "x") }, localIP: "", localIPv6: "")
        expect(many.count <= ScriptRunner.maxPushed + 4, "bounded: \(many.count)")
    }
    test("SCR-05", "outcomes") {
        expectEqual(ScriptRunner.outcome(.pre, .exited(0)), .proceed)
        expectEqual(ScriptRunner.outcome(.pre, .exited(1)), .cancelConnection)
        expectEqual(ScriptRunner.outcome(.pre, .timedOut), .cancelConnection)
        expectEqual(ScriptRunner.outcome(.up, .exited(3)), .connectedWithErrors)
        expectEqual(ScriptRunner.outcome(.up, .timedOut), .connectedWithErrors)
        expectEqual(ScriptRunner.outcome(.up, .exited(0)), .proceed)
        expectEqual(ScriptRunner.outcome(.down, .exited(1)), .proceed, "disconnecting goes on regardless")
    }

    // MARK: L-NET
    func facts(_ routes: [[String]]) -> OpenVPNLogFacts { OpenVPNLogFacts(device: "utun9", routes: routes) }
    let defaultHalves = [["-net", "0.0.0.0", "10.84.0.1", "128.0.0.0"], ["-net", "128.0.0.0", "10.84.0.1", "128.0.0.0"]]
    test("NET-01", "two tunnels take the default route") {
        let c = NetworkConflicts.find([("a", facts(defaultHalves), ""), ("b", facts(defaultHalves), ""),
                                       ("c", facts([["-net", "10.91.0.0", "10.81.0.1", "255.255.255.0"]]), "")])
        expectEqual(c, [.bothTakeDefaultRoute("a", "b")])
    }
    test("NET-02", "overlapping routes") {
        let a = facts([["-net", "10.91.0.0", "10.81.0.1", "255.255.255.0"]])
        let b = facts([["-net", "10.91.0.128", "10.82.0.1", "255.255.255.128"]])
        let c = facts([["-net", "10.92.0.0", "10.83.0.1", "255.255.255.0"]])
        expectEqual(NetworkConflicts.find([("a", a, ""), ("b", b, ""), ("c", c, "")]),
                    [.overlappingRoutes("a", "b", "10.91.0.128/25")])
        let host = facts([["-net", "203.0.113.7", "192.168.64.1", "255.255.255.255"]])
        expectEqual(NetworkConflicts.find([("a", host, ""), ("b", host, "")]), [],
                    "the same host route to a shared server is not a conflict")
    }
    test("NET-06", "a network change: another router, address or DHCP lease on the same interface, or another interface") {
        let g4: [String: Any] = ["PrimaryInterface": "en0", "Router": "192.168.1.1"]
        let s4: [String: Any] = ["Addresses": ["192.168.1.20"], "Router": "192.168.1.1"]
        let dhcp: [String: Any] = ["Option_54": Data([192, 168, 1, 1]), "Option_6": Data([192, 168, 1, 1])]
        func id(_ g: [String: Any] = g4, _ s: [String: Any] = s4, _ d: [String: Any]? = dhcp) -> NetworkIdentity? {
            NetworkIdentity.from(global4: g, global6: nil, service4: s, service6: nil, dhcp: d)
        }
        var d = NetworkChangeDetector()
        expect(!d.update(id()), "the first look is no change")
        expect(!d.update(id()), "the same network")
        // Another Wi-Fi network on the same en0: the same subnet and router, another DHCP server.
        expect(d.update(id(g4, s4, ["Option_54": Data([192, 168, 1, 2]), "Option_6": Data([192, 168, 1, 1])])))
        expect(d.update(id(g4, ["Addresses": ["192.168.1.21"], "Router": "192.168.1.1"])), "a new address")
        expect(d.update(id(g4.merging(["Router": "10.0.0.1"]) { $1 }, ["Addresses": ["10.0.0.5"], "Router": "10.0.0.1"])),
               "a new router")
        let eth = id(["PrimaryInterface": "en5", "Router": "10.0.0.1"], ["Addresses": ["10.0.0.5"], "Router": "10.0.0.1"])
        expect(d.update(eth), "Wi-Fi to Ethernet")
        expect(!d.update(nil), "no network: nothing to reconnect to")
        expect(!d.update(eth), "the same network back after a moment without (DHCP set again; found in INT-27f)")
        expect(!d.update(nil))
        expect(d.update(id(g4, ["Addresses": ["192.168.1.99"], "Router": "192.168.1.1"])), "another one after none")
    }
    test("NET-07", "MugVPN's own tunnels and DNS are no network change") {
        let s4: [String: Any] = ["Addresses": ["192.168.1.20"], "Router": "192.168.1.1"]
        expectEqual(NetworkIdentity.from(global4: ["PrimaryInterface": "utun5"], global6: nil, service4: nil, service6: nil, dhcp: nil), nil)
        var d = NetworkChangeDetector()
        let a = NetworkIdentity.from(global4: ["PrimaryInterface": "en0"], global6: nil, service4: s4, service6: nil, dhcp: nil)
        _ = d.update(a)
        // The DNS MugVPN sets is not part of it (only DHCP's own record is).
        expect(!d.update(NetworkIdentity.from(global4: ["PrimaryInterface": "en0"], global6: nil, service4: s4,
                                              service6: ["Addresses": ["fd00::99"]], dhcp: nil)), "a temporary IPv6 address")
    }
    test("NET-05", "a route another tunnel already holds still counts for conflicts") {
        let first = """
        2026-10-06 05:46:44 /sbin/route add -net 0.0.0.0 10.84.0.1 128.0.0.0
        2026-10-06 05:46:44 /sbin/route add -net 128.0.0.0 10.84.0.1 128.0.0.0
        """
        let second = first + "\n2026-10-06 05:46:45 ERROR: OS X route add command failed: external program exited with error status: 1"
        let f2 = OpenVPNLogFacts.parse(second)
        expectEqual(f2.routes.count, 1, "cleanup: only the add that worked")
        expectEqual(f2.requestedRoutes.count, 2, "conflicts: every route asked for")
        expectEqual(NetworkConflicts.find([("d", OpenVPNLogFacts.parse(first), first), ("d2", f2, second)]),
                    [.bothTakeDefaultRoute("d", "d2")])
    }
    test("NET-03", "DNS refused by the script") {
        let log = "2026-10-06 05:46:44 setting DNS failed, already redirecting to another tunnel\n"
        expectEqual(NetworkConflicts.find([("b", facts([]), ""), ("d", facts([]), log)]), [.dnsTakenByAnother("d")])
    }
}

func registerUninstallAppTests() {
    test("UNI-04", "what the app removes for the user") {
        let all = UninstallPlan.userPaths(home: "/Users/u", keepProfiles: false)
        expectEqual(all, ["/Users/u/Library/Application Support/MugVPN", "/Users/u/Library/Logs/MugVPN",
                          "/Users/u/Library/Preferences/com.mugvpn.app.plist"])
        let keep = UninstallPlan.userPaths(home: "/Users/u", keepProfiles: true)
        expect(!keep.contains("/Users/u/Library/Application Support/MugVPN"), "profiles kept")
        expect(keep.contains("/Users/u/Library/Logs/MugVPN"))
        expectEqual(CommandLineRequest.parse(["--uninstall"]), .uninstall(confirmed: false, keepProfiles: false))
        expectEqual(CommandLineRequest.parse(["--uninstall", "--yes", "--keep-profiles"]), .uninstall(confirmed: true, keepProfiles: true))
    }
}

func registerLogViewTests() {
    test("LOGV-01", "which log View Log opens") {
        let have: Set<String> = ["/run/H1/openvpn.log", "/logs/a.501.log"]
        func path(_ helperID: String?, _ files: Set<String> = have) -> String? {
            LogLocation.path(profile: "a", helperID: helperID, uid: 501, runDir: "/run", logsDir: "/logs",
                             exists: { files.contains($0) })
        }
        expectEqual(path("H1"), "/run/H1/openvpn.log", "connected: the live log")
        expectEqual(path(nil), "/logs/a.501.log", "disconnected: the kept log")
        expectEqual(path("H1", ["/logs/a.501.log"]), "/logs/a.501.log", "no live log yet: the last one")
        expectEqual(path(nil, []), nil, "nothing to show")
    }
}

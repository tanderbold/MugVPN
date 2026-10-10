import Foundation
import MugVPNAppCore
import MugVPNCore

final class FakeHelperClient: HelperClient {
    var version: String? = MugVPNIDs.helperVersion
    func version(reply: @escaping (String?) -> Void) { reply(version) }
    var restarts = 0
    /// What a restart brings (the new helper's version), or nil: busy.
    var restartTo: String?? = .some(MugVPNIDs.helperVersion)
    /// An older helper: it has no restart call at all.
    var restartUnsupported = false
    /// Answers its older calls (an old helper) or nothing at all (not running, not registered).
    var reachable = true
    func reachable(reply: @escaping (Bool) -> Void) { reply(reachable) }
    var restartNotNewer = false
    /// The restart call fails (no answer), and the helper then answers this version (a new one started).
    var restartFailsThenVersion: String?
    func restartIfIdle(reply: @escaping (HelperRestart) -> Void) {
        restarts += 1
        if restartNotNewer { return reply(.notNewer) }
        if let v = restartFailsThenVersion { version = v; return reply(.unavailable) }
        // An older helper: no such call; the XPC client hears only that there was no answer.
        if restartUnsupported { return reply(.unavailable) }
        guard case .some(let v) = restartTo else { return reply(.inUse) }
        version = v
        reply(.restarting)
    }
    var blocked: [String] = []
    var unblocks = 0
    func blocks(reply: @escaping ([String]) -> Void) { reply(blocked) }
    func unblock(reply: @escaping (String?) -> Void) { unblocks += 1; blocked = []; reply(nil) }
    func suspendBlocks(seconds: Int, reply: @escaping (String?) -> Void) { reply(nil) }
    var starts: [ProfileBundle] = []
    var stops: [String] = []
    var running: [ConnectionInfo] = []
    var refuse: String?
    var nextID = 0
    /// When set, start replies wait until `answerStarts()`.
    var deferStarts = false
    var deferred: [() -> Void] = []
    func answerStarts() { let d = deferred; deferred = []; d.forEach { $0() } }
    func start(_ bundle: ProfileBundle, reply: @escaping (Result<(id: String, socket: String), Error>) -> Void) {
        if deferStarts {
            deferStarts = false
            deferred.append { self.start(bundle, reply: reply) }
            return
        }
        starts.append(bundle)
        if let r = refuse { return reply(.failure(ProfileError(r))) }
        nextID += 1
        let id = "H\(nextID)"
        running.append(ConnectionInfo(id: id, name: bundle.name, pid: 1, managementSocket: "/run/\(id)/m.sock", ownerUID: 501))
        reply(.success((id, "/run/\(id)/m.sock")))
    }
    func stop(_ id: String, reply: @escaping (String?) -> Void) {
        stops.append(id)
        reply(nil)
    }
    func list(reply: @escaping ([ConnectionInfo]) -> Void) { reply(running) }
    var released: [String] = []
    var releaseError: String?
    func releaseManagement(_ id: String, reply: @escaping (String?) -> Void) {
        released.append(id)
        reply(releaseError)
    }
    var tunnelRequests: [(id: String, kind: String, message: String)] = []
    func tunnelRequest(_ id: String, kind: String, message: String, reply: @escaping (Result<FileHandle?, Error>) -> Void) {
        tunnelRequests.append((id, kind, message))
        reply(.success(kind == "OPENTUN" ? FileHandle(fileDescriptor: 77, closeOnDealloc: false) : nil))
    }
    var uninstalls: [Bool] = []
    func uninstall(keepProfiles: Bool, reply: @escaping (String?) -> Void) { uninstalls.append(keepProfiles); reply(nil) }
    var persistentStarts: [String] = []
    var refusePersistent: String?
    func startPersistent(_ name: String, reply: @escaping (Result<String, Error>) -> Void) {
        persistentStarts.append(name)
        if let r = refusePersistent { return reply(.failure(ProfileError(r))) }
        nextID += 1
        let id = "P\(nextID)"
        running.append(ConnectionInfo(id: id, name: name, pid: 1, managementSocket: "/run/\(id)/m.sock", ownerUID: 0, persistent: true))
        reply(.success(id))
    }
}

final class FakeLink: ManagementLink {
    var written: [String] = []
    var closed = false
    let onData: (Data) -> Void
    let onClose: () -> Void
    init(onData: @escaping (Data) -> Void, onClose: @escaping () -> Void) {
        self.onData = onData
        self.onClose = onClose
    }
    func write(_ data: Data) { written += String(decoding: data, as: UTF8.self).split(separator: "\n").map(String.init) }
    var passed: [Int32] = []
    func write(_ data: Data, passing fd: Int32) -> Bool {
        write(data)
        passed.append(fd)
        return true
    }
    func close() { closed = true }
    func push(_ s: String) { onData(Data(s.utf8)) }
}

final class FakeTransport: ManagementTransport {
    var failures = 0
    var attempts: [String] = []
    var links: [String: FakeLink] = [:]
    func open(_ socket: String, onData: @escaping (Data) -> Void, onClose: @escaping () -> Void) -> ManagementLink? {
        attempts.append(socket)
        if failures > 0 { failures -= 1; return nil }
        let l = FakeLink(onData: onData, onClose: onClose)
        links[socket] = l
        return l
    }
}

final class FakeScheduler: Scheduler {
    var pending: [(TimeInterval, () -> Void)] = []
    func after(_ s: TimeInterval, _ f: @escaping () -> Void) { pending.append((s, f)) }
    /// Run timers until none are left (or `limit` rounds).
    func drain(limit: Int = 1000) {
        var n = 0
        while !pending.isEmpty && n < limit {
            let p = pending.removeFirst()
            p.1()
            n += 1
        }
    }
}

final class FakeReader: ProfileBundleReader {
    var broken: Set<String> = []
    func bundle(for p: Profile) throws -> ProfileBundle {
        if broken.contains(p.id) { throw ProfileError("cannot read \(p.path)") }
        return ProfileBundle(name: p.name, config: "client\ndev tun\n", files: [:])
    }
}

final class FakeMemory: ActiveMemory {
    var remembered: [String] = []
}

final class ManagerHarness {
    let helper = FakeHelperClient()
    let transport = FakeTransport()
    let scheduler = FakeScheduler()
    let reader = FakeReader()
    let memory = FakeMemory()
    let ui = FakeUI()
    lazy var m = ConnectionManager(helper: helper, transport: transport, reader: reader, scheduler: scheduler,
                                   secrets: FakeSecrets(), settings: { ConnectionSettings() }, ui: { [ui] _ in ui },
                                   memory: memory)
    let a = Profile(name: "a", path: "/cfg/a.ovpn", source: .user, folder: "")
    let b = Profile(name: "b", path: "/cfg/b.ovpn", source: .user, folder: "")
    init() { m.profiles = [a, b] }
    func link(_ helperID: String) -> FakeLink? { transport.links["/run/\(helperID)/m.sock"] }
}

func registerManagerTests() {
    test("MAN-23", "at start the helper's version is asked: another one than the app's is said") {
        let h = ManagerHarness()
        h.m.appStarted()
        expectEqual(h.m.helperVersionMismatch, nil, "the same version")
        let old = ManagerHarness()
        old.helper.version = "0.0.9"
        var changes = 0
        old.m.onChange = { changes += 1 }
        old.m.appStarted()
        old.helper.restartTo = nil   // busy: stays as it is
        _ = old
        expect(changes > 0, "the app hears of it")
        let none = ManagerHarness()
        none.helper.version = nil
        none.helper.restartTo = nil
        none.m.appStarted()
        expectEqual(none.m.helperVersionMismatch, "unknown", "a helper that does not answer (an older one has no version call)")
    }
    test("MAN-25", "a helper in use (another user's tunnel, a block) is asked again later, waiting longer each time") {
        let h = ManagerHarness()
        h.helper.version = "0.0.9"
        h.helper.restartTo = nil
        h.m.appStarted()
        expectEqual(h.helper.restarts, 1)
        var waits: [TimeInterval] = []
        for _ in 0..<7 {
            guard let next = h.scheduler.pending.first else { break }
            waits.append(next.0)
            h.scheduler.pending.removeFirst()
            next.1()
        }
        expectEqual(waits, [60, 120, 240, 480, 960, 1800, 1800])
        h.helper.restartTo = .some(MugVPNIDs.helperVersion)
        h.scheduler.drain(limit: 3)
        expectEqual(h.m.helperVersionMismatch, nil, "once free it is started again and answers with the app's version")
    }
    test("MAN-26", "a helper without the restart call (an older one): updated by hand, asked of the user") {
        let h = ManagerHarness()
        h.helper.version = nil
        h.helper.restartUnsupported = true
        h.m.appStarted()
        expectEqual(h.m.helperVersionMismatch, "unknown")
        expect(h.m.helperNeedsManualUpdate, "the app offers to put the new one in place")
        expect(h.scheduler.pending.isEmpty, "not asked again: it cannot")
    }
    test("MAN-27", "a newer helper than the app (another user's newer MugVPN) is left alone") {
        let h = ManagerHarness()
        h.helper.version = "9.0.0"
        h.m.appStarted()
        expectEqual(h.m.helperVersionMismatch, "9.0.0")
        expectEqual(h.helper.restarts, 0, "never stopped for an older app")
        expect(!h.m.helperNeedsManualUpdate)
        expect(ConnectionManager.isOlder("0.1.9", than: "0.2.0") && ConnectionManager.isOlder("unknown", than: "0.2.0"))
        expect(!ConnectionManager.isOlder("0.10.0", than: "0.9.0") && !ConnectionManager.isOlder("0.2.0", than: "0.2.0"))
    }
    test("MAN-28", "put in place by hand, but the old one is still there: offered again") {
        let h = ManagerHarness()
        h.helper.version = nil
        h.helper.restartUnsupported = true
        h.m.appStarted()
        expect(h.m.helperNeedsManualUpdate)
        h.m.helperReplaced()
        h.scheduler.drain(limit: 3)
        expect(h.m.helperNeedsManualUpdate, "the same old helper answers: the offer comes back")
    }
    test("MAN-29", "a helper that does not answer at all is not taken for an old one") {
        let h = ManagerHarness()
        h.helper.version = nil
        h.helper.reachable = false
        h.m.appStarted()
        expectEqual(h.m.helperVersionMismatch, nil, "nothing known: nothing said")
        expect(!h.m.helperNeedsManualUpdate, "no offer to stop every tunnel")
        expect(!h.scheduler.pending.isEmpty, "asked again later")
        h.helper.reachable = true
        h.helper.version = MugVPNIDs.helperVersion
        h.scheduler.drain(limit: 3)
        expectEqual(h.m.helperVersionMismatch, nil)
    }
    test("MAN-30", "a helper whose bundle on disk is no newer (the service registered from an older copy): put in place by hand") {
        let h = ManagerHarness()
        h.helper.version = "0.0.9"
        h.helper.restartNotNewer = true
        h.m.appStarted()
        expect(h.m.helperNeedsManualUpdate, "re-registering from this copy is the way")
    }
    test("MAN-31", "a restart call that fails while a new helper is already there: no offer to put one in place") {
        let h = ManagerHarness()
        h.helper.version = "0.0.9"
        h.helper.restartFailsThenVersion = MugVPNIDs.helperVersion   // started again meanwhile
        h.m.appStarted()
        expect(!h.m.helperNeedsManualUpdate)
        expectEqual(h.m.helperVersionMismatch, nil, "asked again: the new one")
    }
    test("MAN-32", "a newer helper is told apart from an older one") {
        let h = ManagerHarness()
        h.helper.version = "9.0.0"
        h.m.appStarted()
        expect(h.m.helperIsNewer)
        let o = ManagerHarness()
        o.helper.version = "0.0.9"
        o.helper.restartTo = nil
        o.m.appStarted()
        expect(!o.m.helperIsNewer)
    }
    test("MAN-33", "a known older version without the restart call (0.1.0): asked a few times, then put in place by hand") {
        let h = ManagerHarness()
        h.helper.version = "0.1.0"
        h.helper.restartUnsupported = true
        h.m.appStarted()
        expect(!h.m.helperNeedsManualUpdate, "not on the first silence")
        h.scheduler.drain(limit: 20)
        expect(h.m.helperNeedsManualUpdate, "the same old version every time: offered by hand")
        expect(h.helper.restarts >= 2 && h.helper.restarts <= 4, "\(h.helper.restarts) tries")
    }
    test("MAN-34", "every start goes through the preflight (the app's certificate check): menus, CLI, auto-connect, wake") {
        let h = ManagerHarness()
        var asked: [String] = []
        var finish: [() -> Void] = []
        h.m.preflight = { p, done in asked.append(p.name); finish.append(done) }
        h.m.connect(h.a)
        h.m.connect(h.a)
        expectEqual(asked, ["a"], "one check for both")
        expect(h.helper.starts.isEmpty, "nothing starts before it is done")
        expect(h.m.isPending(h.a.id))
        finish.removeFirst()()
        expectEqual(h.helper.starts.count, 1)
        // A disconnect while checked: no start.
        h.m.connect(h.b)
        h.m.disconnect(h.b.id)
        finish.removeFirst()()
        expectEqual(h.helper.starts.count, 1)
        // Disconnect all and quitting cancel too.
        let q = ManagerHarness()
        var qf: [() -> Void] = []
        q.m.preflight = { _, done in qf.append(done) }
        q.m.connect(q.a)
        q.m.disconnectAll()
        q.m.connect(q.b)
        q.m.appQuitting {}
        qf.forEach { $0() }
        expect(q.helper.starts.isEmpty, "\(q.helper.starts.map(\.name))")
        // Auto-connect at start goes the same way.
        let s = ManagerHarness()
        var sa: [String] = []
        s.m.preflight = { p, done in sa.append(p.name); done() }
        s.m.autoConnect = { $0.name == "a" }
        s.m.appStarted()
        expectEqual(sa, ["a"])
    }
    test("MAN-35", "a helper that never answers the start: the connection ends with an error, not silence") {
        let h = ManagerHarness()
        h.helper.deferStarts = true            // no answer
        h.m.connect(h.a)
        expect(h.m.active[h.a.id] != nil)
        let waits = h.scheduler.pending.map(\.0)
        expect(waits.contains(ConnectionManager.helperStartTimeout), "\(waits)")
        h.scheduler.drain(limit: 5)
        expect(h.m.active[h.a.id] == nil, "given up")
        expect(h.m.lastError[h.a.id]?.contains("helper") == true, "\(h.m.lastError)")
        h.helper.answerStarts()               // a late answer: stopped, nothing left
        expect(h.m.active[h.a.id] == nil)
        expectEqual(h.helper.stops.count, 1, "the late tunnel is stopped")
    }
    test("MAN-36", "quitting is not held up by a start the helper has not answered (found in 0.2.2)") {
        let h = ManagerHarness()
        h.helper.deferStarts = true
        h.m.connect(h.a)
        var quit = false
        h.m.appQuitting { quit = true }
        expect(quit, "nothing of it to stop yet: quit at once")
        h.helper.answerStarts()
        expectEqual(h.helper.stops.count, 1, "a late answer: that tunnel is stopped")
    }
    test("MAN-37", "a helper that does not answer at all is said to the app once (it may re-register a service launchd lost)") {
        let h = ManagerHarness()
        h.helper.version = nil
        h.helper.reachable = false
        var told = 0
        h.m.onHelperUnreachable = { told += 1 }
        h.m.appStarted()
        h.scheduler.drain(limit: 3)
        expectEqual(told, 1, "once, not on every retry")
    }
    test("MAN-24", "another helper version: started again once nothing of this app's uses it, then asked again") {
        let h = ManagerHarness()
        h.helper.version = "0.0.9"
        h.m.connect(h.a)
        h.m.appStarted()
        expectEqual(h.helper.restarts, 0, "a connection of this app's is up: not now")
        expectEqual(h.m.helperVersionMismatch, "0.0.9")
        h.m.disconnect(h.a.id)
        h.link("H1")?.push(">STATE:1,EXITING,SIGTERM,,,,,\n")
        h.link("H1")?.onClose()
        expectEqual(h.helper.restarts, 1, "nothing up any more: started again")
        h.scheduler.drain()
        expectEqual(h.m.helperVersionMismatch, nil, "the new one answers with the app's version")
    }
    test("MAN-22", "quitting is not held up by a connection that goes another way, nor for ever") {
        let h = ManagerHarness()
        h.transport.failures = 1000          // its management socket never answers
        h.m.connect(h.a)
        var done = 0
        h.m.appQuitting { done += 1 }
        h.scheduler.drain(limit: 1000)
        expectEqual(done, 1, "it gave up on the socket: nothing left to wait for")
        let k = ManagerHarness()
        k.m.connect(k.a)
        var later = 0
        k.m.appQuitting { later += 1 }      // its openvpn never ends
        k.scheduler.drain(limit: 1000)
        expectEqual(later, 1, "not for ever: a deadline")
        k.scheduler.drain(limit: 1000)
        expectEqual(later, 1, "once")
    }
    test("MAN-21", "a persistent tunnel the app cannot attach to is left running") {
        let h = ManagerHarness()
        let site = Profile(name: "site", path: "/L/config-auto/site.ovpn", source: .persistent, folder: "")
        h.m.profiles = [site]
        h.helper.running = [ConnectionInfo(id: "P1", name: "site", pid: 1, managementSocket: "/run/P1/m.sock", ownerUID: 0, persistent: true)]
        h.transport.failures = 1000
        h.m.connect(site)
        h.scheduler.drain(limit: 500)
        expectEqual(h.helper.stops, [], "never stopped: it is the Mac's, not this app's")
        expect(h.m.lastError[site.id] != nil)
        h.helper.releaseError = "only an administrator can attach to a persistent connection"
        h.transport.failures = 0
        h.m.connect(site)
        expectEqual(h.transport.links.count, 0, "not attached when the helper says no")
        expect(h.m.lastError[site.id]?.contains("administrator") == true)
    }
    test("MAN-20", "attaching to a persistent tunnel: the helper lets go of its management first; its tunnel requests go to the helper") {
        let h = ManagerHarness()
        let site = Profile(name: "site", path: "/L/config-auto/site.ovpn", source: .persistent, folder: "")
        h.m.profiles = [site]
        h.helper.running = [ConnectionInfo(id: "P1", name: "site", pid: 1, managementSocket: "/run/P1/m.sock", ownerUID: 0, persistent: true)]
        h.m.connect(site)
        expectEqual(h.helper.released, ["P1"])
        expectEqual(h.transport.attempts, ["/run/P1/m.sock"], "then the app connects")
        let l = h.link("P1")!
        l.push(">NEED-OK:Need 'ROUTE' confirmation MSG:10.20.0.0 255.255.0.0 10.8.0.1\r\n")
        expectEqual(h.helper.tunnelRequests.map(\.id), ["P1"])
    }
    test("MAN-19", "openvpn's tunnel requests go to the helper with the connection's id") {
        let h = ManagerHarness()
        h.m.connect(h.a)
        let l = h.link("H1")!
        l.push(">NEED-OK:Need 'OPENTUN' confirmation MSG:tun\r\n")
        l.push(">NEED-OK:Need 'ROUTE' confirmation MSG:10.20.0.0 255.255.0.0 10.8.0.1\r\n")
        expectEqual(h.helper.tunnelRequests.map(\.id), ["H1", "H1"])
        expectEqual(h.helper.tunnelRequests.map(\.kind), ["OPENTUN", "ROUTE"])
        expectEqual(l.passed, [77], "the descriptor passed on the socket")
        expect(l.written.contains("needok 'OPENTUN' ok") && l.written.contains("needok 'ROUTE' ok"), "\(l.written)")
    }
    test("MAN-01", "connect: helper, socket, attach") {
        let h = ManagerHarness()
        h.m.connect(h.a)
        expectEqual(h.helper.starts.map(\.name), ["a"])
        expectEqual(h.transport.attempts, ["/run/H1/m.sock"])
        expectEqual(h.link("H1")?.written, ["state on", "log on all", "bytecount 5", "hold off", "hold release"])
        expectEqual(h.m.active["/cfg/a.ovpn"]?.controller.status, .connecting(""))
        expectEqual(h.m.active["/cfg/a.ovpn"]?.controller.profile, h.a.secretsKey, "secrets by profile (PRF-16)")
    }
    test("MAN-02", "socket retries, then gives up") {
        let h = ManagerHarness()
        h.transport.failures = 3
        h.m.connect(h.a)
        h.scheduler.drain()
        expectEqual(h.transport.attempts.count, 4)
        expect(h.link("H1") != nil, "opened on the 4th try")
        let g = ManagerHarness()
        g.transport.failures = 1000
        g.m.connect(g.a)
        g.scheduler.drain()
        expectEqual(g.transport.attempts.count, 50, "0.2 s apart for 10 s")
        expectEqual(g.helper.stops, ["H1"])
        expect(g.m.active["/cfg/a.ovpn"] == nil)
        expect(g.m.lastError["/cfg/a.ovpn"]?.contains("management") == true)
    }
    test("MAN-03", "refused or unreadable profile") {
        let h = ManagerHarness()
        h.helper.refuse = "line 3: up: runs a program as root"
        h.m.connect(h.a)
        expect(h.transport.attempts.isEmpty)
        expect(h.m.active.isEmpty)
        expectEqual(h.m.lastError["/cfg/a.ovpn"], "line 3: up: runs a program as root")
        let r = ManagerHarness()
        r.reader.broken = ["/cfg/b.ovpn"]
        r.m.connect(r.b)
        expect(r.helper.starts.isEmpty)
        expect(r.m.lastError["/cfg/b.ovpn"]?.contains("cannot read") == true)
    }
    test("MAN-04", "connect twice starts once") {
        let h = ManagerHarness()
        h.m.connect(h.a)
        h.m.connect(h.a)
        expectEqual(h.helper.starts.count, 1)
    }
    test("MAN-05", "disconnect, then gone when openvpn ends") {
        let h = ManagerHarness()
        h.m.connect(h.a)
        h.m.disconnect("/cfg/a.ovpn")
        expectEqual(h.helper.stops, ["H1"])
        expect(h.m.active["/cfg/a.ovpn"] != nil, "still there until openvpn exits")
        h.link("H1")?.push(">STATE:1,EXITING,SIGTERM,,,,,\n")
        h.link("H1")?.onClose()
        expect(h.m.active["/cfg/a.ovpn"] == nil)
        expect(h.m.lastError["/cfg/a.ovpn"] == nil, "a requested stop is not an error")
    }
    test("MAN-06", "disconnect all") {
        let h = ManagerHarness()
        h.m.connect(h.a)
        h.m.connect(h.b)
        h.m.disconnectAll()
        expectEqual(Set(h.helper.stops), ["H1", "H2"])
    }
    test("MAN-07", "pick up tunnels the helper still runs") {
        let h = ManagerHarness()
        h.helper.running = [ConnectionInfo(id: "OLD", name: "b", pid: 9, managementSocket: "/run/OLD/m.sock", ownerUID: 501),
                            ConnectionInfo(id: "GONE", name: "zzz", pid: 9, managementSocket: "/run/GONE/m.sock", ownerUID: 501)]
        h.m.appStarted()
        expectEqual(h.helper.starts.count, 0)
        expectEqual(h.m.active["/cfg/b.ovpn"]?.helperID, "OLD")
        expectEqual(h.transport.links["/run/OLD/m.sock"]?.written.first, "state on")
        expectEqual(h.helper.stops, ["GONE"], "a tunnel for a profile that no longer exists is stopped")
    }
    test("MAN-08", "quit remembers and stops; the next start reconnects") {
        let h = ManagerHarness()
        h.m.connect(h.a)
        var done = false
        h.m.appQuitting { done = true }
        expectEqual(h.memory.remembered, ["/cfg/a.ovpn"])
        expectEqual(h.helper.stops, ["H1"])
        h.link("H1")?.onClose()
        expect(done, "quit completes once every tunnel has ended")
        let next = ManagerHarness()
        next.memory.remembered = ["/cfg/a.ovpn", "/cfg/missing.ovpn"]
        next.m.appStarted()
        expectEqual(next.helper.starts.map(\.name), ["a"])
        expectEqual(next.memory.remembered, [], "used once")
    }
    test("MAN-09", "socket data to events, commands to the socket") {
        let h = ManagerHarness()
        h.m.connect(h.a)
        h.link("H1")?.push(">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,1.2.3.4,1194,,\n")
        expectEqual(h.m.active["/cfg/a.ovpn"]?.controller.status, .connected(ip: "10.8.0.2", ipv6: "", withErrors: false))
        h.link("H1")?.push(">PASSWORD:Need 'Auth' username/password\n")
        h.ui.credentialsReply?(CredentialsAnswer(username: "u", password: "p", save: false))
        expectEqual(Array(h.link("H1")?.written.suffix(2) ?? []), ["username \"Auth\" \"u\"", "password \"Auth\" \"p\""])
        h.link("H1")?.onClose()
        expect(h.m.active["/cfg/a.ovpn"] == nil)
        expect(h.m.lastError["/cfg/a.ovpn"] != nil, "an unexpected end is reported")
    }
    test("MAN-15", "disconnect before the helper answered") {
        let h = ManagerHarness()
        h.helper.deferStarts = true
        h.m.connect(h.a)
        h.m.disconnect("/cfg/a.ovpn")
        expect(h.helper.stops.isEmpty, "nothing to stop yet")
        h.helper.answerStarts()
        expectEqual(h.helper.stops, ["H1"])
        expect(h.m.active.isEmpty, "gone at once: no socket will ever close for it")
        expect(h.transport.attempts.isEmpty, "the socket is not opened")
        let q = ManagerHarness()
        q.helper.deferStarts = true
        q.m.connect(q.a)
        var done = false
        q.m.appQuitting { done = true }
        q.helper.answerStarts()
        expect(done, "quitting does not wait for it")
    }
    test("MAN-10", "reconnect") {
        let h = ManagerHarness()
        h.m.connect(h.a)
        h.m.reconnect("/cfg/a.ovpn")
        expectEqual(h.link("H1")?.written.last, "signal SIGUSR1")
    }
}

final class FakeScripts: ScriptExecutor {
    var runs: [(plan: ScriptRunner.Plan, env: [String: String])] = []
    var pending: [(ScriptRunner.Exit) -> Void] = []
    func run(_ plan: ScriptRunner.Plan, env: [String: String], completion: @escaping (ScriptRunner.Exit) -> Void) {
        runs.append((plan, env))
        pending.append(completion)
    }
    func finish(_ exit: ScriptRunner.Exit) { pending.removeFirst()(exit) }
}

final class ScriptHarness {
    let base = ManagerHarness()
    let scripts = FakeScripts()
    var present: Set<String> = []
    lazy var m: ConnectionManager = {
        let m = ConnectionManager(helper: base.helper, transport: base.transport, reader: base.reader, scheduler: base.scheduler,
                                  secrets: FakeSecrets(), settings: { ConnectionSettings() }, ui: { [ui = base.ui] _ in ui },
                                  memory: base.memory,
                                  scripts: ScriptSupport(executor: scripts, settings: { Settings() }, logsDir: "/logs",
                                                         entries: { [unowned self] dir in
                                                             self.present.filter { ($0 as NSString).deletingLastPathComponent == dir }
                                                                 .map { ($0 as NSString).lastPathComponent }
                                                         }))
        m.profiles = [a]
        return m
    }()
    let a = Profile(name: "a", path: "/cfg/a.ovpn", source: .user, folder: "")
    func link() -> FakeLink? { base.link("H1") }
}

func registerScriptManagerTests() {
    test("MAN-11", "pre-connect script") {
        let h = ScriptHarness()
        h.present = ["/cfg/a_pre.sh"]
        h.m.connect(h.a)
        expectEqual(h.scripts.runs.map(\.plan.path), ["/cfg/a_pre.sh"])
        expect(h.base.helper.starts.isEmpty, "not before the script ends")
        h.scripts.finish(.exited(0))
        expectEqual(h.base.helper.starts.count, 1)
        let f = ScriptHarness()
        f.present = ["/cfg/a_pre.sh"]
        f.m.connect(f.a)
        f.scripts.finish(.exited(2))
        expect(f.base.helper.starts.isEmpty)
        expect(f.m.active.isEmpty)
        expect(f.m.lastError["/cfg/a.ovpn"]?.contains("pre-connect script") == true)
        let t = ScriptHarness()
        t.present = ["/cfg/a_pre.sh"]
        t.m.connect(t.a)
        t.scripts.finish(.timedOut)
        expect(t.base.helper.starts.isEmpty, "a timeout cancels too")
    }
    test("MAN-12", "connect script") {
        let h = ScriptHarness()
        h.present = ["/cfg/a_up.sh"]
        h.m.connect(h.a)
        expect(h.scripts.runs.isEmpty, "not before CONNECTED")
        h.link()?.push(">ECHO:1,setenv SITE berlin\n")
        h.link()?.push(">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,1.2.3.4,1194,,\n")
        expectEqual(h.scripts.runs.map(\.plan.path), ["/cfg/a_up.sh"])
        expectEqual(h.scripts.runs.first?.env["ifconfig_local"], "10.8.0.2")
        expectEqual(h.scripts.runs.first?.env["PUSHED_SITE"], "berlin")
        h.scripts.finish(.exited(1))
        expectEqual(h.m.active["/cfg/a.ovpn"]?.controller.status, .connected(ip: "10.8.0.2", ipv6: "", withErrors: true))
        h.link()?.push(">STATE:1700000001,RECONNECTING,ping-restart,,,,,\n>STATE:1700000002,CONNECTED,SUCCESS,10.8.0.2,1.2.3.4,1194,,\n")
        expectEqual(h.scripts.runs.count, 1, "once per connection, not per reconnect")
    }
    test("MAN-13", "disconnect script") {
        let h = ScriptHarness()
        h.present = ["/cfg/a_down.sh"]
        h.m.connect(h.a)
        h.link()?.push(">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,1.2.3.4,1194,,\n")
        h.m.disconnect("/cfg/a.ovpn")
        expectEqual(h.scripts.runs.map(\.plan.path), ["/cfg/a_down.sh"])
        expect(h.base.helper.stops.isEmpty, "the tunnel stays up while the script runs")
        h.scripts.finish(.exited(1))
        expectEqual(h.base.helper.stops, ["H1"], "then it stops, whatever the script returned")
        let lost = ScriptHarness()
        lost.present = ["/cfg/a_down.sh"]
        lost.m.connect(lost.a)
        lost.link()?.onClose()
        expect(lost.scripts.runs.isEmpty, "no down script when openvpn is already gone")
    }
}

func registerPowerTests() {
    func up(_ h: ManagerHarness, _ p: Profile, _ id: String) {
        h.m.connect(p)
        h.link(id)?.push(">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,1.2.3.4,1194,,\n")
    }
    test("PWR-01", "wake reconnects at once") {
        let h = ManagerHarness()
        up(h, h.a, "H1")
        h.m.connect(h.b)
        h.link("H2")?.push(">STATE:1700000000,RECONNECTING,ping-restart,,,,,\n")
        h.m.handle(.didWake, disconnectOnSleep: false)
        expectEqual(h.link("H1")?.written.last, "signal SIGUSR1")
        expectEqual(h.link("H2")?.written.last, "signal SIGUSR1")
    }
    test("PWR-02", "disconnect on sleep, connect again on wake") {
        let h = ManagerHarness()
        up(h, h.a, "H1")
        h.m.handle(.willSleep, disconnectOnSleep: true)
        expectEqual(h.helper.stops, ["H1"])
        h.link("H1")?.onClose()
        expect(h.m.active.isEmpty)
        expect(h.m.lastError.isEmpty, "a stop for sleep is not an error")
        h.m.handle(.didWake, disconnectOnSleep: true)
        expectEqual(h.helper.starts.map(\.name), ["a", "a"])
        let n = ManagerHarness()
        up(n, n.a, "H1")
        n.m.handle(.willSleep, disconnectOnSleep: false)
        expect(n.helper.stops.isEmpty, "off by default: tunnels stay")
    }
    test("PWR-03", "network changes, debounced") {
        let h = ManagerHarness()
        up(h, h.a, "H1")
        h.m.handle(.networkChanged, disconnectOnSleep: false)
        h.m.handle(.networkChanged, disconnectOnSleep: false)
        h.m.handle(.networkChanged, disconnectOnSleep: false)
        expect(h.link("H1")?.written.last != "signal SIGUSR1", "not at once")
        expectEqual(h.scheduler.pending.map(\.0).filter { $0 != ConnectionManager.helperStartTimeout }, [2], "one timer")
        h.scheduler.drain()
        expectEqual(h.link("H1")?.written.filter { $0 == "signal SIGUSR1" }.count, 1)
    }
    test("PWR-04", "no tunnels, nothing to do") {
        let h = ManagerHarness()
        h.m.handle(.didWake, disconnectOnSleep: true)
        h.m.handle(.networkChanged, disconnectOnSleep: false)
        h.scheduler.drain()
        expect(h.helper.starts.isEmpty && h.helper.stops.isEmpty)
    }
    test("PWR-05", "a tunnel being disconnected is left alone") {
        let h = ManagerHarness()
        up(h, h.a, "H1")
        h.m.disconnect("/cfg/a.ovpn")
        h.m.handle(.didWake, disconnectOnSleep: false)
        expect(h.link("H1")?.written.last != "signal SIGUSR1")
    }
}

func registerSplitDNSTests() {
    test("MAN-16", "split DNS flag goes into the bundle") {
        let h = ManagerHarness()
        h.m.splitDNS = { $0.id == "/cfg/a.ovpn" }
        h.m.connect(h.a)
        h.m.connect(h.b)
        expectEqual(h.helper.starts.map(\.splitDNS), [true, false])
        expectEqual(h.helper.starts[0].config, "client\ndev tun\n", "the profile text is not changed")
    }
    test("MAN-18", "the connection's protection goes into the bundle") {
        let h = ManagerHarness()
        h.m.protection = { $0.name == "a" ? ProtectionOptions(killSwitch: true, blockIPv6: true, dnsOnlyTunnel: true, allowLAN: true)
                                          : ProtectionOptions() }
        h.m.connect(h.a)
        h.m.connect(h.b)
        expectEqual(h.helper.starts.map(\.protection), [ProtectionOptions(killSwitch: true, blockIPv6: true, dnsOnlyTunnel: true, allowLAN: true),
                                                       ProtectionOptions()])
    }
}

func registerPersistentAppTests() {
    let site = Profile(name: "site", path: "/auto/site.ovpn", source: .persistent, folder: "")
    func harness(_ mode: PersistentConnections) -> ManagerHarness {
        let h = ManagerHarness()
        h.m.profiles = [h.a, site]
        h.m.persistentMode = { mode }
        return h
    }
    let runningSite = ConnectionInfo(id: "P0", name: "site", pid: 7, managementSocket: "/run/P0/m.sock", ownerUID: 0,
                                     persistent: true, managementPassword: "pw0")
    test("PER-08", "attach to running persistent tunnels by the setting; never stop them") {
        let auto = harness(.auto)
        auto.helper.running = [runningSite]
        auto.m.appStarted()
        expectEqual(auto.m.active["/auto/site.ovpn"]?.helperID, "P0")
        expectEqual(Array(auto.transport.links["/run/P0/m.sock"]?.written.prefix(2) ?? []), ["pw0", "state on"],
                    "PER-08c: the password first")
        expect(auto.helper.stops.isEmpty)
        for mode in [PersistentConnections.manual, .disable] {
            let h = harness(mode)
            h.helper.running = [runningSite]
            h.m.appStarted()
            expect(h.m.active.isEmpty, "\(mode): not attached")
            expect(h.helper.stops.isEmpty, "\(mode): not stopped")
        }
        let gone = harness(.auto)
        gone.m.profiles = [gone.a]
        gone.helper.running = [runningSite]
        gone.m.appStarted()
        expect(gone.helper.stops.isEmpty, "a persistent tunnel without a local profile is not ours to stop")
    }
    test("PER-08b", "connect a persistent profile: attach if running, else start it") {
        let h = harness(.manual)
        h.helper.running = [runningSite]
        h.m.connect(site)
        expect(h.helper.persistentStarts.isEmpty && h.helper.starts.isEmpty)
        expectEqual(h.m.active["/auto/site.ovpn"]?.helperID, "P0")
        let s = harness(.auto)
        s.m.connect(site)
        expectEqual(s.helper.persistentStarts, ["site"])
        expectEqual(s.m.active["/auto/site.ovpn"]?.helperID, "P1")
        expect(s.transport.links["/run/P1/m.sock"] != nil)
        let r = harness(.auto)
        r.helper.refusePersistent = "only an administrator can start persistent connections"
        r.m.connect(site)
        expect(r.m.active.isEmpty)
        expect(r.m.lastError["/auto/site.ovpn"]?.contains("administrator") == true)
    }
    test("PER-10", "quitting detaches from persistent tunnels") {
        let h = harness(.auto)
        h.helper.running = [runningSite]
        h.m.appStarted()
        h.m.connect(h.a)
        var done = false
        h.m.appQuitting { done = true }
        expectEqual(h.helper.stops, ["H1"], "only the user's own tunnel stops")
        expectEqual(h.memory.remembered, ["/cfg/a.ovpn"])
        expect(h.transport.links["/run/P0/m.sock"]?.closed == true, "management closed")
        h.link("H1")?.onClose()
        expect(done, "quit does not wait for the persistent one")
    }
    test("PER-09", "disconnect a persistent tunnel") {
        let h = harness(.auto)
        h.helper.running = [runningSite]
        h.m.appStarted()
        h.m.disconnect("/auto/site.ovpn")
        expectEqual(h.helper.stops, ["P0"])
        h.transport.links["/run/P0/m.sock"]?.onClose()
        expect(h.m.active.isEmpty)
        expect(h.m.profiles.contains(site))
        expect(h.m.lastError.isEmpty)
    }
}

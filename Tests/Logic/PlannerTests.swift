import Foundation
import MugVPNCore
import MugVPNPlanner

// The planner's decisions on their own (both products apply them).

private func facts(_ id: String, key: String? = nil, owner: UInt32 = 501, persistent: Bool = false, exited: Bool = false,
                   kill: Bool = false, lan: Bool = false, ipv6: Bool = false, dns: Bool = false, full: Bool = false,
                   wasGuarded: Bool = false, lifts: Bool = false, device: String? = nil) -> ProtectionFacts {
    ProtectionFacts(id: id, lockKey: key ?? id, lockNames: [key ?? id], owner: owner, persistent: persistent, exited: exited,
                    protection: ProtectionOptions(killSwitch: kill, blockIPv6: ipv6, dnsOnlyTunnel: dns, allowLAN: lan),
                    takesAllTraffic: full, wasGuarded: wasGuarded, liftsBlock: lifts, device: device, restricted: false, dnsServers: [])
}

func registerPlannerTests() {
    test("PLAN-01", "armings: one per name and user taking all traffic with a kill switch; the LAN open only if all allow it") {
        let a = ProtectionPlanner.arming([facts("1", key: "office", kill: true, lan: true, wasGuarded: true),
                                          facts("2", key: "office", kill: true, lan: false, wasGuarded: true),
                                          facts("3", key: "home", kill: true, wasGuarded: false),
                                          facts("4", key: "lab", kill: true, wasGuarded: true)])
        expectEqual(a.map(\.name), ["office", "lab"])
        expectEqual(a.first?.allowLAN, false)
        expect(a.allSatisfy(\.armed))
    }
    test("PLAN-02", "a block added: merged to the stricter, a user's oldest fired blocks go past the limit") {
        var locks: [ProtectionLock] = []
        locks = ProtectionPlanner.adding(ProtectionLock(name: "a", owner: 501, allowLAN: true), to: locks)
        locks = ProtectionPlanner.adding(ProtectionLock(name: "a", owner: 501, allowLAN: false), to: locks)
        expectEqual(locks.count, 1)
        expectEqual(locks.first?.allowLAN, false)
        for n in ["b", "c", "d", "e"] { locks = ProtectionPlanner.adding(ProtectionLock(name: n, owner: 501), to: locks) }
        expectEqual(locks.map(\.name), ["b", "c", "d", "e"], "at most \(ProtectionPlanner.maxLocksPerUser), the oldest gone")
    }
    test("PLAN-03", "the plan: IPv6 and DNS blocks while a protected tunnel takes all traffic; its block goes when its owner connects it again") {
        let fired = ProtectionLock(name: "office", owner: 501)
        let p = ProtectionPlanner.plan([facts("1", key: "office", kill: true, ipv6: true, dns: true, full: true, lifts: true, device: "utun4")],
                                       locks: [fired], suspended: [:], now: 100)
        expect(p.state.blockIPv6 && p.state.dnsOnlyTunnels)
        expectEqual(p.state.tunnels, ["utun4"])
        expectEqual(p.nowGuarded, ["1"])
        expectEqual(p.liftDone, ["1"])
        expect(p.locksChanged)
        expectEqual(p.locks, [ProtectionLock(name: "office", owner: 501, armed: true)], "the fired block gone, the arming there")
        expect(p.state.locks.isEmpty)
    }
    test("PLAN-04", "a block lifted for a while: not enforced until its time, then again") {
        let fired = ProtectionLock(name: "office", owner: 501)
        let key = ProtectionPlanner.suspendKey(fired)
        let during = ProtectionPlanner.plan([], locks: [fired], suspended: [key: 200], now: 100)
        expect(during.state.locks.isEmpty)
        let after = ProtectionPlanner.plan([], locks: [fired], suspended: [key: 200], now: 201)
        expectEqual(after.state.locks.count, 1)
        expect(after.suspended.isEmpty)
    }
    test("PLAN-05", "who lifts blocks: owners theirs, administrators all; a persistent connection's only an administrator") {
        let mine = ProtectionLock(name: "a", owner: 501), theirs = ProtectionLock(name: "b", owner: 502)
        let everyone = ProtectionLock(name: "site", owner: 0, everyone: true)
        if case .success(let left) = ProtectionPlanner.unblocking([mine, theirs], uid: 501, admin: false) { expectEqual(left, [theirs]) } else { expect(false) }
        if case .failure = ProtectionPlanner.unblocking([theirs], uid: 501, admin: false) {} else { expect(false, "not theirs") }
        if case .success(let left) = ProtectionPlanner.unblocking([mine, theirs], uid: 0, admin: true) { expect(left.isEmpty) } else { expect(false) }
        if case .failure = ProtectionPlanner.suspension([mine, everyone], uid: 501, admin: false) {} else { expect(false, "a persistent block stays") }
        if case .success(let lift) = ProtectionPlanner.suspension([mine, everyone], uid: 0, admin: true) { expectEqual(lift.count, 2) } else { expect(false) }
    }
    test("PLAN-06", "routes: a standard user only private and listed networks, nothing narrower than the LAN; between connections no taking another's") {
        func net(_ n: String) -> IPv4Net { let p = n.split(separator: "/"); return IPv4Net(address: TunnelState.ipv4(p[0])!, prefix: Int(p[1])!) }
        let r = { (n: String, m: String) in TunnelRoute(kind: .tunnel, net: n, mask: m, via: "utun4") }
        var std = ConnectionLimits(restricted: true, mayRouteAll: false, mayChangeDNS: false)
        expectThrows("public, not listed", matching: "administrator") {
            try NetworkPolicy.checkRoutes([r("8.8.8.0", "255.255.255.0")], tunnel: TunnelState(), owner: 501, limits: std, others: [], lan4: [], message: "")
        }
        std.allowed.networks4 = [net("8.8.8.0/24")]
        try NetworkPolicy.checkRoutes([r("8.8.8.0", "255.255.255.0")], tunnel: TunnelState(), owner: 501, limits: std, others: [], lan4: [], message: "")
        expectThrows("narrower than the LAN", matching: "the Mac's own") {
            try NetworkPolicy.checkRoutes([r("192.168.1.0", "255.255.255.128")], tunnel: TunnelState(), owner: 501, limits: std,
                                          others: [], lan4: [net("192.168.1.0/24")], message: "")
        }
        var theirs = TunnelState()
        theirs.device = "utun4"
        _ = try theirs.ifconfig("10.9.0.2 255.255.255.0 1500 subnet")
        _ = try theirs.route("10.50.0.0 255.255.0.0 10.9.0.1", gateway: nil)
        let other = OtherConnection(owner: 502, exited: false, tunnel: theirs)
        expectThrows("inside another user's", matching: "another user's tunnel") {
            try NetworkPolicy.checkRoutes([r("10.50.1.0", "255.255.255.0")], tunnel: TunnelState(), owner: 501, limits: ConnectionLimits(),
                                          others: [other], lan4: [], message: "")
        }
        // The same user's own networks may nest (two of one's own tunnels).
        try NetworkPolicy.checkRoutes([r("10.50.1.0", "255.255.255.0")], tunnel: TunnelState(), owner: 501, limits: ConnectionLimits(),
                                      others: [OtherConnection(owner: 501, exited: false, tunnel: theirs)], lan4: [], message: "")
    }
    test("PLAN-07", "DNS: a standard user's servers inside its own tunnel, not the Mac's resolvers; all names only when allowed") {
        var t = TunnelState()
        t.device = "utun4"
        _ = try t.ifconfig("10.8.0.2 255.255.255.0 1500 subnet")
        t.subnetRoute = TunnelRoute(kind: .tunnel, net: "10.8.0.0", mask: "255.255.255.0", via: "utun4")   // its network's route in
        var std = ConnectionLimits(restricted: true, mayRouteAll: false, mayChangeDNS: false)
        std.allowed.domains = ["corp.lan"]
        let inside = DNSPlan(device: "utun4", servers: ["10.8.0.1"], matchDomains: ["corp.lan"], searchDomains: [], split: true)
        try NetworkPolicy.checkDNS(inside, tunnel: t, limits: std, lan4: [], systemResolvers: { ["192.168.1.1"] })
        expectThrows("a domain not listed", matching: "DNS for other.lan") {
            try NetworkPolicy.checkDNS(DNSPlan(device: "utun4", servers: ["10.8.0.1"], matchDomains: ["other.lan"], searchDomains: [], split: true),
                                       tunnel: t, limits: std, lan4: [], systemResolvers: { [] })
        }
        expectThrows("all names", matching: "DNS for all names") {
            try NetworkPolicy.checkDNS(DNSPlan(device: "utun4", servers: ["10.8.0.1"], matchDomains: [], searchDomains: [], split: false),
                                       tunnel: t, limits: std, lan4: [], systemResolvers: { [] })
        }
        expectThrows("outside its tunnel", matching: "not inside this tunnel") {
            try NetworkPolicy.checkDNS(DNSPlan(device: "utun4", servers: ["1.1.1.1"], matchDomains: ["corp.lan"], searchDomains: [], split: true),
                                       tunnel: t, limits: std, lan4: [], systemResolvers: { [] })
        }
        expectThrows("resolvers unknown", matching: "not known") {
            try NetworkPolicy.checkDNS(inside, tunnel: t, limits: std, lan4: [], systemResolvers: { nil })
        }
    }
    test("PLAN-08", "DNS between connections: another user's domain refused (a part of it too); all names to who has none, then who asked first") {
        var theirs = TunnelState()
        theirs.dnsApplied = true
        theirs.dnsDomains = ["corp.example"]
        let other = OtherConnection(owner: 502, exited: false, tunnel: theirs)
        expectEqual(NetworkPolicy.domainAnsweredByAnotherUser(["a.corp.example."], owner: 501, others: [other]), "a.corp.example.")
        expectEqual(NetworkPolicy.domainAnsweredByAnotherUser(["corp.example"], owner: 502, others: [other]), nil, "one's own")
        let p = { (s: [String]) in DNSPlan(device: "utun4", servers: ["10.8.0.1"], matchDomains: [], searchDomains: s, split: false) }
        expectEqual(NetworkPolicy.allNamesOrder([(item: "b", plan: p(["b.lan"]), order: 1), (item: "c", plan: p([]), order: 3),
                                                 (item: "a", plan: p([]), order: 2)]), ["a", "c", "b"])
        var all = TunnelState()
        all.dnsApplied = true
        expect(NetworkPolicy.allNamesHeld(by: [OtherConnection(owner: 1, exited: false, tunnel: all)]))
        expect(!NetworkPolicy.allNamesHeld(by: [OtherConnection(owner: 1, exited: true, tunnel: all)]))
    }
    test("PLAN-09", "a session's typed network: private address and network, hosts outside one each, none in another's tunnel, IPv6 not the Mac's") {
        func ip(_ s: String) -> UInt32 { TunnelState.ipv4(Substring(s))! }
        var a = SessionNetwork()
        a.local4 = ip("10.81.0.2"); a.prefix4 = 24
        a.routes4 = SessionNetwork.halves
        a.outside4 = [ip("198.51.100.7")]
        try NetworkPolicy.checkSession(a, others: [], lan4: [], lan6: [])
        expect(a.takesAllTraffic)
        var pub = a; pub.local4 = ip("8.8.8.8")
        expectThrows("public address", matching: "private") { try NetworkPolicy.checkSession(pub, others: [], lan4: [], lan6: []) }
        expectThrows("in the LAN", matching: "the Mac's own") {
            try NetworkPolicy.checkSession(a, others: [], lan4: [IPv4Net(address: ip("10.81.0.0"), prefix: 16)], lan6: [])
        }
        var loop = a; loop.outside4 = [ip("127.0.0.1")]
        expectThrows("loopback outside", matching: "single host") { try NetworkPolicy.checkSession(loop, others: [], lan4: [], lan6: []) }
        var b = SessionNetwork()
        b.local4 = ip("10.82.0.2"); b.prefix4 = 24
        b.routes4 = [IPv4Net(address: ip("198.51.100.0"), prefix: 24)]
        expectThrows("a's server inside b's network", matching: "another connection's") {
            try NetworkPolicy.checkSession(a, others: [b], lan4: [], lan6: [])
        }
        expectThrows("b's network takes a's server", matching: "another connection's host route") {
            try NetworkPolicy.checkSession(b, others: [a], lan4: [], lan6: [])
        }
        var six = a; six.outside4 = []; six.local6 = "fd00:85::1000"; six.prefix6 = 64
        try NetworkPolicy.checkSession(six, others: [], lan4: [], lan6: [])
        expectThrows("the Mac's own IPv6", matching: "the Mac's own") { try NetworkPolicy.checkSession(six, others: [], lan4: [], lan6: ["fd00:85::/48"]) }
    }
    test("PLAN-10", "DNS assignment: all names to the one without domains of its own, the other limited to its own, whatever the order") {
        let a = DNSAssignment.Want(id: "a", servers: ["10.81.0.1"], domains: [], searchDomains: ["corp.example"], order: 1)
        let b = DNSAssignment.Want(id: "b", servers: ["10.82.0.1"], domains: [], searchDomains: [], order: 2)
        let split = DNSAssignment.Want(id: "s", servers: ["10.83.0.1"], domains: ["c.test"], searchDomains: [], order: 3)
        for wants in [[a, b, split], [split, b, a]] {
            let r = DNSAssignment.assign(wants)
            expectEqual(r.states, ["a": .limited, "b": .all, "s": .split])
            expectEqual(r.domains["a"], ["corp.example"])
            expectEqual(r.domains["b"], [])
        }
        var b2 = b; b2.id = "b2"; b2.order = 0
        let r = DNSAssignment.assign([b, b2])
        expectEqual(r.states, ["b2": .all, "b": .waiting], "two without domains: who asked first, the other waits")
        expectEqual(r.domains["b"], nil)
    }
    test("PLAN-11", "a split connection with everything outside it blocked while it is up (the App Store build's strict kill switch): armed once up, its block goes when it is up again; without that, a split one does neither (as before)") {
        let fired = ProtectionLock(name: "office", owner: 501)
        var f = facts("1", key: "office", kill: true, lifts: true, device: "utun4")
        f.blocksAllOutside = true
        let p = ProtectionPlanner.plan([f], locks: [fired], suspended: [:], now: 100)
        expectEqual(p.liftDone, ["1"])
        expectEqual(p.nowGuarded, ["1"], "armed from now on")
        expectEqual(p.locks, [ProtectionLock(name: "office", owner: 501, armed: true)], "the fired block gone, the arming there")
        expect(!p.state.blockIPv6 && !p.state.dnsOnlyTunnels, "IPv6 and DNS rules stay those of tunnels taking all traffic")
        let q = ProtectionPlanner.plan([facts("1", key: "office", kill: true, lifts: true, device: "utun4")], locks: [fired], suspended: [:], now: 100)
        expect(q.liftDone.isEmpty && q.nowGuarded.isEmpty)
        expectEqual(q.locks, [fired], "a split one without it: the block stays")
    }
}

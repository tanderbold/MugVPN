import Foundation
import MugVPNCore
import MugVPNPlanner

// The planner's decisions on their own (both products apply them).

private func facts(_ id: String, key: String? = nil, owner: UInt32 = 501, persistent: Bool = false, exited: Bool = false,
                   kill: Bool = false, lan: Bool = false, ipv6: Bool = false, dns: Bool = false, full: Bool = false,
                   wasFull: Bool = false, lifts: Bool = false, device: String? = nil) -> ProtectionFacts {
    ProtectionFacts(id: id, lockKey: key ?? id, lockNames: [key ?? id], owner: owner, persistent: persistent, exited: exited,
                    protection: ProtectionOptions(killSwitch: kill, blockIPv6: ipv6, dnsOnlyTunnel: dns, allowLAN: lan),
                    takesAllTraffic: full, wasFull: wasFull, liftsBlock: lifts, device: device, restricted: false, dnsServers: [])
}

func registerPlannerTests() {
    test("PLAN-01", "armings: one per name and user taking all traffic with a kill switch; the LAN open only if all allow it") {
        let a = ProtectionPlanner.arming([facts("1", key: "office", kill: true, lan: true, wasFull: true),
                                          facts("2", key: "office", kill: true, lan: false, wasFull: true),
                                          facts("3", key: "home", kill: true, wasFull: false),
                                          facts("4", key: "lab", kill: true, wasFull: true)])
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
        expectEqual(p.nowFull, ["1"])
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
}

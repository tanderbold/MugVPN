import Foundation
import MugVPNCore
import MugVPNHelperCore

private func protectedBundle(_ name: String = "office", kill: Bool = true, ipv6: Bool = false, dns: Bool = false,
                             lan: Bool = false) -> Data {
    var b = ProfileBundle(name: name, config: "client\ndev tun\nremote vpn.example.com 1194 udp", files: [:])
    b.protection = ProtectionOptions(killSwitch: kill, blockIPv6: ipv6, dnsOnlyTunnel: dns, allowLAN: lan)
    return try! JSONEncoder().encode(b)
}

/// openvpn's log once a tunnel that takes all traffic is up.
private func fullLog(_ dev: String) -> Data { Data(sampleLog(device: dev).utf8) }

private func lastAnchor(_ sys: FakeSystem) -> String { sys.pf.last ?? "" }

/// What openvpn asks for to bring up a tunnel that takes all traffic (def1).
func bringUp(_ sys: FakeSystem, _ h: HelperCore, _ id: String, uid: UInt32 = 501, device: String = "utun5",
             routes: [String] = ["0.0.0.0 128.0.0.0 10.8.0.1", "128.0.0.0 128.0.0.0 10.8.0.1"]) throws {
    sys.utunName = device
    _ = try h.tunnelRequest(id: id, uid: uid, kind: "OPENTUN", message: "tun")
    _ = try h.tunnelRequest(id: id, uid: uid, kind: "IFCONFIG", message: "10.8.0.2 255.255.255.0 1500 subnet")
    for r in routes { _ = try h.tunnelRequest(id: id, uid: uid, kind: "ROUTE", message: r) }
}

/// Start a protected connection and bring its full tunnel up.
private func upFull(_ sys: FakeSystem, _ h: HelperCore, uid: UInt32 = 501, id: String = "ID1", name: String = "office",
                    lan: Bool = false) throws -> String {
    let (cid, _) = try h.start(bundle: protectedBundle(name, lan: lan), uid: uid)
    try bringUp(sys, h, cid, uid: uid)
    return cid
}

func registerProtectionHelperTests() {
    test("PROT-01", "no protection asked: PF untouched") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        _ = try h.start(bundle: bundle(), uid: 501)
        try sys.writeFile("/L/run/ID1/openvpn.log", fullLog("utun5"), mode: 0o600)
        sys.fireTimers()
        h.refreshProtection()
        expect(sys.pf.allSatisfy(\.isEmpty), "\(sys.pf)")
    }
    test("PROT-02", "kill switch armed while the full tunnel is up: nothing blocked yet, the arming kept on disk") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        _ = try upFull(sys, h)
        expect(!lastAnchor(sys).contains("user 501"), "traffic goes through the tunnel")
        let saved = String(decoding: sys.files["/L/locks.json"]?.data ?? Data(), as: UTF8.self)
        expect(saved.contains("office") && saved.contains("armed"), "survives a helper crash: \(saved)")
    }
    test("PROT-03", "an unexpected drop blocks its owner only; a requested stop lifts everything") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        _ = try upFull(sys, h)
        sys.launched[0].process.onExit(.exited(1))
        let a = lastAnchor(sys)
        expect(a.contains("block return out quick proto { tcp udp } all user 501") && !a.contains("utun5"), a)
        expect(!a.contains("user 502") && !a.contains("block return out quick all"), "other users untouched")
        expectEqual(h.locks(uid: 502), [], "another user is not blocked and does not see the owner's profiles")
        expectEqual(h.locks(uid: 501), ["office"], "its owner does")
        let s2 = FakeSystem()
        let h2 = makeHelper(s2)
        let id = try upFull(s2, h2)
        _ = h2.stop(id: id, uid: 501)
        s2.launched[0].process.onExit(.exited(0))
        expectEqual(lastAnchor(s2), "", "nothing left")
        expect(s2.files["/L/locks.json"] == nil, "the arming is gone too")
    }
    test("PROT-04", "who lifts a block") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        _ = try upFull(sys, h)
        sys.launched[0].process.onExit(.signaled(9))
        expectEqual(h.unblock(uid: 502), "only its owner or an administrator can lift the block")
        expectEqual(h.locks(uid: 0), ["office"], "an administrator sees it")
        expectEqual(h.unblock(uid: 501), nil)
        expectEqual(h.locks(uid: 501), [])
        expectEqual(lastAnchor(sys), "")
    }
    test("PROT-05", "blocks and armed kill switches survive the helper; a foreign file does not count") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        _ = try upFull(sys, h)
        // The helper dies with the tunnel up (launchd takes openvpn down with it).
        sys.pf = []
        let again = makeHelper(sys)
        try again.prepareRunDirectory()
        expect(lastAnchor(sys).contains("user 501"), "the armed kill switch fires at restart")
        expectEqual(again.locks(uid: 501), ["office"])
        let s2 = FakeSystem()
        try s2.writeFile("/L/locks.json", Data(#"[{"name":"x","owner":501,"allowLAN":false,"armed":false}]"#.utf8), mode: 0o644)
        s2.infos["/L/locks.json"] = (501, 0o644)
        try makeHelper(s2).prepareRunDirectory()
        expect(s2.pf.allSatisfy(\.isEmpty))
    }
    test("PROT-06", "DNS and IPv6 blocks only while a tunnel takes all traffic, with or without def1") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: protectedBundle(kill: false, ipv6: true, dns: true), uid: 501)
        try bringUp(sys, h, id, routes: ["10.9.0.0 255.255.255.0 10.8.0.1"])
        expect(sys.pf.allSatisfy(\.isEmpty), "a split tunnel: nothing to block")
        // A server that pushes redirect-gateway without def1.
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "ROUTEDEL", message: "0.0.0.0 0.0.0.0 192.168.64.1")
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "ROUTE", message: "0.0.0.0 0.0.0.0 10.8.0.1")
        let a = lastAnchor(sys)
        expect(a.contains("block return out quick inet6 all") && a.contains("to any port 53"), a)
    }
    test("PROT-11", "an armed kill switch stays armed while a tunnel of that name is up (ext. audit 5: P2)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        _ = try upFull(sys, h)                                    // office, armed
        _ = try? h.start(bundle: protectedBundle(), uid: 501)     // another "office"
        let saved = String(decoding: sys.files["/L/locks.json"]?.data ?? Data(), as: UTF8.self)
        expect(saved.contains("office") && saved.contains("armed"), "a second start leaves the arming: \(saved)")
        try bringUp(sys, h, "ID2", uid: 501, device: "utun6")
        _ = h.stop(id: "ID2", uid: 501)
        sys.launched[1].process.onExit(.exited(0))                // one of the two ends as asked
        let after = String(decoding: sys.files["/L/locks.json"]?.data ?? Data(), as: UTF8.self)
        expect(after.contains("office"), "the other still takes all traffic: still armed: \(after)")
    }
    test("PROT-12", "a same-named tunnel that drops does not take the arming of the one still up (ext. audit 6: P2)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        _ = try upFull(sys, h)                                    // office, armed
        let (b, _) = try h.start(bundle: protectedBundle(), uid: 501)
        try bringUp(sys, h, b, uid: 501, device: "utun6")
        sys.launched[1].process.onExit(.exited(1))                // the second drops: fired
        _ = try h.start(bundle: protectedBundle(), uid: 501)      // connecting again lifts the fired block
        // The helper dies with the first tunnel up.
        sys.pf = []
        try makeHelper(sys).prepareRunDirectory()
        expect(lastAnchor(sys).contains("user 501"), "the first's arming was kept and fires: \(sys.files["/L/locks.json"].map { String(decoding: $0.data, as: UTF8.self) } ?? "none")")
    }
    test("PROT-13", "same-named kill switches, one with the LAN allowed: the stricter holds (ext. audit 7: P2)") {
        for laxFirst in [true, false] {
            let sys = FakeSystem()
            let h = makeHelper(sys)
            _ = try upFull(sys, h, lan: laxFirst)
            let (b, _) = try h.start(bundle: protectedBundle(lan: !laxFirst), uid: 501)
            try bringUp(sys, h, b, uid: 501, device: "utun6")
            // The helper dies with both up.
            sys.pf = []
            try makeHelper(sys).prepareRunDirectory()
            expect(lastAnchor(sys).contains("all user 501"), "LAN closed (lax first: \(laxFirst)): \(lastAnchor(sys))")
        }
        // Fired ones merge the same way.
        let sys = FakeSystem()
        let h = makeHelper(sys)
        _ = try upFull(sys, h, lan: false)
        let (b, _) = try h.start(bundle: protectedBundle(lan: true), uid: 501)
        try bringUp(sys, h, b, uid: 501, device: "utun6")
        sys.launched[0].process.onExit(.exited(1))
        sys.launched[1].process.onExit(.exited(1))
        expect(lastAnchor(sys).contains("all user 501"), lastAnchor(sys))
        // The stricter one ends as asked: the arming follows the one still up.
        let s2 = FakeSystem()
        let h2 = makeHelper(s2)
        let a2 = try upFull(s2, h2, lan: true)
        let (b2, _) = try h2.start(bundle: protectedBundle(lan: false), uid: 501)
        try bringUp(s2, h2, b2, uid: 501, device: "utun6")
        _ = h2.stop(id: b2, uid: 501)
        s2.launched[1].process.onExit(.exited(0))
        s2.pf = []
        try makeHelper(s2).prepareRunDirectory()
        expect(lastAnchor(s2).contains("to ! <mugvpn_lan> user 501"), "\(a2): \(lastAnchor(s2))")
    }
    test("PROT-07", "connecting the same profile again lifts its block") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        _ = try upFull(sys, h)
        sys.launched[0].process.onExit(.exited(1))
        _ = try h.start(bundle: protectedBundle(), uid: 501)
        expectEqual(h.locks(uid: 501), [])
    }
    test("PROT-08", "bounded: short names, a few blocks per user") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        for i in 0..<6 {
            let name = "\(i)" + String(repeating: "n", count: 200)
            let (id, _) = try h.start(bundle: protectedBundle(name), uid: 501)
            try bringUp(sys, h, id, device: "utun\(i + 5)")
            sys.launched[i].process.onExit(.exited(1))
        }
        let names = h.locks(uid: 501)
        expectEqual(names.count, HelperCore.maxLocksPerUser)
        expect(names.allSatisfy { $0.count <= 64 }, "\(names.map(\.count))")
    }
    test("PROT-09", "protection is checked and put back; a failed apply is retried") {
        let sys = FakeSystem()
        sys.admins = [501, 502]  // two users who may route all traffic (the policy is not what is tested here)
        let h = makeHelper(sys)
        _ = try upFull(sys, h)
        sys.launched[0].process.onExit(.exited(1))
        let n = sys.pf.count
        sys.pfIntactAnswer = false   // someone ran pfctl -d or flushed the anchor
        h.refreshProtection()
        expectEqual(sys.pf.count, n + 1, "applied again")
        sys.pfIntactAnswer = true
        sys.pfApplyFails = true
        let (other, _) = try h.start(bundle: protectedBundle("other"), uid: 502)
        try bringUp(sys, h, other, uid: 502, device: "utun9")
        sys.pfApplyFails = false
        let m = sys.pf.count
        h.refreshProtection()
        expectEqual(sys.pf.count, m + 1, "retried after the failure")
    }
    test("PROT-10", "uninstall lifts PF and forgets blocks before removing files") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        _ = try upFull(sys, h)
        sys.launched[0].process.onExit(.exited(1))
        try h.uninstall(uid: 501, keepProfiles: true)
        expectEqual(sys.pf.last, "")
        expect(sys.files["/L/locks.json"] == nil, "a reinstall does not bring blocks back")
        expectEqual(sys.pfClearedBeforeRemoval, true)
    }
}

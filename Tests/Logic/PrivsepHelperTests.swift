import Foundation
import MugVPNCore
import MugVPNHelperCore
import MugVPNAppCore

// The helper side of privilege separation: requests from an unprivileged openvpn
// (through its owner's app), what the helper carries out, and what it undoes.

private func psBundle(kill: Bool = false) -> Data {
    var b = ProfileBundle(name: "office", config: "client\ndev tun\nremote vpn.example.com 1194 udp", files: [:])
    b.protection = ProtectionOptions(killSwitch: kill)
    return try! JSONEncoder().encode(b)
}

private func dnsUp(_ sys: FakeSystem, _ h: HelperCore, _ dev: String, _ net: String, _ vars: [String], dnsUp: Bool = true) throws -> String {
    let (id, _) = try h.start(bundle: psBundle(), uid: 501)
    sys.utunName = dev
    _ = try h.tunnelRequest(id: id, uid: 501, kind: "OPENTUN", message: "tun")
    _ = try h.tunnelRequest(id: id, uid: 501, kind: "IFCONFIG", message: "\(net).2 255.255.255.0 1500 subnet")
    for v in vars { _ = try h.tunnelRequest(id: id, uid: 501, kind: "DNSVAR", message: v) }
    if dnsUp { _ = try? h.tunnelRequest(id: id, uid: 501, kind: "DNSUP", message: dev) }
    return id
}

/// A standard user's tunnel (utun6) with split DNS for corp.lan on 10.99.0.53, inside it through the route
/// 10.99.0.0/16 or (inSubnet) its own network; routeAll: the administrator lets users route all traffic.
private func standardSplit(inSubnet: Bool = false, routeAll: Bool = false) throws -> (FakeSystem, HelperCore, String) {
    let sys = FakeSystem()
    try sys.makeDirectory("/L", mode: 0o755)
    let policy = routeAll ? #"{"usersMayChangeDNS": true, "usersMayRouteAllTraffic": true}"# : #"{"usersMayChangeDNS": true}"#
    try sys.writeFile("/L/policy.json", Data(policy.utf8), mode: 0o644)
    sys.systemDNS = ["192.168.64.1"]
    let h = makeHelper(sys)
    let (b, _) = try h.start(bundle: psBundle(), uid: 502)
    sys.utunName = "utun6"
    _ = try h.tunnelRequest(id: b, uid: 502, kind: "OPENTUN", message: "tun")
    _ = try h.tunnelRequest(id: b, uid: 502, kind: "IFCONFIG", message: "10.9.0.2 255.255.255.0 1500 subnet")
    let server = inSubnet ? "10.9.0.53" : "10.99.0.53"
    if !inSubnet { _ = try h.tunnelRequest(id: b, uid: 502, kind: "ROUTE", message: "10.99.0.0 255.255.0.0 10.9.0.1") }
    _ = try h.tunnelRequest(id: b, uid: 502, kind: "DNSVAR", message: "dns_server_1_address_1=\(server)")
    _ = try h.tunnelRequest(id: b, uid: 502, kind: "DNSVAR", message: "dns_server_1_resolve_domain_1=corp.lan")
    _ = try h.tunnelRequest(id: b, uid: 502, kind: "DNSUP", message: "utun6")
    expectEqual(sys.splitResolvers["utun6"]?.servers, [server], "set up")
    return (sys, h, b)
}

func registerPrivsepHelperTests() {
    test("PS-01", "openvpn runs as the unprivileged service user, not root") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        _ = try h.start(bundle: psBundle(), uid: 501)
        expectEqual(sys.launched[0].user?.uid, FakeSystem.serviceUser.uid, "user profiles run unprivileged")
        expectEqual(sys.launched[0].path, "/L/libexec/openvpn")
        expectEqual(sys.dirs["/L/run/ID1/sock"], 0o711, "a socket folder the service user owns")
        expectEqual(sys.owners["/L/run/ID1/sock"]?.uid, FakeSystem.serviceUser.uid)
        let c = sys.launched[0].args
        expectEqual(c[c.firstIndex(of: "--management")! + 1], "/L/run/ID1/sock/m.sock")
        expectEqual(c[c.firstIndex(of: "--tmp-dir")! + 1], "/L/run/ID1/sock", "the one folder its sandbox lets it write")
        expectEqual(sys.owners["/L/run/ID1/config.ovpn"]?.gid, FakeSystem.serviceUser.gid, "the config readable by its group")
    }
    test("PS-02", "a tunnel request: only the owner, carried out after the checks") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 501)
        expectEqual(try? h.tunnelRequest(id: id, uid: 502, kind: "OPENTUN", message: "tun").fd, nil, "not the owner")
        let r = try h.tunnelRequest(id: id, uid: 501, kind: "OPENTUN", message: "tun")
        expectEqual(r.fd, 99)
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "IFCONFIG", message: "10.8.0.2 255.255.255.0 1500 subnet")
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "ROUTE", message: "10.20.0.0 255.255.0.0 10.8.0.1")
        expectThrows("a route around the tunnel") {
            _ = try h.tunnelRequest(id: id, uid: 501, kind: "ROUTE", message: "198.51.100.0 255.255.255.0 192.168.64.1")
        }
        expectEqual(sys.commands.map { $0.first! }, ["ifconfig", "route", "route"])
        expectThrows("unknown request") { _ = try h.tunnelRequest(id: id, uid: 501, kind: "EXEC", message: "/bin/sh") }
        let state = String(decoding: sys.files["/L/run/ID1/state.json"]?.data ?? Data(), as: UTF8.self)
        expect(state.contains("utun7") && state.contains("10.20.0.0"), "kept beside the run (crash cleanup): \(state)")
    }
    test("PS-03", "DNS up and down through the helper") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 501)
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "OPENTUN", message: "tun")
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "DNSVAR", message: "dns_server_1_address_1=10.8.0.53")
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "DNSVAR", message: "dns_server_1_resolve_domain_1=corp.example.com")
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "DNSUP", message: "utun7")
        expectEqual(sys.dnsSet.map(\.device), ["utun7"])
        expect(sys.dnsSet.first?.split == true)
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "DNSDOWN", message: "utun7")
        expectEqual(sys.dnsRestored, ["utun7"])
    }
    test("PS-04", "when openvpn ends, the helper undoes what it did (not what a log says)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 501)
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "OPENTUN", message: "tun")
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "IFCONFIG", message: "10.8.0.2 255.255.255.0 1500 subnet")
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "ROUTE", message: "203.0.113.7 255.255.255.255 192.168.64.1")
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "DNSVAR", message: "dns_server_1_address_1=10.8.0.53")
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "DNSUP", message: "utun7")
        // A log an unprivileged openvpn could have written means nothing now.
        try sys.writeFile("/L/run/ID1/openvpn.log", Data(sampleLog(device: "utun9").utf8), mode: 0o600)
        sys.launched[0].process.onExit(.exited(0))
        expect(sys.commands.contains(["route", "-n", "delete", "-net", "203.0.113.7", "192.168.64.1", "255.255.255.255"]), "\(sys.commands)")
        expectEqual(sys.dnsRestored, ["utun7"])
        expect(!sys.routesDeleted.contains { $0.contains("10.84.0.0") }, "nothing from the log")
    }
    test("PS-05", "after a helper crash: the kept state is undone at start") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 501)
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "OPENTUN", message: "tun")
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "IFCONFIG", message: "10.8.0.2 255.255.255.0 1500 subnet")
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "ROUTE", message: "203.0.113.7 255.255.255.255 192.168.64.1")
        sys.commands = []
        try makeHelper(sys).prepareRunDirectory()
        expect(sys.commands.contains(["route", "-n", "delete", "-net", "203.0.113.7", "192.168.64.1", "255.255.255.255"]))
        // A run that asked for nothing yet: its log (openvpn's own writing) is not believed.
        let s2 = FakeSystem()
        _ = try makeHelper(s2).start(bundle: psBundle(), uid: 501)
        try s2.writeFile("/L/run/ID1/openvpn.log", Data(sampleLog(device: "utun9").utf8), mode: 0o600)
        try makeHelper(s2).prepareRunDirectory()
        expectEqual(s2.routesDeleted, [], "nothing from the log")
        expectEqual(s2.dnsRestored, [])
    }
    test("PS-06", "protection knows the tunnel from the helper's own records") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(kill: true), uid: 501)
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "OPENTUN", message: "tun")
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "IFCONFIG", message: "10.8.0.2 255.255.255.0 1500 subnet")
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "ROUTE", message: "0.0.0.0 128.0.0.0 10.8.0.1")
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "ROUTE", message: "128.0.0.0 128.0.0.0 10.8.0.1")
        sys.launched[0].process.onExit(.exited(1))
        expect((sys.pf.last ?? "").contains("user 501"), "the kill switch fired from the helper's records")
    }
    test("PS-07", "a standard user's requests: no routes for all traffic, no DNS for all names (split DNS is fine)") {
        // Under privilege separation the owner's app forwards the requests: the helper checks them.
        let sys = FakeSystem()
        sys.admins = []
        try sys.makeDirectory("/L", mode: 0o755)
        try sys.writeFile("/L/policy.json", Data(#"{"allowedDomains": ["corp.internal"]}"#.utf8), mode: 0o644)
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 502)
        _ = try h.tunnelRequest(id: id, uid: 502, kind: "OPENTUN", message: "tun")
        _ = try h.tunnelRequest(id: id, uid: 502, kind: "IFCONFIG", message: "10.8.0.2 255.255.255.0 1500 subnet")
        _ = try h.tunnelRequest(id: id, uid: 502, kind: "ROUTE", message: "10.20.0.0 255.255.0.0 10.8.0.1")
        for wide in ["0.0.0.0 128.0.0.0 10.8.0.1", "0.0.0.0 0.0.0.0 10.8.0.1", "64.0.0.0 192.0.0.0 10.8.0.1"] {
            expectThrows(wide, matching: "administrator") { _ = try h.tunnelRequest(id: id, uid: 502, kind: "ROUTE", message: wide) }
        }
        expectThrows("IPv6 for everything", matching: "administrator") {
            _ = try h.tunnelRequest(id: id, uid: 502, kind: "ROUTE6", message: "2000::/3 utun7")
        }
        _ = try h.tunnelRequest(id: id, uid: 502, kind: "DNSVAR", message: "dns_server_1_address_1=10.8.0.53")
        expectThrows("DNS for all names", matching: "administrator") { _ = try h.tunnelRequest(id: id, uid: 502, kind: "DNSUP", message: "utun7") }
        expectEqual(sys.dnsSet.count, 0)
        sys.clock += 5
        _ = try h.tunnelRequest(id: id, uid: 502, kind: "DNSVAR", message: "dns_server_1_resolve_domain_1=corp.internal")
        _ = try h.tunnelRequest(id: id, uid: 502, kind: "DNSUP", message: "utun7")
        expectEqual(sys.dnsSet.map(\.split), [true], "its own domains")
    }
    test("PS-08", "a reconnect's new tunnel: the old one's DNS goes first") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 501)
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "OPENTUN", message: "tun")
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "DNSVAR", message: "dns_server_1_address_1=10.8.0.53")
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "DNSUP", message: "utun7")
        sys.utunName = "utun8"
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "OPENTUN", message: "tun")
        expectEqual(sys.dnsRestored, ["utun7"])
        sys.commandFails = true
        _ = try? h.tunnelRequest(id: id, uid: 501, kind: "ROUTE6", message: "fd00:20::/64 utun8")
        sys.commandFails = false
        sys.commands = []
        sys.launched[0].process.onExit(.signaled(9))
        expect(!sys.commands.contains { $0.contains("fd00:20::") }, "a route that was not added is not deleted")
    }
    test("PS-09", "every connection's openvpn has its own unprivileged id") {
        let sys = FakeSystem()
        let base = HelperCore.serviceIDBase
        sys.takenIDs = [base + 1]
        let h = makeHelper(sys)
        _ = try h.start(bundle: psBundle(), uid: 501)
        _ = try h.start(bundle: psBundle(), uid: 502)
        expectEqual(sys.launched.map { $0.user?.uid }, [base, base + 2], "an id the directory has is skipped")
        expectEqual(sys.launched.map { $0.user?.gid }, [base, base + 2])
        expectEqual(sys.owners["/L/run/ID2/config.ovpn"]?.gid, base + 2, "its files are its group's only")
        expectEqual(sys.owners["/L/run/ID2/sock"]?.uid, base + 2)
        sys.launched[0].process.onExit(.exited(0))
        _ = try h.start(bundle: psBundle(), uid: 501)
        expect(sys.launched[2].user?.uid != base + 2, "a live one's id is never shared")
    }
    test("PS-10", "undo deletes a tunnel route only while it is still there and still this tunnel's") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (a, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, a, uid: 501, device: "utun5", routes: ["10.0.0.0 255.0.0.0 10.8.0.1", "10.50.0.0 255.255.0.0 10.8.0.1"])
        // A's utun closes (the kernel takes its routes); B adds the same network through its own.
        sys.closedDevices.insert("utun5")
        sys.routeTable = sys.routeTable.filter { !$0.contains("utun5") }
        // (Another user could not: the same network is refused, PS-22. The same user's second connection can.)
        let (b, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, b, uid: 501, device: "utun6", routes: ["10.0.0.0 255.0.0.0 10.8.0.1"])
        sys.commands = []
        sys.launched[0].process.onExit(.signaled(9))
        expect(!sys.commands.contains { $0.first == "route" && $0.contains("delete") }, "nothing of B's: \(sys.commands)")
        expect(sys.routeTable.contains(["route", "-n", "add", "-net", "10.0.0.0", "-netmask", "255.0.0.0", "-interface", "utun6"]))
        // A reconnect: what the old utun still has goes before the new one is used.
        let (c, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, c, uid: 501, device: "utun8", routes: ["10.60.0.0 255.255.0.0 10.8.0.1"])
        sys.utunName = "utun9"
        _ = try h.tunnelRequest(id: c, uid: 501, kind: "OPENTUN", message: "tun")
        expect(!sys.routeTable.contains { $0.contains("utun8") }, "the old device's routes are gone")
    }
    test("PS-11", "two connections to one server share its host route; the last one removes it") {
        let sys = FakeSystem()
        sys.admins = [501, 502]  // two users who may route freely (the policy is not what is tested here)
        let h = makeHelper(sys)
        let server = "203.0.113.7 255.255.255.255 192.168.64.1"
        let (a, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, a, uid: 501, device: "utun5", routes: [server])
        let (b, _) = try h.start(bundle: psBundle(), uid: 502)
        try bringUp(sys, h, b, uid: 502, device: "utun6", routes: [server])
        let host = ["route", "-n", "add", "-net", "203.0.113.7", "192.168.64.1", "255.255.255.255"]
        sys.launched[0].process.onExit(.exited(0))
        expect(sys.routeTable.contains(host), "B still needs it")
        sys.launched[1].process.onExit(.exited(0))
        expect(!sys.routeTable.contains(host), "gone with the last")
        // A host route nobody of ours added (the Mac's own) is not adopted.
        sys.routeTable.insert(host)
        let (c, _) = try h.start(bundle: psBundle(), uid: 501)
        expectThrows("not ours") { try bringUp(sys, h, c, uid: 501, device: "utun7", routes: [server]) }
    }
    test("PS-12", "no host route around another connection's tunnel") {
        let sys = FakeSystem()
        sys.admins = [501, 502]  // two users who may route freely (the policy is not what is tested here)
        let h = makeHelper(sys)
        let (a, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, a, uid: 501, device: "utun5", routes: ["203.0.113.0 255.255.255.0 10.8.0.1"])
        let (b, _) = try h.start(bundle: psBundle(), uid: 502)
        try bringUp(sys, h, b, uid: 502, device: "utun6", routes: [])
        expectThrows("into A's network", matching: "another") {
            _ = try h.tunnelRequest(id: b, uid: 502, kind: "ROUTE", message: "203.0.113.9 255.255.255.255 192.168.64.1")
        }
    }
    test("PS-13", "a standard user's routes: private networks only, public ones as an administrator allows") {
        // The routing table is the whole Mac's: a public network routed into one user's tunnel takes everyone's traffic to it.
        let sys = FakeSystem()
        sys.admins = []
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 502)
        try bringUp(sys, h, id, uid: 502, device: "utun5", routes: ["10.20.0.0 255.255.0.0 10.8.0.1", "172.16.0.0 255.240.0.0 10.8.0.1",
                                                                   "100.64.0.0 255.192.0.0 10.8.0.1"])
        for pub in ["203.0.113.0 255.255.255.0 10.8.0.1", "1.0.0.0 255.0.0.0 10.8.0.1", "198.51.100.7 255.255.255.255 192.168.64.1"] {
            expectThrows(pub, matching: "administrator") { _ = try h.tunnelRequest(id: id, uid: 502, kind: "ROUTE", message: pub) }
        }
        _ = try h.tunnelRequest(id: id, uid: 502, kind: "ROUTE6", message: "fd00:1::/48 utun5")
        expectThrows("public IPv6", matching: "administrator") {
            _ = try h.tunnelRequest(id: id, uid: 502, kind: "ROUTE6", message: "2001:db8::/32 utun5")
        }
        // An administrator's list.
        try sys.makeDirectory("/L", mode: 0o755)
        try sys.writeFile("/L/policy.json", Data(#"{"allowedNetworks": ["203.0.113.0/24", "2001:db8::/32"]}"#.utf8), mode: 0o644)
        let (b, _) = try h.start(bundle: psBundle(), uid: 502)
        try bringUp(sys, h, b, uid: 502, device: "utun6", routes: ["203.0.113.0 255.255.255.0 10.8.0.1", "203.0.113.128 255.255.255.128 10.8.0.1"])
        _ = try h.tunnelRequest(id: b, uid: 502, kind: "ROUTE6", message: "2001:db8:5::/48 utun6")
        expectThrows("wider than allowed", matching: "administrator") {
            _ = try h.tunnelRequest(id: b, uid: 502, kind: "ROUTE", message: "203.0.112.0 255.255.254.0 10.8.0.1")
        }
    }
    test("PS-14", "a failed request leaves no trace in the records") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 501)
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "OPENTUN", message: "tun")
        sys.commandFails = true
        expectThrows("ifconfig fails") {
            _ = try h.tunnelRequest(id: id, uid: 501, kind: "IFCONFIG", message: "10.8.0.2 255.255.255.0 1500 subnet")
        }
        sys.commandFails = false
        expectThrows("no subnet recorded", matching: "tunnel") {
            _ = try h.tunnelRequest(id: id, uid: 501, kind: "ROUTE", message: "10.20.0.0 255.255.0.0 10.8.0.1")
        }
        // The subnet's route already there (a LAN of the same range): the address is still set.
        sys.routeTable.insert(["route", "-n", "add", "-net", "10.8.0.0", "-netmask", "255.255.255.0", "-interface", "utun7"])
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "IFCONFIG", message: "10.8.0.2 255.255.255.0 1500 subnet")
    }
    test("PS-15", "a connection's id leaves nothing running; at start, none of the range does") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        _ = try h.start(bundle: psBundle(), uid: 501)
        sys.launched[0].process.onExit(.exited(0))
        let base = HelperCore.serviceIDBase
        expectEqual(sys.killedUIDs, [base...base])
        try makeHelper(sys).prepareRunDirectory()
        expectEqual(sys.killedUIDs.last, base...(base + HelperCore.serviceIDCount - 1))
    }
    test("PS-16", "no more than a few utun devices at once per connection") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 501)
        for i in 0..<HelperCore.maxOpenTunnels {
            sys.utunName = "utun\(10 + i)"
            _ = try h.tunnelRequest(id: id, uid: 501, kind: "OPENTUN", message: "tun")
        }
        sys.utunName = "utun20"
        expectThrows("one more while all are open", matching: "tunnels") { _ = try h.tunnelRequest(id: id, uid: 501, kind: "OPENTUN", message: "tun") }
        sys.closedDevices.insert("utun10")
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "OPENTUN", message: "tun")
    }
    test("PS-17", "a utun stays the helper's until its routes and DNS are undone; another's device is never touched") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (a, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, a, uid: 501, device: "utun5", routes: ["10.0.0.0 255.0.0.0 10.8.0.1"])
        expectEqual(sys.heldDevices, ["utun5"], "held: the kernel cannot give the name to anyone else")
        sys.commands = []
        sys.launched[0].process.onExit(.signaled(9))
        let deleted = sys.commands.firstIndex { $0.contains("delete") }
        expect(deleted != nil, "\(sys.commands)")
        expectEqual(sys.releasedDevices, ["utun5"], "released only after the routes went")
        // Records that name a device another connection now has: left alone.
        let (b, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, b, uid: 501, device: "utun6", routes: ["10.30.0.0 255.255.0.0 10.8.0.1"])
        let (c, _) = try h.start(bundle: psBundle(), uid: 502)
        try bringUp(sys, h, c, uid: 502, device: "utun6", routes: [])
        sys.commands = []
        sys.launched[1].process.onExit(.signaled(9))
        expect(!sys.commands.contains { $0.contains("utun6") }, "C's device: \(sys.commands)")
        expect(!sys.releasedDevices.contains("utun6"), "C keeps it")
        _ = c
    }
    test("PS-18", "a reconnect whose new tunnel cannot be opened keeps the old one as it was") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, id, uid: 501, device: "utun5", routes: ["10.20.0.0 255.255.0.0 10.8.0.1"])
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "DNSVAR", message: "dns_server_1_address_1=10.8.0.53")
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "DNSUP", message: "utun5")
        sys.commands = []
        sys.openUtunFails = true
        expectThrows("no utun") { _ = try h.tunnelRequest(id: id, uid: 501, kind: "OPENTUN", message: "tun") }
        expectEqual(sys.commands, [], "nothing of the old one undone")
        expectEqual(sys.dnsRestored, [])
        sys.openUtunFails = false
        sys.utunName = "utun6"
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "OPENTUN", message: "tun")
        expectEqual(sys.dnsRestored, ["utun5"])
        expect(sys.commands.contains(["route", "-n", "delete", "-net", "10.20.0.0", "-netmask", "255.255.0.0", "-interface", "utun5"]))
        expectEqual(sys.releasedDevices, ["utun5"])
    }
    test("PS-19", "host routes and other connections' networks: checked both ways; another's def1 is no network") {
        let sys = FakeSystem()
        sys.admins = [501, 502]  // two users who may route all traffic (the policy is not what is tested here)
        let h = makeHelper(sys)
        let (a, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, a, uid: 501, device: "utun5", routes: ["203.0.113.9 255.255.255.255 192.168.64.1"])
        let (b, _) = try h.start(bundle: psBundle(), uid: 502)
        try bringUp(sys, h, b, uid: 502, device: "utun6", routes: [])
        expectThrows("over A's host route", matching: "another") {
            _ = try h.tunnelRequest(id: b, uid: 502, kind: "ROUTE", message: "203.0.113.0 255.255.255.0 10.8.0.1")
        }
        // A tunnel taking all traffic does not keep the others from reaching their servers.
        _ = try h.tunnelRequest(id: b, uid: 502, kind: "ROUTE", message: "0.0.0.0 128.0.0.0 10.8.0.1")
        _ = try h.tunnelRequest(id: b, uid: 502, kind: "ROUTE", message: "128.0.0.0 128.0.0.0 10.8.0.1")
        let (c, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, c, uid: 501, device: "utun7", routes: ["198.51.100.4 255.255.255.255 192.168.64.1"])
    }
    test("PS-20", "after an upgrade or before its first request: a run of openvpn without root is never undone from its log") {
        let sys = FakeSystem()
        try sys.makeDirectory("/L", mode: 0o755)
        try sys.makeDirectory("/L/run", mode: 0o711)
        // An older helper's record: fewer fields.
        try sys.writeFile("/L/run/OLD/state.json", Data(#"{"device":"utun5","dnsApplied":true,"routes":[{"kind":"host","net":"203.0.113.7","mask":"255.255.255.255","via":"192.168.64.1"}],"dnsVars":{}}"#.utf8), mode: 0o600)
        sys.routeTable.insert(["route", "-n", "add", "-net", "203.0.113.7", "192.168.64.1", "255.255.255.255"])
        // One with no record, its log written by openvpn itself.
        try sys.makeDirectory("/L/run/NEW", mode: 0o711)
        try sys.makeDirectory("/L/run/NEW/sock", mode: 0o711)
        try sys.writeFile("/L/run/NEW/openvpn.log", Data(sampleLog(device: "utun9").utf8), mode: 0o600)
        try makeHelper(sys).prepareRunDirectory()
        expectEqual(sys.dnsRestored, ["utun5"])
        expect(!sys.routeTable.contains(["route", "-n", "add", "-net", "203.0.113.7", "192.168.64.1", "255.255.255.255"]))
        expectEqual(sys.routesDeleted, [], "nothing from NEW's log")
    }
    test("PS-21", "a standard user's split DNS: only the domains an administrator lists") {
        // A resolver for a domain is the whole Mac's, asked by one mDNSResponder for every user:
        // no isolation is possible, private names (corp.internal) included.
        let sys = FakeSystem()
        sys.admins = []
        let h = makeHelper(sys)
        func dns(_ domain: String) throws {
            let (id, _) = try h.start(bundle: psBundle(), uid: 502)
            sys.utunName = "utun\(sys.launched.count + 4)"
            _ = try h.tunnelRequest(id: id, uid: 502, kind: "OPENTUN", message: "tun")
            _ = try h.tunnelRequest(id: id, uid: 502, kind: "IFCONFIG", message: "10.8.0.2 255.255.255.0 1500 subnet")
            sys.clock += 5
            defer { sys.launched.last!.process.onExit(.exited(0)) }
            _ = try h.tunnelRequest(id: id, uid: 502, kind: "DNSVAR", message: "dns_server_1_address_1=10.8.0.53")
            _ = try h.tunnelRequest(id: id, uid: 502, kind: "DNSVAR", message: "dns_server_1_resolve_domain_1=\(domain)")
            _ = try h.tunnelRequest(id: id, uid: 502, kind: "DNSUP", message: sys.utunName)
        }
        for bad in ["bank.example", "example.com", "office.local", "corp.internal", "lan", "printer.home.arpa"] {
            expectThrows(bad, matching: "administrator") { try dns(bad) }
        }
        try sys.makeDirectory("/L", mode: 0o755)
        try sys.writeFile("/L/policy.json", Data(#"{"allowedDomains": ["corp.example.com", "corp.internal"]}"#.utf8), mode: 0o644)
        try dns("corp.example.com")
        try dns("eu.corp.example.com")
        try dns("corp.internal")
        expectThrows("not listed", matching: "administrator") { try dns("example.com") }
    }
    test("PS-22", "no tunnel takes part of another user's networks, whichever came first") {
        let sys = FakeSystem()
        sys.admins = [501, 502]  // two users who may route all traffic (the policy is not what is tested here)
        let h = makeHelper(sys)
        let (a, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, a, uid: 501, device: "utun5", routes: ["10.0.0.0 255.0.0.0 10.8.0.1"])
        let (b, _) = try h.start(bundle: psBundle(), uid: 502)
        sys.utunName = "utun6"
        _ = try h.tunnelRequest(id: b, uid: 502, kind: "OPENTUN", message: "tun")
        // B's own address inside A's network: A's traffic to it would stay on the Mac.
        expectThrows("in A's network", matching: "another") {
            _ = try h.tunnelRequest(id: b, uid: 502, kind: "IFCONFIG", message: "10.9.0.2 255.255.255.0 1500 subnet")
        }
        _ = try h.tunnelRequest(id: b, uid: 502, kind: "IFCONFIG", message: "172.16.9.2 255.255.255.0 1500 subnet")
        for narrower in ["10.0.0.0 255.0.0.0 172.16.9.1", "10.0.0.0 255.128.0.0 172.16.9.1", "10.20.0.0 255.255.0.0 172.16.9.1"] {
            expectThrows(narrower, matching: "another") { _ = try h.tunnelRequest(id: b, uid: 502, kind: "ROUTE", message: narrower) }
        }
        // Wider takes only what A's more specific route does not: A keeps its networks.
        _ = try h.tunnelRequest(id: b, uid: 502, kind: "ROUTE", message: "8.0.0.0 248.0.0.0 172.16.9.1")
        _ = try h.tunnelRequest(id: b, uid: 502, kind: "ROUTE", message: "192.168.50.0 255.255.255.0 172.16.9.1")
        // def1 is "everything else", not a network of its own; the same user's tunnels are the user's business.
        _ = try h.tunnelRequest(id: b, uid: 502, kind: "ROUTE", message: "0.0.0.0 128.0.0.0 172.16.9.1")
        let (c, _) = try h.start(bundle: psBundle(), uid: 501)
        sys.utunName = "utun7"
        _ = try h.tunnelRequest(id: c, uid: 501, kind: "OPENTUN", message: "tun")
        _ = try h.tunnelRequest(id: c, uid: 501, kind: "IFCONFIG", message: "10.9.0.2 255.255.255.0 1500 subnet")
    }
    test("PS-23", "a tunnel's IPv6 network: not the LAN's, not another tunnel's") {
        let sys = FakeSystem()
        sys.localIPv6 = ["2001:db8:1::/64"]
        let h = makeHelper(sys)
        let (a, _) = try h.start(bundle: psBundle(), uid: 501)
        _ = try h.tunnelRequest(id: a, uid: 501, kind: "OPENTUN", message: "tun")
        expectThrows("the LAN's prefix", matching: "network") {
            _ = try h.tunnelRequest(id: a, uid: 501, kind: "IFCONFIG6", message: "2001:db8:1::99/64 1500")
        }
        _ = try h.tunnelRequest(id: a, uid: 501, kind: "IFCONFIG6", message: "fd00:8::2/64 1500")
        let (b, _) = try h.start(bundle: psBundle(), uid: 502)
        sys.utunName = "utun8"
        _ = try h.tunnelRequest(id: b, uid: 502, kind: "OPENTUN", message: "tun")
        expectThrows("A's prefix", matching: "another") {
            _ = try h.tunnelRequest(id: b, uid: 502, kind: "IFCONFIG6", message: "fd00:8::9/64 1500")
        }
        _ = try h.tunnelRequest(id: b, uid: 502, kind: "IFCONFIG6", message: "fd00:9::2/64 1500")
    }
    test("PS-24", "while another user's tunnel takes all traffic, few host routes around it") {
        let sys = FakeSystem()
        sys.admins = [501, 502]  // two users who may route freely (the policy is not what is tested here)
        let h = makeHelper(sys)
        let (a, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, a, uid: 501, device: "utun5")
        let (b, _) = try h.start(bundle: psBundle(), uid: 502)
        try bringUp(sys, h, b, uid: 502, device: "utun6", routes: ["203.0.113.7 255.255.255.255 192.168.64.1",
                                                                  "203.0.113.8 255.255.255.255 192.168.64.1"])
        expectThrows("a third", matching: "all traffic") {
            _ = try h.tunnelRequest(id: b, uid: 502, kind: "ROUTE", message: "198.51.100.1 255.255.255.255 192.168.64.1")
        }
    }
    test("PS-25", "requests are rationed: a flood does not hold the helper; DNS not changed in a loop") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, id, uid: 501, device: "utun5", routes: [])
        var refused = 0
        for _ in 0..<(HelperCore.requestBurst + 10) {
            if (try? h.tunnelRequest(id: id, uid: 501, kind: "DNSVAR", message: "dns_server_1_address_1=10.8.0.53")) == nil { refused += 1 }
        }
        expect(refused >= 10, "\(refused) refused")
        sys.clock += 60
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "DNSUP", message: "utun5")
        expectThrows("DNS again at once", matching: "soon") { _ = try h.tunnelRequest(id: id, uid: 501, kind: "DNSUP", message: "utun5") }
        sys.clock += 2
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "DNSUP", message: "utun5")
    }
    test("PS-26", "a tunnel's own addresses: not the Mac's networks, not another user's (audit 4: H1)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (a, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, a, uid: 501, device: "utun5", routes: ["10.20.0.0 255.255.0.0 10.8.0.1"])
        let (b, _) = try h.start(bundle: psBundle(), uid: 502)
        sys.utunName = "utun6"
        _ = try h.tunnelRequest(id: b, uid: 502, kind: "OPENTUN", message: "tun")
        for bad in ["192.168.64.1 255.255.255.0 1500 subnet", "10.9.0.2 192.168.64.1 1500 net30",
                    "10.9.0.2 10.8.0.1 1500 net30", "10.20.0.5 255.255.255.0 1500 subnet"] {
            expectThrows(bad, matching: "network") { _ = try h.tunnelRequest(id: b, uid: 502, kind: "IFCONFIG", message: bad) }
        }
        _ = try h.tunnelRequest(id: b, uid: 502, kind: "IFCONFIG", message: "10.9.0.2 255.255.255.0 1500 subnet")
    }
    test("PS-27", "IPv6 routes: not inside another user's networks or the Mac's (audit 4: H3)") {
        let sys = FakeSystem()
        sys.localIPv6 = ["fd99::/64"]
        let h = makeHelper(sys)
        let (a, _) = try h.start(bundle: psBundle(), uid: 501)
        _ = try h.tunnelRequest(id: a, uid: 501, kind: "OPENTUN", message: "tun")
        _ = try h.tunnelRequest(id: a, uid: 501, kind: "IFCONFIG6", message: "fd00:8::2/64 1500")
        _ = try h.tunnelRequest(id: a, uid: 501, kind: "ROUTE6", message: "fd00:20::/48 utun7")
        let (b, _) = try h.start(bundle: psBundle(), uid: 502)
        sys.utunName = "utun8"
        _ = try h.tunnelRequest(id: b, uid: 502, kind: "OPENTUN", message: "tun")
        for bad in ["fd00:8::/65 utun8", "fd00:20:0:1::/64 utun8", "fd99::/80 utun8"] {
            expectThrows(bad, matching: "network") { _ = try h.tunnelRequest(id: b, uid: 502, kind: "ROUTE6", message: bad) }
        }
        _ = try h.tunnelRequest(id: b, uid: 502, kind: "ROUTE6", message: "fd00:30::/48 utun8")
    }
    test("PS-28", "split DNS: not a domain another user's tunnel answers for (audit 4: M2)") {
        let sys = FakeSystem()
        sys.admins = [501, 502]  // both may set DNS: what is tested is the overlap between users
        let h = makeHelper(sys)
        func dns(_ uid: UInt32, _ dev: String, _ domain: String) throws {
            let (id, _) = try h.start(bundle: psBundle(), uid: uid)
            sys.utunName = dev
            _ = try h.tunnelRequest(id: id, uid: uid, kind: "OPENTUN", message: "tun")
            _ = try h.tunnelRequest(id: id, uid: uid, kind: "DNSVAR", message: "dns_server_1_address_1=10.8.0.53")
            _ = try h.tunnelRequest(id: id, uid: uid, kind: "DNSVAR", message: "dns_server_1_resolve_domain_1=\(domain)")
            _ = try h.tunnelRequest(id: id, uid: uid, kind: "DNSUP", message: dev)
        }
        try dns(501, "utun5", "corp.internal")
        for taken in ["corp.internal", "eu.corp.internal"] {
            expectThrows(taken, matching: "another") { try dns(502, "utun6", taken) }
        }
        try dns(502, "utun7", "lab.internal")
        try dns(501, "utun9", "x.corp.internal")  // the same user's
    }
    test("PS-29", "a standard user's tunnel carries that user's traffic only (audit 4: H2)") {
        let sys = FakeSystem()
        sys.admins = [501]
        let h = makeHelper(sys)
        let (b, _) = try h.start(bundle: psBundle(), uid: 502)
        try bringUp(sys, h, b, uid: 502, device: "utun6", routes: ["10.30.0.0 255.255.0.0 10.8.0.1"])
        let anchor = sys.pf.last ?? ""
        expect(anchor.contains("pass out quick on utun6 proto { tcp udp } user 502"), anchor)
        expect(!anchor.contains("user 65"), "no DNS of its own: the system resolver has no business there: \(anchor)")
        expect(!anchor.contains("proto { icmp icmp6 }"), "ICMP cannot be told by user: not through it either")
        expect(anchor.contains("block return out quick on utun6 proto { tcp udp } all") && anchor.contains("block drop out quick on utun6 all"),
               "nobody else's TCP, UDP or other protocols: \(anchor)")
        let (a, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, a, uid: 501, device: "utun5", routes: ["10.40.0.0 255.255.0.0 10.8.0.1"])
        expect(!(sys.pf.last ?? "").contains("on utun5 proto"), "an administrator's tunnel is the whole Mac's")
    }
    test("PS-30", "the ration is per user, not per connection (audit 4: M4)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        var refused = 0
        for _ in 0..<4 {
            let (id, _) = try h.start(bundle: psBundle(), uid: 501)
            for _ in 0..<(HelperCore.requestBurst / 2) {
                if (try? h.tunnelRequest(id: id, uid: 501, kind: "DNSVAR", message: "dns_server_1_address_1=10.8.0.53")) == nil { refused += 1 }
            }
        }
        expect(refused >= HelperCore.requestBurst, "\(refused)")
    }
    test("PS-31", "an administrator's attach is not beaten by a pending reconnect of the helper (audit 4: L4)") {
        let sys = FakeSystem()
        try sys.makeDirectory("/L/auto", mode: 0o755)
        try sys.writeFile("/L/auto/site.ovpn", Data("client\ndev tun\nremote a 1194\n".utf8), mode: 0o600)
        let h = makeHelper(sys)
        h.startPersistentProfiles()
        sys.channelFails = true
        sys.fireTimers()              // not listening yet: a retry in 1 s is pending
        let id = h.list(uid: 0)[0].id
        sys.channelFails = false
        let stale = sys.timers
        sys.timers = []
        _ = h.releaseManagement(id: id, uid: 501)
        stale.forEach { $0.f() }
        expectEqual(sys.channels.count, 0, "the older retry does not take the slot meant for the app")
        sys.fireTimers()
        expectEqual(sys.channels.count, 1, "the helper queues up after the app's turn")
    }
    test("PS-32", "what the helper did is on disk before it counts: a record it cannot write undoes the change (ext. audit: 3)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, id, uid: 501, device: "utun5", routes: [])
        sys.failWrites = ["state.json"]
        sys.commands = []
        expectThrows("not recorded", matching: "record") {
            _ = try h.tunnelRequest(id: id, uid: 501, kind: "ROUTE", message: "10.20.0.0 255.255.0.0 10.8.0.1")
        }
        expect(!sys.commands.contains { $0.contains("10.20.0.0") && $0.contains("add") }, "not even started: \(sys.commands)")
    }
    test("PS-33", "DNS a tunnel cannot have as asked (DoT, other port, DNSSEC) is not set as plain DNS (ext. audit: 5)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 501)
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "OPENTUN", message: "tun")
        for v in ["dns_server_1_address_1=10.8.0.53", "dns_server_1_transport=DoT", "dns_server_2_address_1=10.8.0.54",
                  "dns_server_1_resolve_domain_1=a.internal", "dns_server_2_resolve_domain_1=b.internal"] {
            _ = try h.tunnelRequest(id: id, uid: 501, kind: "DNSVAR", message: v)
        }
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "DNSUP", message: "utun7")
        expectEqual(sys.dnsSet.last?.servers, ["10.8.0.54"], "the first server it can use plainly")
        let (j, _) = try h.start(bundle: psBundle(), uid: 501)
        sys.utunName = "utun8"
        _ = try h.tunnelRequest(id: j, uid: 501, kind: "OPENTUN", message: "tun")
        for v in ["dns_server_1_address_1=10.8.0.53", "dns_server_1_port_1=853"] {
            _ = try h.tunnelRequest(id: j, uid: 501, kind: "DNSVAR", message: v)
        }
        expectThrows("none it can use", matching: "DNS") { _ = try h.tunnelRequest(id: j, uid: 501, kind: "DNSUP", message: "utun8") }
    }
    test("PS-34", "a utun given back is taken down first: no address or route of it stays (audit 4: M3)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, id, uid: 501, device: "utun5", routes: [])
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "IFCONFIG6", message: "fd00:8::2/64 1500")
        sys.commands = []
        sys.launched[0].process.onExit(.signaled(9))
        expect(sys.commands.contains(["ifconfig", "utun5", "inet", "10.8.0.2", "delete"]), "\(sys.commands)")
        expect(sys.commands.contains(["ifconfig", "utun5", "inet6", "fd00:8::2", "delete"]))
        expect(sys.commands.contains(["ifconfig", "utun5", "down"]))
        expectEqual(sys.releasedDevices, ["utun5"])
    }
    test("PS-35", "a standard user routes no host around the tunnel (via the Mac's gateway) unless allowed all traffic (ext. audit 2: P1)") {
        let sys = FakeSystem()
        sys.admins = []
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 502)
        try bringUp(sys, h, id, uid: 502, device: "utun5", routes: [])
        for host in ["10.0.0.5 255.255.255.255 192.168.64.1", "10.0.0.6 255.255.255.255 192.168.64.1 dev en0"] {
            expectThrows(host, matching: "administrator") { _ = try h.tunnelRequest(id: id, uid: 502, kind: "ROUTE", message: host) }
        }
    }
    test("PS-36", "a standard user's route stands only while PF keeps it to that user (ext. audit 2: P2)") {
        let sys = FakeSystem()
        sys.admins = []
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 502)
        try bringUp(sys, h, id, uid: 502, device: "utun5", routes: [])
        sys.pfApplyFails = true
        sys.pfIntactAnswer = false   // PF switched off under us, and it cannot be put back
        sys.commands = []
        expectThrows("no isolation, no route", matching: "isolat") {
            _ = try h.tunnelRequest(id: id, uid: 502, kind: "ROUTE", message: "10.20.0.0 255.255.0.0 10.8.0.1")
        }
        expect(sys.commands.contains(["route", "-n", "delete", "-net", "10.20.0.0", "-netmask", "255.255.0.0", "-interface", "utun5"]),
               "taken away again: \(sys.commands)")
    }
    test("PS-37", "a run whose first record cannot be written leaves nothing running (ext. audit 2: P2)") {
        let sys = FakeSystem()
        sys.failWrites = ["state.json"]
        let h = makeHelper(sys)
        expectThrows("not started") { _ = try h.start(bundle: psBundle(), uid: 501) }
        expect(h.isEmpty, "no connection kept")
        expectEqual(sys.launched.first?.process.signals, [SIGKILL])
        expectEqual(sys.killedUIDs, [HelperCore.serviceIDBase...HelperCore.serviceIDBase])
    }
    test("PS-38", "what the helper is about to change is on disk before it changes it (ext. audit 2: P3)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, id, uid: 501, device: "utun5", routes: [])
        var recorded = false
        sys.onCommand = { cmd in
            if cmd.contains("10.20.0.0") {
                recorded = String(decoding: sys.files["/L/run/ID1/state.json"]?.data ?? Data(), as: UTF8.self).contains("10.20.0.0")
            }
        }
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "ROUTE", message: "10.20.0.0 255.255.0.0 10.8.0.1")
        expect(recorded, "the record names the route before route add runs")
    }
    test("PS-39", "the system resolver reaches a standard user's tunnel only for its administrator-approved DNS (ext. audit 4: P1)") {
        let sys = FakeSystem()
        sys.admins = []
        try sys.makeDirectory("/L", mode: 0o755)
        try sys.writeFile("/L/policy.json", Data(#"{"allowedDomains": ["corp.internal"]}"#.utf8), mode: 0o644)
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 502)
        try bringUp(sys, h, id, uid: 502, device: "utun5", routes: [])
        expect(!(sys.pf.last ?? "").contains("user 65"))
        for v in ["dns_server_1_address_1=10.8.0.53", "dns_server_1_resolve_domain_1=corp.internal"] {
            _ = try h.tunnelRequest(id: id, uid: 502, kind: "DNSVAR", message: v)
        }
        _ = try h.tunnelRequest(id: id, uid: 502, kind: "DNSUP", message: "utun5")
        let a = sys.pf.last ?? ""
        expect(a.contains("pass out quick on utun5 proto { tcp udp } from any to { 10.8.0.53 } port 53 user 65"), a)
    }
    test("PS-40", "PF lost and not to be put back: standard users' tunnels stop (ext. audit 4: P2)") {
        let sys = FakeSystem()
        sys.admins = [501]
        let h = makeHelper(sys)
        let (b, _) = try h.start(bundle: psBundle(), uid: 502)
        try bringUp(sys, h, b, uid: 502, device: "utun6", routes: ["10.30.0.0 255.255.0.0 10.8.0.1"])
        let (a, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, a, uid: 501, device: "utun5", routes: [])
        sys.pfIntactAnswer = false
        sys.pfApplyFails = true
        h.refreshProtection()
        expect(!sys.routeTable.contains { $0.contains("utun6") }, "its routes go at once, before openvpn ends: \(sys.routeTable)")
        expect(sys.commands.contains(["ifconfig", "utun6", "down"]))
        expectEqual(sys.launched[0].process.signals, [SIGKILL], "and its openvpn is stopped at once")
        expectEqual(sys.launched[1].process.signals, [], "an administrator's goes on")
    }
    test("PS-41", "an address set by a request that is taken back goes too (ext. audit 4: P2)") {
        let sys = FakeSystem()
        sys.admins = []
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 502)
        _ = try h.tunnelRequest(id: id, uid: 502, kind: "OPENTUN", message: "tun")
        sys.pfIntactAnswer = false
        sys.pfApplyFails = true
        expectThrows("not isolated", matching: "isolat") {
            _ = try h.tunnelRequest(id: id, uid: 502, kind: "IFCONFIG", message: "10.8.0.2 255.255.255.0 1500 subnet")
        }
        expect(sys.commands.contains(["ifconfig", "utun7", "inet", "10.8.0.2", "delete"]), "\(sys.commands)")
    }
    test("PS-42", "a kill switch that cannot be recorded: no tunnel for all traffic (ext. audit 4: P2)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        var b = ProfileBundle(name: "office", config: "client\ndev tun\nremote vpn.example.com 1194 udp", files: [:])
        b.protection = ProtectionOptions(killSwitch: true)
        let (id, _) = try h.start(bundle: try JSONEncoder().encode(b), uid: 501)
        try bringUp(sys, h, id, uid: 501, device: "utun5", routes: ["0.0.0.0 128.0.0.0 10.8.0.1"])
        sys.failWrites = ["locks.json"]
        sys.commands = []
        expectThrows("the arming is not on disk", matching: "kill switch") {
            _ = try h.tunnelRequest(id: id, uid: 501, kind: "ROUTE", message: "128.0.0.0 128.0.0.0 10.8.0.1")
        }
        expect(sys.commands.contains(["route", "-n", "delete", "-net", "128.0.0.0", "-netmask", "128.0.0.0", "-interface", "utun5"]))
    }
    test("PS-43", "a change that failed is not left in the record (ext. audit 4: P3)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, id, uid: 501, device: "utun5", routes: [])
        sys.commandFails = true
        expectThrows("route add fails") { _ = try h.tunnelRequest(id: id, uid: 501, kind: "ROUTE", message: "10.20.0.0 255.255.0.0 10.8.0.1") }
        let saved = String(decoding: sys.files["/L/run/ID1/state.json"]?.data ?? Data(), as: UTF8.self)
        expect(!saved.contains("10.20.0.0"), saved)
    }
    test("PS-44", "a standard user's DNS servers: in its own tunnel, not the Mac's resolvers, not the Mac's networks (ext. audit 5: P1)") {
        let sys = FakeSystem()
        sys.admins = []
        sys.systemDNS = ["10.0.0.2"]
        try sys.makeDirectory("/L", mode: 0o755)
        try sys.writeFile("/L/policy.json", Data(#"{"allowedDomains": ["corp.internal"]}"#.utf8), mode: 0o644)
        let h = makeHelper(sys)
        func dns(_ server: String, routes: [String] = []) throws {
            let (id, _) = try h.start(bundle: psBundle(), uid: 502)
            try bringUp(sys, h, id, uid: 502, device: "utun\(sys.launched.count + 4)", routes: routes)
            sys.clock += 5
            for v in ["dns_server_1_address_1=\(server)", "dns_server_1_resolve_domain_1=corp.internal"] {
                _ = try h.tunnelRequest(id: id, uid: 502, kind: "DNSVAR", message: v)
            }
            _ = try h.tunnelRequest(id: id, uid: 502, kind: "DNSUP", message: sys.utunName)
            sys.launched.last!.process.onExit(.exited(0))
        }
        for bad in [("10.0.0.2", ["10.0.0.2 255.255.255.255 10.8.0.1"]), ("10.30.0.9", [])] {
            expectThrows(bad.0, matching: "DNS") { try dns(bad.0, routes: bad.1) }
        }
        try dns("10.8.0.53")
        try dns("10.20.0.53", routes: ["10.20.0.0 255.255.0.0 10.8.0.1"])
    }
    test("PS-47", "the Mac's resolver in another spelling is still the Mac's; no list of them, no DNS (ext. audit 6: P1)") {
        let sys = FakeSystem()
        sys.admins = []
        sys.systemDNS = ["10.0.0.2"]
        try sys.makeDirectory("/L", mode: 0o755)
        try sys.writeFile("/L/policy.json", Data(#"{"allowedDomains": ["corp.internal"]}"#.utf8), mode: 0o644)
        let h = makeHelper(sys)
        func dns(_ server: String) throws {
            let (id, _) = try h.start(bundle: psBundle(), uid: 502)
            try bringUp(sys, h, id, uid: 502, device: "utun\(sys.launched.count + 4)", routes: ["10.0.0.0 255.255.255.0 10.8.0.1"])
            sys.clock += 5
            for v in ["dns_server_1_address_1=\(server)", "dns_server_1_resolve_domain_1=corp.internal"] {
                _ = try h.tunnelRequest(id: id, uid: 502, kind: "DNSVAR", message: v)
            }
            defer { sys.launched.last!.process.onExit(.exited(0)) }
            _ = try h.tunnelRequest(id: id, uid: 502, kind: "DNSUP", message: sys.utunName)
        }
        for bad in ["010.000.000.002", "10.0.0.02"] {
            expectThrows(bad, matching: "DNS") { try dns(bad) }
        }
        try dns("10.0.0.53")
        sys.systemDNS = nil
        expectThrows("the Mac's resolvers unknown", matching: "DNS") { try dns("10.0.0.53") }
    }
    test("PS-48", "a standard user's DNS set again with the same server: its own is not the Mac's (ext. audit 6: P3)") {
        let sys = FakeSystem()
        sys.admins = []
        try sys.makeDirectory("/L", mode: 0o755)
        try sys.writeFile("/L/policy.json", Data(#"{"allowedDomains": ["corp.internal"]}"#.utf8), mode: 0o644)
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 502)
        try bringUp(sys, h, id, uid: 502, device: "utun5", routes: [])
        for v in ["dns_server_1_address_1=10.8.0.53", "dns_server_1_resolve_domain_1=corp.internal"] {
            _ = try h.tunnelRequest(id: id, uid: 502, kind: "DNSVAR", message: v)
        }
        _ = try h.tunnelRequest(id: id, uid: 502, kind: "DNSUP", message: "utun5")
        sys.clock += 5
        _ = try h.tunnelRequest(id: id, uid: 502, kind: "DNSUP", message: "utun5")
    }
    test("PS-50", "a standard user allowed to change the Mac's DNS sets it again with the same server (ext. audit 7: P3)") {
        let sys = FakeSystem()
        sys.admins = []
        try sys.makeDirectory("/L", mode: 0o755)
        try sys.writeFile("/L/policy.json", Data(#"{"usersMayChangeDNS": true}"#.utf8), mode: 0o644)
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 502)
        try bringUp(sys, h, id, uid: 502, device: "utun5", routes: [])
        _ = try h.tunnelRequest(id: id, uid: 502, kind: "DNSVAR", message: "dns_server_1_address_1=10.8.0.53")
        _ = try h.tunnelRequest(id: id, uid: 502, kind: "DNSUP", message: "utun5")
        sys.systemDNS = ["10.8.0.53"]   // the Mac's resolver now: its own, set for all names
        sys.clock += 5
        _ = try h.tunnelRequest(id: id, uid: 502, kind: "DNSUP", message: "utun5")
    }
    test("PS-51", "DNS for all names already another tunnel's: one with its own domains gets them split instead") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (a, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, a, uid: 501, device: "utun5", routes: [])
        _ = try h.tunnelRequest(id: a, uid: 501, kind: "DNSVAR", message: "dns_server_1_address_1=10.8.0.53")
        _ = try h.tunnelRequest(id: a, uid: 501, kind: "DNSUP", message: "utun5")
        expectEqual(sys.dnsSet.last?.split, false, "the first takes all names")
        let (b, _) = try h.start(bundle: psBundle(), uid: 501)
        sys.utunName = "utun6"
        _ = try h.tunnelRequest(id: b, uid: 501, kind: "OPENTUN", message: "tun")
        _ = try h.tunnelRequest(id: b, uid: 501, kind: "IFCONFIG", message: "10.9.0.2 255.255.255.0 1500 subnet")
        for v in ["dns_server_1_address_1=10.9.0.53", "dns_search_domain_1=corp.lan"] {
            _ = try h.tunnelRequest(id: b, uid: 501, kind: "DNSVAR", message: v)
        }
        _ = try h.tunnelRequest(id: b, uid: 501, kind: "DNSUP", message: "utun6")
        let p = sys.dnsSet.last
        expect(p?.device == "utun6" && p?.split == true && p?.matchDomains == ["corp.lan"], "its own domains, split: \(String(describing: p))")
    }
    test("PS-52", "DNS for all names already another tunnel's and no domains of its own: said so (the app warns)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (a, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, a, uid: 501, device: "utun5", routes: [])
        _ = try h.tunnelRequest(id: a, uid: 501, kind: "DNSVAR", message: "dns_server_1_address_1=10.8.0.53")
        _ = try h.tunnelRequest(id: a, uid: 501, kind: "DNSUP", message: "utun5")
        let (b, _) = try h.start(bundle: psBundle(), uid: 501)
        sys.utunName = "utun6"
        _ = try h.tunnelRequest(id: b, uid: 501, kind: "OPENTUN", message: "tun")
        _ = try h.tunnelRequest(id: b, uid: 501, kind: "IFCONFIG", message: "10.9.0.2 255.255.255.0 1500 subnet")
        _ = try h.tunnelRequest(id: b, uid: 501, kind: "DNSVAR", message: "dns_server_1_address_1=10.9.0.53")
        let before = sys.dnsSet.count
        expectThrows("taken", matching: "already another tunnel's") { _ = try h.tunnelRequest(id: b, uid: 501, kind: "DNSUP", message: "utun6") }
        expectEqual(sys.dnsSet.count, before, "nothing set")
    }
    test("PS-53", "the server's DNS for the domains its user lists (none pushed): split on those") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        var b = ProfileBundle(name: "office", config: "client\ndev tun\nremote vpn.example.com 1194 udp", files: [:])
        b.dnsDomains = ["intranet.example"]
        let (id, _) = try h.start(bundle: try JSONEncoder().encode(b), uid: 501)
        try bringUp(sys, h, id, uid: 501, device: "utun5", routes: [])
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "DNSVAR", message: "dns_server_1_address_1=10.8.0.53")
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "DNSUP", message: "utun5")
        let p = sys.dnsSet.last
        expect(p?.split == true && p?.matchDomains == ["intranet.example"] && p?.servers == ["10.8.0.53"], "\(String(describing: p))")
    }
    test("PS-54", "who has DNS for all names is worked out again when its owner lets go: those with nothing first, then who asked first") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        func up(_ dev: String, _ net: String, _ vars: [String]) throws -> String {
            let (id, _) = try h.start(bundle: psBundle(), uid: 501)
            sys.utunName = dev
            _ = try h.tunnelRequest(id: id, uid: 501, kind: "OPENTUN", message: "tun")
            _ = try h.tunnelRequest(id: id, uid: 501, kind: "IFCONFIG", message: "\(net).2 255.255.255.0 1500 subnet")
            for v in vars { _ = try h.tunnelRequest(id: id, uid: 501, kind: "DNSVAR", message: v) }
            return id
        }
        let a = try up("utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        _ = try h.tunnelRequest(id: a, uid: 501, kind: "DNSUP", message: "utun5")
        let b = try up("utun6", "10.9.0", ["dns_server_1_address_1=10.9.0.53", "dns_search_domain_1=corp.lan"])
        _ = try h.tunnelRequest(id: b, uid: 501, kind: "DNSUP", message: "utun6")
        let c = try up("utun7", "10.10.0", ["dns_server_1_address_1=10.10.0.53"])
        expectThrows("waits", matching: "already another tunnel's") { _ = try h.tunnelRequest(id: c, uid: 501, kind: "DNSUP", message: "utun7") }
        let states = { Dictionary(uniqueKeysWithValues: h.list(uid: 501).map { ($0.id, $0.dns ?? "-") }) }
        expectEqual(states(), [a: "all", b: "limited", c: "waiting"])
        // The owner lets go: c, which got nothing, before b (its domains meanwhile), though b asked first.
        sys.clock += 5
        _ = try h.tunnelRequest(id: a, uid: 501, kind: "DNSDOWN", message: "utun5")
        expectEqual(sys.dnsSet.last?.device, "utun7")
        expectEqual(sys.dnsSet.last?.split, false, "all names now")
        expectEqual(states()[c], "all")
        expectEqual(states()[b], "limited")
        // c ends: b, limited to its domains till now, gets all names (its split DNS taken off first).
        sys.launched[2].process.onExit(.exited(0))
        expectEqual(sys.dnsSet.last?.device, "utun6")
        expect(sys.dnsRestored.contains("utun6"), "its split DNS taken off first")
        expectEqual(states()[b], "all")
    }
    test("PS-55", "a DNS domain that is not a name: refused before openvpn is started (none left behind)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        var b = ProfileBundle(name: "office", config: "client\ndev tun\nremote vpn.example.com 1194 udp", files: [:])
        b.dnsDomains = ["bad domain; rm -rf /"]
        expectThrows("bad", matching: "domain") { _ = try h.start(bundle: try JSONEncoder().encode(b), uid: 501) }
        expect(sys.launched.isEmpty, "no openvpn")
        expect(h.isEmpty)
    }
    test("PS-66", "too many domains for the server's DNS: said as such (not as names that are not domains)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        var b = ProfileBundle(name: "office", config: "client\ndev tun\nremote vpn.example.com 1194 udp", files: [:])
        b.dnsDomains = (1...33).map { "d\($0).example.com" }
        expectThrows("33", matching: "at most 32") { _ = try h.start(bundle: try JSONEncoder().encode(b), uid: 501) }
        expect(sys.launched.isEmpty)
    }
    test("PS-56", "the owner of all names reconnects (a new utun) and ends before its DNS: the next gets all names") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let a = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        let b = try dnsUp(sys, h, "utun6", "10.9.0", ["dns_server_1_address_1=10.9.0.53"])
        expectEqual(h.list(uid: 501).first { $0.id == b }?.dns, "waiting")
        sys.utunName = "utun7"
        sys.clock += 5
        _ = try h.tunnelRequest(id: a, uid: 501, kind: "OPENTUN", message: "tun")   // a reconnect: its DNS goes
        expectEqual(h.list(uid: 501).first { $0.id == b }?.dns, "all", "not left waiting for a DNSUP that may not come")
        sys.launched[0].process.onExit(.exited(1))
        expectEqual(h.list(uid: 501).first { $0.id == b }?.dns, "all")
    }
    test("PS-57", "handing all names on: the record first, the system after; a refusal of either leaves things as they were") {
        // setDNS refused: the split DNS it had stays (put back), still limited.
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let a = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        let b = try dnsUp(sys, h, "utun6", "10.9.0", ["dns_server_1_address_1=10.9.0.53", "dns_search_domain_1=corp.lan"])
        sys.failAllNamesDNS = true
        sys.clock += 5
        _ = try h.tunnelRequest(id: a, uid: 501, kind: "DNSDOWN", message: "utun5")
        expectEqual(h.list(uid: 501).first { $0.id == b }?.dns, "limited", "still its domains")
        expectEqual(sys.dnsSet.last?.searchDomains, ["corp.lan"], "put back whole")
        sys.failAllNamesDNS = false
        let saved = String(decoding: sys.files["/L/run/\(b)/state.json"]?.data ?? Data(), as: UTF8.self)
        expect(saved.contains("corp.lan"), "the record says its split DNS: \(saved)")
        // The record cannot be written: nothing changed on the system.
        let s2 = FakeSystem()
        let h2 = makeHelper(s2)
        let a2 = try dnsUp(s2, h2, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        let b2 = try dnsUp(s2, h2, "utun6", "10.9.0", ["dns_server_1_address_1=10.9.0.53"])
        s2.failWrites = ["/L/run/\(b2)/state.json"]
        let setBefore = s2.dnsSet.count
        s2.clock += 5
        _ = try h2.tunnelRequest(id: a2, uid: 501, kind: "DNSDOWN", message: "utun5")
        expectEqual(s2.dnsSet.count, setBefore, "no DNS set without its record")
        expectEqual(h2.list(uid: 501).first { $0.id == b2 }?.dns, "waiting")
    }
    test("PS-57b", "handing all names on refused and its split DNS cannot be put back: not claimed as set") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let a = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        let b = try dnsUp(sys, h, "utun6", "10.9.0", ["dns_server_1_address_1=10.9.0.53", "dns_search_domain_1=corp.lan"])
        sys.failDNSFor = ["utun6"]
        sys.clock += 5
        _ = try h.tunnelRequest(id: a, uid: 501, kind: "DNSDOWN", message: "utun5")
        expectEqual(h.list(uid: 501).first { $0.id == b }?.dns, "waiting", "its DNS is off")
    }
    test("PS-58", "all names handed on only once the owner's own change is recorded: one owner at most") {
        for kind in ["DNSDOWN", "OPENTUN"] {
            let sys = FakeSystem()
            let h = makeHelper(sys)
            let a = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
            let b = try dnsUp(sys, h, "utun6", "10.9.0", ["dns_server_1_address_1=10.9.0.53"])
            sys.failNthWrite = 1       // the owner's record of its own change fails (its rollback is recorded)
            sys.utunName = "utun7"
            sys.clock += 5
            expectThrows(kind) { _ = try h.tunnelRequest(id: a, uid: 501, kind: kind, message: kind == "DNSDOWN" ? "utun5" : "tun") }
            let owners = h.list(uid: 501).filter { $0.dns == "all" }.map(\.id)
            expect(owners.count <= 1, "\(kind): \(owners)")
            expectEqual(h.list(uid: 501).first { $0.id == b }?.dns, "waiting", "\(kind): not handed on")
            let last = sys.dnsSet.last
            expect(last?.device == "utun5" && last?.split == false, "\(kind): the owner's DNS set again with its record: \(String(describing: last))")
            sys.failWrites = []
        }
    }
    test("PS-59", "a rolled-back DNS change puts back the whole plan it had; a refusal of that is not claimed as set") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let a = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53", "dns_search_domain_1=corp.lan"])
        sys.failNthWrite = 1
        sys.clock += 5
        expectThrows("DNSDOWN") { _ = try h.tunnelRequest(id: a, uid: 501, kind: "DNSDOWN", message: "utun5") }
        expectEqual(sys.dnsSet.last?.searchDomains, ["corp.lan"], "its search domains too")
        expectEqual(h.list(uid: 501).first { $0.id == a }?.dns, "all")
        // Putting it back refused: not shown as set.
        sys.failDNSFor = ["utun5"]
        sys.failNthWrite = 1
        sys.clock += 5
        expectThrows("DNSDOWN") { _ = try h.tunnelRequest(id: a, uid: 501, kind: "DNSDOWN", message: "utun5") }
        expectEqual(h.list(uid: 501).first { $0.id == a }?.dns, nil, "no DNS claimed")
    }
    test("PS-60", "a DNS change that only moves its search domains, not recorded: the old plan back, on the Mac and as last set") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let a = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53", "dns_search_domain_1=a.lan"])
        _ = try h.tunnelRequest(id: a, uid: 501, kind: "DNSVAR", message: "dns_search_domain_1=b.lan")
        sys.clock += 5
        sys.failNthWrite = 2   // the record ahead is written, the final one is not
        expectThrows("DNSUP") { _ = try h.tunnelRequest(id: a, uid: 501, kind: "DNSUP", message: "utun5") }
        expectEqual(sys.dnsSet.last?.searchDomains, ["a.lan"], "the Mac back on the old plan")
        // What a later rollback puts back is the old plan too.
        sys.clock += 5
        sys.failNthWrite = 1
        expectThrows("DNSDOWN") { _ = try h.tunnelRequest(id: a, uid: 501, kind: "DNSDOWN", message: "utun5") }
        expectEqual(sys.dnsSet.last?.searchDomains, ["a.lan"])
        expectEqual(h.list(uid: 501).first { $0.id == a }?.dns, "all")
    }
    test("PS-61", "a rollback that cannot be recorded: the connection is undone and stopped (not left with a wrong record)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, id, uid: 501, device: "utun5", routes: ["10.20.0.0 255.255.0.0 10.8.0.1"])
        sys.failAfterWrites = 1   // the record ahead only: the final write and the rollback's fail
        expectThrows("ROUTE") { _ = try h.tunnelRequest(id: id, uid: 501, kind: "ROUTE", message: "10.30.0.0 255.255.0.0 10.8.0.1") }
        sys.failAfterWrites = nil
        expectEqual(sys.launched[0].process.signals, [SIGKILL], "stopped")
        expect(!sys.routeTable.contains { $0.contains("10.20.0.0") || $0.contains("10.30.0.0") }, "and undone")
    }
    test("PS-62", "DNS set again in another mode: the old one is taken off first (all names to split frees them)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let a = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        let b = try dnsUp(sys, h, "utun6", "10.9.0", ["dns_server_1_address_1=10.9.0.53"])
        _ = try h.tunnelRequest(id: a, uid: 501, kind: "DNSVAR", message: "dns_server_1_resolve_domain_1=corp.lan")
        sys.clock += 5
        _ = try h.tunnelRequest(id: a, uid: 501, kind: "DNSUP", message: "utun5")
        expectEqual(sys.splitResolvers["utun5"]?.matchDomains, ["corp.lan"])
        expectEqual(sys.allNames["utun5"], nil, "the primary's DNS no longer a's")
        expectEqual(h.list(uid: 501).first { $0.id == a }?.dns, "split")
        expectEqual(sys.allNames["utun6"]?.servers, ["10.9.0.53"], "all names to the one waiting")
        expectEqual(h.list(uid: 501).first { $0.id == b }?.dns, "all")
    }
    test("PS-62b", "DNS set again refused: the old one back on, as it was") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let a = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        _ = try h.tunnelRequest(id: a, uid: 501, kind: "DNSVAR", message: "dns_server_1_resolve_domain_1=corp.lan")
        sys.clock += 5
        // Split refused, all names still accepted: the old plan goes back.
        let old = sys.allNames["utun5"]
        sys.failSplitDNS = true
        expectThrows("DNSUP") { _ = try h.tunnelRequest(id: a, uid: 501, kind: "DNSUP", message: "utun5") }
        expectEqual(sys.allNames["utun5"], old)
        expectEqual(sys.splitResolvers["utun5"], nil)
        expectEqual(h.list(uid: 501).first { $0.id == a }?.dns, "all")
    }
    test("PS-63", "all names handed on only to a plan that still passes the checks (its DNS server still inside its tunnel)") {
        let sys = FakeSystem()
        try sys.makeDirectory("/L", mode: 0o755)
        try sys.writeFile("/L/policy.json", Data(#"{"usersMayChangeDNS": true}"#.utf8), mode: 0o644)
        sys.systemDNS = ["192.168.64.1"]
        let h = makeHelper(sys)
        let a = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        let (b, _) = try h.start(bundle: psBundle(), uid: 502)
        sys.utunName = "utun6"
        _ = try h.tunnelRequest(id: b, uid: 502, kind: "OPENTUN", message: "tun")
        _ = try h.tunnelRequest(id: b, uid: 502, kind: "IFCONFIG", message: "10.9.0.2 255.255.255.0 1500 subnet")
        _ = try h.tunnelRequest(id: b, uid: 502, kind: "ROUTE", message: "10.99.0.0 255.255.0.0 10.9.0.1")
        _ = try h.tunnelRequest(id: b, uid: 502, kind: "DNSVAR", message: "dns_server_1_address_1=10.99.0.53")
        _ = try? h.tunnelRequest(id: b, uid: 502, kind: "DNSUP", message: "utun6")
        expectEqual(h.list(uid: 502).first { $0.id == b }?.dns, "waiting")
        _ = try h.tunnelRequest(id: b, uid: 502, kind: "ROUTEDEL", message: "10.99.0.0 255.255.0.0 10.9.0.1")
        sys.clock += 5
        _ = try h.tunnelRequest(id: a, uid: 501, kind: "DNSDOWN", message: "utun5")
        expectEqual(sys.allNames["utun6"], nil, "its DNS server is no longer inside its tunnel")
        expect(h.list(uid: 502).first { $0.id == b }?.dns != "all")
    }
    test("PS-64", "a DNS change rolled back takes its place in the queue for all names back too") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let a = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        let b = try dnsUp(sys, h, "utun6", "10.9.0", ["dns_server_1_address_1=10.9.0.53", "dns_search_domain_1=corp.lan"], dnsUp: false)
        sys.failNthWrite = 2   // its record ahead written, the final one not
        expectThrows("DNSUP") { _ = try h.tunnelRequest(id: b, uid: 501, kind: "DNSUP", message: "utun6") }
        sys.clock += 5
        _ = try h.tunnelRequest(id: a, uid: 501, kind: "DNSDOWN", message: "utun5")
        expectEqual(sys.allNames["utun6"], nil, "not given all names for a request that failed")
        expectEqual(h.list(uid: 501).first { $0.id == b }?.dns, nil)
    }
    test("PS-65", "DNS that cannot be taken off: not claimed off, all names not handed on") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let a = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        let b = try dnsUp(sys, h, "utun6", "10.9.0", ["dns_server_1_address_1=10.9.0.53"])
        sys.failRestoreFor = ["utun5"]
        sys.clock += 5
        expectThrows("DNSDOWN") { _ = try h.tunnelRequest(id: a, uid: 501, kind: "DNSDOWN", message: "utun5") }
        expectEqual(h.list(uid: 501).first { $0.id == a }?.dns, "all")
        expectEqual(h.list(uid: 501).first { $0.id == b }?.dns, "waiting")
        // A reconnect (a new utun) likewise.
        sys.utunName = "utun7"
        expectThrows("OPENTUN") { _ = try h.tunnelRequest(id: a, uid: 501, kind: "OPENTUN", message: "tun") }
        expectEqual(h.list(uid: 501).first { $0.id == b }?.dns, "waiting")
        expectEqual(sys.allNames["utun5"]?.servers, ["10.8.0.53"])
    }
    test("PS-67", "a tunnel's DNS that cannot be taken off when it ends: kept on record, tried again, all names not handed on till then") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let a = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        let b = try dnsUp(sys, h, "utun6", "10.9.0", ["dns_server_1_address_1=10.9.0.53"])
        _ = a
        sys.failRestoreFor = ["utun5"]
        sys.launched[0].process.onExit(.exited(1))
        expectEqual(sys.allNames["utun6"], nil, "not while a's may still be in effect")
        expectEqual(h.list(uid: 501).first { $0.id == b }?.dns, "waiting")
        expect(sys.files["/L/dns-left.json"] != nil, "on record (outlives the helper)")
        sys.failRestoreFor = []
        sys.fireTimers()
        expectEqual(sys.allNames["utun5"], nil)
        expectEqual(sys.allNames["utun6"]?.servers, ["10.9.0.53"], "handed on once a's is off")
        expect(sys.files["/L/dns-left.json"] == nil)
    }
    test("PS-67b", "the helper starts again: DNS a dead tunnel left (its record, or one not taken off before) taken off, or kept on record") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        _ = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        sys.failRestoreFor = ["utun5"]
        try makeHelper(sys).prepareRunDirectory()
        expect(sys.files["/L/dns-left.json"] != nil, "not lost with the run directory")
        sys.failRestoreFor = []
        let h2 = makeHelper(sys)
        try h2.prepareRunDirectory()
        expectEqual(sys.allNames["utun5"], nil)
        expect(sys.files["/L/dns-left.json"] == nil)
    }
    test("PS-68", "a route taken away that its DNS server needed (a standard user's): its DNS goes with it") {
        let sys = FakeSystem()
        try sys.makeDirectory("/L", mode: 0o755)
        try sys.writeFile("/L/policy.json", Data(#"{"usersMayChangeDNS": true}"#.utf8), mode: 0o644)
        sys.systemDNS = ["192.168.64.1"]
        let h = makeHelper(sys)
        let (b, _) = try h.start(bundle: psBundle(), uid: 502)
        sys.utunName = "utun6"
        _ = try h.tunnelRequest(id: b, uid: 502, kind: "OPENTUN", message: "tun")
        _ = try h.tunnelRequest(id: b, uid: 502, kind: "IFCONFIG", message: "10.9.0.2 255.255.255.0 1500 subnet")
        _ = try h.tunnelRequest(id: b, uid: 502, kind: "ROUTE", message: "10.99.0.0 255.255.0.0 10.9.0.1")
        _ = try h.tunnelRequest(id: b, uid: 502, kind: "DNSVAR", message: "dns_server_1_address_1=10.99.0.53")
        _ = try h.tunnelRequest(id: b, uid: 502, kind: "DNSVAR", message: "dns_server_1_resolve_domain_1=corp.lan")
        _ = try h.tunnelRequest(id: b, uid: 502, kind: "DNSUP", message: "utun6")
        expectEqual(sys.splitResolvers["utun6"]?.servers, ["10.99.0.53"])
        _ = try h.tunnelRequest(id: b, uid: 502, kind: "ROUTEDEL", message: "10.99.0.0 255.255.0.0 10.9.0.1")
        expectEqual(sys.splitResolvers["utun6"], nil, "its server is outside the tunnel now")
        expectEqual(h.list(uid: 502).first { $0.id == b }?.dns, nil)
        let saved = String(decoding: sys.files["/L/run/\(b)/state.json"]?.data ?? Data(), as: UTF8.self)
        expect(!saved.contains("10.99.0.53\"]"), "the record says no DNS: \(saved)")
    }
    test("PS-69", "DNS taken off because its server left the tunnel: on record as set until it is off (a crash between keeps it undone)") {
        let (sys, h, b) = try standardSplit()
        var onDisk = ""
        sys.onRestore = { _ in onDisk = String(decoding: sys.files["/L/run/\(b)/state.json"]?.data ?? Data(), as: UTF8.self) }
        _ = try h.tunnelRequest(id: b, uid: 502, kind: "ROUTEDEL", message: "10.99.0.0 255.255.0.0 10.9.0.1")
        expect(onDisk.contains("\"dnsApplied\":true"), "the record still says set while it is taken off: \(onDisk)")
        expectEqual(sys.splitResolvers["utun6"], nil)
    }
    test("PS-70", "any change of its tunnel checks its DNS again: a new address (IFCONFIG) or a host route around it (ROUTE)") {
        let (sys, h, b) = try standardSplit(inSubnet: true)
        _ = try h.tunnelRequest(id: b, uid: 502, kind: "IFCONFIG", message: "10.7.0.2 255.255.255.0 1500 subnet")
        expectEqual(sys.splitResolvers["utun6"], nil, "its server is no longer in its network")
        let (s2, h2, b2) = try standardSplit(routeAll: true)
        _ = try h2.tunnelRequest(id: b2, uid: 502, kind: "ROUTE", message: "10.99.0.53 255.255.255.255 192.168.64.1")
        expectEqual(s2.splitResolvers["utun6"], nil, "the more specific route takes its server around the tunnel")
        expectEqual(h2.list(uid: 502).first { $0.id == b2 }?.dns, nil)
    }
    test("PS-71", "uninstalling while DNS of a tunnel could not be taken off: refused with why, the helper stays to try again") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        _ = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        sys.failRestoreFor = ["utun5"]
        var answer: String?? = .none
        try h.uninstall(uid: 501, keepProfiles: false) { answer = .some($0) }
        sys.launched[0].process.onExit(.signaled(15))
        expect(answer != nil, "answered")
        expectEqual(answer ?? nil, HelperRefusal.dnsCleanupPending, "said why")
        expect(sys.files["/L/dns-left.json"] != nil, "the record to try again stays")
        sys.failRestoreFor = []
        try h.uninstall(uid: 501, keepProfiles: false) { answer = .some($0) }
        expectEqual(answer, .some(nil), "taken off now: uninstalled")
    }
    test("PS-72", "its DNS off but its backup left (all names held back): removed later, all names handed on then") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let a = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        let b = try dnsUp(sys, h, "utun6", "10.9.0", ["dns_server_1_address_1=10.9.0.53"])
        sys.failBackupRemovalFor = ["utun5"]
        sys.clock += 5
        _ = try h.tunnelRequest(id: a, uid: 501, kind: "DNSDOWN", message: "utun5")
        expectEqual(h.list(uid: 501).first { $0.id == a }?.dns, nil, "its DNS is off")
        expectEqual(h.list(uid: 501).first { $0.id == b }?.dns, "waiting", "the backup left holds all names back")
        sys.failBackupRemovalFor = []
        sys.fireTimers()
        expect(sys.backupsLeft.isEmpty)
        expectEqual(h.list(uid: 501).first { $0.id == b }?.dns, "all")
    }
    test("PS-73", "the record of DNS left behind cannot be written: the tunnel's own record is kept (not removed with its run directory)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let a = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        sys.failRestoreFor = ["utun5"]
        sys.failWrites = ["/L/dns-left.json"]
        sys.launched[0].process.onExit(.exited(1))
        expect(sys.files["/L/run/\(a)/state.json"] != nil, "kept for the next helper")
        sys.failWrites = []
        sys.failRestoreFor = []
        try makeHelper(sys).prepareRunDirectory()
        expectEqual(sys.allNames["utun5"], nil, "taken off by the next helper")
    }
    test("PS-74", "all names refused with the backup made for it left behind: on record, removed later") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        sys.failAllNamesDNS = true
        sys.leaveBackupOnFailedSet = ["utun5"]
        _ = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        expect(sys.files["/L/dns-left.json"] != nil, "the backup left is on record")
        sys.failAllNamesDNS = false
        sys.leaveBackupOnFailedSet = []
        sys.fireTimers()
        expect(sys.backupsLeft.isEmpty)
        expect(sys.files["/L/dns-left.json"] == nil)
    }
    test("PS-75", "its DNS off, the backup left and dns-left not writable: shown off (as it is), the backup on its own record, all names held back") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let a = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        let b = try dnsUp(sys, h, "utun6", "10.9.0", ["dns_server_1_address_1=10.9.0.53"])
        sys.failBackupRemovalFor = ["utun5"]
        sys.failWrites = ["/L/dns-left.json"]
        sys.clock += 5
        _ = try h.tunnelRequest(id: a, uid: 501, kind: "DNSDOWN", message: "utun5")
        expectEqual(h.list(uid: 501).first { $0.id == a }?.dns, nil, "not shown as set: it is not")
        let saved = String(decoding: sys.files["/L/run/\(a)/state.json"]?.data ?? Data(), as: UTF8.self)
        expect(saved.contains("\"dnsBackupLeft\":\"utun5\""), "the backup left is on its record: \(saved)")
        expectEqual(h.list(uid: 501).first { $0.id == b }?.dns, "waiting", "all names held back by it")
        sys.failBackupRemovalFor = []
        sys.failWrites = []
        sys.fireTimers()
        expect(sys.backupsLeft.isEmpty)
        expectEqual(h.list(uid: 501).first { $0.id == b }?.dns, "all")
        // Its record of a backup left is undone by a new helper too.
        let s2 = FakeSystem()
        let h2 = makeHelper(s2)
        let a2 = try dnsUp(s2, h2, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        s2.failBackupRemovalFor = ["utun5"]
        s2.failWrites = ["/L/dns-left.json"]
        s2.clock += 5
        _ = try h2.tunnelRequest(id: a2, uid: 501, kind: "DNSDOWN", message: "utun5")
        s2.failBackupRemovalFor = []
        s2.failWrites = []
        try makeHelper(s2).prepareRunDirectory()
        expect(s2.backupsLeft.isEmpty, "removed by the next helper")
    }
    test("PS-76", "a route deleted but the change not recorded: the route put back (the record and the Mac agree)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, id, uid: 501, device: "utun5", routes: ["10.20.0.0 255.255.0.0 10.8.0.1"])
        sys.failNthWrite = 1
        expectThrows("ROUTEDEL") { _ = try h.tunnelRequest(id: id, uid: 501, kind: "ROUTEDEL", message: "10.20.0.0 255.255.0.0 10.8.0.1") }
        expect(sys.routeTable.contains { $0.contains("10.20.0.0") }, "back as the record says")
        // Cannot be put back: the connection is undone and stopped.
        let s2 = FakeSystem()
        let h2 = makeHelper(s2)
        let (id2, _) = try h2.start(bundle: psBundle(), uid: 501)
        try bringUp(s2, h2, id2, uid: 501, device: "utun5", routes: ["10.20.0.0 255.255.0.0 10.8.0.1"])
        s2.failNthWrite = 1
        s2.failRouteAdds = true
        expectThrows("ROUTEDEL") { _ = try h2.tunnelRequest(id: id2, uid: 501, kind: "ROUTEDEL", message: "10.20.0.0 255.255.0.0 10.8.0.1") }
        expectEqual(s2.launched[0].process.signals, [SIGKILL])
    }
    test("PS-77", "uninstall after the app went to the Trash, held back by DNS left: done once that DNS is off") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        var gone = false
        h.onUninstalled = { gone = true }
        _ = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        sys.failRestoreFor = ["utun5"]
        h.uninstallMovedToTrash()
        sys.launched[0].process.onExit(.signaled(15))
        expect(!gone, "held back")
        sys.failRestoreFor = []
        sys.fireTimers()
        expect(gone, "uninstalled once the DNS is off")
    }
    test("PS-79", "an older run's DNS (from its log) not taken off and not recordable: its directory stays for the next helper") {
        let sys = FakeSystem()
        try sys.makeDirectory("/L/run", mode: 0o711)
        try sys.makeDirectory("/L/run/OLD1", mode: 0o711)
        try sys.writeFile("/L/run/OLD1/openvpn.log", Data(sampleLog(device: "utun3").utf8), mode: 0o644)
        sys.failRestoreFor = ["utun3"]
        sys.failWrites = ["/L/dns-left.json"]
        try makeHelper(sys).prepareRunDirectory()
        expect(sys.files["/L/run/OLD1/openvpn.log"] != nil, "kept")
        sys.failRestoreFor = []
        sys.failWrites = []
        try makeHelper(sys).prepareRunDirectory()
        expectEqual(sys.dnsRestored, ["utun3"])
        expect(sys.list("/L/run").isEmpty)
    }
    test("PS-80", "a route deletion rolled back (not recorded): the route and the DNS it carried both back") {
        let (sys, h, b) = try standardSplit()
        sys.failNthWrite = 1
        expectThrows("ROUTEDEL") { _ = try h.tunnelRequest(id: b, uid: 502, kind: "ROUTEDEL", message: "10.99.0.0 255.255.0.0 10.9.0.1") }
        expect(sys.routeTable.contains { $0.contains("10.99.0.0") }, "the route back")
        expectEqual(sys.splitResolvers["utun6"]?.servers, ["10.99.0.53"], "and its DNS")
        expectEqual(h.list(uid: 502).first { $0.id == b }?.dns, "split")
    }
    test("PS-81", "uninstall after the Trash held back by DNS left: on disk, done by the next helper once the DNS is off") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        _ = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        sys.failRestoreFor = ["utun5"]
        h.uninstallMovedToTrash()
        sys.launched[0].process.onExit(.signaled(15))
        expect(sys.files["/L/uninstall-pending.json"] != nil, "the wish outlives the helper")
        sys.failRestoreFor = []
        let h2 = makeHelper(sys)
        var gone = false
        h2.onUninstalled = { gone = true }
        try h2.prepareRunDirectory()
        expect(gone, "the next helper finishes it")
    }
    test("PS-82", "all names off with the backup left, the new DNS refused, all names back: the backup is theirs again (never removed under them)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let a = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        _ = try h.tunnelRequest(id: a, uid: 501, kind: "DNSVAR", message: "dns_server_1_resolve_domain_1=corp.lan")
        sys.failBackupRemovalFor = ["utun5"]
        sys.failWrites = ["/L/dns-left.json"]
        sys.failSplitDNS = true
        sys.clock += 5
        expectThrows("DNSUP") { _ = try h.tunnelRequest(id: a, uid: 501, kind: "DNSUP", message: "utun5") }
        expectEqual(h.list(uid: 501).first { $0.id == a }?.dns, "all", "the old DNS back")
        let saved = String(decoding: sys.files["/L/run/\(a)/state.json"]?.data ?? Data(), as: UTF8.self)
        expect(!saved.contains("dnsBackupLeft"), "no backup left over: it is the live one's \(saved)")
        sys.failBackupRemovalFor = []
        sys.failWrites = []
        sys.failSplitDNS = false
        sys.fireTimers()
        expect(sys.lostBackups.isEmpty, "not removed under all names")
        sys.launched[0].process.onExit(.exited(0))
        expectEqual(sys.allNames["utun5"], nil, "put back at the end")
        expect(sys.lostBackups.isEmpty)
    }
    test("PS-83", "the wish to uninstall after the Trash not writable at first: written later, kept until uninstalled") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        _ = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        sys.failRestoreFor = ["utun5"]
        sys.failWrites = ["/L/uninstall-pending.json"]
        h.uninstallMovedToTrash()
        sys.launched[0].process.onExit(.signaled(15))
        expect(sys.files["/L/uninstall-pending.json"] == nil)
        sys.failWrites = []
        sys.fireTimers()
        expect(sys.files["/L/uninstall-pending.json"] != nil, "written on a later try")
        sys.failRestoreFor = []
        let h2 = makeHelper(sys)
        var gone = false
        h2.onUninstalled = { gone = true }
        try h2.prepareRunDirectory()
        expect(gone)
    }
    test("PS-84", "a record (an earlier version's) of all names and a backup left on the same device, its DNS not taken off: the backup stays") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let a = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        let path = "/L/run/\(a)/state.json"
        var state = try JSONSerialization.jsonObject(with: sys.files[path]!.data) as! [String: Any]
        state["dnsBackupLeft"] = "utun5"
        try sys.writeFile(path, try JSONSerialization.data(withJSONObject: state), mode: 0o600)
        sys.failRestoreFor = ["utun5"]
        try makeHelper(sys).prepareRunDirectory()
        expect(sys.lostBackups.isEmpty, "the only copy of the Mac's own DNS kept")
        expect(sys.files["/L/dns-left.json"] != nil, "left on record to take off")
    }
    test("PS-85", "an uninstall waiting for DNS (after the Trash, keeping profiles), then an administrator's without: profiles go too") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        try sys.writeFile("/L/config/office.ovpn", Data("client".utf8), mode: 0o644)
        _ = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        sys.failRestoreFor = ["utun5"]
        h.uninstallMovedToTrash()
        sys.launched[0].process.onExit(.signaled(15))
        var answer: String?? = .none
        try h.uninstall(uid: 501, keepProfiles: false) { answer = .some($0) }
        expectEqual(answer ?? nil, HelperRefusal.dnsCleanupPending)
        let marker = String(decoding: sys.files["/L/uninstall-pending.json"]?.data ?? Data(), as: UTF8.self)
        expect(marker.contains("false"), "the wish on disk: profiles go \(marker)")
        sys.failRestoreFor = []
        sys.fireTimers()
        expect(sys.files["/L/config/office.ovpn"] == nil, "removed as the last request asked")
    }
    test("PS-86", "a standard user's uninstall while one waits for DNS: refused before anything changes (profiles kept as asked)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        try sys.writeFile("/L/config/office.ovpn", Data("client".utf8), mode: 0o644)
        _ = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        sys.failRestoreFor = ["utun5"]
        h.uninstallMovedToTrash()
        sys.launched[0].process.onExit(.signaled(15))
        let marker = sys.files["/L/uninstall-pending.json"]?.data
        expectThrows(matching: "administrator") { try h.uninstall(uid: 502, keepProfiles: false) }
        expectEqual(sys.files["/L/uninstall-pending.json"]?.data, marker, "the wish on disk unchanged")
        sys.failRestoreFor = []
        sys.fireTimers()
        expect(sys.files["/L/config/office.ovpn"] != nil, "profiles kept, as the Trash uninstall asked")
    }
    test("PS-87", "uninstalling after the Trash: the wish on disk until all else is gone and checked, then it goes before success is said") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        try sys.writeFile("/LD/com.mugvpn.helper.plist", Data("<plist/>".utf8), mode: 0o644)
        var gone = false
        h.onUninstalled = { gone = sys.files["/L/uninstall-pending.json"] == nil }
        h.uninstallMovedToTrash()
        expect(gone, "the wish gone before launchd is asked to let go (a helper started again from the Trash finds that on its own)")
        let order = sys.removedPaths
        expectEqual(order.last, "/L/uninstall-pending.json", "the wish last: \(order)")
        expect(order.firstIndex(of: "/LD/com.mugvpn.helper.plist")! < order.firstIndex(of: "/L/uninstall-pending.json")!)
    }
    test("PS-109", "a wish to uninstall found by a helper that runs from a reinstalled app (not the Trash): dropped, nothing removed") {
        let sys = FakeSystem()
        try sys.makeDirectory("/L", mode: 0o755)
        try sys.writeFile("/L/uninstall-pending.json", Data(#"{"keepProfiles":true}"#.utf8), mode: 0o600)
        try sys.writeFile("/LD/com.mugvpn.helper.plist", Data("<plist/>".utf8), mode: 0o644)
        sys.runningFromTrash = false
        let h = makeHelper(sys)
        var gone = false
        h.onUninstalled = { gone = true }
        try h.prepareRunDirectory()
        expect(!gone, "not uninstalled")
        expect(sys.files["/L/uninstall-pending.json"] == nil, "the stale wish dropped")
        expect(sys.files["/LD/com.mugvpn.helper.plist"] != nil)
    }
    test("PS-110", "an uninstall after the Trash stopped halfway (a file would not go): its wish stays, a helper starting again finishes") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        try sys.writeFile("/LD/com.mugvpn.helper.plist", Data("<plist/>".utf8), mode: 0o644)
        try? sys.makeDirectory("/L/libexec", mode: 0o755)
        sys.failRemoves = ["/L/libexec"]
        h.uninstallMovedToTrash()
        expect(sys.files["/L/uninstall-pending.json"] != nil, "the wish still on disk")
        expect(sys.files["/LD/com.mugvpn.helper.plist"] != nil)
        sys.failRemoves = []
        let h2 = makeHelper(sys)          // the helper (or the Mac) started again
        var gone = false
        h2.onUninstalled = { gone = true }
        try h2.prepareRunDirectory()
        expect(gone, "finished")
    }
    test("PS-88", "same-named profiles stay apart in the helper: their ids listed, their blocks and kept logs their own") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        func bundle(_ id: String) throws -> Data {
            var b = ProfileBundle(name: "office", config: "client\ndev tun\nremote vpn.example.com 1194 udp", files: [:])
            b.profileID = id
            b.protection = ProtectionOptions(killSwitch: true)
            return try JSONEncoder().encode(b)
        }
        let (a, _) = try h.start(bundle: try bundle("/cfg/office.ovpn"), uid: 501)
        let (b, _) = try h.start(bundle: try bundle("/cfg/berlin/office.ovpn"), uid: 501)
        expectEqual(Set(h.list(uid: 501).compactMap(\.profileID)), ["/cfg/office.ovpn", "/cfg/berlin/office.ovpn"])
        try bringUp(sys, h, a, uid: 501, device: "utun5")
        try bringUp(sys, h, b, uid: 501, device: "utun6", routes: ["0.0.0.0 128.0.0.0 10.8.0.1", "128.0.0.0 128.0.0.0 10.8.0.1"])
        for id in [a, b] { try sys.writeFile("/L/run/\(id)/openvpn.log", Data("log \(id)".utf8), mode: 0o600) }
        sys.launched[0].process.onExit(.exited(1))      // a drops: its block
        _ = h.stop(id: b, uid: 501)
        sys.launched[1].process.onExit(.exited(0))      // b ends as asked
        let kept = sys.list("/Logs").filter { $0.hasPrefix("office") }
        expectEqual(kept.count, 2, "a log each: \(kept)")
        expectEqual(h.locks(uid: 501), ["office"], "shown by name")
        let saved = String(decoding: sys.files["/L/locks.json"]?.data ?? Data(), as: UTF8.self)
        expectEqual(saved.components(separatedBy: "office~").count - 1, 1, "one block, a's (keyed by id): \(saved)")
    }
    test("PS-89", "a route that cannot be deleted when its tunnel ends: its record kept and tried again until it goes") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, id, uid: 501, device: "utun5", routes: ["203.0.113.7 255.255.255.255 192.168.64.1"])
        sys.failRouteDeletes = true
        sys.launched[0].process.onExit(.exited(0))
        expect(sys.files["/L/run/\(id)/state.json"] != nil, "its record stays")
        sys.failRouteDeletes = false
        sys.fireTimers()
        expect(!sys.routeTable.contains { $0.contains("203.0.113.7") }, "deleted on a later try")
        expect(sys.files["/L/run/\(id)/state.json"] == nil, "then its record goes")
    }
    test("PS-89b", "ROUTEDEL whose route cannot be deleted: refused, the record keeps it (the Mac still has it)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, id, uid: 501, device: "utun5", routes: ["203.0.113.7 255.255.255.255 192.168.64.1"])
        sys.failRouteDeletes = true
        expectThrows("ROUTEDEL") { _ = try h.tunnelRequest(id: id, uid: 501, kind: "ROUTEDEL", message: "203.0.113.7 255.255.255.255 192.168.64.1") }
        let saved = String(decoding: sys.files["/L/run/\(id)/state.json"]?.data ?? Data(), as: UTF8.self)
        expect(saved.contains("203.0.113.7"), "still on record: \(saved)")
    }
    test("PS-90", "Append to the log: the kept log grows by each run (bounded, the newest kept); otherwise replaced") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        func run(_ text: String, append: Bool) throws {
            var b = ProfileBundle(name: "office", config: "client\ndev tun\nremote vpn.example.com 1194 udp", files: [:])
            b.profileID = "/cfg/office.ovpn"
            b.appendLog = append
            let (id, _) = try h.start(bundle: try JSONEncoder().encode(b), uid: 501)
            try sys.writeFile("/L/run/\(id)/openvpn.log", Data(text.utf8), mode: 0o600)
            _ = h.stop(id: id, uid: 501)
            sys.launched.last!.process.onExit(.exited(0))
        }
        let kept = "/Logs/" + ProfileKey.logName(profile: "office", id: "/cfg/office.ovpn", uid: 501) + ".log"
        try run("first\n", append: true)
        try run("second\n", append: true)
        expectEqual(String(decoding: sys.files[kept]?.data ?? Data(), as: UTF8.self), "first\nsecond\n")
        try run("third\n", append: false)
        expectEqual(String(decoding: sys.files[kept]?.data ?? Data(), as: UTF8.self), "third\n")
        try run(String(repeating: "x", count: HelperCore.maxKeptLogBytes), append: true)
        expectEqual(sys.files[kept]?.data.count, HelperCore.maxKeptLogBytes, "bounded")
    }
    test("PS-91", "ROUTE6DEL whose route stays: refused, still on record") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, id, uid: 501, device: "utun5", routes: [])
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "ROUTE6", message: "fd00:1::/48 utun5")
        sys.failRouteDeletes = true
        expectThrows("ROUTE6DEL") { _ = try h.tunnelRequest(id: id, uid: 501, kind: "ROUTE6DEL", message: "fd00:1::/48 utun5") }
        let saved = String(decoding: sys.files["/L/run/\(id)/state.json"]?.data ?? Data(), as: UTF8.self)
        expect(saved.contains("fd00:1::"), "still on record: \(saved)")
    }
    test("PS-92", "a default route in two halves, the second refused, the first not taken back: undone and stopped, the half on record") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, id, uid: 501, device: "utun5", routes: [])
        sys.failRouteAddFor = ["128.0.0.0"]
        sys.failRouteDeletes = true
        expectThrows("ROUTE") { _ = try h.tunnelRequest(id: id, uid: 501, kind: "ROUTE", message: "0.0.0.0 0.0.0.0 10.8.0.1") }
        expectEqual(sys.launched[0].process.signals, [SIGKILL], "undone and stopped")
        sys.launched[0].process.onExit(.signaled(9))
        let saved = String(decoding: sys.files["/L/run/\(id)/state.json"]?.data ?? Data(), as: UTF8.self)
        expect(saved.contains("\"0.0.0.0\""), "the half still there is on record: \(saved)")
    }
    test("PS-93", "a new route the rollback cannot take away: kept on record, the connection undone and stopped") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, id, uid: 501, device: "utun5", routes: [])
        sys.failNthWrite = 2          // the record ahead written, the final one not
        sys.failRouteDeletes = true   // and the route it added does not go
        expectThrows("ROUTE") { _ = try h.tunnelRequest(id: id, uid: 501, kind: "ROUTE", message: "203.0.113.7 255.255.255.255 192.168.64.1") }
        expectEqual(sys.launched[0].process.signals, [SIGKILL], "undone and stopped")
        sys.launched[0].process.onExit(.signaled(9))
        let saved = String(decoding: sys.files["/L/run/\(id)/state.json"]?.data ?? Data(), as: UTF8.self)
        expect(saved.contains("203.0.113.7"), "the route still there is on record: \(saved)")
        sys.failRouteDeletes = false
        sys.fireTimers()
        expect(!sys.routeTable.contains { $0.contains("203.0.113.7") }, "taken away on a later try")
    }
    test("PS-94", "a route a dead tunnel left that cannot be deleted at helper start: tried again while it runs") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, id, uid: 501, device: "utun5", routes: ["203.0.113.7 255.255.255.255 192.168.64.1"])
        sys.failRouteDeletes = true
        let h2 = makeHelper(sys)
        try h2.prepareRunDirectory()
        expect(sys.files["/L/run/\(id)/state.json"] != nil, "kept")
        sys.failRouteDeletes = false
        sys.fireTimers()
        expect(!sys.routeTable.contains { $0.contains("203.0.113.7") })
        expect(sys.files["/L/run/\(id)/state.json"] == nil, "then gone")
    }
    test("PS-95", "a route that stays and DNS put on record: the run's own record is still kept (the route needs it)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let a = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        _ = try h.tunnelRequest(id: a, uid: 501, kind: "ROUTE", message: "203.0.113.7 255.255.255.255 192.168.64.1")
        sys.failRouteDeletes = true
        sys.failRestoreFor = ["utun5"]
        sys.launched[0].process.onExit(.exited(1))
        expect(sys.files["/L/dns-left.json"] != nil, "DNS on record")
        expect(sys.files["/L/run/\(a)/state.json"] != nil, "and the route's record kept")
    }
    test("PS-96", "uninstalling while PF will not let go of MugVPN's rules: refused with why, the helper stays to try again") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        try sys.writeFile("/LD/com.mugvpn.helper.plist", Data("<plist/>".utf8), mode: 0o644)
        var answer: String?? = .none
        sys.pfApplyFails = true
        try h.uninstall(uid: 501, keepProfiles: false) { answer = .some($0) }
        expect((answer ?? nil)?.contains("PF") == true, "said why: \(String(describing: answer))")
        expect(sys.files["/LD/com.mugvpn.helper.plist"] != nil, "the helper stays")
        sys.pfApplyFails = false
        try h.uninstall(uid: 501, keepProfiles: false) { answer = .some($0) }
        expectEqual(answer, .some(nil))
        expect(sys.files["/LD/com.mugvpn.helper.plist"] == nil)
    }
    test("PS-97", "kept logs over the limit: the oldest go (by when they were written, not by name)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        try? sys.makeDirectory("/Logs", mode: 0o755)
        for i in 0..<HelperCore.keptLogsPerUser {
            sys.clock = TimeInterval(100 + i)
            // "z…" is the oldest, the last letter written the newest: the name order is the other way round.
            try sys.writeFile("/Logs/\(String(UnicodeScalar(UInt8(122 - i))))old.501.log", Data("x".utf8), mode: 0o600)
        }
        sys.clock = 1000
        let (id, _) = try h.start(bundle: psBundle(), uid: 501)
        try sys.writeFile("/L/run/\(id)/openvpn.log", Data("new".utf8), mode: 0o600)
        _ = h.stop(id: id, uid: 501)
        sys.launched[0].process.onExit(.exited(0))
        let left = sys.list("/Logs").filter { $0.hasSuffix(".501.log") }
        expect(!left.contains("zold.501.log"), "the oldest went: \(left.sorted())")
        let newest = String(UnicodeScalar(UInt8(122 - (HelperCore.keptLogsPerUser - 1)))) + "old.501.log"
        expect(left.contains(newest), "the newest stayed")
        expectEqual(left.count, HelperCore.keptLogsPerUser)
    }
    test("PS-98", "uninstalling: a file that does not go (the blocks, the helper's own) is said, the helper stays to try again") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        try sys.writeFile("/LD/com.mugvpn.helper.plist", Data("<plist/>".utf8), mode: 0o644)
        try sys.writeFile("/L/locks.json", Data("[]".utf8), mode: 0o600)
        sys.failRemoves = ["/L/locks.json"]
        var answer: String?? = .none
        try h.uninstall(uid: 501, keepProfiles: true) { answer = .some($0) }
        expect((answer ?? nil) != nil, "not claimed done")
        expect(sys.files["/LD/com.mugvpn.helper.plist"] != nil, "the helper stays")
        sys.failRemoves = ["/L/libexec"]
        try? sys.makeDirectory("/L/libexec", mode: 0o755)
        try h.uninstall(uid: 501, keepProfiles: true) { answer = .some($0) }
        expect((answer ?? nil)?.contains("/L/libexec") == true, "\(String(describing: answer))")
        expect(sys.files["/LD/com.mugvpn.helper.plist"] != nil)
        sys.failRemoves = []
        try h.uninstall(uid: 501, keepProfiles: true) { answer = .some($0) }
        expectEqual(answer, .some(nil))
    }
    test("PS-99", "an older version's run (from its log): routes that will not go keep its folder, tried again while the helper runs") {
        let sys = FakeSystem()
        try sys.makeDirectory("/L/run", mode: 0o711)
        try sys.makeDirectory("/L/run/OLD1", mode: 0o711)
        try sys.writeFile("/L/run/OLD1/openvpn.log", Data(sampleLog(device: "utun3").utf8), mode: 0o644)
        sys.failLegacyRoutes = true
        let h = makeHelper(sys)
        try h.prepareRunDirectory()
        expect(sys.files["/L/run/OLD1/openvpn.log"] != nil, "kept")
        sys.failLegacyRoutes = false
        sys.fireTimers()
        expect(sys.files["/L/run/OLD1/openvpn.log"] == nil, "cleaned up and gone")
    }
    test("PS-100", "a log whose rename into place is refused: its run folder stays and it is put in place on a later try") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        var b = ProfileBundle(name: "office", config: "client\ndev tun\nremote vpn.example.com 1194 udp", files: [:])
        b.profileID = "/cfg/office.ovpn"
        let (id, _) = try h.start(bundle: try JSONEncoder().encode(b), uid: 501)
        try sys.writeFile("/L/run/\(id)/openvpn.log", Data("why it dropped".utf8), mode: 0o600)
        let kept = "/Logs/" + ProfileKey.logName(profile: "office", id: "/cfg/office.ovpn", uid: 501) + ".log"
        sys.failMoves = [kept]
        _ = h.stop(id: id, uid: 501)
        sys.launched[0].process.onExit(.exited(0))
        expect(sys.files[kept] == nil && sys.dirs["/L/run/\(id)"] != nil, "not written in place by halves; the run kept")
        sys.failMoves = []
        sys.fireTimers()
        expectEqual(String(decoding: sys.files[kept]?.data ?? Data(), as: UTF8.self), "why it dropped")
    }
    test("PS-101", "DNS a dead tunnel left on a utun a live one has again: not taken off under it (the live one's own end does)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let a = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        sys.failRestoreFor = ["utun5"]
        sys.launched[0].process.onExit(.exited(1))          // a's DNS left on record
        sys.failRestoreFor = []
        _ = a
        let b = try dnsUp(sys, h, "utun5", "10.9.0", ["dns_server_1_address_1=10.9.0.53"])   // utun5 again, its DNS
        let before = sys.dnsRestored.count
        sys.fireTimers()
        expectEqual(sys.dnsRestored.count, before, "the live one's DNS not taken off")
        expectEqual(h.list(uid: 501).first { $0.id == b }?.dns, "all")
    }
    test("PS-102", "ROUTEDEL of a default route: one half gone, the other stays, the first not back: undone and stopped") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, id, uid: 501, device: "utun5", routes: [])
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "ROUTE", message: "0.0.0.0 0.0.0.0 10.8.0.1")
        // The second half does not go; the first cannot be put back.
        sys.failRouteDeleteFor = ["128.0.0.0"]
        sys.failRouteAdds = true
        expectThrows("ROUTEDEL") { _ = try h.tunnelRequest(id: id, uid: 501, kind: "ROUTEDEL", message: "0.0.0.0 0.0.0.0 10.8.0.1") }
        expectEqual(sys.launched[0].process.signals, [SIGKILL], "not left with a record of a route that is not there")
    }
    test("PS-103", "a log neither moved nor copied into place: its run folder stays, the log saved later (not lost)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        var b = ProfileBundle(name: "office", config: "client\ndev tun\nremote vpn.example.com 1194 udp", files: [:])
        b.profileID = "/cfg/office.ovpn"
        let (id, _) = try h.start(bundle: try JSONEncoder().encode(b), uid: 501)
        try sys.writeFile("/L/run/\(id)/openvpn.log", Data("why it dropped".utf8), mode: 0o600)
        let kept = "/Logs/" + ProfileKey.logName(profile: "office", id: "/cfg/office.ovpn", uid: 501) + ".log"
        sys.failMoves = [kept]
        sys.failWrites = [kept]
        _ = h.stop(id: id, uid: 501)
        sys.launched[0].process.onExit(.exited(0))
        expect(sys.files["/L/run/\(id)/openvpn.log.kept"] != nil, "still in its run folder (marked moved)")
        sys.failMoves = []
        sys.failWrites = []
        sys.fireTimers()
        expectEqual(String(decoding: sys.files[kept]?.data ?? Data(), as: UTF8.self), "why it dropped")
        expect(sys.files["/L/run/\(id)/openvpn.log"] == nil)
    }
    test("PS-104", "a connection undone at once (fail closed) takes its own DNS off (its utun is not someone else's)") {
        let (sys, h, b) = try standardSplit()
        sys.failNthWrite = 1           // its rollback cannot be recorded: undone and stopped
        sys.failWrites = ["/L/run/\(b)/state.json"]
        _ = try? h.tunnelRequest(id: b, uid: 502, kind: "ROUTE", message: "10.98.0.0 255.255.0.0 10.9.0.1")
        expectEqual(sys.launched[0].process.signals, [SIGKILL], "undone and stopped")
        expectEqual(sys.splitResolvers["utun6"], nil, "its DNS taken off")
    }
    test("PS-105", "the helper starts again after a crash: the dead tunnel's log is kept (it says why it dropped)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, id, uid: 501, device: "utun5", routes: [])
        try sys.writeFile("/L/run/\(id)/openvpn.log", Data("the last words".utf8), mode: 0o600)
        sys.dirs["/Logs"] = nil          // a fresh install: no logs folder yet
        sys.failWritesWithoutDir = true
        try makeHelper(sys).prepareRunDirectory()
        expect(sys.list("/L/run").isEmpty, "its folder gone at once (not left for a retry)")
        let kept = "/Logs/" + ProfileKey.logName(profile: "office", id: nil, uid: 501) + ".log"
        expectEqual(String(decoding: sys.files[kept]?.data ?? Data(), as: UTF8.self), "the last words")
    }
    test("PS-106", "the log of a tunnel that died with the helper: kept as its profile's log, its user's to read") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        var b = ProfileBundle(name: "office", config: "client\ndev tun\nremote vpn.example.com 1194 udp", files: [:])
        b.profileID = "/cfg/office.ovpn"
        let (id, _) = try h.start(bundle: try JSONEncoder().encode(b), uid: 501)
        try bringUp(sys, h, id, uid: 501, device: "utun5", routes: [])
        try sys.writeFile("/L/run/\(id)/openvpn.log", Data("the last words".utf8), mode: 0o600)
        try makeHelper(sys).prepareRunDirectory()
        let kept = "/Logs/" + ProfileKey.logName(profile: "office", id: "/cfg/office.ovpn", uid: 501) + ".log"
        expectEqual(String(decoding: sys.files[kept]?.data ?? Data(), as: UTF8.self), "the last words", "View Log finds it")
        expectEqual(sys.owners[kept]?.uid, 501, "its user's")
    }
    test("PS-107", "a dead run's log that cannot be kept at helper start: tried again while the helper runs") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, id, uid: 501, device: "utun5", routes: [])
        try sys.writeFile("/L/run/\(id)/openvpn.log", Data("words".utf8), mode: 0o600)
        let h2 = makeHelper(sys)
        sys.failMoves = Set(["/Logs/recovered-\(id).log", "/Logs/" + ProfileKey.logName(profile: "office", id: nil, uid: 501) + ".log"])
        sys.failWrites = sys.failMoves
        try h2.prepareRunDirectory()
        expect(sys.files["/L/run/\(id)/openvpn.log"] != nil || sys.files["/L/run/\(id)/openvpn.log.kept"] != nil, "its run's copy kept")
        sys.failMoves = []
        sys.failWrites = []
        sys.fireTimers()
        expect(sys.files["/L/run/\(id)/openvpn.log"] == nil && sys.files["/L/run/\(id)/openvpn.log.kept"] == nil, "kept on a later try")
    }
    test("PS-108", "a dead run 0.2.4 recorded (no profile, no user): its log kept for administrators to read") {
        let sys = FakeSystem()
        try sys.makeDirectory("/L/run", mode: 0o711)
        try sys.makeDirectory("/L/run/OLD", mode: 0o711)
        // What 0.2.4 wrote: the tunnel only.
        try sys.writeFile("/L/run/OLD/state.json", Data(#"{"device":"utun5","routes":[],"dnsVars":{},"dnsApplied":false,"opened":["utun5"]}"#.utf8), mode: 0o600)
        try sys.writeFile("/L/run/OLD/openvpn.log", Data("words".utf8), mode: 0o600)
        try makeHelper(sys).prepareRunDirectory()
        expectEqual(String(decoding: sys.files["/Logs/recovered-OLD.log"]?.data ?? Data(), as: UTF8.self), "words")
        expectEqual(sys.owners["/Logs/recovered-OLD.log"]?.gid, 80, "administrators may read it")
        expect(sys.list("/L/run").isEmpty)
    }
    test("PS-111", "a route deletion half done that cannot be put back: its DNS taken off (never put back), the connection undone") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let a = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        _ = try h.tunnelRequest(id: a, uid: 501, kind: "ROUTE", message: "0.0.0.0 0.0.0.0 10.8.0.1")
        sys.failRouteDeleteFor = ["128.0.0.0"]
        sys.failRouteAdds = true
        let setBefore = sys.dnsSet.count
        expectThrows("ROUTEDEL") { _ = try h.tunnelRequest(id: a, uid: 501, kind: "ROUTEDEL", message: "0.0.0.0 0.0.0.0 10.8.0.1") }
        expectEqual(sys.dnsSet.count, setBefore, "its DNS not set again")
        expectEqual(sys.allNames["utun5"], nil, "taken off")
        expectEqual(sys.launched[0].process.signals, [SIGKILL])
    }
    test("PS-112", "an older version's run with more routes than one pass takes: all deleted over passes, its folder kept till then") {
        let sys = FakeSystem()
        try sys.makeDirectory("/L/run", mode: 0o711)
        try sys.makeDirectory("/L/run/OLD1", mode: 0o711)
        let n = HelperCore.maxCleanupRoutes + 40
        let routes = (0..<n).map { "2026-10-06 05:46:44 /sbin/route add -net 10.\(1 + $0 / 250).\($0 % 250).0 192.168.64.1 255.255.255.0" }
        try sys.writeFile("/L/run/OLD1/openvpn.log", Data((["2026-10-06 05:46:44 Opened utun device utun3"] + routes).joined(separator: "\n").utf8), mode: 0o644)
        let h = makeHelper(sys)
        try h.prepareRunDirectory()
        sys.fireTimers()
        expectEqual(Set(sys.routesDeleted.map { $0.joined(separator: " ") }).count, n, "every one of them deleted (a batch a pass)")
        expect(sys.dirs["/L/run/OLD1"] == nil, "then gone")
    }
    test("PS-113", "a dead run's log written but not given to its user: its own copy stays, given on a later try") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        var b = ProfileBundle(name: "office", config: "client\ndev tun\nremote vpn.example.com 1194 udp", files: [:])
        b.profileID = "/cfg/office.ovpn"
        let (id, _) = try h.start(bundle: try JSONEncoder().encode(b), uid: 501)
        try bringUp(sys, h, id, uid: 501, device: "utun5", routes: [])
        try sys.writeFile("/L/run/\(id)/openvpn.log", Data("words".utf8), mode: 0o600)
        let kept = "/Logs/" + ProfileKey.logName(profile: "office", id: "/cfg/office.ovpn", uid: 501) + ".log"
        sys.failOwners = [kept]
        let h2 = makeHelper(sys)
        try h2.prepareRunDirectory()
        expect(sys.files["/L/run/\(id)/openvpn.log.kept"] != nil, "its run folder and its copy (marked moved) stay")
        sys.failOwners = []
        sys.fireTimers()
        expectEqual(sys.owners[kept]?.uid, 501)
        expect(sys.files["/L/run/\(id)/openvpn.log"] == nil)
    }
    test("PS-114", "an older run's route that would not go in an early batch: tried again, the folder kept until it goes") {
        let sys = FakeSystem()
        try sys.makeDirectory("/L/run", mode: 0o711)
        try sys.makeDirectory("/L/run/OLD1", mode: 0o711)
        let n = HelperCore.maxCleanupRoutes + 40
        let routes = (0..<n).map { "2026-10-06 05:46:44 /sbin/route add -net 10.\(1 + $0 / 250).\($0 % 250).0 192.168.64.1 255.255.255.0" }
        try sys.writeFile("/L/run/OLD1/openvpn.log", Data((["2026-10-06 05:46:44 Opened utun device utun3"] + routes).joined(separator: "\n").utf8), mode: 0o644)
        sys.failLegacyRouteFor = ["10.1.5.0"]      // one in the first batch
        let h = makeHelper(sys)
        try h.prepareRunDirectory()
        sys.fireTimers()
        expect(sys.dirs["/L/run/OLD1"] != nil, "kept while that one stays")
        sys.failLegacyRouteFor = []
        sys.routesDeleted = []
        sys.fireTimers()
        expect(sys.routesDeleted.contains { $0.contains("10.1.5.0") }, "tried again")
        expect(sys.dirs["/L/run/OLD1"] == nil, "then gone")
    }
    test("PS-115", "fail-closed after a half route deletion: a DNS backup left and not recordable stays on the record") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let a = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        _ = try h.tunnelRequest(id: a, uid: 501, kind: "ROUTE", message: "0.0.0.0 0.0.0.0 10.8.0.1")
        sys.failRouteDeleteFor = ["128.0.0.0"]
        sys.failRouteAdds = true
        sys.failBackupRemovalFor = ["utun5"]
        sys.failWrites = ["/L/dns-left.json"]
        _ = try? h.tunnelRequest(id: a, uid: 501, kind: "ROUTEDEL", message: "0.0.0.0 0.0.0.0 10.8.0.1")
        let saved = String(decoding: sys.files["/L/run/\(a)/state.json"]?.data ?? Data(), as: UTF8.self)
        expect(saved.contains("dnsBackupLeft"), "the backup left is on its record: \(saved)")
    }
    test("PS-116", "a dead run's log appended, not yet given to its user: a later try does not append it twice") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        var b = ProfileBundle(name: "office", config: "client\ndev tun\nremote vpn.example.com 1194 udp", files: [:])
        b.profileID = "/cfg/office.ovpn"
        b.appendLog = true
        let (id, _) = try h.start(bundle: try JSONEncoder().encode(b), uid: 501)
        try bringUp(sys, h, id, uid: 501, device: "utun5", routes: [])
        let kept = "/Logs/" + ProfileKey.logName(profile: "office", id: "/cfg/office.ovpn", uid: 501) + ".log"
        try sys.writeFile(kept, Data("old\n".utf8), mode: 0o600)
        try sys.writeFile("/L/run/\(id)/openvpn.log", Data("new\n".utf8), mode: 0o600)
        sys.failOwners = [kept]
        let h2 = makeHelper(sys)
        try h2.prepareRunDirectory()
        sys.failOwners = []
        sys.fireTimers()
        expectEqual(String(decoding: sys.files[kept]?.data ?? Data(), as: UTF8.self), "old\nnew\n", "once")
    }
    test("PS-117", "a dead run's log appended, stopped before its copy was marked moved: a later try does not append it twice") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        var b = ProfileBundle(name: "office", config: "client\ndev tun\nremote vpn.example.com 1194 udp", files: [:])
        b.profileID = "/cfg/office.ovpn"
        b.appendLog = true
        let (id, _) = try h.start(bundle: try JSONEncoder().encode(b), uid: 501)
        try bringUp(sys, h, id, uid: 501, device: "utun5", routes: [])
        let kept = "/Logs/" + ProfileKey.logName(profile: "office", id: "/cfg/office.ovpn", uid: 501) + ".log"
        try sys.writeFile(kept, Data("old\n".utf8), mode: 0o600)
        try sys.writeFile("/L/run/\(id)/openvpn.log", Data("new\n".utf8), mode: 0o600)
        sys.failMoves = ["/L/run/\(id)/openvpn.log.kept"]      // marking it moved fails
        let h2 = makeHelper(sys)
        try h2.prepareRunDirectory()
        sys.failMoves = []
        sys.fireTimers()
        expectEqual(String(decoding: sys.files[kept]?.data ?? Data(), as: UTF8.self), "old\nnew\n", "once")
    }
    test("PS-118", "uninstalling with profiles not kept (not after the Trash): the support folder itself goes too") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        try sys.makeDirectory("/L", mode: 0o755)
        try sys.writeFile("/L/config/office.ovpn", Data("client".utf8), mode: 0o644)
        var answer: String?? = .none
        try h.uninstall(uid: 501, keepProfiles: false) { answer = .some($0) }
        expectEqual(answer, .some(nil))
        expect(sys.dirs["/L"] == nil && !sys.files.keys.contains { $0.hasPrefix("/L/") }, "nothing of it left")
    }
    test("PS-119", "a tunnel that ends, its log appended but not yet its user's: a later try does not append it twice") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        var b = ProfileBundle(name: "office", config: "client\ndev tun\nremote vpn.example.com 1194 udp", files: [:])
        b.profileID = "/cfg/office.ovpn"
        b.appendLog = true
        let (id, _) = try h.start(bundle: try JSONEncoder().encode(b), uid: 501)
        let kept = "/Logs/" + ProfileKey.logName(profile: "office", id: "/cfg/office.ovpn", uid: 501) + ".log"
        try sys.writeFile(kept, Data("old\n".utf8), mode: 0o600)
        try sys.writeFile("/L/run/\(id)/openvpn.log", Data("new\n".utf8), mode: 0o600)
        sys.failOwners = [kept]
        _ = h.stop(id: id, uid: 501)
        sys.launched[0].process.onExit(.exited(0))
        sys.failOwners = []
        sys.fireTimers()
        expectEqual(String(decoding: sys.files[kept]?.data ?? Data(), as: UTF8.self), "old\nnew\n", "once")
    }
    test("PS-120", "a run's log staged in its own folder (two dead runs of one profile never share it)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        var b = ProfileBundle(name: "office", config: "client\ndev tun\nremote vpn.example.com 1194 udp", files: [:])
        b.profileID = "/cfg/office.ovpn"
        let (id, _) = try h.start(bundle: try JSONEncoder().encode(b), uid: 501)
        let kept = "/Logs/" + ProfileKey.logName(profile: "office", id: "/cfg/office.ovpn", uid: 501) + ".log"
        try sys.writeFile("/L/run/\(id)/openvpn.log", Data("words".utf8), mode: 0o600)
        sys.failMoves = [kept]
        sys.failWrites = [kept]
        _ = h.stop(id: id, uid: 501)
        sys.launched[0].process.onExit(.exited(0))
        expect(sys.files["/L/run/\(id)/openvpn.log.new"] != nil, "staged in its run's folder")
        expect(!sys.files.keys.contains { $0.hasPrefix("/Logs/") && $0.hasSuffix(".new") }, "nothing staged in the shared logs folder")
    }
    test("PS-121", "a run's files whose owner or mode cannot be set: openvpn not started, the run folder gone") {
        for path in ["/L/run/ID1/config.ovpn", "/L/run/ID1/sock"] {
            let sys = FakeSystem()
            let h = makeHelper(sys)
            sys.failOwners = [path]
            expectThrows(path, matching: "could not set") { _ = try h.start(bundle: psBundle(), uid: 501) }
            expect(sys.launched.isEmpty, "\(path): not started")
            expect(sys.dirs["/L/run/ID1"] == nil, "\(path): nothing left")
        }
    }
    test("PS-122", "a run folder whose removal is refused: kept on the list, tried again") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 501)
        sys.failRemoves = ["/L/run/\(id)"]
        _ = h.stop(id: id, uid: 501)
        sys.launched[0].process.onExit(.exited(0))
        expect(sys.dirs["/L/run/\(id)"] != nil)
        sys.failRemoves = []
        sys.fireTimers()
        expect(sys.dirs["/L/run/\(id)"] == nil, "gone on a later try")
    }
    test("PS-123", "two dead runs of one profile, both appending, the first stopped before its log was in place: both logs kept") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        var b = ProfileBundle(name: "office", config: "client\ndev tun\nremote vpn.example.com 1194 udp", files: [:])
        b.profileID = "/cfg/office.ovpn"
        b.appendLog = true
        let (a, _) = try h.start(bundle: try JSONEncoder().encode(b), uid: 501)
        let kept = "/Logs/" + ProfileKey.logName(profile: "office", id: "/cfg/office.ovpn", uid: 501) + ".log"
        // a staged old+A and marked its copy moved, but stopped before putting it in place; another run (B) of the
        // profile has appended its log since.
        try sys.writeFile("/L/run/\(a)/openvpn.log.new", Data("old\nA\n".utf8), mode: 0o600)
        try sys.writeFile("/L/run/\(a)/openvpn.log.kept", Data("A\n".utf8), mode: 0o600)
        try sys.writeFile(kept, Data("old\nB\n".utf8), mode: 0o600)
        try makeHelper(sys).prepareRunDirectory()
        let text = String(decoding: sys.files[kept]?.data ?? Data(), as: UTF8.self)
        expect(text.contains("A\n") && text.contains("B\n") && text.hasPrefix("old\n"), "both kept: \(text)")
        expectEqual(text.components(separatedBy: "A\n").count - 1, 1, "each once")
    }
    test("PS-124", "a log in place, its owner not set, another run appended since: the retry does not append it again") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        var b = ProfileBundle(name: "office", config: "client\ndev tun\nremote vpn.example.com 1194 udp", files: [:])
        b.profileID = "/cfg/office.ovpn"
        b.appendLog = true
        let (a, _) = try h.start(bundle: try JSONEncoder().encode(b), uid: 501)
        let kept = "/Logs/" + ProfileKey.logName(profile: "office", id: "/cfg/office.ovpn", uid: 501) + ".log"
        // A was put in place (its copy alone marked moved), then B appended.
        try sys.writeFile("/L/run/\(a)/openvpn.log.kept", Data("A\n".utf8), mode: 0o600)
        try sys.writeFile(kept, Data("old\nA\nB\n".utf8), mode: 0o600)
        try makeHelper(sys).prepareRunDirectory()
        expectEqual(String(decoding: sys.files[kept]?.data ?? Data(), as: UTF8.self), "old\nA\nB\n", "A once")
        expectEqual(sys.owners[kept]?.uid, 501)
    }
    test("PS-125", "a run whose log is the same as the last one kept: appended all the same (content does not decide)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        var b = ProfileBundle(name: "office", config: "client\ndev tun\nremote vpn.example.com 1194 udp", files: [:])
        b.profileID = "/cfg/office.ovpn"
        b.appendLog = true
        let (id, _) = try h.start(bundle: try JSONEncoder().encode(b), uid: 501)
        let kept = "/Logs/" + ProfileKey.logName(profile: "office", id: "/cfg/office.ovpn", uid: 501) + ".log"
        try sys.writeFile(kept, Data("same\n".utf8), mode: 0o600)
        try sys.writeFile("/L/run/\(id)/openvpn.log", Data("same\n".utf8), mode: 0o600)
        _ = h.stop(id: id, uid: 501)
        sys.launched[0].process.onExit(.exited(0))
        expectEqual(String(decoding: sys.files[kept]?.data ?? Data(), as: UTF8.self), "same\nsame\n")
    }
    test("PS-126", "not appending, the old kept log ending as the new one: replaced by the new one alone") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        var b = ProfileBundle(name: "office", config: "client\ndev tun\nremote vpn.example.com 1194 udp", files: [:])
        b.profileID = "/cfg/office.ovpn"
        let (id, _) = try h.start(bundle: try JSONEncoder().encode(b), uid: 501)
        let kept = "/Logs/" + ProfileKey.logName(profile: "office", id: "/cfg/office.ovpn", uid: 501) + ".log"
        try sys.writeFile(kept, Data("old\nnew\n".utf8), mode: 0o600)
        try sys.writeFile("/L/run/\(id)/openvpn.log.new", Data("new\n".utf8), mode: 0o600)
        try sys.writeFile("/L/run/\(id)/openvpn.log.kept", Data("new\n".utf8), mode: 0o600)
        try makeHelper(sys).prepareRunDirectory()
        expectEqual(String(decoding: sys.files[kept]?.data ?? Data(), as: UTF8.self), "new\n")
    }
    test("PS-127", "after the Trash, a user's log or settings that would not go: not finished, the wish kept, a helper starting again removes them") {
        let sys = FakeSystem()
        sys.userHomes = ["/Users/a", "/var/home/b", "/Users/c"]
        for home in sys.userHomes { try makeHome(sys, home) }
        // c's Library a link (to wherever c likes): nothing removed through it.
        sys.dirs["/Users/c/Library"] = nil
        sys.links.insert("/Users/c/Library")
        try sys.makeDirectory("/Users/c/Library/Logs/MugVPN", mode: 0o755)
        for d in ["/Users/a/Library/Logs/MugVPN", "/var/home/b/Library/Logs/MugVPN"] { try sys.makeDirectory(d, mode: 0o755) }
        try sys.writeFile("/var/home/b/Library/Preferences/com.mugvpn.app.plist", Data(), mode: 0o600)
        try sys.writeFile("/LD/com.mugvpn.helper.plist", Data("<plist/>".utf8), mode: 0o644)
        sys.failRemoves = ["/Users/a/Library/Logs/MugVPN"]
        let h = makeHelper(sys)
        var gone = false
        var notes: [String] = []
        h.onNote = { notes.append($0) }
        h.onUninstalled = { gone = true }
        h.uninstallMovedToTrash()
        expect(notes.contains { $0.contains("/Users/c/Library/Logs/MugVPN") && $0.contains("not safe") },
               "one behind a link: left and said, not taken for removed \(notes)")
        expect(!gone, "not finished while a user's log stays")
        expect(sys.files["/L/uninstall-pending.json"] != nil, "the wish still on disk")
        expect(sys.files["/LD/com.mugvpn.helper.plist"] != nil, "the helper stays registered to try again")
        expect(sys.fileInfo("/var/home/b/Library/Preferences/com.mugvpn.app.plist") == nil, "a home outside /Users too")
        sys.failRemoves = []
        let h2 = makeHelper(sys)
        h2.onUninstalled = { gone = true }
        try h2.prepareRunDirectory()
        expect(gone, "finished by the next helper")
        expect(sys.fileInfo("/Users/a/Library/Logs/MugVPN") == nil)
        expect(sys.fileInfo("/Users/c/Library/Logs/MugVPN") != nil, "not through a link")
    }
    test("PS-128", "a full uninstall joining one after the Trash: the support folder goes too, checked before success is said") {
        let sys = FakeSystem()
        try sys.makeDirectory("/L", mode: 0o755)
        try sys.writeFile("/L/config/office.ovpn", Data("client".utf8), mode: 0o644)
        let h = makeHelper(sys)
        var gone = false
        h.onUninstalled = { gone = true }
        _ = try h.start(bundle: bundle(), uid: 501)
        h.uninstallMovedToTrash()
        var answer: String?? = .none
        try h.uninstall(uid: 0, keepProfiles: false) { answer = .some($0) }
        sys.launched[0].process.onExit(.exited(0))
        expect(gone)
        expectEqual(answer ?? "no answer", nil)
        expect(sys.files["/L/uninstall-pending.json"] == nil, "the wish gone")
        expect(sys.fileInfo("/L") == nil, "and the support folder (profiles were not kept)")
    }
    test("PS-129", "after the Trash keeping profiles: the wish goes, profiles stay; a wish or folder that would not go: not finished, tried again") {
        let sys = FakeSystem()
        try sys.writeFile("/L/config/office.ovpn", Data("client".utf8), mode: 0o644)
        let h = makeHelper(sys)
        var gone = false
        h.onUninstalled = { gone = true }
        sys.failRemoves = ["/L/uninstall-pending.json"]
        h.uninstallMovedToTrash()
        expect(!gone, "the wish would not go: not finished")
        expect(sys.fileInfo("/L/uninstall-pending.json") != nil)
        sys.failRemoves = []
        sys.fireTimers()
        expect(gone, "tried again")
        expect(sys.fileInfo("/L/uninstall-pending.json") == nil)
        expect(sys.fileInfo("/L/config/office.ovpn") != nil, "profiles stay")
        let sys2 = FakeSystem()
        try sys2.makeDirectory("/L", mode: 0o755)
        let h2 = makeHelper(sys2)
        var answer: String?? = .none
        sys2.failRemoves = ["/L"]
        try h2.uninstall(uid: 0, keepProfiles: false) { answer = .some($0) }
        expect((answer ?? nil)?.hasPrefix(HelperRefusal.filesPending) == true, "the support folder would not go: said \(String(describing: answer))")
    }
    test("PS-132", "where the app is installed: kept while the helper runs from it, read back when it runs from the Trash (after a restart)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        expectEqual(h.appLocation(running: "/Applications/MugVPN.app/Contents"), "/Applications/MugVPN.app/Contents")
        expectEqual(sys.files["/L/app-location"].map { String(decoding: $0.data, as: UTF8.self) }, "/Applications/MugVPN.app/Contents")
        expectEqual(sys.files["/L/app-location"]?.mode, 0o600)
        let again = makeHelper(sys)       // started again, from the Trash
        expectEqual(again.appLocation(running: "/Users/u/.Trash/MugVPN.app/Contents"), "/Applications/MugVPN.app/Contents",
                    "where it was installed (a replacement there keeps it)")
        expectEqual(sys.files["/L/app-location"].map { String(decoding: $0.data, as: UTF8.self) }, "/Applications/MugVPN.app/Contents",
                    "the Trash never recorded")
        let none = FakeSystem()
        expectEqual(makeHelper(none).appLocation(running: "/Users/u/.Trash/MugVPN.app/Contents"), nil, "not known: not in place")
        try none.writeFile("/L/app-location", Data("/Users/u/.Trash/X.app/Contents".utf8), mode: 0o600)
        expectEqual(makeHelper(none).appLocation(running: "/Users/u/.Trash/MugVPN.app/Contents"), nil, "a Trash location never counts")
        // In place, it goes with uninstalling.
        h.uninstallMovedToTrash()
        expect(sys.fileInfo("/L/app-location") == nil, "removed with the rest")
    }
    test("PS-130", "the live log its owner could not be let read: the connection not started, said, nothing of it left") {
        let sys = FakeSystem()
        sys.failGrants = true
        let h = makeHelper(sys)
        expectThrows(matching: "read this connection's log") { _ = try h.start(bundle: bundle(), uid: 501) }
        expect(h.list(uid: 0).isEmpty)
        expect(sys.list("/L/run").isEmpty, "its run folder gone")
    }
    test("PS-131", "users' logs and settings removed only step by step from their home (never by a path root resolves again)") {
        let sys = FakeSystem()
        sys.userHomes = ["/Users/a"]
        try makeHome(sys, "/Users/a")
        try sys.makeDirectory("/Users/a/Library/Logs/MugVPN", mode: 0o755)
        let h = makeHelper(sys)
        h.uninstallMovedToTrash()
        expect(!sys.removedPaths.contains { $0.hasPrefix("/Users/") }, "no plain remove in a home: \(sys.removedPaths)")
        expect(sys.homeRemovals.contains("/Users/a|Library/Logs|MugVPN"), "\(sys.homeRemovals)")
        expect(sys.homeRemovals.contains("/Users/a|Library/Preferences|com.mugvpn.app.plist"))
        expect(sys.fileInfo("/Users/a/Library/Logs/MugVPN") == nil)
    }
    test("PS-133", "a volume mounted in a user's MugVPN logs: not entered, left and said; the uninstall finishes") {
        let sys = FakeSystem()
        sys.userHomes = ["/Users/a"]
        try makeHome(sys, "/Users/a")
        try sys.makeDirectory("/Users/a/Library/Logs/MugVPN", mode: 0o755)
        try sys.makeDirectory("/Users/a/Library/Logs/MugVPN/vol", mode: 0o755)
        try sys.writeFile("/Users/a/Library/Logs/MugVPN/vol/data", Data("x".utf8), mode: 0o644)
        sys.mounts = ["/Users/a/Library/Logs/MugVPN/vol"]
        let h = makeHelper(sys)
        var notes: [String] = [], gone = false
        h.onNote = { notes.append($0) }
        h.onUninstalled = { gone = true }
        h.uninstallMovedToTrash()
        expect(sys.files["/Users/a/Library/Logs/MugVPN/vol/data"] != nil, "the volume's files stay")
        expect(notes.contains { $0.contains("/Users/a/Library/Logs/MugVPN") }, "\(notes)")
        expect(gone, "nothing more root could do: finished, said")
    }
    test("PS-134", "the app in the Trash: a boot cleanup of the system's shell kept for the next boot; out of the Trash, unloaded and removed") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let helper = "/Users/u/.Trash/MugVPN.app/Contents/MacOS/MugVPNHelper"
        h.bootCleanup(armed: true, helper: helper, app: "/Applications/MugVPN.app/Contents")
        let plist = "/LD/com.mugvpn.cleanup.plist"
        expectEqual(sys.files[plist]?.mode, 0o644)
        let p = try PropertyListSerialization.propertyList(from: sys.files[plist]?.data ?? Data(), format: nil) as? [String: Any]
        expectEqual(p?["Label"] as? String, "com.mugvpn.cleanup")
        expectEqual(p?["RunAtLoad"] as? Bool, true)
        let env = p?["EnvironmentVariables"] as? [String: String] ?? [:]
        expectEqual(env, ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "MUGVPN_HELPER": helper,
                          "MUGVPN_APP_INFO": "/Applications/MugVPN.app/Contents/Info.plist"],
                    "where to look, in its environment (its arguments hold nothing a process pattern matches)")
        let args = p?["ProgramArguments"] as? [String] ?? []
        expectEqual(Array(args.prefix(2)), ["/bin/sh", "-c"], "nothing of MugVPN's runs it (gone by then)")
        let script = args.last ?? ""
        expect(!script.contains(helper) && !script.contains("MugVPNHelper") && !script.contains("libexec/openvpn"),
               "no path a process pattern looks for: \(script)")
        expect(script.hasPrefix("[ -n \"$MUGVPN_HELPER\" ] || exit 1; [ -e \"$MUGVPN_HELPER\" ] && exit 0; "),
               "left be while the helper (or a replacement) is there; not told where: nothing done \(script)")
        expect(script.contains("gone_from_launchd com.mugvpn.helper 30 || {"), "nothing removed unless launchd is known to have no helper")
        expect(script.contains("|| { say 'not all removed"), "a removal that fails is not success")
        expect(!script.contains("/L/config") && !script.contains("/L/auto") && !script.contains("policy"), "profiles stay")
        let sh = Process()
        sh.executableURL = URL(fileURLWithPath: "/bin/sh")
        sh.arguments = ["-n", "-c", script]
        try sh.run()
        sh.waitUntilExit()
        expectEqual(sh.terminationStatus, 0, "valid sh")
        sys.loadedJobs = ["com.mugvpn.cleanup"]
        sys.failUnload = ["com.mugvpn.cleanup"]
        h.bootCleanup(armed: false, helper: helper, app: nil)
        expect(sys.files[plist] != nil, "launchd would not let go of it: its file stays (tried again)")
        sys.failUnload = []
        h.bootCleanup(armed: false, helper: helper, app: nil)
        expect(sys.files[plist] == nil && sys.loadedJobs.isEmpty, "out of the Trash: unloaded, then removed")
    }
    test("PS-135", "the boot cleanup leaves launchd wherever it goes: the helper's uninstall, a helper from a reinstalled app") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let plist = "/LD/com.mugvpn.cleanup.plist"
        h.bootCleanup(armed: true, helper: "/Users/u/.Trash/MugVPN.app/Contents/MacOS/MugVPNHelper", app: nil)
        sys.loadedJobs = ["com.mugvpn.cleanup"]
        sys.failUnload = ["com.mugvpn.cleanup"]
        var gone = false, answer: String?? = .none
        h.onUninstalled = { gone = true }
        try h.uninstall(uid: 0, keepProfiles: true) { answer = .some($0) }
        expect(!gone, "launchd still has it: not finished")
        expect((answer ?? nil)?.contains(plist) == true, "said: \(String(describing: answer))")
        sys.failUnload = []
        try h.uninstall(uid: 0, keepProfiles: true)
        expect(gone && sys.loadedJobs.isEmpty && sys.files[plist] == nil)
        try sys.writeFile(plist, Data(), mode: 0o644)
        sys.loadedJobs = ["com.mugvpn.cleanup"]
        sys.runningFromTrash = false
        try makeHelper(sys).prepareRunDirectory()
        expect(sys.files[plist] == nil && sys.loadedJobs.isEmpty, "a helper from a reinstalled app: unloaded and removed")
        try sys.writeFile(plist, Data(), mode: 0o644)
        sys.runningFromTrash = true
        try makeHelper(sys).prepareRunDirectory()
        expect(sys.files[plist] != nil, "one from the Trash keeps it")
    }
    test("PS-136", "the boot cleanup run (temporary paths, stand-in system tools): nothing removed unless launchd has no helper") {
        let fm = FileManager.default
        let root = NSTemporaryDirectory() + "mugvpn-boot-\(UUID().uuidString)"
        defer { try? fm.removeItem(atPath: root) }
        let bin = root + "/bin"
        try fm.createDirectory(atPath: bin, withIntermediateDirectories: true)
        // Only these on PATH: the real launchctl (or anything else of the Mac's) cannot be reached.
        func tool(_ name: String, _ body: String) {
            fm.createFile(atPath: bin + "/" + name, contents: Data("#!/bin/sh\n\(body)\n".utf8), attributes: [.posixPermissions: 0o755])
        }
        tool("launchctl", "echo \"$*\" >> \(root)/calls; [ \"$1\" = print ] && exit $(/bin/cat \(root)/print-status); "
             + "[ \"$2\" = system/com.mugvpn.cleanup ] && [ -e \(root)/self-bootout-fails ] && exit 5; exit 0")
        tool("pgrep", "echo \"pgrep $*\" >> \(root)/calls; exit $(/bin/cat \(root)/pgrep-status)")
        tool("pkill", "echo \"pkill $*\" >> \(root)/calls; exit 0")
        tool("logger", "echo \"$*\" >> \(root)/said")
        tool("rm", "exec /bin/rm \"$@\"")
        let paths = HelperPaths(openvpn: root + "/L/libexec/openvpn", runDir: root + "/L/run", logsDir: root + "/Logs",
                                autoDir: root + "/L/auto", libexecDir: root + "/L/libexec", systemConfigDir: root + "/L/config",
                                devDaemonPlist: root + "/LD/com.mugvpn.helper.plist", supportDir: root + "/L")
        func setUp() throws {
            for d in ["/L/run/x", "/L/libexec", "/Logs", "/L/config", "/LD"] { try fm.createDirectory(atPath: root + d, withIntermediateDirectories: true) }
            for f in ["/L/locks.json", "/L/config/office.ovpn", "/LD/com.mugvpn.helper.plist", "/LD/com.mugvpn.cleanup.plist"] {
                fm.createFile(atPath: root + f, contents: Data())
            }
            try? fm.removeItem(atPath: root + "/calls")
        }
        func run(print: Int, pgrep: Int = 1, helper: String? = "/nonexistent/MugVPNHelper") throws -> Int32 {
            try setUp()
            try "\(print)".write(toFile: root + "/print-status", atomically: true, encoding: .utf8)
            try "\(pgrep)".write(toFile: root + "/pgrep-status", atomically: true, encoding: .utf8)
            let sh = Process()
            sh.executableURL = URL(fileURLWithPath: "/bin/sh")
            sh.arguments = ["-c", HelperCore.bootCleanupScript(paths: paths)]
            sh.environment = ["PATH": bin].merging(helper.map { ["MUGVPN_HELPER": $0] } ?? [:]) { $1 }
            try sh.run()
            sh.waitUntilExit()
            return sh.terminationStatus
        }
        func exists(_ p: String) -> Bool { fm.fileExists(atPath: root + p) }
        expectEqual(try run(print: 0), 1, "launchd still has the helper: stopped")
        expect(exists("/L/run/x") && exists("/L/locks.json") && exists("/L/libexec"), "nothing removed")
        expectEqual(try run(print: 5), 1, "launchd could not tell: stopped")
        expect(exists("/L/run/x"))
        expectEqual(try run(print: 113, pgrep: 0), 0, "a helper runs (from anywhere): left to it")
        expect(exists("/L/run/x"))
        expectEqual(try run(print: 113, pgrep: 2), 1, "pgrep could not tell: stopped")
        expect(exists("/L/run/x"))
        expectEqual(try run(print: 113, helper: nil), 1, "not told where the helper is: nothing done")
        expect(exists("/L/run/x"))
        fm.createFile(atPath: root + "/helper", contents: Data())
        expectEqual(try run(print: 113, helper: root + "/helper"), 0)
        expect(exists("/L/run/x"), "the helper still there: left to it")
        expect(!((try? String(contentsOfFile: root + "/calls", encoding: .utf8)) ?? "").contains("bootout"), "not even asked to stop")
        expectEqual(try run(print: 113), 0, "launchd has no helper: done")
        for p in ["/L/run", "/L/libexec", "/Logs", "/L/locks.json", "/LD/com.mugvpn.helper.plist", "/LD/com.mugvpn.cleanup.plist"] {
            expect(!exists(p), "\(p) gone")
        }
        expect(exists("/L/config/office.ovpn"), "profiles stay")
        let said = (try? String(contentsOfFile: root + "/said", encoding: .utf8)) ?? ""
        expect(said.contains("Login Items") && said.contains("Library/Logs/MugVPN"), "what it leaves is said in the system log: \(said)")
        let calls = (try? String(contentsOfFile: root + "/calls", encoding: .utf8)) ?? ""
        expect(calls.contains("bootout system/com.mugvpn.cleanup"), "and it leaves launchd: \(calls)")
        expect(!said.contains("keeps this finished job"))
        fm.createFile(atPath: root + "/self-bootout-fails", contents: Data())
        expectEqual(try run(print: 113), 0)
        let saidAgain = (try? String(contentsOfFile: root + "/said", encoding: .utf8)) ?? ""
        expect(saidAgain.contains("launchd keeps this finished job until the next restart"), "launchd not letting go of it is said: \(saidAgain)")
        expect(calls.contains("pgrep -f Contents/MacOS/MugVPNHelpe[r]"), "\(calls)")
        expect(calls.contains("pkill -9 -f \(root)/L/libexec/openvp[n]"), "\(calls)")
    }
    test("PS-137", "the cleanup scripts' process patterns (real pgrep) never match a process whose command line is the script") {
        let paths = HelperPaths.standard
        let scripts = [HelperCore.bootCleanupScript(paths: paths), UninstallPlan.systemRemovalScript(keepProfiles: true)]
        let patterns = [ShellProcessCheck.helperPattern, ShellProcessCheck.pattern(paths.openvpn)]
        for p in patterns { expect(scripts.allSatisfy { $0.contains("'\(p)'") }, "\(p) is what both scripts use") }
        expectEqual(ShellProcessCheck.helperPattern, "Contents/MacOS/MugVPNHelpe[r]")
        expectEqual(ShellProcessCheck.pattern(paths.openvpn), "/Library/Application Support/MugVPN/libexec/openvp[n]")
        func matched(_ pattern: String, _ pid: Int32) throws -> Bool {
            let g = Process()
            g.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
            g.arguments = ["-f", pattern]
            let out = Pipe()
            g.standardOutput = out
            try g.run()
            g.waitUntilExit()
            return String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
                .split(separator: "\n").contains(Substring("\(pid)"))
        }
        // The helper as SMAppService starts it (relative argv[0]) and as a plain launch daemon (absolute): both found.
        for argv0 in ["Contents/MacOS/MugVPNHelper", "/Applications/MugVPN.app/Contents/MacOS/MugVPNHelper"] {
            let fake = Process()
            fake.executableURL = URL(fileURLWithPath: "/bin/sh")
            fake.arguments = ["-c", "sleep 30; :", argv0]
            try fake.run()
            usleep(200_000)
            defer { fake.terminate() }
            expect(try matched(ShellProcessCheck.helperPattern, fake.processIdentifier), "a helper run as \(argv0) is found")
        }
        for script in scripts {
            // A process holding the script in its arguments, as `sh -c <script>` does (asleep: it runs nothing).
            let holder = Process()
            holder.executableURL = URL(fileURLWithPath: "/bin/sh")
            let marker = "mugvpn-ps137-\(UUID().uuidString)"
            holder.arguments = ["-c", "sleep 30; :", script, marker]
            try holder.run()
            usleep(200_000)
            defer { holder.terminate() }
            for p in patterns {
                expect(!(try matched(p, holder.processIdentifier)), "\(p) does not match the script's own process")
            }
            // (pgrep sees that process at all.)
            let g = Process()
            g.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
            g.arguments = ["-f", marker]
            let out = Pipe()
            g.standardOutput = out
            try g.run()
            g.waitUntilExit()
            let pids = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self).split(separator: "\n")
            expect(pids.contains(Substring("\(holder.processIdentifier)")), "pgrep sees the holder at all")
        }
    }

    test("PS-138", "uninstalling after the Trash not finished: said for the system log, once per reason (retries say nothing new)") {
        let sys = FakeSystem()
        try sys.makeDirectory("/L/libexec", mode: 0o755)
        sys.failRemoves = ["/L/libexec"]
        let h = makeHelper(sys)
        var notes: [String] = []
        h.onNote = { notes.append($0) }
        h.uninstallMovedToTrash()
        sys.fireTimers()
        sys.fireTimers()
        let said = notes.filter { $0.contains("not finished") }
        expectEqual(said.count, 1, "\(notes)")
        expect(said.first?.contains("/L/libexec") == true, "what stayed is named: \(said)")
        sys.failRemoves = []
        sys.loadedJobs = ["com.mugvpn.cleanup"]
        sys.failUnload = ["com.mugvpn.cleanup"]
        try sys.writeFile("/LD/com.mugvpn.cleanup.plist", Data(), mode: 0o644)
        sys.fireTimers()
        expect(notes.contains { $0.contains("not finished") && $0.contains("com.mugvpn.cleanup.plist") }, "a new reason is said: \(notes)")
        let manual = FakeSystem()
        let m = makeHelper(manual)
        var mnotes: [String] = []
        m.onNote = { mnotes.append($0) }
        try manual.makeDirectory("/L/libexec", mode: 0o755)
        manual.failRemoves = ["/L/libexec"]
        try m.uninstall(uid: 0, keepProfiles: true)
        expect(mnotes.isEmpty, "an uninstall someone asked for is answered instead")
    }
    test("PS-139", "two tunnels asking all names, one with the server's domains: the same split whichever came first") {
        // A: DNS servers and its own search domains; B: DNS servers only. Neither asks for split DNS.
        let aVars = ["dns_server_1_address_1=10.8.0.53", "dns_search_domain_1=corp.lan"]
        let bVars = ["dns_server_1_address_1=10.9.0.53"]
        func outcome(aFirst: Bool) throws -> (all: String?, split: [String: [String]], states: [String]) {
            let sys = FakeSystem()
            let h = makeHelper(sys)
            var ids: [String: String] = [:]
            for (name, dev, net, vars) in aFirst ? [("A", "utun5", "10.8.0", aVars), ("B", "utun6", "10.9.0", bVars)]
                                                 : [("B", "utun6", "10.9.0", bVars), ("A", "utun5", "10.8.0", aVars)] {
                ids[name] = try dnsUp(sys, h, dev, net, vars)
                sys.clock += 5
            }
            let st = Dictionary(uniqueKeysWithValues: h.list(uid: 501).map { ($0.id, $0.dns ?? "-") })
            return (sys.allNames.keys.first, sys.splitResolvers.mapValues(\.matchDomains), [st[ids["A"]!]!, st[ids["B"]!]!])
        }
        let ab = try outcome(aFirst: true), ba = try outcome(aFirst: false)
        expectEqual(ab.all, "utun6", "B (no domains of its own) has all names")
        expectEqual(ab.split, ["utun5": ["corp.lan"]], "A its server's domains")
        expectEqual(ab.states, ["limited", "all"])
        expectEqual(ba.all, ab.all, "the same either way")
        expectEqual(ba.split, ab.split)
        expectEqual(ba.states, ab.states)
    }
    test("PS-140", "all names taken from a tunnel that has its server's domains: on record first, given back when the other lets go") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let a = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53", "dns_search_domain_1=corp.lan"])
        sys.clock += 5
        var order: [String] = []
        sys.onRestore = { dev in
            if dev == "utun5" { order.append(String(decoding: sys.files["/L/run/\(a)/state.json"]?.data ?? Data(), as: UTF8.self)) }
        }
        let b = try dnsUp(sys, h, "utun6", "10.9.0", ["dns_server_1_address_1=10.9.0.53"])
        expect(order.first?.contains("corp.lan") == true, "A's record says its split DNS before its all names go: \(order)")
        expect(sys.dnsRestored.contains("utun5"), "A's all names taken off (the primary's DNS put back) first")
        expectEqual(sys.allNames.keys.sorted(), ["utun6"])
        // Asked again (reconnect, a network change): the same.
        sys.clock += 5
        _ = try? h.tunnelRequest(id: b, uid: 501, kind: "DNSUP", message: "utun6")
        sys.clock += 5
        _ = try? h.tunnelRequest(id: a, uid: 501, kind: "DNSUP", message: "utun5")
        expectEqual(sys.allNames.keys.sorted(), ["utun6"])
        expectEqual(sys.splitResolvers["utun5"]?.matchDomains, ["corp.lan"])
        // B lets go: A has all names again.
        sys.clock += 5
        _ = try h.tunnelRequest(id: b, uid: 501, kind: "DNSDOWN", message: "utun6")
        expectEqual(sys.allNames.keys.sorted(), ["utun5"])
        expectEqual(h.list(uid: 501).first { $0.id == a }?.dns, "all")
        expect(!String(decoding: sys.files["/L/run/\(a)/state.json"]?.data ?? Data(), as: UTF8.self).contains("corp.lan\"]"),
               "its record: all names again")
    }
    test("PS-141", "all names kept by a tunnel whose split is the user's choice, by another user's, or when neither has domains") {
        // Split DNS asked for (the switch): it never held all names; the other simply gets them.
        let sys = FakeSystem()
        let h = makeHelper(sys)
        var bundleA = ProfileBundle(name: "a", config: "client\ndev tun\nremote vpn.example.com 1194 udp", files: [:])
        bundleA.splitDNS = true
        let (a, _) = try h.start(bundle: try JSONEncoder().encode(bundleA), uid: 501)
        sys.utunName = "utun5"
        _ = try h.tunnelRequest(id: a, uid: 501, kind: "OPENTUN", message: "tun")
        _ = try h.tunnelRequest(id: a, uid: 501, kind: "IFCONFIG", message: "10.8.0.2 255.255.255.0 1500 subnet")
        for v in ["dns_server_1_address_1=10.8.0.53", "dns_search_domain_1=corp.lan"] { _ = try h.tunnelRequest(id: a, uid: 501, kind: "DNSVAR", message: v) }
        _ = try h.tunnelRequest(id: a, uid: 501, kind: "DNSUP", message: "utun5")
        sys.clock += 5
        _ = try dnsUp(sys, h, "utun6", "10.9.0", ["dns_server_1_address_1=10.9.0.53"])
        expectEqual(sys.allNames.keys.sorted(), ["utun6"])
        expectEqual(sys.splitResolvers["utun5"]?.matchDomains, ["corp.lan"])
        // Neither has domains: the second waits (said), the first keeps all names.
        let s2 = FakeSystem()
        let h2 = makeHelper(s2)
        _ = try dnsUp(s2, h2, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53"])
        s2.clock += 5
        let b2 = try dnsUp(s2, h2, "utun6", "10.9.0", ["dns_server_1_address_1=10.9.0.53"])
        expectEqual(s2.allNames.keys.sorted(), ["utun5"])
        expectEqual(h2.list(uid: 501).first { $0.id == b2 }?.dns, "waiting")
        // Another user's tunnel holds all names (it has domains): not taken from them.
        let s3 = FakeSystem()
        try s3.makeDirectory("/L", mode: 0o755)
        try s3.writeFile("/L/policy.json", Data(#"{"usersMayChangeDNS": true}"#.utf8), mode: 0o644)
        s3.systemDNS = ["192.168.64.1"]
        let h3 = makeHelper(s3)
        _ = try dnsUp(s3, h3, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53", "dns_search_domain_1=corp.lan"])
        s3.clock += 5
        let (c, _) = try h3.start(bundle: psBundle(), uid: 502)
        s3.utunName = "utun6"
        _ = try h3.tunnelRequest(id: c, uid: 502, kind: "OPENTUN", message: "tun")
        _ = try h3.tunnelRequest(id: c, uid: 502, kind: "IFCONFIG", message: "10.9.0.2 255.255.255.0 1500 subnet")
        _ = try h3.tunnelRequest(id: c, uid: 502, kind: "DNSVAR", message: "dns_server_1_address_1=10.9.0.53")
        expectThrows("waits", matching: "already another tunnel's") { _ = try h3.tunnelRequest(id: c, uid: 502, kind: "DNSUP", message: "utun6") }
        expectEqual(s3.allNames.keys.sorted(), ["utun5"], "another user's all names stay theirs")
    }
    test("PS-142", "the new tunnel's all names refused: the other's all names given back (on record too); not even that: its split stays") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let a = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53", "dns_search_domain_1=corp.lan"])
        sys.clock += 5
        sys.failDNSFor = ["utun6"]
        let b = try dnsUp(sys, h, "utun6", "10.9.0", ["dns_server_1_address_1=10.9.0.53"])
        expectEqual(sys.allNames.keys.sorted(), ["utun5"], "A has all names again")
        expectEqual(h.list(uid: 501).first { $0.id == a }?.dns, "all")
        expect(h.list(uid: 501).first { $0.id == b }?.dns != "all")
        let rec = String(decoding: sys.files["/L/run/\(a)/state.json"]?.data ?? Data(), as: UTF8.self)
        expect(!rec.contains("\"dnsDomains\":[\"corp.lan\"]"), "A's record: all names, as on the Mac: \(rec)")
        // A's split cannot be set: nothing changes (A keeps all names, B waits).
        let s2 = FakeSystem()
        let h2 = makeHelper(s2)
        let a2 = try dnsUp(s2, h2, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53", "dns_search_domain_1=corp.lan"])
        s2.clock += 5
        s2.failSplitDNS = true
        let b2 = try dnsUp(s2, h2, "utun6", "10.9.0", ["dns_server_1_address_1=10.9.0.53"])
        expectEqual(s2.allNames.keys.sorted(), ["utun5"])
        expectEqual(h2.list(uid: 501).first { $0.id == a2 }?.dns, "all")
        expectEqual(h2.list(uid: 501).first { $0.id == b2 }?.dns, "waiting")
        // A's record cannot be written first: nothing changes either.
        let s3 = FakeSystem()
        let h3 = makeHelper(s3)
        let a3 = try dnsUp(s3, h3, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53", "dns_search_domain_1=corp.lan"])
        s3.clock += 5
        s3.failWrites = ["/L/run/\(a3)/state.json"]
        _ = try dnsUp(s3, h3, "utun6", "10.9.0", ["dns_server_1_address_1=10.9.0.53"])
        expectEqual(s3.allNames.keys.sorted(), ["utun5"], "no change without its record")
    }
    test("PS-143", "three tunnels: those without domains of their own come first for all names, whatever the order") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let a = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53", "dns_search_domain_1=corp.lan"])
        sys.clock += 5
        let b = try dnsUp(sys, h, "utun6", "10.9.0", ["dns_server_1_address_1=10.9.0.53"])
        sys.clock += 5
        let c = try dnsUp(sys, h, "utun7", "10.10.0", ["dns_server_1_address_1=10.10.0.53"])
        let states = { Dictionary(uniqueKeysWithValues: h.list(uid: 501).map { ($0.id, $0.dns ?? "-") }) }
        expectEqual(states(), [a: "limited", b: "all", c: "waiting"])
        // B lets go: C (nothing at all till now) before A (which has its domains), though A asked first.
        sys.clock += 5
        _ = try h.tunnelRequest(id: b, uid: 501, kind: "DNSDOWN", message: "utun6")
        expectEqual(states()[c], "all")
        expectEqual(states()[a], "limited")
    }
    test("PS-144", "the helper dies after all names changed hands: the next one takes both tunnels' DNS off by their records") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        _ = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53", "dns_search_domain_1=corp.lan"])
        sys.clock += 5
        _ = try dnsUp(sys, h, "utun6", "10.9.0", ["dns_server_1_address_1=10.9.0.53"])
        expect(!sys.allNames.isEmpty && !sys.splitResolvers.isEmpty)
        try makeHelper(sys).prepareRunDirectory()
        expect(sys.allNames.isEmpty, "all names off: \(sys.allNames)")
        expect(sys.splitResolvers.isEmpty, "the split resolver off: \(sys.splitResolvers)")
        expect(sys.dnsRestored.contains("utun5") && sys.dnsRestored.contains("utun6"))
    }
    test("PS-145", "all names handed over, then neither side can have them: the other stays in line and is tried again") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let a = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53", "dns_search_domain_1=corp.example"])
        sys.clock += 5
        // B's all names refused, and A's back too: A keeps its split (in line), retried later.
        sys.failDNSFor = ["utun6"]
        sys.failAllNamesDNS = true
        _ = try dnsUp(sys, h, "utun6", "10.9.0", ["dns_server_1_address_1=10.9.0.53"])
        expectEqual(h.list(uid: 501).first { $0.id == a }?.dns, "limited", "its domains still, in line")
        expect(sys.allNames.isEmpty)
        sys.failAllNamesDNS = false
        sys.fireTimers()
        expectEqual(sys.allNames.keys.sorted(), ["utun5"], "tried again: A has all names back")
        expectEqual(h.list(uid: 501).first { $0.id == a }?.dns, "all")
    }
    test("PS-146", "the request's own record fails after all names were handed over: undone as a whole, the other's all names back") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let a = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53", "dns_search_domain_1=corp.example"])
        sys.clock += 5
        let b = try dnsUp(sys, h, "utun6", "10.9.0", ["dns_server_1_address_1=10.9.0.53"], dnsUp: false)
        // B's record: written inside the request (DNS on record first), then refused at the request's end.
        sys.failNthWriteMatching = ("/L/run/\(b)/state.json", 2)
        _ = try? h.tunnelRequest(id: b, uid: 501, kind: "DNSUP", message: "utun6")
        expectEqual(sys.allNames.keys.sorted(), ["utun5"], "A has all names again")
        expectEqual(h.list(uid: 501).first { $0.id == a }?.dns, "all")
    }
    test("PS-147", "giving all names back cannot be recorded: its split stays (record and Mac agree), in line, tried again") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let a = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53", "dns_search_domain_1=corp.example"])
        sys.clock += 5
        let b = try dnsUp(sys, h, "utun6", "10.9.0", ["dns_server_1_address_1=10.9.0.53"], dnsUp: false)
        sys.failDNSFor = ["utun6"]
        // A's record: written once to hand over (split), refused when giving all names back.
        sys.failNthWriteMatching = ("/L/run/\(a)/state.json", 2)
        _ = try? h.tunnelRequest(id: b, uid: 501, kind: "DNSUP", message: "utun6")
        expectEqual(h.list(uid: 501).first { $0.id == a }?.dns, "limited")
        expectEqual(sys.splitResolvers["utun5"]?.matchDomains, ["corp.example"])
        expect(String(decoding: sys.files["/L/run/\(a)/state.json"]?.data ?? Data(), as: UTF8.self).contains("corp.example"),
               "its record says its split, as on the Mac")
        sys.fireTimers()
        expectEqual(sys.allNames.keys.sorted(), ["utun5"], "tried again")
    }
    test("PS-148", "a standard user's two tunnels (the administrator lets users change DNS): the same whichever came first") {
        func outcome(aFirst: Bool) throws -> [String: String] {
            let sys = FakeSystem()
            try sys.makeDirectory("/L", mode: 0o755)
            try sys.writeFile("/L/policy.json", Data(#"{"usersMayChangeDNS": true}"#.utf8), mode: 0o644)
            sys.systemDNS = ["192.168.64.1"]
            let h = makeHelper(sys)
            func up(_ dev: String, _ net: String, _ vars: [String]) throws -> String {
                let (id, _) = try h.start(bundle: psBundle(), uid: 502)
                sys.utunName = dev
                _ = try h.tunnelRequest(id: id, uid: 502, kind: "OPENTUN", message: "tun")
                _ = try h.tunnelRequest(id: id, uid: 502, kind: "IFCONFIG", message: "\(net).2 255.255.255.0 1500 subnet")
                for v in vars { _ = try h.tunnelRequest(id: id, uid: 502, kind: "DNSVAR", message: v) }
                _ = try? h.tunnelRequest(id: id, uid: 502, kind: "DNSUP", message: dev)
                sys.clock += 5
                return id
            }
            let aV = ["dns_server_1_address_1=10.8.0.53", "dns_search_domain_1=corp.example"], bV = ["dns_server_1_address_1=10.9.0.53"]
            var ids: [String: String] = [:]
            if aFirst { ids["A"] = try up("utun5", "10.8.0", aV); ids["B"] = try up("utun6", "10.9.0", bV) }
            else { ids["B"] = try up("utun6", "10.9.0", bV); ids["A"] = try up("utun5", "10.8.0", aV) }
            let st = Dictionary(uniqueKeysWithValues: h.list(uid: 502).map { ($0.id, $0.dns ?? "-") })
            return ["A": st[ids["A"]!]!, "B": st[ids["B"]!]!, "all": sys.allNames.keys.first ?? "-"]
        }
        let ab = try outcome(aFirst: true)
        expectEqual(ab, ["A": "limited", "B": "all", "all": "utun6"])
        expectEqual(try outcome(aFirst: false), ab)
    }
    test("PS-149", "a tunnel limited to its domains says which, to its owner and administrators only") {
        let sys = FakeSystem()
        sys.admins = [501]
        let h = makeHelper(sys)
        let a = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53", "dns_search_domain_1=corp.example"])
        sys.clock += 5
        _ = try dnsUp(sys, h, "utun6", "10.9.0", ["dns_server_1_address_1=10.9.0.53"])
        expectEqual(h.list(uid: 501).first { $0.id == a }?.dnsDomains, ["corp.example"])
        expectEqual(h.list(uid: 0).first { $0.id == a }?.dnsDomains, ["corp.example"])
        expect(h.list(uid: 502).isEmpty, "another user does not see it at all")
    }
    test("PS-150", "handing all names over, the holder's DNS lost (neither its split nor its all names set): it is stopped, not left without its DNS") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let a = try dnsUp(sys, h, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53", "dns_search_domain_1=corp.example"])
        sys.clock += 5
        sys.failDNSFor = ["utun5"]
        _ = try dnsUp(sys, h, "utun6", "10.9.0", ["dns_server_1_address_1=10.9.0.53"])
        expect(!sys.launched[0].process.signals.isEmpty, "A undone and stopped (its domains would go to B's servers)")
        expect(h.list(uid: 501).first { $0.id == a }?.dns != "waiting", "never in line with domains it does not have")
        // Giving all names back fails the same way: stopped too.
        let s2 = FakeSystem()
        let h2 = makeHelper(s2)
        _ = try dnsUp(s2, h2, "utun5", "10.8.0", ["dns_server_1_address_1=10.8.0.53", "dns_search_domain_1=corp.example"])
        s2.clock += 5
        let b2 = try dnsUp(s2, h2, "utun6", "10.9.0", ["dns_server_1_address_1=10.9.0.53"], dnsUp: false)
        s2.failDNSFor = ["utun6"]
        // A's DNS taken off twice: to hand over (all names to split), then to give back (split to all names): from
        // then on nothing of A's can be set.
        var restores = 0
        s2.onRestore = { dev in
            guard dev == "utun5" else { return }
            restores += 1
            if restores == 2 { s2.failDNSFor.insert("utun5") }
        }
        _ = try? h2.tunnelRequest(id: b2, uid: 501, kind: "DNSUP", message: "utun6")
        expectEqual(restores, 2, "handed over, then given back")
        expect(!s2.launched[0].process.signals.isEmpty, "A stopped: neither its all names back nor its split")
    }

    test("PS-49", "closed after PF is lost: the kill switch fires and stays, the utun is given back (ext. audit 6: P2)") {
        let sys = FakeSystem()
        sys.admins = []
        try sys.makeDirectory("/L", mode: 0o755)
        try sys.writeFile("/L/policy.json", Data(#"{"usersMayRouteAllTraffic": true}"#.utf8), mode: 0o644)
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(kill: true), uid: 502)
        try bringUp(sys, h, id, uid: 502, device: "utun5", routes: ["0.0.0.0 128.0.0.0 10.8.0.1", "128.0.0.0 128.0.0.0 10.8.0.1"])
        sys.pfIntactAnswer = false
        sys.pfApplyFails = true
        h.refreshProtection()
        expect(sys.releasedDevices.contains("utun5"), "its utun is given back: \(sys.releasedDevices)")
        sys.launched[0].process.onExit(.signaled(9))
        expectEqual(h.locks(uid: 502), ["office"], "the kill switch fired")
        sys.pfIntactAnswer = true
        sys.pfApplyFails = false
        h.refreshProtection()
        expect((sys.pf.last ?? "").contains("user 502"), "and holds once PF is back: \(sys.pf.last ?? "")")
        sys.pf = []
        try makeHelper(sys).prepareRunDirectory()
        expect((sys.pf.last ?? "").contains("user 502"), "and after the helper starts again")
    }
    test("PS-45", "a standard user routes nothing into the Mac's own networks (ext. audit 5: P1)") {
        let sys = FakeSystem()
        sys.admins = []
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 502)
        try bringUp(sys, h, id, uid: 502, device: "utun5", routes: [])
        for r in ["192.168.64.1 255.255.255.255 10.8.0.1", "192.168.64.0 255.255.255.128 10.8.0.1", "192.168.64.0 255.255.255.0 10.8.0.1"] {
            expectThrows(r, matching: "network") { _ = try h.tunnelRequest(id: id, uid: 502, kind: "ROUTE", message: r) }
        }
        // Wider than the LAN: the LAN's own route still wins for its addresses.
        _ = try h.tunnelRequest(id: id, uid: 502, kind: "ROUTE", message: "192.168.0.0 255.255.0.0 10.8.0.1")
    }
    test("PS-46", "a record that cannot be put back after a failed change: the connection is undone and stopped (ext. audit 5: P3)") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 501)
        try bringUp(sys, h, id, uid: 501, device: "utun5", routes: ["10.20.0.0 255.255.0.0 10.8.0.1"])
        // route add fails (it is there already, not ours); the record ahead is written, putting it back is not.
        sys.routeTable.insert(["route", "-n", "add", "-net", "10.30.0.0", "-netmask", "255.255.0.0", "-interface", "utun5"])
        sys.failAfterWrites = 1
        expectThrows("route add fails") { _ = try h.tunnelRequest(id: id, uid: 501, kind: "ROUTE", message: "10.30.0.0 255.255.0.0 10.8.0.1") }
        sys.failAfterWrites = nil
        expectEqual(sys.launched[0].process.signals, [SIGKILL], "stopped")
        expect(!sys.routeTable.contains { $0.contains("10.20.0.0") }, "and undone")
    }
    test("PS-151", "an IPv6 route asked again (openvpn after a reconnect of its own): taken as it is, not added twice, the connection kept") {
        let sys = FakeSystem()
        let h = makeHelper(sys)
        let (id, _) = try h.start(bundle: psBundle(), uid: 501)
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "OPENTUN", message: "tun")
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "ROUTE6", message: "fd00:20::/64 utun7")
        let adds = sys.commands.filter { $0.contains("fd00:20::") && $0.contains("add") }.count
        // The system refuses a route that is there already (EEXIST): a second add would fail the connection.
        sys.commandFails = true
        _ = try h.tunnelRequest(id: id, uid: 501, kind: "ROUTE6", message: "fd00:20::/64 utun7")
        sys.commandFails = false
        expectEqual(sys.commands.filter { $0.contains("fd00:20::") && $0.contains("add") }.count, adds, "not added again")
    }
}

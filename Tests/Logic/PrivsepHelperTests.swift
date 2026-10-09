import Foundation
import MugVPNCore
import MugVPNHelperCore

// The helper side of privilege separation: requests from an unprivileged openvpn
// (through its owner's app), what the helper carries out, and what it undoes.

private func psBundle(kill: Bool = false) -> Data {
    var b = ProfileBundle(name: "office", config: "client\ndev tun\nremote vpn.example.com 1194 udp", files: [:])
    b.protection = ProtectionOptions(killSwitch: kill)
    return try! JSONEncoder().encode(b)
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
}

import Foundation
import MugVPNCore
import MugVPNHelperCore

// Privilege separation: openvpn runs unprivileged and asks (through the app)
// for what needs root. The helper checks every request against the connection
// it belongs to; this is the new trust boundary (workdocs/SECURITY.md).

func registerTunnelRequestTests() {
    func tunnel() -> TunnelState {
        var t = TunnelState()
        t.device = "utun7"
        return t
    }
    test("TUN-01", "the tunnel address: private, not wider than /8, sane MTU and topology") {
        var t = tunnel()
        expectEqual(try t.ifconfig("10.8.0.2 255.255.255.0 1500 subnet"),
                    [["ifconfig", "utun7", "inet", "10.8.0.2", "10.8.0.2", "netmask", "255.255.255.0", "mtu", "1500", "up"],
                     ["route", "-n", "add", "-net", "10.8.0.0", "-netmask", "255.255.255.0", "-interface", "utun7"]])
        expectEqual(t.subnet, IPv4Net(address: 0x0A08_0000, prefix: 24))
        var p = tunnel()
        expectEqual(try p.ifconfig("10.8.0.6 10.8.0.5 1400 net30"),
                    [["ifconfig", "utun7", "10.8.0.6", "10.8.0.5", "mtu", "1400", "up"]])
        for bad in ["8.8.8.8 255.255.255.0 1500 subnet", "10.8.0.2 128.0.0.0 1500 subnet", "10.8.0.2 255.255.255.0 99999 subnet",
                    "10.8.0.2 255.255.255.0 1500 weird", "10.8.0.2;x 255.255.255.0 1500 subnet", "10.8.0.2 255.255.255.0"] {
            var x = tunnel()
            expectThrows(bad) { _ = try x.ifconfig(bad) }
        }
        var none = TunnelState()
        expectThrows("before OPENTUN", matching: "tunnel") { _ = try none.ifconfig("10.8.0.2 255.255.255.0 1500 subnet") }
    }
    test("TUN-02", "routes go into the tunnel (bound to its utun), or are host routes via the Mac's own gateway") {
        var t = tunnel()
        _ = try t.ifconfig("10.8.0.2 255.255.255.0 1500 subnet")
        let gw = DefaultGateway(address: "192.168.64.1", interface: "en0")
        expectEqual(try t.route("10.20.0.0 255.255.0.0 10.8.0.1", gateway: gw).map(\.add),
                    [["route", "-n", "add", "-net", "10.20.0.0", "-netmask", "255.255.0.0", "-interface", "utun7"]])
        expectEqual(try t.route("0.0.0.0 128.0.0.0 10.8.0.1", gateway: gw).first?.kind, .tunnel, "def1 into the tunnel")
        expectEqual(try t.route("203.0.113.7 255.255.255.255 192.168.64.1", gateway: gw).map(\.add),
                    [["route", "-n", "add", "-net", "203.0.113.7", "192.168.64.1", "255.255.255.255"]], "the server via the Mac's gateway")
        expectEqual(try t.route("198.51.100.9 255.255.255.255 192.168.64.1 dev en0", gateway: gw).map(\.add),
                    [["route", "-n", "add", "-cloning", "-net", "198.51.100.9", "-netmask", "255.255.255.255", "-interface", "en0"]])
        for bad in ["10.20.0.0 255.255.0.0 192.168.64.50", "198.51.100.0 255.255.255.0 192.168.64.1",
                    "10.20.0.0 255.255.0.0 10.9.9.9", "10.20.0.0 255.255.0.0", "x y z",
                    "127.0.0.1 255.255.255.255 192.168.64.1", "224.0.0.9 255.255.255.255 192.168.64.1",
                    "198.51.100.9 255.255.255.255 192.168.64.1 dev en1"] {
            expectThrows(bad) { _ = try t.route(bad, gateway: gw) }
        }
        _ = try t.route("192.168.1.10 255.255.255.255 192.168.64.1", gateway: gw)  // a server on a private network
        expectEqual(t.routes.count, 5, "what it added is remembered for cleanup")
        expect(t.takesAllTraffic == false)
        _ = try t.route("128.0.0.0 128.0.0.0 10.8.0.1", gateway: gw)
        expect(t.takesAllTraffic)
        t.device = "utun9"
        expect(!t.takesAllTraffic, "only the current device's routes count")
    }
    test("TUN-03", "a route is taken away only if this connection added it, exactly") {
        var t = tunnel()
        _ = try t.ifconfig("10.8.0.2 255.255.255.0 1500 subnet")
        let gw = DefaultGateway(address: "192.168.64.1", interface: "en0")
        _ = try t.route("10.20.0.0 255.255.0.0 10.8.0.1", gateway: gw)
        _ = try t.route("10.30.0.0 255.255.0.0 10.8.0.1", gateway: gw)
        expectThrows("not added", matching: "not") { _ = try t.deleteRoute("10.30.0.0 255.255.255.0 10.8.0.1") }
        expectThrows("not added", matching: "not") { _ = try t.deleteRoute("10.40.0.0 255.255.0.0 10.8.0.1") }
        expectThrows("garbage", matching: "not") { _ = try t.deleteRoute("route -n add") }
        expectEqual(try t.deleteRoute("10.20.0.0 255.255.0.0 10.8.0.1").map(\.delete),
                    [["route", "-n", "delete", "-net", "10.20.0.0", "-netmask", "255.255.0.0", "-interface", "utun7"]])
        expectEqual(t.routes.map(\.net), ["10.30.0.0"])
        expectEqual(try t.route6("fd00:20::/64 utun7").add, ["route", "-n", "add", "-inet6", "fd00:20::", "-prefixlen", "64", "-iface", "utun7"])
        expectThrows("not added 6", matching: "not") { _ = try t.deleteRoute6("fd00:30::/64 utun7") }
        expectEqual(try t.deleteRoute6("fd00:20::/64 utun7").delete, ["route", "-n", "delete", "-inet6", "fd00:20::", "-prefixlen", "64", "-iface", "utun7"])
    }
    test("TUN-10", "a server's split domain: not a whole top-level domain") {
        var t = tunnel()
        for bad in ["dns_server_1_resolve_domain_1=com", "dns_server_1_resolve_domain_1=ru", "dns_server_1_resolve_domain_1=.",
                    "dns_search_domain_1=net"] {
            expectThrows(bad) { try t.dnsVar(bad) }
        }
        for good in ["dns_server_1_resolve_domain_1=corp.example.com", "dns_server_1_resolve_domain_2=internal",
                     "dns_server_1_resolve_domain_3=lan", "dns_server_1_resolve_domain_4=home.arpa"] {
            try t.dnsVar(good)
        }
    }
    test("TUN-07", "a tunnel's network lies wholly in private space") {
        for bad in ["192.168.1.5 255.0.0.0 1500 subnet", "172.16.0.2 255.0.0.0 1500 subnet", "100.64.0.5 255.128.0.0 1500 subnet"] {
            var x = tunnel()
            expectThrows(bad, matching: "private") { _ = try x.ifconfig(bad) }
        }
        for good in ["10.8.0.2 255.0.0.0 1500 subnet", "100.64.0.5 255.192.0.0 1500 subnet", "172.16.0.2 255.240.0.0 1500 subnet"] {
            var x = tunnel()
            _ = try x.ifconfig(good)
        }
    }
    test("TUN-08", "routes per connection are bounded") {
        var t = tunnel()
        _ = try t.ifconfig("10.8.0.2 255.255.255.0 1500 subnet")
        for i in 0..<TunnelState.maxRoutes { _ = try t.route("10.\(i / 256 + 20).\(i % 256).0 255.255.255.0 10.8.0.1", gateway: nil) }
        expectThrows("one more", matching: "routes") { _ = try t.route("10.99.0.0 255.255.255.0 10.8.0.1", gateway: nil) }
        expectThrows("one more 6", matching: "routes") { _ = try t.route6("fd00:1::/64 utun7") }
    }
    test("TUN-09", "how much of the public Internet its routes take (an administrator's limit)") {
        var t = tunnel()
        _ = try t.ifconfig("10.8.0.2 255.255.255.0 1500 subnet")
        _ = try t.route("10.0.0.0 255.0.0.0 10.8.0.1", gateway: nil)
        expectEqual(t.publicCoverage, 0, "private space does not count")
        _ = try t.route("1.0.0.0 255.0.0.0 10.8.0.1", gateway: nil)
        _ = try t.route("203.0.113.0 255.255.255.0 10.8.0.1", gateway: nil)
        expectEqual(t.publicCoverage, (1 << 24) + 256)
        _ = try t.route6("fd00:1::/64 utun7")
        _ = try t.route6("2001:db8::/32 utun7")
        expectEqual(t.publicRoutes6.map(\.net), ["2001:db8::"])
        expect(t.takes(0x0A08_0005) && t.takes(0xCB00_7105) && !t.takes(0x0808_0808))
    }
    test("TUN-06", "redirect-gateway without def1: two halves through the tunnel, the Mac's default never deleted") {
        var t = tunnel()
        _ = try t.ifconfig("10.8.0.2 255.255.255.0 1500 subnet")
        let gw = DefaultGateway(address: "192.168.64.1", interface: "en0")
        expectEqual(try t.deleteRoute("0.0.0.0 0.0.0.0 192.168.64.1"), [], "openvpn's delete of the system default: nothing done")
        expectEqual(try t.route("0.0.0.0 0.0.0.0 10.8.0.1", gateway: gw).map(\.add),
                    [["route", "-n", "add", "-net", "0.0.0.0", "-netmask", "128.0.0.0", "-interface", "utun7"],
                     ["route", "-n", "add", "-net", "128.0.0.0", "-netmask", "128.0.0.0", "-interface", "utun7"]])
        expect(t.takesAllTraffic)
        expectThrows("the default via the Mac's gateway is no tunnel route") { _ = try t.route("0.0.0.0 0.0.0.0 192.168.64.1", gateway: gw) }
        expectEqual(try t.deleteRoute("0.0.0.0 0.0.0.0 10.8.0.1").count, 2, "both halves go")
        expectEqual(t.routes.count, 0)
    }
    test("TUN-04", "IPv6: address and routes on its own device only") {
        var t = tunnel()
        expectEqual(try t.ifconfig6("fd00:8::2/64 1500"), [["ifconfig", "utun7", "inet6", "fd00:8::2/64", "mtu", "1500", "up"]])
        expectEqual(try t.route6("2000::/3 utun7").add, ["route", "-n", "add", "-inet6", "2000::", "-prefixlen", "3", "-iface", "utun7"])
        for bad in ["2000::/3 en0", "2000::/3 utun9", "zz::/3 utun7", "2000::/200 utun7"] {
            expectThrows(bad) { _ = try t.route6(bad) }
        }
        expectThrows("prefix") { _ = try t.ifconfig6("fd00:8::2/8 1500") }
    }
    test("TUN-05", "DNS from openvpn's variables, checked") {
        var t = tunnel()
        try t.dnsVar("dns_server_1_address_1=10.8.0.53")
        try t.dnsVar("dns_server_1_resolve_domain_1=corp.example.com")
        try t.dnsVar("dns_search_domain_1=corp.example.com")
        let plan = try t.dnsPlan(device: "utun7", splitMarker: false)
        expectEqual(plan.servers, ["10.8.0.53"])
        expectEqual(plan.matchDomains, ["corp.example.com"])
        expectEqual(plan.searchDomains, ["corp.example.com"])
        expect(plan.split)
        for bad in ["dns_server_1_address_1=10.8.0.53; rm", "dns_search_domain_1=bad domain", "PATH=/tmp", "dns_server_1_address_1=example.com"] {
            var x = tunnel()
            expectThrows(bad) { try x.dnsVar(bad) }
        }
        var full = tunnel()
        try full.dnsVar("dns_server_1_address_1=10.8.0.53")
        expect(!(try full.dnsPlan(device: "utun7", splitMarker: false).split), "no domains: all names")
        var legacy = tunnel()
        try legacy.dnsVar("dns_server_1_address_1=10.8.0.53")
        try legacy.dnsVar("dns_search_domain_1=b.test")
        let s = try legacy.dnsPlan(device: "utun7", splitMarker: true)
        expect(s.split && s.matchDomains == ["b.test"], "Split DNS by Domain turns search domains into match domains")
        expectThrows("another device", matching: "device") { _ = try t.dnsPlan(device: "utun9", splitMarker: false) }
    }
}

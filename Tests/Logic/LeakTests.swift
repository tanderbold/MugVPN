import Foundation
import MugVPNAppCore

// Real `netstat -rn -f inet` of the Mac VM with stand-d (all traffic) up.
private let fullTunnel = """
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
0/1                10.84.0.1          UGScg               utun4
default            192.168.64.1       UGScg                 en0
10.84/24           10.84.0.2          UGSc                utun4
10.84.0.2          10.84.0.2          UH                  utun4
10.94/24           10.84.0.1          UGSc                utun4
127                127.0.0.1          UCS                   lo0
127.0.0.1          127.0.0.1          UH                    lo0
127.0.0.1/32       192.168.64.1       UGSc                  en0
128.0/1            10.84.0.1          UGSc                utun4
169.254            link#5             UCS                   en0      !
192.168.64         link#5             UCS                   en0      !
192.168.64.1/32    link#5             UCS                   en0      !
192.168.64.1       5e:e9:1e:5a:67:64  UHLWIir               en0   1182
192.168.64.4/32    link#5             UCS                   en0      !
224.0.0/4          link#5             UmCS                  en0      !
224.0.0.251        1:0:5e:0:0:fb      UHmLWI                en0
255.255.255.255/32 link#5             UCS                   en0      !
"""

private let scutil = """
DNS configuration

resolver #1
  nameserver[0] : 10.84.0.1
  nameserver[1] : 192.168.64.1
  flags    : Request A records
  order    : 5000

resolver #2
  domain   : local
  nameserver[0] : 224.0.0.251
  options  : mdns
"""

func registerLeakTests() {
    // Leak checks after connecting (from Tunnelblick's DNS check and the TunnelVision/LocalNet attacks).
    test("LEAK-01", "netstat's abbreviated destinations") {
        let r = LeakCheck.routes(netstat: fullTunnel)
        func find(_ s: String) -> RouteEntry? { r.first { $0.cidr == s } }
        expectEqual(find("0.0.0.0/1")?.interface, "utun4")
        expectEqual(find("128.0.0.0/1")?.interface, "utun4")
        expectEqual(find("0.0.0.0/0")?.interface, "en0", "default")
        expect(find("10.84.0.0/24") != nil && find("127.0.0.0/8") != nil && find("169.254.0.0/16") != nil
               && find("192.168.64.0/24") != nil && find("10.84.0.2/32") != nil && find("224.0.0.0/4") != nil)
        expectEqual(LeakCheck.primaryDNS(scutil: scutil), ["10.84.0.1", "192.168.64.1"])
    }
    test("LEAK-02", "all traffic through the tunnel: nothing to report") {
        let f = LeakCheck.findings(routes: LeakCheck.routes(netstat: fullTunnel), tunnels: ["utun4"],
                                   dns: [("10.84.0.1", "utun4")], servers: ["127.0.0.1"])
        expectEqual(f, [])
    }
    test("LEAK-03", "a public network routed around the tunnel (TunnelVision, LocalNet)") {
        let text = fullTunnel + "\n198.51.100/24      192.168.64.1       UGSc                  en0\n"
            + "203.0.113.7/32     192.168.64.1       UGSc                  en0\n"
        let f = LeakCheck.findings(routes: LeakCheck.routes(netstat: text), tunnels: ["utun4"], dns: [],
                                   servers: ["203.0.113.7"])
        expectEqual(f, [.bypass("198.51.100.0/24", "en0")], "the VPN server's own route is fine")
    }
    test("LEAK-04", "the tunnel does not hold the default route, or DNS goes elsewhere") {
        let noDef1 = fullTunnel.replacingOccurrences(of: "128.0/1            10.84.0.1          UGSc                utun4\n", with: "")
        expectEqual(LeakCheck.findings(routes: LeakCheck.routes(netstat: noDef1), tunnels: ["utun4"], dns: [], servers: []),
                    [.defaultOutside])
        let f = LeakCheck.findings(routes: LeakCheck.routes(netstat: fullTunnel), tunnels: ["utun4"],
                                   dns: [("10.84.0.1", "utun4"), ("8.8.8.8", "en0"), ("127.0.0.1", "lo0")], servers: [])
        expectEqual(f, [.dnsOutside("8.8.8.8", "en0")], "a local resolver is not a leak")
    }
    test("LEAK-05", "two full tunnels: either one counts as the tunnel") {
        let text = fullTunnel.replacingOccurrences(of: "128.0/1            10.84.0.1          UGSc                utun4",
                                                   with: "128.0/1            10.85.0.1          UGSc                utun5")
        expectEqual(LeakCheck.findings(routes: LeakCheck.routes(netstat: text), tunnels: ["utun4", "utun5"], dns: [], servers: []), [])
    }
    test("LEAK-06", "what cannot be checked is said, not passed over") {
        let f = LeakCheck.findings(routes: LeakCheck.routes(netstat: fullTunnel), tunnels: ["utun4"],
                                   dns: [("10.84.0.1", nil), ("fe80::1%en0", "en0")], servers: [])
        expect(f.contains(.unverified("10.84.0.1")), "\(f)")
        expect(f.contains(.dnsOutside("fe80::1%en0", "en0")), "IPv6 DNS servers count too: \(f)")
    }
    test("LEAK-07", "IPv6 default route around the tunnel when IPv6 is not blocked") {
        let six = """
        Internet6:
        Destination                             Gateway                                 Flags               Netif Expire
        default                                 fe80::1%en0                             UGcg                  en0
        ::1                                     ::1                                     UHL                   lo0
        """
        expectEqual(LeakCheck.ipv6Defaults(netstat: six), ["en0"])
        expectEqual(LeakCheck.ipv6Findings(defaults: ["en0"], tunnels: ["utun4"], blocked: false), [.ipv6Outside("en0")])
        expectEqual(LeakCheck.ipv6Findings(defaults: ["en0"], tunnels: ["utun4"], blocked: true), [], "PF blocks it")
        expectEqual(LeakCheck.ipv6Findings(defaults: ["utun4"], tunnels: ["utun4"], blocked: false), [])
    }
    test("LEAK-09", "special-use IPv4 ranges are no leak; a public IPv6 network routed outside is") {
        for (net, p) in [(0xC000_0000 as UInt32, 24), (0xC000_0200, 24), (0xC612_0000, 15)] {
            expect(!LeakCheck.isPublic(net, p), "\(net)")
        }
        let netstat6 = """
        Destination                             Gateway                                 Flags         Netif Expire
        default                                 fe80::1%en0                             UGcg            en0
        2001:db8:1::/64                         link#4                                  UCS             en0
        2a00:1450::/32                          fe80::1%en0                             UGS             en0
        fd00:5::/64                             fe80::1%en0                             UGS             en0
        2001:db8:9::/48                         link#12                                 UCS           utun5
        """
        expectEqual(LeakCheck.ipv6Bypass(netstat: netstat6, tunnels: ["utun5"]), [.bypass("2a00:1450::/32", "en0")])
    }
    test("LEAK-08", "the VPN server is the address openvpn connected to, not any host route") {
        let log = "2026-10-07 09:58:24 TCP/UDP: Preserving recently used remote address: [AF_INET]203.0.113.7:1194\n"
            + "2026-10-07 09:58:24 UDPv4 link remote: [AF_INET]203.0.113.7:1194\n"
        expectEqual(LeakCheck.serverAddresses(log: log), ["203.0.113.7"])
        let text = fullTunnel + "\n198.51.100.9/32     192.168.64.1       UGSc                  en0\n"
        expectEqual(LeakCheck.findings(routes: LeakCheck.routes(netstat: text), tunnels: ["utun4"], dns: [],
                                       servers: LeakCheck.serverAddresses(log: log)),
                    [.bypass("198.51.100.9/32", "en0")], "a pushed net_gateway host route is not the server")
    }
}

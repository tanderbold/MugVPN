import Foundation
import MugVPNCore

// The protection engine's PF rules (see workdocs/SECURITY.md). The helper builds
// them only from typed values it validated itself. a
// kill switch's block covers its owner's sockets only (one user's drop must not
// cut off the others), so no exceptions for servers are needed: openvpn is root's.

private func rules(_ p: ProtectionState) -> [String] {
    PFRules.anchor(p).components(separatedBy: "\n").filter { !$0.isEmpty && !$0.hasPrefix("#") }
}

func registerProtectionTests() {
    test("PF-01", "nothing to protect: an empty anchor") {
        expectEqual(rules(ProtectionState()), [])
    }
    test("PF-02", "kill switch: its owner's traffic outside the tunnels is blocked, nobody else's") {
        var s = ProtectionState()
        s.tunnels = ["utun4", "utun7"]
        s.locks = [.init(owner: 501, allowLAN: false)]
        let r = rules(s)
        // Without state: a local server's SYN-ACK goes out on lo0 too, and would meet the block (found in INT-30c).
        expectEqual(r.first, "pass out quick on lo0 all no state")
        expect(r.contains("pass out quick on { utun4 utun7 } all"))
        expectEqual(r.last, "block return out quick proto { tcp udp } all user 501")
        expect(!r.contains { $0.hasPrefix("pass quick") || $0.hasPrefix("pass in") }, "only outbound passes: \(r)")
        expect(!r.contains { $0.contains("block return out quick all") }, "not the whole Mac")
    }
    test("PF-03", "allow the local network: a table of private ranges, per owner") {
        var s = ProtectionState()
        s.locks = [.init(owner: 501, allowLAN: true), .init(owner: 502, allowLAN: false)]
        let r = rules(s)
        let table = r.first { $0.hasPrefix("table <mugvpn_lan>") } ?? ""
        for net in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "fe80::/10", "fc00::/7", "ff00::/8"] {
            expect(table.contains(net), net)
        }
        expect(r.contains("block return out quick proto { tcp udp } to ! <mugvpn_lan> user 501"))
        expect(r.contains("block return out quick proto { tcp udp } all user 502"), "another user's choice does not widen it")
    }
    test("PF-04", "DNS only through the tunnels while one takes all traffic") {
        var s = ProtectionState()
        s.tunnels = ["utun4"]
        s.dnsOnlyTunnels = true
        let r = rules(s)
        let tunnel = r.firstIndex(of: "pass out quick on { utun4 } all")!
        let dns = r.firstIndex(of: "block return out quick proto { tcp udp } to any port 53")!
        expect(tunnel < dns)
    }
    test("PF-05", "IPv6 blocked while an IPv4 tunnel takes all traffic; neighbour discovery stays") {
        var s = ProtectionState()
        s.tunnels = ["utun4"]
        s.blockIPv6 = true
        let r = rules(s)
        let nd = r.firstIndex { $0.hasPrefix("pass out quick inet6 proto icmp6 all icmp6-type") }!
        let block = r.firstIndex(of: "block return out quick inet6 all")!
        expect(r.firstIndex(of: "pass out quick on { utun4 } all")! < block && nd < block)
    }
    test("PF-06", "only valid values reach the rules") {
        var s = ProtectionState()
        s.tunnels = ["utun4", "en0", "utun4;block", ""]
        s.locks = [.init(owner: 501, allowLAN: false)]
        let text = PFRules.anchor(s)
        expect(text.contains("{ utun4 }") && !text.contains("en0") && !text.contains(";"), text)
    }
    test("PF-08", "a persistent tunnel's kill switch: the whole Mac, but openvpn, DHCP and name lookups") {
        var s = ProtectionState()
        s.locks = [.init(owner: 0, allowLAN: false, everyone: true)]
        let r = rules(s)
        expect(r.contains("pass out quick proto { tcp udp } user 469999999 >< 470004096"), "MugVPN's openvpn reaches its servers: \(r)")
        expect(r.contains("pass out quick proto udp from any port 68 to any port 67"), "DHCP")
        expect(r.contains("pass out quick proto { tcp udp } to any port 53 user 65"), "the resolver, for openvpn's server names")
        expectEqual(r.last, "block return out quick proto { tcp udp } all")
        s.locks = [.init(owner: 0, allowLAN: true, everyone: true)]
        expectEqual(rules(s).last, "block return out quick proto { tcp udp } to ! <mugvpn_lan>")
        s.locks = [.init(owner: 0, allowLAN: true, everyone: true), .init(owner: 0, allowLAN: false, everyone: true)]
        expectEqual(rules(s).last, "block return out quick proto { tcp udp } all", "the stricter")
    }
    test("PF-07", "the anchor's name and where it hangs") {
        expectEqual(PFRules.anchorName, "com.apple/mugvpn")
    }
}

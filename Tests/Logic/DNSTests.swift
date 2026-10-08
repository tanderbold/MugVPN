import Foundation
import MugVPNAppCore
import MugVPNCore

func registerDNSTests() {
    let base = "client\ndev tun\nremote vpn.example.com 1194\nverb 3\n"
    test("DNS-01", "read the DNS mode") {
        expectEqual(try ConnectionDraft(config: base).dns, DNSChoice())
        let own = try ConnectionDraft(config: base + "dns server 1 address 10.0.0.53 fd00::53\ndns server 1 resolve-domains corp.example.com lab.example.com\n").dns
        expectEqual(own.mode, .own)
        expectEqual(own.servers, ["10.0.0.53", "fd00::53"])
        expectEqual(own.domains, ["corp.example.com", "lab.example.com"])
        let low = try ConnectionDraft(config: base + "dns server 5 address 9.9.9.9\ndns server 2 address 1.1.1.1\n").dns
        expectEqual(low.servers, ["1.1.1.1"], "the first by priority")
        let none = try ConnectionDraft(config: base + "pull-filter ignore \"dns \"\npull-filter ignore \"dhcp-option\"\n").dns
        expectEqual(none.mode, .none)
    }
    test("DNS-02", "own servers for some domains") {
        var d = try ConnectionDraft(config: base + "dhcp-option DNS 8.8.8.8\n")
        d.dns = DNSChoice(mode: .own, servers: ["10.0.0.53"], domains: ["corp.example.com"])
        let out = try d.apply(to: base + "dhcp-option DNS 8.8.8.8\n")
        expect(out.hasPrefix("client\ndev tun\nremote vpn.example.com 1194\nverb 3\n"), out)
        expect(out.contains("pull-filter ignore \"dns \"\npull-filter ignore \"dhcp-option\"\ndns server 1 address 10.0.0.53\ndns server 1 resolve-domains corp.example.com\n"), out)
        expect(!out.contains("8.8.8.8"), "the old DNS line is replaced")
        expectEqual(try ConnectionDraft(config: out).dns, d.dns)
    }
    test("DNS-03", "all names, no change, and back") {
        var d = try ConnectionDraft(config: base)
        d.dns = DNSChoice(mode: .own, servers: ["10.0.0.53", "10.0.0.54"], domains: [])
        let all = try d.apply(to: base)
        expect(all.contains("dns server 1 address 10.0.0.53 10.0.0.54\n") && !all.contains("resolve-domains"), all)
        d.dns = DNSChoice(mode: .none)
        let none = try d.apply(to: base)
        expect(none.contains("pull-filter ignore \"dns \"") && !none.contains("dns server"), none)
        var back = try ConnectionDraft(config: all)
        back.dns = DNSChoice()
        expectEqual(try back.apply(to: all), base, "nothing of ours left")
    }
    test("DNS-04", "checks and lists") {
        expectEqual(ConnectionDraft.parseList("a.example.com, b.example.com\nc.example.com  d"), ["a.example.com", "b.example.com", "c.example.com", "d"])
        var d = try ConnectionDraft(config: base + "auth-user-pass\n<ca>\nCA\n</ca>\n")
        func problem(_ c: DNSChoice, _ word: String) {
            var x = d
            x.dns = c
            expect(x.problems.contains { $0.contains(word) }, "\(c): \(x.problems)")
        }
        d.dns = DNSChoice(mode: .own, servers: ["10.0.0.53", "fd00::53"], domains: ["corp.example.com"])
        expectEqual(d.problems, [])
        problem(DNSChoice(mode: .own, servers: [], domains: []), "DNS server")
        problem(DNSChoice(mode: .own, servers: ["10.0.0"], domains: []), "10.0.0")
        problem(DNSChoice(mode: .own, servers: ["dns.example.com"], domains: []), "dns.example.com")
        problem(DNSChoice(mode: .own, servers: (1...9).map { "10.0.0.\($0)" }, domains: []), "8")
        problem(DNSChoice(mode: .own, servers: ["10.0.0.53"], domains: ["bad domain!"]), "bad domain!")
        problem(DNSChoice(mode: .own, servers: ["10.0.0.53"], domains: ["-x.example.com"]), "-x.example.com")
    }
    test("DNS-05", "policy; the user's own lines stay") {
        var d = try ConnectionDraft(config: base)
        d.dns = DNSChoice(mode: .own, servers: ["10.0.0.53"], domains: ["corp.example.com"])
        _ = try ProfilePolicy.check(ConfigParser.parse(d.apply(to: base)), bundleFiles: [])
        d.dns = DNSChoice(mode: .none)
        _ = try ProfilePolicy.check(ConfigParser.parse(d.apply(to: base)), bundleFiles: [])
        let mine = base + "dns server 2 address 1.1.1.1\ndns search-domains x.example.com\n"
        var e = try ConnectionDraft(config: mine)
        e.allTraffic = true
        let out = try e.apply(to: mine)
        expect(out.contains("dns server 2 address 1.1.1.1\ndns search-domains x.example.com\n"), out)
    }
}

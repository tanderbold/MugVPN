import Foundation
import MugVPNAppCore
import MugVPNCore

private let sample = """
# office VPN
client
dev tun
proto udp
remote vpn.example.com 1194
remote vpn2.example.com 443 tcp
resolv-retry infinite
nobind
ca ca.crt
cert me.crt
key me.key
<tls-auth>
-----BEGIN OpenVPN Static key V1-----
abc
-----END OpenVPN Static key V1-----
</tls-auth>
key-direction 1
verb 3

"""

func registerConnectionDraftTests() {
    test("EDIT-01", "read a profile into the form") {
        let d = try ConnectionDraft(config: sample)
        expectEqual(d.servers, [.init(host: "vpn.example.com", port: 1194, proto: .udp),
                                .init(host: "vpn2.example.com", port: 443, proto: .tcp)])
        expectEqual(d.device, .tun)
        expectEqual(d.ca, .file("ca.crt"))
        expectEqual(d.cert, .file("me.crt"))
        expectEqual(d.key, .file("me.key"))
        expectEqual(d.tlsAuth, .inline("-----BEGIN OpenVPN Static key V1-----\nabc\n-----END OpenVPN Static key V1-----\n"))
        expectEqual(d.tlsCrypt, nil)
        expect(!d.askPassword && !d.allTraffic)
        expect(d.serversEditable)
        let e = try ConnectionDraft(config: "client\nport 443\nproto tcp-client\nremote a\nremote b 1195\nauth-user-pass\nredirect-gateway def1\ndev tap\n")
        expectEqual(e.servers, [.init(host: "a", port: 443, proto: .tcp), .init(host: "b", port: 1195, proto: .tcp)])
        expect(e.askPassword && e.allTraffic)
        expectEqual(e.device, .tap)
        let f = try ConnectionDraft(config: "client\nremote a\n")
        expectEqual(f.servers, [.init(host: "a", port: 1194, proto: .udp)], "openvpn's defaults")
    }
    test("EDIT-02", "nothing changed, nothing rewritten") {
        let d = try ConnectionDraft(config: sample)
        expectEqual(try d.apply(to: sample), sample)
        let crlf = sample.replacingOccurrences(of: "\n", with: "\r\n")
        expectEqual(try ConnectionDraft(config: crlf).apply(to: crlf), crlf)
    }
    test("EDIT-03", "servers change only their lines") {
        var d = try ConnectionDraft(config: sample)
        d.servers = [.init(host: "new.example.com", port: 1195, proto: .tcp)]
        let out = try d.apply(to: sample)
        expect(out.hasPrefix("# office VPN\nclient\ndev tun\n"), "the top stays")
        expect(out.contains("remote new.example.com 1195 tcp\n"))
        expect(!out.contains("vpn.example.com") && !out.contains("vpn2.example.com"))
        expect(out.contains("ca ca.crt\ncert me.crt\nkey me.key\n<tls-auth>"), "the rest as it was")
        expectEqual(try ConnectionDraft(config: out).servers, d.servers)
        d.servers.append(.init(host: "b.example.com", port: 1194, proto: .udp))
        expectEqual(try ConnectionDraft(config: d.apply(to: sample)).servers, d.servers)
        // The global proto must not override what a server line says.
        let p = try ConnectionDraft(config: d.apply(to: "client\nproto tcp\nremote x 1\n"))
        expectEqual(p.servers, d.servers)
    }
    test("EDIT-04", "certificates: replace with content, remove") {
        var d = try ConnectionDraft(config: sample)
        d.ca = .inline("-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n")
        d.cert = nil
        d.key = nil
        var out = try d.apply(to: sample)
        expect(out.contains("<ca>\n-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n</ca>\n"))
        expect(!out.contains("ca ca.crt") && !out.contains("cert me.crt") && !out.contains("key me.key"))
        expectEqual(try ConnectionDraft(config: out).ca, d.ca)
        d.tlsAuth = nil
        d.tlsCrypt = .inline("K\n")
        out = try d.apply(to: sample)
        expect(!out.contains("<tls-auth>") && !out.contains("key-direction"), "tls-auth and its direction gone")
        expect(out.contains("<tls-crypt>\nK\n</tls-crypt>\n"))
        var n = try ConnectionDraft(config: "client\nremote a\n")
        n.tlsAuth = .inline("K\n")
        expect(try n.apply(to: "client\nremote a\n").contains("key-direction 1"), "a client's inline tls-auth")
    }
    test("EDIT-05", "password and all traffic switches") {
        var d = try ConnectionDraft(config: sample)
        d.askPassword = true
        d.allTraffic = true
        let on = try d.apply(to: sample)
        expect(on.contains("auth-user-pass\n") && on.contains("redirect-gateway def1\n"))
        var back = try ConnectionDraft(config: on)
        expect(back.askPassword && back.allTraffic)
        back.askPassword = false
        back.allTraffic = false
        let off = try back.apply(to: on)
        expect(!off.contains("auth-user-pass") && !off.contains("redirect-gateway"))
        // Options the user wrote stay as they are while the switch is on.
        let custom = "client\nremote a\nredirect-gateway def1 bypass-dhcp\nauth-user-pass creds.txt\n"
        expectEqual(try ConnectionDraft(config: custom).apply(to: custom), custom)
    }
    test("EDIT-06", "<connection> blocks: servers read-only") {
        let text = "client\n<connection>\nremote a 1194 udp\n</connection>\n<connection>\nremote b 443 tcp\n</connection>\nca ca.crt\n"
        var d = try ConnectionDraft(config: text)
        expect(!d.serversEditable)
        expectEqual(d.servers.map(\.host), ["a", "b"], "shown")
        d.ca = .inline("CA\n")
        let out = try d.apply(to: text)
        expect(out.contains("<connection>\nremote a 1194 udp\n</connection>"), "blocks stay")
        expect(out.contains("<ca>\nCA\n</ca>"))
        d.servers = [.init(host: "z", port: 1, proto: .udp)]
        expectThrows("servers edited", matching: "text") { _ = try d.apply(to: text) }
    }
    test("EDIT-07", "form problems") {
        var d = ConnectionDraft()
        d.servers = [.init(host: "vpn.example.com", port: 1194, proto: .udp)]
        d.ca = .inline("CA\n")
        d.askPassword = true
        expectEqual(d.problems, [])
        func has(_ change: (inout ConnectionDraft) -> Void, _ word: String) {
            var x = d
            change(&x)
            expect(x.problems.contains { $0.contains(word) }, "\(word): \(x.problems)")
        }
        has({ $0.servers = [] }, "server")
        has({ $0.servers[0].host = "" }, "server")
        has({ $0.servers[0].host = "a b" }, "server")
        has({ $0.servers[0].port = 0 }, "port")
        has({ $0.servers[0].port = 70000 }, "port")
        has({ $0.ca = nil }, "CA")
        has({ $0.cert = .inline("C\n") }, "key")
        has({ $0.key = .inline("K\n") }, "certificate")
        has({ $0.askPassword = false }, "password")
    }
    test("EDIT-08", "a new connection") {
        var d = ConnectionDraft()
        d.servers = [.init(host: "vpn.example.com", port: 443, proto: .tcp)]
        d.ca = .inline("-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n")
        d.askPassword = true
        let text = try d.newConfig()
        expect(text.hasPrefix("client\n"))
        expect(text.contains("remote vpn.example.com 443 tcp\n"))
        let directives = try ConfigParser.parse(text)
        _ = try ProfilePolicy.check(directives, bundleFiles: [])
        let back = try ConnectionDraft(config: text)
        expectEqual(back.servers, d.servers)
        expectEqual(back.ca, d.ca)
        expect(back.askPassword)
        expectEqual(back.device, .tun)
    }
    test("EDIT-09", "awkward values are written safely") {
        var d = try ConnectionDraft(config: "client\nremote a\n")
        d.ca = .file("my certs/ca \"1\".crt")
        let out = try d.apply(to: "client\nremote a\n")
        expectEqual(try ConnectionDraft(config: out).ca, d.ca)
        d.servers = [.init(host: "a#b", port: 1, proto: .udp)]
        expect(d.problems.contains { $0.contains("server") }, "a host openvpn would cut at #")
    }
    test("EDIT-10", "create a profile") {
        let fs = MemFS()
        let store = ProfileStore(fs: fs, userDir: userDir, systemDir: systemDir)
        let p = try store.create(name: "Office", config: "client\nremote a 1194\n<ca>\n\(testCA)</ca>\n")
        expectEqual(p.path, "\(userDir)/Office/Office.ovpn")
        expectEqual(fs.text(p.path), "client\nremote a 1194\n<ca>\n\(testCA)</ca>\n")
        expect(store.scan().contains { $0.name == "Office" })
        expectThrows("taken", matching: "already") { _ = try store.create(name: "office", config: "client\nremote a\n") }
        expectThrows("empty") { _ = try store.create(name: " ", config: "client\nremote a\n") }
        expectThrows("slash") { _ = try store.create(name: "a/b", config: "client\nremote a\n") }
        expectThrows("policy", matching: "cannot use") { _ = try store.create(name: "Bad", config: "client\nremote a\nup /bin/sh\n") }
        expectThrows("no server", matching: "remote") { _ = try store.create(name: "Bad", config: "client\n") }
        expectThrows("missing file") { _ = try store.create(name: "Bad", config: "client\nremote a\nca ca.crt\n") }
        expect(!fs.exists("\(userDir)/Bad"), "nothing written")
    }
    test("EDIT-11", "save a profile") {
        let fs = MemFS()
        fs.add("\(userDir)/work/work.ovpn", "client\nremote w 1194\nca ca.crt\n")
        fs.add("\(userDir)/work/ca.crt", "CA")
        fs.add("\(systemDir)/corp.ovpn", "client\nremote c 1194\n")
        let store = ProfileStore(fs: fs, userDir: userDir, systemDir: systemDir)
        func p(_ name: String) -> Profile { store.scan().first { $0.name == name }! }
        expectEqual(store.config(of: p("work")), "client\nremote w 1194\nca ca.crt\n")
        try store.save(p("work"), config: "client\nremote w2 1194\nca ca.crt\n")
        expectEqual(fs.text("\(userDir)/work/work.ovpn"), "client\nremote w2 1194\nca ca.crt\n")
        expectThrows("policy", matching: "cannot use") { try store.save(p("work"), config: "client\nremote w\nplugin x.so\n") }
        expectThrows("missing file") { try store.save(p("work"), config: "client\nremote w\nkey none.key\n") }
        expectThrows("no server", matching: "remote") { try store.save(p("work"), config: "client\n") }
        expectEqual(fs.text("\(userDir)/work/work.ovpn"), "client\nremote w2 1194\nca ca.crt\n", "unchanged")
        expectThrows("system", matching: "administrator") { try store.save(p("corp"), config: "client\nremote x\n") }
    }
    test("EDIT-12", "servers as text") {
        let (ok, errs) = ConnectionDraft.parseServers("vpn.example.com 443 tcp\n\n  b.example.com:1195 \nc\n")
        expectEqual(errs, [])
        expectEqual(ok, [.init(host: "vpn.example.com", port: 443, proto: .tcp),
                         .init(host: "b.example.com", port: 1195, proto: .udp),
                         .init(host: "c", port: 1194, proto: .udp)])
        expectEqual(ConnectionDraft.formatServers(ok), "vpn.example.com 443 tcp\nb.example.com 1195 udp\nc 1194 udp")
        let (_, bad) = ConnectionDraft.parseServers("a x\nb 1 icmp\nc 1 udp extra\n")
        expectEqual(bad.count, 3)
        expect(bad[0].hasPrefix("line 1") && bad[1].hasPrefix("line 2") && bad[2].hasPrefix("line 3"), "\(bad)")
    }
    test("EDIT-13", "only new problems block saving") {
        let fp = "client\nremote a\npeer-fingerprint AB:CD\nauth-user-pass\n"
        var d = try ConnectionDraft(config: fp)
        expectEqual(d.problems, [], "a fingerprint stands for the CA")
        let p12 = "client\nremote a\npkcs12 me.p12\n"
        expectEqual(try ConnectionDraft(config: p12).problems, [], "pkcs12 holds the CA, certificate and key")
        let odd = "client\nremote a\n"
        d = try ConnectionDraft(config: odd)
        expect(!d.problems.isEmpty)
        let was = d
        d.allTraffic = true
        expectEqual(d.problems(since: was), [], "the profile had these before")
        d.servers = []
        expect(d.problems(since: was).contains { $0.contains("server") })
        expectEqual(d.problems(since: nil), d.problems)
    }
    test("EDIT-14", "a chosen certificate file is PEM text, nothing more") {
        let pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
        expectEqual(ConnectionDraft.materialText(Data(pem.utf8)), pem)
        let key = "-----BEGIN OpenVPN Static key V1-----\nab\n-----END OpenVPN Static key V1-----"
        expectEqual(ConnectionDraft.materialText(Data(key.utf8)), key + "\n")
        expectEqual(ConnectionDraft.materialText(Data((pem + "</ca>\nremote evil 1194\n<ca>\n").utf8)), nil)
        expectEqual(ConnectionDraft.materialText(Data(("x\n\u{0C}</ca>\n" + pem).utf8)), nil)
        expectEqual(ConnectionDraft.materialText(Data("just text\n".utf8)), nil, "not PEM")
        expectEqual(ConnectionDraft.materialText(Data([0xff, 0xfe, 0x00])), nil, "binary")
        expectEqual(ConnectionDraft.materialText(Data(("-----BEGIN X-----\n" + String(repeating: "A", count: 300) + "\n-----END X-----\n").utf8)), nil,
                    "a line openvpn would split")
        expectEqual(ConnectionDraft.materialText(Data(count: (1 << 20) + 1)), nil, "too large")
    }
}

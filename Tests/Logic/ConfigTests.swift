import Foundation
import MugVPNCore

private func parse(_ s: String) throws -> [ConfigDirective] { try ConfigParser.parse(s) }
private func names(_ s: String) throws -> [String] { try parse(s).map(\.name) }
private func args(_ s: String) throws -> [String] { try parse(s).first?.args ?? [] }

/// Directives without line numbers, for comparisons across a serialize round trip.
private func shape(_ ds: [ConfigDirective]) -> [ConfigDirective] {
    ds.map { var d = $0; d.line = 0; return d }
}

func registerConfigTests() {
    // The parser reads a profile exactly as openvpn does: an inline block ends at a line whose
    // leading C whitespace (space, \t, \v, \f, \r) is followed by the close tag, lines come
    // in 256-byte pieces, and characters are compared as bytes (Swift's String compares
    // grapheme clusters, in which a combining mark merges with the quote or tag before it).
    test("CFG-26", "quotes, backslashes and tags are seen as openvpn sees them, combining marks or not") {
        let mark = "\u{301}"
        // A block ends at a close tag even with a combining mark right after it (openvpn: strncmp).
        expectThrows("close tag + mark", matching: "after") { _ = try parse("<ca>\nX\n</ca>\(mark)\nverb 3\n") }
        let ds = try? parse("<ca>\nX\n</ca>\nverb 3\n")
        expectEqual(ds?.map(\.name), ["ca", "verb"])
        // A quote with a mark on it still opens a quoted token.
        expectEqual(try args("setenv X \"\(mark)a b\""), ["X", "\(mark)a b"])
        // A backslash before a quote with a mark: the quote is escaped, the mark is text.
        expectEqual(try args("setenv X \"a\\\"\(mark)b\""), ["X", "a\"\(mark)b"])
        // The writer escapes per scalar too, and a close tag with a mark inside a block is refused.
        let out = ConfigParser.serialize([ConfigDirective(name: "setenv", args: ["X", "\"\(mark)"])])
        expectEqual(try parse(out).first?.args, ["X", "\"\(mark)"])
        expectThrows("written block", matching: "close") {
            _ = try ConfigParser.serializeForOpenVPN([ConfigDirective(name: "ca", inline: "X\n</ca>\(mark)\nverb 9\n")])
        }
        // An inline tag is recognised by its bytes.
        expectThrows("tag with a mark", matching: "tag") { _ = try parse("<ca>\(mark)\nX\n</ca>\n") }
    }
    test("CFG-22", "an inline block ends where openvpn ends it") {
        for ws in ["\u{0B}", "\u{0C}", "\r", " \u{0C}\t"] {
            let ds = try parse("<ca>\nX\n\(ws)</ca>\nverb 3\n")
            expectEqual(ds.map(\.name), ["ca", "verb"], "close after \(ws.unicodeScalars.map { $0.value })")
            expectEqual(ds.first?.inline, "X\n")
        }
    }
    test("CFG-23", "lines longer than openvpn reads at once are refused") {
        let long = String(repeating: "A", count: 255)
        expectThrows("inline", matching: "long") { _ = try parse("<ca>\n\(long)\n</ca>\n") }
        expectThrows("top level", matching: "long") { _ = try parse("setenv-safe X \(long)\n") }
        expectThrows("multi-byte", matching: "long") { _ = try parse("<ca>\n" + String(repeating: "é", count: 128) + "\n</ca>\n") }
        _ = try parse("<ca>\n" + String(repeating: "A", count: 254) + "\n</ca>\n")
    }
    test("CFG-24", "C whitespace separates tokens as in openvpn") {
        expectEqual(try args("remote a\u{0B}b\u{0C}c\r"), ["a", "b", "c"])
    }
    test("CFG-25", "what the helper writes is read by openvpn line by line as written") {
        let long = String(repeating: "B", count: 200)
        let ds = [ConfigDirective(name: "setenv-safe", args: ["X", long, long])]
        expectThrows("over a line", matching: "long") { _ = try ConfigParser.serializeForOpenVPN(ds) }
        let ok = [ConfigDirective(name: "verb", args: ["3"]), ConfigDirective(name: "ca", inline: "X\n")]
        expectEqual(try ConfigParser.serializeForOpenVPN(ok), ConfigParser.serialize(ok))
        let hidden = [ConfigDirective(name: "ca", inline: "X\n\u{0C}</ca>\nverb 9\n")]
        expectThrows("a close tag inside", matching: "close") { _ = try ConfigParser.serializeForOpenVPN(hidden) }
    }
    test("CFG-01", "several tokens") {
        expectEqual(try parse("remote vpn.example.com 1194 udp"),
                    [ConfigDirective(name: "remote", args: ["vpn.example.com", "1194", "udp"], line: 1)])
    }
    test("CFG-02", "comments and blank lines") {
        expectEqual(try names("# c\n; c\n\n   \nverb 3\n  # indented"), ["verb"])
        expectEqual(try args("remote a 1 # trailing"), ["a", "1"])
        expectEqual(try args("remote a 1 ;trailing"), ["a", "1"])
        expectEqual(try args("setenv X a#b"), ["X", "a#b"], "# inside a token is not a comment")
        expectEqual(try parse("x\n\nverb 3")[1].line, 3, "line numbers count blank lines")
    }
    test("CFG-03", "leading -- is dropped") {
        expectEqual(try names("--verb 3"), ["verb"])
        expectEqual(try names("-- 3"), ["--"], "a bare -- stays (openvpn needs 3+ chars)")
    }
    test("CFG-04", "double quotes with escapes") {
        expectEqual(try args("setenv X \"a b\\\"c\\\\d\""), ["X", "a b\"c\\d"])
        expectEqual(try args("setenv X \"a\"b"), ["X", "a", "b"], "a closing quote ends the token")
    }
    test("CFG-05", "single quotes are literal") {
        expectEqual(try args("setenv X 'a\\b \"c'"), ["X", "a\\b \"c"])
    }
    test("CFG-06", "escaped space") {
        expectEqual(try args("ca a\\ b.crt"), ["a b.crt"])
    }
    test("CFG-07", "unterminated quote") {
        expectThrows(matching: "unterminated") { _ = try parse("ca \"x") }
        expectThrows(matching: "unterminated") { _ = try parse("ca 'x") }
    }
    test("CFG-08", "bad backslash, as openvpn") {
        expectThrows(matching: "backslash") { _ = try parse("ca a\\x") }
        expectThrows(matching: "backslash") { _ = try parse("ca a\\") }
    }
    test("CFG-09", "token longer than 255") {
        expectThrows(matching: "longer") { _ = try parse("ca " + String(repeating: "a", count: 256)) }
        // A 255-character token no longer fits on a line openvpn reads whole (CFG-23).
        expectEqual(try args("ca " + String(repeating: "a", count: 251)).first?.count, 251)
    }
    test("CFG-10", "more than 16 parameters") {
        expectThrows(matching: "too many") { _ = try parse("x" + String(repeating: " a", count: 16)) }
        expectEqual(try args("x" + String(repeating: " a", count: 15)).count, 15)
    }
    test("CFG-11", "inline block kept verbatim") {
        let d = try parse("<ca>\n-----BEGIN-----\n  AAA\n-----END-----\n</ca>\nverb 3")
        expectEqual(d.map(\.name), ["ca", "verb"])
        expectEqual(d[0].inline, "-----BEGIN-----\n  AAA\n-----END-----\n")
        expectEqual(d[0].args, [])
        expectEqual(try parse("<ca>\n</ca>")[0].inline, "", "empty block")
        expectEqual(try parse("  <ca>\nX\n  </ca>")[0].inline, "X\n", "indented tags")
    }
    test("CFG-12", "missing end tag") {
        expectThrows(matching: "missing </ca>") { _ = try parse("<ca>\nAAA\n") }
    }
    test("CFG-13", "text after a tag") {
        expectThrows(matching: "after inline tag") { _ = try parse("<ca> x\nA\n</ca>") }
        expectThrows(matching: "after </ca>") { _ = try parse("<ca>\nA\n</ca> x") }
    }
    test("CFG-14", "stray tags") {
        expectThrows(matching: "stray") { _ = try parse("</ca>") }
        expectThrows(matching: "stray") { _ = try parse("<ca") }
    }
    test("CFG-15", "CRLF") {
        let d = try parse("remote a 1\r\n<ca>\r\nX\r\n</ca>\r\n")
        expectEqual(d.map(\.name), ["remote", "ca"])
        expectEqual(d[0].args, ["a", "1"])
        expectEqual(d[1].inline, "X\n")
    }
    test("CFG-16", "NUL byte") {
        expectThrows(matching: "NUL") { _ = try parse("verb 3\u{0}") }
    }
    test("CFG-17", "serialize round trip") {
        let samples = ["remote vpn.example.com 1194 udp", "setenv X \"a b\\\"c\\\\d\"", "setenv X 'a\\b'",
                       "ca a\\ b.crt", "<ca>\n-----BEGIN-----\nAAA\n</ca>", "setenv X \"\"",
                       "<connection>\nremote a 1\n</connection>\nverb 3"]
        for s in samples {
            let d = try parse(s)
            expectEqual(shape(try parse(ConfigParser.serialize(d))), shape(d), s)
        }
    }
    test("CFG-18", "serialize quotes every parameter") {
        let out = ConfigParser.serialize([ConfigDirective(name: "setenv", args: ["X", "a \"b\\"])])
        expectEqual(out, "setenv \"X\" \"a \\\"b\\\\\"\n")
    }
    test("CFG-19", "empty quoted token") {
        expectEqual(try args("setenv X \"\""), ["X", ""])
    }
    test("CFG-21", "an escaped space before a token is skipped, as openvpn does") {
        expectEqual(try args("remote \\ host 1194"), ["host", "1194"])
        expectEqual(try args("remote \\ \\\\ x"), ["\\", "x"])
        expectEqual(try args("remote a\\ b 1"), ["a b", "1"], "inside a token it is still a space")
    }
    test("CFG-20", "UTF-8 BOM ignored") {
        expectEqual(try names("\u{FEFF}client\nverb 3"), ["client", "verb"])
    }
}

/// An OpenVPN static key as the policy expects one (POL-36).
let testStaticKey = "-----BEGIN OpenVPN Static key V1-----\n" + String(repeating: "0123456789abcdef0123456789abcdef\n", count: 16)
    + "-----END OpenVPN Static key V1-----\n"

private func checked(_ s: String, files: Set<String> = []) throws -> ProfilePolicy.Result {
    try ProfilePolicy.check(try ConfigParser.parse(s), bundleFiles: files)
}

func registerPolicyTests() {
    test("POL-01", "plain client profile passes unchanged") {
        let text = "client\ndev tun\nproto udp\nremote a 1194\nnobind\npersist-key\nremote-cert-tls server\ncipher AES-256-GCM\nverb 3"
        let r = try checked(text)
        expectEqual(shape(r.directives), shape(try ConfigParser.parse(text)))
        expect(r.files.isEmpty && r.dropped.isEmpty)
    }
    test("POL-02", "forbidden directives refused with reason and line") {
        let forbidden = ["up /bin/sh", "down /bin/sh", "route-up x", "route-pre-down x", "ipchange x", "tls-verify x",
                         "learn-address x", "client-connect x", "client-disconnect x", "auth-user-pass-verify x via-file",
                         "dns-updown /tmp/x", "iproute /tmp/x", "plugin x.so", "engine x", "providers legacy",
                         "pkcs11-providers /x.dylib", "config other.ovpn", "log /etc/passwd", "log-append /x",
                         "status /tmp/x", "writepid /tmp/x", "tls-export-cert /tmp", "tmp-dir /tmp", "cd /",
                         "chroot /", "daemon", "syslog", "capath /etc", "mode server", "server 10.0.0.0 255.0.0.0",
                         "server-bridge", "dev-node /dev/x"]
        for f in forbidden {
            let name = String(f.split(separator: " ")[0])
            expectThrows(f, matching: "line 2: \(name):") { _ = try checked("client\n" + f) }
        }
    }
    test("POL-03", "management directives refused") {
        for m in ["management 127.0.0.1 1", "management-client-user root", "management-hold", "management-query-passwords"] {
            expectThrows(m, matching: "management") { _ = try checked(m) }
        }
    }
    test("POL-04", "unknown directive refused") {
        expectThrows(matching: "not supported") { _ = try checked("frobnicate 1") }
    }
    test("POL-05", "script-security") {
        expect((try? checked("script-security 0")) != nil, "0")
        expect((try? checked("script-security 1")) != nil, "1")
        expectThrows("2") { _ = try checked("script-security 2") }
        expectThrows("3") { _ = try checked("script-security 3") }
        expectThrows("none") { _ = try checked("script-security") }
        expectThrows("text") { _ = try checked("script-security x") }
    }
    test("POL-29", "user and group refused") {
        for l in ["user nobody", "group nogroup", "user root", "group wheel"] {
            expectThrows(l) { _ = try checked(l) }
        }
    }
    test("POL-26", "no privileged ports, no listening") {
        for l in ["lport 80", "port 22", "proto tcp-server", "lport 1023"] { expectThrows(l) { _ = try checked(l) } }
        for l in ["lport 0", "port 1194", "lport 50000", "proto tcp-client", "proto udp", "proto tcp"] {
            expect((try? checked(l)) != nil, l)
        }
    }
    test("POL-27", "no negative nice, no mlock") {
        for l in ["nice -5", "mlock"] { expectThrows(l) { _ = try checked(l) } }
        expect((try? checked("nice 5")) != nil)
    }
    test("POL-28", "the log keeps its timestamps") {
        for l in ["suppress-timestamps", "machine-readable-output"] { expectThrows(l) { _ = try checked(l) } }
    }
    test("POL-07", "dev") {
        expect((try? checked("dev tun")) != nil)
        expect((try? checked("dev utun7")) != nil)
        for bad in ["dev tap", "dev tun0x", "dev utun", "dev utunX", "dev", "dev tun tun"] {
            expectThrows(bad) { _ = try checked(bad) }
        }
    }
    test("POL-08", "setenv opt with a known directive is that directive") {
        expectThrows("forbidden", matching: "runs a program") { _ = try checked("setenv opt up /bin/sh") }
        let r = try checked("setenv opt verb 4\nsetenv opt block-outside-dns")
        expectEqual(r.directives.map(\.name), ["verb"])
        expect(r.dropped.contains("block-outside-dns"), "another system's option, left out (POL-23)")
        let f = try checked("setenv opt ca ca.crt", files: ["ca.crt"])
        expectEqual(f.directives.first?.args, ["file0"])
    }
    test("POL-09", "setenv opt with an unknown directive is dropped") {
        let r = try checked("setenv opt frob 1")
        expect(r.directives.isEmpty)
        expectEqual(r.dropped, ["setenv opt frob"])
        expectThrows("setenv opt alone") { _ = try checked("setenv opt") }
    }
    test("POL-10", "ignore-unknown-option dropped") {
        let r = try checked("ignore-unknown-option frob\nverb 3")
        expectEqual(r.directives.map(\.name), ["verb"])
        expectEqual(r.dropped, ["ignore-unknown-option"])
    }
    test("POL-11", "inline block of a forbidden directive") {
        expectThrows(matching: "runs a program") { _ = try checked("<up>\n/bin/sh\n</up>") }
    }
    test("POL-12", "inline block of a non-file directive") {
        expectThrows(matching: "inline") { _ = try checked("<route>\n10.0.0.0\n</route>") }
    }
    test("POL-13", "connection block checked and rewritten") {
        expectThrows(matching: "runs a program") { _ = try checked("<connection>\nremote a\nup /bin/sh\n</connection>") }
        let r = try checked("<connection>\nremote a 1194\nhttp-proxy p 1 pa\n</connection>", files: ["pa"])
        expectEqual(r.files, ["pa"])
        let inner = try ConfigParser.parse(r.directives[0].inline ?? "")
        expectEqual(inner.map(\.args), [["a", "1194"], ["p", "1", "file0"]])
    }
    test("POL-14", "nested connection block") {
        // A <connection> inside <connection> cannot be written in one file (the
        // outer block ends at the first </connection>), so check the parsed shape.
        let nested = ConfigDirective(name: "connection", inline: "<connection>\nremote a\n</connection>\n")
        expectThrows(matching: "nested") {
            _ = try ProfilePolicy.check([nested], bundleFiles: [])
        }
    }
    test("POL-15", "file arguments rewritten") {
        // dh is left out (POL-36): a server's file.
        let names = ["ca", "cert", "key", "extra-certs", "pkcs12", "tls-auth", "tls-crypt", "tls-crypt-v2",
                     "secret", "crl-verify", "askpass", "auth-user-pass", "http-proxy-user-pass"]
        for n in names {
            let r = try checked("\(n) f.bin", files: ["f.bin"])
            expectEqual(r.directives.first?.args.first, "file0", n)
            expectEqual(r.files, ["f.bin"], n)
        }
        let ta = try checked("tls-auth ta.key 1", files: ["ta.key"])
        expectEqual(ta.directives[0].args, ["file0", "1"], "extra parameters kept")
    }
    test("POL-16", "same file twice gets one name") {
        let r = try checked("ca a.crt\ncert b.crt\nextra-certs a.crt", files: ["a.crt", "b.crt"])
        expectEqual(r.files, ["a.crt", "b.crt"])
        expectEqual(r.directives.map { $0.args[0] }, ["file0", "file1", "file0"])
    }
    test("POL-17", "file missing from the bundle") {
        expectThrows(matching: "was not sent") { _ = try checked("ca ca.crt") }
    }
    test("POL-18", "[inline] is not a file") {
        let r = try checked("tls-auth [inline] 1\n<tls-auth>\n\(testStaticKey)</tls-auth>")
        expect(r.files.isEmpty)
        expectEqual(r.directives[0].args, ["[inline]", "1"])
    }
    test("POL-19", "auth-user-pass without a file stays interactive") {
        let r = try checked("auth-user-pass")
        expectEqual(r.directives[0].args, [])
        expect(r.files.isEmpty)
    }
    test("POL-20", "http-proxy auth") {
        for mode in ["auto", "auto-nct", "stdin"] {
            expect(try checked("http-proxy p 8080 \(mode)").files.isEmpty, mode)
        }
        expectEqual(try checked("http-proxy p 8080 auth.txt basic", files: ["auth.txt"]).directives[0].args,
                    ["p", "8080", "file0", "basic"])
        expect(try checked("http-proxy p 8080").files.isEmpty)
        expectThrows("one parameter") { _ = try checked("http-proxy p") }
    }
    test("POL-21", "socks-proxy auth file") {
        expectEqual(try checked("socks-proxy s 1080 sa", files: ["sa"]).directives[0].args, ["s", "1080", "file0"])
        expect(try checked("socks-proxy s 1080").files.isEmpty)
    }
    test("POL-22", "crl-verify directory") {
        expectThrows(matching: "director") { _ = try checked("crl-verify /etc/crl dir") }
    }
    test("POL-30", "a directive hidden in an inline block is seen and refused") {
        for ws in ["\u{0B}", "\u{0C}", "\r"] {
            // Refused either way: the hidden line is a forbidden directive, the stray close tag an error.
            expectThrows("hidden after \(ws.unicodeScalars.map { $0.value })") {
                _ = try ProfilePolicy.check(try ConfigParser.parse("client\n<ca>\nX\n\(ws)</ca>\nlog /tmp/x\n</ca>\n"), bundleFiles: [])
            }
        }
        let inConnection = "client\n<connection>\nremote a\nhttp-proxy p 8080 \"" + String(repeating: "C", count: 240) + "\"\n</connection>\n"
        expectThrows("long line in a connection block", matching: "long") {
            _ = try ProfilePolicy.check(try ConfigParser.parse(inConnection), bundleFiles: [])
        }
    }
    test("POL-34", "a route goes through the tunnel or the user's own gateway, not another host") {
        for ok in ["route 10.0.0.0 255.0.0.0", "route 10.0.0.0 255.0.0.0 vpn_gateway", "route 10.0.0.0 255.0.0.0 default",
                   "route 203.0.113.7 255.255.255.255 net_gateway", "route 10.0.0.0 255.0.0.0 vpn_gateway 10", "route 10.0.0.0"] {
            expect((try? checked(ok)) != nil, ok)
        }
        for bad in ["route 10.0.0.0 255.0.0.0 192.168.1.50", "route 10.0.0.0 255.0.0.0 remote_host"] {
            expectThrows(bad, matching: "gateway") { _ = try checked(bad) }
        }
    }
    test("POL-37", "no other way to send routes to a LAN host") {
        for bad in ["route-gateway 192.168.1.50", "route-ipv6 2000::/3 fe80::1", "route-ipv6-gateway fe80::1"] {
            expectThrows(bad) { _ = try checked(bad) }
        }
        for ok in ["route-gateway dhcp", "route-ipv6 2000::/3", "route-ipv6 fd00::/8 vpn_gateway"] {
            expect((try? checked(ok)) != nil, ok)
        }
    }
    test("POL-39", "a server is checked as a server: remote-cert-tls added when the profile names no check") {
        expect(try checked("client\nremote a\nca ca.crt", files: ["ca.crt"]).needsServerCheck)
        for check in ["remote-cert-tls server", "verify-x509-name vpn.example.com name", "remote-cert-eku \"TLS Web Server Authentication\"",
                      "remote-cert-ku a0", "peer-fingerprint AB:CD"] {
            expect(!(try checked("client\nremote a\nca ca.crt\n" + check, files: ["ca.crt"]).needsServerCheck), check)
        }
        expect(!(try checked("client\nremote a")).needsServerCheck, "no CA named: nothing to check against")
    }
    test("POL-40", "no broken or legacy ciphers (SWEET32 and the like)") {
        for bad in ["cipher BF-CBC", "cipher DES-EDE3-CBC", "data-ciphers AES-256-GCM:DES-CBC", "data-ciphers-fallback BF-CBC",
                    "cipher CAST5-CBC", "cipher RC2-CBC", "cipher DESX-CBC", "cipher SEED-CBC", "cipher IDEA-CBC", "auth MD5",
                    "ncp-ciphers AES-128-GCM:BF-CBC"] {
            expectThrows(bad) { _ = try checked("client\nremote a\n" + bad) }
        }
        for ok in ["cipher AES-256-CBC", "data-ciphers AES-256-GCM:CHACHA20-POLY1305", "auth SHA256", "auth SHA1"] {
            expect((try? checked("client\nremote a\n" + ok)) != nil, ok)
        }
    }
    test("POL-38", "a file named twice is checked as everything it is named as") {
        let r = try checked("auth-user-pass f\nkey f", files: ["f"])
        expectEqual(Set(r.fileKinds["f"] ?? []), ["auth-user-pass", "key"])
    }
    test("POL-35", "no plaintext or weak crypto") {
        for bad in ["cipher none", "data-ciphers AES-256-GCM:none", "data-ciphers-fallback none", "auth none",
                    "tls-version-min 1.0", "tls-version-min 1.1 or-highest", "tls-cert-profile insecure", "allow-compression yes",
                    "tls-cert-profile legacy", "tls-cipher DEFAULT:@SECLEVEL=0", "tls-groups X25519@SECLEVEL=0"] {
            expectThrows(bad) { _ = try checked(bad) }
        }
        for ok in ["cipher AES-256-GCM", "data-ciphers AES-256-GCM:CHACHA20-POLY1305", "auth SHA256", "tls-version-min 1.2",
                   "tls-version-min 1.3 or-highest", "tls-cert-profile preferred", "allow-compression asym", "allow-compression no"] {
            expect((try? checked(ok)) != nil, ok)
        }
    }
    test("POL-36", "inline blocks hold what their name says") {
        let cert = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
        let key = "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n"
        let sk = "-----BEGIN OpenVPN Static key V1-----\n" + String(repeating: "0123456789abcdef0123456789abcdef\n", count: 16)
            + "-----END OpenVPN Static key V1-----\n"
        for (name, body) in [("ca", cert), ("cert", "# comment\n" + cert), ("extra-certs", cert + cert), ("key", key),
                             ("key", "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\nabc\n-----END RSA PRIVATE KEY-----\n"),
                             ("tls-auth", sk), ("tls-crypt", "#\n" + sk), ("auth-user-pass", "u\np\n"),
                             ("tls-crypt-v2", "-----BEGIN OpenVPN tls-crypt-v2 client key-----\nQUJD\n-----END OpenVPN tls-crypt-v2 client key-----\n"),
                             ("peer-fingerprint", "# srv\n" + Array(repeating: "AB", count: 32).joined(separator: ":") + "\n"),
                             ("crl-verify", "-----BEGIN X509 CRL-----\nMIIB\n-----END X509 CRL-----\n"), ("pkcs12", "TUlJQg==\n")] {
            expect((try? checked("<\(name)>\n\(body)</\(name)>")) != nil, name)
        }
        for (name, body) in [("ca", key), ("ca", "hello\n"), ("key", cert), ("tls-auth", cert), ("auth-user-pass", "a\nb\nc\n"),
                             ("ca", cert + key), ("pkcs12", "not base64!\n"),
                             ("ca", "-----BEGIN CERTIFICATE-----\n" + String(repeating: "QUJD\n", count: 20000) + "-----END CERTIFICATE-----\n")] {
            expectThrows(name, matching: name) { _ = try checked("<\(name)>\n\(body)</\(name)>") }
        }
        expectEqual(try checked("dh dh.pem", files: ["dh.pem"]).directives, [], "dh: a server's file, left out")
    }
    test("POL-23", "Windows-only options are dropped, not passed to openvpn") {
        let r = try checked("block-outside-dns\nregister-dns\nip-win32 dynamic\nroute-method exe\nwindows-driver wintun\n"
                            + "tap-sleep 1\ndhcp-release\ndhcp-renew\ndhcp-pre-release\nshow-net-up\ntxqueuelen 100\nverb 3")
        expectEqual(r.directives.map(\.name), ["route-method", "verb"])
        expectEqual(Set(r.dropped), ["block-outside-dns", "register-dns", "ip-win32", "windows-driver", "tap-sleep",
                                     "dhcp-release", "dhcp-renew", "dhcp-pre-release", "show-net-up", "txqueuelen"])
    }
    test("POL-31", "setenv: only what openvpn itself reads goes to root openvpn") {
        let r = try checked("setenv UV_SITE berlin\nsetenv REMOTE_RANDOM_HOSTNAME\nsetenv PUSH_PEER_INFO\n"
                            + "setenv SERVER_POLL_TIMEOUT 5\nsetenv CORP_SITE x\nsetenv MallocLogFile /tmp/x\n"
                            + "setenv FORWARD_COMPATIBLE 1\nsetenv opt verb 3")
        expectEqual(r.directives.map { $0.args.first ?? $0.name }, ["UV_SITE", "REMOTE_RANDOM_HOSTNAME", "PUSH_PEER_INFO",
                                                                    "SERVER_POLL_TIMEOUT", "3"])
        expect(r.dropped.contains("setenv CORP_SITE") && r.dropped.contains("setenv MallocLogFile")
               && r.dropped.contains("setenv FORWARD_COMPATIBLE"), "\(r.dropped)")
    }
    test("POL-32", "options MugVPN's openvpn cannot use or a client must not set") {
        for line in ["pkcs11-id x", "pkcs11-id-management", "key-derivation tls-ekm", "connect-freq 1 1",
                     "dev-type tap", "allow-pull-fqdn", "allow-recursive-routing"] {
            expectThrows(line) { _ = try checked(line) }
        }
        expectEqual(try checked("dev-type tun").directives.map(\.name), ["dev-type"])
    }
    test("POL-33", "redirect-gateway always keeps the default route (def1)") {
        // Without def1 openvpn deletes the system default route; a crash leaves the Mac offline.
        expectEqual(try checked("redirect-gateway").directives[0].args, ["def1"])
        expectEqual(try checked("redirect-gateway local bypass-dhcp").directives[0].args, ["local", "bypass-dhcp", "def1"])
        expectEqual(try checked("redirect-gateway def1 ipv6").directives[0].args, ["def1", "ipv6"])
    }
    test("POL-24", "referenced files") {
        let d = try ConfigParser.parse("ca a\ncert b\nca a\ntls-auth [inline]\nsetenv opt key k\n<connection>\nsocks-proxy s 1 sa\n</connection>\nhttp-proxy p 1 auto")
        expectEqual(ProfilePolicy.referencedFiles(d), ["a", "b", "k", "sa"])
    }
    test("POL-25", "any bundle key, only fileN in the run directory") {
        let r = try checked("ca /etc/ssl/ca.crt\ncert ../up/c.crt", files: ["/etc/ssl/ca.crt", "../up/c.crt"])
        expectEqual(r.directives.map { $0.args[0] }, ["file0", "file1"])
        expectEqual(ProfilePolicy.runName(forIndex: 1), "file1")
    }
}

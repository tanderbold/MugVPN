import Foundation
import MugVPNAppCore

// L-DIAG: what an exported diagnostics archive may contain.

func registerDiagnosticsTests() {
    test("DIAG-01", "a profile in the archive: no keys, secrets or passwords; the rest as it is") {
        let config = """
        client
        remote vpn.example.com 1194
        <ca>
        -----BEGIN CERTIFICATE-----
        CA
        -----END CERTIFICATE-----
        </ca>
        <key>
        -----BEGIN PRIVATE KEY-----
        SECRET
        -----END PRIVATE KEY-----
        </key>
        <tls-crypt>
        SECRET2
        </tls-crypt>
        <auth-user-pass>
        alice
        hunter2
        </auth-user-pass>
        http-proxy-user-pass creds.txt
        askpass pass.txt
        """
        let s = MugVPNAppCore.Diagnostics.sanitize(config: config)
        for secret in ["SECRET", "SECRET2", "hunter2", "alice"] { expect(!s.contains(secret), "\(secret) in \(s)") }
        expect(s.contains("remote vpn.example.com 1194") && s.contains("-----BEGIN CERTIFICATE-----"), s)
        expect(s.contains("<key>\n[removed]\n</key>"), s)
        expect(s.contains("http-proxy-user-pass [removed]"), s)
        expectEqual(MugVPNAppCore.Diagnostics.sanitize(config: "client\n<key>\nunterminated"), "[a profile MugVPN cannot read: left out]")
    }
    test("DIAG-03", "only what is known to be safe keeps its arguments: setenv values, headers, comments go") {
        let config = """
        # my password is hunter2
        client
        dev tun
        proto udp
        remote vpn.example.com 1194 udp
        setenv API_TOKEN hunter3
        setenv-safe OTHER hunter4
        http-proxy proxy.lan 3128 creds.txt basic
        http-proxy-option CUSTOM-HEADER Authorization "Basic aHVudGVyNQ=="
        static-challenge "Enter PIN hunter6" 1
        ; another comment hunter7
        route 10.1.0.0 255.255.0.0
        cert me.crt
        <connection>
        remote b.example.com 443 tcp
        setenv X hunter8
        </connection>
        """
        let s = MugVPNAppCore.Diagnostics.sanitize(config: config)
        for secret in ["hunter2", "hunter3", "hunter4", "aHVudGVyNQ==", "hunter6", "hunter7", "hunter8", "creds.txt"] {
            expect(!s.contains(secret), "\(secret) in \(s)")
        }
        for kept in ["client", "dev tun", "proto udp", "remote vpn.example.com 1194 udp", "route 10.1.0.0 255.255.0.0",
                     "cert me.crt", "remote b.example.com 443 tcp", "http-proxy proxy.lan 3128 [removed]",
                     "setenv [removed]", "http-proxy-option [removed]"] {
            expect(s.contains(kept), "\(kept) missing from \(s)")
        }
    }
    test("DIAG-02", "the archive's files: a summary, the system's state, each profile and log") {
        let files = MugVPNAppCore.Diagnostics.files(
            summary: ["MugVPN": "1.2", "helper": "1.2", "openvpn": "2.7.8", "macOS": "15.1"],
            commands: ["routes.txt": "default 192.168.1.1", "dns.txt": "resolver #1"],
            profiles: [("office (work)", "client\n<key>\nK\n</key>\n")], logs: [("office", "line")])
        expectEqual(files.map(\.name).sorted(),
                    ["dns.txt", "logs/office.log", "profiles/office (work).ovpn", "routes.txt", "summary.txt"])
        let summary = files.first { $0.name == "summary.txt" }!.text
        expect(summary.contains("openvpn: 2.7.8") && summary.contains("macOS: 15.1"), summary)
        expect(!files.first { $0.name.hasPrefix("profiles/") }!.text.contains("\nK\n"), "sanitized")
        expectEqual(MugVPNAppCore.Diagnostics.files(summary: [:], commands: [:], profiles: [("../x/y", "client\n")], logs: [])
                        .map(\.name).filter { $0.hasPrefix("profiles/") }, ["profiles/.._x_y.ovpn"], "no way out of the folder")
    }
}

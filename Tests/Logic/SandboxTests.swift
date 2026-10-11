import Foundation
import MugVPNHelperCore

func registerSandboxTests() {
    let p = OpenVPNSandbox.profile(binary: "/L/libexec/openvpn", runDir: "/L/run/ID1", lookups: ["com.apple.dnssd.service"])
    test("SBX-01", "openvpn reads only what it needs: the system's files, its own run folder and binary; nothing else") {
        let lines = p.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
        let deny = lines.firstIndex(of: "(deny file-read*)")
        expect(deny != nil, "reading is denied by default: \(p)")
        let allows = lines.filter { $0.hasPrefix("(allow file-read*") }
        expect(allows.allSatisfy { lines.firstIndex(of: $0)! > deny! }, "allowed after the default denial")
        let read = allows.joined(separator: " ")
        for want in ["(subpath \"/System\")", "(subpath \"/usr/lib\")", "(subpath \"/private/etc\")", "(subpath \"/L/run/ID1\")",
                     "(literal \"/L/libexec/openvpn\")", "(subpath \"/dev\")"] {
            expect(read.contains(want), "\(want) readable: \(read)")
        }
        for not in ["/tmp", "/private/tmp", "/Volumes", "/opt", "/usr/local", "/Users", "/private/var/root"] {
            expect(!read.contains("\"\(not)\"") && !read.contains("\"\(not)/"), "\(not) not readable")
        }
    }
    test("SBX-02", "writes, processes and services as before: only its socket folder, nothing started, only the lookups named") {
        expect(p.contains("(deny file-write* (require-not (require-any (subpath \"/L/run/ID1/sock\")"), p)
        expect(p.contains("(deny process-fork)"))
        expect(p.contains("(global-name \"com.apple.dnssd.service\")"))
    }
}

import Foundation
import MugVPNAppCore

private func kinds(_ line: String) -> [(String, LogHighlighter.Kind)] {
    LogHighlighter.spans(line).map { (String(line[$0.range]), $0.kind) }
}

private func has(_ line: String, _ text: String, _ kind: LogHighlighter.Kind) -> Bool {
    kinds(line).contains { $0.0 == text && $0.1 == kind }
}

func registerHighlightTests() {
    test("HL-01", "timestamp") {
        let l = "2026-10-06 05:46:44 TCP connection established"
        expect(has(l, "2026-10-06 05:46:44", .timestamp))
    }
    test("HL-02", "errors colour the whole line") {
        for l in ["2026-10-06 05:46:44 ERROR: OS X route add command failed", "FATAL: Cannot open TUN",
                  "2026-10-06 05:46:44 AUTH: Received control message: AUTH_FAILED",
                  "Verification Failed: 'Auth'", "Exiting due to fatal error", "TLS Error: TLS handshake failed",
                  "TCP: connect to [AF_INET]127.0.0.1:1194 failed: Connection refused"] {
            let body = l.hasPrefix("2026") ? String(l.dropFirst(20)) : l
            expect(has(l, body, .error), l)
        }
    }
    test("HL-03", "warnings") {
        expect(has("2026-10-06 05:46:44 WARNING: this cipher is weak", "WARNING: this cipher is weak", .warning))
        expect(has("DEPRECATED OPTION: --cipher set to 'AES-256-CBC'", "DEPRECATED OPTION: --cipher set to 'AES-256-CBC'", .warning))
    }
    test("HL-04", "success") {
        expect(has("2026-10-06 05:46:44 Initialization Sequence Completed", "Initialization Sequence Completed", .success))
        expect(has("Peer Connection Initiated with [AF_INET]1.2.3.4:1194", "Peer Connection Initiated", .success))
        expect(has(">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,1.2.3.4,1194,,", "CONNECTED,SUCCESS", .success))
    }
    test("HL-05", "addresses") {
        let l = "2026-10-06 05:46:44 /sbin/ifconfig utun4 10.81.0.2 10.81.0.2 netmask 255.255.255.0 mtu 1500 up"
        expect(has(l, "10.81.0.2", .address))
        expect(has("link remote: [AF_INET]192.168.64.1:1194", "192.168.64.1:1194", .address))
        expect(has("dns server 1 address fd00::53", "fd00::53", .address))
        expect(!kinds("version 2.7.7 built").contains { $0.1 == .address }, "a version is not an address")
    }
    test("HL-06", "keywords") {
        expect(has("PUSH: Received control message: 'PUSH_REPLY,route 10.91.0.0'", "PUSH_REPLY", .keyword))
        expect(has("2026-10-06 05:46:44 /sbin/route add -net 10.91.0.0 10.81.0.1 255.255.255.0", "route add", .keyword))
        expect(has("SIGUSR1[soft,connection-reset] received, process restarting", "SIGUSR1", .keyword))
        expect(has("SIGUSR1[soft,connection-reset] received, process restarting", "restarting", .keyword))
        expect(has("Opened utun device utun4", "utun4", .keyword))
        expect(has("dns up command exited with status 0", "dns", .keyword))
    }
    test("HL-07", "plain lines; spans never overlap or leave the line") {
        expect(LogHighlighter.spans("Data Channel: cipher 'AES-256-GCM'").isEmpty)
        var rng = SystemRandomNumberGenerator()
        let alphabet = Array("abcERROR:WARNING 0123456789.:/-,[]_ PUSH_REPLY route add utun dns SIGTERM CONNECTED,SUCCESS")
        for _ in 0..<500 {
            let line = String((0..<Int.random(in: 0...80, using: &rng)).map { _ in alphabet.randomElement(using: &rng)! })
            let spans = LogHighlighter.spans(line).sorted { $0.range.lowerBound < $1.range.lowerBound }
            for (a, b) in zip(spans, spans.dropFirst()) where a.range.upperBound > b.range.lowerBound {
                expect(false, "overlap in \(line.debugDescription)")
            }
            for s in spans where s.range.lowerBound < line.startIndex || s.range.upperBound > line.endIndex {
                expect(false, "outside \(line.debugDescription)")
            }
        }
    }
    test("HL-08", "log theme setting") {
        let b = FakeSettingsBackend()
        let st = SettingsStore(backend: b)
        expectEqual(st.settings.logTheme, .system)
        try st.update { $0.logTheme = .dark }
        expectEqual(b.values["log_theme"] as? String, "dark")
        expectEqual(SettingsStore(backend: b).settings.logTheme, .dark)
    }
}

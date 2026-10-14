import Foundation
import MugVPNAppCore
import MugVPNCore

// The app's typed commands and events, and openvpn 2's management interface as one way to carry them.

func registerTunnelLinkTests() {
    test("LNK-01", "every command as openvpn 2's management command; a value with a line break or NUL is found") {
        let cases: [(TunnelCommand, String)] = [
            (.watchState, "state on"), (.watchLog, "log on all"), (.byteCount(seconds: 5), "bytecount 5"),
            (.holdOff, "hold off"), (.releaseHold, "hold release"),
            (.confirm(name: "OPENTUN", ok: true), "needok 'OPENTUN' ok"), (.confirm(name: "x", ok: false), "needok 'x' cancel"),
            (.answer(name: "pkcs11-id-request", value: "a\"b"), "needstr 'pkcs11-id-request' \"a\\\"b\""),
            (.countPKCS11, "pkcs11-id-count"), (.getPKCS11(2), "pkcs11-id-get 2"),
            (.username(type: "Auth", value: "u"), "username \"Auth\" \"u\""),
            (.password(type: "Private Key", value: "p\\q"), "password \"Private Key\" \"p\\\\q\""),
            (.challengeResponse("123456"), "cr-response MTIzNDU2"),
            (.proxyNone, "proxy NONE"), (.proxyHTTP(host: "proxy.example.com", port: 8080), "proxy HTTP proxy.example.com 8080"),
            (.reconnect, "signal SIGUSR1"), (.managementPassword("secret"), "secret"),
        ]
        for (c, text) in cases {
            expectEqual(c.managementText, text)
            expect(!c.hasLineBreak, text)
        }
        for c in [TunnelCommand.password(type: "Auth", value: "a\nsignal SIGTERM"), .username(type: "Auth", value: "a\r"),
                  .answer(name: "x", value: "\0"), .challengeResponse("x\ny"), .proxyHTTP(host: "h\n", port: 1)] {
            expect(c.hasLineBreak, "\(c)")
        }
    }
    test("LNK-02", "openvpn 2's interface: lines in as typed events, its close as one more, commands out as its lines") {
        let bytes = FakeTransport()
        var events: [ManagementEvent] = []
        var closed = 0
        guard let link = ManagementTunnelTransport(bytes).open("/run/1/m.sock", onEvent: { events.append($0) },
                                                               onClose: { closed += 1 }) else { return expect(false, "opened") }
        guard let l = bytes.links["/run/1/m.sock"] else { return expect(false) }
        l.onData(Data(">HOLD:Waiting for hold release:0\n>BYTECOUNT:10,".utf8))
        l.onData(Data("20\n".utf8))
        expectEqual(events, [.hold, .byteCount(input: 10, output: 20)], "a line split over two reads put together")
        link.send(.releaseHold)
        var sent: Bool?
        link.send(.confirm(name: "OPENTUN", ok: true), passing: 7) { sent = $0 }
        expectEqual(l.written, ["hold release", "needok 'OPENTUN' ok"])
        expectEqual(l.passed, [7])
        expectEqual(sent, true)
        l.onClose()
        expectEqual(events.last, .disconnected)
        expectEqual(closed, 1)
        bytes.failures = 1
        expect(ManagementTunnelTransport(bytes).open("/run/2/m.sock", onEvent: { _ in }, onClose: {}) == nil, "not there yet")
    }
}

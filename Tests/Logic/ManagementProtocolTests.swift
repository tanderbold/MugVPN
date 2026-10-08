import Foundation
import MugVPNAppCore
import MugVPNCore

private func feed(_ p: ManagementProtocol, _ s: String) -> [ManagementEvent] {
    p.received(Data(s.utf8))
}

private func event(_ line: String) -> ManagementEvent {
    guard case .realtime(let type, let payload) = ManagementMessage.parse(line) else { return .other(type: "", payload: line) }
    return ManagementEvent.parse(type: type, payload: payload)
}

func registerManagementProtocolTests() {
    test("MGT-04", "lines split across reads, CRLF") {
        let p = ManagementProtocol()
        expectEqual(feed(p, ">BYTECOUNT:1"), [])
        expectEqual(feed(p, "0,20\r\n>HOLD:Waiting for hold release:0\r"), [.byteCount(input: 10, output: 20)])
        expectEqual(feed(p, "\n"), [.hold])
    }
    test("MGT-05", "password prompt without a newline") {
        let p = ManagementProtocol()
        expectEqual(feed(p, "ENTER PASSWORD:"), [.passwordPrompt])
    }
    test("MGT-06", "multi-line reply up to END") {
        let p = ManagementProtocol()
        var got: [ManagementReply] = []
        let bytes = p.command("status", multiline: true) { got.append($0) }
        expectEqual(String(decoding: bytes, as: UTF8.self), "status\n")
        expectEqual(feed(p, "OpenVPN CLIENT LIST\nUpdated,x\nEND\n"), [])
        expectEqual(got, [.lines(["OpenVPN CLIENT LIST", "Updated,x"])])
    }
    test("MGT-07", "replies matched to commands in order, events in between") {
        let p = ManagementProtocol()
        var got: [String] = []
        _ = p.command("state on") { got.append("1:\($0)") }
        _ = p.command("hold release") { got.append("2:\($0)") }
        _ = p.command("bogus") { got.append("3:\($0)") }
        let events = feed(p, "SUCCESS: real-time state notification set to ON\n>LOG:1,I,hello\nSUCCESS: hold release succeeded\nERROR: unknown command, enter 'help' for more options\n")
        expectEqual(events, [.log("hello")])
        expectEqual(got, ["1:success(\"real-time state notification set to ON\")",
                          "2:success(\"hold release succeeded\")",
                          "3:error(\"unknown command, enter \\'help\\' for more options\")"])
        expectEqual(feed(p, "SUCCESS: stray\n"), [], "a reply without a command is ignored")
    }
    test("MGT-08", "socket closed") {
        let p = ManagementProtocol()
        var got: [ManagementReply] = []
        _ = p.command("state on") { got.append($0) }
        expectEqual(p.closed(), [.disconnected])
        expectEqual(got, [.error("disconnected")], "pending commands fail")
    }
    test("MGT-09", "password requests") {
        expectEqual(event(">PASSWORD:Need 'Auth' username/password"), .password(.credentials(type: "Auth", staticChallenge: nil)))
        expectEqual(event(">PASSWORD:Need 'HTTP Proxy' username/password"), .password(.credentials(type: "HTTP Proxy", staticChallenge: nil)))
        expectEqual(event(">PASSWORD:Need 'Private Key' password"), .password(.secret(type: "Private Key")))
        expectEqual(event(">PASSWORD:Verification Failed: 'Auth'"), .password(.failed(type: "Auth", challenge: nil)))
        expectEqual(event(">PASSWORD:Verification Failed: 'Private Key'"), .password(.failed(type: "Private Key", challenge: nil)))
        expectEqual(event(">PASSWORD:Auth-Token:abc123"), .password(.authToken("abc123")))
    }
    test("MGT-10", "static challenge") {
        expectEqual(event(">PASSWORD:Need 'Auth' username/password SC:1,Please enter token PIN"),
                    .password(.credentials(type: "Auth", staticChallenge: StaticChallenge(echo: true, concat: false, text: "Please enter token PIN"))))
        expectEqual(event(">PASSWORD:Need 'Auth' username/password SC:2,OTP, please"),
                    .password(.credentials(type: "Auth", staticChallenge: StaticChallenge(echo: false, concat: true, text: "OTP, please"))))
    }
    test("MGT-11", "dynamic challenge CRV1") {
        let e = event(">PASSWORD:Verification Failed: 'Auth' ['CRV1:R,E:Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l:Y3Ix:Please enter token PIN']")
        expectEqual(e, .password(.failed(type: "Auth", challenge: DynamicChallenge(
            echo: true, responseRequired: true, stateID: "Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l", username: "cr1",
            text: "Please enter token PIN"))))
        let e2 = event(">PASSWORD:Verification Failed: 'Auth' ['CRV1::id:dXNlcg==:Text: with colons']")
        expectEqual(e2, .password(.failed(type: "Auth", challenge: DynamicChallenge(
            echo: false, responseRequired: false, stateID: "id", username: "user", text: "Text: with colons"))))
    }
    test("MGT-12", "INFOMSG kinds") {
        expectEqual(event(">INFOMSG:WEB_AUTH::https://sso.example.com/a?b=c"), .info(.webAuth(flags: "", url: "https://sso.example.com/a?b=c")))
        expectEqual(event(">INFOMSG:WEB_AUTH:external:https://x"), .info(.webAuth(flags: "external", url: "https://x")))
        expectEqual(event(">INFOMSG:OPEN_URL:https://x/y"), .info(.webAuth(flags: "", url: "https://x/y")))
        expectEqual(event(">INFOMSG:CR_TEXT:E,R:Enter the code: now"), .info(.crText(echo: true, responseRequired: true, text: "Enter the code: now")))
        expectEqual(event(">INFOMSG:something else"), .info(.text("something else")))
    }
    test("MGT-13", "NEED-OK, NEED-STR, pkcs11") {
        expectEqual(event(">NEED-OK:Need 'token-insertion-request' confirmation MSG:Please insert your token"),
                    .needOK(name: "token-insertion-request", message: "Please insert your token"))
        expectEqual(event(">NEED-STR:Need 'name' input MSG:Please specify your name"),
                    .needString(name: "name", message: "Please specify your name"))
        expectEqual(event(">PKCS11ID-COUNT:3"), .pkcs11Count(3))
        expectEqual(event(">PKCS11ID-ENTRY:'1', ID:'pkcs11:id=abc', BLOB:'MIIB'"),
                    .pkcs11Entry(index: 1, id: "pkcs11:id=abc", certificate: "MIIB"))
    }
    test("MGT-14", "BYTECOUNT") {
        expectEqual(event(">BYTECOUNT:123456789012,42"), .byteCount(input: 123456789012, output: 42))
    }
    test("MGT-15", "ECHO") {
        expectEqual(event(">ECHO:1101519562,msg-window Hello there"), .echo(.window("Hello there")))
        expectEqual(event(">ECHO:1101519562,msg-notify Heads up"), .echo(.notify("Heads up")))
        expectEqual(event(">ECHO:1101519562,msg part one"), .echo(.append("part one")))
        expectEqual(event(">ECHO:1101519562,msg-n line"), .echo(.appendLine("line")))
        expectEqual(event(">ECHO:1101519562,forget-passwords"), .echo(.forgetPasswords))
        expectEqual(event(">ECHO:1101519562,setenv x"), .echo(.other("setenv x")))
    }
    test("MGT-16", "HOLD, FATAL, LOG, STATE, PROXY") {
        expectEqual(event(">HOLD:Waiting for hold release:10"), .hold)
        expectEqual(event(">FATAL:Cannot open TUN"), .fatal("Cannot open TUN"))
        expectEqual(event(">LOG:1700000000,W,careful, comma"), .log("careful, comma"))
        expectEqual(event(">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,1.2.3.4,1194,,"),
                    .state(ManagementState(payload: "1700000000,CONNECTED,SUCCESS,10.8.0.2,1.2.3.4,1194,,")!))
        expectEqual(event(">PROXY:1,TCP,vpn.example.com"), .proxy(index: 1, proto: "TCP", host: "vpn.example.com"))
    }
    test("MGT-17", "malformed messages do not crash") {
        for line in [">PASSWORD:", ">PASSWORD:Need", ">ECHO:", ">ECHO:x", ">BYTECOUNT:x,y", ">BYTECOUNT:", ">STATE:",
                     ">INFOMSG:WEB_AUTH", ">INFOMSG:CR_TEXT:", ">NEED-OK:", ">PKCS11ID-COUNT:x",
                     ">PASSWORD:Verification Failed: 'Auth' ['CRV1:']", ">PROXY:", ">PKCS11ID-ENTRY:'x'"] {
            _ = event(line)
        }
        let p = ManagementProtocol()
        _ = feed(p, String(repeating: "x", count: 100_000) + "\n\u{FF}\n")
        expect(true)
    }
}

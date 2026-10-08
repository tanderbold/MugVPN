import Foundation
import MugVPNCore

func registerManagementTests() {
    test("MGT-01", "message kinds") {
        expectEqual(ManagementMessage.parse(">HOLD:Waiting for hold release:0"), .realtime(type: "HOLD", payload: "Waiting for hold release:0"))
        expectEqual(ManagementMessage.parse("SUCCESS: hold release succeeded"), .success("hold release succeeded"))
        expectEqual(ManagementMessage.parse("ERROR: unknown command"), .error("unknown command"))
        expectEqual(ManagementMessage.parse("END"), .line("END"))
        expectEqual(ManagementMessage.parse(">INFO"), .line(">INFO"), "no colon: not a real-time message")
        expectEqual(ManagementMessage.parse(">PASSWORD:Need 'Auth' username/password"),
                    .realtime(type: "PASSWORD", payload: "Need 'Auth' username/password"))
    }
    test("MGT-02", "STATE fields") {
        let s = ManagementState(payload: "1700000000,CONNECTED,SUCCESS,10.8.0.2,1.2.3.4,1194,,fd00::2")
        expectEqual(s?.time, 1700000000)
        expectEqual(s?.name, "CONNECTED")
        expectEqual(s?.description, "SUCCESS")
        expectEqual(s?.localIP, "10.8.0.2")
        expectEqual(s?.remoteIP, "1.2.3.4")
        expectEqual(s?.localIPv6, "fd00::2")
        expectEqual(ManagementState(payload: "1700000000,WAIT,,,")?.name, "WAIT")
        expect(ManagementState(payload: "x,WAIT") == nil)
        expect(ManagementState(payload: "1700000000") == nil)
    }
    test("MGT-03", "quoting") {
        expectEqual(managementQuote("a\"b\\c"), "\"a\\\"b\\\\c\"")
        expectEqual(managementQuote(""), "\"\"")
    }
}

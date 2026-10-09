import Foundation
import MugVPNAppCore

// L-CAP: networks that ask for a sign-in first (hotels, airports, trains).

func registerCaptivePortalTests() {
    test("CAP-01", "Apple's probe page as it is: no sign-in; anything else in its place: a sign-in page") {
        let ok = HTTPResponse(status: 200, body: Data("<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>".utf8),
                              contentDisposition: nil)
        expectEqual(CaptivePortal.verdict(.success(ok)), false)
        let portal = HTTPResponse(status: 200, body: Data("<html><form>Accept the terms</form></html>".utf8), contentDisposition: nil)
        expectEqual(CaptivePortal.verdict(.success(portal)), true)
        expectEqual(CaptivePortal.verdict(.success(HTTPResponse(status: 302, body: Data(), contentDisposition: nil))), true)
        expectEqual(CaptivePortal.verdict(.failure(ProfileError("offline"))), nil, "no answer: cannot tell")
        expectEqual(CaptivePortal.verdict(.success(HTTPResponse(status: 503, body: Data(), contentDisposition: nil))), nil)
        expectEqual(CaptivePortal.probeURL.absoluteString, "http://captive.apple.com/hotspot-detect.html")
        expectEqual(CaptivePortal.signInSeconds, 120)
    }
}

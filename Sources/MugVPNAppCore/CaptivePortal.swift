import Foundation

/// Networks that ask for a sign-in before anything else gets through (hotels, airports, trains):
/// asked as macOS asks, with Apple's probe page.
public enum CaptivePortal {
    public static let probeURL = URL(string: "http://captive.apple.com/hotspot-detect.html")!
    /// How long a kill switch's block is lifted to sign in.
    public static let signInSeconds = 120

    /// true: a sign-in page answers in the probe's place; false: the network lets everything through;
    /// nil: no answer to tell by (offline, blocked, a server error).
    public static func verdict(_ r: Result<HTTPResponse, Error>) -> Bool? {
        guard case .success(let resp) = r else { return nil }
        if (300..<400).contains(resp.status) { return true }
        guard resp.status == 200 else { return nil }
        return !String(decoding: resp.body, as: UTF8.self).contains("<TITLE>Success</TITLE>")
    }
}

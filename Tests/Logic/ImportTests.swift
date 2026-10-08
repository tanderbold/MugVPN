import Foundation
import MugVPNAppCore

final class FakeHTTP: HTTPFetcher {
    var responses: [Result<HTTPResponse, Error>] = []
    var requests: [(url: URL, username: String, password: String)] = []
    func get(_ url: URL, username: String, password: String, completion: @escaping (Result<HTTPResponse, Error>) -> Void) {
        requests.append((url, username, password))
        completion(responses.isEmpty ? .failure(ProfileError("no response")) : responses.removeFirst())
    }
}

private let profileText = "client\ndev tun\nremote vpn.example.com 1194\n<ca>\nX\n</ca>\n"

private func ok(_ body: String = profileText, disposition: String? = nil) -> Result<HTTPResponse, Error> {
    .success(HTTPResponse(status: 200, body: Data(body.utf8), contentDisposition: disposition))
}

private func download(_ http: FakeHTTP, _ source: ImportSource, challenge: String? = "123",
                      asked: ((DynamicChallenge) -> Void)? = nil) -> Result<DownloadedProfile, ProfileError>? {
    var out: Result<DownloadedProfile, ProfileError>?
    ProfileDownloader(http: http).download(source, username: "alice", password: "pw", askChallenge: { c, reply in
        asked?(c)
        reply(challenge)
    }) { out = $0 }
    return out
}

func registerImportTests() {
    test("ASI-01", "Access Server URL") {
        func u(_ h: String, _ auto: Bool = false) -> String? { ProfileDownloader.requestURL(.accessServer(host: h, autologin: auto))?.absoluteString }
        expectEqual(u("vpn.example.com"), "https://vpn.example.com/rest/GetUserlogin?tls-cryptv2=1&action=import")
        expectEqual(u("https://vpn.example.com:943/"), "https://vpn.example.com:943/rest/GetUserlogin?tls-cryptv2=1&action=import")
        expectEqual(u("vpn.example.com", true), "https://vpn.example.com/rest/GetAutologin?tls-cryptv2=1&action=import")
        expectEqual(u("http://vpn.example.com"), "https://vpn.example.com/rest/GetUserlogin?tls-cryptv2=1&action=import")
        expectEqual(u("  vpn.example.com  "), "https://vpn.example.com/rest/GetUserlogin?tls-cryptv2=1&action=import")
        expectEqual(u(""), nil)
        expectEqual(u("bad host/"), nil)
    }
    test("ASI-02", "plain URL") {
        func u(_ s: String) -> String? { ProfileDownloader.requestURL(.url(s))?.absoluteString }
        expectEqual(u("https://x.example.com/p.ovpn"), "https://x.example.com/p.ovpn")
        expectEqual(u("http://x.example.com/p.ovpn"), "https://x.example.com/p.ovpn")
        expectEqual(u("x.example.com/a/p.ovpn?k=1"), "https://x.example.com/a/p.ovpn?k=1")
        expectEqual(u(""), nil)
        expectEqual(u("ftp://x/p"), nil)
    }
    test("ASI-03", "profile name") {
        let h = FakeHTTP()
        h.responses = [ok(disposition: "attachment; filename=\"client-office.ovpn\"")]
        guard case .success(let p)? = download(h, .accessServer(host: "vpn.example.com", autologin: false)) else { return expect(false) }
        expectEqual(p.name, "client-office")
        expectEqual(p.text, profileText)
        expectEqual(h.requests.first?.username, "alice")
        expectEqual(h.requests.first?.password, "pw")
        h.responses = [ok()]
        if case .success(let q)? = download(h, .accessServer(host: "https://vpn.example.com:943", autologin: false)) {
            expectEqual(q.name, "vpn.example.com")
        } else { expect(false) }
        h.responses = [ok()]
        if case .success(let r)? = download(h, .url("https://x.example.com/dl/work.ovpn")) {
            expectEqual(r.name, "work")
        } else { expect(false) }
        h.responses = [ok(disposition: "attachment; filename=\"../../evil.ovpn\"")]
        if case .success(let e)? = download(h, .url("https://x.example.com/p.ovpn")) {
            expectEqual(e.name, "evil", "no path in the name")
        } else { expect(false) }
    }
    test("ASI-08", "a downloaded profile: bounded size, a plain visible name") {
        let h = FakeHTTP()
        h.responses = [ok(profileText + "# " + String(repeating: "x", count: ProfileDownloader.maxBytes) + "\n")]
        if case .failure(let e)? = download(h, .url("https://x.example.com/p.ovpn")) {
            expect(e.description.contains("large"), e.description)
        } else { expect(false, "a huge body is refused") }
        for (disp, want) in [(".hidden.ovpn", "hidden"), ("a:b.ovpn", "a_b"), ("...ovpn", "x.example.com"),
                             (String(repeating: "n", count: 100) + ".ovpn", String(repeating: "n", count: 64))] {
            h.responses = [ok(disposition: "attachment; filename=\"\(disp)\"")]
            if case .success(let r)? = download(h, .url("https://x.example.com/")) {
                expectEqual(r.name, want, disp)
            } else { expect(false, disp) }
        }
    }
    test("ASI-04", "dynamic challenge on 401") {
        let h = FakeHTTP()
        let crv = "<Error><Type>Authorization Required</Type><Message>CRV1:R,E:sid42:YWxpY2U=:Enter OTP</Message></Error>"
        h.responses = [.success(HTTPResponse(status: 401, body: Data(crv.utf8), contentDisposition: nil)), ok()]
        var asked: DynamicChallenge?
        let r = download(h, .accessServer(host: "vpn.example.com", autologin: false), asked: { asked = $0 })
        expectEqual(asked?.text, "Enter OTP")
        expectEqual(h.requests.count, 2)
        expectEqual(h.requests.last?.username, "alice")
        expectEqual(h.requests.last?.password, "CRV1::sid42::123")
        if case .success = r {} else { expect(false, "\(String(describing: r))") }
    }
    test("ASI-05", "errors") {
        let h = FakeHTTP()
        h.responses = [.success(HTTPResponse(status: 401, body: Data("<Error><Message>nope</Message></Error>".utf8), contentDisposition: nil))]
        if case .failure(let e)? = download(h, .accessServer(host: "a.example.com", autologin: false)) {
            expect(e.description.contains("username or password"), e.description)
        } else { expect(false) }
        h.responses = [.success(HTTPResponse(status: 404, body: Data(), contentDisposition: nil))]
        if case .failure(let e)? = download(h, .url("https://a.example.com/p")) {
            expect(e.description.contains("HTTP 404"), e.description)
        } else { expect(false) }
        h.responses = [.failure(ProfileError("The Internet connection appears to be offline."))]
        if case .failure(let e)? = download(h, .url("https://a.example.com/p")) {
            expect(e.description.contains("offline"), e.description)
        } else { expect(false) }
        if case .failure(let e)? = download(h, .url("")) {
            expect(e.description.contains("address"), e.description)
        } else { expect(false) }
    }
    test("ASI-06", "not a profile") {
        let h = FakeHTTP()
        h.responses = [ok("<html><body>Login</body></html>")]
        if case .failure(let e)? = download(h, .url("https://a.example.com/p")) {
            expect(e.description.contains("not an OpenVPN profile"), e.description)
        } else { expect(false) }
    }
    test("ASI-07", "challenge cancelled") {
        let h = FakeHTTP()
        let crv = "<Error><Message>CRV1:R:sid:YQ==:OTP</Message></Error>"
        h.responses = [.success(HTTPResponse(status: 401, body: Data(crv.utf8), contentDisposition: nil))]
        let r = download(h, .accessServer(host: "a.example.com", autologin: false), challenge: nil)
        expect(r == nil, "no result: cancelled quietly")
        expectEqual(h.requests.count, 1)
    }
}

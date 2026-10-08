import Foundation
import MugVPNCore

public struct HTTPResponse: Sendable {
    public var status: Int
    public var body: Data
    public var contentDisposition: String?
    public init(status: Int, body: Data, contentDisposition: String?) {
        self.status = status
        self.body = body
        self.contentDisposition = contentDisposition
    }
}

/// GET with basic authentication (URLSession in the app, a fake in tests).
public protocol HTTPFetcher: AnyObject {
    func get(_ url: URL, username: String, password: String, completion: @escaping (Result<HTTPResponse, Error>) -> Void)
}

public enum ImportSource: Equatable, Sendable {
    /// An OpenVPN Access Server: its REST profile download.
    case accessServer(host: String, autologin: Bool)
    case url(String)
}

public struct DownloadedProfile: Equatable, Sendable {
    public var name: String
    public var text: String
}

/// Downloads a profile from an Access Server or a URL, answering the
/// server's dynamic challenge.
public final class ProfileDownloader {
    private let http: HTTPFetcher

    public init(http: HTTPFetcher) { self.http = http }

    public static func requestURL(_ source: ImportSource) -> URL? {
        switch source {
        case .accessServer(let host, let autologin):
            guard var c = components(host) else { return nil }
            c.path = "/rest/\(autologin ? "GetAutologin" : "GetUserlogin")"
            c.query = "tls-cryptv2=1&action=import"
            return c.url
        case .url(let s):
            return components(s)?.url
        }
    }

    /// Always https: a profile carries keys.
    static func components(_ input: String) -> URLComponents? {
        var s = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { return nil }
        if s.lowercased().hasPrefix("http://") { s = "https://" + s.dropFirst(7) }
        if !s.contains("://") { s = "https://" + s }
        guard var c = URLComponents(string: s), c.scheme?.lowercased() == "https",
              let host = c.host, !host.isEmpty, !host.contains(" ") else { return nil }
        c.scheme = "https"
        return c
    }

    /// A profile with its keys inline is a few KB.
    public static let maxBytes = 1 << 20

    /// `completion` is not called when the user cancels a challenge.
    public func download(_ source: ImportSource, username: String, password: String,
                         askChallenge: @escaping (DynamicChallenge, @escaping (String?) -> Void) -> Void,
                         completion: @escaping (Result<DownloadedProfile, ProfileError>) -> Void) {
        guard let url = ProfileDownloader.requestURL(source) else {
            return completion(.failure(ProfileError("that is not a server address or https URL")))
        }
        http.get(url, username: username, password: password) { [self] result in
            switch result {
            case .failure(let e):
                completion(.failure(ProfileError("\(e)")))
            case .success(let r) where r.status == 200:
                guard r.body.count <= ProfileDownloader.maxBytes else {
                    return completion(.failure(ProfileError("the profile the server sent is too large")))
                }
                let text = String(decoding: r.body, as: UTF8.self)
                guard let d = try? ConfigParser.parse(text), d.contains(where: { $0.name == "remote" || $0.name == "client" }) else {
                    return completion(.failure(ProfileError("the server sent something that is not an OpenVPN profile")))
                }
                completion(.success(DownloadedProfile(name: name(r.contentDisposition, source, url), text: text)))
            case .success(let r) where r.status == 401:
                let body = String(decoding: r.body, as: UTF8.self)
                if let start = body.range(of: "<Message>CRV1:"), let end = body.range(of: "</Message>", range: start.upperBound..<body.endIndex),
                   let ch = ManagementEvent.parseCRV1(String(body[start.upperBound..<end.lowerBound])) {
                    askChallenge(ch) { response in
                        guard let response else { return }
                        self.download(source, username: username, password: "CRV1::\(ch.stateID)::\(response)",
                                      askChallenge: askChallenge, completion: completion)
                    }
                } else {
                    completion(.failure(ProfileError("the server did not accept the username or password")))
                }
            case .success(let r):
                completion(.failure(ProfileError("the server answered HTTP \(r.status)")))
            }
        }
    }

    /// No leading dots (a hidden folder), no separators, at most 64 characters.
    /// "name.ovpn" -> "name", the same on every macOS (Foundation's deletingPathExtension
    /// treats names such as "...ovpn" differently from one version to the next).
    static func withoutExtension(_ s: String) -> String {
        guard let dot = s.lastIndex(of: "."), dot != s.startIndex else { return s }
        return String(s[..<dot])
    }

    /// A path as it may be shown: no line breaks, control or text-direction characters.
    public static func visible(_ s: String) -> String {
        let odd = CharacterSet.controlCharacters.union(.newlines)
            .union(CharacterSet(charactersIn: "\u{200E}\u{200F}\u{202A}\u{202B}\u{202C}\u{202D}\u{202E}\u{2066}\u{2067}\u{2068}\u{2069}"))
        return String(String.UnicodeScalarView(s.unicodeScalars.map { odd.contains($0) ? "?" : $0 }))
    }

    public static func plainName(_ s: String) -> String {
        let odd = CharacterSet.controlCharacters.union(.newlines).union(CharacterSet(charactersIn: "/:\\"))
            .union(CharacterSet(charactersIn: "\u{200E}\u{200F}\u{202A}\u{202B}\u{202C}\u{202D}\u{202E}\u{2066}\u{2067}\u{2068}\u{2069}"))
        var n = String(String.UnicodeScalarView(s.unicodeScalars.map { odd.contains($0) ? "_" : $0 }))
        while n.hasPrefix(".") { n.removeFirst() }
        return String(n.trimmingCharacters(in: .whitespaces).prefix(64))
    }

    private func name(_ disposition: String?, _ source: ImportSource, _ url: URL) -> String {
        if let d = disposition, let r = d.range(of: "filename=") {
            let raw = d[r.upperBound...].split(separator: ";")[0].trimmingCharacters(in: CharacterSet(charactersIn: "\" "))
            let base = ProfileDownloader.plainName(ProfileDownloader.withoutExtension((raw as NSString).lastPathComponent))
            if !base.isEmpty { return base }
        }
        switch source {
        case .accessServer: return url.host ?? "profile"
        case .url:
            let raw = url.lastPathComponent == "/" ? "/" : ProfileDownloader.withoutExtension(url.lastPathComponent)
            let base = raw == "/" ? "" : ProfileDownloader.plainName(raw)
            return base.isEmpty ? (url.host ?? "profile") : base
        }
    }
}

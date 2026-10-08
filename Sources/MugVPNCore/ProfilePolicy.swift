import Foundation

/// What the root helper lets a user's profile do.
///
/// openvpn runs as root, so a profile is a request to run code as root. A
/// user profile may only use directives on the allowlist below; everything
/// that runs programs (`up`, `plugin`, `tls-verify`...), writes files (`log`,
/// `status`, `writepid`...), changes the process (`cd`, `chroot`, `daemon`) or
/// talks to management (the helper sets that up itself) is refused. Files the
/// profile names travel inside the bundle and are rewritten to the copies in
/// the run directory, so openvpn never opens a path the user picked.
public enum ProfilePolicy {
    public struct Violation: Error, Equatable, CustomStringConvertible {
        public var line: Int
        public var directive: String
        public var reason: String
        public var description: String { "line \(line): \(directive): \(reason)" }
    }

    public struct Result: Sendable {
        /// The cleaned config to hand to openvpn.
        public var directives: [ConfigDirective]
        /// Bundle file keys the config uses, in the order they appear.
        public var files: [String]
        /// Directives dropped without harm (e.g. `ignore-unknown-option`).
        public var dropped: [String]
        /// For each bundle file key: the directives that name it (what it must hold, for each).
        public var fileKinds: [String: [String]] = [:]
    }

    struct FileUse { var key: String; var kind: String }

    /// Directives that take no file and are safe as given.
    static let plain: Set<String> = [
        "client", "pull", "tls-client", "nobind", "float", "persist-key", "persist-tun",
        "persist-remote-ip", "persist-local-ip", "proto", "proto-force", "remote",
        "remote-random", "remote-random-hostname", "resolv-retry", "bind", "rport",
        "local", "connect-retry", "connect-retry-max", "connect-timeout", "server-poll-timeout",
        "key-direction", "remote-cert-tls", "remote-cert-ku", "remote-cert-eku", "verify-x509-name",
        "x509-username-field", "x509-track", "verify-hash", "peer-fingerprint", "tls-version-min",
        "tls-version-max", "tls-cipher", "tls-ciphersuites", "tls-groups", "tls-cert-profile",
        "ecdh-curve", "tls-timeout", "hand-window", "tran-window", "reneg-sec", "reneg-bytes",
        "reneg-pkts", "tls-exit", "cipher", "data-ciphers", "data-ciphers-fallback", "ncp-ciphers",
        "auth", "comp-lzo", "compress", "allow-compression", "verb", "mute", "mute-replay-warnings",
        "auth-retry", "auth-nocache", "static-challenge", "pull-filter", "route-ipv6",
        "route-metric", "route-delay", "route-nopull",
        "route-noexec", "ifconfig-noexec", "redirect-private", "block-ipv6",
        "dhcp-option", "dns", "ifconfig", "ifconfig-ipv6", "ifconfig-nowarn", "topology", "tun-mtu",
        "tun-mtu-extra", "tun-mtu-max", "mssfix", "fragment", "link-mtu", "mtu-disc", "mtu-test",
        "sndbuf", "rcvbuf", "keepalive", "ping", "ping-restart", "ping-exit",
        "ping-timer-rem", "inactive", "session-timeout", "explicit-exit-notify", "http-proxy-option",
        "socks-proxy-retry", "setenv-safe", "push-peer-info", "replay-window", "fast-io",
        "multihomed", "tcp-nodelay",
        "client-nat", "auth-token-user", "opt-verify",
        "echo", "route-table", "max-routes", "remap-usr1", "disable-dco", "disable-occ",
        "tls-exit", "server-poll-timeout",
        // Accepted and ignored by openvpn on macOS.
        "route-method",
    ]

    /// Options of other systems that profiles from Windows or Linux carry. openvpn
    /// on macOS does not know them and would stop: they are left out.
    static let otherSystems: Set<String> = [
        "block-outside-dns", "register-dns", "ip-win32", "tap-sleep", "dhcp-release", "dhcp-renew",
        "dhcp-pre-release", "windows-driver", "show-net-up", "txqueuelen",
    ]

    /// `setenv` names openvpn itself reads. Other variables would only be
    /// passed to the programs root openvpn runs (route, ifconfig); the app
    /// takes them from the profile for the user's own scripts.
    static func openvpnReads(_ name: String) -> Bool {
        name.hasPrefix("UV_") || ["REMOTE_RANDOM_HOSTNAME", "PUSH_PEER_INFO", "SERVER_POLL_TIMEOUT"].contains(name)
    }

    /// Directives whose parameters at these positions (1-based) are files.
    static let fileArgs: [String: [Int]] = [
        "ca": [1], "cert": [1], "key": [1], "extra-certs": [1], "pkcs12": [1], "dh": [1],
        "tls-auth": [1], "tls-crypt": [1], "tls-crypt-v2": [1], "secret": [1], "crl-verify": [1],
        "askpass": [1], "auth-user-pass": [1], "http-proxy-user-pass": [1],
    ]

    /// Directives whose inline block holds file content rather than options.
    static let inlineFiles: Set<String> = [
        "ca", "cert", "key", "extra-certs", "pkcs12", "dh", "tls-auth", "tls-crypt", "tls-crypt-v2",
        "secret", "crl-verify", "auth-user-pass", "http-proxy-user-pass", "peer-fingerprint",
    ]

    static let forbidden: [String: String] = [
        "up": "runs a program as root", "down": "runs a program as root",
        "route-up": "runs a program as root", "route-pre-down": "runs a program as root",
        "ipchange": "runs a program as root", "tls-verify": "runs a program as root",
        "learn-address": "runs a program as root", "client-connect": "runs a program as root",
        "client-disconnect": "runs a program as root",
        "auth-user-pass-verify": "runs a program as root", "dns-updown": "runs a program as root",
        "iproute": "runs a program as root", "plugin": "loads code into openvpn",
        "engine": "loads code into openvpn", "providers": "loads code into openvpn",
        "pkcs11-providers": "loads code into openvpn", "config": "reads another file",
        "log": "writes files as root", "log-append": "writes files as root",
        "status": "writes files as root", "writepid": "writes files as root",
        "tls-export-cert": "writes files as root", "tmp-dir": "writes files as root",
        "cd": "changes the working directory", "chroot": "changes the root directory",
        "daemon": "detaches from the helper", "syslog": "detaches logging from the helper",
        "capath": "reads a directory", "mode": "server mode", "server": "server mode",
        "server-bridge": "server mode", "dev-node": "names a device node",
        "user": "MugVPN does not drop privileges (the DNS script would trust a file the unprivileged openvpn wrote)",
        "group": "MugVPN does not drop privileges (the DNS script would trust a file the unprivileged openvpn wrote)",
        "mlock": "locks memory as root",
        "suppress-timestamps": "MugVPN reads openvpn's log with its timestamps",
        "machine-readable-output": "MugVPN reads openvpn's log with its timestamps",
    ]

    /// Validate `directives` from a user's profile. `bundleFiles` are the file
    /// names the app sent along with the config.
    public static func check(_ directives: [ConfigDirective], bundleFiles: Set<String>) throws -> Result {
        var out: [ConfigDirective] = []
        var files: [String] = []
        var dropped: [String] = []
        var uses: [FileUse] = []
        try check(directives, bundleFiles: bundleFiles, out: &out, files: &uses, dropped: &dropped, nested: false)
        files = uses.map(\.key).reduce(into: [String]()) { if !$0.contains($1) { $0.append($1) } }
        var kinds: [String: [String]] = [:]
        for u in uses where !(kinds[u.key] ?? []).contains(u.kind) { kinds[u.key, default: []].append(u.kind) }
        var r = Result(directives: out, files: files, dropped: dropped)
        r.fileKinds = kinds
        return r

    }

    private static func check(_ directives: [ConfigDirective], bundleFiles: Set<String>,
                              out: inout [ConfigDirective], files: inout [FileUse],
                              dropped: inout [String], nested: Bool) throws {
        for var d in directives {
            func refuse(_ reason: String) -> Violation {
                Violation(line: d.line, directive: d.name, reason: reason)
            }
            if d.name.hasPrefix("management") {
                throw refuse("the management interface is set up by MugVPN")
            }
            if let reason = forbidden[d.name] {
                throw refuse(reason)
            }
            // dh: a server's file; clients have no use for it.
            if d.name == "ignore-unknown-option" || d.name == "dh" || otherSystems.contains(d.name) {
                dropped.append(d.name)
                continue
            }
            if d.name == "setenv", d.args.first == "opt" {
                // "setenv opt X ..." makes openvpn apply X if it knows it. Treat
                // it as X; drop it only if X is unknown to us.
                guard d.args.count >= 2 else { throw refuse("setenv opt without an option") }
                let inner = ConfigDirective(name: d.args[1], args: Array(d.args.dropFirst(2)), line: d.line)
                if isKnown(inner.name) {
                    try check([inner], bundleFiles: bundleFiles, out: &out, files: &files,
                              dropped: &dropped, nested: nested)
                } else {
                    dropped.append("setenv opt " + inner.name)
                }
                continue
            }

            if let inline = d.inline {
                if d.name == "connection" {
                    guard !nested else { throw refuse("nested connection block") }
                    var inner: [ConfigDirective] = []
                    let parsed: [ConfigDirective]
                    do { parsed = try ConfigParser.parse(inline) } catch let e as ConfigParseError {
                        throw refuse("in connection block: \(e.message)")
                    }
                    try check(parsed, bundleFiles: bundleFiles, out: &inner, files: &files,
                              dropped: &dropped, nested: true)
                    do { d.inline = try ConfigParser.serializeForOpenVPN(inner) } catch let e as ConfigParseError {
                        throw refuse("in connection block: \(e.message)")
                    }
                    out.append(d)
                    continue
                }
                guard inlineFiles.contains(d.name) else { throw refuse("not allowed as an inline block") }
                if let problem = contentProblem(d.name, Data(inline.utf8), inline: true) { throw refuse(problem) }
                out.append(d)
                continue
            }

            switch d.name {
            case "dev":
                guard d.args.count == 1, d.args[0] == "tun" || isUtun(d.args[0]) else {
                    throw refuse("only tun devices are supported on macOS")
                }
            case "script-security":
                guard d.args.count >= 1, let level = Int(d.args[0]), level <= 1 else {
                    throw refuse("script-security above 1 lets the profile run programs")
                }
            case "lport", "port":
                // Port 0 lets the system choose; below 1024 a root openvpn would take a privileged port.
                guard d.args.count == 1, let n = Int(d.args[0]), n == 0 || (1024...65535).contains(n) else {
                    throw refuse("ports below 1024 are not allowed")
                }
            case "proto":
                guard d.args.count == 1, !d.args[0].lowercased().hasSuffix("-server") else {
                    throw refuse("MugVPN connects to servers; it does not listen")
                }
            case "nice":
                guard d.args.count == 1, let n = Int(d.args[0]), n >= 0 else {
                    throw refuse("a root openvpn may not raise its own priority")
                }
            case "setenv":
                guard d.args.count >= 1, d.args.count <= 2 else { throw refuse("bad setenv") }
                guard openvpnReads(d.args[0]) else {
                    dropped.append("setenv " + d.args[0])
                    continue
                }
            case "route":
                // Through the tunnel, or the user's own gateway; never another host on the LAN,
                // which would then get every user's traffic for that network.
                guard !d.args.isEmpty else { throw refuse("bad route") }
                if d.args.count >= 3, !["vpn_gateway", "default", "net_gateway"].contains(d.args[2]) {
                    throw refuse("the gateway must be vpn_gateway or net_gateway")
                }
            case "cipher", "data-ciphers", "data-ciphers-fallback", "ncp-ciphers", "auth":
                guard !d.args.joined(separator: ":").lowercased().split(separator: ":").contains("none") else {
                    throw refuse("a tunnel without encryption or authentication")
                }
            case "tls-version-min":
                guard let v = d.args.first, v == "1.2" || v == "1.3" else { throw refuse("TLS below 1.2") }
            case "tls-cert-profile":
                guard d.args.first != "insecure", d.args.first != "legacy" else { throw refuse("a weak certificate profile") }
            case "tls-cipher", "tls-ciphersuites", "tls-groups":
                guard !d.args.joined().uppercased().contains("SECLEVEL=0") else { throw refuse("OpenSSL security level 0") }
            case "route-gateway":
                // Every route without its own gateway would go to it: only the server's (dhcp).
                guard d.args == ["dhcp"] else { throw refuse("route-gateway may only be dhcp") }
            case "route-ipv6":
                guard (1...2).contains(d.args.count), d.args.count == 1 || d.args[1] == "vpn_gateway" else {
                    throw refuse("an IPv6 route goes through the tunnel")
                }
            case "allow-compression":
                guard let v = d.args.first, v == "no" || v == "asym" else {
                    throw refuse("compressing what is sent leaks data (VORACLE)")
                }
            case "dev-type":
                guard d.args == ["tun"] else { throw refuse("only tun devices are supported on macOS") }
            case "redirect-gateway":
                // Without def1 openvpn deletes the system's default route; if it then
                // dies, the Mac is left without one.
                if !d.args.contains("def1") { d.args.append("def1") }
            case "http-proxy":
                guard (2...4).contains(d.args.count) else { throw refuse("bad http-proxy") }
                if d.args.count >= 3, !["stdin", "auto", "auto-nct"].contains(d.args[2]) {
                    d.args[2] = try fileRef(d.args[2], d, bundleFiles, &files)
                }
            case "socks-proxy":
                guard (1...3).contains(d.args.count) else { throw refuse("bad socks-proxy") }
                if d.args.count == 3 { d.args[2] = try fileRef(d.args[2], d, bundleFiles, &files) }
            case "crl-verify":
                guard d.args.count == 1 else { throw refuse("crl-verify directories are not supported") }
                d.args[0] = try fileRef(d.args[0], d, bundleFiles, &files)
            case "auth-user-pass", "askpass", "http-proxy-user-pass":
                // Without a file openvpn asks over management; with one, the file comes along.
                if let f = d.args.first { d.args[0] = try fileRef(f, d, bundleFiles, &files) }
            default:
                if let positions = fileArgs[d.name] {
                    for p in positions {
                        guard p <= d.args.count else { throw refuse("missing file name") }
                        // "[inline]" refers to an inline block of the same name.
                        if d.args[p - 1] != "[inline]" {
                            d.args[p - 1] = try fileRef(d.args[p - 1], d, bundleFiles, &files)
                        }
                    }
                } else if !plain.contains(d.name) {
                    throw refuse("not supported in user profiles")
                }
            }
            out.append(d)
        }
    }

    static func isKnown(_ name: String) -> Bool {
        plain.contains(name) || fileArgs[name] != nil || forbidden[name] != nil
            || otherSystems.contains(name)
            || ["dev", "dev-type", "redirect-gateway", "route", "route-gateway", "route-ipv6", "tls-cipher",
                "tls-ciphersuites", "tls-groups", "script-security", "setenv", "http-proxy", "socks-proxy", "connection", "lport", "port",
                "proto", "nice"].contains(name) || name.hasPrefix("management")
    }

    static func isUtun(_ s: String) -> Bool {
        s.hasPrefix("utun") && s.count > 4 && s.count <= 8 && s.dropFirst(4).allSatisfy { ("0"..."9").contains($0) }
    }

    /// Files a profile names (as written in it), for the app to read and send
    /// along. Inline blocks and "[inline]" are not files.
    public static func referencedFiles(_ directives: [ConfigDirective]) -> [String] {
        var names: [String] = []
        for d in directives {
            if d.name == "connection", let inline = d.inline,
               let inner = try? ConfigParser.parse(inline) {
                names += referencedFiles(inner)
                continue
            }
            guard d.inline == nil else { continue }
            if d.name == "setenv", d.args.first == "opt", d.args.count >= 2 {
                names += referencedFiles([ConfigDirective(name: d.args[1], args: Array(d.args.dropFirst(2)))])
                continue
            }
            switch d.name {
            case "http-proxy":
                if d.args.count >= 3, !["stdin", "auto", "auto-nct"].contains(d.args[2]) { names.append(d.args[2]) }
            case "socks-proxy":
                if d.args.count == 3 { names.append(d.args[2]) }
            default:
                for p in fileArgs[d.name] ?? [] where p <= d.args.count && d.args[p - 1] != "[inline]" {
                    names.append(d.args[p - 1])
                }
            }
        }
        var seen = Set<String>()
        return names.filter { seen.insert($0).inserted }
    }

    /// The name the run directory will use for a bundle file: its position.
    public static func runName(forIndex i: Int) -> String { "file\(i)" }

    private static func fileRef(_ name: String, _ d: ConfigDirective, _ bundleFiles: Set<String>,
                                _ files: inout [FileUse]) throws -> String {
        guard bundleFiles.contains(name) else {
            throw Violation(line: d.line, directive: d.name, reason: "file \(name) was not sent with the profile")
        }
        // One run file per key; every directive naming it is remembered (each kind is checked).
        let keys = files.reduce(into: [String]()) { if !$0.contains($1.key) { $0.append($1.key) } }
        files.append(FileUse(key: name, kind: d.name))
        if let i = keys.firstIndex(of: name) { return runName(forIndex: i) }
        return runName(forIndex: keys.count)
    }
}

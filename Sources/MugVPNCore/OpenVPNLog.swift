import Foundation

/// What a connection changed in the system, read back from openvpn's own log
/// (written as root into the run directory). The helper needs it when openvpn
/// dies without tearing down: then nobody else removes the routes it added
/// outside the tunnel or puts the DNS configuration back.
///
/// Every value is checked (device name, IP addresses), so a log line a server
/// managed to shape cannot make the helper run anything else.
public struct OpenVPNLogFacts: Equatable, Sendable {
    public var device: String?
    /// `route add` invocations that worked, as the arguments after "add":
    /// what cleanup may delete.
    public var routes: [[String]] = []
    /// Every route asked for, worked or not: what conflict checks look at.
    public var requestedRoutes: [[String]] = []
    /// Default routes openvpn deleted (`redirect-gateway` without def1), as `route` arguments.
    public var deletedDefaults: [[String]] = []

    public init(device: String? = nil, routes: [[String]] = []) {
        self.device = device
        self.routes = routes
        self.requestedRoutes = routes
    }

    public static func parse(_ log: String) -> OpenVPNLogFacts {
        var f = Follower()
        f.feed(Data(log.utf8))
        f.finish()
        return f.facts
    }

    /// Reads a growing log piece by piece (the helper looks again every few
    /// seconds without reading it all again).
    public struct Follower: Sendable {
        public private(set) var facts = OpenVPNLogFacts()
        /// Bytes read so far.
        public private(set) var offset: UInt64 = 0
        private var lastAdd: [String]?
        private var partial = Data()

        public init() {}

        public mutating func feed(_ data: Data) {
            offset += UInt64(data.count)
            partial.append(data)
            while let nl = partial.firstIndex(of: 0x0A) {
                let line = String(decoding: partial[partial.startIndex..<nl], as: UTF8.self)
                partial.removeSubrange(partial.startIndex...nl)
                consume(line)
            }
        }

        /// The last line, if it has no newline yet.
        public mutating func finish() {
            if !partial.isEmpty { consume(String(decoding: partial, as: UTF8.self)) }
            partial = Data()
        }

        private mutating func consume(_ line: String) {
            // "2026-10-06 05:46:44 <message>": the message starts after the timestamp.
            guard let msg = OpenVPNLogFacts.message(of: line) else { return }
            if msg.hasPrefix("Opened utun device ") {
                let dev = String(msg.dropFirst("Opened utun device ".count))
                if OpenVPNLogFacts.isUtun(dev) { facts.device = dev }
            } else if msg.hasPrefix("/sbin/route add ") {
                let args = msg.dropFirst("/sbin/route add ".count).split(separator: " ").map(String.init)
                lastAdd = OpenVPNLogFacts.validRoute(args)
                if let r = lastAdd {
                    facts.routes.append(r)
                    facts.requestedRoutes.append(r)
                }
            } else if msg.hasPrefix("MugVPN: route add ") {
                // openvpn without root (privilege separation) logs what it asks the helper for.
                lastAdd = OpenVPNLogFacts.privsepRoute(msg.dropFirst("MugVPN: route add ".count).split(separator: " ").map(String.init))
                if let r = lastAdd {
                    facts.routes.append(r)
                    facts.requestedRoutes.append(r)
                }
            } else if msg.hasPrefix("MugVPN: the helper refused route"), let r = lastAdd {
                if facts.routes.last == r { facts.routes.removeLast() }
                lastAdd = nil
            } else if msg.hasPrefix("/sbin/route delete ") {
                // redirect-gateway without def1: openvpn takes the default route away (put back after a crash).
                let args = msg.dropFirst("/sbin/route delete ".count).split(separator: " ").map(String.init)
                if args.count == 4, args[0] == "-net", args[1] == "0.0.0.0", args[3] == "0.0.0.0",
                   OpenVPNLogFacts.validRoute(args) != nil, !facts.deletedDefaults.contains(args) {
                    facts.deletedDefaults.append(args)
                }
                lastAdd = nil
            } else if msg.hasPrefix("ERROR: OS X route add") || msg.hasPrefix("ERROR: MacOS X route add -inet6"),
                      msg.contains("command failed"), let r = lastAdd {
                // The add failed (the route already existed): it is not ours to delete.
                if facts.routes.last == r { facts.routes.removeLast() }
                lastAdd = nil
            } else if msg.hasPrefix("/") {
                lastAdd = nil
            }
        }
    }

    static func message(of line: String) -> String? {
        // openvpn's timestamp: "YYYY-MM-DD HH:MM:SS "
        guard line.count > 20 else { return nil }
        let ts = line.prefix(20)
        let shape = Array(ts)
        guard shape[4] == "-", shape[7] == "-", shape[10] == " ", shape[13] == ":", shape[16] == ":",
              shape[19] == " " else { return nil }
        return String(line.dropFirst(20))
    }

    static func isUtun(_ s: String) -> Bool {
        s.hasPrefix("utun") && s.count > 4 && s.count <= 8 && s.dropFirst(4).allSatisfy(\.isASCII) && s.dropFirst(4).allSatisfy(\.isNumber)
    }

    /// Accept exactly the forms openvpn 2.7 writes on macOS (route.c, TARGET_DARWIN):
    ///   -net <dst> <gw> <mask>
    ///   -cloning -net <dst> -netmask <mask> -interface <if>     (on-link)
    ///   -inet6 <dst> -prefixlen <n> <gw>
    ///   -inet6 <dst> -prefixlen <n> -iface <utun>
    static func validRoute(_ a: [String]) -> [String]? {
        if a.count == 4, a[0] == "-net", isIPv4(a[1]), isIPv4(a[2]), isIPv4(a[3]) { return a }
        if a.count == 7, a[0] == "-cloning", a[1] == "-net", isIPv4(a[2]), a[3] == "-netmask", isIPv4(a[4]),
           a[5] == "-interface", isInterface(a[6]) { return a }
        if a.count == 5, a[0] == "-inet6", isIPv6(a[1]), a[2] == "-prefixlen", isPrefixLength(a[3]), isIPv6(a[4]) { return a }
        if a.count == 6, a[0] == "-inet6", isIPv6(a[1]), a[2] == "-prefixlen", isPrefixLength(a[3]), a[4] == "-iface",
           isUtun(a[5]) { return a }
        return nil
    }

    /// A privsep request ("net mask gateway [dev iface]", "-inet6 net/bits dev") in the
    /// classic `route add` form the rest of the facts use.
    static func privsepRoute(_ a: [String]) -> [String]? {
        if a.count == 3, a[0] == "-inet6" {
            let p = a[1].split(separator: "/").map(String.init)
            guard p.count == 2 else { return nil }
            return validRoute(["-inet6", p[0], "-prefixlen", p[1], "-iface", a[2]])
        }
        if a.count == 3 { return validRoute(["-net", a[0], a[2], a[1]]) }
        if a.count == 5, a[3] == "dev" { return validRoute(["-cloning", "-net", a[0], "-netmask", a[1], "-interface", a[4]]) }
        return nil
    }

    /// `route delete` arguments for a route added with `args`.
    public static func deleteArguments(_ args: [String]) -> [String] {
        args.first == "-cloning" ? Array(args.dropFirst()) : args
    }

    static func isPrefixLength(_ s: String) -> Bool {
        s.count <= 3 && s.allSatisfy(\.isASCII) && Int(s).map { (0...128).contains($0) } == true
    }

    /// A network interface name: letters then digits (en0, bridge100, utun5).
    static func isInterface(_ s: String) -> Bool {
        guard s.count <= 15, let i = s.firstIndex(where: \.isNumber), i != s.startIndex else { return false }
        return s[..<i].allSatisfy { $0.isASCII && $0.isLowercase } && s[i...].allSatisfy { $0.isASCII && $0.isNumber }
    }

    static func isIPv4(_ s: String) -> Bool {
        var a = in_addr()
        return s.count <= 15 && inet_pton(AF_INET, s, &a) == 1
    }

    static func isIPv6(_ s: String) -> Bool {
        var a = in6_addr()
        return s.count <= 45 && inet_pton(AF_INET6, s, &a) == 1
    }

    static func isIPv6Prefix(_ s: String) -> Bool {
        let parts = s.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let len = Int(parts[1]), (0...128).contains(len) else { return false }
        return isIPv6(String(parts[0]))
    }
}

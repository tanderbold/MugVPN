import Foundation

/// One IPv4 route of the system table.
public struct RouteEntry: Equatable, Sendable {
    public var network: UInt32
    public var prefix: Int
    public var gateway: String
    public var interface: String
    public var cidr: String {
        let n = network
        return "\(n >> 24).\((n >> 16) & 255).\((n >> 8) & 255).\(n & 255)/\(prefix)"
    }
}

/// Something that sends traffic around a tunnel that should carry all of it.
public enum LeakFinding: Equatable, Sendable {
    /// The tunnels do not hold both halves of the address space (0/1, 128/1).
    case defaultOutside
    /// A public network is routed through a physical interface, past the tunnel
    /// (a rogue DHCP server's classless routes, TunnelVision; or LocalNet).
    case bypass(String, String)
    /// A DNS server in use is reached outside the tunnel.
    case dnsOutside(String, String)
    /// Where a DNS server in use is reached could not be found out.
    case unverified(String)
    /// IPv6 has a default route outside the tunnels (and is not blocked).
    case ipv6Outside(String)
}

/// After a connection that takes all traffic comes up (and when the network
/// changes): does the system really send everything into a tunnel? Read-only:
/// the routing table and DNS as any user sees them.
public enum LeakCheck {
    /// `netstat -rn -f inet`, with its abbreviated destinations: `10.84/24`,
    /// `127` (a /8), `192.168.64` (a /24), `10.84.0.2` (a host), `default`.
    public static func routes(netstat: String) -> [RouteEntry] {
        var out: [RouteEntry] = []
        for line in netstat.components(separatedBy: "\n") {
            let f = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard f.count >= 4, let (net, prefix) = destination(f[0]) else { continue }
            out.append(RouteEntry(network: net, prefix: prefix, gateway: f[1], interface: f[3]))
        }
        return out
    }

    static func destination(_ s: String) -> (UInt32, Int)? {
        if s == "default" { return (0, 0) }
        let parts = s.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count <= 2 else { return nil }
        let octets = parts[0].split(separator: ".", omittingEmptySubsequences: false)
        guard (1...4).contains(octets.count) else { return nil }
        var net: UInt32 = 0
        for i in 0..<4 {
            guard i < octets.count else { net <<= 8; continue }
            guard let o = UInt32(octets[i]), o <= 255 else { return nil }
            net = net << 8 | o
        }
        let prefix: Int
        if parts.count == 2 {
            guard let p = Int(parts[1]), (0...32).contains(p) else { return nil }
            prefix = p
        } else {
            prefix = octets.count * 8
        }
        return (net, prefix)
    }

    /// The name servers of `scutil --dns`'s first resolver (the one for all names).
    public static func primaryDNS(scutil: String) -> [String] {
        var inFirst = false, out: [String] = []
        for line in scutil.components(separatedBy: "\n") {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("resolver #") { if inFirst { break }; inFirst = t == "resolver #1"; continue }
            if inFirst, t.hasPrefix("nameserver["), let r = t.range(of: ": ") { out.append(String(t[r.upperBound...])) }
        }
        return out
    }

    /// - tunnels: utun devices of connections that take all traffic.
    /// - dns: each DNS server in use with the interface the system reaches it through.
    /// - servers: the VPN servers' addresses (their own routes go around the tunnel by design).
    public static func findings(routes: [RouteEntry], tunnels: Set<String>, dns: [(String, String?)],
                                servers: [String]) -> [LeakFinding] {
        var out: [LeakFinding] = []
        let halves = routes.filter { $0.prefix == 1 && tunnels.contains($0.interface) }.map(\.network)
        if !(halves.contains(0) && halves.contains(0x8000_0000)) { out.append(.defaultOutside) }
        let serverNets = Set(servers.compactMap(parse))
        for r in routes where r.prefix >= 2 && !tunnels.contains(r.interface) && r.interface != "lo0"
            && isPublic(r.network, r.prefix) && !(r.prefix == 32 && serverNets.contains(r.network)) {
            out.append(.bypass(r.cidr, r.interface))
        }
        for (server, iface) in dns {
            if let a = parse(server), a >> 24 == 127 { continue }        // a local resolver
            if server == "::1" { continue }
            guard let iface else { out.append(.unverified(server)); continue }
            if !tunnels.contains(iface) && iface != "lo0" { out.append(.dnsOutside(server, iface)) }
        }
        return out
    }

    /// Interfaces of IPv6 default routes in `netstat -rn -f inet6`.
    public static func ipv6Defaults(netstat: String) -> [String] {
        netstat.components(separatedBy: "\n").compactMap { line in
            let f = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            return f.count >= 4 && f[0] == "default" ? f[3] : nil
        }
    }

    /// Public IPv6 networks (2000::/3) routed via a router outside the tunnels: an RA's
    /// route information, as TunnelVision does with DHCP. (On-link networks are the LAN.)
    public static func ipv6Bypass(netstat: String, tunnels: Set<String>) -> [LeakFinding] {
        netstat.components(separatedBy: "\n").compactMap { line in
            let f = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard f.count >= 4, f[0] != "default", f[0].contains("/"), !f[1].hasPrefix("link#"),
                  let first = f[0].first, first == "2" || first == "3",
                  !tunnels.contains(f[3]), f[3] != "lo0" else { return nil }
            return .bypass(f[0], f[3])
        }
    }

    public static func ipv6Findings(defaults: [String], tunnels: Set<String>, blocked: Bool) -> [LeakFinding] {
        guard !blocked else { return [] }
        return defaults.filter { !tunnels.contains($0) && $0 != "lo0" }.map { .ipv6Outside($0) }
    }

    /// The addresses openvpn connected to ("link remote: [AF_INET]x:port").
    public static func serverAddresses(log: String) -> [String] {
        var out: [String] = []
        for line in log.components(separatedBy: "\n") {
            guard let r = line.range(of: "link remote: [AF_INET]") ?? line.range(of: "link remote: [AF_INET6]") else { continue }
            let rest = line[r.upperBound...]
            let host = rest.split(separator: ":").dropLast().joined(separator: ":")
            if !host.isEmpty, !out.contains(host) { out.append(host) }
        }
        return out
    }

    static func parse(_ s: String) -> UInt32? {
        guard let (n, p) = destination(s), p == 32 else { return nil }
        return n
    }

    /// Not private, link-local, loopback, CGNAT, multicast or reserved.
    public static func isPublic(_ net: UInt32, _ prefix: Int) -> Bool {
        // Private, shared, link-local, loopback, multicast, reserved, and the special-use
        // ranges of RFC 6890 (IETF protocols, documentation, benchmarking).
        let reserved: [(UInt32, Int)] = [(0x0A00_0000, 8), (0xAC10_0000, 12), (0xC0A8_0000, 16), (0xA9FE_0000, 16),
                                         (0x7F00_0000, 8), (0x6440_0000, 10), (0xE000_0000, 4), (0xF000_0000, 4),
                                         (0, 8), (0xC000_0000, 24), (0xC000_0200, 24), (0xC612_0000, 15)]
        return !reserved.contains { (base, len) in
            prefix >= len && (net >> UInt32(32 - len)) == (base >> UInt32(32 - len))
        }
    }
}

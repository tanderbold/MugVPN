import Foundation
import MugVPNCore

/// Warnings when active tunnels get in each other's way (they are not
/// stopped: the user may want it so).
public enum NetworkConflict: Equatable, Sendable {
    case bothTakeDefaultRoute(String, String)
    /// Both route the same network (same prefix): which one gets the traffic is not clear.
    case overlappingRoutes(String, String, String)
    /// The narrow one routes networks inside the broad one's routes: those go to it (the more specific
    /// route wins), the rest of the broad one's as before. Usually meant so; said once per pair.
    case narrowerRoutes(broad: String, narrow: String, count: Int)
    /// The DNS script refused: another tunnel already redirects all DNS.
    case dnsTakenByAnother(String)
}

public enum NetworkConflicts {
    /// - tunnels: (profile name, facts from its log, the log text)
    public static func find(_ tunnels: [(String, OpenVPNLogFacts, String)]) -> [NetworkConflict] {
        var out: [NetworkConflict] = []
        // What each tunnel asked for: a route another tunnel already holds is the conflict itself.
        let nets = tunnels.map { t in (t.0, t.1.requestedRoutes.compactMap(IPv4Net.init(route:))) }
        let takesDefault = nets.filter { $0.1.contains { $0.prefix == 1 && ($0.address == 0 || $0.address == 0x8000_0000) } }.map(\.0)
        // IPv6 the same way: all of it (the global range), and overlaps of narrower routes.
        let nets6 = tunnels.map { t in (t.0, t.1.requestedRoutes.compactMap(IPv6Net.init(route:))) }
        let takesAll6 = nets6.filter { IPv6Net.coversGlobal($0.1) }.map(\.0)
        if takesDefault.count >= 2 {
            out.append(.bothTakeDefaultRoute(takesDefault[0], takesDefault[1]))
        } else if takesAll6.count >= 2 {
            out.append(.bothTakeDefaultRoute(takesAll6[0], takesAll6[1]))
        }
        // Per pair of connections, IPv4 and IPv6 together: one line for the same networks, one per
        // direction for narrower ones (however many routes: two real VPNs gave 26 lines before).
        for i in tunnels.indices {
            for j in tunnels.indices where j > i {
                var same: [String] = [], iInJ = 0, jInI = 0
                func look<N>(_ x: [N], _ y: [N], overlap: (N, N) -> N?, prefix: (N) -> Int, text: (N) -> String) {
                    for a in x {
                        for b in y {
                            guard let o = overlap(a, b) else { continue }
                            if prefix(a) == prefix(b) { if !same.contains(text(o)) { same.append(text(o)) } }
                            else if prefix(a) < prefix(b) { jInI += 1 } else { iInJ += 1 }
                        }
                    }
                }
                look(nets[i].1.filter { $0.prefix > 1 && $0.prefix < 32 }, nets[j].1.filter { $0.prefix > 1 && $0.prefix < 32 },
                     overlap: { $0.overlap($1) }, prefix: \.prefix, text: \.description)
                look(nets6[i].1.filter { $0.prefix > 7 && $0.prefix < 128 }, nets6[j].1.filter { $0.prefix > 7 && $0.prefix < 128 },
                     overlap: { $0.overlap($1) }, prefix: \.prefix, text: \.description)
                let (a, b) = (tunnels[i].0, tunnels[j].0)
                if !same.isEmpty {
                    let shown = same.prefix(3).joined(separator: ", ") + (same.count > 3 ? " (+\(same.count - 3))" : "")
                    out.append(.overlappingRoutes(a, b, shown))
                }
                if jInI > 0 { out.append(.narrowerRoutes(broad: a, narrow: b, count: jInI)) }
                if iInJ > 0 { out.append(.narrowerRoutes(broad: b, narrow: a, count: iInJ)) }
            }
        }
        for t in tunnels where t.2.contains("setting DNS failed, already redirecting")
            || t.2.contains("DNS for all names is already another tunnel's") {
            out.append(.dnsTakenByAnother(t.0))
        }
        return out
    }
}

struct IPv4Net: Equatable {
    var address: UInt32
    var prefix: Int

    /// From an openvpn route: ["-net", dst, gw, mask].
    init?(route r: [String]) {
        guard r.count == 4, r[0] == "-net", r[1] != "-inet6",
              let a = IPv4Net.parse(r[1]), let m = IPv4Net.parse(r[3]) else { return nil }
        let p = m.nonzeroBitCount
        guard m == (p == 0 ? 0 : UInt32.max << (32 - p)) else { return nil }
        address = a & m
        prefix = p
    }

    init(address: UInt32, prefix: Int) {
        self.address = address
        self.prefix = prefix
    }

    var mask: UInt32 { prefix == 0 ? 0 : UInt32.max << (32 - prefix) }

    /// The smaller of two nets when one contains the other.
    func overlap(_ o: IPv4Net) -> IPv4Net? {
        let m = prefix < o.prefix ? mask : o.mask
        guard address & m == o.address & m else { return nil }
        return prefix > o.prefix ? self : o
    }

    var description: String {
        "\(address >> 24).\(address >> 16 & 255).\(address >> 8 & 255).\(address & 255)/\(prefix)"
    }

    static func parse(_ s: String) -> UInt32? {
        let p = s.split(separator: ".").compactMap { UInt32($0) }
        guard p.count == 4, p.allSatisfy({ $0 < 256 }) else { return nil }
        return p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]
    }
}

struct IPv6Net: Equatable {
    var bytes: [UInt8]
    var prefix: Int

    /// From an openvpn route: ["-inet6", net, "-prefixlen", bits, gateway | "-iface", dev].
    init?(route r: [String]) {
        guard r.count >= 4, r[0] == "-inet6", r[2] == "-prefixlen", let p = Int(r[3]), (0...128).contains(p),
              let b = IPv6Net.parse(r[1]) else { return nil }
        self.init(bytes: b, prefix: p)
    }

    init(bytes: [UInt8], prefix: Int) {
        self.prefix = prefix
        self.bytes = IPv6Net.masked(bytes, prefix)
    }

    static func masked(_ b: [UInt8], _ p: Int) -> [UInt8] {
        (0..<16).map { i in
            let bits = max(0, min(8, p - i * 8))
            return bits == 0 ? 0 : b[i] & UInt8(truncatingIfNeeded: 0xFF << (8 - bits))
        }
    }

    func overlap(_ o: IPv6Net) -> IPv6Net? {
        let p = min(prefix, o.prefix)
        guard IPv6Net.masked(bytes, p) == IPv6Net.masked(o.bytes, p) else { return nil }
        return prefix > o.prefix ? self : o
    }

    func contains(_ o: IPv6Net) -> Bool { prefix <= o.prefix && IPv6Net.masked(o.bytes, prefix) == bytes }

    /// The routes cover 2000::/3, where all of the Internet's IPv6 is (redirect-gateway ipv6).
    static func coversGlobal(_ nets: [IPv6Net]) -> Bool {
        let global = IPv6Net(bytes: [0x20] + Array(repeating: 0, count: 15), prefix: 3)
        if nets.contains(where: { $0.contains(global) }) { return true }
        let halves = [IPv6Net(bytes: [0x20] + Array(repeating: 0, count: 15), prefix: 4),
                      IPv6Net(bytes: [0x30] + Array(repeating: 0, count: 15), prefix: 4)]
        return halves.allSatisfy { h in nets.contains { $0.contains(h) } }
    }

    var description: String {
        var a = in6_addr()
        withUnsafeMutableBytes(of: &a) { $0.copyBytes(from: bytes) }
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        inet_ntop(AF_INET6, &a, &buf, socklen_t(buf.count))
        return String(cString: buf) + "/\(prefix)"
    }

    static func parse(_ s: String) -> [UInt8]? {
        var a = in6_addr()
        guard s.count <= 45, inet_pton(AF_INET6, s, &a) == 1 else { return nil }
        return withUnsafeBytes(of: a) { Array($0) }
    }
}

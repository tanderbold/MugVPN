import Foundation
import MugVPNCore

/// Warnings when active tunnels get in each other's way (they are not
/// stopped: the user may want it so).
public enum NetworkConflict: Equatable, Sendable {
    case bothTakeDefaultRoute(String, String)
    case overlappingRoutes(String, String, String)
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
        if takesDefault.count >= 2 { out.append(.bothTakeDefaultRoute(takesDefault[0], takesDefault[1])) }
        for i in nets.indices {
            for j in nets.indices where j > i {
                for a in nets[i].1 where a.prefix > 1 && a.prefix < 32 {
                    for b in nets[j].1 where b.prefix > 1 && b.prefix < 32 {
                        if let o = a.overlap(b) {
                            out.append(.overlappingRoutes(nets[i].0, nets[j].0, o.description))
                        }
                    }
                }
            }
        }
        for t in tunnels where t.2.contains("setting DNS failed, already redirecting") {
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

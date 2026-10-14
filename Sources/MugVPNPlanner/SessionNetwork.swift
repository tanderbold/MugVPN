import Foundation

/// A VPN session's network as its server set it up, typed (OpenVPN 3 gives it so; openvpn's requests come as text
/// and go through TunnelState).
public struct SessionNetwork: Equatable, Sendable, Codable {
    /// Its address and its network's prefix (or a point-to-point peer).
    public var local4: UInt32?
    public var prefix4: Int = 32
    public var peer4: UInt32?
    /// Networks into its tunnel (redirect-gateway as the two halves).
    public var routes4: [IPv4Net] = []
    /// Hosts kept outside the tunnel (its server, net_gateway).
    public var outside4: [UInt32] = []
    /// IPv6: its address/prefix, networks into the tunnel ("net/bits"), hosts outside.
    public var local6: String?
    public var prefix6: Int = 0
    public var routes6: [String] = []
    public var outside6: [String] = []
    /// Its DNS as its server (or its profile) set it.
    public var dnsServers: [String] = []
    public var dnsDomains: [String] = []
    public var searchDomains: [String] = []
    public var mtu: Int = 1500

    public init() {}

    public static let halves = [IPv4Net(address: 0, prefix: 1), IPv4Net(address: 0x8000_0000, prefix: 1)]

    /// Its own network (the subnet of its address).
    public var subnet4: IPv4Net? { local4.map { IPv4Net(address: $0 & IPv4Net(address: 0, prefix: prefix4).mask, prefix: prefix4) } }
    /// It takes all IPv4 traffic.
    public var takesAllTraffic: Bool {
        routes4.contains { $0.prefix == 0 } || SessionNetwork.halves.allSatisfy { h in routes4.contains { $0.prefix == 1 && $0.address == h.address } }
    }
    /// Networks traffic to which goes into it (its own, its peer, its routes of /8 or narrower).
    public var networks: [IPv4Net] {
        (subnet4.map { [$0] } ?? []) + (peer4.map { [IPv4Net(address: $0, prefix: 32)] } ?? []) + routes4.filter { $0.prefix >= 8 }
    }
}

extension NetworkPolicy {
    /// A session's network on its own (as MugVPN's helper checks openvpn's requests) and against the Mac's networks
    /// and the other sessions: its addresses private and not the Mac's own; outside the tunnel only single unicast
    /// hosts, none inside another session's networks; no network of its taking another's outside host; IPv6 not the
    /// Mac's own nor another's.
    public static func checkSession(_ n: SessionNetwork, others: [SessionNetwork], lan4: [IPv4Net], lan6: [String]) throws {
        guard let local = n.local4 else { throw PolicyRefusal("no tunnel address") }
        guard TunnelState.isPrivate(local) else { throw PolicyRefusal("a tunnel address must be private") }
        guard (576...9000).contains(n.mtu) else { throw PolicyRefusal("MTU \(n.mtu): 576 to 9000") }
        if let peer = n.peer4 {
            guard TunnelState.isPrivate(peer) else { throw PolicyRefusal("a tunnel's peer must be private") }
        } else {
            guard (8...30).contains(n.prefix4) else { throw PolicyRefusal("a tunnel's network may be /8 at the widest") }
            guard let net = n.subnet4, TunnelState.privateBlock(of: net) != nil else {
                throw PolicyRefusal("a tunnel's network must be private")
            }
        }
        for a in [n.local4, n.peer4].compactMap({ $0 }) where lan4.contains(where: { $0.contains(a) }) {
            throw PolicyRefusal("\(TunnelState.text(a)) is in a network of the Mac's own")
        }
        guard n.routes4.count + n.outside4.count + n.routes6.count + n.outside6.count <= TunnelState.maxRoutes else {
            throw PolicyRefusal("more than \(TunnelState.maxRoutes) routes")
        }
        for h in n.outside4 where !TunnelState.isUnicastHost(h) {
            throw PolicyRefusal("\(TunnelState.text(h)): only a single host may be kept outside the tunnel")
        }
        for h in n.outside6 {
            guard let a = IPv6Host(h), a.unicast else { throw PolicyRefusal("\(h): only a single host may be kept outside the tunnel") }
        }
        let theirNets = others.flatMap(\.networks), theirHosts = others.flatMap(\.outside4)
        for h in n.outside4 where theirNets.contains(where: { $0.contains(h) }) {
            throw PolicyRefusal("\(TunnelState.text(h)) is in another connection's tunnel")
        }
        for r in n.routes4 where r.prefix >= 8 && theirHosts.contains(where: { r.contains($0) }) {
            throw PolicyRefusal("\(TunnelState.text(r.address))/\(r.prefix) takes another connection's host route")
        }
        if let l6 = n.local6 {
            guard (64...124).contains(n.prefix6) else { throw PolicyRefusal("an IPv6 tunnel network: /64 to /124") }
            let mine = "\(l6)/\(n.prefix6)"
            if lan6.contains(where: { TunnelState.overlap6($0, mine) }) { throw PolicyRefusal("\(mine) is a network of the Mac's own") }
            if others.compactMap({ o in o.local6.map { "\($0)/\(o.prefix6)" } }).contains(where: { TunnelState.overlap6($0, mine) }) {
                throw PolicyRefusal("\(mine) is another tunnel's network")
            }
        }
        for r in n.routes6 {
            guard let bits = r.split(separator: "/").last.flatMap({ Int($0) }) else { throw PolicyRefusal("bad IPv6 route \(r)") }
            for l in lan6 {
                guard let b = l.split(separator: "/").last.flatMap({ Int($0) }), b <= bits, TunnelState.overlap6(l, r) else { continue }
                throw PolicyRefusal("\(r) is inside another network (\(l))")
            }
        }
    }
}

/// An IPv6 host's address, as checked for routes outside the tunnel.
struct IPv6Host {
    let bytes: [UInt8]
    init?(_ s: String) {
        let a = s.split(separator: "/")
        guard a.count <= 2, a.count == 1 || a[1] == "128" else { return nil }
        var addr = in6_addr()
        guard inet_pton(AF_INET6, String(a[0]), &addr) == 1 else { return nil }
        bytes = withUnsafeBytes(of: &addr) { Array($0) }
    }
    /// Not unspecified/loopback, link-local or multicast.
    var unicast: Bool {
        !(bytes.allSatisfy { $0 == 0 } || bytes.prefix(15).allSatisfy { $0 == 0 } && bytes[15] == 1
          || (bytes[0] == 0xFE && bytes[1] & 0xC0 == 0x80) || bytes[0] == 0xFF)
    }
}

/// Who gets which DNS among sessions, decided from scratch each time (so the order of connecting never decides):
/// all names go to one session; one with no domains of its own has them before one that has some (that one keeps
/// its own domains); among equals, who asked first.
public enum DNSAssignment {
    public struct Want: Sendable {
        public var id: String
        public var servers: [String]
        /// Domains it is for (split DNS); empty: it wants all names.
        public var domains: [String]
        /// Its server's search domains (where it goes when another has all names).
        public var searchDomains: [String]
        /// When it asked (smaller: earlier).
        public var order: Int
        public init(id: String, servers: [String], domains: [String], searchDomains: [String], order: Int) {
            self.id = id
            self.servers = servers
            self.domains = domains
            self.searchDomains = searchDomains
            self.order = order
        }
    }

    public enum State: String, Sendable, Codable { case split, all, limited, waiting }

    public struct Result: Equatable, Sendable {
        /// The domains each session's DNS answers for (empty: all names); none when it has none now.
        public var domains: [String: [String]]
        public var states: [String: State]
    }

    public static func assign(_ wants: [Want]) -> Result {
        var domains: [String: [String]] = [:], states: [String: State] = [:]
        for w in wants where !w.domains.isEmpty {
            domains[w.id] = w.domains
            states[w.id] = .split
        }
        let all = wants.filter { $0.domains.isEmpty && !$0.servers.isEmpty }
            .sorted { a, b in
                let (na, nb) = (a.searchDomains.isEmpty, b.searchDomains.isEmpty)
                return na != nb ? na : a.order < b.order
            }
        for (i, w) in all.enumerated() {
            if i == 0 {
                domains[w.id] = []
                states[w.id] = .all
            } else if !w.searchDomains.isEmpty {
                domains[w.id] = w.searchDomains
                states[w.id] = .limited
            } else {
                states[w.id] = .waiting
            }
        }
        return Result(domains: domains, states: states)
    }
}

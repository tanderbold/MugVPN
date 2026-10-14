import Foundation

/// A request refused by the planner's rules; its text says why.
public struct PolicyRefusal: Error, Equatable, CustomStringConvertible {
    public let description: String
    public init(_ d: String) { description = d }
}

/// Public networks and DNS domains an administrator allows a standard user.
public struct Allowances: Equatable, Sendable {
    public var networks4: [IPv4Net] = []
    public var networks6: [String] = []
    public var domains: [String] = []
    public init() {}

    public func allows(_ n: IPv4Net) -> Bool {
        TunnelState.privateBlock(of: n) != nil || networks4.contains { $0.prefix <= n.prefix && $0.contains(n.address) }
    }
    public func allows6(_ net: String, bits: Int) -> Bool {
        if TunnelState.isULA(net), bits >= 7 { return true }
        return networks6.contains { a in
            guard let b = a.split(separator: "/").last.flatMap({ Int($0) }) else { return false }
            return b <= bits && TunnelState.overlap6(a, "\(net)/\(bits)")
        }
    }
    /// A domain an administrator listed (or under one). Private names too: one mDNSResponder asks for every user,
    /// so a resolver cannot be kept to its owner.
    public func allows(domain: String) -> Bool {
        let d = NetworkPolicy.norm(domain)
        return domains.contains { a in d == NetworkPolicy.norm(a) || d.hasSuffix("." + NetworkPolicy.norm(a)) }
    }
}

/// What a connection may do to the Mac's routing and DNS (an administrator's policy for standard users).
public struct ConnectionLimits: Equatable, Sendable {
    /// A standard user's: its tunnel carries its owner's traffic only.
    public var restricted = false
    public var mayRouteAll = true
    public var mayChangeDNS = true
    public var allowed = Allowances()
    public init(restricted: Bool = false, mayRouteAll: Bool = true, mayChangeDNS: Bool = true, allowed: Allowances = Allowances()) {
        self.restricted = restricted
        self.mayRouteAll = mayRouteAll
        self.mayChangeDNS = mayChangeDNS
        self.allowed = allowed
    }
}

/// Another connection, as the rules for this one see it.
public struct OtherConnection: Sendable {
    public var owner: UInt32
    public var exited: Bool
    public var tunnel: TunnelState
    public init(owner: UInt32, exited: Bool, tunnel: TunnelState) {
        self.owner = owner
        self.exited = exited
        self.tunnel = tunnel
    }
}

/// The rules between a connection's tunnel, the Mac's own networks and the other connections (pure: both products
/// apply what they allow).
public enum NetworkPolicy {
    public static let policyText = "an administrator does not let standard users change the whole Mac's routing or DNS"
    /// While another user's tunnel takes all traffic: holes around it (its server), no more.
    public static let hostsBesideFullTunnel = 2

    public static func norm(_ d: String) -> String { d.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ".")) }

    /// Networks and outside hosts of the others (another owner's only, or everyone's).
    public static func otherNetworks(owner: UInt32, others: [OtherConnection], otherOwnersOnly: Bool) -> (nets: [IPv4Net], hosts: [UInt32]) {
        var nets: [IPv4Net] = [], hosts: [UInt32] = []
        for o in others where !(otherOwnersOnly && o.owner == owner) {
            nets += o.tunnel.networks
            hosts += o.tunnel.outsideHosts
        }
        return (nets, hosts)
    }

    /// IFCONFIG: its own addresses (the Mac delivers traffic to them locally, routes to the peer) never in the Mac's
    /// own networks, nor where another user's tunnel sends traffic (its routes, its peer, gateways and DNS servers).
    /// The same 10.8.0.x on both ends of two servers is common and harmless: both are local.
    public static func checkAddresses(_ t: TunnelState, owner: UInt32, others: [OtherConnection], lan4: [IPv4Net]) throws {
        let otherUsers = others.filter { $0.owner != owner }
        let used = Set(otherUsers.flatMap { $0.tunnel.serverAddresses + $0.tunnel.outsideHosts })
        let routed = otherUsers.flatMap(\.tunnel.routedNetworks)
        for a in [t.local, t.peer].compactMap({ $0 }) {
            if lan4.contains(where: { $0.contains(a) }) {
                throw PolicyRefusal("\(TunnelState.text(a)) is in a network of the Mac's own")
            }
            if used.contains(a) || routed.contains(where: { $0.contains(a) }) {
                throw PolicyRefusal("\(TunnelState.text(a)) is in another user's network")
            }
        }
    }

    /// The route to its own network: not when it lies in another user's networks (as narrow or narrower, it would
    /// take their traffic).
    public static func subnetRouteAllowed(_ net: IPv4Net, owner: UInt32, others: [OtherConnection]) -> Bool {
        let theirs = otherNetworks(owner: owner, others: others, otherOwnersOnly: true).nets
        return !theirs.contains { $0.contains(net.address) && $0.prefix <= net.prefix }
    }

    /// IFCONFIG6: allowed by the administrator's list, not one of the Mac's own IPv6 networks nor another tunnel's.
    public static func checkNetwork6(_ mine: String, limits: ConnectionLimits, others: [OtherConnection], lan6: [String],
                                     message: String) throws {
        if !limits.mayRouteAll {
            let p = mine.split(separator: "/")
            if p.count == 2, !limits.allowed.allows6(String(p[0]), bits: Int(p[1]) ?? 0) {
                throw PolicyRefusal("IFCONFIG6 \(message): \(policyText)")
            }
        }
        if lan6.contains(where: { TunnelState.overlap6($0, mine) }) {
            throw PolicyRefusal("\(mine) is a network of the Mac's own")
        }
        if others.compactMap(\.tunnel.net6).contains(where: { TunnelState.overlap6($0, mine) }) {
            throw PolicyRefusal("\(mine) is another tunnel's network")
        }
    }

    /// ROUTE: what `added` may take, given the connection's tunnel after it (`t`), its limits, the Mac's networks and
    /// the others.
    public static func checkRoutes(_ added: [TunnelRoute], tunnel t: TunnelState, owner: UInt32, limits: ConnectionLimits,
                                   others: [OtherConnection], lan4: [IPv4Net], message: String) throws {
        func parts(_ r: TunnelRoute) -> (UInt32, Int)? {
            guard let a = TunnelState.ipv4(Substring(r.net)), let m = TunnelState.ipv4(Substring(r.mask)),
                  let p = TunnelState.prefix(ofMask: m) else { return nil }
            return (a, p)
        }
        // A standard user: private networks, and public ones an administrator lists; no host around the tunnels
        // (via the Mac's gateway, it would leave another user's tunnel).
        if !limits.mayRouteAll {
            if added.contains(where: { !$0.intoTunnel }) { throw PolicyRefusal("ROUTE \(message): \(policyText)") }
            for r in added {
                guard let (a, p) = parts(r), limits.allowed.allows(IPv4Net(address: a, prefix: p)) else {
                    throw PolicyRefusal("ROUTE \(message): \(policyText)")
                }
            }
        }
        if limits.restricted {
            // Nothing into the Mac's own networks (its LAN, its router, its DNS): as narrow as a network of the Mac's
            // or narrower would win over it (wider does not).
            for r in added {
                guard let (a, p) = parts(r) else { continue }
                if lan4.contains(where: { $0.contains(a) && $0.prefix <= p }) {
                    throw PolicyRefusal("\(r.net)/\(p) is a network of the Mac's own")
                }
            }
        }
        // Between connections, whichever comes first: a host route via the Mac's gateway must not cut into another's
        // network, nor a network take another's host route.
        let (theirNets, theirHosts) = otherNetworks(owner: owner, others: others, otherOwnersOnly: false)
        let otherUsers = otherNetworks(owner: owner, others: others, otherOwnersOnly: true).nets
        for r in added {
            guard let (a, p) = parts(r) else { continue }
            if !r.intoTunnel, theirNets.contains(where: { $0.contains(a) }) {
                throw PolicyRefusal("\(r.net) is in another connection's tunnel")
            }
            if r.intoTunnel, p >= 8, theirHosts.contains(where: { IPv4Net(address: a, prefix: p).contains($0) }) {
                throw PolicyRefusal("\(r.net)/\(p) takes another connection's host route")
            }
            // As narrow as another user's network or narrower: the more specific route wins, and their traffic would
            // come here. (Wider takes only what their routes do not.)
            if r.intoTunnel, otherUsers.contains(where: { $0.contains(a) && $0.prefix <= p }) {
                throw PolicyRefusal("\(r.net)/\(p) is inside another user's tunnel")
            }
        }
        let fullElsewhere = others.contains { $0.owner != owner && $0.tunnel.takesAllTraffic }
        if fullElsewhere, t.outsideHosts.count > hostsBesideFullTunnel {
            throw PolicyRefusal("another user's tunnel takes all traffic: no more host routes around it")
        }
    }

    /// ROUTE6: not as narrow as another user's IPv6 network, or the Mac's own, or narrower (theirs would come here);
    /// allowed by the administrator's list.
    public static func checkRoute6(_ r: TunnelRoute, owner: UInt32, limits: ConnectionLimits, others: [OtherConnection],
                                   lan6: [String], message: String) throws {
        let bits = Int(r.mask) ?? 0
        let theirs6 = others.filter { $0.owner != owner }
            .flatMap { o in (o.tunnel.net6.map { [$0] } ?? []) + o.tunnel.routes.filter { $0.kind == .tunnel6 }.map { "\($0.net)/\($0.mask)" } }
        for n in lan6 + theirs6 {
            guard let b = n.split(separator: "/").last.flatMap({ Int($0) }), b <= bits,
                  TunnelState.overlap6(n, "\(r.net)/\(bits)") else { continue }
            throw PolicyRefusal("\(r.net)/\(bits) is inside another network (\(n))")
        }
        if !limits.mayRouteAll, !limits.allowed.allows6(r.net, bits: bits) {
            throw PolicyRefusal("ROUTE6 \(message): \(policyText)")
        }
    }

    /// DNS a connection may set: a standard user's for its own (or listed) domains only unless allowed all names; its
    /// servers inside its own tunnel, never the Mac's own resolvers or networks (the system resolver would send
    /// everyone's queries there). `systemResolvers` is asked only when needed; nil: not known.
    public static func checkDNS(_ plan: DNSPlan, tunnel t: TunnelState, limits: ConnectionLimits, lan4: [IPv4Net],
                                systemResolvers: () -> [String]?) throws {
        if !limits.mayChangeDNS {
            if !plan.split { throw PolicyRefusal("DNS for all names: \(policyText)") }
            if let d = plan.matchDomains.first(where: { !limits.allowed.allows(domain: $0) }) {
                throw PolicyRefusal("DNS for \(d): \(policyText)")
            }
        }
        guard limits.restricted else { return }
        let mine = t.networks
        // (An administrator who lets users change the Mac's DNS lets them replace its resolvers too.)
        var system = Set<UInt32>()
        if !limits.mayChangeDNS {
            guard let known = systemResolvers() else { throw PolicyRefusal("DNS not set: the Mac's own DNS servers are not known") }
            // As numbers: one address has more than one spelling.
            system = Set(known.compactMap { TunnelState.ipv4(Substring($0)) })
        }
        for srv in plan.servers {
            guard let a = TunnelState.ipv4(Substring(srv)), TunnelState.text(a) == srv, !system.contains(a),
                  !lan4.contains(where: { $0.contains(a) }), !t.outsideHosts.contains(a),
                  mine.contains(where: { $0.contains(a) }) || t.peer == a else {
                throw PolicyRefusal("DNS server \(srv): not inside this tunnel")
            }
        }
    }

    /// A domain another user's tunnel answers for, or a part of it: the more specific one would win. - Returns: the
    /// first such domain.
    public static func domainAnsweredByAnotherUser(_ domains: [String], owner: UInt32, others: [OtherConnection]) -> String? {
        let theirs = others.filter { $0.owner != owner && $0.tunnel.dnsApplied }.flatMap(\.tunnel.dnsDomains)
        return domains.first { m in theirs.contains { norm(m) == norm($0) || norm(m).hasSuffix("." + norm($0)) } }
    }

    /// One tunnel has all names at a time: another holds them now?
    public static func allNamesHeld(by others: [OtherConnection]) -> Bool {
        others.contains { !$0.exited && $0.tunnel.dnsApplied && $0.tunnel.dnsDomains.isEmpty }
    }

    /// Who gets all names next among those waiting: those with no domains of their own first, then who asked first.
    public static func allNamesOrder<T>(_ waiting: [(item: T, plan: DNSPlan, order: Int)]) -> [T] {
        waiting.sorted { a, b in
            let (na, nb) = (a.plan.searchDomains.isEmpty, b.plan.searchDomains.isEmpty)
            return na != nb ? na : a.order < b.order
        }.map(\.item)
    }
}

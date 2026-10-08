import Foundation

// Privilege separation: openvpn runs unprivileged and asks its management client
// (MugVPN's app) for what needs root; the app forwards each request to the helper.
// Everything here treats the request text as hostile: it may come from a server
// that compromised openvpn, or from the user's own app. Only what keeps traffic
// inside this connection's tunnel, or sends a single host the way the Mac already
// would, is carried out; the helper remembers what it did and undoes exactly that.

public struct TunnelRequestError: Error, CustomStringConvertible, Equatable {
    public var description: String
    init(_ d: String) { description = d }
}

/// An IPv4 network: address and prefix length.
public struct IPv4Net: Equatable, Sendable, Codable {
    public var address: UInt32
    public var prefix: Int
    public init(address: UInt32, prefix: Int) {
        self.address = address
        self.prefix = prefix
    }
    var mask: UInt32 { prefix == 0 ? 0 : UInt32.max << UInt32(32 - prefix) }
    public func contains(_ a: UInt32) -> Bool { a & mask == address & mask }
    /// Share any address: one contains the other's start.
    public func overlaps(_ o: IPv4Net) -> Bool { contains(o.address) || o.contains(address) }
}

/// The Mac's own default route before the tunnel (from the routing table).
public struct DefaultGateway: Equatable, Sendable {
    public var address: String
    public var interface: String
    public init(address: String, interface: String) {
        self.address = address
        self.interface = interface
    }
}

/// What DNS a tunnel asks for, ready for the helper to set.
public struct DNSPlan: Equatable, Sendable {
    public var device: String
    public var servers: [String]
    /// Only these names go to the servers (split); empty with `split` false: all names.
    public var matchDomains: [String]
    public var searchDomains: [String]
    public var split: Bool
}

/// A route the helper added for a connection.
public struct TunnelRoute: Equatable, Sendable, Codable {
    public enum Kind: String, Sendable, Codable {
        /// Into the tunnel, bound to its utun (`-interface`): it goes with the device.
        case tunnel
        /// One host via the Mac's own gateway (the VPN server, `net_gateway`).
        case host
        /// One host on the Mac's own interface (an on-link gateway).
        case onLink
        /// IPv6 into the tunnel.
        case tunnel6
    }
    public var kind: Kind
    public var net: String
    /// Netmask (IPv4) or prefix length (IPv6).
    public var mask: String
    /// The utun (tunnel, tunnel6), the gateway address (host) or the interface (onLink).
    public var via: String

    public init(kind: Kind, net: String, mask: String, via: String) {
        self.kind = kind
        self.net = net
        self.mask = mask
        self.via = via
    }

    public var add: [String] {
        switch kind {
        case .tunnel: return ["route", "-n", "add", "-net", net, "-netmask", mask, "-interface", via]
        case .host: return ["route", "-n", "add", "-net", net, via, mask]
        case .onLink: return ["route", "-n", "add", "-cloning", "-net", net, "-netmask", mask, "-interface", via]
        case .tunnel6: return ["route", "-n", "add", "-inet6", net, "-prefixlen", mask, "-iface", via]
        }
    }
    public var delete: [String] {
        var d = add
        d[2] = "delete"
        d.removeAll { $0 == "-cloning" }
        return d
    }
    /// Through its tunnel's device (gone with it).
    public var intoTunnel: Bool { kind == .tunnel || kind == .tunnel6 }
}

/// One connection's tunnel as the helper set it up.
public extension TunnelState {
    /// openvpn's requests (NEED-OK names) that only the helper answers.
    static let requestNames: Set<String> = ["OPENTUN", "IFCONFIG", "IFCONFIG6", "ROUTE", "ROUTE6", "ROUTEDEL",
                                            "ROUTE6DEL", "DNSVAR", "DNSUP", "DNSDOWN"]
}

public struct TunnelState: Equatable, Sendable, Codable {
    public var device: String?
    public var subnet: IPv4Net?
    /// The other end on a point-to-point (net30/p2p) tunnel.
    public var peer: UInt32?
    /// Every route it added, to delete exactly those.
    public private(set) var routes: [TunnelRoute] = []
    public private(set) var dnsVars: [String: String] = [:]
    public var dnsApplied = false
    /// Every utun it opened (reconnects open new ones).
    public var opened: [String] = []
    /// The route to its own network (subnet topology), once added.
    public var subnetRoute: TunnelRoute?
    /// Its IPv6 network ("prefix/bits"), once set.
    public var net6: String?
    /// Its own IPv4 address, once set.
    public var local: UInt32?
    /// Domains its DNS answers for while applied (split DNS).
    public var dnsDomains: [String] = []
    /// Gateways inside the tunnel its routes named (the server's side).
    public var gateways: [UInt32] = []
    /// Servers its DNS asks while applied.
    public var dnsServers: [String] = []

    /// A connection with more routes than this is not a VPN profile but an attack on the helper.
    public static let maxRoutes = 512

    public init() {}

    private enum CodingKeys: String, CodingKey { case device, subnet, peer, routes, dnsVars, dnsApplied, opened, subnetRoute, net6, local, dnsDomains, gateways, dnsServers }

    /// A record of an older helper lacks newer fields: it still counts.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        device = try c.decodeIfPresent(String.self, forKey: .device)
        subnet = try c.decodeIfPresent(IPv4Net.self, forKey: .subnet)
        peer = try c.decodeIfPresent(UInt32.self, forKey: .peer)
        routes = (try? c.decodeIfPresent([TunnelRoute].self, forKey: .routes)) ?? []
        dnsVars = (try? c.decodeIfPresent([String: String].self, forKey: .dnsVars)) ?? [:]
        dnsApplied = (try? c.decodeIfPresent(Bool.self, forKey: .dnsApplied)) ?? false
        opened = (try? c.decodeIfPresent([String].self, forKey: .opened)) ?? device.map { [$0] } ?? []
        subnetRoute = try? c.decodeIfPresent(TunnelRoute.self, forKey: .subnetRoute)
        net6 = try? c.decodeIfPresent(String.self, forKey: .net6)
        local = try? c.decodeIfPresent(UInt32.self, forKey: .local)
        dnsDomains = (try? c.decodeIfPresent([String].self, forKey: .dnsDomains)) ?? []
        gateways = (try? c.decodeIfPresent([UInt32].self, forKey: .gateways)) ?? []
        dnsServers = (try? c.decodeIfPresent([String].self, forKey: .dnsServers)) ?? []
    }

    /// Routes of the current device that cover everything (def1's halves, or a default).
    public var takesAllTraffic: Bool {
        let nets = routes.filter { $0.kind == .tunnel && $0.via == device }.map { ($0.net, $0.mask) }
        let halves = nets.contains { $0 == ("0.0.0.0", "128.0.0.0") } && nets.contains { $0 == ("128.0.0.0", "128.0.0.0") }
        return halves || nets.contains { $0 == ("0.0.0.0", "0.0.0.0") }
    }

    /// IPv4 addresses outside private space its tunnel routes take (an administrator's limit).
    public var publicCoverage: UInt64 {
        routes.filter { $0.kind == .tunnel }.reduce(0) { sum, r in
            guard let a = TunnelState.ipv4(Substring(r.net)), let m = TunnelState.ipv4(Substring(r.mask)),
                  let p = TunnelState.prefix(ofMask: m) else { return sum }
            return TunnelState.privateBlock(of: IPv4Net(address: a, prefix: p)) != nil ? sum : sum + (UInt64(1) << UInt64(32 - p))
        }
    }

    /// IPv6 tunnel routes outside unique local space (fc00::/7).
    public var publicRoutes6: [TunnelRoute] {
        routes.filter { $0.kind == .tunnel6 && !TunnelState.isULA($0.net) }
    }

    /// Its own networks: the tunnel's network and routes into it of /8 or narrower
    /// (def1's halves are "everything else", not a network of its own).
    public var networks: [IPv4Net] {
        // Its own network counts once its route is in (it may not be: another took that range).
        var nets = subnetRoute != nil ? (subnet.map { [$0] } ?? []) : []
        if let peer { nets.append(IPv4Net(address: peer, prefix: 32)) }
        for r in routes where r.kind == .tunnel && r.via == device {
            if let n = TunnelState.ipv4(Substring(r.net)), let m = TunnelState.ipv4(Substring(r.mask)),
               let p = TunnelState.prefix(ofMask: m), p >= 8 { nets.append(IPv4Net(address: n, prefix: p)) }
        }
        return nets
    }

    /// Networks its routes send into the tunnel (not its own network: that may be anyone's default).
    public var routedNetworks: [IPv4Net] {
        routes.filter { $0.kind == .tunnel && $0.via == device }.compactMap { r in
            guard let n = TunnelState.ipv4(Substring(r.net)), let m = TunnelState.ipv4(Substring(r.mask)),
                  let p = TunnelState.prefix(ofMask: m), p >= 8 else { return nil }
            return IPv4Net(address: n, prefix: p)
        }
    }

    /// Addresses on the server's side it uses: its peer, its routes' gateways, its DNS servers.
    public var serverAddresses: [UInt32] {
        var a = gateways + (peer.map { [$0] } ?? [])
        a += dnsVars.filter { $0.key.contains("_address_") }.compactMap { TunnelState.ipv4(Substring($0.value)) }
        return a
    }

    /// Hosts it routes outside the tunnel, via the Mac's gateway or interface.
    public var outsideHosts: [UInt32] {
        routes.filter { $0.kind == .host || $0.kind == .onLink }.compactMap { TunnelState.ipv4(Substring($0.net)) }
    }

    /// Does one of its own networks take this address?
    public func takes(_ a: UInt32) -> Bool { networks.contains { $0.contains(a) } }

    // MARK: - parsing

    static func ipv4(_ s: Substring) -> UInt32? {
        var a = in_addr()
        guard s.count <= 15, inet_pton(AF_INET, String(s), &a) == 1 else { return nil }
        return UInt32(bigEndian: a.s_addr)
    }

    static func ipv6(_ s: Substring) -> Bool {
        var a = in6_addr()
        return s.count <= 45 && inet_pton(AF_INET6, String(s), &a) == 1
    }

    static func prefix(ofMask m: UInt32) -> Int? {
        let p = m.nonzeroBitCount
        return (p == 0 ? 0 : UInt32.max << UInt32(32 - p)) == m ? p : nil
    }

    public static func text(_ a: UInt32) -> String { "\(a >> 24).\((a >> 16) & 255).\((a >> 8) & 255).\(a & 255)" }

    static let privateBlocks = [IPv4Net(address: 0x0A00_0000, prefix: 8), IPv4Net(address: 0xAC10_0000, prefix: 12),
                                IPv4Net(address: 0xC0A8_0000, prefix: 16), IPv4Net(address: 0x6440_0000, prefix: 10)]

    /// Private (RFC 1918) or shared (CGNAT) space: a tunnel's own addresses.
    static func isPrivate(_ a: UInt32) -> Bool { privateBlocks.contains { $0.contains(a) } }

    /// The private block a whole network lies in, if it does.
    static func privateBlock(of n: IPv4Net) -> IPv4Net? {
        privateBlocks.first { $0.prefix <= n.prefix && $0.contains(n.address) }
    }

    /// A host a route via the Mac's gateway may name: not loopback, link-local, multicast or
    /// reserved. (A VPN server may well be on a private network; another connection's
    /// networks are the helper's check.)
    static func isUnicastHost(_ a: UInt32) -> Bool {
        let special = [IPv4Net(address: 0, prefix: 8), IPv4Net(address: 0x7F00_0000, prefix: 8),
                       IPv4Net(address: 0xA9FE_0000, prefix: 16), IPv4Net(address: 0xE000_0000, prefix: 3)]
        return !special.contains { $0.contains(a) }
    }

    static func isULA(_ s: String) -> Bool {
        var a = in6_addr()
        guard inet_pton(AF_INET6, s, &a) == 1 else { return false }
        return withUnsafeBytes(of: &a) { $0[0] & 0xFE == 0xFC }
    }

    func requireDevice() throws -> String {
        guard let d = device else { throw TunnelRequestError("no tunnel opened yet") }
        return d
    }

    // MARK: - requests

    /// IFCONFIG "local netmask-or-remote mtu topology".
    public mutating func ifconfig(_ msg: String) throws -> [[String]] {
        let dev = try requireDevice()
        let f = msg.split(separator: " ")
        guard f.count == 4, let local = TunnelState.ipv4(f[0]), let second = TunnelState.ipv4(f[1]),
              let mtu = Int(f[2]), (576...9000).contains(mtu) else { throw TunnelRequestError("bad IFCONFIG \(msg)") }
        guard TunnelState.isPrivate(local) else { throw TunnelRequestError("a tunnel address must be private") }
        self.local = local
        switch f[3] {
        case "subnet":
            guard let p = TunnelState.prefix(ofMask: second), (8...30).contains(p) else {
                throw TunnelRequestError("a tunnel's network may be /8 at the widest")
            }
            let net = IPv4Net(address: local & IPv4Net(address: 0, prefix: p).mask, prefix: p)
            guard TunnelState.privateBlock(of: net) != nil else {
                throw TunnelRequestError("a tunnel's network must be private (\(msg))")
            }
            subnet = net
            let l = TunnelState.text(local), m = TunnelState.text(second)
            return [["ifconfig", dev, "inet", l, l, "netmask", m, "mtu", String(mtu), "up"],
                    ["route", "-n", "add", "-net", TunnelState.text(net.address), "-netmask", m, "-interface", dev]]
        case "net30", "p2p":
            guard TunnelState.isPrivate(second) else { throw TunnelRequestError("a tunnel's peer must be private") }
            peer = second
            subnet = IPv4Net(address: local, prefix: 32)
            return [["ifconfig", dev, TunnelState.text(local), TunnelState.text(second), "mtu", String(mtu), "up"]]
        default:
            throw TunnelRequestError("bad topology \(f[3])")
        }
    }

    /// The route a ROUTE or ROUTEDEL message names, checked.
    func parseRoute(_ msg: String, gateway sys: DefaultGateway?) throws -> [TunnelRoute] {
        let dev = try requireDevice()
        let f = msg.split(separator: " ")
        guard f.count == 3 || (f.count == 5 && f[3] == "dev"), let net = TunnelState.ipv4(f[0]), let mask = TunnelState.ipv4(f[1]),
              let p = TunnelState.prefix(ofMask: mask), let gw = TunnelState.ipv4(f[2]),
              net & IPv4Net(address: 0, prefix: p).mask == net else { throw TunnelRequestError("bad ROUTE \(msg)") }
        let inTunnel = (subnet.map { $0.contains(gw) } ?? false) || peer == gw
        if f.count == 3, inTunnel {
            // Bound to the device, not the gateway's address: nothing on the LAN can take it.
            if p == 0 {
                // redirect-gateway without def1: the Mac's own default stays (nothing to put
                // back after a crash); two halves through the tunnel win over it.
                return [TunnelRoute(kind: .tunnel, net: "0.0.0.0", mask: "128.0.0.0", via: dev),
                        TunnelRoute(kind: .tunnel, net: "128.0.0.0", mask: "128.0.0.0", via: dev)]
            }
            return [TunnelRoute(kind: .tunnel, net: String(f[0]), mask: String(f[1]), via: dev)]
        }
        // One host the way the Mac reaches it anyway (the VPN server, net_gateway).
        guard p == 32, let sys, TunnelState.isUnicastHost(net) else {
            throw TunnelRequestError("a route must go through the tunnel (\(msg))")
        }
        if f.count == 3, String(f[2]) == sys.address {
            return [TunnelRoute(kind: .host, net: String(f[0]), mask: String(f[1]), via: String(f[2]))]
        }
        if f.count == 5, String(f[4]) == sys.interface {
            return [TunnelRoute(kind: .onLink, net: String(f[0]), mask: String(f[1]), via: String(f[4]))]
        }
        throw TunnelRequestError("a route must go through the tunnel (\(msg))")
    }

    /// ROUTE "network netmask gateway [dev iface]": what to add (now remembered).
    public mutating func route(_ msg: String, gateway sys: DefaultGateway?) throws -> [TunnelRoute] {
        let new = try parseRoute(msg, gateway: sys).filter { !routes.contains($0) }
        let f = msg.split(separator: " ")
        if new.contains(where: \.intoTunnel), f.count >= 3, let gw = TunnelState.ipv4(f[2]), !gateways.contains(gw) {
            gateways.append(gw)
        }
        guard routes.count + new.count <= TunnelState.maxRoutes else {
            throw TunnelRequestError("more than \(TunnelState.maxRoutes) routes")
        }
        routes += new
        return new
    }

    /// ROUTEDEL: only a route this connection added; what to delete (now forgotten).
    public mutating func deleteRoute(_ msg: String, gateway sys: DefaultGateway? = nil) throws -> [TunnelRoute] {
        let f = msg.split(separator: " ")
        if f.count >= 3, f[0] == "0.0.0.0", f[1] == "0.0.0.0",
           let gw = TunnelState.ipv4(f[2]), !((subnet.map { $0.contains(gw) } ?? false) || peer == gw) {
            // The Mac's own default (openvpn's step before redirect-gateway): left alone.
            return []
        }
        let named: [TunnelRoute]
        do { named = try parseRoute(msg, gateway: sys) } catch { throw TunnelRequestError("this connection did not add \(msg)") }
        let ours = named.filter { routes.contains($0) }
        guard !ours.isEmpty else { throw TunnelRequestError("this connection did not add \(msg)") }
        forget(ours)
        return ours
    }

    /// Routes that were not (or no longer) added after all.
    public mutating func forget(_ rs: [TunnelRoute]) { routes.removeAll { rs.contains($0) } }

    /// The routes to take away when the connection ends, newest first.
    public func cleanup() -> [TunnelRoute] { routes.reversed() + (subnetRoute.map { [$0] } ?? []) }

    /// Forget what belonged to an earlier utun (a reconnect opened a new one): returned to be deleted.
    public mutating func dropDevice(_ old: String) -> [TunnelRoute] {
        var gone = routes.filter { $0.intoTunnel && $0.via == old }
        if let r = subnetRoute, r.via == old { gone.append(r); subnetRoute = nil }
        forget(gone)
        return gone
    }

    /// IFCONFIG6 "address/bits mtu".
    public mutating func ifconfig6(_ msg: String) throws -> [[String]] {
        let dev = try requireDevice()
        let f = msg.split(separator: " ")
        let a = f.first?.split(separator: "/") ?? []
        guard f.count == 2, a.count == 2, TunnelState.ipv6(a[0]), let bits = Int(a[1]), (64...124).contains(bits),
              let mtu = Int(f[1]), (1280...9000).contains(mtu) else { throw TunnelRequestError("bad IFCONFIG6 \(msg): prefix 64-124") }
        net6 = String(f[0])
        return [["ifconfig", dev, "inet6", String(f[0]), "mtu", String(mtu), "up"]]
    }

    /// Do two IPv6 networks ("address/bits") share addresses?
    public static func overlap6(_ a: String, _ b: String) -> Bool {
        func parse(_ s: String) -> ([UInt8], Int)? {
            let p = s.split(separator: "/")
            guard p.count == 2, let bits = Int(p[1]), (0...128).contains(bits) else { return nil }
            var addr = in6_addr()
            guard inet_pton(AF_INET6, String(p[0]), &addr) == 1 else { return nil }
            return (withUnsafeBytes(of: &addr) { Array($0) }, bits)
        }
        guard let (x, xb) = parse(a), let (y, yb) = parse(b) else { return false }
        let n = min(xb, yb)
        for i in 0..<n {
            let shift = UInt8(7 - i % 8)
            let bx: UInt8 = (x[i / 8] >> shift) & 1
            let by: UInt8 = (y[i / 8] >> shift) & 1
            if bx != by { return false }
        }
        return true
    }

    /// ROUTE6 "network/bits device": on this tunnel only.
    func parseRoute6(_ msg: String) throws -> TunnelRoute {
        let dev = try requireDevice()
        let f = msg.split(separator: " ")
        let a = f.first?.split(separator: "/") ?? []
        guard f.count == 2, String(f[1]) == dev, a.count == 2, TunnelState.ipv6(a[0]), let bits = Int(a[1]), (0...128).contains(bits)
        else { throw TunnelRequestError("an IPv6 route must go through the tunnel (\(msg))") }
        return TunnelRoute(kind: .tunnel6, net: String(a[0]), mask: String(bits), via: dev)
    }

    public mutating func route6(_ msg: String) throws -> TunnelRoute {
        let r = try parseRoute6(msg)
        guard routes.count < TunnelState.maxRoutes else { throw TunnelRequestError("more than \(TunnelState.maxRoutes) routes") }
        if !routes.contains(r) { routes.append(r) }
        return r
    }

    /// ROUTE6DEL: only a route this connection added.
    public mutating func deleteRoute6(_ msg: String) throws -> TunnelRoute {
        guard let r = try? parseRoute6(msg), routes.contains(r) else { throw TunnelRequestError("this connection did not add \(msg)") }
        forget([r])
        return r
    }

    // MARK: - DNS

    /// One-label names for private networks (RFC 6762, ICANN's .internal, common practice).
    /// (Not "local": that is multicast DNS, every user's.)
    static let privateSingleLabels: Set<String> = ["internal", "lan", "home", "corp", "intranet", "private", "localdomain"]

    static func isDomain(_ s: String) -> Bool {
        let name = s.hasSuffix(".") ? String(s.dropLast()) : s
        guard !name.isEmpty, name.count <= 253 else { return false }
        return name.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { l in
            !l.isEmpty && l.count <= 63 && l.unicodeScalars.allSatisfy { $0.isASCII && (CharacterSet.alphanumerics.contains($0) || $0 == "-" || $0 == "_") }
        }
    }

    /// DNSVAR "name=value", one of openvpn's dns-updown variables.
    public mutating func dnsVar(_ msg: String) throws {
        guard let eq = msg.firstIndex(of: "=") else { throw TunnelRequestError("bad DNSVAR") }
        let name = String(msg[..<eq]), value = String(msg[msg.index(after: eq)...])
        let ok: Bool
        if name.range(of: #"^dns_server_\d{1,2}_address_\d{1,2}$"#, options: .regularExpression) != nil {
            ok = TunnelState.ipv4(Substring(value)) != nil || TunnelState.ipv6(Substring(value))
        } else if name.range(of: #"^dns_server_\d{1,2}_resolve_domain_\d{1,3}$"#, options: .regularExpression) != nil
                    || name.range(of: #"^dns_search_domain_\d{1,3}$"#, options: .regularExpression) != nil {
            // A whole top-level domain (com, ru...) would take every user's names: one label
            // only for names meant for private networks.
            let labels = value.split(separator: ".").count
            ok = TunnelState.isDomain(value)
                && (labels >= 2 || TunnelState.privateSingleLabels.contains(value.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))))
        } else if name.range(of: #"^dns_server_\d{1,2}_(port_\d{1,2}|dnssec|transport|sni)$"#, options: .regularExpression) != nil {
            ok = value.count <= 253 && value.unicodeScalars.allSatisfy { $0.isASCII && (CharacterSet.alphanumerics.contains($0) || ".-_".unicodeScalars.contains($0)) }
        } else {
            ok = false
        }
        guard ok, dnsVars.count < 256 else { throw TunnelRequestError("refused DNS setting \(name)") }
        dnsVars[name] = value
    }

    public mutating func clearDNS() { dnsVars = [:] }

    /// What to set for DNSUP on `device` (`splitMarker`: the connection's "Split DNS by Domain").
    public func dnsPlan(device dev: String, splitMarker: Bool) throws -> DNSPlan {
        guard dev == device else { throw TunnelRequestError("DNS for another device") }
        func indexed(_ prefix: String) -> [String] {
            dnsVars.filter { $0.key.hasPrefix(prefix) }
                .sorted { Int($0.key.dropFirst(prefix.count)) ?? 0 < Int($1.key.dropFirst(prefix.count)) ?? 0 }.map(\.value)
        }
        // The first server openvpn names (by priority number) that can be used as plain DNS:
        // DNS over TLS/HTTPS, another port or DNSSEC asked for is not quietly made plain.
        let serverIDs = Set(dnsVars.keys.compactMap { k -> Int? in
            guard k.hasPrefix("dns_server_"), k.contains("_address_") else { return nil }
            return Int(k.dropFirst("dns_server_".count).prefix { $0.isNumber })
        })
        func plain(_ n: Int) -> Bool {
            let transport = dnsVars["dns_server_\(n)_transport"]?.lowercased() ?? "plain"
            let dnssec = dnsVars["dns_server_\(n)_dnssec"]?.lowercased() ?? "no"
            let ports = dnsVars.filter { $0.key.hasPrefix("dns_server_\(n)_port_") }.map(\.value)
            return transport == "plain" && (dnssec == "no" || dnssec == "optional") && ports.allSatisfy { $0 == "53" }
        }
        guard let first = serverIDs.sorted().first(where: plain) else {
            throw TunnelRequestError(serverIDs.isEmpty ? "no DNS server"
                                     : "no DNS server MugVPN can set as asked (DNS over TLS/HTTPS, another port or DNSSEC)")
        }
        let servers = indexed("dns_server_\(first)_address_")
        var match = indexed("dns_server_\(first)_resolve_domain_")
        let search = indexed("dns_search_domain_")
        if match.isEmpty && splitMarker { match = search }
        return DNSPlan(device: dev, servers: servers, matchDomains: match, searchDomains: search, split: !match.isEmpty)
    }
}

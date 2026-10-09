import Foundation

/// Which network the Mac is on, from SystemConfiguration's state: the primary interface, its
/// router and addresses, and what its DHCP server handed out. A new Wi-Fi network, a new lease
/// or a move to Ethernet changes it; MugVPN's own tunnels (utun) and the DNS it sets do not.
public struct NetworkIdentity: Equatable, Sendable {
    public var interface: String
    public var router: String
    public var addresses: [String]
    /// IPv6: the router only (temporary addresses come and go on their own).
    public var router6: String
    /// The DHCP server and the DNS servers it gave (DHCP's own record: MugVPN never writes it).
    public var dhcp: [String]

    /// - global4/global6: State:/Network/Global/IPv4, IPv6; service4/6 and dhcp: the primary service's.
    /// - Returns: nil without a primary network, or while it is a tunnel's.
    public static func from(global4: [String: Any]?, global6: [String: Any]?, service4: [String: Any]?,
                            service6: [String: Any]?, dhcp: [String: Any]?) -> NetworkIdentity? {
        guard let g = global4 ?? global6, let ifname = g["PrimaryInterface"] as? String,
              !ifname.hasPrefix("utun"), !ifname.hasPrefix("lo") else { return nil }
        func strings(_ d: [String: Any]?, _ k: String) -> [String] { (d?[k] as? [String] ?? []).sorted() }
        func hex(_ v: Any?) -> String { (v as? Data).map { $0.map { String(format: "%02x", $0) }.joined() } ?? "" }
        return NetworkIdentity(
            interface: ifname,
            router: service4?["Router"] as? String ?? global4?["Router"] as? String ?? "",
            addresses: strings(service4, "Addresses"),
            router6: service6?["Router"] as? String ?? global6?["Router"] as? String ?? "",
            dhcp: [hex(dhcp?["Option_54"]), hex(dhcp?["Option_6"]), hex(dhcp?["Option_3"])])
    }
}

/// Decides when a change of state is a change of network (worth reconnecting the tunnels for).
public struct NetworkChangeDetector: Sendable {
    private var last: NetworkIdentity?
    public init() {}

    /// - Returns: true when the Mac is now on a different network than the last one it was on;
    ///   false for the first look, for no network, or for the same one (back after a moment without).
    public mutating func update(_ now: NetworkIdentity?) -> Bool {
        guard let now else { return false }
        defer { last = now }
        guard let before = last else { return false }
        return before != now
    }
}

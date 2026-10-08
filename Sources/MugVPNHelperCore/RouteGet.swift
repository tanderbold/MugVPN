import Foundation

/// Reading `route -n get` (macOS): the helper deletes a route only while it is in the
/// table exactly as added. `route get` answers with the best match, so the destination,
/// the mask (or prefix length) and the way out must all be the route's own.
public enum RouteGet {
    public static func matches(_ output: String, _ r: TunnelRoute) -> Bool {
        var fields: [String: String] = [:]
        for line in output.split(separator: "\n") {
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            if parts.count == 2, fields[parts[0]] == nil { fields[parts[0]] = parts[1] }
        }
        guard let dest = fields["destination"], let mask = fields["mask"] ?? (r.kind == .tunnel6 ? nil : "255.255.255.255") else {
            return false
        }
        if r.kind == .tunnel6 {
            guard dest == r.net || canonical6(dest) == canonical6(r.net), let bits = Int(r.mask), prefix6(mask) == bits else { return false }
        } else {
            // 0.0.0.0 is printed as "default", for the default route and def1's lower half alike.
            let d = dest == "default" ? "0.0.0.0" : dest
            let m = mask == "default" ? "0.0.0.0" : mask
            guard d == r.net, m == r.mask else { return false }
        }
        switch r.kind {
        case .tunnel, .tunnel6: return fields["interface"] == r.via && fields["gateway"] == nil
        case .onLink: return fields["interface"] == r.via && fields["gateway"] == nil
        case .host: return fields["gateway"] == r.via
        }
    }

    static func canonical6(_ s: String) -> [UInt8]? {
        var a = in6_addr()
        guard inet_pton(AF_INET6, s, &a) == 1 else { return nil }
        return withUnsafeBytes(of: &a) { Array($0) }
    }

    /// "ffff:ffff:ffff::" -> 48 (only contiguous masks).
    static func prefix6(_ mask: String) -> Int? {
        guard let bytes = canonical6(mask) else { return nil }
        var bits = 0, ended = false
        for b in bytes {
            for i in (0..<8).reversed() {
                if b & (1 << i) != 0 {
                    if ended { return nil }
                    bits += 1
                } else {
                    ended = true
                }
            }
        }
        return bits
    }
}

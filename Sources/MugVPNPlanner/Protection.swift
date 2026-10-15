import Foundation
import MugVPNCore

/// A kill switch's block: armed while its tunnel is up (it fires if the tunnel goes without being asked to), fired
/// once it did; traffic stays blocked until its owner (or an administrator) lifts it or connects the profile again.
public struct ProtectionLock: Codable, Equatable, Sendable {
    public var name: String
    public var owner: UInt32
    public var allowLAN: Bool = false
    /// Armed: its tunnel is up; it fires if the helper starts again without it (a crash).
    public var armed: Bool = false
    /// A persistent tunnel's: the whole Mac's traffic.
    public var everyone: Bool = false

    public init(name: String, owner: UInt32, allowLAN: Bool = false, armed: Bool = false, everyone: Bool = false) {
        self.name = name
        self.owner = owner
        self.allowLAN = allowLAN
        self.armed = armed
        self.everyone = everyone
    }
    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        name = try c.decode(String.self, forKey: .name)
        owner = try c.decode(UInt32.self, forKey: .owner)
        allowLAN = try c.decodeIfPresent(Bool.self, forKey: .allowLAN) ?? false
        armed = try c.decodeIfPresent(Bool.self, forKey: .armed) ?? false
        everyone = try c.decodeIfPresent(Bool.self, forKey: .everyone) ?? false
    }
}

/// One connection as protection sees it.
public struct ProtectionFacts: Sendable {
    public var id: String
    /// Its block's key, and the names an earlier block of its profile may carry.
    public var lockKey: String
    public var lockNames: [String]
    public var owner: UInt32
    public var persistent: Bool
    public var exited: Bool
    public var protection: ProtectionOptions
    public var takesAllTraffic: Bool
    /// It took all traffic at some point (its kill switch is armed from then on).
    public var wasFull: Bool
    /// Started again by its owner after its block: the block goes once it takes all traffic.
    public var liftsBlock: Bool
    /// Up with everything outside it blocked meanwhile (the App Store build's strict kill switch), split or not: its
    /// kill switch is armed, and its own block goes when it is up again, as for one taking all traffic. (Its IPv6 and
    /// DNS rules stay those of its routes.)
    public var blocksAllOutside: Bool
    public var device: String?
    /// A standard user's tunnel: only its owner's traffic may enter it.
    public var restricted: Bool
    /// Its DNS servers while its DNS is set.
    public var dnsServers: [String]

    public init(id: String, lockKey: String, lockNames: [String], owner: UInt32, persistent: Bool, exited: Bool,
                protection: ProtectionOptions, takesAllTraffic: Bool, wasFull: Bool, liftsBlock: Bool, device: String?,
                restricted: Bool, dnsServers: [String], blocksAllOutside: Bool = false) {
        self.id = id
        self.lockKey = lockKey
        self.lockNames = lockNames
        self.owner = owner
        self.persistent = persistent
        self.exited = exited
        self.protection = protection
        self.takesAllTraffic = takesAllTraffic
        self.wasFull = wasFull
        self.liftsBlock = liftsBlock
        self.device = device
        self.restricted = restricted
        self.dnsServers = dnsServers
        self.blocksAllOutside = blocksAllOutside
    }
}

/// What the kill switches, IPv6 and DNS protection must enforce, decided from the connections and the blocks: pure,
/// both products apply it (PF for MugVPN, the packet tunnel's settings for the App Store version).
public enum ProtectionPlanner {
    public static let maxLocksPerUser = 4
    public static let maxSuspend: TimeInterval = 300

    public static func suspendKey(_ l: ProtectionLock) -> String { "\(l.owner)/\(l.everyone)/\(l.name)" }

    /// Armings follow the tunnels up: one per name and user taking all traffic with a kill switch, the LAN open only
    /// if every such tunnel allows it.
    public static func arming(_ connections: [ProtectionFacts]) -> [ProtectionLock] {
        var want: [ProtectionLock] = []
        for c in connections.sorted(by: { $0.id < $1.id }) where !c.exited && c.protection.killSwitch && c.wasFull {
            if let i = want.firstIndex(where: { $0.name == c.lockKey && $0.owner == c.owner && $0.everyone == c.persistent }) {
                want[i].allowLAN = want[i].allowLAN && c.protection.allowLAN
            } else {
                want.append(ProtectionLock(name: c.lockKey, owner: c.owner, allowLAN: c.protection.allowLAN, armed: true,
                                           everyone: c.persistent))
            }
        }
        return want
    }

    /// The armings in `locks` replaced by `want`; nil when they are the same.
    public static func syncing(_ locks: [ProtectionLock], to want: [ProtectionLock]) -> [ProtectionLock]? {
        func key(_ l: ProtectionLock) -> String { "\(l.owner)/\(l.allowLAN)/\(l.everyone)/\(l.name)" }
        guard Set(locks.filter(\.armed).map(key)) != Set(want.map(key)) else { return nil }
        return locks.filter { !$0.armed } + want
    }

    /// A block added: armed and fired kept apart (one tunnel of a name dropping leaves another's arming); blocks of
    /// one name merged to the stricter (the LAN open only if all of them allow it); a user's oldest fired blocks go
    /// past the limit.
    public static func adding(_ l: ProtectionLock, to locks: [ProtectionLock]) -> [ProtectionLock] {
        var l = l, locks = locks
        func same(_ x: ProtectionLock) -> Bool { x.name == l.name && x.owner == l.owner && x.armed == l.armed && x.everyone == l.everyone }
        if let old = locks.first(where: same) { l.allowLAN = l.allowLAN && old.allowLAN }
        locks.removeAll(where: same)
        locks.append(l)
        while locks.filter({ $0.owner == l.owner && !$0.armed }).count > maxLocksPerUser,
              let i = locks.firstIndex(where: { $0.owner == l.owner && !$0.armed }) {
            locks.remove(at: i)
        }
        return locks
    }

    public struct Plan: Sendable {
        public var state: ProtectionState
        public var locks: [ProtectionLock]
        /// The blocks changed (to be saved).
        public var locksChanged: Bool
        public var suspended: [String: TimeInterval]
        /// Connections that now took all traffic, and those whose block-lifting is done.
        public var nowFull: Set<String>
        public var liftDone: Set<String>
    }

    /// What must be enforced now.
    public static func plan(_ connections: [ProtectionFacts], locks: [ProtectionLock], suspended: [String: TimeInterval],
                            now: TimeInterval) -> Plan {
        var s = ProtectionState()
        var locks = locks, changed = false
        var nowFull = Set<String>(), liftDone = Set<String>()
        var facts = connections
        for i in facts.indices {
            let c = facts[i]
            let full = c.takesAllTraffic
            // (What its kill switch guards: everything, through it or blocked.)
            let guarded = full || c.blocksAllOutside
            if let dev = c.device {
                s.tunnels.append(dev)
                if c.restricted {
                    s.ownTraffic.append(ProtectionState.OwnTunnel(device: dev, owner: c.owner, dnsServers: c.dnsServers))
                }
            }
            // Its own profile up again with all traffic: the block its drop left goes (the arming of a tunnel of that
            // name still up stays).
            if guarded, c.liftsBlock, !c.exited {
                liftDone.insert(c.id)
                facts[i].liftsBlock = false
                let fired = { (l: ProtectionLock) in c.lockNames.contains(l.name) && l.owner == c.owner && !l.armed && !l.everyone }
                if locks.contains(where: fired) {
                    locks.removeAll(where: fired)
                    changed = true
                }
            }
            guard c.protection.any else { continue }
            if guarded, !c.wasFull {
                facts[i].wasFull = true
                nowFull.insert(c.id)
            }
            // A persistent tunnel up again with all traffic: the block its drop left goes (nobody connects it by hand).
            if full, c.persistent, !c.exited {
                let fired = { (l: ProtectionLock) in l.everyone && !l.armed && l.name == c.lockKey }
                if locks.contains(where: fired) {
                    locks.removeAll(where: fired)
                    changed = true
                }
            }
            if full {
                s.blockIPv6 = s.blockIPv6 || c.protection.blockIPv6
                s.dnsOnlyTunnels = s.dnsOnlyTunnels || c.protection.dnsOnlyTunnel
            }
        }
        // Armed on disk: if the helper dies with the tunnel, the next one blocks.
        if let synced = syncing(locks, to: arming(facts)) {
            locks = synced
            changed = true
        }
        let live = suspended.filter { $0.value > now }
        s.locks = locks.filter { !$0.armed && live[suspendKey($0)] == nil }
            .map { ProtectionState.Lock(owner: $0.owner, allowLAN: $0.allowLAN, everyone: $0.everyone) }
        return Plan(state: s, locks: locks, locksChanged: changed, suspended: live, nowFull: nowFull, liftDone: liftDone)
    }

    /// Who may lift blocks for a while (to sign in to a network): an administrator all, a user their own, and only
    /// when every block on them can go. - Returns: the blocks to lift, or why not.
    public static func suspension(_ locks: [ProtectionLock], uid: UInt32, admin: Bool) -> Result<[ProtectionLock], ProtectionRefusal> {
        let mine = locks.filter { !$0.armed && (admin || $0.owner == uid) }
        guard !mine.isEmpty || locks.allSatisfy(\.armed) else { return .failure(ProtectionRefusal("only its owner or an administrator can lift the block")) }
        if !admin, locks.contains(where: { !$0.armed && $0.everyone }) {
            return .failure(ProtectionRefusal("a persistent connection blocks the Internet: only an administrator can lift that block"))
        }
        return .success(mine)
    }

    /// Lifting blocks: an administrator all of them, a user their own. - Returns: the blocks that stay, or why not.
    public static func unblocking(_ locks: [ProtectionLock], uid: UInt32, admin: Bool) -> Result<[ProtectionLock], ProtectionRefusal> {
        let fired = locks.filter { !$0.armed }
        guard admin || fired.contains(where: { $0.owner == uid }) || fired.isEmpty else {
            return .failure(ProtectionRefusal("only its owner or an administrator can lift the block"))
        }
        return .success(locks.filter { $0.armed || !(admin || $0.owner == uid) })
    }
}

public struct ProtectionRefusal: Error, Equatable, CustomStringConvertible {
    public let description: String
    public init(_ d: String) { description = d }
}

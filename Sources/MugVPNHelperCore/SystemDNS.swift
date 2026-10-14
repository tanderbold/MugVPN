import Foundation
import MugVPNPlanner

/// As much of the SystemConfiguration dynamic store as DNS needs (a fake in tests).
public protocol DNSStore {
    func value(_ key: String) -> [String: Any]?
    func set(_ key: String, _ value: [String: Any]) -> Bool
    /// True when the key is gone (or was never there).
    func remove(_ key: String) -> Bool
    func keys(matching pattern: String) -> [String]
}

/// What openvpn's macos-dns-updown.sh does, without a shell: split DNS as a supplemental resolver for
/// the tunnel; all names by replacing the primary service's DNS (kept to restore), one tunnel at a time.
public struct SystemDNS {
    /// In a backup: the service whose DNS it is (the primary may change before it is restored).
    public static let backupServiceKey = "MugVPNService"
    /// In a backup: what MugVPN set on that service (the last few), to tell its own setting from a newer one.
    public static let backupAppliedKey = "MugVPNApplied"
    let store: DNSStore
    let log: (String) -> Void

    public init(store: DNSStore, log: @escaping (String) -> Void = { _ in }) {
        self.store = store
        self.log = log
    }

    private func base(_ dev: String) -> String { "State:/Network/Service/openvpn-\(dev)" }

    public func set(_ plan: DNSPlan) -> DNSSet {
        let base = base(plan.device)
        if plan.split {
            var dns: [String: Any] = ["ServerAddresses": plan.servers, "SupplementalMatchDomains": plan.matchDomains,
                                      "SupplementalMatchDomainsNoSearch": 1]
            // Pushed search domains: short names get them (gitlab -> gitlab.corp.example).
            if !plan.searchDomains.isEmpty { dns["SearchDomains"] = plan.searchDomains }
            return store.set("\(base)/DNS", dns) ? .set : .failed
        }
        let backupKey = "\(base)/DnsBackup"
        let others = store.keys(matching: "State:/Network/Service/openvpn-.*/DnsBackup")
        guard others.allSatisfy({ $0 == backupKey }) else {
            log("DNS for all names is already another tunnel's: not set for \(plan.device)")
            return .failed
        }
        // Set again: the service its backup is of (the primary may have changed since).
        let existing = store.value(backupKey)
        guard let primary = existing?[SystemDNS.backupServiceKey] as? String
                ?? store.value("State:/Network/Global/IPv4")?["PrimaryService"] as? String else { return .failed }
        let key = "Setup:/Network/Service/\(primary)/DNS"
        var created = false
        if existing == nil {
            // An empty backup: the primary service had no DNS of its own (it came from DHCP).
            var backup = store.value(key) ?? [:]
            backup[SystemDNS.backupServiceKey] = primary
            guard store.set(backupKey, backup) else { return .failed }
            created = true
        }
        var dns: [String: Any] = ["ServerAddresses": plan.servers, "SearchOrder": 5000]
        if !plan.searchDomains.isEmpty { dns["SearchDomains"] = plan.searchDomains }
        // What it sets goes on record first (a crash after the write still finds it its own).
        if var backup = store.value(backupKey) {
            let applied = (backup[SystemDNS.backupAppliedKey] as? [[String: Any]] ?? []) + [dns]
            backup[SystemDNS.backupAppliedKey] = Array(applied.suffix(8))
            if !store.set(backupKey, backup) {
                if created, !store.remove(backupKey) { return .failedBackupLeft }
                return .failed
            }
        }
        guard store.set(key, dns) else {
            // Nothing set: a backup made just now goes (it would hold the next tunnel back); one from
            // before is the only copy of what to put back, and stays.
            if created, !store.remove(backupKey) {
                log("could not remove \(plan.device)'s DNS backup")
                return .failedBackupLeft
            }
            return .failed
        }
        return .set
    }

    /// The reverse for one device: `failed` while some of its DNS may still be in effect (the caller keeps it
    /// as set); `backupLeft` when its DNS is off but the backup stays (it holds all names back: removeBackup).
    public func restore(device dev: String) -> DNSRestore {
        let base = base(dev)
        guard store.remove("\(base)/DNS") else { return .failed }
        let backupKey = "\(base)/DnsBackup"
        guard var backup = store.value(backupKey) else { return .done }
        guard let primary = backup.removeValue(forKey: SystemDNS.backupServiceKey) as? String
                ?? store.value("State:/Network/Global/IPv4")?["PrimaryService"] as? String else { return .failed }
        let applied = backup.removeValue(forKey: SystemDNS.backupAppliedKey) as? [[String: Any]]
        // The service whose DNS was replaced, even if another is primary now. An empty backup: there was
        // no DNS of the service's own before.
        let key = "Setup:/Network/Service/\(primary)/DNS"
        // Changed since (the user, DHCP, a management profile): that setting stays; only MugVPN's own is replaced.
        let current = store.value(key)
        let ours = applied.map { a in a.contains { NSDictionary(dictionary: $0).isEqual(to: current ?? [:]) } } ?? true
        if !ours {
            log("the primary DNS changed while \(dev) had all names: left as it is")
            guard store.remove(backupKey) else { return .backupLeft }
            return .done
        }
        guard backup.isEmpty ? store.remove(key) : store.set(key, backup) else {
            log("could not restore the primary DNS from \(dev)'s backup")
            return .failed   // the backup stays: what to put back, and all names still held
        }
        log("restored the primary DNS from \(dev)'s backup")
        // Its DNS is off now. A backup that stays holds the next tunnel back from all names (refused, not
        // leaked) until removeBackup takes it.
        guard store.remove(backupKey) else {
            log("could not remove \(dev)'s DNS backup")
            return .backupLeft
        }
        return .done
    }

    /// Only the backup a restore left (its DNS is the Mac's own again).
    public func removeBackup(device dev: String) -> Bool { store.remove("\(base(dev))/DnsBackup") }
}

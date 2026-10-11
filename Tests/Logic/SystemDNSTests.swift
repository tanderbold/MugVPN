import Foundation
import MugVPNCore
import MugVPNHelperCore

/// The dynamic store as a dictionary; writes to keys in `failSet`/`failRemove` are refused.
final class FakeDNSStore: DNSStore {
    var values: [String: [String: Any]] = [:]
    var failSet: Set<String> = []
    var failRemove: Set<String> = []
    func value(_ key: String) -> [String: Any]? { values[key] }
    func set(_ key: String, _ value: [String: Any]) -> Bool {
        guard !failSet.contains(key) else { return false }
        values[key] = value
        return true
    }
    func remove(_ key: String) -> Bool {
        guard values[key] != nil else { return true }
        guard !failRemove.contains(key) else { return false }
        values[key] = nil
        return true
    }
    func keys(matching pattern: String) -> [String] {
        let re = try! NSRegularExpression(pattern: "^" + pattern + "$")
        return values.keys.filter { re.firstMatch(in: $0, range: NSRange($0.startIndex..., in: $0)) != nil }
    }
}

func registerSystemDNSTests() {
    let primaryKey = "Setup:/Network/Service/S1/DNS"
    let backupKey = "State:/Network/Service/openvpn-utun5/DnsBackup"
    func store() -> FakeDNSStore {
        let s = FakeDNSStore()
        s.values["State:/Network/Global/IPv4"] = ["PrimaryService": "S1"]
        s.values[primaryKey] = ["ServerAddresses": ["192.168.1.1"]]
        return s
    }
    let all = DNSPlan(device: "utun5", servers: ["10.8.0.53"], matchDomains: [], searchDomains: ["corp.lan"], split: false)
    test("SDNS-01", "all names set again, the primary's DNS refused: the backup from before stays (the only copy)") {
        let s = store()
        let dns = SystemDNS(store: s)
        expectEqual(dns.set(all), .set)
        s.failSet = [primaryKey]
        expectEqual(dns.set(all), .failed)
        expectEqual(s.values[backupKey]?["ServerAddresses"] as? [String], ["192.168.1.1"], "still there to put back")
    }
    test("SDNS-02", "all names refused at once: the backup made for it goes (it would hold the next tunnel back)") {
        let s = store()
        s.failSet = [primaryKey]
        expectEqual(SystemDNS(store: s).set(all), .failed)
        expect(s.values[backupKey] == nil)
    }
    test("SDNS-03", "set again after the primary service changed: the service its backup is of") {
        let s = store()
        let dns = SystemDNS(store: s)
        expectEqual(dns.set(all), .set)
        s.values["State:/Network/Global/IPv4"] = ["PrimaryService": "S2"]
        expectEqual(dns.set(all), .set)
        expect(s.values["Setup:/Network/Service/S2/DNS"] == nil, "not the new primary's")
        expectEqual(dns.restore(device: "utun5"), .done)
        expectEqual(s.values[primaryKey]?["ServerAddresses"] as? [String], ["192.168.1.1"])
    }
    test("SDNS-04", "restored, its backup not removable: its DNS is off (backup left); it holds all names back until removed") {
        let s = store()
        let dns = SystemDNS(store: s)
        expectEqual(dns.set(all), .set)
        s.failRemove = [backupKey]
        expectEqual(dns.restore(device: "utun5"), .backupLeft, "the primary's DNS is the Mac's own again")
        expectEqual(s.values[primaryKey]?["ServerAddresses"] as? [String], ["192.168.1.1"])
        let other = DNSPlan(device: "utun6", servers: ["10.9.0.53"], matchDomains: [], searchDomains: [], split: false)
        expectEqual(dns.set(other), .failed, "refused, not leaked")
        expect(!dns.removeBackup(device: "utun5"))
        s.failRemove = []
        expect(dns.removeBackup(device: "utun5"))
        expectEqual(dns.set(other), .set, "all names free again")
    }
    test("SDNS-05", "what could not be taken off is said: its resolver, or the primary's DNS not put back") {
        let s = store()
        let dns = SystemDNS(store: s)
        let split = DNSPlan(device: "utun5", servers: ["10.8.0.53"], matchDomains: ["corp.lan"], searchDomains: [], split: true)
        expectEqual(dns.set(split), .set)
        s.failRemove = ["State:/Network/Service/openvpn-utun5/DNS"]
        expectEqual(dns.restore(device: "utun5"), .failed)
        s.failRemove = []
        expectEqual(dns.restore(device: "utun5"), .done)
        expectEqual(dns.set(all), .set)
        s.failSet = [primaryKey]
        expectEqual(dns.restore(device: "utun5"), .failed)
        expect(s.values[backupKey] != nil, "kept: what to put back")
    }
    test("SDNS-06", "all names refused after its backup was made, and the backup not removable: said (it holds all names back)") {
        let s = store()
        s.failSet = [primaryKey]
        s.failRemove = [backupKey]
        expectEqual(SystemDNS(store: s).set(all), .failedBackupLeft)
    }
    test("SDNS-07", "split DNS keeps its search domains (short names get the company's suffix)") {
        let s = store()
        let split = DNSPlan(device: "utun5", servers: ["10.8.0.53"], matchDomains: ["corp.lan"], searchDomains: ["corp.lan"], split: true)
        expectEqual(SystemDNS(store: s).set(split), .set)
        expectEqual(s.values["State:/Network/Service/openvpn-utun5/DNS"]?["SearchDomains"] as? [String], ["corp.lan"])
    }
    test("SDNS-08", "the Mac's DNS changed while the VPN had all names (the user, DHCP, MDM): left as changed, not put back") {
        let s = store()
        let dns = SystemDNS(store: s)
        expectEqual(dns.set(all), .set)
        s.values[primaryKey] = ["ServerAddresses": ["9.9.9.9"]]
        expectEqual(dns.restore(device: "utun5"), .done)
        expectEqual(s.values[primaryKey]?["ServerAddresses"] as? [String], ["9.9.9.9"], "the newer setting kept")
        expect(s.values[backupKey] == nil, "the backup goes")
    }
    test("SDNS-09", "set again with other servers, then taken off: the Mac's own DNS back (any of what it set counts as its)") {
        let s = store()
        let dns = SystemDNS(store: s)
        expectEqual(dns.set(all), .set)
        var other = all
        other.servers = ["10.8.0.54"]
        expectEqual(dns.set(other), .set)
        expectEqual(dns.restore(device: "utun5"), .done)
        expectEqual(s.values[primaryKey]?["ServerAddresses"] as? [String], ["192.168.1.1"])
        // A second set refused after the record of it: what was there is still taken as its own.
        expectEqual(dns.set(all), .set)
        s.failSet = [primaryKey]
        expectEqual(dns.set(other), .failed)
        s.failSet = []
        expectEqual(dns.restore(device: "utun5"), .done)
        expectEqual(s.values[primaryKey]?["ServerAddresses"] as? [String], ["192.168.1.1"])
    }
}

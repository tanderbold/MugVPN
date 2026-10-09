import Foundation

/// Connections asked for while their certificate is still being checked: one check for all of
/// them, and a disconnect in the meantime means no start.
public struct PendingStarts: Sendable {
    private var waiting: [String: Bool] = [:]   // id → still wanted
    public init() {}

    /// - Returns: true for the first ask (it starts the check); later ones wait for that check.
    public mutating func begin(_ id: String) -> Bool {
        if waiting[id] != nil { waiting[id] = true; return false }
        waiting[id] = true
        return true
    }
    public func isPending(_ id: String) -> Bool { waiting[id] == true }
    public mutating func cancel(_ id: String) { if waiting[id] != nil { waiting[id] = false } }
    public mutating func cancelAll() { for k in waiting.keys { waiting[k] = false } }
    /// The check is done. - Returns: whether to connect now (nil: nothing was waiting).
    public mutating func finish(_ id: String) -> Bool? { waiting.removeValue(forKey: id) }
}

import Foundation

/// Notifications ask the system's permission when the first one is to be shown (its use is clear
/// then), not at launch; what comes meanwhile waits for the answer.
public final class NotificationGate {
    private let ask: (@escaping (Bool) -> Void) -> Void
    private let post: (String) -> Void
    private var allowed: Bool?
    private var asking = false
    private var waiting: [String] = []

    /// - ask: the system's prompt (once); - post: show one (here as an opaque payload).
    public init(ask: @escaping (@escaping (Bool) -> Void) -> Void, post: @escaping (String) -> Void) {
        self.ask = ask
        self.post = post
    }

    public func notify(_ payload: String) {
        if let allowed { if allowed { post(payload) }; return }
        waiting.append(payload)
        guard !asking else { return }
        asking = true
        ask { [weak self] ok in
            guard let self else { return }
            self.allowed = ok
            let w = self.waiting
            self.waiting = []
            if ok { w.forEach(self.post) }
        }
    }
}

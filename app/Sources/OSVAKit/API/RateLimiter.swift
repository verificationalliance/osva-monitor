import Foundation

/// Keeps the app under the server's per-client limits (formalinformer/api/server.py): 30 checks a minute (single and
/// batch alike) and 120 other requests a minute. The app takes less than half of each, so a person using the site
/// from the same address is not slowed down by it.
public actor RateLimiter {
    public enum Budget: Sendable { case check, read }

    private struct Bucket {
        var tokens: Double
        let capacity: Double
        let perSecond: Double
        var updated: ContinuousClock.Instant
    }

    private var buckets: [Budget: Bucket]
    private let clock = ContinuousClock()

    public init(checksPerMinute: Double = 12, readsPerMinute: Double = 50) {
        let now = ContinuousClock.now
        buckets = [
            .check: Bucket(tokens: checksPerMinute, capacity: checksPerMinute, perSecond: checksPerMinute / 60, updated: now),
            .read: Bucket(tokens: readsPerMinute, capacity: readsPerMinute, perSecond: readsPerMinute / 60, updated: now),
        ]
    }

    /// Waits until the budget allows one more request, then takes it.
    public func acquire(_ budget: Budget) async {
        while true {
            var b = buckets[budget]!
            let now = clock.now
            let elapsed = b.updated.duration(to: now)
            let seconds = Double(elapsed.components.seconds) + Double(elapsed.components.attoseconds) / 1e18
            b.tokens = min(b.capacity, b.tokens + seconds * b.perSecond)
            b.updated = now
            if b.tokens >= 1 {
                b.tokens -= 1
                buckets[budget] = b
                return
            }
            buckets[budget] = b
            let wait = (1 - b.tokens) / b.perSecond
            try? await Task.sleep(for: .milliseconds(Int(wait * 1000) + 10))
        }
    }
}

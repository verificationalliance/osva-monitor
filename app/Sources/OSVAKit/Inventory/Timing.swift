import Foundation

extension Duration {
    /// The duration in seconds, for a source's report.
    var seconds: Double { Double(components.seconds) + Double(components.attoseconds) / 1e18 }
}

/// How long a source took: its report says, so a slow source shows up.
enum Stopwatch {
    static func time<T>(_ body: () async -> T) async -> (value: T, seconds: Double) {
        let clock = ContinuousClock(), start = clock.now
        let value = await body()
        return (value, (clock.now - start).seconds)
    }
}

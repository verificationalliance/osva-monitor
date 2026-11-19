import Foundation

/// Answers kept on disk for a while (Application Support/OSVA Monitor/cache), so that a rescan does not ask about the
/// same exact versions again: fewer requests, and less said about this Mac.
public struct DiskCache: Sendable {
    public let directory: URL
    public init(directory: URL) { self.directory = directory }

    public func read(_ namespace: String, _ key: String, maxAge: TimeInterval, now: Date = Date()) -> Data? {
        let url = file(namespace, key)
        guard let modified = (try? url.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate,
              now.timeIntervalSince(modified) < maxAge else { return nil }
        return try? Data(contentsOf: url)
    }

    public func write(_ namespace: String, _ key: String, _ data: Data) {
        let url = file(namespace, key)
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? data.write(to: url, options: .atomic)
    }

    public func readJSON<T: Decodable>(_ type: T.Type, _ namespace: String, _ key: String, maxAge: TimeInterval) -> T? {
        read(namespace, key, maxAge: maxAge).flatMap { try? JSONDecoder().decode(type, from: $0) }
    }

    public func writeJSON<T: Encodable>(_ value: T, _ namespace: String, _ key: String) {
        if let data = try? JSONEncoder().encode(value) { write(namespace, key, data) }
    }

    private func file(_ namespace: String, _ key: String) -> URL {
        // FNV-1a: a stable file name for any key, with no characters a file system could object to.
        var h: UInt64 = 0xcbf2_9ce4_8422_2325
        for b in key.utf8 { h = (h ^ UInt64(b)) &* 0x0000_0100_0000_01b3 }
        return directory.appendingPathComponent(namespace, isDirectory: true).appendingPathComponent(String(format: "%016llx.json", h))
    }
}

import Foundation

/// Keeps the public index on disk (Application Support/OSVA Monitor/app-index.tsv) and refreshes it once a day (and
/// before a scan when it is older than that) with a conditional request (If-None-Match / If-Modified-Since), so an
/// unchanged index costs one small response. The server sends it gzip-compressed; URLSession decompresses it.
public actor IndexStore {
    private struct Meta: Codable {
        var etag: String?
        var lastModified: String?
        var fetchedAt: Date
    }

    public struct Loaded: Sendable {
        public var index: PublicIndex
        /// Set when the index could not be refreshed and an older copy is used.
        public var problem: String?
    }

    private let directory: URL
    private let transport: any HTTPTransport
    private var memo: (stamp: String, index: PublicIndex)?

    public init(directory: URL, transport: any HTTPTransport) {
        self.directory = directory; self.transport = transport
    }

    private var dataURL: URL { directory.appendingPathComponent("app-index.tsv") }
    private var metaURL: URL { directory.appendingPathComponent("app-index.meta.json") }

    public func load(maxAge: TimeInterval = 86_400, now: Date = Date()) async throws -> Loaded {
        let fm = FileManager.default
        try fm.createDirectory(at: directory, withIntermediateDirectories: true)
        for old in ["lookup.json", "lookup.meta.json"] {           // the index format before app-index.tsv
            try? fm.removeItem(at: directory.appendingPathComponent(old))
        }
        var meta = (try? Data(contentsOf: metaURL)).flatMap { try? JSONDecoder().decode(Meta.self, from: $0) }
        let haveCopy = fm.fileExists(atPath: dataURL.path) && meta != nil
        if haveCopy, let m = meta, now.timeIntervalSince(m.fetchedAt) < maxAge {
            return Loaded(index: try parsed(stamp: m), problem: nil)
        }
        var request = URLRequest(url: SiteURL.index)
        request.setValue(HTTPHeaders.userAgent, forHTTPHeaderField: "User-Agent")
        request.setValue("gzip", forHTTPHeaderField: "Accept-Encoding")
        if haveCopy, let m = meta {
            if let e = m.etag { request.setValue(e, forHTTPHeaderField: "If-None-Match") }
            if let l = m.lastModified { request.setValue(l, forHTTPHeaderField: "If-Modified-Since") }
        }
        do {
            let (data, response) = try await transport.send(request)
            if response.statusCode == 304, haveCopy, var m = meta {
                m.fetchedAt = now
                try JSONEncoder().encode(m).write(to: metaURL, options: .atomic)
                return Loaded(index: try parsed(stamp: m), problem: nil)
            }
            guard response.statusCode == 200 else { throw APIClient.APIError.http(status: response.statusCode, message: "") }
            let index = try PublicIndex.decode(data)                  // never replace a good copy with a bad one
            try data.write(to: dataURL, options: .atomic)
            meta = Meta(etag: response.value(forHTTPHeaderField: "ETag"),
                        lastModified: response.value(forHTTPHeaderField: "Last-Modified"), fetchedAt: now)
            try JSONEncoder().encode(meta).write(to: metaURL, options: .atomic)
            memo = (Self.stamp(meta!), index)
            return Loaded(index: index, problem: nil)
        } catch {
            guard haveCopy, let m = meta else { throw error }
            let age = RelativeDateTimeFormatter().localizedString(for: m.fetchedAt, relativeTo: now)
            return Loaded(index: try parsed(stamp: m), problem: "Could not refresh the public index; using the copy from \(age).")
        }
    }

    private func parsed(stamp meta: Meta) throws -> PublicIndex {
        let stamp = Self.stamp(meta)
        if let memo, memo.stamp == stamp { return memo.index }
        let index = try PublicIndex.decode(Data(contentsOf: dataURL))
        memo = (stamp, index)
        return index
    }

    private static func stamp(_ m: Meta) -> String { "\(m.etag ?? "")|\(m.lastModified ?? "")" }
}

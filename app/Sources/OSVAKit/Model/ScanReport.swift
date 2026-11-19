import Foundation

/// One request that carried something about this Mac's software to the server.
public struct SentRequest: Hashable, Codable, Sendable {
    /// "POST api/v1/check/batch", "GET api/v1/check", "GET api/v1/project".
    public var endpoint: String
    /// What it named, one entry per package or project: "PyPI urllib3 1.26.5", "project openssl".
    public var items: [String]

    public init(endpoint: String, items: [String]) { self.endpoint = endpoint; self.items = items }
}

/// Exactly what left this Mac in one scan ("What leaves your Mac" in Settings), and what did not.
public struct SentRecord: Hashable, Codable, Sendable {
    public var requests: [SentRequest] = []
    /// Installed packages not in the public index, and Homebrew packages with no graded project: never sent anywhere.
    /// The number of distinct names in `withheld` before it was cut to `listLimit`.
    public var withheldCount: Int = 0
    /// Packages and projects already checked recently, answered from the local cache: not sent again.
    public var answeredFromCache: Int = 0
    /// What the cache answered, as it was named when it was sent: "PyPI urllib3 1.26.5 · Python 3.9.6 · macOS",
    /// "project openssl". At most `listLimit`.
    public var cached: [String] = []
    /// What was never sent, by where it was found ("Homebrew", "pip", "Folders"): "six 1.15.0". These stay on this Mac;
    /// the list is kept so Settings can show them. At most `listLimit` in all.
    public var withheld: [Coverage.Bucket] = []

    /// The most names a list keeps, so a huge lockfile cannot make the saved report huge. The counts stay exact.
    public static let listLimit = 10_000

    public init(requests: [SentRequest] = [], withheldCount: Int = 0, answeredFromCache: Int = 0, cached: [String] = [],
                withheld: [Coverage.Bucket] = []) {
        self.requests = requests; self.withheldCount = withheldCount; self.answeredFromCache = answeredFromCache
        self.cached = Array(cached.prefix(Self.listLimit)); self.withheld = Self.cut(withheld, to: Self.listLimit)
    }

    public init(from decoder: Decoder) throws {                  // reports saved before the lists were kept
        let c = try decoder.container(keyedBy: CodingKeys.self)
        requests = try c.decode([SentRequest].self, forKey: .requests)
        withheldCount = try c.decode(Int.self, forKey: .withheldCount)
        answeredFromCache = try c.decode(Int.self, forKey: .answeredFromCache)
        cached = Array((try c.decodeIfPresent([String].self, forKey: .cached) ?? []).prefix(Self.listLimit))
        withheld = Self.cut(try c.decodeIfPresent([Coverage.Bucket].self, forKey: .withheld) ?? [], to: Self.listLimit)
    }

    /// The buckets in order, keeping at most `limit` items in all; empty buckets are dropped.
    static func cut(_ buckets: [Coverage.Bucket], to limit: Int) -> [Coverage.Bucket] {
        var left = limit, out: [Coverage.Bucket] = []
        for b in buckets where left > 0 && !b.items.isEmpty {
            out.append(Coverage.Bucket(source: b.source, items: Array(b.items.prefix(left))))
            left -= out[out.count - 1].items.count
        }
        return out
    }

    /// Every distinct item named, in the order first sent.
    public var distinctItems: [String] {
        var seen = Set<String>(), out: [String] = []
        for r in requests { for i in r.items where seen.insert(i).inserted { out.append(i) } }
        return out
    }
}

/// What a scan could not vouch for, told honestly rather than counted as clean.
public struct Coverage: Codable, Sendable, Hashable {
    /// A list under one heading: the source ("pip", "Homebrew") and its items ("six 1.15.0").
    public struct Bucket: Codable, Sendable, Hashable, Identifiable {
        public var source: String
        public var items: [String]
        /// For a list of apps (or of what apps bundle), each item's app bundle, in the same order, for its icon ("" when
        /// not known).
        public var paths: [String]?
        public var id: String { source }
        public init(source: String, items: [String], paths: [String]? = nil) {
            self.source = source; self.items = items; self.paths = paths.flatMap { $0.count == items.count ? $0 : nil }
        }
    }

    /// Checkable packages that are not in the public index: nothing has ever been reported about them. That is no
    /// known problem, not proof of safety.
    public var notInIndex: [Bucket] = []
    /// What the app cannot classify at all: Homebrew packages with no graded project, apps that do not
    /// bundle Electron, packages of registries the site does not check.
    public var notChecked: [Bucket] = []
    /// Apps something else keeps up to date (the App Store, macOS, the browser a web app runs in). Not checked here
    /// either, and said so; listed apart from the apps nobody is known to look after.
    public var updatedElsewhere: [Bucket] = []

    public init(notInIndex: [Bucket] = [], notChecked: [Bucket] = [], updatedElsewhere: [Bucket] = []) {
        self.notInIndex = notInIndex; self.notChecked = notChecked; self.updatedElsewhere = updatedElsewhere
    }

    public init(from decoder: Decoder) throws {                  // reports saved before apps were told apart
        let c = try decoder.container(keyedBy: CodingKeys.self)
        notInIndex = try c.decodeIfPresent([Bucket].self, forKey: .notInIndex) ?? []
        notChecked = try c.decodeIfPresent([Bucket].self, forKey: .notChecked) ?? []
        updatedElsewhere = try c.decodeIfPresent([Bucket].self, forKey: .updatedElsewhere) ?? []
    }

    public var notInIndexCount: Int { notInIndex.reduce(0) { $0 + $1.items.count } }
    public var notCheckedCount: Int { notChecked.reduce(0) { $0 + $1.items.count } }
    public var updatedElsewhereCount: Int { updatedElsewhere.reduce(0) { $0 + $1.items.count } }
}

/// The result of one scan, kept on disk so the popover has something to show at launch.
public struct ScanReport: Codable, Sendable, Hashable {
    public var startedAt: Date
    public var finishedAt: Date
    public var inventory: Inventory
    public var findings: [Finding]
    public var sent: SentRecord
    /// When the public index the scan used was generated.
    public var indexGeneratedAt: String?
    /// Problems worth showing ("could not reach verificationalliance.org"); the scan still shows what it could check.
    public var problems: [String]
    public var coverage: Coverage

    public init(startedAt: Date, finishedAt: Date, inventory: Inventory, findings: [Finding], sent: SentRecord,
                indexGeneratedAt: String?, problems: [String], coverage: Coverage = Coverage()) {
        self.startedAt = startedAt; self.finishedAt = finishedAt; self.inventory = inventory; self.findings = findings
        self.sent = sent; self.indexGeneratedAt = indexGeneratedAt; self.problems = problems; self.coverage = coverage
    }

    /// Findings that need action (malicious, exploited, critical or high): the number beside the menu-bar shield.
    public var actionCount: Int { findings.filter { $0.group.needsAction }.count }
}

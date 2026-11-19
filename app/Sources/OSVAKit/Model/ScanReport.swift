import Foundation

/// One request that carried something about this Mac's software to the server.
public struct SentRequest: Hashable, Codable, Sendable {
    /// "POST api/v1/check/batch", "GET api/v1/check", "GET api/v1/project".
    public var endpoint: String
    /// What it named, one entry per package or project: "PyPI urllib3 1.26.5", "project openssl".
    public var items: [String]

    public init(endpoint: String, items: [String]) { self.endpoint = endpoint; self.items = items }
}

/// Exactly what left this Mac in one scan ("What leaves your Mac" in Settings).
public struct SentRecord: Hashable, Codable, Sendable {
    public var requests: [SentRequest] = []
    /// Installed packages not in the public index: never sent anywhere.
    public var withheldCount: Int = 0
    /// Packages already checked recently, answered from the local cache: not sent again.
    public var answeredFromCache: Int = 0

    public init(requests: [SentRequest] = [], withheldCount: Int = 0, answeredFromCache: Int = 0) {
        self.requests = requests; self.withheldCount = withheldCount; self.answeredFromCache = answeredFromCache
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
        public var id: String { source }
        public init(source: String, items: [String]) { self.source = source; self.items = items }
    }

    /// Checkable packages that are not in the public index: nothing has ever been reported about them. That is no
    /// known problem, not proof of safety.
    public var notInIndex: [Bucket] = []
    /// What the app cannot classify at all: Homebrew packages with no graded project, apps that do not
    /// bundle Electron, packages of registries the site does not check.
    public var notChecked: [Bucket] = []

    public init(notInIndex: [Bucket] = [], notChecked: [Bucket] = []) { self.notInIndex = notInIndex; self.notChecked = notChecked }

    public var notInIndexCount: Int { notInIndex.reduce(0) { $0 + $1.items.count } }
    public var notCheckedCount: Int { notChecked.reduce(0) { $0 + $1.items.count } }
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

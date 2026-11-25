import Foundation

/// Severity as the site rates it.
public enum Severity: String, Codable, Sendable, CaseIterable, Comparable {
    case low = "LOW", moderate = "MODERATE", high = "HIGH", critical = "CRITICAL"

    /// Reads the API's spellings ("MODERATE", "MEDIUM", "high" ...). Nil for empty or unknown.
    public init?(api: String?) {
        switch (api ?? "").uppercased() {
        case "CRITICAL": self = .critical
        case "HIGH": self = .high
        case "MODERATE", "MEDIUM": self = .moderate
        case "LOW": self = .low
        default: return nil
        }
    }

    public var label: String {
        switch self { case .critical: return "Critical"; case .high: return "High"; case .moderate: return "Moderate"; case .low: return "Low" }
    }

    private var rank: Int { Severity.allCases.firstIndex(of: self)! }
    public static func < (a: Severity, b: Severity) -> Bool { a.rank < b.rank }
}

/// How much of a project is formally verified, read the way the site reads it (`vtier` in site/formalinformer/app.js).
public enum Verification: String, Codable, Sendable {
    case none
    /// Contains formally verified parts; the project as a whole is not verified (the dashed check).
    case parts
    /// Formally verified as a whole (the filled check).
    case whole

    public var explanation: String {
        switch self {
        case .none: return ""
        case .parts: return "Contains formally verified parts; the project as a whole is not verified"
        case .whole: return "Formally verified as a whole"
        }
    }
}

/// A flaw the suggested upgrade does not fix here, and why: information, not a failure.
public struct UnresolvedFlaw: Hashable, Codable, Sendable {
    public enum Reason: String, Codable, Sendable { case needsPython, otherPlatform, noFix, unknown }
    public var id: String
    public var severity: Severity?
    public var fixedIn: String?
    public var reason: Reason
    /// "Python >=3.10", "Windows".
    public var detail: String?
    /// The version of the Python the package is installed in, when known.
    public var python: String?
    /// Whether the package runs on this Mac (installed software), rather than being a project's dependency.
    public var onThisMac: Bool
    /// The advisory's one-line summary ("ChromaDB has a code injection vulnerability"), so that two flaws with the same
    /// reason ("Windows only") are not read as one listed twice. Nil when the answer has none (the API sends at most
    /// 40 flaws per package); the row then names the flaw by its id.
    public var summary: String?

    public init(id: String, severity: Severity?, fixedIn: String?, reason: Reason, detail: String?, python: String? = nil, onThisMac: Bool = true,
                summary: String? = nil) {
        self.id = id; self.severity = severity; self.fixedIn = fixedIn; self.reason = reason; self.detail = detail
        self.python = python; self.onThisMac = onThisMac; self.summary = summary
    }

    /// The flaw's name for its line: the summary, else the id.
    public var name: String { summary ?? id }

    /// "Fixed in 83.0.0, which needs Python ≥3.10; this Python is 3.9.6", "Windows only, does not affect this Mac",
    /// "No fixed release yet".
    public var explanation: String {
        switch reason {
        case .needsPython:
            let needs = (detail ?? "a newer Python").replacingOccurrences(of: ">=", with: "≥")
            let this = python.map { "; this Python is \($0)" } ?? ""
            return (fixedIn.map { "Fixed in \($0), which needs " } ?? "Needs ") + needs + this
        case .otherPlatform:
            let platform = detail.map { $0.prefix(1).uppercased() + $0.dropFirst() } ?? "Another platform"
            return onThisMac ? "\(platform) only, does not affect this Mac" : "\(platform) only"
        case .noFix:
            return "No fixed release yet"
        case .unknown:
            return fixedIn.map { "Fixed in \($0), not by this upgrade" } ?? "Not fixed by this upgrade"
        }
    }

    /// Whether it can affect this Mac at all.
    public var affectsThisMac: Bool { !(reason == .otherPlatform && onThisMac) }
}

/// Something installed on this Mac that the site knows to be wrong.
public struct Finding: Identifiable, Hashable, Codable, Sendable {
    /// The popover's groups, in the order they are shown. The raw values are what saved reports hold: 0-3 are the
    /// groups of 0.5.1 and before, and the new ones come after them.
    public enum Group: Int, Codable, Sendable, CaseIterable, Comparable {
        case malicious = 0, exploited = 1, criticalHigh = 2, other = 3
        /// No published ranges, and the first fixed versions say the version is affected (`Check.likely`).
        case likely = 4
        /// The site reports it, but the app did not check it against published ranges (`Check.reported`).
        case reported = 5

        public var title: String {
            switch self {
            case .malicious: return "Malicious"
            case .exploited: return "Exploited in the wild"
            case .criticalHigh: return "Critical and high"
            case .other: return "Other"
            case .likely, .reported: return "Not checked against published ranges"
            }
        }

        /// The popover's sections, in the order they are shown: what needs action, what the core could not check
        /// against published ranges, then Other. Likely and reported share one section, keyed `.likely` (`section`).
        public static let sections: [Group] = [.malicious, .exploited, .criticalHigh, .likely, .other]

        /// The section a finding of this group is shown in.
        public var section: Group { isNotChecked ? .likely : self }

        /// Groups that call for action now; they decide the menu-bar icon and the count beside it. Only what the core
        /// checked is counted: never `likely` or `reported`.
        public var needsAction: Bool { self == .malicious || self == .exploited || self == .criticalHigh }

        /// Not checked against published ranges: likely affected, or reported.
        public var isNotChecked: Bool { self == .likely || self == .reported }

        /// How urgent the group is, lower first: the groups that call for action in their order, and every other group
        /// (Other, likely, reported) the same, since none of them calls for action.
        public var urgency: Int { needsAction ? rawValue : Group.other.rawValue }

        public static func < (a: Group, b: Group) -> Bool { a.rawValue < b.rawValue }
    }

    /// How a finding's flaws were checked against the ranges the site publishes (BatchCheck): affected when the core
    /// finds the version inside one, likely when there are none and the first fixed versions say so, else reported.
    public enum Check: String, Codable, Sendable { case affected, likely, reported }

    /// The most urgent flaw of a finding that the app did not check against published ranges (likely affected, or
    /// reported), when it is exploited in the wild or critical. Never counted and never fixed by a version, but never
    /// silent either: an exploited one makes the finding notify, and either marks its row.
    public struct NotChecked: Hashable, Codable, Sendable {
        /// The flaw's id ("CVE-2026-1"); nil for a critical flaw past the list the server sends, which it does not name.
        public var id: String?
        public var exploited: Bool
        public var critical: Bool

        public init(id: String?, exploited: Bool, critical: Bool) { self.id = id; self.exploited = exploited; self.critical = critical }

        /// The more urgent of two: exploited first, then critical; the first on a tie.
        public static func worse(_ a: NotChecked?, _ b: NotChecked?) -> NotChecked? {
            func rank(_ x: NotChecked?) -> Int { x.map { ($0.exploited ? 2 : 0) + ($0.critical ? 1 : 0) } ?? -1 }
            return rank(b) > rank(a) ? b : a
        }

        /// "critical, exploited in the wild", "exploited in the wild", "critical".
        public var words: String { exploited && critical ? "critical, exploited in the wild" : exploited ? "exploited in the wild" : "critical" }
    }

    public enum Subject: Hashable, Codable, Sendable {
        /// A registry package, checked at its exact version.
        case package(ecosystem: Ecosystem, name: String)
        /// A project our site grades (matched from Homebrew), checked against its recent advisories.
        case project(slug: String, name: String, installedAs: String)
        /// An app or a library bundled in one, checked against its product record's recent advisories.
        case product(key: String, name: String)
        /// An editor or browser extension its store reported as malicious.
        case addOn(store: String, id: String)
    }

    public var id: String
    public var group: Group
    public var subject: Subject
    /// The name to show: the package's, the project's, or the app's (for an app that bundles Electron).
    public var title: String
    /// Set when the version is not the titled thing's own: "Electron" for an app that bundles it.
    public var component: String?
    public var installedVersion: String
    /// The version to upgrade to, when the verified core checked one, as the app shows it (`CheckedUpgrade.display`).
    /// Set only from a `CheckedUpgrade` (the initialiser, `setUpgrade`); a report saved on disk keeps the one it was made
    /// with.
    public private(set) var fixedVersion: String?
    public var severity: Severity?
    public var advisoryIDs: [String]
    /// How many distinct flaws (advisories describing the same flaw count once).
    public var flawCount: Int
    public var exploited: Bool
    public var malicious: Bool
    /// One line of context: "likely affected: the issuer names 3.5.10 as fixed", or how this place is upgraded. Set by the
    /// initialiser and only added to (`addNote`), never replaced.
    public private(set) var note: String?
    /// How many of its flaws the upgrade to `fixedVersion` fixes (when the server's plan says).
    public var fixesCount: Int?
    /// The flaws that upgrade does not fix here, with the reason.
    public var unresolved: [UnresolvedFlaw]
    /// Set when it matches the site's "patch these first" list.
    public var bigIssue: String?
    public var origins: [Origin]
    public var pageURL: URL
    /// The command to paste into Terminal, as UpgradeCommand wrote it: set only from an `UpgradeCommand.Advice` (the
    /// initialiser, `setAdvice`); a report saved on disk keeps the one it was made with.
    public private(set) var upgradeCommand: String?
    /// What `upgradeCommand` was made from. The Fix button makes the command again from these and runs it only if it
    /// is exactly `upgradeCommand` (nil in reports saved before the button existed: they get no button until rescanned).
    public var commandInputs: UpgradeCommand.Inputs?
    public var verification: Verification
    public var grade: String?
    /// Where each copy is on this Mac and why it is there, one per copy (nil in reports saved before, or when nothing
    /// could be told). Read from local files after the API was asked; never sent.
    public var provenance: [Provenance]? = nil
    /// An exploited or critical flaw the app did not check against published ranges (nil in reports saved before).
    public var notChecked: NotChecked? = nil
    /// A program's finding with nothing to do on this Mac, every flaw of another platform or outside its published ranges:
    /// listed (nil otherwise, and in reports saved before). It never weighs in the app's finding it is folded into.
    public var onlyElsewhere: Bool? = nil
    /// Every flaw the site reports for it lies outside its published ranges, in the core's order: checked, the version
    /// clear, listed in Other with nothing to do (nil otherwise, and in reports saved before).
    public var outsideItsRanges: Bool? = nil

    /// Listed with nothing to do on this Mac: every flaw lies outside its published ranges, or is of another platform.
    /// Such a finding is never counted, never a lower-severity finding, and never "still affected" after a fix.
    public var affectsNothingHere: Bool { outsideItsRanges == true || onlyElsewhere == true }

    /// A finding whose version to upgrade to is one the core checked (`upgrade.display`), or none, and whose command is
    /// UpgradeCommand's (`advice.command`), or none.
    public init(id: String, group: Group, subject: Subject, title: String, component: String? = nil, installedVersion: String,
                upgrade: CheckedUpgrade?, severity: Severity?, advisoryIDs: [String], flawCount: Int, exploited: Bool, malicious: Bool,
                note: String?, bigIssue: String?, origins: [Origin], pageURL: URL, advice: UpgradeCommand.Advice?,
                verification: Verification, grade: String?, fixesCount: Int? = nil, unresolved: [UnresolvedFlaw] = [],
                commandInputs: UpgradeCommand.Inputs? = nil, notChecked: NotChecked? = nil) {
        self.id = id; self.group = group; self.subject = subject; self.title = title; self.component = component
        self.installedVersion = installedVersion
        self.fixedVersion = upgrade?.display; self.severity = severity; self.advisoryIDs = advisoryIDs; self.flawCount = flawCount
        self.exploited = exploited; self.malicious = malicious; self.note = note; self.bigIssue = bigIssue
        self.origins = origins; self.pageURL = pageURL; self.upgradeCommand = advice?.command
        self.verification = verification; self.grade = grade
        self.fixesCount = fixesCount; self.unresolved = unresolved; self.commandInputs = commandInputs; self.notChecked = notChecked
    }

    /// The version to upgrade to, from one the core checked, or none.
    public mutating func setUpgrade(_ upgrade: CheckedUpgrade?) { fixedVersion = upgrade?.display }

    /// The command, from UpgradeCommand's advice, or none.
    public mutating func setAdvice(_ advice: UpgradeCommand.Advice?) { upgradeCommand = advice?.command }

    /// One more sentence for the note: after it, or `first`, before it.
    public mutating func addNote(_ sentence: String?, first: Bool = false) {
        guard let sentence else { return }
        note = note.map { first ? sentence + " " + $0 : $0 + " " + sentence } ?? sentence
    }

    public var ecosystem: Ecosystem? {
        if case let .package(ecosystem, _) = subject { return ecosystem }
        return nil
    }

    /// Where it came from, for one line: "Homebrew openssl@3", "Slack, Figma", "global npm".
    public var originSummary: String {
        if case let .project(_, _, installedAs) = subject, let first = origins.first, first.kind == .homebrew {
            return "\(first.label) \(installedAs)"
        }
        if let profiles = Origin.profilesSummary(origins) { return profiles }
        var seen = Set<String>(), labels: [String] = []
        for o in origins where seen.insert(o.location).inserted { labels.append(o.location) }
        let shown = labels.prefix(3).joined(separator: ", ")
        return labels.count > 3 ? "\(shown) and \(labels.count - 3) more" : shown
    }

    /// The installed version, with the component it belongs to ("Electron 18.3.15", "42.11.16").
    public var installedLabel: String { (component.map { "\($0) " } ?? "") + installedVersion }

    /// "1.13.8 → 1.19.5", "Electron 24.2.0 → 42.11.16", "1.14.1", in one string (notifications, accessibility).
    public var versionLine: String {
        if malicious { return installedLabel }
        return fixedVersion.map { "\(installedLabel) → \($0)" } ?? installedLabel
    }

    /// Notifications are sent for these when they first appear: malicious, exploited in the wild (checked or not), or
    /// on the site's "patch these first" list.
    public var deservesNotification: Bool { malicious || exploited || notChecked?.exploited == true || bigIssue != nil }

    /// The findings to notify about after a scan: those that deserve it and did not before, or have become more serious
    /// since: a more urgent group (`urgency`), newly malicious or exploited, or a new "patch these first" item. A group
    /// that only moved the other way, as when a report saved by 0.5.1 is followed by one that checks ranges, or between
    /// groups that call for no action (likely to Other), notifies nothing.
    public static func toNotify(_ findings: [Finding], after previous: [Finding]?) -> [Finding] {
        let before = Dictionary((previous ?? []).filter(\.deservesNotification).map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        return findings.filter { f in
            guard f.deservesNotification else { return false }
            guard let old = before[f.id] else { return true }
            func exploited(_ x: Finding) -> Bool { x.exploited || x.notChecked?.exploited == true }
            return f.group.urgency < old.group.urgency || (f.malicious && !old.malicious) || (exploited(f) && !exploited(old))
                || (f.bigIssue != nil && f.bigIssue != old.bigIssue)
        }
    }

}

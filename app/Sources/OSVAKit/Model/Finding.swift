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
    /// The popover's groups, in the order they are shown.
    public enum Group: Int, Codable, Sendable, CaseIterable, Comparable {
        case malicious, exploited, criticalHigh, other

        public var title: String {
            switch self {
            case .malicious: return "Malicious"
            case .exploited: return "Exploited in the wild"
            case .criticalHigh: return "Critical and high"
            case .other: return "Other"
            }
        }

        /// Groups that call for action now; they decide the menu-bar icon and the count beside it.
        public var needsAction: Bool { self != .other }

        public static func < (a: Group, b: Group) -> Bool { a.rawValue < b.rawValue }
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
    /// The version to upgrade to, when one is known.
    public var fixedVersion: String?
    public var severity: Severity?
    public var advisoryIDs: [String]
    /// How many distinct flaws (advisories describing the same flaw count once).
    public var flawCount: Int
    public var exploited: Bool
    public var malicious: Bool
    /// One line of context: "likely affected: the issuer names 3.5.10 as fixed", or how this place is upgraded.
    public var note: String?
    /// How many of its flaws the upgrade to `fixedVersion` fixes (when the server's plan says).
    public var fixesCount: Int?
    /// The flaws that upgrade does not fix here, with the reason.
    public var unresolved: [UnresolvedFlaw]
    /// Set when it matches the site's "patch these first" list.
    public var bigIssue: String?
    public var origins: [Origin]
    public var pageURL: URL
    public var upgradeCommand: String?
    /// What `upgradeCommand` was made from. The Fix button makes the command again from these and runs it only if it
    /// is exactly `upgradeCommand` (nil in reports saved before the button existed: they get no button until rescanned).
    public var commandInputs: UpgradeCommand.Inputs?
    public var verification: Verification
    public var grade: String?
    /// Where each copy is on this Mac and why it is there, one per copy (nil in reports saved before, or when nothing
    /// could be told). Read from local files after the API was asked; never sent.
    public var provenance: [Provenance]? = nil

    public init(id: String, group: Group, subject: Subject, title: String, component: String? = nil, installedVersion: String, fixedVersion: String?,
                severity: Severity?, advisoryIDs: [String], flawCount: Int, exploited: Bool, malicious: Bool,
                note: String?, bigIssue: String?, origins: [Origin], pageURL: URL, upgradeCommand: String?,
                verification: Verification, grade: String?, fixesCount: Int? = nil, unresolved: [UnresolvedFlaw] = [],
                commandInputs: UpgradeCommand.Inputs? = nil) {
        self.id = id; self.group = group; self.subject = subject; self.title = title; self.component = component
        self.installedVersion = installedVersion
        self.fixedVersion = fixedVersion; self.severity = severity; self.advisoryIDs = advisoryIDs; self.flawCount = flawCount
        self.exploited = exploited; self.malicious = malicious; self.note = note; self.bigIssue = bigIssue
        self.origins = origins; self.pageURL = pageURL; self.upgradeCommand = upgradeCommand
        self.verification = verification; self.grade = grade
        self.fixesCount = fixesCount; self.unresolved = unresolved; self.commandInputs = commandInputs
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

    /// Notifications are sent for these when they first appear.
    public var deservesNotification: Bool { malicious || exploited || bigIssue != nil }

    /// Changes when a finding becomes more serious (newly exploited, newly on the "patch these first" list), so that
    /// it is notified again then.
    public var notificationKey: String { "\(id)|\(group.rawValue)|\(bigIssue ?? "")" }
}

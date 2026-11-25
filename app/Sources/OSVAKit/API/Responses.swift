import Foundation

// The API's answers, decoded leniently: a field the server leaves out or adds never breaks a scan.
// Shapes: formalinformer/api/server.py (check_many, osv_check, project, state).

/// POST api/v1/check/batch: the vulnerable and malicious packages among those asked about, each with its flaws and
/// a plan: the version that fixes what can be fixed on this Mac (with this package's Python), and what remains.
public struct BatchResponse: Decodable, Sendable {
    /// One flaw (advisories describing the same flaw are merged by the server).
    public struct Flaw: Codable, Sendable, Hashable {
        public var id: String
        public var aliases: [String]
        public var severity: String?
        public var summary: String?
        /// The fixed versions the site names, read strictly: [] when it names none, or when the list could not be read
        /// (`fixedInUnreadable`).
        public var fixedIn: [String]
        /// The server sent a `fixed_in` the app could not read as a list of versions: the flaw is not checked by it,
        /// never by []. Kept in the cache's copy (`fixed_in_unreadable`).
        public var fixedInUnreadable: Bool
        /// The first fixed version installable here (with this package's Python), if any.
        public var fixForYou: String?
        /// "windows", "macos", "linux": the flaw affects that platform only. Nil: any platform.
        public var platform: String?
        public var exploitedSince: String?
        public var malicious: Bool
        /// The affected ranges the site publishes for this flaw, read strictly (`AffectedRange`). Nil when it publishes
        /// none it can state exactly (`rangesNote` says why), when the server is older than ranges, or when they could
        /// not be read (`rangesUnreadable`).
        public var ranges: [AffectedRange]?
        public var rangesNote: String?
        /// The server sent ranges the app could not read: the flaw is not checked against them, never against a wider
        /// range. Kept in the cache's copy (`ranges_unreadable`).
        public var rangesUnreadable: Bool

        enum CodingKeys: String, CodingKey {
            case id, aliases, severity, summary, platform, malicious, ranges
            case fixedIn = "fixed_in", fixForYou = "fix_for_you", exploitedSince = "exploited_since"
            case rangesNote = "ranges_note", rangesUnreadable = "ranges_unreadable", fixedInUnreadable = "fixed_in_unreadable"
        }
        public init(from d: Decoder) throws {
            let c = try d.container(keyedBy: CodingKeys.self)
            id = try c.decode(String.self, forKey: .id)
            aliases = (try? c.decodeIfPresent([String].self, forKey: .aliases)) ?? []
            severity = try? c.decodeIfPresent(String.self, forKey: .severity)
            summary = try? c.decodeIfPresent(String.self, forKey: .summary)
            (fixedIn, fixedInUnreadable) = c.strictVersions(.fixedIn, unreadableKey: .fixedInUnreadable)
            fixForYou = try? c.decodeIfPresent(String.self, forKey: .fixForYou)
            platform = try? c.decodeIfPresent(String.self, forKey: .platform)
            exploitedSince = try? c.decodeIfPresent(String.self, forKey: .exploitedSince)
            malicious = (try? c.decodeIfPresent(Bool.self, forKey: .malicious)) ?? false
            (ranges, rangesUnreadable) = c.strictRanges(.ranges, unreadableKey: .rangesUnreadable)
            rangesNote = try? c.decodeIfPresent(String.self, forKey: .rangesNote)
        }

        /// The flaw as the core weighs it: its ranges, and `fixedIn` as its first fixed versions. Nil when either could
        /// not be read.
        public var coreAdvisory: CoreAdvisory? {
            rangesUnreadable || fixedInUnreadable ? nil : CoreAdvisory(ranges: ranges, fixed: fixedIn)
        }

        /// Whether it can affect a Mac (no platform named, or macOS).
        public var affectsThisMac: Bool { platform == nil || platform?.lowercased() == "macos" }
    }

    /// What upgrading does here: the one version to ask for, what it fixes, and what it cannot.
    public struct Plan: Codable, Sendable, Hashable {
        public struct Remaining: Codable, Sendable, Hashable {
            public enum Reason: String, Codable, Sendable {
                case needsPython = "needs-python", otherPlatform = "other-platform", noFix = "no-fix", malicious, unknown
                /// Asked within constraints (a dependent's specifier, a runtime boundary): its fix lies outside them.
                case blockedByConstraint = "blocked-by-constraint"
            }
            public var id: String
            public var fixedIn: String?
            public var reason: Reason
            /// "Python >=3.10", "Windows".
            public var detail: String?
            /// For blocked-by-constraint: the constraint, as it was sent, that excludes the fix ("<2.9").
            public var constraint: String?

            enum CodingKeys: String, CodingKey { case id, reason, detail, constraint, fixedIn = "fixed_in" }
            public init(from d: Decoder) throws {
                let c = try d.container(keyedBy: CodingKeys.self)
                id = (try? c.decodeIfPresent(String.self, forKey: .id)) ?? ""
                fixedIn = try? c.decodeIfPresent(String.self, forKey: .fixedIn)
                reason = (try? c.decodeIfPresent(String.self, forKey: .reason)).flatMap(Reason.init(rawValue:)) ?? .unknown
                detail = try? c.decodeIfPresent(String.self, forKey: .detail)
                constraint = try? c.decodeIfPresent(String.self, forKey: .constraint)
            }
        }

        /// The version the server plans to upgrade to (`target` on the wire), which the core has not judged: read only by
        /// BatchCheck, which shows it only when `Core.judge` confirms it (a guard in ClaimsTests holds this name to it).
        public var unjudgedTarget: String?
        public var fixes: [String]
        public var remaining: [Remaining]
        public var requiresPython: String?
        public var newestInstallable: String?

        enum CodingKeys: String, CodingKey {
            case unjudgedTarget = "target", fixes, remaining, requiresPython = "requires_python", newestInstallable = "newest_installable"
        }
        public init(from d: Decoder) throws {
            let c = try d.container(keyedBy: CodingKeys.self)
            unjudgedTarget = try? c.decodeIfPresent(String.self, forKey: .unjudgedTarget)
            fixes = (try? c.decodeIfPresent([String].self, forKey: .fixes)) ?? []
            remaining = (try? c.decodeIfPresent([Remaining].self, forKey: .remaining)) ?? []
            requiresPython = try? c.decodeIfPresent(String.self, forKey: .requiresPython)
            newestInstallable = try? c.decodeIfPresent(String.self, forKey: .newestInstallable)
        }
    }

    public struct Result: Codable, Sendable, Hashable {
        public var ecosystem: String
        public var name: String
        public var version: String
        /// The Python version asked with, when the server echoes it.
        public var python: String?
        public var malicious: Bool
        public var distinctFlaws: Int
        public var worstSeverity: String?
        /// CVE ids exploited in the wild (CISA KEV).
        public var exploited: [String]
        public var advisories: [String]
        public var flaws: [Flaw]
        public var plan: Plan?

        enum CodingKeys: String, CodingKey {
            case ecosystem, name, version, python, malicious, advisories, exploited, flaws, plan
            case distinctFlaws = "distinct_flaws", worstSeverity = "worst_severity"
        }

        public init(from d: Decoder) throws {
            let c = try d.container(keyedBy: CodingKeys.self)
            ecosystem = try c.decode(String.self, forKey: .ecosystem)
            name = try c.decode(String.self, forKey: .name)
            version = try c.decode(String.self, forKey: .version)
            python = try? c.decodeIfPresent(String.self, forKey: .python)
            malicious = try c.decodeIfPresent(Bool.self, forKey: .malicious) ?? false
            distinctFlaws = try c.decodeIfPresent(Int.self, forKey: .distinctFlaws) ?? 0
            worstSeverity = try c.decodeIfPresent(String.self, forKey: .worstSeverity)
            exploited = (try? c.decodeIfPresent([String].self, forKey: .exploited)) ?? []
            advisories = try c.decodeIfPresent([String].self, forKey: .advisories) ?? []
            flaws = (try? c.decodeIfPresent([Flaw].self, forKey: .flaws)) ?? []
            plan = try? c.decodeIfPresent(Plan.self, forKey: .plan)
        }
    }

    public var checked: Int
    public var packages: [Result]

    enum CodingKeys: String, CodingKey { case checked, packages }
    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        checked = try c.decodeIfPresent(Int.self, forKey: .checked) ?? 0
        packages = try c.decodeIfPresent([Result].self, forKey: .packages) ?? []
    }
}

/// GET api/v1/project/<slug>: a graded project's profile with its recent advisories.
public struct ProjectResponse: Codable, Sendable {
    public struct Advisory: Codable, Sendable, Hashable {
        public var id: String
        public var date: String
        public var severity: String
        public var title: String
        /// The first fixed version the issuer names for each release branch. Decides only when `ranges` is nil. Read
        /// strictly: [] when it names none, or when the list could not be read (`fixedHintUnreadable`).
        public var fixedHint: [String]
        /// The server sent a `fixed_hint` the app could not read as a list of versions: the advisory is not checked by
        /// it, never by []. Kept in the cache's copy (`fixed_hint_unreadable`).
        public var fixedHintUnreadable: Bool
        public var kev: Bool
        public var cve: String?
        /// Every affected range the issuer states, read strictly (`AffectedRange`). Nil when the server has none for
        /// this advisory (an older server, or a record it cannot read as ranges exactly: `rangesNote` says why), or when
        /// the app could not read them (`rangesUnreadable`). The core reads [] as it reads nil.
        public var ranges: [AffectedRange]?
        public var rangesNote: String?
        /// The server sent ranges the app could not read: the advisory is not checked against them, never against a
        /// wider range. Kept in the cache's copy (`ranges_unreadable`).
        public var rangesUnreadable: Bool
        /// Builds a distributor's own record says contain the fix ("Amazon Corretto" 27.0.1.1.4: its changelog at that
        /// tag lists the advisory), not necessarily the first that does. [] from servers that do not send them.
        public var fixedBuilds: [FixedBuild]

        public struct FixedBuild: Codable, Sendable, Hashable {
            public var dist: String
            public var build: String
            public var url: String?
            public init(dist: String, build: String, url: String? = nil) { self.dist = dist; self.build = build; self.url = url }
        }

        enum CodingKeys: String, CodingKey {
            case id, date, title, kev, cve, ranges, severity = "sev", fixedHint = "fixed_hint", rangesNote = "ranges_note"
            case fixedBuilds = "fixed_builds", rangesUnreadable = "ranges_unreadable", fixedHintUnreadable = "fixed_hint_unreadable"
        }
        public init(from d: Decoder) throws {
            let c = try d.container(keyedBy: CodingKeys.self)
            id = try c.decode(String.self, forKey: .id)
            date = try c.decodeIfPresent(String.self, forKey: .date) ?? ""
            severity = try c.decodeIfPresent(String.self, forKey: .severity) ?? ""
            title = try c.decodeIfPresent(String.self, forKey: .title) ?? ""
            (fixedHint, fixedHintUnreadable) = c.strictVersions(.fixedHint, unreadableKey: .fixedHintUnreadable)
            kev = (try? c.decodeIfPresent(Bool.self, forKey: .kev)) ?? false
            cve = try? c.decodeIfPresent(String.self, forKey: .cve)
            (ranges, rangesUnreadable) = c.strictRanges(.ranges, unreadableKey: .rangesUnreadable)
            rangesNote = try? c.decodeIfPresent(String.self, forKey: .rangesNote)
            fixedBuilds = (try? c.decodeIfPresent([FixedBuild].self, forKey: .fixedBuilds)) ?? []    // optional, and never fatal
        }

        /// The advisory as the core weighs it: its ranges, and `fixedHint` as its first fixed versions. Nil when either
        /// could not be read.
        public var coreAdvisory: CoreAdvisory? {
            rangesUnreadable || fixedHintUnreadable ? nil : CoreAdvisory(ranges: ranges, fixed: fixedHint)
        }
    }

    /// One entry of the project's formal-verification record.
    public struct Verified: Codable, Sendable, Hashable {
        public var name: String
        /// "self" (the project proves itself), "proofs" (proofs maintained in CI), "shipped" (ships proved code),
        /// "external" (others' proofs about it).
        public var kind: String
        /// "full", "partial", "protocol-model".
        public var level: String
        /// Whether the site counts it as verification of what ships.
        public var counts: Bool

        enum CodingKeys: String, CodingKey { case name, kind, level, counts }
        public init(from d: Decoder) throws {
            let c = try d.container(keyedBy: CodingKeys.self)
            name = try c.decodeIfPresent(String.self, forKey: .name) ?? ""
            kind = try c.decodeIfPresent(String.self, forKey: .kind) ?? ""
            level = try c.decodeIfPresent(String.self, forKey: .level) ?? ""
            counts = (try? c.decodeIfPresent(Bool.self, forKey: .counts)) ?? false
        }
    }

    public var slug: String
    public var name: String
    public var grade: String?
    public var gradeLabel: String?
    public var verified: [Verified]
    public var recent: [Advisory]

    enum CodingKeys: String, CodingKey { case slug, name, grade, verified, recent, gradeLabel = "grade_label" }
    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        slug = try c.decode(String.self, forKey: .slug)
        name = try c.decodeIfPresent(String.self, forKey: .name) ?? slug
        grade = try c.decodeIfPresent(String.self, forKey: .grade)
        gradeLabel = try c.decodeIfPresent(String.self, forKey: .gradeLabel)
        verified = (try? c.decodeIfPresent([Verified].self, forKey: .verified)) ?? []
        recent = (try? c.decodeIfPresent([Advisory].self, forKey: .recent)) ?? []
    }

    /// The site's tier (`fv_tier` in formalinformer/pipeline/fi/trust.py): the API's project record carries the
    /// `verified` list it is computed from, not the tier itself.
    public var verificationTier: String {
        let ranks = ["none", "ships_proved_code", "proofs_in_ci", "fully_verified_artifact"]
        var tier = "none"
        for v in verified where v.counts {
            let t: String
            switch v.kind {
            case "self": t = v.level == "full" ? "fully_verified_artifact" : v.level == "partial" ? "proofs_in_ci" : "none"
            case "proofs": t = "proofs_in_ci"
            case "shipped": t = "ships_proved_code"
            default: t = "none"
            }
            if ranks.firstIndex(of: t)! > ranks.firstIndex(of: tier)! { tier = t }
        }
        return tier
    }

    /// The mark the site draws (`vtier` in site/formalinformer/app.js): filled for a project verified as a whole,
    /// dashed for one with verified parts.
    public var verificationMark: Verification {
        let tier = verificationTier
        if tier == "fully_verified_artifact" { return .whole }
        if tier == "proofs_in_ci" || tier == "ships_proved_code" || verified.contains(where: \.counts) { return .parts }
        return .none
    }
}

/// GET api/v1/state: only the part the app uses, the home page's "patch these first" list.
public struct StateResponse: Codable, Sendable {
    public struct BigIssue: Codable, Sendable, Hashable {
        public var name: String
        public var slug: String
        public var severity: String?
        public var exploited: Bool
        public var date: String
        public var ids: [String]
        public var fixedIn: [String]
        public var title: String

        enum CodingKeys: String, CodingKey { case name, slug, severity, exploited, date, ids, title, fixedIn = "fixed_in" }
        public init(from d: Decoder) throws {
            let c = try d.container(keyedBy: CodingKeys.self)
            slug = try c.decode(String.self, forKey: .slug)
            name = try c.decodeIfPresent(String.self, forKey: .name) ?? slug
            severity = try c.decodeIfPresent(String.self, forKey: .severity)
            exploited = (try? c.decodeIfPresent(Bool.self, forKey: .exploited)) ?? false
            date = try c.decodeIfPresent(String.self, forKey: .date) ?? ""
            ids = (try? c.decodeIfPresent([String].self, forKey: .ids)) ?? []
            fixedIn = (try? c.decodeIfPresent([String].self, forKey: .fixedIn)) ?? []
            title = try c.decodeIfPresent(String.self, forKey: .title) ?? ""
        }
    }

    public var bigIssues: [BigIssue]

    private struct Big: Codable { var vulns: [BigIssue]? }
    enum CodingKeys: String, CodingKey { case bigIssues = "big_issues" }
    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        bigIssues = (try? c.decodeIfPresent(Big.self, forKey: .bigIssues))?.vulns ?? []
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(Big(vulns: bigIssues), forKey: .bigIssues)
    }
}

/// What the core decides by, read strictly: a value that does not read is marked unreadable, never read as a wider
/// range or as no fixed versions. The cache's copy says so at `unreadableKey`.
extension KeyedDecodingContainer {
    /// An advisory's or flaw's `ranges`: absent or null is nil; a list of ranges that reads strictly (`AffectedRange`)
    /// is kept; anything else is nil and unreadable.
    func strictRanges(_ key: Key, unreadableKey: Key) -> (ranges: [AffectedRange]?, unreadable: Bool) {
        if (try? decodeIfPresent(Bool.self, forKey: unreadableKey)) == true { return (nil, true) }
        guard contains(key), (try? decodeNil(forKey: key)) != true else { return (nil, false) }
        guard let ranges = try? decode([AffectedRange].self, forKey: key) else { return (nil, true) }
        return (ranges, false)
    }

    /// A list of fixed versions (`fixed_in`, `fixed_hint`): absent or null is [], none stated; a list of strings is
    /// kept; anything else (a string, a number, a null in the list) is [] and unreadable.
    func strictVersions(_ key: Key, unreadableKey: Key) -> (versions: [String], unreadable: Bool) {
        if (try? decodeIfPresent(Bool.self, forKey: unreadableKey)) == true { return ([], true) }
        guard contains(key), (try? decodeNil(forKey: key)) != true else { return ([], false) }
        guard let versions = try? decode([String].self, forKey: key) else { return ([], true) }
        return (versions, false)
    }
}

/// The body of POST api/v1/check/batch. Per package: the Python a PyPI package is installed in (so the plan only names
/// releases that Python can install), and the platform it runs on: "macos" for software installed on this Mac, an
/// explicit null ("may run anywhere") for a project folder's dependencies.
struct BatchRequest: Encodable {
    struct Package: Encodable {
        var ecosystem: String
        var name: String
        var version: String
        var python: String?
        var platform: String?
        /// PEP 440 specifiers the plan's target must satisfy (a partial fix): versions only, never a name.
        var constraints: [String]? = nil

        enum CodingKeys: String, CodingKey { case ecosystem, name, version, python, platform, constraints }
        func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encode(ecosystem, forKey: .ecosystem)
            try c.encode(name, forKey: .name)
            try c.encode(version, forKey: .version)
            try c.encodeIfPresent(python, forKey: .python)
            try c.encode(platform, forKey: .platform)                 // null is meaningful: "may run anywhere"
            try c.encodeIfPresent(constraints, forKey: .constraints)
        }
    }
    var packages: [Package]
}

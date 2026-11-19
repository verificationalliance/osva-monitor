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
        public var fixedIn: [String]
        /// The first fixed version installable here (with this package's Python), if any.
        public var fixForYou: String?
        /// "windows", "macos", "linux": the flaw affects that platform only. Nil: any platform.
        public var platform: String?
        public var exploitedSince: String?
        public var malicious: Bool

        enum CodingKeys: String, CodingKey {
            case id, aliases, severity, summary, platform, malicious
            case fixedIn = "fixed_in", fixForYou = "fix_for_you", exploitedSince = "exploited_since"
        }
        public init(from d: Decoder) throws {
            let c = try d.container(keyedBy: CodingKeys.self)
            id = try c.decode(String.self, forKey: .id)
            aliases = (try? c.decodeIfPresent([String].self, forKey: .aliases)) ?? []
            severity = try? c.decodeIfPresent(String.self, forKey: .severity)
            summary = try? c.decodeIfPresent(String.self, forKey: .summary)
            fixedIn = (try? c.decodeIfPresent([String].self, forKey: .fixedIn)) ?? []
            fixForYou = try? c.decodeIfPresent(String.self, forKey: .fixForYou)
            platform = try? c.decodeIfPresent(String.self, forKey: .platform)
            exploitedSince = try? c.decodeIfPresent(String.self, forKey: .exploitedSince)
            malicious = (try? c.decodeIfPresent(Bool.self, forKey: .malicious)) ?? false
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

        public var target: String?
        public var fixes: [String]
        public var remaining: [Remaining]
        public var requiresPython: String?
        public var newestInstallable: String?

        enum CodingKeys: String, CodingKey {
            case target, fixes, remaining, requiresPython = "requires_python", newestInstallable = "newest_installable"
        }
        public init(from d: Decoder) throws {
            let c = try d.container(keyedBy: CodingKeys.self)
            target = try? c.decodeIfPresent(String.self, forKey: .target)
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
        /// The first fixed version the issuer names for each release branch. Decides only when `ranges` is nil.
        public var fixedHint: [String]
        public var kev: Bool
        public var cve: String?
        /// Every affected range the issuer states ([]: no version is affected). Nil when the server has none for this
        /// advisory: an older server, or a record it cannot read as ranges exactly (`rangesNote` says why).
        public var ranges: [AffectedRange]?
        public var rangesNote: String?

        enum CodingKeys: String, CodingKey {
            case id, date, title, kev, cve, ranges, severity = "sev", fixedHint = "fixed_hint", rangesNote = "ranges_note"
        }
        public init(from d: Decoder) throws {
            let c = try d.container(keyedBy: CodingKeys.self)
            id = try c.decode(String.self, forKey: .id)
            date = try c.decodeIfPresent(String.self, forKey: .date) ?? ""
            severity = try c.decodeIfPresent(String.self, forKey: .severity) ?? ""
            title = try c.decodeIfPresent(String.self, forKey: .title) ?? ""
            fixedHint = (try? c.decodeIfPresent([String].self, forKey: .fixedHint)) ?? []
            kev = (try? c.decodeIfPresent(Bool.self, forKey: .kev)) ?? false
            cve = try? c.decodeIfPresent(String.self, forKey: .cve)
            ranges = try? c.decodeIfPresent([AffectedRange].self, forKey: .ranges)     // malformed reads as none: fixed_hint decides
            rangesNote = try? c.decodeIfPresent(String.self, forKey: .rangesNote)
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

import Foundation

/// Where an installed copy is on this Mac and why it is there, read from the Mac's own files: pip's metadata,
/// Homebrew's receipts, the lockfile, the app bundle. It stays on this Mac; nothing here is ever put into a request.
///
/// A source may fill in what it knows cheaply while taking inventory (`InstalledPackage.provenance`: pip's sources set
/// the site-packages directory pip reported). After the findings are made, `ProvenanceExplainer` completes it for the
/// copies behind each finding (`Finding.provenance`), so only what can be shown is read.
public struct Provenance: Hashable, Codable, Sendable {
    /// The copy on disk, as precisely as known: the package's own folder, the app, the keg, the lockfile.
    public var path: String?
    /// Why it is there, in one short line: "Needed by fastapi → blooper-backend (your project)".
    public var why: String?
    /// What that means for the upgrade, only when it is safe to say: "Nothing here uses it — removing it may be better
    /// than upgrading it."
    public var advice: String?
    /// What needs it directly, with the versions each accepts when the source says.
    public var dependents: [Dependent]
    /// More, on demand: "blooper-backend is your project, editable from ~/code/blooper", "Installed with pip on 19 Nov 2026".
    public var details: [String]

    public init(path: String? = nil, why: String? = nil, advice: String? = nil, dependents: [Dependent] = [], details: [String] = []) {
        self.path = path; self.why = why; self.advice = advice; self.dependents = dependents; self.details = details
    }

    public init(from decoder: Decoder) throws {                  // every field optional, so later additions still load
        let c = try decoder.container(keyedBy: CodingKeys.self)
        path = try c.decodeIfPresent(String.self, forKey: .path)
        why = try c.decodeIfPresent(String.self, forKey: .why)
        advice = try c.decodeIfPresent(String.self, forKey: .advice)
        dependents = try c.decodeIfPresent([Dependent].self, forKey: .dependents) ?? []
        details = try c.decodeIfPresent([String].self, forKey: .details) ?? []
    }

    /// Whether there is anything to show beyond the path.
    public var hasMore: Bool { !dependents.isEmpty || !details.isEmpty }

    /// One installed thing that needs this one.
    public struct Dependent: Hashable, Codable, Sendable {
        public var name: String
        public var version: String?
        /// The versions it accepts, as it writes them ("<0.49.0,>=0.40.0"); "" when any version will do; nil when the
        /// source does not say (Homebrew).
        public var specifier: String?
        /// Whether someone asked for it by name (pip's REQUESTED, Homebrew's installed_on_request); nil when unknown.
        public var requested: Bool?

        public init(name: String, version: String? = nil, specifier: String? = nil, requested: Bool? = nil) {
            self.name = name; self.version = version; self.specifier = specifier; self.requested = requested
        }

        /// "fastapi 0.120.0 needs <0.49.0,>=0.40.0", "ffmpeg 8.0 needs it".
        public var line: String {
            let who = name + (version.map { " \($0)" } ?? "")
            switch specifier {
            case nil: return "\(who) needs it"
            case ""?: return "\(who) needs any version"
            case let s?: return "\(who) needs \(s)"
            }
        }
    }
}

/// The sentences, in one place. Pure: every source's explanation is made of these.
public enum ProvenanceText {
    /// "Nothing here uses it — removing it may be better than upgrading it."
    public static let unused = "Nothing here uses it — removing it may be better than upgrading it."

    /// Said of Oracle's JDK where it is explained, while the index has no record of Oracle Java SE of its own.
    public static let oracleAsOpenJDK = "Oracle's builds share OpenJDK's HotSpot, so they are checked against OpenJDK's advisories."

    /// What is at the top of a chain of dependents: who asked for it.
    public enum Top: Hashable, Sendable {
        /// Your own project, installed editable or from a folder: "blooper-backend (your project)".
        case project
        /// Installed by name: "gradio (installed by you)".
        case requested
        /// Named in a project's manifest: "express (in package.json)".
        case manifest(String)
        /// Nothing above it; who asked for it is not known.
        case unknown
    }

    /// Names shown in one line; a longer chain keeps both ends ("a → … → z") and is given whole in the details.
    static let maxShownChain = 3

    /// "Needed by fastapi → blooper-backend (your project)": `chain` goes from what needs the package directly up to
    /// the top, which `top` describes. Long chains keep both ends ("a → … → z").
    public static func neededBy(chain: [String], top: Top) -> String {
        guard !chain.isEmpty else { return "" }
        var names = chain
        if names.count > maxShownChain { names = [names[0], "…", names.last!] }
        return "Needed by " + names.joined(separator: " → ") + suffix(top)
    }

    /// "Needed by ffmpeg and yt-dlp (installed by you)", "Needed by a, b and 3 more": several things need it directly.
    public static func neededBy(names: [String], top: Top) -> String {
        guard let first = names.first else { return "" }
        let list: String
        switch names.count {
        case 1: list = first
        case 2: list = "\(first) and \(names[1])"
        default: list = "\(first), \(names[1]) and \(names.count - 2) more"
        }
        return "Needed by " + list + suffix(top)
    }

    /// The "Needed by" line for a package with dependents: the chain up to whoever asked for it; when the nearest
    /// dependent is that itself, every direct dependent of the same kind ("Needed by ffmpeg and yt-dlp (installed by
    /// you)"); when nobody is known to have asked, the direct dependents, not one chain picked among many.
    public static func neededBy(chain: [String], top: Top, direct: [String], directLikeTop: [String]) -> String {
        if top == .unknown || chain.isEmpty { return neededBy(names: direct.isEmpty ? chain : direct, top: .unknown) }
        if chain.count == 1, directLikeTop.count > 1 { return neededBy(names: [chain[0]] + directLikeTop.filter { $0 != chain[0] }, top: top) }
        return neededBy(chain: chain, top: top)
    }

    private static func suffix(_ top: Top) -> String {
        switch top {
        case .project: return " (your project)"
        case .requested: return " (installed by you)"
        case let .manifest(file): return " (in \(file))"
        case .unknown: return ""
        }
    }

    /// "You installed it on 12 Jan 2026", "You installed it with uv on …", "You installed it".
    public static func installedByYou(on date: Date?, with tool: String? = nil, timeZone: TimeZone = .current) -> String {
        "You installed it" + (tool.map { " with \($0)" } ?? "") + (date.map { " on " + day($0, timeZone: timeZone) } ?? "")
    }

    /// "Installed by Poetry on 12 Jan 2026", "Installed on 12 Jan 2026": who asked for it is not known.
    public static func installed(on date: Date?, by tool: String? = nil, timeZone: TimeZone = .current) -> String? {
        guard date != nil || tool != nil else { return nil }
        return "Installed" + (tool.map { " by \($0)" } ?? "") + (date.map { " on " + day($0, timeZone: timeZone) } ?? "")
    }

    /// "3 Mar 2026". A date before 2000 is no install date (npm's tarballs carry 1985) and is left out by callers.
    public static func day(_ date: Date, timeZone: TimeZone = .current) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = timeZone
        f.dateFormat = "d MMM yyyy"
        return f.string(from: date)
    }

    /// A date worth stating as an install date.
    static func plausible(_ date: Date?) -> Date? {
        guard let date, date.timeIntervalSince1970 > 946_684_800 else { return nil }     // after 1 Jan 2000
        return date
    }
}

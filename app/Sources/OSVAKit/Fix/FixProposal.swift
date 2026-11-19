import Foundation

// Fixes the app proposes but never runs without the person's OK, because they do less than the full fix or move more
// than the finding's own package (research rules 4.3 and 4.7):
//   - a partial fix: when a dependent's specifier or a runtime boundary blocks the full fix, the highest version under
//     every one of them that removes at least one flaw and adds none. The site picks it (`check/batch` with
//     `constraints`), from versions and operators alone;
//   - an upgrade together: when a dependent's specifier blocks every fixing version, pip's own resolver is asked for a
//     consistent set that moves what holds it back, and the set is run as one exact-pinned transaction.

/// One constraint on a package's upgrade: a specifier set and who it comes from.
public struct FixConstraint: Hashable, Sendable {
    /// As the site takes it: "<2.9", "<0.49.0,>=0.40.0".
    public var specifier: String
    /// The installed package that needs it ("whisperx").
    public var from: String
    /// A runtime boundary (rule 4.5) rather than a specifier the dependent declares.
    public var boundary: Bool

    public init(specifier: String, from: String, boundary: Bool) { self.specifier = specifier; self.from = from; self.boundary = boundary }
}

/// PEP 440 specifier sets as the app sends them and says them.
public enum PythonConstraints {
    /// At most this many go with one package.
    public static let maxSent = 8

    /// A specifier set the site takes: 1 to 4 clauses joined by "," with no spaces, lowercase, at most 64 characters.
    /// A clause is an operator (`~= == != <= >= < >`, never `===`) and a public version: release numbers, then
    /// optionally `aN`, `bN` or `rcN`, `.postN`, `.devN`; or a wildcard `N.N.*` after `==` or `!=` only. `~=` needs two
    /// release numbers. Nothing else: no name, marker, local version or epoch ever leaves the Mac in one.
    public static func isSendable(_ s: String) -> Bool {
        guard (1...64).contains(s.count), s.allSatisfy({ $0.isASCII }) else { return false }
        let clauses = s.split(separator: ",", omittingEmptySubsequences: false)
        guard (1...4).contains(clauses.count) else { return false }
        return clauses.allSatisfy { clause($0) }
    }

    static func clause(_ c: Substring) -> Bool {
        let s = String(c)
        if let m = s.wholeMatch(of: /(~=|==|!=|<=|>=|<|>)([0-9]{1,6}(?:\.[0-9]{1,6}){0,5})(?:(?:a|b|rc)[0-9]{1,6})?(?:\.post[0-9]{1,6})?(?:\.dev[0-9]{1,6})?/) {
            return m.1 != "~=" || m.2.contains(".")
        }
        return s.wholeMatch(of: /(?:==|!=)[0-9]{1,6}(?:\.[0-9]{1,6}){0,5}\.\*/) != nil
    }

    /// The specifiers as one set the site takes ("<0.49.0,>=0.40.0"), or nil if one of them is not one it takes.
    public static func sendable(_ specifiers: [PythonSpecifier]) -> String? {
        guard !specifiers.isEmpty else { return nil }
        let s = specifiers.map { $0.op.rawValue + $0.version.lowercased() }.joined(separator: ",")
        return isSendable(s) ? s : nil
    }

    /// What holds `package` back from `target` in this site, as constraints a partial fix must stay within:
    ///   - each installed dependent's specifiers on it that refuse the target (markers and extras in use counted),
    ///     except a dependent that pins it exactly and moves with it (torchaudio's `torch==`);
    ///   - a runtime boundary the target would cross while something installed uses the package, as "<2.9".
    /// Nil when one of them is not something the site takes (a direct URL, an unreadable specifier), or there are more
    /// than `maxSent`: then no partial fix is asked for.
    public static func blocking(_ package: String, from installed: String, to target: String, in site: PythonSite) -> [FixConstraint]? {
        let key = PythonNames.normal(package)
        let extras = site.activeExtras()
        var out: [FixConstraint] = []
        var companions = Set<String>()
        for d in site.distributions where d.key != key {
            for line in d.requires {
                guard let r = PythonRequirement(line), r.key == key else { continue }
                if let m = r.marker, PythonMarker.evaluate(m, environment: site.markers, extras: extras[d.key] ?? []) == false { continue }
                guard !r.refuses(target).isEmpty else { continue }
                if r.specifiers.contains(where: { $0.op == .equal || $0.op == .arbitrary || ($0.op == .compatible && PythonSite.patchLevel($0.version)) }),
                   r.specifiers.allSatisfy({ $0.admits(installed) == true }), !d.editable {
                    companions.insert(d.key)                        // pins it: moves with it
                    continue
                }
                guard !r.url, !r.unreadable, let s = sendable(r.specifiers) else { return nil }
                if !out.contains(where: { $0.specifier == s }) { out.append(FixConstraint(specifier: s, from: d.name, boundary: false)) }
            }
        }
        if let boundary = RuntimeBoundaries.crossed(key, from: installed, to: target, in: site),
           let user = PipGuard.users(of: [key], in: site, except: companions.union([key])).first {
            let s = "<" + boundary.version
            if isSendable(s), !out.contains(where: { $0.specifier == s }) { out.append(FixConstraint(specifier: s, from: user.name, boundary: true)) }
        }
        return out.isEmpty || out.count > maxSent ? nil : out
    }

    /// A specifier set in words, for one short line: "<2.9" is "below 2.9", "<0.49.0,>=0.40.0" "below 0.49.0",
    /// "~=2.8.0" and "==2.8.*" "2.8"; anything else as written, spaced ("!= 1.8, < 3").
    public static func words(_ set: String) -> String {
        let clauses = set.split(separator: ",").compactMap { PythonSpecifier(String($0)) }
        let uppers = clauses.filter { $0.op == .less || $0.op == .lessEqual }
        if uppers.count == 1, clauses.allSatisfy({ [.less, .lessEqual, .greaterEqual, .greater, .notEqual].contains($0.op) }) {
            let u = uppers[0]
            return u.op == .less ? "below \(u.version)" : "\(u.version) or older"
        }
        if clauses.count == 1, let c = clauses.first {
            if c.op == .compatible {
                let release = PythonSpecifier.release(PythonSpecifier.plain(c.version))
                if release.count >= 3 { return release.dropLast().joined(separator: ".") }
            }
            if c.op == .equal, c.version.hasSuffix(".*") { return String(c.version.dropLast(2)) }
            if c.op == .equal { return c.version }
        }
        return clauses.map(\.display).joined(separator: ", ")
    }
}

/// A fix the app proposes, which runs only with the person's OK.
public enum FixProposal: Hashable, Sendable {
    /// The best version under every constraint: the offer's plan targets it, and runs through the usual gates.
    case partial(Partial)
    /// The fix with what holds it back, as pip's resolver works it out at the review.
    case together(Together)

    public struct Partial: Hashable, Sendable {
        /// The flaws the partial target removes, and the finding's flaws.
        public var fixes: Int
        public var of: Int
        /// The constraint that blocks the rest, and who needs it.
        public var blocker: FixConstraint
        /// Every constraint it was asked within, as sent.
        public var constraints: [String]
        public init(fixes: Int, of: Int, blocker: FixConstraint, constraints: [String]) {
            self.fixes = fixes; self.of = of; self.blocker = blocker; self.constraints = constraints
        }
    }

    public struct Together: Hashable, Sendable {
        /// The finding's package, and the lowest version that fixes it: pip is asked for `package>=fix`.
        public var package: String
        public var fix: String
        /// What holds it back, named without versions so pip may move them, or with the range a project of the person's
        /// gives them ("fastapi<0.121"): pip must keep the project whole.
        public var blockers: [String]
        /// The blockers' other installed dependents, named so pip keeps them consistent too (never a project installed
        /// for development: pip would look for it on PyPI).
        public var others: [String]
        /// Blockers a project installed for development constrains: name → that project and its specifier, for the
        /// line that says to change it there.
        public var held: [String: Held]
        /// The finding is exploited in the wild: the line says this fixes it.
        public var exploited: Bool
        /// The Python, for asking the site about the flaws of what the set moves.
        public var python: PythonEnvironment?

        public struct Held: Hashable, Sendable {
            public var project: String
            public var specifier: String
        }

        public init(package: String, fix: String, blockers: [String], others: [String] = [], held: [String: Held] = [:], exploited: Bool = false,
                    python: PythonEnvironment? = nil) {
            self.package = package; self.fix = fix; self.blockers = blockers; self.others = others; self.held = held; self.exploited = exploited
            self.python = python
        }

        /// What pip is asked for: the fix as a floor, each blocker (with the range a project of the person's gives it),
        /// then the blockers' other dependents.
        public var requirements: [String] {
            ["\(package)>=\(fix)"] + blockers.map { b in held[PythonNames.normal(b)].map { b + $0.specifier } ?? b } + others
        }

        /// The names pip asks PyPI about, for the review's one line.
        public var asked: [String] { [package] + blockers + others }
    }
}

extension FixProposal {
    /// "Partly fixes: 6 of 14 flaws. whisperx needs torch below 2.9.", "Update starlette with fastapi and the
    /// instrumentator (fixes the exploited flaw)": what the row and the review say about it.
    public func line(_ plan: FixPlan) -> String {
        switch self {
        case let .partial(p):
            return "Partly fixes: \(p.fixes) of \(p.of) flaws. \(p.blocker.from) needs \(plan.pip?.name ?? plan.title) \(PythonConstraints.words(p.blocker.specifier))."
        case let .together(t):
            return "Update \(t.package) with \(Self.names(t.blockers + t.others))" + (t.exploited ? " (fixes the exploited flaw)" : "")
        }
    }

    /// The review's line in Fix all: "torch to 2.8.0 (6 of 14; whisperx needs below 2.9)", "starlette with fastapi and
    /// the instrumentator (fixes the exploited flaw)".
    public func reviewLine(_ plan: FixPlan) -> String {
        switch self {
        case let .partial(p):
            return "\(plan.pip?.name ?? plan.title) to \(plan.target ?? "?") (\(p.fixes) of \(p.of); \(p.blocker.from) needs \(PythonConstraints.words(p.blocker.specifier)))"
        case let .together(t):
            return "\(t.package) with \(Self.names(t.blockers + t.others))" + (t.exploited ? " (fixes the exploited flaw)" : "")
        }
    }

    /// The button: "Update to 2.8.0", "Update together".
    public func buttonTitle(_ plan: FixPlan) -> String {
        switch self {
        case .partial: return plan.actionTitle
        case .together: return "Update together"
        }
    }

    /// The privacy line of an upgrade together: "pip asks PyPI about starlette, fastapi".
    public var asks: String? {
        guard case let .together(t) = self else { return nil }
        return "pip asks PyPI about " + t.asked.joined(separator: ", ")
    }

    /// "fastapi and the instrumentator": a long name by its last word, as people say it.
    static func names(_ list: [String]) -> String {
        let short = list.map { n -> String in
            let words = n.split(separator: "-")
            return words.count >= 3 ? "the " + words.last! : n
        }
        switch short.count {
        case 0: return ""
        case 1: return short[0]
        case 2: return "\(short[0]) and \(short[1])"
        default: return short.dropLast().joined(separator: ", ") + " and " + short.last!
        }
    }
}

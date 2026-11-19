import Foundation

/// Findings for what the program sources find. A Go or Rust program, or a pipx or uv tool, is one finding however
/// many of its packages have flaws, because the program is what gets updated: "gh 2.62.0 was built with
/// golang.org/x/net 0.23.0 — fixed in 0.33.0 · built with Go 1.22.3, whose stdlib has 4 known flaws". A Homebrew
/// formula that is already a project finding takes its programs' flaws into that finding instead of a second one.
/// MacPorts, Nix and conda packages matched to graded projects follow the Homebrew project path.
extension FindingBuilder {
    /// A MacPorts, Nix or conda package matched to a graded project through the index's R lines.
    public struct ManagedMatch: Sendable {
        public var package: ManagedPackage
        public var project: PublicIndex.Project
        public init(package: ManagedPackage, project: PublicIndex.Project) { self.package = package; self.project = project }
    }

    /// Whether an installed copy's finding belongs to the program or tool it is part of.
    static func belongsToProgram(_ origin: Origin) -> Bool {
        switch origin {
        case .program, .pythonTool: return true
        default: return false
        }
    }

    /// The approved packages split into those with copies of their own and those inside programs and tools.
    static func separatingPrograms(_ approved: [ApprovedPackage: [InstalledPackage]])
        -> (packages: [ApprovedPackage: [InstalledPackage]], programs: [ApprovedPackage: [InstalledPackage]]) {
        var packages: [ApprovedPackage: [InstalledPackage]] = [:], programs: [ApprovedPackage: [InstalledPackage]] = [:]
        for (p, installs) in approved {
            let inPrograms = installs.filter { belongsToProgram($0.origin) }
            if !inPrograms.isEmpty { programs[p] = inPrograms }
            if inPrograms.count < installs.count { packages[p] = installs.filter { !belongsToProgram($0.origin) } }
        }
        return (packages, programs)
    }

    // MARK: Programs and tools

    /// One of a program's packages that has known flaws, as the check answered for it.
    struct Component {
        var package: ApprovedPackage
        /// The name as the program spells it.
        var name: String
        var group: Finding.Group
        var severity: Severity?
        var flawCount: Int
        var exploited: Bool
        var malicious: Bool
        /// The version that fixes what can be fixed (the server's plan), if it reads as a version.
        var target: String?
        var advisories: [String]
        var unresolved: [UnresolvedFlaw]
        var fixes: Int?
        /// The program's own module, crate or package, rather than something it was built with.
        var own: Bool

        var isStdlib: Bool { package.ecosystem == .go && package.name == "stdlib" }
        /// What the row shows for it: "Go" for Go's standard library, nil for the program's own package.
        var label: String? { isStdlib ? "Go" : own ? nil : name }
        /// Versions as people write them: Go's "v0.23.0" is "0.23.0", "v25.0.6+incompatible" is "25.0.6", and a
        /// pseudo-version ("v0.0.0-20210226172049-e18ecbb05110") is its base and date, "0.0.0-20210226".
        static func shown(_ v: String) -> String {
            var s = v.hasPrefix("v") && v.dropFirst().first?.isNumber == true ? String(v.dropFirst()) : v
            for build in ["+incompatible", "+dirty"] where s.hasSuffix(build) { s.removeLast(build.count) }
            if let m = pseudoVersion.firstMatch(s), let base = m[1], let date = m[2] { return "\(base)-\(date)" }
            return s
        }

        private static let pseudoVersion = Regex(#"^([0-9]+\.[0-9]+\.[0-9]+)-(?:[0-9A-Za-z.]*\.)?([0-9]{8})[0-9]{6}-[0-9a-f]{12}$"#)

        /// The row's line, "golang.org/x/net 0.23.0 → 0.62.0", fits the panel's width (44 characters of its monospaced
        /// type): a long module path is shortened to its last parts, which name it ("hashicorp/go-retryablehttp").
        static func rowLabel(_ label: String?, installed: String, fixed: String?) -> String? {
            guard let label else { return nil }
            let rest = installed.count + (fixed.map { $0.count + 3 } ?? 0) + 1
            var parts = label.split(separator: "/").map(String.init)
            while parts.count > 1 && parts.joined(separator: "/").count + rest > 44 { parts.removeFirst() }
            return parts.joined(separator: "/")
        }
    }

    /// The same reading of an answer as `packageFindings`: what affects this Mac, how serious, and the plan's version.
    func component(_ package: ApprovedPackage, _ verdict: BatchResponse.Result, name: String, own: Bool) -> Component {
        let flaws = verdict.flaws
        let here = flaws.filter(\.affectsThisMac)                           // programs are installed software: macOS
        let malicious = verdict.malicious || flaws.contains(where: \.malicious) || verdict.plan?.remaining.contains { $0.reason == .malicious } == true
        let exploited = flaws.isEmpty ? !verdict.exploited.isEmpty : here.contains { $0.exploitedSince != nil }
        let severityHere = flaws.isEmpty ? Severity(api: verdict.worstSeverity) : here.compactMap { Severity(api: $0.severity) }.max()
        let onlyElsewhere = !flaws.isEmpty && here.isEmpty && !malicious
        let group: Finding.Group = malicious ? .malicious : onlyElsewhere ? .other : exploited ? .exploited
            : (severityHere ?? .low) >= .high ? .criticalHigh : .other
        // The API lists at most 40 flaws; the ones it leaves out are counted as affecting this Mac too.
        let unlisted = max(verdict.distinctFlaws - flaws.count, 0)
        let count = flaws.isEmpty ? max(verdict.distinctFlaws, malicious ? 0 : 1) : onlyElsewhere ? flaws.count : here.count + unlisted
        // A version from the server goes into a sentence or a command only if it reads as a version (FixSafety).
        let target = (malicious || onlyElsewhere ? nil : verdict.plan?.target).flatMap { FixSafety.isSafeVersion($0) ? $0 : nil }
        let unresolved = (verdict.plan?.remaining ?? []).filter { $0.reason != .malicious }.map { r in
            UnresolvedFlaw(id: r.id, severity: Severity(api: flaws.first { $0.id == r.id }?.severity), fixedIn: r.fixedIn,
                           reason: Self.reason(r.reason), detail: r.detail, python: package.python, onThisMac: true)
        }
        return Component(package: package, name: name, group: group, severity: malicious ? nil : severityHere ?? flaws.compactMap { Severity(api: $0.severity) }.max(),
                         flawCount: count, exploited: exploited, malicious: malicious, target: target, advisories: verdict.advisories,
                         unresolved: unresolved, fixes: verdict.plan.map { $0.fixes.count }, own: own)
    }

    /// Whether a package is the program's or tool's own (its main module, root crate, or the tool's package).
    static func isOwn(_ install: InstalledPackage) -> Bool {
        switch install.origin {
        case let .program(p):
            return p.module == install.name
        case let .pythonTool(t):
            return PackageNames.indexName(install.name, in: .pypi) == t.mainPackage
        default:
            return false
        }
    }

    /// One finding per program (per Homebrew formula, when the programs are a formula's), or the program's flaws
    /// added to the formula's project finding when there is one.
    func programFindings(_ programs: [ApprovedPackage: [InstalledPackage]], verdicts: [ApprovedPackage: BatchResponse.Result],
                         into findings: inout [Finding]) {
        struct Group { var key: String; var origins: [Origin] = []; var components: [String: Component] = [:] }
        var groups: [String: Group] = [:]
        for (package, installs) in programs {
            guard let verdict = verdicts[package] else { continue }
            for install in installs {
                let key: String
                switch install.origin {
                case let .program(p): key = p.formula.map { "brew|\($0)|\(p.version ?? "")" } ?? p.app.map { "app|\($0)" } ?? "prog|\(p.path)"
                case let .pythonTool(t): key = "tool|\(t.manager.rawValue)|\(t.venv)"
                default: continue
                }
                var g = groups[key] ?? Group(key: key)
                if !g.origins.contains(install.origin) { g.origins.append(install.origin) }
                if g.components[package.versionKey] == nil {
                    g.components[package.versionKey] = component(package, verdict, name: install.name, own: Self.isOwn(install))
                }
                groups[key] = g
            }
        }
        for g in groups.values.sorted(by: { $0.key < $1.key }) {
            let parts = g.components.values.sorted(by: Self.worseFirst)
            guard let worst = parts.first else { continue }
            let sentence = Self.sentence(for: g.origins[0], programs: g.origins, parts: parts)
            let severity = parts.compactMap(\.severity).max(), exploited = parts.contains(where: \.exploited)
            let malicious = parts.contains(where: \.malicious)
            let group = parts.map(\.group).min()!
            let advisories = Array(Set(parts.flatMap(\.advisories))).sorted()
            // Versions of one package share most of their flaws: the most any of them has stands for all.
            let flaws = Self.byName(parts).reduce(0) { $0 + ($1.map(\.flawCount).max() ?? 0) }

            // A Homebrew formula already reported as a graded project: one finding, with its programs' flaws in it.
            if case let .program(p) = g.origins[0], let formula = p.formula,
               let i = findings.firstIndex(where: { f in
                   if case .project = f.subject { return f.origins.contains(.homebrewFormula(name: formula)) }
                   return false
               }) {
                findings[i].note = [findings[i].note, sentence].compactMap { $0 }.joined(separator: " ")
                findings[i].advisoryIDs += advisories.filter { !findings[i].advisoryIDs.contains($0) }
                findings[i].flawCount += flaws
                findings[i].exploited = findings[i].exploited || exploited
                findings[i].malicious = findings[i].malicious || malicious
                if group < findings[i].group { findings[i].group = group }
                if let s = severity, findings[i].severity.map({ s > $0 }) ?? true { findings[i].severity = s }
                continue
            }

            let advice = Self.programAdvice(origin: g.origins[0], programs: g.origins.count, parts: parts, malicious: malicious)
            let fixable = parts.contains { $0.target != nil }
            let title: String
            let id: String
            switch g.origins[0] {
            case let .program(p): title = p.formula ?? p.app ?? p.name; id = "prog|" + g.key
            case let .pythonTool(t): title = t.name; id = "tool|\(t.manager.rawValue)|\(t.venv)|\(t.version ?? "")"
            default: continue
            }
            // A program's flaws for other systems do not affect this Mac, and a program is updated as a whole: the
            // three most serious flaws no release fixes yet are named, the site lists the rest.
            var unresolved: [UnresolvedFlaw] = [], seenFlaws = Set<String>()
            for u in parts.flatMap(\.unresolved) where u.affectsThisMac && seenFlaws.insert(u.id).inserted { unresolved.append(u) }
            unresolved = Array(unresolved.sorted { ($0.severity ?? .low, $1.id) > ($1.severity ?? .low, $0.id) }.prefix(3))
            let allElsewhere = parts.allSatisfy { $0.group == .other && $0.target == nil && !$0.malicious }
            let command = allElsewhere || (!fixable && !malicious) ? nil : advice.command
            findings.append(Finding(
                id: id, group: group, subject: .package(ecosystem: worst.package.ecosystem, name: worst.package.name), title: title,
                component: Component.rowLabel(worst.label, installed: Component.shown(worst.package.version), fixed: worst.target.map(Component.shown)),
                installedVersion: Component.shown(worst.package.version),
                fixedVersion: worst.target.map(Component.shown), severity: malicious ? nil : severity, advisoryIDs: advisories,
                flawCount: flaws, exploited: exploited, malicious: malicious,
                note: [sentence, advice.note].compactMap { $0 }.joined(separator: " "), bigIssue: nil, origins: g.origins,
                pageURL: SiteURL.packagePage(worst.package.ecosystem, worst.package.name, version: worst.package.version),
                upgradeCommand: command, verification: .none, grade: nil, fixesCount: parts.count == 1 ? worst.fixes : nil,
                unresolved: unresolved, commandInputs: command == nil ? nil : Self.inputs(origin: g.origins[0], malicious: malicious)))
        }
    }

    /// The programs an app ships, when the app is already a finding of its own (its product record, a library it
    /// bundles): one finding for the app, with its programs' flaws in it, as for a Homebrew formula's project finding.
    public static func foldingProgramsIntoApps(_ findings: [Finding]) -> [Finding] {
        var out = findings
        var folded = Set<String>()
        for f in findings {
            let apps = f.origins.compactMap { o -> String? in if case let .program(p) = o, p.place == .app { return p.app }; return nil }
            guard let app = apps.first, apps.count == f.origins.count,
                  let i = out.firstIndex(where: { a in
                      a.id != f.id && !folded.contains(a.id) && a.origins.contains { o in
                          if case let .application(_, bundlePath, _) = o { return (bundlePath as NSString).lastPathComponent == app + ".app" }
                          return false
                      }
                  }) else { continue }
            // Its sentence, without the advice: the app's own finding already says how the app is updated.
            out[i].note = [out[i].note, f.note.map(Self.firstSentence)].compactMap { $0 }.joined(separator: " ")
            out[i].advisoryIDs += f.advisoryIDs.filter { !out[i].advisoryIDs.contains($0) }
            out[i].flawCount += f.flawCount
            out[i].exploited = out[i].exploited || f.exploited
            out[i].malicious = out[i].malicious || f.malicious
            if f.group < out[i].group { out[i].group = f.group }
            if let s = f.severity, out[i].severity.map({ s > $0 }) ?? true { out[i].severity = s }
            folded.insert(f.id)
        }
        return out.filter { !folded.contains($0.id) }
    }

    /// "Docker’s 6 programs were built with … known flaws." out of the note that follows it with advice.
    static func firstSentence(_ note: String) -> String {
        guard let end = note.range(of: ". ") else { return note }
        return String(note[..<end.lowerBound]) + "."
    }

    /// Worst first: malicious, exploited, critical and high, by severity, then by how many flaws; the standard
    /// library after modules of the same weight (a module is what an update most often changes).
    static func worseFirst(_ a: Component, _ b: Component) -> Bool {
        let ra = (a.group.rawValue, -(a.severity.map { Severity.allCases.firstIndex(of: $0)! } ?? -1), a.isStdlib ? 1 : 0, -a.flawCount, a.name)
        let rb = (b.group.rawValue, -(b.severity.map { Severity.allCases.firstIndex(of: $0)! } ?? -1), b.isStdlib ? 1 : 0, -b.flawCount, b.name)
        return ra < rb
    }

    /// "gh 2.62.0 was built with golang.org/x/net 0.23.0 — fixed in 0.33.0 · built with Go 1.22.3, whose stdlib has
    /// 4 known flaws." At most four parts are named; the rest are counted.
    static func sentence(for origin: Origin, programs: [Origin], parts: [Component]) -> String {
        let subject: String
        var plural = false
        switch origin {
        case let .program(p):
            let all = programs.compactMap { o -> BuiltProgram? in if case let .program(q) = o { return q }; return nil }
            let names = Array(Set(all.map(\.name))).sorted()
            let versions = Set(all.compactMap(\.version))
            let version = versions.count == 1 ? " " + versions.first! : ""
            plural = names.count > 1
            subject = names.count == 1 ? p.name + version
                : names.count <= 3 ? Self.list(names) + version
                : "\(p.formula ?? p.app ?? p.name)’s \(names.count) programs"
        case let .pythonTool(t): subject = t.name + (t.version.map { " \($0)" } ?? "")
        default: subject = ""
        }
        let isTool: Bool = { if case .pythonTool = origin { return true }; return false }()
        func flaws(_ n: Int) -> String { n == 1 ? "1 known flaw" : "\(n) known flaws" }
        // One clause per package, whatever versions the programs have of it: own package first, then what it was built
        // with, the standard library last.
        let named = Self.byName(parts)
        let ordered = named.filter { $0[0].own } + named.filter { !$0[0].own && !$0[0].isStdlib } + named.filter { $0[0].isStdlib }
        var clauses: [String] = []
        for (i, same) in ordered.prefix(4).enumerated() {
            let c = same[0]
            let built = i > 0 ? "built with" : plural ? "were built with" : "was built with"
            let versions = Core.shared.sortedVersions(Array(Set(same.map(\.package.version)))).map(Component.shown)
            let range = versions.count == 1 ? versions[0] : "\(versions.first!) to \(versions.last!)"
            let most = same.map(\.flawCount).max() ?? 0
            let target = Core.shared.newestVersion(same.compactMap(\.target)).map(Component.shown)
            let fix = same.contains(where: \.malicious) ? " — malicious" : target.map { " — fixed in \($0)" } ?? " — no fixed release yet"
            if c.own {
                clauses.append(c.malicious ? "is malicious" : "has \(flaws(most))" + fix)
            } else if c.isStdlib {
                clauses.append("\(built) Go \(range), whose stdlib has \(versions.count > 1 ? "up to " : "")\(flaws(most))")
            } else {
                clauses.append((isTool ? "uses" : built) + " \(c.name) \(range)" + fix)
            }
        }
        if ordered.count > 4 {
            let more = ordered.count - 4
            clauses.append("\(more) more \(isTool ? "package" : "dependenc")\(isTool ? (more == 1 ? "" : "s") : (more == 1 ? "y" : "ies")) with known flaws")
        }
        return "\(subject) " + clauses.joined(separator: " · ") + "."
    }

    /// The components grouped by package, in the order of their worst version.
    static func byName(_ parts: [Component]) -> [[Component]] {
        var order: [String] = [], groups: [String: [Component]] = [:]
        for c in parts {
            let key = "\(c.package.ecosystem)\u{1F}\(c.package.name)"
            if groups[key] == nil { order.append(key) }
            groups[key, default: []].append(c)
        }
        return order.map { groups[$0]! }
    }

    static func list(_ names: [String]) -> String {
        names.count <= 2 ? names.joined(separator: " and ") : names.dropLast().joined(separator: ", ") + " and " + names.last!
    }

    /// What the Fix button makes the command again from: only a Homebrew formula's program has one it may run
    /// (FixPlan); for the others the command is there to read and copy.
    static func inputs(origin: Origin, malicious: Bool) -> UpgradeCommand.Inputs? {
        guard case let .program(p) = origin, p.place == .homebrew, let formula = p.formula else { return nil }
        return UpgradeCommand.Inputs(origin: origin, name: formula, ecosystem: nil, target: nil, malicious: malicious)
    }

    /// The program's or tool's command.
    static func programAdvice(origin: Origin, programs: Int = 1, parts: [Component], malicious: Bool) -> UpgradeCommand.Advice {
        switch origin {
        case var .program(p):
            if programs > 1, p.formula == nil, p.app != nil { p.name = "them" }      // "Docker ships them."
            return UpgradeCommand.program(p, rebuildOnly: !parts.contains(where: \.own), malicious: malicious)
        case let .pythonTool(t):
            return UpgradeCommand.pythonTool(t, upgrades: parts.map { ($0.name, $0.target) }, malicious: malicious)
        default:
            return UpgradeCommand.Advice(command: nil)
        }
    }

    // MARK: MacPorts, Nix and conda packages matched to graded projects

    /// Like Homebrew's project findings: the project's recent critical, high and exploited advisories, each decided
    /// by the verified core against the installed version.
    func managedFindings(_ managed: [ManagedMatch], projects: [String: ProjectResponse]) -> [Finding] {
        var out: [Finding] = []
        for match in managed {
            guard let project = projects[match.project.slug] else { continue }
            let installed = match.package.version
            // Each advisory by the issuer's ranges when it has them, else by its first fixed versions (AdvisoryCheck).
            guard let d = AdvisoryCheck.decide(installed, project.recent) else { continue }
            let target = d.target
            let advice = UpgradeCommand.advice(for: match.package.origin, name: match.package.name, ecosystem: nil, target: target, malicious: false)
            out.append(Finding(
                id: Self.managedID(match.package), group: d.exploited ? .exploited : .criticalHigh,
                subject: .project(slug: project.slug, name: project.name, installedAs: match.package.name), title: project.name,
                installedVersion: installed, fixedVersion: target, severity: d.severity,
                advisoryIDs: d.advisories.map(\.id), flawCount: d.hits.count, exploited: d.exploited, malicious: false,
                note: [d.note, advice.note].compactMap { $0 }.joined(separator: " "),
                bigIssue: nil, origins: [match.package.origin], pageURL: SiteURL.projectPage(slug: project.slug),
                upgradeCommand: advice.command, verification: project.verificationMark, grade: project.grade))
        }
        return out
    }

    static func managedID(_ p: ManagedPackage) -> String {
        let place: String
        switch p.origin {
        case let .conda(env): place = env.prefix
        case let .nix(profile, _): place = profile.path
        default: place = ""
        }
        return "\(p.manager.rawValue)|\(p.name)|\(p.version)|\(place)"
    }

    /// The site's "patch these first" list, for packages matched through R lines (as for Homebrew's).
    func applyBigIssues(_ issues: [StateResponse.BigIssue], toManaged managed: [ManagedMatch], findings: inout [Finding],
                        projects: [String: ProjectResponse]) {
        for issue in issues where !issue.fixedIn.isEmpty {
            let label = "On the site's “patch these first” list: \(issue.title.isEmpty ? issue.name : issue.title)"
            let severity = Severity(api: issue.severity)
            let group: Finding.Group = issue.exploited ? .exploited : (severity ?? .low) >= .high ? .criticalHigh : .other
            let check = IssueCheck(issue, project: projects[issue.slug])        // the project's ranges when it has them
            for match in managed where match.project.slug == issue.slug {
                let v = match.package.version
                guard check.affects(v) else { continue }
                let target = check.fix(v)
                let id = Self.managedID(match.package)
                if let i = findings.firstIndex(where: { $0.id == id }) {
                    findings[i].bigIssue = label
                    if issue.exploited { findings[i].exploited = true }
                    if group < findings[i].group { findings[i].group = group }
                    if findings[i].severity == nil || (severity.map { $0 > findings[i].severity! } ?? false) { findings[i].severity = severity }
                    if findings[i].fixedVersion == nil { findings[i].fixedVersion = target }
                } else {
                    let project = projects[issue.slug]
                    let advice = UpgradeCommand.advice(for: match.package.origin, name: match.package.name, ecosystem: nil, target: target, malicious: false)
                    findings.append(Finding(
                        id: id, group: group, subject: .project(slug: issue.slug, name: project?.name ?? match.project.name, installedAs: match.package.name),
                        title: project?.name ?? match.project.name, installedVersion: v, fixedVersion: target, severity: severity,
                        advisoryIDs: issue.ids, flawCount: max(issue.ids.count, 1), exploited: issue.exploited, malicious: false,
                        note: check.note(v, target), bigIssue: label,
                        origins: [match.package.origin], pageURL: SiteURL.projectPage(slug: issue.slug), upgradeCommand: advice.command,
                        verification: project?.verificationMark ?? .none, grade: project?.grade))
                }
            }
        }
    }
}

extension Scanner {
    /// "Not checked" for the program sources: managed packages no R line names, and what the sources could not read.
    static func programCoverage(unmatchedManaged: [ManagedPackage], unchecked: [UncheckedItem]) -> [Coverage.Bucket] {
        var out: [Coverage.Bucket] = []
        let titles: [ManagedPackage.Manager: String] = [.macports: "MacPorts ports with no graded project",
                                                        .nix: "Nix packages with no graded project",
                                                        .conda: "conda packages with no graded project"]
        for manager in ManagedPackage.Manager.allCases {
            let items = unmatchedManaged.filter { $0.manager == manager }.map { "\($0.name) \($0.version)" }
            if !items.isEmpty { out.append(.init(source: titles[manager]!, items: Array(Set(items)).sorted())) }
        }
        var buckets: [String] = []
        for u in unchecked where !buckets.contains(u.bucket) { buckets.append(u.bucket) }
        for b in buckets {
            out.append(.init(source: b, items: Array(Set(unchecked.filter { $0.bucket == b }.map(\.item))).sorted()))
        }
        return out
    }
}

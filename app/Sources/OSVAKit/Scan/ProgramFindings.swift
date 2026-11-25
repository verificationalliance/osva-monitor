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
        /// How its flaws were checked against the site's ranges (nil: malicious).
        var check: Finding.Check?
        /// The server's target, when the core confirms it fixes some of the flaws the part is shown for (BatchCheck).
        var upgrade: CheckedUpgrade?
        /// Its affected and likely flaws on this Mac, which the program's sentence weighs the newest upgrade against.
        var flagged: [BatchResponse.Flaw]
        /// The flaws on this Mac it is not shown for (likely ones of an affected part, reported ones and those past the
        /// list), and the most urgent of them: said in the sentence, never hidden.
        var more: Int
        var moreAlert: Finding.NotChecked?
        /// Its most urgent flaw not checked against published ranges, when exploited or critical.
        var notChecked: Finding.NotChecked?
        var advisories: [String]
        var unresolved: [UnresolvedFlaw]
        var fixes: Int?
        /// The program's own module, crate or package, rather than something it was built with.
        var own: Bool
        /// Every flaw it has is of another platform: listed, nothing to do on this Mac. Such a part never decides how
        /// serious its program is, nor takes over the finding it is folded into.
        var onlyElsewhere = false

        var isStdlib: Bool { package.ecosystem == .go && package.name == "stdlib" }
        /// The upgrade's version as people write it (`shown`).
        var shownUpgrade: String? { upgrade.map { Self.shown($0.version) } }
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

    /// The same reading of an answer as `packageFindings` (BatchCheck, `state`): what affects this Mac, how serious, and
    /// the server's version only as the core confirmed it. Programs are installed software: macOS.
    func component(_ package: ApprovedPackage, _ verdict: BatchResponse.Result, name: String, own: Bool) -> Component {
        let check = BatchCheck.read(verdict, installed: package.version)
        let state = Self.state(verdict, check, onThisMac: true, program: true)
        let upgrade = state.malicious || state.onlyElsewhere || state.check == .reported ? nil : check.upgrade(for: state.here)
        let unresolved = state.malicious
            ? (verdict.plan?.remaining ?? []).filter { $0.reason != .malicious }.map { r in
                UnresolvedFlaw(id: r.id, severity: Severity(api: verdict.flaws.first { $0.id == r.id }?.severity), fixedIn: r.fixedIn,
                               reason: Self.reason(r.reason), detail: r.detail, python: package.python, onThisMac: true)
            }
            : state.check == .reported ? [] : Self.unresolved(check, upgrade: upgrade, python: package.python, onThisMac: true)
        let decided = (state.check == .affected || state.check == .likely) && !state.onlyElsewhere
        return Component(package: package, name: name, group: state.group, severity: state.severity, flawCount: state.flawCount,
                         exploited: state.exploited, malicious: state.malicious, check: state.check, upgrade: upgrade,
                         flagged: decided ? check.flagged.filter(\.affectsThisMac) : [], more: state.moreLikely + state.moreReported,
                         moreAlert: .worse(state.likelyAlert, state.reportedAlert), notChecked: state.notChecked,
                         advisories: verdict.advisories, unresolved: unresolved,
                         fixes: Self.fixesCount(check, state, upgrade: upgrade, plan: verdict.plan), own: own, onlyElsewhere: state.onlyElsewhere)
    }

    /// The parts a program's flaw count is made of: of those with flaws on this Mac, the ones the core found affected
    /// (and malicious ones), else the likely ones, else the reported ones, as for a package's finding. Only when every
    /// part's flaws are of another platform, those.
    static func countedParts(_ parts: [Component]) -> [Component] {
        let here = parts.filter { !$0.onlyElsewhere }
        guard !here.isEmpty else { return parts }
        let checked = here.filter { !$0.group.isNotChecked }
        if !checked.isEmpty { return checked }
        let likely = here.filter { $0.group == .likely }
        return likely.isEmpty ? here : likely
    }

    /// The parts that decide a program's group and weigh in a finding it is folded into: those with flaws on this Mac.
    static func partsHere(_ parts: [Component]) -> [Component] { parts.filter { !$0.onlyElsewhere } }

    /// Flaws counted once per package: versions of one package share most of their flaws, so the most any of them has
    /// stands for all.
    static func flawCount(_ parts: [Component]) -> Int {
        Self.byName(parts).reduce(0) { $0 + ($1.map(\.flawCount).max() ?? 0) }
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
            // How serious it is, and how many flaws: from the parts the core checked when there are any (FindingBuilder.state)
            let counted = Self.countedParts(parts)
            let severity = counted.compactMap(\.severity).max(), exploited = counted.contains(where: \.exploited)
            let malicious = parts.contains(where: \.malicious)
            // an affected part's group beats likely and reported; a part with flaws only elsewhere decides nothing
            let here = Self.partsHere(parts)
            let group = (here.isEmpty ? parts : here).map(\.group).min()!
            let advisories = Array(Set(parts.flatMap(\.advisories))).sorted()
            let flaws = Self.flawCount(counted)
            let notChecked = parts.map(\.notChecked).reduce(nil, Finding.NotChecked.worse)

            // A Homebrew formula already reported as a graded project: one finding, with its programs' flaws in it. Only
            // the parts the core checked add flaws and weight to it: a likely or reported part is said in the sentence.
            // A project finding the core did not check (its advisories publish no ranges) that takes in a checked part
            // is decided by it, as an affected flaw decides a package's finding: its own advisories stay in its note
            // and its mark.
            if case let .program(p) = g.origins[0], let formula = p.formula,
               let i = findings.firstIndex(where: { f in
                   if case .project = f.subject { return f.origins.contains(.homebrewFormula(name: formula)) }
                   return false
               }) {
                let checked = here.filter { !$0.group.isNotChecked }
                findings[i].note = [findings[i].note, sentence].compactMap { $0 }.joined(separator: " ")
                findings[i].advisoryIDs += advisories.filter { !findings[i].advisoryIDs.contains($0) }
                if findings[i].group.isNotChecked && !checked.isEmpty {
                    findings[i].flawCount = Self.flawCount(checked)
                    findings[i].exploited = checked.contains(where: \.exploited)
                    findings[i].severity = checked.compactMap(\.severity).max()
                }
                else {
                    findings[i].flawCount += Self.flawCount(checked)
                    findings[i].exploited = findings[i].exploited || checked.contains(where: \.exploited)
                    if let s = checked.compactMap(\.severity).max(), findings[i].severity.map({ s > $0 }) ?? true { findings[i].severity = s }
                }
                findings[i].malicious = findings[i].malicious || malicious
                findings[i].notChecked = .worse(findings[i].notChecked, notChecked)
                if !here.isEmpty && group < findings[i].group { findings[i].group = group }
                continue
            }

            let advice = Self.programAdvice(origin: g.origins[0], programs: g.origins.count, parts: parts, malicious: malicious)
            let fixable = parts.contains { $0.upgrade != nil }
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
            // without an upgrade on the row, no "not by this upgrade" line
            if worst.upgrade == nil { unresolved.removeAll { $0.reason == .unknown } }
            unresolved = Array(unresolved.sorted { ($0.severity ?? .low, $1.id) > ($1.severity ?? .low, $0.id) }.prefix(3))
            let allElsewhere = parts.allSatisfy { $0.group == .other && $0.upgrade == nil && !$0.malicious }
            let command = allElsewhere || (!fixable && !malicious) ? nil : advice.command
            var program = Finding(
                id: id, group: group, subject: .package(ecosystem: worst.package.ecosystem, name: worst.package.name), title: title,
                component: Component.rowLabel(worst.label, installed: Component.shown(worst.package.version), fixed: worst.shownUpgrade),
                installedVersion: Component.shown(worst.package.version),
                fixedVersion: worst.shownUpgrade, severity: malicious ? nil : severity, advisoryIDs: advisories,
                flawCount: flaws, exploited: exploited, malicious: malicious,
                note: [sentence, advice.note].compactMap { $0 }.joined(separator: " "), bigIssue: nil, origins: g.origins,
                pageURL: SiteURL.packagePage(worst.package.ecosystem, worst.package.name, version: worst.package.version),
                upgradeCommand: command, verification: .none, grade: nil, fixesCount: parts.count == 1 ? worst.fixes : nil,
                unresolved: unresolved, commandInputs: command == nil ? nil : Self.inputs(origin: g.origins[0], malicious: malicious),
                notChecked: notChecked)
            if here.isEmpty { program.onlyElsewhere = true }
            findings.append(program)
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
            // Its sentence, without the advice: the app's own finding already says how the app is updated. A program
            // with no part the core checked adds no flaws and no weight: it is said, not counted. An app's finding the
            // core did not check, taking in a checked program, is decided by it, as for a formula's project finding.
            let elsewhere = f.onlyElsewhere == true                 // nothing to do on this Mac: said, never weighed
            let checked = !f.group.isNotChecked && !elsewhere
            out[i].note = [out[i].note, f.note.map(Self.firstSentence)].compactMap { $0 }.joined(separator: " ")
            out[i].advisoryIDs += f.advisoryIDs.filter { !out[i].advisoryIDs.contains($0) }
            if checked && out[i].group.isNotChecked {
                out[i].flawCount = f.flawCount; out[i].exploited = f.exploited; out[i].severity = f.severity
            } else if checked {
                out[i].flawCount += f.flawCount
                out[i].exploited = out[i].exploited || f.exploited
                if let s = f.severity, out[i].severity.map({ s > $0 }) ?? true { out[i].severity = s }
            }
            out[i].malicious = out[i].malicious || f.malicious
            out[i].notChecked = .worse(out[i].notChecked, f.notChecked)
            if !elsewhere && f.group < out[i].group { out[i].group = f.group }
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
    /// library after modules of the same weight (a module is what an update most often changes); a part whose flaws
    /// are all of another platform after every part with flaws on this Mac.
    static func worseFirst(_ a: Component, _ b: Component) -> Bool {
        let ra = (a.onlyElsewhere ? 1 : 0, a.group.rawValue, -(a.severity.map { Severity.allCases.firstIndex(of: $0)! } ?? -1), a.isStdlib ? 1 : 0, -a.flawCount, a.name)
        let rb = (b.onlyElsewhere ? 1 : 0, b.group.rawValue, -(b.severity.map { Severity.allCases.firstIndex(of: $0)! } ?? -1), b.isStdlib ? 1 : 0, -b.flawCount, b.name)
        return ra < rb
    }

    /// "gh 2.62.0 was built with golang.org/x/net 0.23.0 — fixed in 0.33.0 · built with Go 1.22.3, whose stdlib has
    /// 4 known flaws." At most four parts are named; the rest are counted. A package's newest upgrade is judged by the
    /// core again, from its newest installed version and against the affected and likely flaws of all its versions:
    /// "fixed in" when it leaves them all, "partly fixed in" when it leaves some, "no fixed release yet" when it leaves
    /// none; "reported, not checked" when no version of it has a flaw the core checked. Call it off the main thread.
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
            let most = Self.countedParts(same).map(\.flawCount).max() ?? 0
            let malicious = same.contains(where: \.malicious), reported = same.allSatisfy { $0.check == .reported }
            let fix = malicious ? " — malicious" : Self.fixClause(same)
            let more = malicious || reported ? "" : Self.moreClause(same)
            if c.own {
                clauses.append(c.malicious ? "is malicious" : "has \(flaws(most))" + fix + more)
            } else if c.isStdlib {
                clauses.append("\(built) Go \(range), whose stdlib has \(versions.count > 1 ? "up to " : "")\(flaws(most))" + (reported ? fix : more))
            } else {
                clauses.append((isTool ? "uses" : built) + " \(c.name) \(range)" + fix + more)
            }
        }
        if ordered.count > 4 {
            let more = ordered.count - 4
            clauses.append("\(more) more \(isTool ? "package" : "dependenc")\(isTool ? (more == 1 ? "" : "s") : (more == 1 ? "y" : "ies")) with known flaws")
        }
        return "\(subject) " + clauses.joined(separator: " · ") + "."
    }

    /// What the newest upgrade of one package's versions does, by the core: " — fixed in 0.62.0", " — partly fixed in
    /// 0.62.0", " — no fixed release yet", or " — reported, not checked" when none of them has a checked flaw.
    static func fixClause(_ same: [Component]) -> String {
        if same.allSatisfy({ $0.check == .reported }) {
            let alert = same.map(\.notChecked).reduce(nil, Finding.NotChecked.worse)
            return " — reported, not checked" + BatchCheck.parenthetical(alert, count: same.map(\.flawCount).max() ?? 0)
        }
        // judged from this Mac's flaws, at the versions they were found in (a version with only reported flaws is not one)
        let core = Core.shared
        let decided = same.filter { !$0.flagged.isEmpty }
        var seen = Set<String>(), flaws: [BatchResponse.Flaw] = []
        for f in decided.flatMap(\.flagged) where seen.insert(f.id).inserted { flaws.append(f) }
        let advisories = flaws.compactMap(\.coreAdvisory)                    // every flagged flaw has one (BatchCheck)
        guard let target = core.newestVersion(decided.compactMap { $0.upgrade?.version }),
              let installed = core.newestVersion(decided.map(\.package.version)), advisories.count == flaws.count,
              let judged = core.judge(target, from: installed, advisories: advisories, flagged: [Bool](repeating: true, count: advisories.count)),
              let upgrade = judged.upgrade else { return " — no fixed release yet" }
        let shown = Component.shown(upgrade.version)
        return judged.leaves.allSatisfy { $0 } ? " — fixed in \(shown)" : " — partly fixed in \(shown)"
    }

    /// ", and 2 more reported, not checked (CVE-X, exploited in the wild)": the flaws on this Mac one package's versions
    /// have beyond those the clause counts (a counted version's others; all of a version that is not counted), and the
    /// most urgent of them; "" when there are none.
    static func moreClause(_ same: [Component]) -> String {
        let counted = Set(countedParts(same).map(\.package))
        let more = same.map { counted.contains($0.package) ? $0.more : $0.flawCount + $0.more }.max() ?? 0
        guard more > 0 else { return "" }
        let alert = same.map { counted.contains($0.package) ? $0.moreAlert : $0.notChecked }.reduce(nil, Finding.NotChecked.worse)
        return ", and \(more) more reported, not checked" + BatchCheck.parenthetical(alert, count: more)
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
            return UpgradeCommand.pythonTool(t, upgrades: parts.map { ($0.name, $0.upgrade?.version) }, malicious: malicious)
        default:
            return UpgradeCommand.Advice(command: nil)
        }
    }

    // MARK: MacPorts, Nix and conda packages matched to graded projects

    /// Like Homebrew's project findings: the project's recent critical, high and exploited advisories, each decided
    /// by the verified core against the installed version (AdvisoryCheck).
    func managedFindings(_ managed: [ManagedMatch], projects: [String: ProjectResponse], decided: inout [String: Decided]) -> [Finding] {
        var out: [Finding] = []
        for match in managed {
            guard let project = projects[match.project.slug] else { continue }
            guard let d = AdvisoryCheck.decide(match.package.version, project.recent) else { continue }
            let make = { (d: AdvisoryCheck) in
                Self.managedFinding(match, slug: project.slug, name: project.name, grade: project.grade, mark: project.verificationMark, d)
            }
            let f = make(d)
            decided[f.id] = .advisories(d, make)
            out.append(f)
        }
        return out
    }

    /// A MacPorts, Nix or conda package's finding, as its project's advisories (or an item of the "patch these first"
    /// list) decided it.
    static func managedFinding(_ match: ManagedMatch, slug: String, name: String, grade: String?, mark: Verification, _ d: AdvisoryCheck) -> Finding {
        let advice = managedAdvice(match.package, upgrade: d.target)
        return Finding(
            id: managedID(match.package), group: d.group,
            subject: .project(slug: slug, name: name, installedAs: match.package.name), title: name,
            installedVersion: match.package.version, upgrade: d.target, severity: d.severity,
            advisoryIDs: d.advisories.map(\.id), flawCount: d.flawCount, exploited: d.exploited, malicious: false,
            note: sentences(d.note, advice.note),
            bigIssue: nil, origins: [match.package.origin], pageURL: SiteURL.projectPage(slug: slug),
            upgradeCommand: advice.command, verification: mark, grade: grade, notChecked: d.notChecked)
    }

    /// MacPorts, Nix and conda pick the version themselves, and only Homebrew's picks are taken without one the core
    /// checked: without a checked upgrade, no command, and no note about running one.
    static func managedAdvice(_ p: ManagedPackage, upgrade: CheckedUpgrade?) -> UpgradeCommand.Advice {
        guard let upgrade else { return UpgradeCommand.Advice(command: nil) }
        return UpgradeCommand.advice(for: p.origin, name: p.name, ecosystem: nil, target: upgrade, malicious: false)
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

    /// The site's "patch these first" list, for packages matched through R lines, decided as for Homebrew's.
    func applyBigIssues(_ issues: [StateResponse.BigIssue], toManaged managed: [ManagedMatch], findings: inout [Finding],
                        projects: [String: ProjectResponse], decided: inout [String: Decided]) {
        for issue in issues {
            let check = IssueCheck(issue, project: projects[issue.slug])        // the project's ranges when it has them
            for match in managed where match.project.slug == issue.slug {
                let v = match.package.version
                guard let verdict = check.verdict(v) else { continue }
                let id = Self.managedID(match.package)
                if let i = findings.firstIndex(where: { $0.id == id }) {
                    Self.apply(issue, verdict: verdict, item: check, to: &findings[i], decided: &decided)
                    continue
                }
                let project = projects[issue.slug]
                let make = { (d: AdvisoryCheck) in
                    Self.managedFinding(match, slug: issue.slug, name: project?.name ?? match.project.name, grade: project?.grade,
                                        mark: project?.verificationMark ?? .none, d)
                }
                let d = AdvisoryCheck.forItem(issue, check, verdict: verdict, installed: v)
                findings.append(Self.labelled(make(d), issue))
                decided[id] = .advisories(d, make)
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

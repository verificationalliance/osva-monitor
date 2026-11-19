import Foundation

/// Java runtimes (JavaSource) matched on this Mac to what the public index can check them against, and turned into
/// findings with the verified decision Homebrew's projects use, on the runtime's version in Java's canonical form.
///
/// What a runtime is checked against comes from the index, not from a list here (`route`):
///   1. its vendor's own record, when the index has a `C jre <vendor> <product>` line for it (`JavaVendor.rawValue`:
///      "oracle", "graalvm", "temurin" …), the way the runtimes bundled in apps are mapped by `C jre java <product>`;
///   2. else, for a build of OpenJDK (Temurin, Zulu, Corretto, Microsoft, Homebrew, Red Hat, Liberica, SapMachine,
///      JetBrains Runtime, one by an unnamed builder) and for Oracle's JDK, which is built from the same sources, the
///      graded project "openjdk", when the index lists it;
///   3. else nothing: GraalVM and Semeru are listed as not checked, with the reason. GraalVM is never checked against
///      OpenJDK's advisories: the site keeps GraalVM's version lists apart from OpenJDK's.
/// So a product the index adds later (Oracle Java SE, GraalVM) is used without a change here. A runtime from a Homebrew
/// formula or cask that is already checked as a graded project is that finding, not a second one.
///
/// Matching reads only this Mac's files and the downloaded index. What a scan may then ask about is the project slug or
/// product key the index itself lists, through the privacy filter; paths, folder names, vendors and versions stay here.
public struct JavaCheck: Sendable {
    public enum Route: Hashable, Sendable {
        case project(slug: String, name: String)
        case product(ProductIndex.Component)
    }

    public struct Match: Hashable, Sendable {
        public var runtime: JavaRuntime
        public var route: Route
    }

    public var matches: [Match] = []
    /// Runtimes the index offers nothing to check against.
    public var unmatched: [JavaRuntime] = []

    public init(matches: [Match] = [], unmatched: [JavaRuntime] = []) { self.matches = matches; self.unmatched = unmatched }

    /// The project OpenJDK's builds are checked as.
    public static let openJDK = "openjdk"

    /// `checkedBrew`: the Homebrew formulae and casks matched to a graded project; their runtimes are their findings.
    public static func match(_ runtimes: [JavaRuntime], index: PublicIndex, checkedBrew: Set<String> = []) -> JavaCheck {
        var out = JavaCheck()
        for r in runtimes {
            if let f = r.formula, checkedBrew.contains(f) { continue }
            if let c = r.cask, checkedBrew.contains(c) { continue }
            if let route = route(for: r.vendor, in: index) { out.matches.append(Match(runtime: r, route: route)) } else { out.unmatched.append(r) }
        }
        return out
    }

    public static func route(for vendor: JavaVendor, in index: PublicIndex) -> Route? {
        if let c = index.products.components.first(where: { $0.kind == .jre && $0.match == vendor.rawValue }) { return .product(c) }
        if vendor.sharesOpenJDK, let p = index.project(slug: openJDK) { return .project(slug: p.slug, name: p.name) }
        return nil
    }

    public var projectSlugs: [String] {
        matches.compactMap { if case let .project(slug, _) = $0.route { return slug }; return nil }
    }

    public var productKeys: [String] {
        matches.compactMap { if case let .product(c) = $0.route { return c.product }; return nil }
    }

    /// The casks whose JDK is checked here: their own line under Homebrew would say nothing checks them.
    public var casks: Set<String> { Set((matches.map(\.runtime) + unmatched).compactMap(\.cask)) }

    // MARK: Findings

    public func findings(products: [String: ProductResponse], projects: [String: ProjectResponse]) -> [Finding] {
        matches.compactMap { finding($0, products: products, projects: projects) }
    }

    func finding(_ m: Match, products: [String: ProductResponse], projects: [String: ProjectResponse]) -> Finding? {
        let r = m.runtime
        let subject: Finding.Subject, recent: [ProjectResponse.Advisory], page: URL
        var grade: String?, mark = Verification.none
        switch m.route {
        case let .project(slug, _):
            guard let p = projects[slug] else { return nil }
            (subject, recent, page) = (.project(slug: slug, name: p.name, installedAs: "java"), p.recent, SiteURL.projectPage(slug: slug))
            // OpenJDK's grade and mark beside a build of it; not beside Oracle's JDK, which is only checked as it
            if r.vendor != .oracle { (grade, mark) = (p.grade, p.verificationMark) }
        case let .product(c):
            guard let record = products[c.product] else { return nil }
            (subject, recent, page) = (.product(key: c.product, name: record.name), record.recent, record.sourceURL ?? SiteURL.home)
        }
        let vendor = Self.vendorFixes(r, recent)
        guard let d = AdvisoryCheck.decide(r.canonical, vendor.recent) else { return nil }
        let origin = Origin.javaRuntime(r)
        // the issuer names no fix, the vendor's own record does: its build is the fix this row names
        let target = d.target.map(JavaVersion.shown) ?? vendor.fix
        let vendorNote = d.target == nil ? vendor.fix.flatMap { fix in r.vendor.buildScheme.map { "\($0.dist)'s changelog lists the fix in \(r.vendor.title) \(fix)." } } : nil
        let inputs = UpgradeCommand.Inputs(origin: origin, name: r.cask ?? r.formula ?? r.vendor.rawValue, ecosystem: nil, target: nil, malicious: false)
        let advice = UpgradeCommand.advice(inputs)
        return Finding(
            id: "java|\(r.realPath)|\(r.canonical)", group: d.exploited ? .exploited : .criticalHigh, subject: subject, title: r.title,
            installedVersion: r.shownVersion, fixedVersion: target, severity: d.severity,
            advisoryIDs: d.advisories.map(\.id), flawCount: d.hits.count, exploited: d.exploited, malicious: false,
            note: [d.note(showing: JavaVersion.shown), vendorNote, vendor.cleared, advice.note].compactMap { $0 }.joined(separator: " "), bigIssue: nil,
            origins: [origin], pageURL: page, upgradeCommand: advice.command, verification: mark, grade: grade,
            commandInputs: advice.command == nil ? nil : inputs)
    }

    /// The advisories a vendor's own build already fixes, set aside: an advisory whose `fixed_builds` names a build of
    /// this vendor on this runtime's line, at or below the runtime's own build (by the verified core's order), does not
    /// apply to it, whatever its JAVA_VERSION says. Below that build it stands, and that build is the fix to name.
    /// Every other vendor, and a runtime whose build is not known, is decided by the advisory's ranges alone.
    static func vendorFixes(_ r: JavaRuntime, _ recent: [ProjectResponse.Advisory])
        -> (recent: [ProjectResponse.Advisory], fix: String?, cleared: String?) {
        guard let scheme = r.vendor.buildScheme, let build = r.vendorBuild else { return (recent, nil, nil) }
        let core = Core.shared, line = ComponentReader.majorOf(build)
        var kept: [ProjectResponse.Advisory] = [], fixes: [String] = [], cleared: [String] = []
        for a in recent {
            let builds = a.fixedBuilds.filter { $0.dist == scheme.dist && ComponentReader.majorOf($0.build) == line && FixSafety.isSafeVersion($0.build) }
            guard let first = core.sortedVersions(builds.map(\.build)).first else { kept.append(a); continue }
            if core.compareVersions(build, first) >= 0 { cleared.append(a.cve ?? a.id); continue }
            kept.append(a); fixes.append(first)
        }
        let said = cleared.isEmpty ? nil
            : "\(r.vendor.title) \(build) has \(scheme.dist)'s fix for \(cleared.joined(separator: ", ")), so \(cleared.count == 1 ? "it does" : "they do") not count here."
        return (kept, core.newestVersion(fixes), said)
    }

    // MARK: What was not checked

    /// The heading of runtimes nothing here has advisories for.
    public static let noRecord = "Java runtimes with no advisory record"

    /// GraalVM and Semeru, and any runtime whose record could not be read (offline, or the server has none).
    public func notChecked(products: [String: ProductResponse], projects: [String: ProjectResponse]) -> [Coverage.Bucket] {
        let missing = matches.filter { m in
            switch m.route {
            case let .project(slug, _): return projects[slug] == nil
            case let .product(c): return products[c.product] == nil
            }
        }.map(\.runtime)
        let items = Array(Set((unmatched + missing).map(\.listItem))).sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }
        return items.isEmpty ? [] : [Coverage.Bucket(source: Self.noRecord, items: items)]
    }
}

extension UpgradeCommand {
    /// A Java runtime, where it came from: its Homebrew cask or formula (a command), else what to do, as text. SDKMAN,
    /// asdf and mise are named, not run: `sdk` is a shell function, and none of the three says which install replaces
    /// which, so the app could not check the result.
    static func java(_ r: JavaRuntime) -> Advice {
        if let cask = r.cask { return Advice(command: "brew upgrade --cask \(quote(cask))") }
        if let formula = r.formula { return Advice(command: "brew upgrade \(quote(formula))") }
        let line = "Java \(r.major)"
        switch r.place {
        case .sdkman: return Advice(command: nil, note: "SDKMAN installed it: install a newer \(line) with sdk install java.")
        case .asdf: return Advice(command: nil, note: "asdf installed it: install a newer \(line) with asdf install java.")
        case .mise: return Advice(command: nil, note: "mise installed it: install a newer \(line) with mise install java.")
        case .intellij: return Advice(command: nil, note: "IntelliJ IDEA downloaded it: download a newer \(line) there, in Project Structure > SDKs.")
        default: break
        }
        if r.vendor == .jetbrains { return Advice(command: nil, note: "It comes with a JetBrains IDE: updating the IDE updates it.") }
        guard let site = r.vendor.download else { return Advice(command: nil, note: "Update it where it came from.") }
        return Advice(command: nil, note: "Install the newest \(line) update from \(site).")
    }
}

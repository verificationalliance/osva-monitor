import Foundation

/// What one scan looks at and where it keeps things.
public struct ScanConfiguration: Sendable {
    public var storage: Storage
    public var tools: ToolEnvironment
    public var folders: [URL]
    public var applicationRoots: [URL]
    public init(storage: Storage, tools: ToolEnvironment = ToolEnvironment(), folders: [URL], applicationRoots: [URL]? = nil) {
        self.storage = storage; self.tools = tools; self.folders = folders
        self.applicationRoots = applicationRoots ?? ElectronSource.defaultRoots(home: tools.home)
    }
}

/// One scan: take inventory, download the public index, let the verified core decide what may be sent, ask the API
/// about that, and turn the answers into findings.
public actor Scanner {
    /// How long answers are reused before asking again.
    public enum Freshness {
        public static let index: TimeInterval = 86_400
        public static let batchVerdict: TimeInterval = 12 * 3600
        public static let project: TimeInterval = 6 * 3600
        public static let state: TimeInterval = 3600
    }

    /// Where exact-version answers are cached. Answers saved by 0.5.1 and before ("batch") have no ranges, so they are
    /// never read as checked answers: a scan asks again and keeps the new answer here.
    static let batchCache = "batch-v2"

    private let configuration: ScanConfiguration
    private let indexStore: IndexStore
    private let api: APIClient
    private var cache: DiskCache { configuration.storage.cache }

    public init(configuration: ScanConfiguration, transport: any HTTPTransport = URLSessionTransport(),
                limiter: RateLimiter = RateLimiter(), pause: @escaping @Sendable (Duration) async -> Void = { try? await Task.sleep(for: $0) }) {
        self.configuration = configuration
        indexStore = IndexStore(directory: configuration.storage.directory, transport: transport)
        api = APIClient(transport: transport, limiter: limiter, pause: pause)
    }

    /// Scans. `refresh` names the sources to look at again (all when nil); the others are taken from `previous`.
    public func scan(previous: ScanReport? = nil, refresh: Set<SourceKind>? = nil,
                     progress: @escaping @Sendable (String) -> Void = { _ in }) async -> ScanReport {
        let started = Date()
        var problems: [String] = []
        _ = await api.takeSentRequests()

        // 1. Inventory: stays on this Mac.
        let kinds = refresh ?? Set(SourceKind.allCases)
        progress("Looking at what is installed…")
        let fresh = await takeInventory(kinds)
        let inventory = previous.map { $0.inventory.replacing(kinds, with: fresh) } ?? fresh
        for r in inventory.reports where r.error != nil { problems.append("\(r.kind.title): \(r.error!)") }

        // 2. The public index: downloading it says nothing about this Mac.
        progress("Reading the public index…")
        let index: PublicIndex
        do {
            let loaded = try await indexStore.load(maxAge: Freshness.index)
            index = loaded.index
            if let p = loaded.problem { problems.append(p) }
        } catch {
            problems.append("Could not download the public index (\(error.localizedDescription)); nothing was checked.")
            return ScanReport(startedAt: started, finishedAt: Date(), inventory: inventory, findings: previous?.findings ?? [],
                              sent: SentRecord(), indexGeneratedAt: previous?.indexGeneratedAt, problems: problems)
        }

        // 3. The verified core decides what may be named to the server.
        let filter = PrivacyFilter(index: index)
        let selection = filter.approve(inventory.packages)
        let brew = inventory.homebrew.compactMap { item in
            ProjectMatcher.project(for: item, in: index).map { FindingBuilder.BrewMatch(item: item, project: $0) }
        }
        // MacPorts, Nix and conda packages that the index's R lines name as a graded project's software.
        let managed = inventory.managed.compactMap { p in
            index.project(manager: p.manager.rawValue, package: p.name).map { FindingBuilder.ManagedMatch(package: p, project: $0) }
        }
        // Apps, the libraries they bundle, and extensions are matched to the index here, on this Mac (BundleCheck).
        progress("Reading apps and extensions…")
        let bundles = BundleCheck.match(inventory, index: index)
        // Java runtimes: by vendor, to a record the index has (JavaCheck). A Homebrew formula's or cask's JDK that is
        // already checked as a graded project is that finding.
        let java = JavaCheck.match(inventory.javaRuntimes, index: index, checkedBrew: Set(brew.map(\.item.name)))
        let approvedProducts = filter.approve(products: bundles.productKeys + java.productKeys)
        let approvedProjects = filter.approve(projects: brew.map(\.project.slug) + bundles.projectSlugs + managed.map(\.project.slug)
                                                  + java.projectSlugs)
        let allowed = Set(approvedProjects.map(\.slug))
        let brewChecked = brew.filter { allowed.contains($0.project.slug) }
        let managedChecked = managed.filter { allowed.contains($0.project.slug) }
        var fromCache: [String] = []                         // what the cache answered, as it was sent

        // 4. Exact versions, 200 at a time.
        let packages = selection.approved.keys.sorted { $0.cacheKey < $1.cacheKey }
        var verdicts: [ApprovedPackage: BatchResponse.Result] = [:]
        var toAsk: [ApprovedPackage] = []
        for p in packages {
            if let cached = cache.readJSON(CachedVerdict.self, Self.batchCache, p.cacheKey, maxAge: Freshness.batchVerdict) {
                if let r = cached.result { verdicts[p] = r }
                fromCache.append(p.sentDescription)
            } else {
                toAsk.append(p)
            }
        }
        for chunk in Self.batches(toAsk) {
            progress("Checking \(toAsk.count) package versions…")
            do {
                let results = try await api.checkBatch(chunk)
                // Within one batch every package and version is asked once (see `batches`), so the answer's
                // ecosystem, name and version identify the question even when the server does not echo the Python.
                let byKey = Dictionary(results.map { ("\($0.ecosystem)\u{1F}\($0.name)\u{1F}\($0.version)", $0) }, uniquingKeysWith: { a, _ in a })
                for p in chunk {
                    let r = byKey[p.versionKey]
                    if let r { verdicts[p] = r }
                    cache.writeJSON(CachedVerdict(result: r), Self.batchCache, p.cacheKey)
                }
            } catch {
                problems.append("Exact-version check: \(error.localizedDescription)")
                if error as? APIClient.APIError == .keptRateLimiting { break }
            }
        }

        // 5. Projects matched from Homebrew (and those the vulnerable packages belong to are already in the answers).
        var projects: [String: ProjectResponse] = [:]
        for p in approvedProjects {
            if let cached = cache.readJSON(ProjectResponse.self, "project", p.slug, maxAge: Freshness.project) {
                projects[p.slug] = cached; fromCache.append(p.sentDescription); continue
            }
            progress("Reading \(p.slug)'s advisories…")
            do {
                let r = try await api.project(p)
                projects[p.slug] = r
                cache.writeJSON(r, "project", p.slug)
            } catch {
                problems.append("Project \(p.slug): \(error.localizedDescription)")
                if error as? APIClient.APIError == .keptRateLimiting { break }
            }
        }

        // 5b. Product records of the apps and bundled libraries the index lists.
        let products = await BundleCheck.records(approvedProducts, api: api, cache: cache, maxAge: Freshness.project, progress: progress)
        problems += products.problems
        fromCache += products.fromCache

        // 6. The site's "patch these first" list.
        var bigIssues: [StateResponse.BigIssue] = []
        if let cached = cache.readJSON(StateResponse.self, "state", "state", maxAge: Freshness.state) {
            bigIssues = cached.bigIssues
        } else {
            do {
                let s = try await api.state()
                bigIssues = s.bigIssues
                cache.writeJSON(s, "state", "state")
            } catch {
                problems.append("“Patch these first” list: \(error.localizedDescription)")
            }
        }

        // 7. Findings, and what could not be vouched for.
        let built = FindingOrder.sorted(FindingBuilder.foldingProgramsIntoApps(
            FindingBuilder(index: index).findings(approved: selection.approved, verdicts: verdicts, brew: brewChecked, projects: projects,
                                                  bigIssues: bigIssues, managed: managedChecked)
                + bundles.findings(products: products.records, projects: projects)
                + java.findings(products: products.records, projects: projects)))
        // Where each finding's copies are and why: read from this Mac's files, after every request was made.
        let findings = await ProvenanceExplainer(tools: configuration.tools).explain(built, inventory: inventory)
        let checkedBrew = Set(brewChecked.map(\.item))
        let notMatchedBrew = inventory.homebrew.filter { !checkedBrew.contains($0) }
        // A formula whose programs were read for what they were built with has been checked, graded project or not.
        let formulaeWithPrograms = Set(inventory.packages.compactMap { p -> String? in
            if case let .program(program) = p.origin { return program.formula }
            return nil
        })
        // ... and so has a cask whose JDK is checked as a Java runtime.
        let javaCasks = java.casks
        let unmatchedBrew = notMatchedBrew.filter { !($0.kind == .formula && formulaeWithPrograms.contains($0.name)) && !($0.kind == .cask && javaCasks.contains($0.name)) }
        let checkedManaged = Set(managedChecked.map(\.package))
        let unmatchedManaged = inventory.managed.filter { !checkedManaged.contains($0) }
        let listedUnderHomebrew = Set(unmatchedBrew.map(\.name))
        let accounted = bundles.accountedApps(products: products.records)
        let apps = AppCoverage.buckets(inventory.otherApps.filter { !accounted.contains($0) }, apps: inventory.apps)
        var coverage = Self.coverage(withheld: selection.withheld, unmatchedBrew: unmatchedBrew, apps: apps.notChecked,
                                     unmatchedManaged: unmatchedManaged,
                                     unchecked: inventory.unchecked.filter { $0.formula.map { !listedUnderHomebrew.contains($0) } ?? true })
        coverage.notChecked += bundles.notChecked(products: products.records, projects: projects)
        coverage.notChecked += java.notChecked(products: products.records, projects: projects)
        coverage.updatedElsewhere = apps.updatedElsewhere
        // What stayed on this Mac counts every formula no project stands for, programs read or not: none was named.
        let withheld = Self.withheld(selection.withheld, unmatchedBrew: notMatchedBrew, unmatchedManaged: unmatchedManaged)
        let sent = SentRecord(requests: await api.takeSentRequests(), withheldCount: withheld.reduce(0) { $0 + $1.items.count },
                              answeredFromCache: fromCache.count, cached: fromCache, withheld: withheld)
        progress("")
        return ScanReport(startedAt: started, finishedAt: Date(), inventory: inventory, findings: findings, sent: sent,
                          indexGeneratedAt: index.generatedAt, problems: problems, coverage: coverage)
    }

    // MARK: One finding again, after a fix

    /// What a re-check found.
    public enum Recheck: Equatable, Sendable {
        /// Installed now at this version (as the row writes it: "1.30.7", "Electron 42.11.16"), and nothing found.
        case fixed(now: String)
        /// Not installed any more.
        case removed
        /// Still found: the finding as it is now.
        case stillAffected(Finding)
        /// Still found, but only as likely affected or reported by the site: not checked against published ranges, so
        /// neither fixed nor still affected. The finding as it is now.
        case notChecked(Finding)
        case couldNotCheck(String)
    }

    /// Checks one finding again, after a fix ran: reads its sources again, asks the API about exactly that package at
    /// the version now installed (a fresh answer, not the cache's), and rebuilds its findings. Returns the report with
    /// them in place of the old finding, and what became of it.
    public func recheck(_ finding: Finding, in report: ScanReport) async -> (report: ScanReport, outcome: Recheck) {
        _ = await api.takeSentRequests()
        let own = Set(finding.origins.map(\.kind))
        var kinds = own
        if kinds.contains(.electron) { kinds.insert(.homebrew) }          // the apps' cask tokens come from Homebrew
        if kinds.contains(.java) { kinds.insert(.homebrew) }              // and which cask installed a JDK
        let fresh = await takeInventory(kinds)
        var updated = report
        updated.inventory = report.inventory.replacing(kinds, with: fresh)
        let sourceError = fresh.reports.first { own.contains($0.kind) && $0.error != nil }.map { "\($0.kind.title): \($0.error!)" }

        let index: PublicIndex
        do { index = try await indexStore.load(maxAge: Freshness.index).index }
        catch { return (report, .couldNotCheck("could not read the public index (\(error.localizedDescription))")) }
        let builder = FindingBuilder(index: index)
        let bigIssues = cache.readJSON(StateResponse.self, "state", "state", maxAge: Freshness.state)?.bigIssues ?? []

        let rebuilt: [Finding]
        let now: String
        switch finding.subject {
        case _ where finding.origins.first?.kind == .java:
            // A Java runtime, read again where it was: an update in place (a cask's installer) keeps its folder.
            switch await javaFindings(finding, in: updated, index: index) {
            case let .answer(outcome?): return (report, outcome)
            case .answer(nil): return sourceError.map { (report, .couldNotCheck($0)) } ?? (Self.replacing(finding, with: [], in: updated), .removed)
            case let .findings(f, current): rebuilt = f; now = current
            }
        case let .project(slug, _, installedAs):
            guard let item = updated.inventory.homebrew.first(where: { $0.name == installedAs && finding.origins.contains($0.origin) }) else {
                return sourceError.map { (report, .couldNotCheck($0)) } ?? (Self.replacing(finding, with: [], in: updated), .removed)
            }
            guard let project = index.project(slug: slug), let approved = PrivacyFilter(index: index).approve(projects: [slug]).first else {
                return (report, .couldNotCheck("\(slug) is not in the public index"))
            }
            var response = cache.readJSON(ProjectResponse.self, "project", slug, maxAge: Freshness.project)
            if response == nil {
                do { response = try await api.project(approved); cache.writeJSON(response!, "project", slug) }
                catch { return (report, .couldNotCheck(error.localizedDescription)) }
            }
            rebuilt = builder.findings(approved: [:], verdicts: [:], brew: [.init(item: item, project: project)], projects: [slug: response!],
                                       bigIssues: bigIssues)
            now = FindingBuilder.versions(item, slug: slug).shown
        case .product, .addOn:
            // An app, a library it bundles, or a malicious extension: no Fix button runs for these (FixPlan), so a fix
            // is never followed by this. The next scan reads them again.
            return (report, .couldNotCheck("apps and extensions are checked again by the next scan"))
        case let .package(ecosystem, name):
            // A program's or tool's finding stands for all it was built with: every one of its packages is asked again.
            let wholeProgram = finding.origins.allSatisfy(FindingBuilder.belongsToProgram)
            let installs = updated.inventory.packages.filter { p in
                (wholeProgram || (p.ecosystem == ecosystem && PackageNames.indexName(p.name, in: ecosystem) == name))
                    && finding.origins.contains { $0.samePlace(as: p.origin) }
            }
            guard !installs.isEmpty else {
                return sourceError.map { (report, .couldNotCheck($0)) } ?? (Self.replacing(finding, with: [], in: updated), .removed)
            }
            let selection = PrivacyFilter(index: index).approve(installs)
            guard !selection.approved.isEmpty else { return (report, .couldNotCheck("the version installed now cannot be checked")) }
            var verdicts: [ApprovedPackage: BatchResponse.Result] = [:]
            for chunk in Self.batches(selection.approved.keys.sorted { $0.cacheKey < $1.cacheKey }) {
                do {
                    let results = try await api.checkBatch(chunk)
                    let byKey = Dictionary(results.map { ("\($0.ecosystem)\u{1F}\($0.name)\u{1F}\($0.version)", $0) }, uniquingKeysWith: { a, _ in a })
                    for p in chunk {
                        if let r = byKey[p.versionKey] { verdicts[p] = r }
                        cache.writeJSON(CachedVerdict(result: byKey[p.versionKey]), Self.batchCache, p.cacheKey)
                    }
                } catch {
                    return (report, .couldNotCheck(error.localizedDescription))
                }
            }
            rebuilt = builder.findings(approved: selection.approved, verdicts: verdicts, brew: [], projects: [:], bigIssues: bigIssues)
                .filter { f in f.origins.contains { o in finding.origins.contains { $0.samePlace(as: o) } } }
            let named = installs.filter { $0.ecosystem == ecosystem && PackageNames.indexName($0.name, in: ecosystem) == name }
            let versions = Array(Set((named.isEmpty ? installs : named).map(\.version)))
            let newest = Core.shared.newestVersion(versions) ?? versions[0]
            now = (finding.component.map { "\($0) " } ?? "") + (wholeProgram ? FindingBuilder.Component.shown(newest) : newest)
        }
        let explained = await ProvenanceExplainer(tools: configuration.tools).explain(rebuilt, inventory: updated.inventory)
        updated = Self.replacing(finding, with: explained, in: updated)
        updated.sent.requests += await api.takeSentRequests()
        return (updated, explained.first.map { $0.group.isNotChecked ? .notChecked($0) : .stillAffected($0) } ?? .fixed(now: now))
    }

    /// What a Java runtime's re-check found: its findings now, or the answer to give instead (nil: it is gone).
    enum JavaRebuilt { case findings([Finding], now: String), answer(Recheck?) }

    /// A Java runtime's findings, read again (JavaSource) and decided as a scan decides them, its record fresh unless
    /// the cache's is.
    private func javaFindings(_ finding: Finding, in updated: ScanReport, index: PublicIndex) async -> JavaRebuilt {
        guard case let .javaRuntime(old)? = finding.origins.first else { return .answer(.couldNotCheck("not a Java runtime")) }
        guard let runtime = updated.inventory.javaRuntimes.first(where: { $0.realPath == old.realPath || $0.path == old.path }) else {
            return .answer(nil)
        }
        let brew = updated.inventory.homebrew.filter { ProjectMatcher.project(for: $0, in: index) != nil }.map(\.name)
        let check = JavaCheck.match([runtime], index: index, checkedBrew: Set(brew))
        guard let m = check.matches.first else { return .answer(.couldNotCheck("nothing in the public index checks \(runtime.title) now")) }
        let filter = PrivacyFilter(index: index)
        var projects: [String: ProjectResponse] = [:], products: [String: ProductResponse] = [:]
        switch m.route {
        case let .project(slug, _):
            guard let approved = filter.approve(projects: [slug]).first else { return .answer(.couldNotCheck("\(slug) is not in the public index")) }
            if let cached = cache.readJSON(ProjectResponse.self, "project", slug, maxAge: Freshness.project) {
                projects[slug] = cached
            } else {
                do { projects[slug] = try await api.project(approved); cache.writeJSON(projects[slug]!, "project", slug) }
                catch { return .answer(.couldNotCheck(error.localizedDescription)) }
            }
        case let .product(c):
            let fetched = await BundleCheck.records(filter.approve(products: [c.product]), api: api, cache: cache, maxAge: Freshness.project) { _ in }
            if let problem = fetched.problems.first { return .answer(.couldNotCheck(problem)) }
            products = fetched.records
        }
        return .findings(check.findings(products: products, projects: projects), now: runtime.shownVersion)
    }

    /// The report with `old` replaced by `new` (and no finding listed twice), still in the list's order.
    static func replacing(_ old: Finding, with new: [Finding], in report: ScanReport) -> ScanReport {
        var r = report
        let ids = Set(new.map(\.id)).union([old.id])
        r.findings = FindingOrder.sorted(r.findings.filter { !ids.contains($0.id) } + new)
        return r
    }

    /// Batches of at most 200 in which each package and version appears once (the same version installed in two
    /// Pythons is two questions, asked in different batches).
    static func batches(_ packages: [ApprovedPackage]) -> [[ApprovedPackage]] {
        var out: [[ApprovedPackage]] = [], keys: [Set<String>] = []
        for p in packages {
            if let i = out.indices.first(where: { out[$0].count < APIClient.batchLimit && !keys[$0].contains(p.versionKey) }) {
                out[i].append(p); keys[i].insert(p.versionKey)
            } else {
                out.append([p]); keys.append([p.versionKey])
            }
        }
        return out
    }

    /// Not in the index (nothing ever reported: no known problem, not proof of safety) versus not checked at all.
    static func coverage(withheld: [InstalledPackage], unmatchedBrew: [HomebrewItem], apps: Coverage.Bucket?,
                         unmatchedManaged: [ManagedPackage] = [], unchecked: [UncheckedItem] = []) -> Coverage {
        func describe(_ p: InstalledPackage) -> String { "\(p.name) \(p.version)" }
        func checkable(_ p: InstalledPackage) -> Bool { Ecosystem.checkable.contains(p.ecosystem) && PackageNames.isPlausibleVersion(p.version) }
        let bySource = Dictionary(grouping: withheld.filter(checkable)) { $0.origin.kind }
        let notInIndex = SourceKind.allCases.compactMap { kind -> Coverage.Bucket? in
            guard let items = bySource[kind], !items.isEmpty else { return nil }
            return Coverage.Bucket(source: kind.title, items: Array(Set(items.map(describe))).sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending })
        }
        var notChecked: [Coverage.Bucket] = []
        if !unmatchedBrew.isEmpty {
            notChecked.append(.init(source: "Homebrew packages with no graded project",
                                    items: unmatchedBrew.map { "\($0.name) \($0.version)" }.sorted()))
        }
        if let apps, !apps.items.isEmpty { notChecked.append(apps) }
        let uncheckable = withheld.filter { !checkable($0) }
        if !uncheckable.isEmpty {
            notChecked.append(.init(source: "Packages the site cannot check", items: Array(Set(uncheckable.map(describe))).sorted()))
        }
        notChecked += Self.programCoverage(unmatchedManaged: unmatchedManaged, unchecked: unchecked)
        return Coverage(notInIndex: notInIndex, notChecked: notChecked)
    }

    /// Everything that stayed on this Mac, by where it was found, each name and version once per source: Homebrew
    /// packages with no graded project, MacPorts, Nix and conda packages no R line names, then packages the privacy
    /// filter did not pass (not in the index, or with a version no registry would have).
    static func withheld(_ packages: [InstalledPackage], unmatchedBrew: [HomebrewItem], unmatchedManaged: [ManagedPackage] = []) -> [Coverage.Bucket] {
        let bySource = Dictionary(grouping: packages) { $0.origin.kind }
        let managedBySource = Dictionary(grouping: unmatchedManaged) { $0.origin.kind }
        return SourceKind.allCases.compactMap { kind in
            var items = Set((bySource[kind] ?? []).map { "\($0.name) \($0.version)" })
            if kind == .homebrew { items.formUnion(unmatchedBrew.map { "\($0.name) \($0.version)" }) }
            items.formUnion((managedBySource[kind] ?? []).map { "\($0.name) \($0.version)" })
            guard !items.isEmpty else { return nil }
            return Coverage.Bucket(source: kind.title, items: items.sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending })
        }
    }

    /// Inventory of the given sources, run side by side. Each report says how long its source took.
    func takeInventory(_ kinds: Set<SourceKind>) async -> Inventory {
        var inventory = Inventory()
        let tools = configuration.tools
        typealias Collected = (packages: [InstalledPackage], report: SourceReport)
        @Sendable func timed(_ body: () async -> Collected) async -> Collected {
            let t = await Stopwatch.time(body)
            var r = t.value
            r.report.seconds = r.report.seconds ?? t.seconds
            return r
        }
        // Homebrew first: its casks say which apps it installed, for the apps' upgrade commands, and which JDKs.
        var caskForApp: [String: String] = [:], caskFootprints: [CaskFootprint] = []
        if kinds.contains(.homebrew) {
            let t = await Stopwatch.time { await HomebrewSource(environment: tools).collect() }
            var r = t.value
            r.report.seconds = t.seconds
            inventory.homebrew = r.items; caskForApp = r.caskForApp; caskFootprints = r.casks; inventory.reports.append(r.report)
        }
        let footprints = caskFootprints
        let globals = GlobalPackageSources(environment: tools)
        let roots = configuration.applicationRoots, folders = configuration.folders, casks = caskForApp
        async let npm = kinds.contains(.npm) ? await timed { await globals.npm() } : nil
        async let pip = kinds.contains(.pip) ? await timed { await PythonSource(environment: tools).collect() } : nil
        async let gem = kinds.contains(.gem) ? await timed { await globals.gem() } : nil
        async let apps = kinds.contains(.electron) ? await Stopwatch.time { ElectronSource(roots: roots, caskForApp: casks).collect() } : nil
        async let lockfiles = kinds.contains(.folders) ? await timed { FolderSource(roots: folders).collect() } : nil
        async let installedApps = kinds.contains(.apps) ? await Stopwatch.time { AppSource(roots: roots, caskForApp: casks).collect() } : nil
        async let addOns = kinds.contains(.extensions) ? await Stopwatch.time { ExtensionSource(home: tools.home).collect() } : nil
        // Go and Rust programs (one pass finds both), pipx and uv tools, conda, MacPorts and Nix time themselves.
        async let programs = kinds.contains(.go) || kinds.contains(.rust) ? ProgramSource(environment: tools, caskForApp: casks).collect() : nil
        async let pythonTools = kinds.contains(.pipx) || kinds.contains(.uv) ? PythonToolSource(environment: tools).collect() : nil
        async let conda = kinds.contains(.conda) ? CondaSource(environment: tools).collect() : nil
        async let ports = kinds.contains(.macports) ? await MacPortsSource(environment: tools).collect() : nil
        async let nix = kinds.contains(.nix) ? NixSource(environment: tools).collect() : nil
        async let javas = kinds.contains(.java) ? await Stopwatch.time { await JavaSource(environment: tools, casks: footprints).collect() } : nil
        let cargo = kinds.contains(.cargo) ? await timed { globals.cargo() } : nil
        let electron = await apps
        inventory.otherApps = electron?.value.otherApps ?? []
        var appPackages = electron.map { (packages: $0.value.packages, report: $0.value.report) }
        appPackages?.report.seconds = electron?.seconds
        if let a = await installedApps {
            var report = a.value.report
            report.seconds = report.seconds ?? a.seconds
            inventory.apps = a.value.apps; inventory.reports.append(report)
        }
        let extensions = await addOns
        inventory.extensions = extensions?.value.extensions ?? []
        var extensionPackages = extensions.map { (packages: $0.value.packages, report: $0.value.report) }
        extensionPackages?.report.seconds = extensions?.seconds
        for r in [appPackages, extensionPackages, await npm, await pip, cargo, await gem, await lockfiles].compactMap({ $0 }) {
            inventory.packages += r.packages
            inventory.reports.append(r.report)
        }
        if let p = await programs {
            inventory.packages += p.packages; inventory.unchecked += p.unchecked; inventory.reports += p.reports
        }
        if let t = await pythonTools { inventory.packages += t.packages; inventory.reports += t.reports }
        if let c = await conda {
            inventory.packages += c.packages; inventory.managed += c.managed; inventory.unchecked += c.unchecked
            inventory.reports.append(c.report)
        }
        if let m = await ports { inventory.managed += m.managed; inventory.reports.append(m.report) }
        if let n = await nix { inventory.managed += n.managed; inventory.unchecked += n.unchecked; inventory.reports.append(n.report) }
        if let j = await javas {
            var report = j.value.report
            report.seconds = report.seconds ?? j.seconds
            inventory.javaRuntimes = j.value.runtimes; inventory.unchecked += j.value.unchecked; inventory.reports.append(report)
        }
        inventory.reports.sort { $0.kind < $1.kind }
        return inventory
    }

}

/// A cached batch answer: `result` is nil when the version had no advisories.
struct CachedVerdict: Codable { var result: BatchResponse.Result? }

// MARK: - What a fix asks the site

extension Scanner: FixServer {
    /// The plan for one Python package at its installed version, its target within `constraints`: a fresh answer (the
    /// cache keeps the scan's own plans). Only a package the privacy filter passes is asked about, as in a scan.
    public func plan(_ finding: Finding, within constraints: [String]) async -> Result<BatchResponse.Plan?, FixServerError> {
        guard case .package(.pypi, _) = finding.subject, let inputs = finding.commandInputs, case .pip = inputs.origin else {
            return .failure(FixServerError("only a Python package's plan can be asked within constraints"))
        }
        guard !constraints.isEmpty, constraints.count <= PythonConstraints.maxSent, constraints.allSatisfy(PythonConstraints.isSendable) else {
            return .failure(FixServerError("the constraints are not ones the app sends"))
        }
        let index: PublicIndex
        do { index = try await indexStore.load(maxAge: Freshness.index).index }
        catch { return .failure(FixServerError("could not read the public index (\(error.localizedDescription))")) }
        let installed = InstalledPackage(ecosystem: .pypi, name: inputs.name, version: finding.installedVersion, origin: inputs.origin)
        guard let approved = PrivacyFilter(index: index).approve([installed]).approved.keys.first else {
            return .failure(FixServerError("\(inputs.name) is not one the app asks about"))
        }
        do { return .success(try await api.checkWithin(approved, constraints: constraints)?.plan) }
        catch { return .failure(FixServerError(error.localizedDescription)) }
    }

    /// The flaws known at each version, asked as a scan asks (privacy filter, batches of 200), never from the cache. A
    /// package the public index does not list has nothing reported; a version no registry would have cannot be asked.
    public func flaws(_ versions: [PackageVersion], python: PythonEnvironment) async -> Result<[PackageVersion: Set<String>], FixServerError> {
        let index: PublicIndex
        do { index = try await indexStore.load(maxAge: Freshness.index).index }
        catch { return .failure(FixServerError("could not read the public index (\(error.localizedDescription))")) }
        let origin = Origin.pip(python: python, user: false, formula: nil)
        if let odd = versions.first(where: { !PackageNames.isPlausibleVersion($0.version) }) {
            return .failure(FixServerError("\(odd.name) \(odd.version) cannot be checked"))
        }
        let selection = PrivacyFilter(index: index).approve(versions.map { InstalledPackage(ecosystem: .pypi, name: $0.name, version: $0.version, origin: origin) })
        var out = Dictionary(uniqueKeysWithValues: Set(versions).map { ($0, Set<String>()) })
        for chunk in Self.batches(selection.approved.keys.sorted { $0.cacheKey < $1.cacheKey }) {
            do {
                let results = try await api.checkBatch(chunk)
                let byKey = Dictionary(results.map { ("\($0.ecosystem)\u{1F}\($0.name)\u{1F}\($0.version)", $0) }, uniquingKeysWith: { a, _ in a })
                for p in chunk {
                    let ids = Set((byKey[p.versionKey]?.flaws ?? []).flatMap { [$0.id] + $0.aliases })
                    for installed in selection.approved[p] ?? [] { out[PackageVersion(name: installed.name, version: installed.version)] = ids }
                }
            } catch {
                return .failure(FixServerError(error.localizedDescription))
            }
        }
        return .success(out)
    }

    /// What the fix questions named since the last call: for "What leaves your Mac".
    public func takeSentRequests() async -> [SentRequest] { await api.takeSentRequests() }
}

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
        let approvedProjects = filter.approve(projects: brew.map(\.project.slug))
        let allowed = Set(approvedProjects.map(\.slug))
        let brewChecked = brew.filter { allowed.contains($0.project.slug) }
        var fromCache: [String] = []                         // what the cache answered, as it was sent

        // 4. Exact versions, 200 at a time.
        let packages = selection.approved.keys.sorted { $0.cacheKey < $1.cacheKey }
        var verdicts: [ApprovedPackage: BatchResponse.Result] = [:]
        var toAsk: [ApprovedPackage] = []
        for p in packages {
            if let cached = cache.readJSON(CachedVerdict.self, "batch", p.cacheKey, maxAge: Freshness.batchVerdict) {
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
                    cache.writeJSON(CachedVerdict(result: r), "batch", p.cacheKey)
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
        let findings = FindingBuilder(index: index).findings(approved: selection.approved, verdicts: verdicts,
                                                             brew: brewChecked, projects: projects, bigIssues: bigIssues)
        let checkedBrew = Set(brewChecked.map(\.item))
        let coverage = Self.coverage(withheld: selection.withheld, unmatchedBrew: inventory.homebrew.filter { !checkedBrew.contains($0) },
                                     otherApps: inventory.otherApps)
        let withheld = Self.withheld(selection.withheld, unmatchedBrew: inventory.homebrew.filter { !checkedBrew.contains($0) })
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
            now = item.version
        case let .package(ecosystem, name):
            let installs = updated.inventory.packages.filter { p in
                p.ecosystem == ecosystem && PackageNames.indexName(p.name, in: ecosystem) == name
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
                        cache.writeJSON(CachedVerdict(result: byKey[p.versionKey]), "batch", p.cacheKey)
                    }
                } catch {
                    return (report, .couldNotCheck(error.localizedDescription))
                }
            }
            rebuilt = builder.findings(approved: selection.approved, verdicts: verdicts, brew: [], projects: [:], bigIssues: bigIssues)
                .filter { f in f.origins.contains { o in finding.origins.contains { $0.samePlace(as: o) } } }
            let versions = Array(Set(installs.map(\.version)))
            now = (finding.component.map { "\($0) " } ?? "") + (Core.shared.newestVersion(versions) ?? versions[0])
        }
        updated = Self.replacing(finding, with: rebuilt, in: updated)
        updated.sent.requests += await api.takeSentRequests()
        return (updated, rebuilt.first.map(Recheck.stillAffected) ?? .fixed(now: now))
    }

    /// The report with `old` replaced by `new` (and no finding listed twice), still in the list's order.
    static func replacing(_ old: Finding, with new: [Finding], in report: ScanReport) -> ScanReport {
        var r = report
        let ids = Set(new.map(\.id)).union([old.id])
        r.findings = (r.findings.filter { !ids.contains($0.id) } + new).sorted(by: FindingBuilder.precedes)
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
    static func coverage(withheld: [InstalledPackage], unmatchedBrew: [HomebrewItem], otherApps: [String]) -> Coverage {
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
        if !otherApps.isEmpty { notChecked.append(.init(source: "Apps that do not bundle Electron", items: otherApps)) }
        let uncheckable = withheld.filter { !checkable($0) }
        if !uncheckable.isEmpty {
            notChecked.append(.init(source: "Packages the site cannot check", items: Array(Set(uncheckable.map(describe))).sorted()))
        }
        return Coverage(notInIndex: notInIndex, notChecked: notChecked)
    }

    /// Everything that stayed on this Mac, by where it was found, each name and version once per source: Homebrew
    /// packages with no graded project, then packages the privacy filter did not pass (not in the index, or with a
    /// version no registry would have).
    static func withheld(_ packages: [InstalledPackage], unmatchedBrew: [HomebrewItem]) -> [Coverage.Bucket] {
        let bySource = Dictionary(grouping: packages) { $0.origin.kind }
        return SourceKind.allCases.compactMap { kind in
            var items = Set((bySource[kind] ?? []).map { "\($0.name) \($0.version)" })
            if kind == .homebrew { items.formUnion(unmatchedBrew.map { "\($0.name) \($0.version)" }) }
            guard !items.isEmpty else { return nil }
            return Coverage.Bucket(source: kind.title, items: items.sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending })
        }
    }

    /// Inventory of the given sources, run side by side.
    func takeInventory(_ kinds: Set<SourceKind>) async -> Inventory {
        var inventory = Inventory()
        let tools = configuration.tools
        // Homebrew first: its casks say which apps it installed, for the apps' upgrade commands.
        var caskForApp: [String: String] = [:]
        if kinds.contains(.homebrew) {
            let r = await HomebrewSource(environment: tools).collect()
            inventory.homebrew = r.items; caskForApp = r.caskForApp; inventory.reports.append(r.report)
        }
        let globals = GlobalPackageSources(environment: tools)
        let roots = configuration.applicationRoots, folders = configuration.folders, casks = caskForApp
        async let npm = kinds.contains(.npm) ? await globals.npm() : nil
        async let pip = kinds.contains(.pip) ? await PythonSource(environment: tools).collect() : nil
        async let gem = kinds.contains(.gem) ? await globals.gem() : nil
        async let apps = kinds.contains(.electron) ? ElectronSource(roots: roots, caskForApp: casks).collect() : nil
        async let lockfiles = kinds.contains(.folders) ? FolderSource(roots: folders).collect() : nil
        let cargo = kinds.contains(.cargo) ? globals.cargo() : nil
        let electron = await apps
        inventory.otherApps = electron?.otherApps ?? []
        let appPackages = electron.map { (packages: $0.packages, report: $0.report) }
        for r in [appPackages, await npm, await pip, cargo, await gem, await lockfiles].compactMap({ $0 }) {
            inventory.packages += r.packages
            inventory.reports.append(r.report)
        }
        inventory.reports.sort { $0.kind < $1.kind }
        return inventory
    }

}

/// A cached batch answer: `result` is nil when the version had no advisories.
struct CachedVerdict: Codable { var result: BatchResponse.Result? }

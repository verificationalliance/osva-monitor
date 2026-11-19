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
        // MacPorts, Nix and conda packages that the index's R lines name as a graded project's software.
        let managed = inventory.managed.compactMap { p in
            index.project(manager: p.manager.rawValue, package: p.name).map { FindingBuilder.ManagedMatch(package: p, project: $0) }
        }
        let approvedProjects = filter.approve(projects: brew.map(\.project.slug) + managed.map(\.project.slug))
        let allowed = Set(approvedProjects.map(\.slug))
        let brewChecked = brew.filter { allowed.contains($0.project.slug) }
        let managedChecked = managed.filter { allowed.contains($0.project.slug) }
        var fromCache = 0

        // 4. Exact versions, 200 at a time.
        let packages = selection.approved.keys.sorted { $0.cacheKey < $1.cacheKey }
        var verdicts: [ApprovedPackage: BatchResponse.Result] = [:]
        var toAsk: [ApprovedPackage] = []
        for p in packages {
            if let cached = cache.readJSON(CachedVerdict.self, "batch", p.cacheKey, maxAge: Freshness.batchVerdict) {
                if let r = cached.result { verdicts[p] = r }
                fromCache += 1
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
                projects[p.slug] = cached; fromCache += 1; continue
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
                                                             brew: brewChecked, projects: projects, bigIssues: bigIssues, managed: managedChecked)
        // A formula whose programs were read for what they were built with has been checked, graded project or not.
        let checkedBrew = Set(brewChecked.map(\.item))
        let formulaeWithPrograms = Set(inventory.packages.compactMap { p -> String? in
            if case let .program(program) = p.origin { return program.formula }
            return nil
        })
        let unmatchedBrew = inventory.homebrew.filter { !checkedBrew.contains($0) && !($0.kind == .formula && formulaeWithPrograms.contains($0.name)) }
        let checkedManaged = Set(managedChecked.map(\.package))
        let listedUnderHomebrew = Set(unmatchedBrew.map(\.name))
        let coverage = Self.coverage(withheld: selection.withheld, unmatchedBrew: unmatchedBrew, otherApps: inventory.otherApps,
                                     unmatchedManaged: inventory.managed.filter { !checkedManaged.contains($0) },
                                     unchecked: inventory.unchecked.filter { $0.formula.map { !listedUnderHomebrew.contains($0) } ?? true })
        let sent = SentRecord(requests: await api.takeSentRequests(),
                              withheldCount: selection.withheld.count + (inventory.homebrew.count - brewChecked.count)
                                  + (inventory.managed.count - managedChecked.count),
                              answeredFromCache: fromCache)
        progress("")
        return ScanReport(startedAt: started, finishedAt: Date(), inventory: inventory, findings: findings, sent: sent,
                          indexGeneratedAt: index.generatedAt, problems: problems, coverage: coverage)
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
    static func coverage(withheld: [InstalledPackage], unmatchedBrew: [HomebrewItem], otherApps: [String],
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
        if !otherApps.isEmpty { notChecked.append(.init(source: "Apps that do not bundle Electron", items: otherApps)) }
        let uncheckable = withheld.filter { !checkable($0) }
        if !uncheckable.isEmpty {
            notChecked.append(.init(source: "Packages the site cannot check", items: Array(Set(uncheckable.map(describe))).sorted()))
        }
        notChecked += Self.programCoverage(unmatchedManaged: unmatchedManaged, unchecked: unchecked)
        return Coverage(notInIndex: notInIndex, notChecked: notChecked)
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
        // Homebrew first: its casks say which apps it installed, for the apps' upgrade commands.
        var caskForApp: [String: String] = [:]
        if kinds.contains(.homebrew) {
            let t = await Stopwatch.time { await HomebrewSource(environment: tools).collect() }
            var r = t.value
            r.report.seconds = t.seconds
            inventory.homebrew = r.items; caskForApp = r.caskForApp; inventory.reports.append(r.report)
        }
        let globals = GlobalPackageSources(environment: tools)
        let roots = configuration.applicationRoots, folders = configuration.folders, casks = caskForApp
        async let npm = kinds.contains(.npm) ? await timed { await globals.npm() } : nil
        async let pip = kinds.contains(.pip) ? await timed { await PythonSource(environment: tools).collect() } : nil
        async let gem = kinds.contains(.gem) ? await timed { await globals.gem() } : nil
        async let apps = kinds.contains(.electron) ? await Stopwatch.time { ElectronSource(roots: roots, caskForApp: casks).collect() } : nil
        async let lockfiles = kinds.contains(.folders) ? await timed { FolderSource(roots: folders).collect() } : nil
        // Go and Rust programs (one pass finds both), pipx and uv tools, conda, MacPorts and Nix time themselves.
        async let programs = kinds.contains(.go) || kinds.contains(.rust) ? ProgramSource(environment: tools, caskForApp: casks).collect() : nil
        async let pythonTools = kinds.contains(.pipx) || kinds.contains(.uv) ? PythonToolSource(environment: tools).collect() : nil
        async let conda = kinds.contains(.conda) ? CondaSource(environment: tools).collect() : nil
        async let ports = kinds.contains(.macports) ? await MacPortsSource(environment: tools).collect() : nil
        async let nix = kinds.contains(.nix) ? NixSource(environment: tools).collect() : nil
        let cargo = kinds.contains(.cargo) ? await timed { globals.cargo() } : nil
        let electron = await apps
        inventory.otherApps = electron?.value.otherApps ?? []
        var appPackages = electron.map { (packages: $0.value.packages, report: $0.value.report) }
        appPackages?.report.seconds = electron?.seconds
        for r in [appPackages, await npm, await pip, cargo, await gem, await lockfiles].compactMap({ $0 }) {
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
        inventory.reports.sort { $0.kind < $1.kind }
        return inventory
    }

}

/// A cached batch answer: `result` is nil when the version had no advisories.
struct CachedVerdict: Codable { var result: BatchResponse.Result? }

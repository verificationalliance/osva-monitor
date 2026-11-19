import AppKit
import Foundation
import Observation
import OSVAKit

/// The running app's state: the last report, the person's settings, the schedule, the folder watcher, notifications.
@MainActor @Observable
public final class AppModel {
    public private(set) var report: ScanReport?
    public private(set) var isScanning = false
    public private(set) var progress = ""
    public private(set) var launchAtLogin = LoginItem.isEnabled
    public private(set) var settings: MonitorSettings

    public let notifier: any Notifier
    private let storage: Storage
    private let tools: ToolEnvironment
    private let transport: any HTTPTransport
    private let limiter = RateLimiter()                  // shared by every scan, so the budget holds across them
    @ObservationIgnored private var timer: Timer?
    @ObservationIgnored private var watcher: FolderWatcher?
    @ObservationIgnored private var pendingRefresh: Set<SourceKind>?
    @ObservationIgnored private var folderDebounce: Task<Void, Never>?

    /// `tools` and `transport` are this Mac's and the network's; tests pass recorded ones.
    public init(storage: Storage = Storage(directory: Paths.supportDirectory()), notifier: any Notifier = SystemNotifier(),
                tools: ToolEnvironment = ToolEnvironment(), transport: any HTTPTransport = URLSessionTransport()) {
        self.storage = storage
        self.notifier = notifier
        self.tools = tools
        self.transport = transport
        advisor = FixAdvisor(tools: tools)
        settings = storage.loadSettings()
        report = storage.loadLastReport()
    }

    /// The long list the panel last opened in its window ("Apps with no security record").
    public var shownList: NameList?

    public var popoverContent: PopoverContent {
        PopoverContent(report: report, isScanning: isScanning, progress: progress, resolved: resolved)
    }

    /// Findings opened when the popover first appears (the capture mode opens one to show the open state).
    public var initiallyExpanded: Set<String> = []

    /// Shows a report without scanning, saving or notifying: the capture mode's fixtures. Nothing is written to disk
    /// and nothing is sent anywhere while it is set.
    public private(set) var isShowingFixtures = false

    /// Fix states to show with the fixtures (the capture mode's --fix-states): nothing runs while fixtures are shown.
    public func showFixtureFixes(_ fixes: [String: FixRowState], resolved: [Finding] = []) {
        guard isShowingFixtures else { return }
        self.fixes = fixes
        self.resolved = resolved
    }

    public func showFixtures(_ report: ScanReport?, settings fixtureSettings: MonitorSettings) {
        isShowingFixtures = true
        timer?.invalidate(); timer = nil
        watcher?.stop(); watcher = nil
        self.report = report
        settings = fixtureSettings
    }

    /// Starts the schedule and the folder watcher, and scans if the last scan is older than the interval.
    public func start() {
        schedule()
        watchFolders()
        prepareFixFolders()
        Task { await notifier.requestPermission() }
        let due = report.map { Date().timeIntervalSince($0.finishedAt) > interval } ?? true
        // A newer app scans at once, so the findings carry what it adds (0.2.0's Fix button needs a new scan).
        let scannedByOlder = report != nil && UserDefaults.standard.string(forKey: Self.scannedByKey) != Self.appVersion
        if due || scannedByOlder { scanNow() }
    }

    /// The app version that made the saved report.
    static let scannedByKey = "lastFullScanAppVersion"
    static var appVersion: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "" }

    private var interval: TimeInterval { TimeInterval(max(1, settings.scanIntervalHours) * 3600) }

    // MARK: Scanning

    /// Scans now. `refresh` names the sources to look at again (all when nil). A request made during a scan runs
    /// right after it.
    public func scanNow(refresh: Set<SourceKind>? = nil) {
        guard !isShowingFixtures else { return }
        guard !isScanning, !isRechecking else {
            pendingRefresh = pendingRefresh.map { p in refresh.map { p.union($0) } ?? Set(SourceKind.allCases) } ?? (refresh ?? Set(SourceKind.allCases))
            return
        }
        isScanning = true
        progress = ""
        let previous = report
        let scanner = makeScanner()
        let report: @Sendable (String) -> Void = { [weak self] message in
            Task { @MainActor in self?.progress = message }
        }
        Task { [weak self] in
            let result = await scanner.scan(previous: previous, refresh: refresh, progress: report)
            self?.finish(result, previous: previous, full: refresh == nil)
        }
    }

    private func makeScanner() -> OSVAKit.Scanner {
        Scanner(configuration: ScanConfiguration(storage: storage, tools: tools,
                                                 folders: settings.watchedFolders.map { URL(fileURLWithPath: $0, isDirectory: true) }),
                transport: transport, limiter: limiter)
    }

    private func finish(_ result: ScanReport, previous: ScanReport?, full: Bool) {
        report = result
        isScanning = false
        progress = ""
        storage.save(result)
        if full { UserDefaults.standard.set(Self.appVersion, forKey: Self.scannedByKey) }
        scanReplacedFindings(full: full)
        if settings.notificationsEnabled {
            let before = Set(previous?.findings.filter(\.deservesNotification).map(\.notificationKey) ?? [])
            let fresh = result.findings.filter { $0.deservesNotification && !before.contains($0.notificationKey) }
            if !fresh.isEmpty { Task { await notifier.post(fresh) } }
        }
        recheckNext()
        runPendingScan()
    }

    private func runPendingScan() {
        if !isRechecking, let next = pendingRefresh {
            pendingRefresh = nil
            scanNow(refresh: next.count == SourceKind.allCases.count ? nil : next)
        }
    }

    private func schedule() {
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.scanNow() }
        }
        timer?.tolerance = 300
    }

    // MARK: Fixes
    //
    // A finding with a runnable command gets a Fix button (FixAdvisor decides; for a `brew upgrade`, after asking
    // Homebrew). Fix… opens a confirmation with the tool's dry run; Run in Terminal writes a one-use script (FixScript)
    // into the app's private fixes/ folder and has Terminal open it. When the command ends, the script leaves a result
    // file in fix-results/, which the app watches; the app then checks that one finding again (Scanner.recheck) and
    // the row says what became of it. No URL scheme, no Apple Events: a web page or another app cannot start a fix.

    /// Each finding's fix, by finding id: its button, its confirmation, how its last run went.
    public private(set) var fixes: [String: FixRowState] = [:]
    /// Findings fixed since the last full scan: gone from the report, still shown in their rows until then.
    public private(set) var resolved: [Finding] = []
    public private(set) var isRechecking = false

    /// Opens a script in Terminal (tests replace it).
    @ObservationIgnored public var terminal: any TerminalOpener = SystemTerminal()
    @ObservationIgnored private let advisor: FixAdvisor
    /// Runs started in this session and not yet ended, by the id in their script's result file.
    @ObservationIgnored private var runs: [UUID: FixRun] = [:]
    /// Runs that ended and wait to be checked again (one at a time, never during a scan).
    @ObservationIgnored private var ended: [(run: FixRun, status: Int32)] = []
    @ObservationIgnored private var resultWatcher: FixResultWatcher?

    private struct FixRun {
        var finding: Finding
        var plan: FixPlan
        var script: URL
    }

    private var fixDirectories: FixDirectories { FixDirectories(support: storage.directory) }

    /// The folders, private; what an earlier session left there removed (its results match no run of this one).
    private func prepareFixFolders() {
        let dirs = fixDirectories
        guard (try? dirs.prepare()) != nil else { return }
        FixScript.sweep(dirs, olderThan: 86_400)
        for name in (try? FileManager.default.contentsOfDirectory(atPath: dirs.results.path)) ?? [] {
            try? FileManager.default.removeItem(at: dirs.results.appendingPathComponent(name))
        }
        startResultWatcher()
    }

    private func startResultWatcher() {
        if resultWatcher == nil {
            resultWatcher = FixResultWatcher(directory: fixDirectories.results) { [weak self] in
                Task { @MainActor in self?.collectFixResults() }
            }
        }
        resultWatcher?.start()
    }

    /// A row opened: decide whether it gets a Fix button. Instant, except a `brew upgrade`, which asks Homebrew first.
    public func assessFix(_ finding: Finding) {
        guard !isShowingFixtures else { return }
        let state = fixes[finding.id] ?? FixRowState()
        guard state.availability == nil, !state.isBusy, !state.isResolved else { return }
        switch FixPlan.make(for: finding, tools: advisor.tools, home: advisor.home) {
        case let .failure(refusal):
            fixes[finding.id, default: FixRowState()].availability = .withheld(refusal.explanation)
        case let .success(plan) where plan.homebrew == nil || plan.action == .removal:
            fixes[finding.id, default: FixRowState()].availability = .offered(FixOffer(plan: plan))
        case .success:
            fixes[finding.id, default: FixRowState()].availability = .checking
            let advisor = self.advisor
            Task { [weak self] in
                let assessment = await advisor.assess(finding)
                guard let self, self.fixes[finding.id]?.availability == .checking else { return }
                self.fixes[finding.id]?.availability = Self.availability(assessment)
            }
        }
    }

    static func availability(_ a: FixAssessment) -> FixRowState.Availability {
        switch a {
        case let .offer(offer): return .offered(offer)
        case let .withheld(why): return .withheld(why)
        case .none: return .withheld(nil)
        }
    }

    /// Fix… pressed: the confirmation opens, and the tool is asked for a dry run.
    public func beginFix(_ finding: Finding) {
        guard case let .offered(offer)? = fixes[finding.id]?.availability, fixes[finding.id]?.isBusy == false else { return }
        fixes[finding.id]?.preview = .loading
        let advisor = self.advisor
        Task { [weak self] in
            let preview = await advisor.preview(offer.plan)
            guard let self, self.fixes[finding.id]?.preview == .loading else { return }
            self.fixes[finding.id]?.preview = .ready(preview)
        }
    }

    public func cancelFix(_ finding: Finding) {
        fixes[finding.id]?.preview = nil
    }

    /// Run in Terminal pressed: the plan is made again from the finding as the report has it now, and runs only if it
    /// is the one the confirmation showed.
    public func runFix(_ finding: Finding) {
        guard !isShowingFixtures, let state = fixes[finding.id], case let .offered(offer)? = state.availability, state.preview != nil,
              !state.isBusy else { return }
        guard let current = report?.findings.first(where: { $0.id == finding.id }),
              case let .success(plan) = FixPlan.make(for: current, tools: advisor.tools, home: advisor.home), plan == offer.plan else {
            fixes[finding.id] = nil
            if let current = report?.findings.first(where: { $0.id == finding.id }) { assessFix(current) }
            return
        }
        let run = UUID()
        let script: URL
        do {
            try fixDirectories.prepare()
            startResultWatcher()
            script = try FixScript.write(plan, run: run, directories: fixDirectories)
        } catch {
            fixes[finding.id]?.preview = nil
            fixes[finding.id]?.progress = .finished(.couldNotOpen(String(describing: error)))
            return
        }
        runs[run] = FixRun(finding: current, plan: plan, script: script)
        fixes[finding.id]?.preview = nil
        fixes[finding.id]?.progress = .running
        terminal.open(script) { [weak self] error in
            guard let error else { return }
            Task { @MainActor in
                guard let self, self.runs.removeValue(forKey: run) != nil else { return }
                try? FileManager.default.removeItem(at: script)
                self.fixes[finding.id]?.progress = .finished(.couldNotOpen(error))
            }
        }
    }

    /// Something changed in fix-results/: take the results of this session's runs (FixResults says why nothing
    /// else there can do more than this) and check each finding again.
    private func collectFixResults() {
        guard !runs.isEmpty else { return }
        for result in FixResults.collect(in: fixDirectories.results, pending: runs.mapValues(\.finding.id)) {
            guard let run = runs.removeValue(forKey: result.run) else { continue }
            try? FileManager.default.removeItem(at: run.script)              // it removes itself; in case it could not
            fixes[run.finding.id, default: FixRowState()].progress = .rechecking
            ended.append((run, result.status))
        }
        recheckNext()
    }

    private func recheckNext() {
        guard !isScanning, !isRechecking, !ended.isEmpty, let report else { return }
        let (run, status) = ended.removeFirst()
        isRechecking = true
        let scanner = makeScanner()
        let advisor = self.advisor
        Task { [weak self] in
            let (updated, recheck) = await scanner.recheck(run.finding, in: report)
            var homebrew: HomebrewAvailability?
            if case .stillAffected = recheck, status == 0 { homebrew = await advisor.homebrew(run.plan) }
            let outcome = FixOutcome.make(status: status, before: run.finding, recheck: recheck, homebrew: homebrew)
            self?.finishRecheck(run, report: updated, recheck: recheck, outcome: outcome)
        }
    }

    private func finishRecheck(_ run: FixRun, report updated: ScanReport, recheck: OSVAKit.Scanner.Recheck, outcome: FixOutcome) {
        isRechecking = false
        report = updated
        storage.save(updated)
        let id = run.finding.id
        if outcome.isResolved {
            resolved.removeAll { $0.id == id }
            resolved.append(run.finding)
            fixes[id] = FixRowState(progress: .finished(outcome))
        } else {
            // Still found, perhaps at a new version (a new id): its row says so, and gets a Fix button again if one applies.
            let now: Finding? = if case let .stillAffected(f) = recheck { f } else { updated.findings.first { $0.id == id } }
            fixes[id] = nil
            if let now {
                fixes[now.id] = FixRowState(progress: .finished(outcome))
                assessFix(now)
            }
        }
        recheckNext()
        runPendingScan()
    }

    /// A scan replaced the findings. A full scan starts the fixes afresh (runs under way go on); after a partial one,
    /// a fixed row whose finding is back is no longer fixed. Rows that had been assessed are assessed again.
    private func scanReplacedFindings(full: Bool) {
        let findings = report?.findings ?? []
        let ids = Set(findings.map(\.id))
        if full {
            resolved = []
            fixes = fixes.filter { $0.value.isBusy }
        } else {
            for f in resolved where ids.contains(f.id) { fixes[f.id] = nil }
            resolved.removeAll { ids.contains($0.id) }
        }
        let assessed = fixes.filter { $0.value.availability != nil && !$0.value.isBusy }.map(\.key)
        for id in assessed {
            fixes[id]?.availability = nil
            fixes[id]?.preview = nil
            if let f = findings.first(where: { $0.id == id }) { assessFix(f) }
        }
    }

    // MARK: Folders

    private func watchFolders() {
        watcher?.stop()
        watcher = nil
        guard !settings.watchedFolders.isEmpty else { return }
        let w = FolderWatcher(roots: settings.watchedFolders) { [weak self] _ in
            Task { @MainActor in self?.folderChanged() }
        }
        w.start()
        watcher = w
    }

    /// A lockfile changed: read the folders again once things settle (an install writes many files).
    private func folderChanged() {
        folderDebounce?.cancel()
        folderDebounce = Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(5))
            guard !Task.isCancelled else { return }
            self?.scanNow(refresh: [.folders])
        }
    }

    // MARK: Settings

    public func addFolder(_ url: URL) {
        guard !isShowingFixtures else { return }
        let path = url.standardizedFileURL.path
        guard !settings.watchedFolders.contains(path) else { return }
        settings.watchedFolders.append(path)
        storage.save(settings)
        watchFolders()
        scanNow(refresh: [.folders])
    }

    public func removeFolder(_ path: String) {
        guard !isShowingFixtures else { return }
        settings.watchedFolders.removeAll { $0 == path }
        storage.save(settings)
        watchFolders()
        scanNow(refresh: [.folders])
    }

    public func setInterval(hours: Int) {
        guard !isShowingFixtures else { return }
        settings.scanIntervalHours = hours
        storage.save(settings)
        schedule()
    }

    public func setNotifications(_ on: Bool) {
        guard !isShowingFixtures else { return }
        settings.notificationsEnabled = on
        storage.save(settings)
        if on { Task { await notifier.requestPermission() } }
    }

    public func setLaunchAtLogin(_ on: Bool) {
        launchAtLogin = LoginItem.set(on)
    }

    /// Asks for a folder with the standard panel and watches it.
    public func chooseFolder() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = true
        panel.prompt = "Watch"
        panel.message = "Choose project folders. OSVA Monitor reads their lockfiles on this Mac."
        NSApp.activate(ignoringOtherApps: true)
        if panel.runModal() == .OK { panel.urls.forEach(addFolder) }
    }
}

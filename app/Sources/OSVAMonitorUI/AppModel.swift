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
    // A finding with a runnable command gets a button (FixAdvisor decides: for a `brew upgrade` after asking Homebrew,
    // for a pip upgrade after checking everything installed that depends on the package). The button opens a review
    // with the tool's dry run; its Update runs the command inside the app (FixProcess: an argument list, no shell, no
    // terminal), with the row showing the steps, the time and the live log. When the command ends, the app checks
    // that one finding again (Scanner.recheck) and, after pip, the environment's own `pip check`; the row says what
    // became of it. One fix runs at a time. Only when the tool asks for an administrator password does the app offer
    // Terminal: a one-use script (FixScript) that leaves a result file the app watches. No URL scheme, no Apple
    // Events: a web page or another app cannot start a fix.

    /// Each finding's fix, by finding id: its button, its review, its run, how its last run went.
    public private(set) var fixes: [String: FixRowState] = [:]
    /// Findings fixed since the last full scan (or whose upgrade broke something): gone from the report, still shown
    /// in their rows.
    public private(set) var resolved: [Finding] = []
    public private(set) var isRechecking = false
    /// The finding whose fix is running in the app (from Preparing to the end of Checking again).
    public private(set) var activeFix: String?

    /// The rows' fix states as the popover shows them: each also knows when another fix is running.
    public var rowFixes: [String: FixRowState] {
        guard let busy = busyTitle else { return fixes }
        return fixes.mapValues { s in
            guard !s.isBusy else { return s }
            var shown = s
            shown.waitingFor = busy
            return shown
        }
    }

    /// The name of the finding whose fix is running, in the app or in Terminal.
    var busyTitle: String? {
        if let activeFix { return activeTitle ?? activeFix }
        return runs.values.first?.plan.title
    }

    /// Opens a script in Terminal (tests replace it).
    @ObservationIgnored public var terminal: any TerminalOpener = SystemTerminal()
    /// Starts commands in the app (tests replace it).
    @ObservationIgnored public var launcher: any FixLaunching = FixProcessLauncher()
    @ObservationIgnored public var limits = FixLimits()
    @ObservationIgnored private let advisor: FixAdvisor
    @ObservationIgnored private var activeTitle: String?
    @ObservationIgnored private var activeProcess: (any FixRunning)?
    @ObservationIgnored private var stopRequested = false
    /// The plan each finding's last run in the app used, for Retry.
    @ObservationIgnored private var lastPlans: [String: FixPlan] = [:]
    /// Terminal runs started in this session and not yet ended, by the id in their script's result file.
    @ObservationIgnored private var runs: [UUID: FixRun] = [:]
    /// Runs that ended and wait to be checked again (one at a time, never during a scan).
    @ObservationIgnored private var ended: [(run: FixRun, end: RunEnd)] = []
    @ObservationIgnored private var resultWatcher: FixResultWatcher?

    private struct FixRun {
        var finding: Finding
        var plan: FixPlan
        var script: URL?
        /// An undo of an earlier run, not the plan's own command.
        var undo: PipUndo?
    }

    private enum RunEnd {
        case terminal(Int32)
        case app(FixEnding, PipGuard.After?)
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

    /// A row opened: decide whether it gets a button. Instant, except a `brew upgrade` (Homebrew is asked) and a pip
    /// upgrade (what depends on the package is read).
    public func assessFix(_ finding: Finding) {
        guard !isShowingFixtures else { return }
        let state = fixes[finding.id] ?? FixRowState()
        guard state.availability == nil, !state.isBusy, !state.isResolved else { return }
        switch FixPlan.make(for: finding, tools: advisor.tools, home: advisor.home) {
        case let .failure(refusal):
            fixes[finding.id, default: FixRowState()].availability = .withheld(refusal.explanation)
        case let .success(plan) where plan.action == .removal || (plan.homebrew == nil && plan.pip == nil):
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

    /// The button pressed: the review opens, and the tool is asked for a dry run.
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

    /// The review's Update (or Remove): the plan is made again from the finding as the report has it now, and runs
    /// only if it is the one the review showed, nothing blocks it, and no other fix is running.
    public func runFix(_ finding: Finding) {
        guard !isShowingFixtures, let state = fixes[finding.id], case let .offered(offer)? = state.availability,
              case let .ready(preview)? = state.preview, preview.blocked == nil, !state.isBusy, busyTitle == nil else { return }
        guard let current = currentPlan(finding, matching: offer.plan) else { return }
        start(current.finding, plan: current.plan, also: preview.installs)
    }

    /// Retry: the same command again, after it did not finish, without the review (it was reviewed, and the plan is
    /// still the same one; if anything changed, the review opens instead).
    public func retryFix(_ finding: Finding) {
        guard !isShowingFixtures, let state = fixes[finding.id], case let .offered(offer)? = state.availability, !state.isBusy,
              busyTitle == nil, state.outcome?.isProblem == true else { return }
        guard offer.plan == lastPlans[finding.id] else { beginFix(finding); return }
        guard let current = currentPlan(finding, matching: offer.plan) else { return }
        start(current.finding, plan: current.plan, also: [:])
    }

    /// The finding as the report has it now, and its plan made again, if that is still `plan`. Otherwise the row is
    /// assessed afresh and nil returned.
    private func currentPlan(_ finding: Finding, matching plan: FixPlan) -> (finding: Finding, plan: FixPlan)? {
        guard let current = report?.findings.first(where: { $0.id == finding.id }),
              case let .success(now) = FixPlan.make(for: current, tools: advisor.tools, home: advisor.home), now == plan else {
            fixes[finding.id] = nil
            if let current = report?.findings.first(where: { $0.id == finding.id }) { assessFix(current) }
            return nil
        }
        return (current, now)
    }

    /// Stop: SIGTERM to the command's process group, SIGKILL after the grace period; before it starts, it never does.
    public func stopFix(_ finding: Finding) {
        guard activeFix == finding.id, fixes[finding.id]?.run?.step != .checking else { return }
        stopRequested = true
        fixes[finding.id]?.run?.stopping = true
        activeProcess?.stop()
    }

    /// Undo, after a pip upgrade broke something: the exact earlier versions put back.
    public func undoFix(_ finding: Finding) {
        guard !isShowingFixtures, busyTitle == nil, let state = fixes[finding.id], !state.isBusy, let undo = state.run?.undo,
              let plan = lastPlans[finding.id] else { return }
        launch(finding, plan: plan, invocation: undo.invocation, doing: "Undoing", command: undo.command, undo: undo, pip: nil)
    }

    private func start(_ finding: Finding, plan: FixPlan, also: [String: String]) {
        lastPlans[finding.id] = plan
        launch(finding, plan: plan, invocation: plan.invocation, doing: plan.doing, command: plan.command, undo: nil,
               pip: plan.action == .upgrade ? plan.pip.map { ($0, also) } : nil)
    }

    /// The run itself: Preparing (for pip, what depends on it is read again, and `pip check` noted), the command, then
    /// Checking again (for pip, `pip check` compared), then the re-check of the finding.
    private func launch(_ finding: Finding, plan: FixPlan, invocation: FixInvocation, doing: String, command: String, undo: PipUndo?,
                        pip: (FixPlan.Pip, [String: String])?) {
        let id = finding.id
        activeFix = id
        activeTitle = plan.title
        stopRequested = false
        initiallyExpanded.insert(id)                          // a panel opened again shows the run
        fixes[id, default: FixRowState()].preview = nil
        fixes[id]?.progress = .running
        fixes[id]?.run = FixRunState(doing: doing, command: command)
        let guardian = PipGuard(tools: tools)
        let environment = FixEnvironment.make(tools: tools, executable: invocation.executable, toolName: plan.toolName)
        let launcher = self.launcher, limits = self.limits
        Task { [weak self] in
            var before: (site: PythonSite, problems: Set<String>)?
            if let (pip, also) = pip {
                switch await guardian.check(pip, also: also) {
                case let .blocked(line, _), let .unknown(line):
                    self?.endBeforeRunning(finding, plan: plan, outcome: .blocked(line))
                    return
                case let .clear(site):
                    guard let problems = await guardian.problems(pip) else {
                        self?.endBeforeRunning(finding, plan: plan, outcome: .blocked("pip check did not answer, so nothing was changed"))
                        return
                    }
                    before = (site, problems)
                }
            }
            guard let self, self.activeFix == id else { return }
            if self.stopRequested { self.endBeforeRunning(finding, plan: plan, outcome: .stopped(nil)); return }
            self.fixes[id]?.run?.step = .running
            let process = launcher.launch(invocation, environment: environment, limits: limits) { [weak self] log in
                Task { @MainActor in
                    guard let self, self.activeFix == id, self.fixes[id]?.run?.step == .running else { return }
                    self.fixes[id]?.run?.log = log
                }
            }
            self.activeProcess = process
            let (ending, log) = await process.ending()
            self.activeProcess = nil
            self.fixes[id]?.run?.log = log
            self.fixes[id]?.run?.endedAt = Date()
            self.fixes[id]?.run?.stopping = false
            self.fixes[id]?.run?.step = .checking
            var after: PipGuard.After?
            if let (pip, _) = pip, let before {
                if case .couldNotStart = ending {} else { after = await guardian.after(pip, before: before.site, problemsBefore: before.problems) }
            }
            self.ended.append((FixRun(finding: finding, plan: plan, undo: undo), .app(ending, after)))
            self.recheckNext()
        }
    }

    /// Nothing ran (blocked, or stopped while preparing): the row says why, and the button is offered again.
    private func endBeforeRunning(_ finding: Finding, plan: FixPlan, outcome: FixOutcome) {
        let id = finding.id
        guard activeFix == id else { return }
        activeFix = nil; activeTitle = nil; activeProcess = nil
        fixes[id]?.progress = .finished(outcome)
        fixes[id]?.run?.endedAt = Date()
        fixes[id]?.run?.stopping = false
    }

    /// Only after the tool asked for an administrator password: the command in a Terminal window, where it can ask.
    /// The plan is made again and must be the one the row showed; the app never sees or handles the password.
    public func runFixInTerminal(_ finding: Finding) {
        guard !isShowingFixtures, busyTitle == nil, let state = fixes[finding.id], state.outcome == .needsPassword,
              !state.isBusy, let plan = lastPlans[finding.id] else { return }
        guard let current = currentPlan(finding, matching: plan) else { return }
        let run = UUID()
        let script: URL
        do {
            try fixDirectories.prepare()
            startResultWatcher()
            script = try FixScript.write(current.plan, run: run, directories: fixDirectories)
        } catch {
            fixes[finding.id]?.progress = .finished(.couldNotOpen(String(describing: error)))
            return
        }
        runs[run] = FixRun(finding: current.finding, plan: current.plan, script: script)
        fixes[finding.id]?.run = nil
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

    /// Something changed in fix-results/: take the results of this session's Terminal runs (FixResults says why
    /// nothing else there can do more than this) and check each finding again.
    private func collectFixResults() {
        guard !runs.isEmpty else { return }
        for result in FixResults.collect(in: fixDirectories.results, pending: runs.mapValues(\.finding.id)) {
            guard let run = runs.removeValue(forKey: result.run) else { continue }
            if let script = run.script { try? FileManager.default.removeItem(at: script) }   // it removes itself; in case it could not
            fixes[run.finding.id, default: FixRowState()].progress = .rechecking
            ended.append((run, .terminal(result.status)))
        }
        recheckNext()
    }

    private func recheckNext() {
        guard !isScanning, !isRechecking, !ended.isEmpty, let report else { return }
        let (run, end) = ended.removeFirst()
        isRechecking = true
        let scanner = makeScanner()
        let advisor = self.advisor
        Task { [weak self] in
            let (updated, recheck) = await scanner.recheck(run.finding, in: report)
            let outcome: FixOutcome
            switch end {
            case let .terminal(status):
                var homebrew: HomebrewAvailability?
                if case .stillAffected = recheck, status == 0 { homebrew = await advisor.homebrew(run.plan) }
                outcome = FixOutcome.make(status: status, before: run.finding, recheck: recheck, homebrew: homebrew)
            case let .app(ending, after) where run.undo != nil:
                _ = after
                outcome = ending.succeeded ? .undone(run.undo!.restores.joined(separator: ", ")) : .undoFailed
            case let .app(ending, after):
                var homebrew: HomebrewAvailability?
                if case .stillAffected = recheck, ending.succeeded { homebrew = await advisor.homebrew(run.plan) }
                var recheck = recheck
                if let why = after?.uncheckable, case .fixed = recheck { recheck = .couldNotCheck(why) }
                outcome = FixOutcome.make(ending: ending, before: run.finding, recheck: recheck, homebrew: homebrew, broke: after?.broke)
                if let undo = after?.undo, after?.broke != nil { self?.fixes[run.finding.id]?.run?.undo = undo }
            }
            self?.finishRecheck(run, report: updated, recheck: recheck, outcome: outcome)
        }
    }

    private func finishRecheck(_ run: FixRun, report updated: ScanReport, recheck: OSVAKit.Scanner.Recheck, outcome: FixOutcome) {
        isRechecking = false
        report = updated
        storage.save(updated)
        let id = run.finding.id
        var state = FixRowState(progress: .finished(outcome), run: run.script == nil ? fixes[id]?.run : nil)
        if case .undone = outcome { state.run?.undo = nil }
        // Still found, perhaps at a new version (a new id): its row says so, and gets its button again if one applies.
        let now: Finding? = if case let .stillAffected(f) = recheck { f } else { updated.findings.first { $0.id == id } }
        resolved.removeAll { $0.id == id }
        fixes[id] = nil
        if let now, !outcome.isResolved {
            fixes[now.id] = state
            if now.id != id, let plan = lastPlans.removeValue(forKey: id) { lastPlans[now.id] = plan }
            assessFix(now)
        } else {
            // gone from the report (fixed, removed, or fixed but broke what depends on it): kept in place until the
            // next full scan
            resolved.append(run.finding)
            fixes[id] = state
        }
        if activeFix == id || activeFix == now?.id { activeFix = nil; activeTitle = nil }
        recheckNext()
        runPendingScan()
    }

    /// A scan replaced the findings. A full scan starts the fixes afresh (runs under way go on, and an upgrade that
    /// broke something keeps its row and its Undo); after a partial one, a fixed row whose finding is back is no
    /// longer fixed. Rows that had been assessed are assessed again.
    private func scanReplacedFindings(full: Bool) {
        let findings = report?.findings ?? []
        let ids = Set(findings.map(\.id))
        if full {
            let keep = fixes.filter { $0.value.isBusy || $0.value.run?.undo != nil }
            resolved = resolved.filter { keep[$0.id] != nil && !ids.contains($0.id) }
            fixes = keep
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

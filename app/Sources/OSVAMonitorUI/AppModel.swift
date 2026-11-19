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
    @ObservationIgnored private let defaults: UserDefaults
    /// This app's version ("0.3.1"), and every version's changelog entry.
    @ObservationIgnored private let version: String
    @ObservationIgnored public let changelog: Changelog
    @ObservationIgnored private var timer: Timer?
    @ObservationIgnored private var watcher: FolderWatcher?
    @ObservationIgnored private var pendingRefresh: Set<SourceKind>?
    @ObservationIgnored private var folderDebounce: Task<Void, Never>?

    /// `tools` and `transport` are this Mac's and the network's, `defaults`, `version` and `changelog` this app's;
    /// tests pass their own.
    public init(storage: Storage = Storage(directory: Paths.supportDirectory()), notifier: any Notifier = SystemNotifier(),
                tools: ToolEnvironment = ToolEnvironment(), transport: any HTTPTransport = URLSessionTransport(),
                defaults: UserDefaults = .standard, version: String = AppModel.appVersion, changelog: Changelog = .bundled) {
        self.storage = storage
        self.notifier = notifier
        self.tools = tools
        self.transport = transport
        self.defaults = defaults
        self.version = version
        self.changelog = changelog
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

    /// Decides whether there is anything new to show, starts the schedule and the folder watcher, and scans if the
    /// last scan is older than the interval.
    public func start() {
        checkWhatsNew()                                   // before this version's first scan is recorded
        schedule()
        watchFolders()
        prepareFixFolders()
        Task { await notifier.requestPermission() }
        let due = report.map { Date().timeIntervalSince($0.finishedAt) > interval } ?? true
        // A newer app scans at once, so the findings carry what it adds (0.2.0's Fix button needs a new scan).
        let scannedByOlder = report != nil && defaults.string(forKey: Self.scannedByKey) != version
        if due || scannedByOlder { scanNow() } else { assessAllFixes() }
    }

    /// The app version that made the saved report.
    static let scannedByKey = "lastFullScanAppVersion"
    public nonisolated static var appVersion: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "" }

    // MARK: What's new

    /// This version's changelog entry, at the top of the panel from the first time it opens after an update until the
    /// person closes it (WhatsNew decides).
    public private(set) var whatsNew: Changelog.Entry?

    /// At launch: show this version's entry if the app was updated to it, and on a first install note the version.
    func checkWhatsNew() {
        let ranBefore = defaults.string(forKey: Self.scannedByKey) != nil || storage.hasSavedState
        switch WhatsNew.decide(current: version, lastSeen: defaults.string(forKey: WhatsNew.lastSeenKey), ranBefore: ranBefore,
                               changelog: changelog) {
        case let .show(entry): whatsNew = entry
        case let .remember(v): defaults.set(v, forKey: WhatsNew.lastSeenKey)
        case .nothing: break
        }
    }

    /// Close: gone, and not shown again for this version.
    public func closeWhatsNew() {
        guard let entry = whatsNew else { return }
        whatsNew = nil
        defaults.set(entry.version, forKey: WhatsNew.lastSeenKey)
    }

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
        if full { defaults.set(version, forKey: Self.scannedByKey) }
        scanReplacedFindings(full: full)
        if settings.notificationsEnabled {
            let before = Set(previous?.findings.filter(\.deservesNotification).map(\.notificationKey) ?? [])
            let fresh = result.findings.filter { $0.deservesNotification && !before.contains($0.notificationKey) }
            if !fresh.isEmpty { Task { await notifier.post(fresh) } }
        }
        recheckNext()
        runPendingScan()
        nextFixAllStep()
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
    // Events: a web page or another app cannot start a fix. Fix all (below) runs the rows' own fixes through this same
    // loop, one after another, after one review.

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

    /// The name of the finding whose fix is running, in the app or in Terminal, or of Fix all's step.
    var busyTitle: String? {
        if let activeFix { return activeTitle ?? activeFix }
        if fixAll?.phase == .running { return fixAll?.currentStep?.name ?? "Fix all" }
        return runs.values.first?.plan.title
    }

    /// Opens a script in Terminal (tests replace it).
    @ObservationIgnored public var terminal: any TerminalOpener = SystemTerminal()
    /// Starts commands in the app (tests replace it).
    @ObservationIgnored public var launcher: any FixLaunching = FixProcessLauncher()
    @ObservationIgnored public var limits = FixLimits()
    @ObservationIgnored private let advisor: FixAdvisor
    @ObservationIgnored private var activeTitle: String?
    /// Every finding the running command fixes (one, or a Fix all step's several): each row shows the run, and each
    /// is checked again after it. `activeFix` is the first.
    @ObservationIgnored private var activeMembers: Set<String> = []
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
        /// Who uses what a pip upgrade changed beyond a patch: a fixed outcome says to check them.
        var check: String?
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
    /// upgrade (what depends on the package is read). A row whose turn in `assessAllFixes` has not come yet is decided
    /// now.
    public func assessFix(_ finding: Finding) {
        if let i = queuedAssessments.firstIndex(where: { $0.id == finding.id }) {
            queuedAssessments.remove(at: i)
            if fixes[finding.id]?.availability == .checking { checkOffer(finding) }
            return
        }
        decideOffer(finding, queue: false)
    }

    /// Every finding's button decided, as each row decides its own (`assessFix`), so Fix all can count them: the
    /// instant ones at once, the rest one at a time in the background (one `brew info` or one Python read at a time).
    public func assessAllFixes() {
        guard !isShowingFixtures else { return }
        queuedAssessments.removeAll()
        for f in report?.findings ?? [] { decideOffer(f, queue: true) }
        drainAssessments()
    }

    @ObservationIgnored private var queuedAssessments: [Finding] = []
    @ObservationIgnored private var draining = false

    private func decideOffer(_ finding: Finding, queue: Bool) {
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
            if queue { queuedAssessments.append(finding) } else { checkOffer(finding) }
        }
    }

    /// The check that decides a `brew upgrade`'s or a pip upgrade's button (FixAdvisor.assess).
    private func checkOffer(_ finding: Finding) {
        let advisor = self.advisor
        Task { [weak self] in
            let assessment = await advisor.assess(finding)
            guard let self, self.fixes[finding.id]?.availability == .checking else { return }
            self.fixes[finding.id]?.availability = Self.availability(assessment)
        }
    }

    private func drainAssessments() {
        guard !draining, !queuedAssessments.isEmpty else { return }
        draining = true
        let advisor = self.advisor
        Task { [weak self] in
            while let self, !self.queuedAssessments.isEmpty {
                let finding = self.queuedAssessments.removeFirst()
                guard self.fixes[finding.id]?.availability == .checking else { continue }
                let assessment = await advisor.assess(finding)
                guard self.fixes[finding.id]?.availability == .checking else { continue }
                self.fixes[finding.id]?.availability = Self.availability(assessment)
            }
            self?.draining = false
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
            let preview = await advisor.preview(offer)
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
        start(current.finding, plan: current.plan, also: preview.installs, pins: preview.pins)
    }

    /// Retry: the same command again, after it did not finish, without the review (it was reviewed, and the plan is
    /// still the same one; if anything changed, the review opens instead).
    public func retryFix(_ finding: Finding) {
        guard !isShowingFixtures, let state = fixes[finding.id], case let .offered(offer)? = state.availability, !state.isBusy,
              busyTitle == nil, state.outcome?.isProblem == true else { return }
        // a pip upgrade is never run again without a fresh dry run: Retry opens its review
        guard offer.plan == lastPlans[finding.id], offer.plan.pip == nil else { beginFix(finding); return }
        guard let current = currentPlan(finding, matching: offer.plan) else { return }
        start(current.finding, plan: current.plan, also: [:], pins: [])
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
    /// Stopping a Fix all step stops Fix all: the rest never start.
    public func stopFix(_ finding: Finding) {
        guard activeFix != nil, activeMembers.contains(finding.id), fixes[finding.id]?.run?.step != .checking else { return }
        stopRequested = true
        for id in activeMembers { fixes[id]?.run?.stopping = true }
        activeProcess?.stop()
        if fixAll?.phase == .running { fixAll?.stopRequested = true }
    }

    /// Undo, after a pip upgrade broke something: the exact earlier versions put back.
    public func undoFix(_ finding: Finding) {
        guard !isShowingFixtures, busyTitle == nil, let state = fixes[finding.id], !state.isBusy, let undo = state.run?.undo,
              let plan = lastPlans[finding.id] else { return }
        launch(finding, plan: plan, invocation: undo.invocation, doing: "Undoing", command: undo.command, undo: undo, pip: nil)
    }

    /// `pins`: for pip, every other package its dry run would install, pinned, after the fix's own pin. `members`: the
    /// other findings the same command fixes (a Fix all step), each with its own plan.
    private func start(_ finding: Finding, plan: FixPlan, also: [String: String], pins: [String], members: [(Finding, FixPlan)] = [],
                       title: String? = nil) {
        lastPlans[finding.id] = plan
        for (m, p) in members { lastPlans[m.id] = p }
        var invocation = plan.invocation
        invocation.arguments += pins
        let command = pins.isEmpty ? plan.command : invocation.argv.map(UpgradeCommand.quote).joined(separator: " ")
        launch(finding, plan: plan, invocation: invocation, doing: plan.doing, command: command, undo: nil,
               pip: plan.action == .upgrade ? plan.pip.map { ($0, also) } : nil, members: members, title: title)
    }

    /// The run itself: Preparing (for pip, what depends on it is read again, and `pip check` noted), the command, then
    /// Checking again (for pip, `pip check` compared), then the re-check of the finding.
    /// A Fix all step (`title` set) keeps the time its Preparing started, and its rows stay as they are: its own card shows
    /// the run.
    private func launch(_ finding: Finding, plan: FixPlan, invocation: FixInvocation, doing: String, command: String, undo: PipUndo?,
                        pip: (FixPlan.Pip, [String: String])?, members: [(Finding, FixPlan)] = [], title: String? = nil) {
        let id = finding.id
        let all = [(finding, plan)] + members
        let ids = all.map(\.0.id)
        let started = title == nil ? Date() : (fixes[id]?.run?.startedAt ?? Date())
        activeFix = id
        activeTitle = title ?? plan.title
        activeMembers = Set(ids)
        stopRequested = false
        if title == nil { initiallyExpanded.insert(id) }       // a panel opened again shows the run
        for m in ids {
            fixes[m, default: FixRowState()].preview = nil
            fixes[m]?.progress = .running
            fixes[m]?.run = FixRunState(doing: doing, startedAt: started, command: command)
        }
        let guardian = PipGuard(tools: tools)
        let environment = FixEnvironment.make(tools: tools, executable: invocation.executable, toolName: plan.toolName)
        let launcher = self.launcher, limits = self.limits
        Task { [weak self] in
            var before: (site: PythonSite, problems: Set<String>)?
            var check: String?
            if let (pip, also) = pip {
                switch await guardian.check(pip, also: also) {
                case let .blocked(line, _), let .unknown(line):
                    self?.endBeforeRunning(finding, plan: plan, outcome: .blocked(line))
                    return
                case .companions:
                    self?.endBeforeRunning(finding, plan: plan, outcome: .blocked("what pins \(pip.name) would not move with it"))
                    return
                case let .clear(site):
                    if PipGuard.beyondPatch(from: pip.installed, to: pip.target) {
                        var moving = Set(also.keys)
                        moving.insert(PythonNames.normal(pip.name))
                        check = PipGuard.usersLine(PipGuard.users(of: moving, in: site, except: moving).map(\.name))
                    }
                    guard let problems = await guardian.problems(pip) else {
                        self?.endBeforeRunning(finding, plan: plan, outcome: .blocked("pip check did not answer, so nothing was changed"))
                        return
                    }
                    before = (site, problems)
                }
            }
            guard let self, self.activeFix == id else { return }
            if self.stopRequested { self.endBeforeRunning(finding, plan: plan, outcome: .stopped(nil)); return }
            for m in ids { self.fixes[m]?.run?.step = .running }
            let process = launcher.launch(invocation, environment: environment, limits: limits) { [weak self] log in
                Task { @MainActor in
                    guard let self, self.activeFix == id, self.fixes[id]?.run?.step == .running else { return }
                    for m in ids { self.fixes[m]?.run?.log = log }
                }
            }
            self.activeProcess = process
            let (ending, log) = await process.ending()
            self.activeProcess = nil
            for m in ids {
                self.fixes[m]?.run?.log = log
                self.fixes[m]?.run?.endedAt = Date()
                self.fixes[m]?.run?.stopping = false
                self.fixes[m]?.run?.step = .checking
            }
            var after: PipGuard.After?
            if let (pip, _) = pip, let before {
                if case .couldNotStart = ending {} else { after = await guardian.after(pip, before: before.site, problemsBefore: before.problems) }
            }
            // each finding the command fixes is checked again, one at a time, and keeps its own outcome and Undo
            for (m, p) in all { self.ended.append((FixRun(finding: m, plan: p, undo: undo, check: check), .app(ending, after))) }
            self.recheckNext()
        }
    }

    /// Nothing ran (blocked, or stopped while preparing): the row says why, and the button is offered again.
    private func endBeforeRunning(_ finding: Finding, plan: FixPlan, outcome: FixOutcome) {
        let id = finding.id
        guard activeFix == id else { return }
        let members = activeMembers.union([id])
        activeFix = nil; activeTitle = nil; activeProcess = nil; activeMembers = []
        for m in members {
            fixes[m]?.progress = .finished(outcome)
            fixes[m]?.run?.endedAt = Date()
            fixes[m]?.run?.stopping = false
            recordFixAll(m, outcome)
        }
        nextFixAllStep()
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
        let guardian = PipGuard(tools: tools)
        Task { [weak self] in
            let (updated, recheck) = await scanner.recheck(run.finding, in: report)
            let outcome: FixOutcome
            switch end {
            case let .terminal(status):
                var homebrew: HomebrewAvailability?
                if case .stillAffected = recheck, status == 0 { homebrew = await advisor.homebrew(run.plan) }
                outcome = FixOutcome.make(status: status, before: run.finding, recheck: recheck, homebrew: homebrew)
            case let .app(ending, _) where run.undo != nil:
                // pip marked what the undo named REQUESTED; the marks that were not there before the fix go
                _ = await guardian.afterUndo(run.undo!)
                outcome = ending.succeeded ? .undone(run.undo!.restores.joined(separator: ", ")) : .undoFailed
            case let .app(ending, after):
                var homebrew: HomebrewAvailability?
                if case .stillAffected = recheck, ending.succeeded { homebrew = await advisor.homebrew(run.plan) }
                var recheck = recheck
                if let why = after?.uncheckable, case .fixed = recheck { recheck = .couldNotCheck(why) }
                outcome = FixOutcome.make(ending: ending, before: run.finding, recheck: recheck, homebrew: homebrew, broke: after?.broke,
                                          check: run.check)
                // Undo stays on screen after anything that broke something, or that others use and pip cannot vouch for
                if let undo = after?.undo, after?.broke != nil || run.check != nil { self?.fixes[run.finding.id]?.run?.undo = undo }
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
        activeMembers.remove(id)
        if let now { activeMembers.remove(now.id) }
        if activeFix != nil, activeMembers.isEmpty { activeFix = nil; activeTitle = nil }
        recordFixAll(id, outcome)
        recheckNext()
        runPendingScan()
        nextFixAllStep()
    }

    /// A scan replaced the findings. A full scan starts the fixes afresh (runs under way go on, and an upgrade that
    /// broke something keeps its row and its Undo); after a partial one, a fixed row whose finding is back is no
    /// longer fixed. Every row is assessed again, so Fix all's count is current.
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
        }
        assessAllFixes()
    }

    // MARK: Fix all
    //
    // One review, then every fix the rows offer (FixRowState.offeredFix, nothing else decides), one at a time, worst
    // first, one command once however many findings it fixes. Each step is the row's own loop: Preparing checks it
    // again (the finding as the report has it now, its plan made again, its offer decided again, the tool's dry run),
    // then the command, pip's checks before and after, the REQUESTED cleanup, the check of each finding, its Undo. An
    // earlier step can change the picture (a Homebrew upgrade brings a dependency along, a pip upgrade changes what
    // depends on what): a step no longer valid is skipped with why, and checked again first if anything ran before it.
    // A step that broke something ends Fix all there, its Undo shown. One that failed is counted, and the next runs.
    // Terminal is never offered: a step that needs a password is counted as needing the person. At the end, the
    // sources the steps changed are read again.

    /// Fix all's review, run or summary, while one is shown.
    public private(set) var fixAll: FixAllState?

    /// What the panel shows of Fix all: the header's count (exactly the rows that offer a fix now) and why it waits,
    /// and the batch with the current step's run.
    public var fixAllPanel: FixAllPanel {
        let findings = report?.findings ?? []
        let running = fixAll?.phase == .running
        var undo: PipUndo?
        if let broke = fixAll?.broke { undo = fixes[broke.step.id]?.run?.undo }
        return FixAllPanel(count: FixAll.offered(findings, fixes: fixes).count, waitingFor: busyTitle,
                           checking: findings.contains { fixes[$0.id]?.availability == .checking }, batch: fixAll,
                           run: running ? activeFix.flatMap { fixes[$0]?.run } : nil, undo: undo)
    }

    /// The header's Fix all: the review opens. Nothing runs from it.
    public func openFixAll() {
        guard !isShowingFixtures, busyTitle == nil, fixAll?.phase != .running, let report else { return }
        let review = FixAll.review(report.findings, fixes: fixes)
        fixAll = review.steps.isEmpty ? nil : review
    }

    /// The review's Cancel, or the summary's Close.
    public func closeFixAll() {
        guard fixAll?.phase != .running else { return }
        fixAll = nil
    }

    /// The review's Fix all: it runs only if the review is still what the rows offer now (otherwise the review shows
    /// what is true now, to be confirmed again), and nothing else is running.
    public func runFixAll() {
        guard !isShowingFixtures, let shown = fixAll, shown.phase == .review, busyTitle == nil, let report else { return }
        var now = FixAll.review(report.findings, fixes: fixes)
        guard now == shown else { fixAll = now.steps.isEmpty ? nil : now; return }
        now.phase = .running
        fixAll = now
        nextFixAllStep()
    }

    /// Stop: the step under way ends as its own Stop ends it, and no other starts.
    public func stopFixAll() {
        guard fixAll?.phase == .running else { return }
        fixAll?.stopRequested = true
        if let step = fixAll?.currentStep, let first = step.findings.first(where: { activeMembers.contains($0.id) }) { stopFix(first) }
        nextFixAllStep()
    }

    /// The next step, once the last has ended and each of its findings was checked again (never during a scan); or
    /// the end: every step had its turn, Stop was pressed, or a step broke something.
    private func nextFixAllStep() {
        guard var batch = fixAll, batch.phase == .running, activeFix == nil, !isRechecking, !isScanning, ended.isEmpty else { return }
        if let i = batch.current {
            if batch.steps[i].status == .running { batch.steps[i].status = .done }
            batch.current = nil
        }
        if batch.ending == nil, batch.stopRequested { batch.ending = .stopped }
        guard batch.ending == nil, let i = batch.steps.firstIndex(where: { $0.status == .waiting }) else {
            for j in batch.steps.indices where batch.steps[j].status == .waiting { batch.steps[j].status = .notRun }
            batch.ending = batch.ending ?? .finished
            batch.phase = .done
            fixAll = batch
            if batch.changedSomething { scanNow(refresh: Self.sources(batch)) }   // what a step changed beyond its findings
            return
        }
        batch.current = i
        batch.steps[i].status = .running
        fixAll = batch
        runFixAllStep(batch.steps[i])
    }

    /// The sources the steps that ran changed: each finding's own, and Homebrew's for what a `brew` command updated.
    static func sources(_ batch: FixAllState) -> Set<SourceKind> {
        var kinds = Set<SourceKind>()
        for step in batch.steps where step.status == .done {
            kinds.formUnion(step.findings.flatMap(\.origins).map(\.kind))
            if step.plan.toolName == "brew" || kinds.contains(.electron) { kinds.insert(.homebrew) }
        }
        return kinds
    }

    /// One step. Preparing checks it again, as the row's own Update would be checked, and more: after an earlier step
    /// ran, each finding is checked again first (Scanner.recheck, as after a run), and one that step already fixed is
    /// done, one it changed left to its row; then each finding as the report has it now, with its plan made again;
    /// the first one's offer decided again (Homebrew asked, a Python's dependents read), which holds for the others
    /// (the same command); the tool's dry run. Then it runs, through `start`.
    private func runFixAllStep(_ step: FixAllState.Step) {
        let first = step.findings[0]
        activeFix = first.id
        activeTitle = step.name
        activeMembers = Set(step.findings.map(\.id))
        stopRequested = false
        for (f, offer) in zip(step.findings, step.offers) {
            fixes[f.id, default: FixRowState()].preview = nil
            fixes[f.id]?.progress = .running
            fixes[f.id]?.run = FixRunState(doing: offer.plan.doing, command: offer.plan.command)
        }
        let advisor = self.advisor
        let recheckFirst = fixAll?.changedSomething == true
        Task { [weak self] in
            guard let self else { return }
            var members = Array(zip(step.findings, step.offers))
            if recheckFirst { members = await self.recheckBeforeStep(members) }
            var ready: [(Finding, FixOffer)] = [], dropped: [(Finding, String)] = []
            for (f, offer) in members where !self.stopRequested {
                guard let current = self.report?.findings.first(where: { $0.id == f.id }),
                      case let .success(plan) = FixPlan.make(for: current, tools: advisor.tools, home: advisor.home), plan == offer.plan else {
                    dropped.append((f, "It changed since the review")); continue
                }
                guard ready.isEmpty else { ready.append((current, offer)); continue }
                switch await advisor.assess(current) {
                case let .offer(now) where now.plan == plan: ready.append((current, now))
                case let .withheld(why):
                    self.fixes[f.id]?.availability = .withheld(why)
                    dropped.append((current, why))
                case .offer: dropped.append((current, "It changed since the review"))
                case .none: dropped.append((current, "The app no longer offers it"))
                }
            }
            guard self.activeFix == first.id else { return }
            if self.stopRequested { self.endFixAllStep(stopped: true); return }
            var preview: FixPreview?
            if let (_, offer) = ready.first {
                let p = await advisor.preview(offer)                                 // the review's own dry run
                if let blocked = p.blocked {
                    dropped += ready.map { ($0.0, blocked.prefix(1).uppercased() + blocked.dropFirst()) }
                    ready = []
                } else {
                    preview = p
                }
            }
            guard self.activeFix == first.id else { return }
            if self.stopRequested { self.endFixAllStep(stopped: true); return }
            for (f, why) in dropped { self.leaveAlone(f, why: why) }                 // the rows say why
            guard let (runFor, offer) = ready.first, let preview else {
                if let i = self.fixAll?.current {
                    let earlier = self.fixAll?.steps[i].outcomes.values.allSatisfy(\.isResolved) == true
                    self.fixAll?.steps[i].status = .skipped(dropped.first.map { Self.clause($0.1) }
                                                            ?? (earlier ? "Fixed by an earlier step" : "It changed since the review"))
                }
                self.endFixAllStep(stopped: false)
                return
            }
            self.fixAll?.changedSomething = true
            self.start(runFor, plan: offer.plan, also: preview.installs, pins: preview.pins,
                       members: ready.dropFirst().map { ($0.0, $0.1.plan) }, title: step.name)
        }
    }

    /// A step ends before its command runs: Stop was pressed while it was preparing (its rows say Stopped, and Retry
    /// is there), or nothing in it was left to run.
    private func endFixAllStep(stopped: Bool) {
        for id in activeMembers where stopped {
            fixes[id]?.progress = .finished(.stopped(nil))
            fixes[id]?.run?.endedAt = Date()
            fixes[id]?.run?.stopping = false
            recordFixAll(id, .stopped(nil))
        }
        activeFix = nil; activeTitle = nil; activeMembers = []
        nextFixAllStep()
    }

    /// After an earlier step ran: each of this step's findings checked again, as after a run (never during a scan).
    /// One that step fixed or removed is done, its row saying so; one it moved to another version that is still
    /// affected is left to its row, which offers what fits it now. The rest go on to the step's own checks.
    private func recheckBeforeStep(_ members: [(Finding, FixOffer)]) async -> [(Finding, FixOffer)] {
        var still: [(Finding, FixOffer)] = []
        for (f, offer) in members {
            while isScanning || isRechecking { try? await Task.sleep(for: .milliseconds(200)) }
            guard !stopRequested, let report else { still.append((f, offer)); continue }
            isRechecking = true                                // a scan asked for now waits, as for any re-check
            let (updated, recheck) = await makeScanner().recheck(f, in: report)
            isRechecking = false
            self.report = updated
            storage.save(updated)
            switch recheck {
            case let .fixed(now): settle(f, .fixed(now: now))
            case .removed: settle(f, .removed)
            case let .stillAffected(now) where now.id != f.id:
                settle(f, .blocked("It changed since the review: now \(now.installedLabel)"), now: now)
            case .stillAffected, .couldNotCheck: still.append((f, offer))
            }
        }
        runPendingScan()
        return still
    }

    /// A step's finding an earlier step fixed, removed or moved: its row says so, as after its own run.
    private func settle(_ finding: Finding, _ outcome: FixOutcome, now: Finding? = nil) {
        activeMembers.remove(finding.id)
        fixes[finding.id] = nil
        resolved.removeAll { $0.id == finding.id }
        if let now {
            fixes[now.id] = FixRowState(progress: .finished(outcome))
            assessFix(now)
        } else {
            resolved.append(finding)
            fixes[finding.id] = FixRowState(progress: .finished(outcome))
        }
        recordFixAll(finding.id, outcome)
    }

    /// Not run: the row says why, and decides its button afresh.
    private func leaveAlone(_ finding: Finding, why: String) {
        let outcome = FixOutcome.blocked(Self.clause(why))
        fixes[finding.id, default: FixRowState()].progress = .finished(outcome)
        fixes[finding.id]?.run = nil
        let decided: Bool
        if case .withheld? = fixes[finding.id]?.availability { decided = true } else { decided = false }   // just now, by Preparing
        if !decided {
            fixes[finding.id]?.availability = nil
            if let current = report?.findings.first(where: { $0.id == finding.id }) { assessFix(current) }
        }
        recordFixAll(finding.id, outcome)
    }

    /// "Homebrew still ships 1.30.6; the fix is 1.30.7 upstream." as a clause: "Not run: Homebrew still ships …".
    static func clause(_ s: String) -> String { s.hasSuffix(".") ? String(s.dropLast()) : s }

    /// A step's finding ended: its outcome kept for the summary. One that broke something ends Fix all after this step.
    private func recordFixAll(_ id: String, _ outcome: FixOutcome) {
        guard var batch = fixAll, batch.phase == .running, let i = batch.current,
              batch.steps[i].findings.contains(where: { $0.id == id }) else { return }
        batch.steps[i].outcomes[id] = outcome
        if case let .broke(what) = outcome, batch.ending == nil { batch.ending = .broke(step: i, what: what) }
        fixAll = batch
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

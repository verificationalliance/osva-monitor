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
    public private(set) var launchAtLogin: Bool
    public private(set) var settings: MonitorSettings

    public let notifier: any Notifier
    @ObservationIgnored private let loginItem: any LoginItemService
    /// Sparkle, in the app; started by `begin` and nothing else.
    @ObservationIgnored private let updater: (any AppUpdating)?
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

    /// `tools` and `transport` are this Mac's and the network's, `defaults`, `version` and `changelog` this app's,
    /// `loginItem` and `updater` the system's and Sparkle's; tests pass their own.
    public init(storage: Storage = Storage(directory: Paths.supportDirectory()), notifier: any Notifier = SystemNotifier(),
                tools: ToolEnvironment = ToolEnvironment(), transport: any HTTPTransport = URLSessionTransport(),
                defaults: UserDefaults = .standard, version: String = AppModel.appVersion, changelog: Changelog = .bundled,
                loginItem: any LoginItemService = SystemLoginItem(), updater: (any AppUpdating)? = nil) {
        self.storage = storage
        self.notifier = notifier
        self.loginItem = loginItem
        self.updater = updater
        launchAtLogin = loginItem.isEnabled
        self.tools = tools
        self.transport = transport
        self.defaults = defaults
        self.version = version
        self.changelog = changelog
        settings = storage.loadSettings()
        report = storage.loadLastReport()
        fixServer = AppFixServer(storage: storage, tools: tools, transport: transport, limiter: limiter) { [weak self] sent in
            Task { @MainActor in self?.recordSent(sent) }
        }
    }

    /// What a fix's questions to the site named (a partial fix's plan, the flaws of what an upgrade together moves):
    /// added to the last report's "What leaves your Mac".
    private func recordSent(_ sent: [SentRequest]) {
        guard !sent.isEmpty, !isShowingFixtures, var r = report else { return }
        r.sent.requests += sent
        report = r
        storage.save(r)
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

    /// At launch. The one gate: until the person agreed (Consent), the app shows the first-launch card and does nothing
    /// else, no scan, no index, no update check, no notification prompt, no login item. Once they have, `begin`.
    public func start() {
        guard Consent.given(defaults) else {
            consent = Consent.prefill(ranBefore: ranBefore, settings: settings, openAtLogin: launchAtLogin,
                                      checksForUpdates: updater?.checksDaily ?? true)
            return
        }
        begin(checksForUpdates: updater?.checksDaily ?? true)
    }

    /// Decides whether there is anything new to show, starts the updater, the schedule and the folder watcher, asks
    /// for notifications if they are on, and scans if the last scan is older than the interval.
    private func begin(checksForUpdates: Bool) {
        checkWhatsNew()                                   // before this version's first scan is recorded
        schedule()
        watchFolders()
        prepareFixFolders()
        if settings.notificationsEnabled { Task { await notifier.requestPermission() } }
        updater?.start(checksDaily: checksForUpdates)
        let due = report.map { Date().timeIntervalSince($0.finishedAt) > interval } ?? true
        // A newer app scans at once, so the findings carry what it adds (0.2.0's Fix button needs a new scan).
        if due || scannedByOlder { scanNow() } else { assessAllFixes() }
    }

    /// The app version that made the saved report.
    static let scannedByKey = "lastFullScanAppVersion"

    /// The saved report was made by an older version of the app (or one from before 0.2.1, which recorded none).
    private var scannedByOlder: Bool { report != nil && defaults.string(forKey: Self.scannedByKey) != version }

    /// Why a row of such a report offers nothing yet.
    static let olderReport = "Not offered until this version of the app has scanned again."

    /// Whether an earlier version ran here: the version of its last scan (recorded since 0.2.1), or a saved scan or
    /// settings file (every version).
    private var ranBefore: Bool { defaults.string(forKey: Self.scannedByKey) != nil || storage.hasSavedState }

    // MARK: Consent

    /// The first-launch card's switches while it waits for Start; nil once the person agreed.
    public private(set) var consent: ConsentChoices?

    /// The menu-bar shield: with a dot beside it while the card waits for Start, otherwise what the last report says.
    public var menuBarState: MenuBarLabel.State { consent == nil ? popoverContent.menuBarState : .waiting }

    /// A switch on the card changed. Nothing is applied before Start.
    public func setConsent(_ choices: ConsentChoices) {
        guard consent != nil else { return }
        consent = choices
    }

    /// Start: the agreement kept, each switch applied as set (the notification prompt and the login item only if on),
    /// then everything `begin` starts, the first scan with it. Quit, instead, leaves all as it was.
    public func agree() {
        guard let choices = consent else { return }
        defaults.set(Consent.version, forKey: Consent.key)
        consent = nil
        if settings.notificationsEnabled != choices.notify {
            settings.notificationsEnabled = choices.notify
            storage.save(settings)
        }
        if choices.openAtLogin != launchAtLogin { launchAtLogin = loginItem.set(choices.openAtLogin) }
        begin(checksForUpdates: choices.checkForUpdates)
    }
    public nonisolated static var appVersion: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "" }

    // MARK: What's new

    /// This version's changelog entry, at the top of the panel from the first time it opens after an update until the
    /// person closes it (WhatsNew decides).
    public private(set) var whatsNew: Changelog.Entry?

    /// At launch: show this version's entry if the app was updated to it, and on a first install note the version.
    func checkWhatsNew() {
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
            let fresh = Finding.toNotify(result.findings, after: previous?.findings)
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
        if fixAll?.phase == .running { return fixAll?.currentBatch?.label ?? "Fix all" }
        return runs.values.first?.plan.title
    }

    /// Opens a script in Terminal (tests replace it).
    @ObservationIgnored public var terminal: any TerminalOpener = SystemTerminal()
    /// Starts commands in the app (tests replace it).
    @ObservationIgnored public var launcher: any FixLaunching = FixProcessLauncher()
    @ObservationIgnored public var limits = FixLimits()
    /// The site, for a partial fix's plan and the flaws of what an upgrade together moves (tests replace it).
    @ObservationIgnored public var fixServer: (any FixServer)?
    private var advisor: FixAdvisor { FixAdvisor(tools: tools, server: fixServer) }
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
        // A report an older version made may hold a version or a command no core checked (0.5.1's npm @latest): no Fix
        // button, and no command to copy, until this version's own scan (it starts at launch) has made them again.
        if scannedByOlder {
            fixes[finding.id, default: FixRowState()].availability = .withheld(Self.olderReport)
            fixes[finding.id]?.hold = .blocked
            return
        }
        switch FixPlan.make(for: finding, tools: advisor.tools, home: advisor.home) {
        case let .failure(refusal):
            fixes[finding.id, default: FixRowState()].availability = .withheld(refusal.explanation)
            fixes[finding.id]?.hold = .yours
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
            self.apply(assessment, finding)
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
                self.apply(assessment, finding)
            }
            self?.draining = false
        }
    }

    /// A finding's offer decided: its button, or why there is none and what the header counts it as, or a proposal,
    /// or Terminal only.
    private func apply(_ a: FixAssessment, _ finding: Finding) {
        var s = fixes[finding.id] ?? FixRowState()
        s.proposal = nil
        s.hold = nil
        switch a {
        case let .offer(offer): s.availability = .offered(offer)
        case let .withheld(why): s.availability = .withheld(why); s.hold = Self.hold(finding, why)
        case let .refused(why): s.availability = .withheld(why); s.hold = .blocked
        case let .propose(why, offer): s.availability = .withheld(why); s.proposal = offer; s.hold = .blocked
        case let .terminal(offer, why): s.availability = .terminal(offer, why)
        case .none: s.availability = .withheld(nil); s.hold = .yours
        }
        fixes[finding.id] = s
    }

    /// Why a finding with no button is left, for the header: no fixed release to be had (Homebrew is behind, or the
    /// newest is installed), or it is the person's to decide. (What something installed holds back is `refused`.)
    nonisolated static func hold(_ f: Finding, _ why: String) -> FixRowState.Hold {
        if why.hasPrefix("Homebrew still ships") || why.hasPrefix("Newest version installed") || why.hasPrefix("Homebrew has no newer") { return .noFix }
        return .yours
    }

    /// The button pressed: the review opens, and the tool is asked for a dry run.
    public func beginFix(_ finding: Finding) {
        guard let offer = fixes[finding.id]?.reviewable, fixes[finding.id]?.isBusy == false else { return }
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
        guard !isShowingFixtures, let state = fixes[finding.id], let offer = state.reviewable,
              case let .ready(preview)? = state.preview, preview.blocked == nil, !state.isBusy, busyTitle == nil else { return }
        guard let current = currentPlan(finding, matching: offer) else { return }
        start(current.finding, offer: offer, preview: preview)
    }

    /// Retry: the same command again, after it did not finish, without the review (it was reviewed, and the plan is
    /// still the same one; if anything changed, the review opens instead).
    public func retryFix(_ finding: Finding) {
        guard !isShowingFixtures, let state = fixes[finding.id], let offer = state.offeredFix ?? state.offeredProposal, !state.isBusy,
              busyTitle == nil, state.outcome?.isProblem == true else { return }
        // a pip upgrade is never run again without a fresh dry run: Retry opens its review
        guard offer.plan == lastPlans[finding.id], offer.plan.pip == nil else { beginFix(finding); return }
        guard let current = currentPlan(finding, matching: offer) else { return }
        start(current.finding, plan: current.plan, also: [:], pins: [])
    }

    /// The finding as the report has it now, and its plan made again, if that is still `plan`. Otherwise the row is
    /// assessed afresh and nil returned.
    private func currentPlan(_ finding: Finding, matching offer: FixOffer) -> (finding: Finding, plan: FixPlan)? {
        currentPlan(finding, matching: offer.plan, target: offer.partialTarget)
    }

    private func currentPlan(_ finding: Finding, matching plan: FixPlan, target: CheckedUpgrade? = nil) -> (finding: Finding, plan: FixPlan)? {
        guard let current = report?.findings.first(where: { $0.id == finding.id }),
              case let .success(now) = FixPlan.make(for: current, tools: advisor.tools, home: advisor.home, target: target), now == plan else {
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

    /// Undo, after a pip upgrade broke something: the exact earlier versions put back. After a batch, the same undo
    /// puts back every version the batch changed, so every row that shares it is checked again with it.
    public func undoFix(_ finding: Finding) {
        guard !isShowingFixtures, busyTitle == nil, let state = fixes[finding.id], !state.isBusy, let undo = state.run?.undo,
              let plan = lastPlans[finding.id] else { return }
        launchUndo(undo, lead: (finding, plan), members: sharing(undo, except: finding.id))
    }

    /// The other findings whose last run left this same undo (a batch's), with their plans.
    private func sharing(_ undo: PipUndo, except id: String) -> [(Finding, FixPlan)] {
        let known = (report?.findings ?? []) + resolved
        return fixes.filter { $0.key != id && $0.value.run?.undo == undo && !$0.value.isBusy }.keys.sorted().compactMap { m in
            guard let f = known.first(where: { $0.id == m }), let p = lastPlans[m] else { return nil }
            return (f, p)
        }
    }

    private func launchUndo(_ undo: PipUndo, lead: (Finding, FixPlan), members: [(Finding, FixPlan)], title: String? = nil) {
        launch(lead.0, plan: lead.1, invocation: undo.invocation, doing: "Undoing", command: undo.command, undo: undo, pip: nil,
               members: members, title: title)
    }

    /// A reviewed offer runs: its command with the dry run's pins, or, for an upgrade together, the whole set its dry
    /// run named, pinned, through the set's own gates.
    private func start(_ finding: Finding, offer: FixOffer, preview: FixPreview, members: [(Finding, FixPlan)] = [], title: String? = nil) {
        let plan = currentPlan(finding, matching: offer)?.plan ?? offer.plan
        if case let .together(t)? = offer.proposal, let pip = plan.pip {
            lastPlans[finding.id] = plan
            let invocation = PipSetPreviewer.invocation(python: pip.python, user: pip.user, pins: preview.pins)
            launch(finding, plan: plan, invocation: invocation, doing: "Updating", command: invocation.display,
                   undo: nil, pip: nil, members: members, title: title,
                   pipSet: PipSetRun(python: pip.python, user: pip.user, name: t.package, installs: preview.report))
            return
        }
        start(finding, plan: plan, also: preview.installs, pins: preview.pins, members: members, title: title)
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

    /// Several pip changes run as one: the Python, where, a name for the lines, and exactly what its dry run said each
    /// would be (the new versions' requirements included), for the end-state gate just before it runs.
    struct PipSetRun {
        var python: String
        var user: Bool
        var name: String
        var installs: [PythonDistribution]
        /// For `PipGuard.after`: where it runs and what to call it.
        var pip: FixPlan.Pip { FixPlan.Pip(python: python, requirement: "", user: user, name: name, target: "") }
    }

    /// The run itself: Preparing (for pip, what depends on it is read again, and `pip check` noted), the command, then
    /// Checking again (for pip, `pip check` compared), then the re-check of the finding.
    /// A Fix all step (`title` set) keeps the time its Preparing started, and its rows stay as they are: its own card shows
    /// the run.
    /// `pipSet`: several pip changes as one (a batch, an upgrade together), gated on the end state as a whole. `limits`:
    /// a batch's own (longer, and on past a password prompt). `arguments`: each finding's item in a batch's command, to
    /// tell from the log which item asked for a password.
    private func launch(_ finding: Finding, plan: FixPlan, invocation: FixInvocation, doing: String, command: String, undo: PipUndo?,
                        pip: (FixPlan.Pip, [String: String])?, members: [(Finding, FixPlan)] = [], title: String? = nil,
                        pipSet: PipSetRun? = nil, limits batchLimits: FixLimits? = nil, arguments: [String: String] = [:]) {
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
        let launcher = self.launcher, limits = batchLimits ?? self.limits
        let tools = self.tools
        Task { [weak self] in
            var before: (site: PythonSite, problems: Set<String>)?
            var check: String?
            if let set = pipSet {
                // the end state as a whole, read again now: every requirement still met, no boundary crossed, no project
                // of the person's moved
                switch await PythonSite.read(python: set.python, tools: tools) {
                case let .failure(e):
                    self?.endBeforeRunning(finding, plan: plan, outcome: .blocked("the app could not read what is installed (\(e.message))"))
                    return
                case let .success(site):
                    if let why = PipSetGuard.refusal(site, installs: set.installs) {
                        self?.endBeforeRunning(finding, plan: plan, outcome: .blocked(why))
                        return
                    }
                    let moving = Set(set.installs.map(\.key))
                    if set.installs.contains(where: { d in site.live(d.key).map { PipGuard.beyondPatch(from: $0.version, to: d.version) } ?? false }) {
                        check = PipGuard.usersLine(PipGuard.users(of: moving, in: site, except: moving).map(\.name))
                    }
                    guard let problems = await guardian.problems(set.pip) else {
                        self?.endBeforeRunning(finding, plan: plan, outcome: .blocked("pip check did not answer, so nothing was changed"))
                        return
                    }
                    before = (site, problems)
                }
            }
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
            if let checked = pipSet?.pip ?? pip?.0, let before {
                if case .couldNotStart = ending {} else { after = await guardian.after(checked, before: before.site, problemsBefore: before.problems) }
            }
            // a batch that went on past a password prompt: the prompt was the item its log was on, the others ended by
            // themselves, and the check after says which are fixed
            let asked = ending == .needsPassword && !arguments.isEmpty ? FixBatchLog.askedForPassword(log, items: Array(Set(arguments.values))) : nil
            // each finding the command fixes is checked again, one at a time, and keeps its own outcome and Undo
            for (m, p) in all {
                var end = ending
                if let asked, let item = arguments[m.id], !asked.contains(item) { end = .exited(1) }
                self.ended.append((FixRun(finding: m, plan: p, undo: undo, check: check), .app(end, after)))
            }
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
        guard !isShowingFixtures, busyTitle == nil, let state = fixes[finding.id], !state.isBusy else { return }
        let plan: FixPlan
        if case let .terminal(offer, _)? = state.availability, state.outcome == nil || state.outcome == .needsPassword {
            plan = offer.plan                                  // a cask whose update needs a password: Terminal from the start
        } else if state.outcome == .needsPassword, let last = lastPlans[finding.id] {
            plan = last
        } else {
            return
        }
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
                var made = FixOutcome.make(ending: ending, before: run.finding, recheck: recheck, homebrew: homebrew, broke: after?.broke,
                                           check: run.check)
                // a partial fix that reached its version: partly fixed, with what remains
                if case let .stillAffected(now) = recheck, ending.succeeded, after?.broke == nil, let pip = run.plan.pip,
                   pip.target != run.finding.fixedVersion,
                   PythonSpecifier.same(now.installedVersion, pip.target) {
                    made = .partlyFixed(now: now.installedLabel, remain: now.flawCount)
                }
                outcome = made
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
        let now: Finding? = switch recheck {
        case let .stillAffected(f), let .notChecked(f): f
        default: updated.findings.first { $0.id == id }
        }
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
    // One review, then every fix the rows offer (FixRowState.offeredFix, nothing else decides), one command per tool and
    // place (FixBatchKind), batch after batch: removals, Homebrew's formulae, casks, each Python, npm, the rest. A proposal
    // the person ticked joins its Python's batch. Each batch is its rows' own loop, for several at once: Preparing checks
    // each item again (the finding as the report has it now, its plan made again, its offer decided again: Homebrew asked,
    // a Python's dependents read), then the batch's dry run (pip's with a report of exactly what it would install,
    // brew's own), and for pip the end state as a whole: every installed package's specifiers, extras and markers, the
    // runtime boundaries, no project of the person's moved. Then the one command, pip's checks before and after, the
    // REQUESTED cleanup, and each finding checked again on its own, with its own outcome.
    //
    // A pip batch that breaks what depends on what it changed is put back at once (the exact earlier versions), then its
    // items run one at a time with the single fix's own gates, so the one that breaks it is found and the rest still land;
    // one that breaks it again on its own is put back at once too. Only an undo that does not finish stops Fix all, with
    // its Undo shown. Terminal is never opened while Fix all runs: what needs a password is listed at the end with its
    // button. At the end, the sources the batches changed are read again.

    /// Fix all's review, run or summary, while one is shown.
    public private(set) var fixAll: FixAllState?

    /// What the panel shows of Fix all: the header's count (exactly the rows that offer a fix now), why it waits, the
    /// breakdown of what needs action, and the review, the run or the summary.
    public var fixAllPanel: FixAllPanel {
        let findings = report?.findings ?? []
        let running = fixAll?.phase == .running
        var undo: PipUndo?
        if let broke = fixAll?.broke { undo = broke.batch.findings.lazy.compactMap { self.fixes[$0.id]?.run?.undo }.first }
        return FixAllPanel(count: FixAll.offered(findings, fixes: fixes).count, waitingFor: busyTitle,
                           checking: findings.contains { fixes[$0.id]?.availability == .checking }, batch: fixAll,
                           run: running ? activeFix.flatMap { fixes[$0]?.run } : nil, undo: undo,
                           breakdown: FixAll.breakdown(findings, fixes: fixes)?.line)
    }

    /// The header's Fix all: the review opens. Nothing runs from it.
    public func openFixAll() {
        guard !isShowingFixtures, busyTitle == nil, fixAll?.phase != .running, let report else { return }
        let review = FixAll.review(report.findings, fixes: fixes)
        fixAll = review.batches.isEmpty && review.proposals.isEmpty ? nil : review
    }

    /// The review's Cancel, or the summary's Close.
    public func closeFixAll() {
        guard fixAll?.phase != .running else { return }
        fixAll = nil
    }

    /// A proposal ticked or unticked in the review: it joins its Python's batch, or leaves it.
    public func tickProposal(_ id: String, _ on: Bool) {
        guard let shown = fixAll, shown.phase == .review, shown.proposals.contains(where: { $0.id == id }), let report else { return }
        var ticked = shown.ticked
        if on { ticked.insert(id) } else { ticked.remove(id) }
        fixAll = FixAll.review(report.findings, fixes: fixes, ticked: ticked)
    }

    /// The review's Fix all: it runs only if the review is still what the rows offer now (otherwise the review shows
    /// what is true now, to be confirmed again), and nothing else is running.
    public func runFixAll() {
        guard !isShowingFixtures, let shown = fixAll, shown.phase == .review, busyTitle == nil, let report else { return }
        var now = FixAll.review(report.findings, fixes: fixes, ticked: shown.ticked)
        guard now == shown, !now.batches.isEmpty else { fixAll = now.batches.isEmpty && now.proposals.isEmpty ? nil : now; return }
        now.phase = .running
        fixAll = now
        nextFixAllStep()
    }

    /// Stop: the batch under way ends as its own Stop ends it, and no other starts. A batch that is being put back is
    /// put back first.
    public func stopFixAll() {
        guard fixAll?.phase == .running else { return }
        fixAll?.stopRequested = true
        if let b = fixAll?.currentBatch, let first = b.findings.first(where: { activeMembers.contains($0.id) }) { stopFix(first) }
        nextFixAllStep()
    }

    /// What runs next within a batch after a run of it ended.
    private enum BatchNext { case undo(PipUndo), item(Int) }

    /// The next run, once the last has ended and each of its findings was checked again (never during a scan): within
    /// the current batch (its undo, its next item one at a time), or the next batch, or the end: every batch had its
    /// turn, Stop was pressed, or an undo did not finish.
    private func nextFixAllStep() {
        guard var all = fixAll, all.phase == .running, activeFix == nil, !isRechecking, !isScanning, ended.isEmpty else { return }
        if let i = all.current {
            if all.batches[i].status == .running, let next = afterRun(&all, i) {
                fixAll = all
                switch next {
                case let .undo(undo): runUndo(undo, batch: i)
                case let .item(k): runItem(i, k)
                }
                return
            }
            if all.batches[i].status == .running { all.batches[i].status = .done }
            all.current = nil
        }
        if all.ending == nil, all.stopRequested { all.ending = .stopped }
        guard all.ending == nil, let i = all.batches.firstIndex(where: { $0.status == .waiting }) else {
            for j in all.batches.indices where all.batches[j].status == .waiting { all.batches[j].status = .notRun }
            all.ending = all.ending ?? .finished
            all.phase = .done
            fixAll = all
            if all.changedSomething { scanNow(refresh: Self.sources(all)) }   // what a batch changed beyond its findings
            return
        }
        all.current = i
        all.batches[i].status = .running
        fixAll = all
        runBatch(i)
    }

    /// After a run of batch `i` ended: whether it broke something (then it is put back), whether the undo finished
    /// (then its items one at a time, or Fix all stops there), and the next item one at a time. Nil: the batch is done.
    private func afterRun(_ all: inout FixAllState, _ i: Int) -> BatchNext? {
        let b = all.batches[i]
        func broke(_ ids: [String]) -> String? {
            ids.lazy.compactMap { id -> String? in if case let .broke(w)? = b.outcomes[id] { return w } else { return nil } }.first
        }
        func undo(_ ids: [String]) -> PipUndo? { ids.lazy.compactMap { self.fixes[$0]?.run?.undo }.first }
        func undoFailed(_ ids: [String]) -> Bool { ids.contains { b.outcomes[$0] == .undoFailed } }
        func putBack(_ ids: [String], _ what: String) {
            for id in ids {
                all.batches[i].outcomes[id] = .putBack(what)
                fixes[id]?.progress = .finished(.putBack(what))
                fixes[id]?.run?.undo = nil
            }
        }
        func nextItem(_ k: Int, _ why: String) -> BatchNext? {
            guard k < b.items.count else { return nil }
            if all.stopRequested {                            // the rest of the batch never starts
                for item in b.items[k...] { for f in item.findings where all.batches[i].outcomes[f.id] == nil { all.batches[i].outcomes[f.id] = .stopped(nil) } }
                return nil
            }
            all.batches[i].stage = .oneByOne(next: k, why: why)
            return .item(k)
        }
        let ids = b.members.map(\.id)
        switch b.stage {
        case .together:
            guard let what = broke(ids), let u = undo(ids) else { return nil }
            all.batches[i].stage = .undoing("it broke \(what)")
            return .undo(u)
        case let .undoing(why):
            if undoFailed(ids) {
                all.ending = .broke(batch: i, what: String(why.dropFirst("it broke ".count)))
                return nil
            }
            if b.items.count > 1 { return nextItem(0, why) }
            putBack(ids, String(why.dropFirst("it broke ".count)))
            return nil
        case let .oneByOne(k, why):
            let mine = b.items[k].findings.map(\.id)
            if let what = broke(mine), let u = undo(mine) {
                all.batches[i].stage = .undoingItem(k, what, why: why)
                return .undo(u)
            }
            return nextItem(k + 1, why)
        case let .undoingItem(k, what, why):
            let mine = b.items[k].findings.map(\.id)
            if undoFailed(mine) {
                all.ending = .broke(batch: i, what: what)
                return nil
            }
            putBack(mine, what)
            return nextItem(k + 1, why)
        }
    }

    /// The sources the batches that ran changed: each finding's own, and Homebrew's for what a `brew` command updated.
    static func sources(_ all: FixAllState) -> Set<SourceKind> {
        var kinds = Set<SourceKind>()
        for b in all.batches where b.status == .done {
            kinds.formUnion(b.findings.flatMap(\.origins).map(\.kind))
            if b.plan.toolName == "brew" || kinds.contains(.electron) { kinds.insert(.homebrew) }
        }
        return kinds
    }

    /// A batch's limits: a single item stops at a password prompt as a row's fix does; several go on (brew goes on past
    /// a cask that asked, and the others still update), with more time.
    private func limits(for items: Int) -> FixLimits {
        var l = limits
        if items > 1 {
            l.stopsAtPassword = false
            l.timeout = limits.timeout * Double(min(items, 4))
        }
        return l
    }

    /// One batch. One item (and not an upgrade together) runs exactly as its row's own fix would, through `runItem`.
    /// Several run as one command, after Preparing checks each again and the batch's dry run and gates pass; if the
    /// gates refuse them together, they run one at a time instead.
    private func runBatch(_ i: Int) {
        guard let b = fixAll?.batches[i] else { return }
        let together = b.items.contains { if case .together? = $0.proposal { true } else { false } }
        guard b.items.count > 1 || together else { runItem(i, 0); return }
        let ids = b.findings.map(\.id)
        activeFix = ids[0]
        activeTitle = b.label
        activeMembers = Set(ids)
        stopRequested = false
        for f in b.findings {
            fixes[f.id, default: FixRowState()].preview = nil
            fixes[f.id]?.progress = .running
            fixes[f.id]?.run = FixRunState(doing: "Updating", command: b.command)
        }
        let advisor = self.advisor
        let recheckFirst = fixAll?.changedSomething == true
        Task { [weak self] in
            guard let self else { return }
            var items = b.items
            if recheckFirst { items = await self.recheckBeforeBatch(items) }
            var ready: [FixAllState.Item] = [], dropped: [(Finding, String)] = []
            for item in items where !self.stopRequested {
                let (r, d) = await self.prepare(item, advisor: advisor)
                if let r { ready.append(r) }
                dropped += d
            }
            guard self.activeFix == ids[0] else { return }
            if self.stopRequested { self.endFixAllStep(stopped: true); return }
            // the batch as a whole: its dry run, and for pip the end state's gates
            var pins: [String] = [], set: PipSetRun?, refused: String?, dryRun: FixLog?
            if !ready.isEmpty, case let .pip(python, user) = b.kind {
                switch await self.prepareSet(ready, python: python, user: user, advisor: advisor) {
                case let .success((installs, p)):
                    pins = p
                    set = PipSetRun(python: python, user: user, name: "what it changed", installs: installs)
                case let .failure(why): refused = why.message
                }
            } else if !ready.isEmpty, let dry = b.kind.dryRun(ready.compactMap { FixBatchKind.argument($0.plan) }) {
                dryRun = await self.brewDryRun(dry)
            }
            guard self.activeFix == ids[0] else { return }
            if self.stopRequested { self.endFixAllStep(stopped: true); return }
            for (f, why) in dropped { self.leaveAlone(f, why: why) }
            guard let first = ready.first else {
                self.fixAll?.batches[i].status = .skipped(dropped.first.map { Self.clause($0.1) } ?? "Fixed by an earlier batch")
                self.endFixAllStep(stopped: false)
                return
            }
            let kept = Set(ready.flatMap(\.findings).map(\.id))
            self.fixAll?.batches[i].left += b.members.filter { !kept.contains($0.id) }
            self.fixAll?.batches[i].items = ready
            if let refused {
                // together they would break something (or pip could not say): one at a time, each with its own gates
                if ready.count > 1 {
                    for f in ready.flatMap(\.findings) { self.fixes[f.id]?.progress = nil; self.fixes[f.id]?.run = nil }
                    self.activeFix = nil; self.activeTitle = nil; self.activeMembers = []
                    self.fixAll?.batches[i].stage = .oneByOne(next: 0, why: Self.clause(refused))
                    self.runItem(i, 0)
                } else {
                    for f in first.findings { self.leaveAlone(f, why: refused) }
                    self.fixAll?.batches[i].status = .skipped(Self.clause(refused))
                    self.endFixAllStep(stopped: false)
                }
                return
            }
            self.fixAll?.changedSomething = true
            let members = ready.flatMap { item in zip(item.findings, item.offers).map { ($0.0, $0.1.plan) } }
            for (f, p) in members { self.lastPlans[f.id] = p }
            var arguments: [String: String] = [:]
            for (f, p) in members { arguments[f.id] = FixBatchKind.argument(p) }
            let invocation = b.kind.invocation(ready.compactMap { FixBatchKind.argument($0.plan) }, pins: pins)
            if let dryRun { for f in ready.flatMap(\.findings) { self.fixes[f.id]?.run?.log = dryRun } }
            self.launch(first.findings[0], plan: first.plan, invocation: invocation, doing: "Updating",
                        command: invocation.display, undo: nil, pip: nil,
                        members: Array(members.dropFirst()), title: b.label, pipSet: set, limits: self.limits(for: ready.count),
                        arguments: arguments)
        }
    }

    /// A pip batch's dry run and gates: pip asked for every item at once (its exact pin and what moves with it, or an
    /// upgrade together's own request), with a report of exactly what it would install; each item's version must be
    /// the one reviewed; the end state must hold for everything installed (PipSetGuard); what an upgrade together moves
    /// must bring no new flaw, and its package's version must fix what its fix fixes, as the core judges it. The set,
    /// and every version pinned, the most urgent first.
    private func prepareSet(_ items: [FixAllState.Item], python: String, user: Bool, advisor: FixAdvisor)
        async -> Result<([PythonDistribution], [String]), FixServerError> {
        var requirements: [String] = [], own: [String: String] = [:], first: [String] = [], checkFlaws = Set<String>()
        var env: PythonEnvironment?, together: [FixProposal.Together] = []
        for item in items {
            let offer = item.offers[0]
            if case let .together(t)? = offer.proposal {
                requirements += t.requirements
                first += [t.package] + t.blockers + t.others
                env = env ?? t.python
                together.append(t)
            } else if let pip = offer.plan.pip {
                requirements += [pip.requirement] + offer.companions.filter(FixSafety.isSafeName)
                own[PythonNames.normal(pip.name)] = pip.target
                first.append(pip.name)
            }
        }
        let site: PythonSite
        switch await PythonSite.read(python: python, tools: tools) {
        case let .failure(e): return .failure(FixServerError("the app could not read what is installed (\(e.message))"))
        case let .success(s): site = s
        }
        let installs: [PythonDistribution]
        switch await PipSetPreviewer(tools: tools).dryRun(python: python, user: user, requirements: requirements) {
        case let .failure(e): return .failure(FixServerError(e.message))
        case let .success(i): installs = i
        }
        for (name, target) in own where installs.first(where: { $0.key == name })?.version != target {
            return .failure(FixServerError("pip's dry run would not install \(name) \(target)"))
        }
        if let why = PipSetGuard.refusal(site, installs: installs) { return .failure(FixServerError(why)) }
        if let env {
            for d in installs where own[d.key] == nil { checkFlaws.insert(d.key) }
            guard let server = advisor.server else { return .failure(FixServerError("the app could not ask the site about what the set moves")) }
            switch await PipSetGuard.review(site, installs: installs, only: checkFlaws, together: together, python: env, server: server) {
            case let .failure(e): return .failure(e)
            case let .success(flaw?): return .failure(FixServerError(flaw))
            case .success(nil): break
            }
        }
        let pins = FixAdvisor.ordered(installs, first: first).map { "\($0.name)==\($0.version)" }
        return .success((installs, pins))
    }

    /// brew's own dry run of a batch, as the first lines of its log.
    private func brewDryRun(_ invocation: FixInvocation) async -> FixLog? {
        guard let r = try? await tools.run(invocation.executable, invocation.arguments, extra: ["HOMEBREW_NO_AUTO_UPDATE": "1"], timeout: 60) else { return nil }
        let lines = FixPreviewer.parseBrewDryRun(String(decoding: r.stdout + Data("\n".utf8) + r.stderr, as: UTF8.self))
        return lines.isEmpty ? nil : FixLog(["Dry run:"] + lines)
    }

    /// Each finding of an item as the report has it now, its plan made again; the first one's offer decided again
    /// (Homebrew asked, a Python's dependents read; a proposal asked again), which holds for the others (the same
    /// command). The item as it stands, and the findings no longer valid, each with why.
    private func prepare(_ item: FixAllState.Item, advisor: FixAdvisor) async -> (FixAllState.Item?, [(Finding, String)]) {
        var findings: [Finding] = [], offers: [FixOffer] = [], dropped: [(Finding, String)] = []
        for (f, offer) in zip(item.findings, item.offers) {
            guard let current = report?.findings.first(where: { $0.id == f.id }),
                  case let .success(plan) = FixPlan.make(for: current, tools: advisor.tools, home: advisor.home, target: offer.partialTarget),
                  plan == offer.plan else {
                dropped.append((f, "It changed since the review")); continue
            }
            if !findings.isEmpty { findings.append(current); offers.append(offer); continue }
            let a = await advisor.assess(current)
            switch a {
            case let .offer(now) where offer.proposal == nil && now.plan == plan:
                findings.append(current); offers.append(now)
            case let .propose(_, now) where offer.proposal != nil && now.plan == plan && Self.sameKind(now.proposal, offer.proposal):
                findings.append(current); offers.append(now)
            case let .withheld(why) where offer.proposal == nil, let .refused(why) where offer.proposal == nil,
                 let .propose(why, _) where offer.proposal == nil:
                apply(a, current)
                dropped.append((current, why))
            case let .terminal(_, why):
                apply(a, current)
                dropped.append((current, why))
            case .none: dropped.append((current, "The app no longer offers it"))
            default: dropped.append((current, "It changed since the review"))
            }
        }
        return (findings.isEmpty ? nil : FixAllState.Item(findings: findings, offers: offers), dropped)
    }

    static func sameKind(_ a: FixProposal?, _ b: FixProposal?) -> Bool {
        switch (a, b) {
        case (.partial?, .partial?), (.together?, .together?): return true
        default: return false
        }
    }

    /// One item, exactly as its row's own fix runs: its offer decided again, its dry run, its gates, its command; after
    /// an earlier batch ran, its findings checked again first.
    private func runItem(_ i: Int, _ k: Int) {
        guard let b = fixAll?.batches[i], k < b.items.count else { return }
        let item = b.items[k]
        let first = item.findings[0]
        activeFix = first.id
        activeTitle = item.name
        activeMembers = Set(item.findings.map(\.id))
        stopRequested = false
        for (f, offer) in zip(item.findings, item.offers) {
            fixes[f.id, default: FixRowState()].preview = nil
            fixes[f.id]?.progress = .running
            fixes[f.id]?.run = FixRunState(doing: offer.plan.doing, command: offer.plan.command)
        }
        let advisor = self.advisor
        let recheckFirst = fixAll?.changedSomething == true
        let alone = b.items.count == 1
        Task { [weak self] in
            guard let self else { return }
            var items = [item]
            if recheckFirst { items = await self.recheckBeforeBatch(items) }
            var ready: FixAllState.Item?, dropped: [(Finding, String)] = []
            if let item = items.first, !self.stopRequested { (ready, dropped) = await self.prepare(item, advisor: advisor) }
            guard self.activeFix == first.id else { return }
            if self.stopRequested { self.endFixAllStep(stopped: true); return }
            var preview: FixPreview?
            if let offer = ready?.offers.first {
                let p = await advisor.preview(offer)                                 // the review's own dry run
                if let blocked = p.blocked {
                    dropped += (ready?.findings ?? []).map { ($0, blocked.prefix(1).uppercased() + blocked.dropFirst()) }
                    ready = nil
                } else {
                    preview = p
                }
            }
            guard self.activeFix == first.id else { return }
            if self.stopRequested { self.endFixAllStep(stopped: true); return }
            for (f, why) in dropped { self.leaveAlone(f, why: why) }                 // the rows say why
            guard let ready, let preview else {
                if alone, let i = self.fixAll?.current {
                    let earlier = self.fixAll?.batches[i].outcomes.values.allSatisfy(\.isResolved) == true
                    self.fixAll?.batches[i].status = .skipped(dropped.first.map { Self.clause($0.1) }
                                                              ?? (earlier ? "Fixed by an earlier batch" : "It changed since the review"))
                }
                self.endFixAllStep(stopped: false)
                return
            }
            self.fixAll?.changedSomething = true
            self.start(ready.findings[0], offer: ready.offers[0], preview: preview,
                       members: zip(ready.findings, ready.offers).dropFirst().map { ($0.0, $0.1.plan) }, title: alone ? b.label : item.name)
        }
    }

    /// Puts back what a batch (or one of its items, one at a time) changed: its own undo, every finding it covered
    /// checked again after it.
    private func runUndo(_ undo: PipUndo, batch i: Int) {
        guard let b = fixAll?.batches[i] else { return }
        let ids: [String]
        if case let .undoingItem(k, _, _) = b.stage { ids = b.items[k].findings.map(\.id) } else { ids = b.members.map(\.id) }
        let known = (report?.findings ?? []) + resolved
        let members = ids.compactMap { id -> (Finding, FixPlan)? in
            guard let f = known.first(where: { $0.id == id }) ?? b.findings.first(where: { $0.id == id }), let p = lastPlans[id] else { return nil }
            return (f, p)
        }
        guard let lead = members.first else { endFixAllStep(stopped: false); return }
        launchUndo(undo, lead: lead, members: Array(members.dropFirst()), title: b.label)
    }

    /// A batch ends before its command runs: Stop was pressed while it was preparing (its rows say Stopped, and Retry
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

    /// After an earlier batch ran: each of these items' findings checked again, as after a run (never during a scan).
    /// One that batch fixed or removed is done, its row saying so; one it moved to another version that is still
    /// affected is left to its row, which offers what fits it now. The rest go on to the batch's own checks.
    private func recheckBeforeBatch(_ items: [FixAllState.Item]) async -> [FixAllState.Item] {
        var out: [FixAllState.Item] = []
        for item in items {
            var findings: [Finding] = [], offers: [FixOffer] = []
            for (f, offer) in zip(item.findings, item.offers) {
                while isScanning || isRechecking { try? await Task.sleep(for: .milliseconds(200)) }
                guard !stopRequested, let report else { findings.append(f); offers.append(offer); continue }
                isRechecking = true                            // a scan asked for now waits, as for any re-check
                let (updated, recheck) = await makeScanner().recheck(f, in: report)
                isRechecking = false
                self.report = updated
                storage.save(updated)
                switch recheck {
                case let .fixed(now): settle(f, .fixed(now: now))
                case .removed: settle(f, .removed)
                case let .stillAffected(now) where now.id != f.id:
                    settle(f, .blocked("It changed since the review: now \(now.installedLabel)"), now: now)
                case let .notChecked(now):                  // only reported now: not the batch's to fix
                    settle(f, .notChecked(FixOutcome.found(before: f, after: now)), now: now)
                case .stillAffected, .couldNotCheck: findings.append(f); offers.append(offer)
                }
            }
            if !findings.isEmpty { out.append(FixAllState.Item(findings: findings, offers: offers)) }
        }
        runPendingScan()
        return out
    }

    /// A batch's finding an earlier batch fixed, removed or moved: its row says so, as after its own run.
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
        switch fixes[finding.id]?.availability {
        case .withheld?, .terminal?: decided = true                 // just now, by Preparing
        default: decided = false
        }
        if !decided {
            fixes[finding.id]?.availability = nil
            fixes[finding.id]?.proposal = nil
            if let current = report?.findings.first(where: { $0.id == finding.id }) { assessFix(current) }
        }
        recordFixAll(finding.id, outcome)
    }

    /// "Homebrew still ships 1.30.6; the fix is 1.30.7 upstream." as a clause: "Not run: Homebrew still ships …".
    static func clause(_ s: String) -> String { s.hasSuffix(".") ? String(s.dropLast()) : s }

    /// A batch's finding ended: its outcome kept for the summary (a later run of the same finding, one at a time, or
    /// its undo, replaces it).
    private func recordFixAll(_ id: String, _ outcome: FixOutcome) {
        guard var all = fixAll, all.phase == .running, let i = all.current, all.batches[i].findings.contains(where: { $0.id == id }) else { return }
        all.batches[i].outcomes[id] = outcome
        fixAll = all
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
        launchAtLogin = loginItem.set(on)
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

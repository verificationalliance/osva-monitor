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
    private let limiter = RateLimiter()                  // shared by every scan, so the budget holds across them
    @ObservationIgnored private var timer: Timer?
    @ObservationIgnored private var watcher: FolderWatcher?
    @ObservationIgnored private var pendingRefresh: Set<SourceKind>?
    @ObservationIgnored private var folderDebounce: Task<Void, Never>?

    public init(storage: Storage = Storage(directory: Paths.supportDirectory()), notifier: any Notifier = SystemNotifier()) {
        self.storage = storage
        self.notifier = notifier
        settings = storage.loadSettings()
        report = storage.loadLastReport()
    }

    public var popoverContent: PopoverContent { PopoverContent(report: report, isScanning: isScanning, progress: progress) }

    /// Findings opened when the popover first appears (the capture mode opens one to show the open state).
    public var initiallyExpanded: Set<String> = []

    /// Shows a report without scanning, saving or notifying: the capture mode's fixtures. Nothing is written to disk
    /// and nothing is sent anywhere while it is set.
    public private(set) var isShowingFixtures = false

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
        Task { await notifier.requestPermission() }
        let due = report.map { Date().timeIntervalSince($0.finishedAt) > interval } ?? true
        if due { scanNow() }
    }

    private var interval: TimeInterval { TimeInterval(max(1, settings.scanIntervalHours) * 3600) }

    // MARK: Scanning

    /// Scans now. `refresh` names the sources to look at again (all when nil). A request made during a scan runs
    /// right after it.
    public func scanNow(refresh: Set<SourceKind>? = nil) {
        guard !isShowingFixtures else { return }
        guard !isScanning else {
            pendingRefresh = pendingRefresh.map { p in refresh.map { p.union($0) } ?? Set(SourceKind.allCases) } ?? (refresh ?? Set(SourceKind.allCases))
            return
        }
        isScanning = true
        progress = ""
        let previous = report
        let scanner = Scanner(configuration: ScanConfiguration(storage: storage, folders: settings.watchedFolders.map { URL(fileURLWithPath: $0, isDirectory: true) }),
                              limiter: limiter)
        let report: @Sendable (String) -> Void = { [weak self] message in
            Task { @MainActor in self?.progress = message }
        }
        Task { [weak self] in
            let result = await scanner.scan(previous: previous, refresh: refresh, progress: report)
            self?.finish(result, previous: previous)
        }
    }

    private func finish(_ result: ScanReport, previous: ScanReport?) {
        report = result
        isScanning = false
        progress = ""
        storage.save(result)
        if settings.notificationsEnabled {
            let before = Set(previous?.findings.filter(\.deservesNotification).map(\.notificationKey) ?? [])
            let fresh = result.findings.filter { $0.deservesNotification && !before.contains($0.notificationKey) }
            if !fresh.isEmpty { Task { await notifier.post(fresh) } }
        }
        if let next = pendingRefresh {
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

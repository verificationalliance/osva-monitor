import AppKit
import Observation
import OSVAMonitorUI
import Sparkle

/// The app's own updates, by Sparkle 2: one standard updater controller for the whole run, with its standard windows.
///
/// What is checked and trusted is set in Info.plist (app/Resources/Info.plist): the feed, the update key, a check a
/// day once the person chose it, the zip verified before it is unpacked, and a feed signed with the same key. Sparkle
/// starts only when the app model starts it (AppModel.begin), after Start on the first-launch card; Info.plist turns
/// the daily check off, so Sparkle never checks on its own before the person said it may. Here, what a menu-bar app
/// needs:
///   - it has no window of its own and is not frontmost, so a check the person asks for activates it first, and
///     Sparkle's window comes up in front;
///   - an update a scheduled check finds is not pushed in a window behind whatever the person is doing (Sparkle's
///     gentle reminders): the popover says it is waiting, and the window comes when they click it. Right after launch
///     Sparkle shows it at once, as usual;
///   - only a zipped app is accepted, never an installer package;
///   - the feed is the one in Info.plist and nothing else: not a feed URL in the user defaults (Sparkle's old way to
///     change it), and the test-only override below exists only in builds made with UPDATE_TESTING=1
///     (scripts/build-app.sh).
@MainActor @Observable
final class Updater: NSObject, AppUpdating {
    private(set) var state = UpdateState.none
    @ObservationIgnored private var controller: SPUStandardUpdaterController?
    @ObservationIgnored private var observations: [NSKeyValueObservation] = []

    /// The daily check as the person last set it, which Sparkle keeps in the user defaults; or on, as it was for
    /// everyone who never changed it before 0.5.0, when Info.plist turned it on. Read before Sparkle starts: the
    /// first-launch card shows it.
    var checksDaily: Bool { UserDefaults.standard.object(forKey: Self.automaticChecksKey) as? Bool ?? true }

    /// Sparkle's own key for its daily check (SUEnableAutomaticChecksKey), in the user defaults and in Info.plist.
    static let automaticChecksKey = "SUEnableAutomaticChecks"

    /// Starts Sparkle, checking once a day or not, in the installed app only (under `swift run` there is no
    /// Info.plist to read, and the capture mode must not reach the network).
    func start(checksDaily: Bool) {
        guard controller == nil, AppBundle.isInstalledApp else { return }
        let controller = SPUStandardUpdaterController(startingUpdater: false, updaterDelegate: self, userDriverDelegate: self)
        self.controller = controller
        #if !OSVA_UPDATE_TESTING
        controller.updater.clearFeedURLFromUserDefaults()
        #endif
        controller.updater.automaticallyChecksForUpdates = checksDaily   // before it starts, so no check goes against it
        controller.startUpdater()
        let updater = controller.updater
        // Sparkle changes these on the main thread, but a setting backed by the user defaults may change elsewhere.
        observations = [
            updater.observe(\.canCheckForUpdates) { [weak self] _, _ in Task { @MainActor in self?.refresh() } },
            updater.observe(\.automaticallyChecksForUpdates) { [weak self] _, _ in Task { @MainActor in self?.refresh() } },
            updater.observe(\.lastUpdateCheckDate) { [weak self] _, _ in Task { @MainActor in self?.refresh() } },
        ]
        refresh()
    }

    /// The person's own check: Sparkle's window shows what it finds, or brings a waiting update to the front.
    func checkForUpdates() {
        guard let controller else { return }
        NSApp.activate(ignoringOtherApps: true)            // a menu-bar app is not frontmost by itself
        controller.checkForUpdates(nil)
    }

    func setChecksAutomatically(_ on: Bool) {
        controller?.updater.automaticallyChecksForUpdates = on
        refresh()
    }

    private func refresh(waiting: String?? = .none) {
        guard let updater = controller?.updater else { return }
        state = UpdateState(isAvailable: true, canCheck: updater.canCheckForUpdates,
                            checksAutomatically: updater.automaticallyChecksForUpdates,
                            version: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "",
                            lastChecked: updater.lastUpdateCheckDate,
                            waitingVersion: waiting ?? state.waitingVersion)
    }

    /// Why an update was not taken.
    struct Refused: LocalizedError {
        let errorDescription: String?
    }
}

extension Updater: SPUUpdaterDelegate {
    /// The feed in Info.plist, always: Sparkle would otherwise let a SUFeedURL in the user defaults replace it. In test
    /// builds only, OSVA_UPDATE_FEED points the updater at another feed, such as a local one; the update key and the
    /// signed-feed requirement still apply to it.
    func feedURLString(for updater: SPUUpdater) -> String? {
        #if OSVA_UPDATE_TESTING
        if let feed = ProcessInfo.processInfo.environment["OSVA_UPDATE_FEED"] { return feed }
        #endif
        return Bundle.main.object(forInfoDictionaryKey: "SUFeedURL") as? String
    }

    /// Only a zipped app, over HTTPS: never an installer package, which would run its own scripts as root.
    func updater(_ updater: SPUUpdater, shouldProceedWithUpdate item: SUAppcastItem, updateCheck: SPUUpdateCheck) throws {
        guard !item.isInformationOnlyUpdate else { return }
        guard item.installationType == "application" else {
            throw Refused(errorDescription: "OSVA Monitor installs only a new copy of the app, not an installer package.")
        }
        guard let url = item.fileURL, url.pathExtension.lowercased() == "zip" else {
            throw Refused(errorDescription: "OSVA Monitor installs only a zipped app.")
        }
        #if OSVA_UPDATE_TESTING
        let local = url.host == "127.0.0.1" || url.host == "localhost"
        #else
        let local = false
        #endif
        guard url.scheme?.lowercased() == "https" || local else {
            throw Refused(errorDescription: "OSVA Monitor downloads updates only over HTTPS.")
        }
    }

    func updater(_ updater: SPUUpdater, didFinishUpdateCycleFor updateCheck: SPUUpdateCheck, error: (any Error)?) {
        refresh()
    }
}

extension Updater: @preconcurrency SPUStandardUserDriverDelegate {
    var supportsGentleScheduledUpdateReminders: Bool { true }

    /// Right after launch Sparkle shows a found update itself, in front. Later, the popover says it is waiting.
    func standardUserDriverShouldHandleShowingScheduledUpdate(_ update: SUAppcastItem, andInImmediateFocus immediateFocus: Bool) -> Bool {
        immediateFocus
    }

    func standardUserDriverWillHandleShowingUpdate(_ handleShowingUpdate: Bool, forUpdate update: SUAppcastItem, state: SPUUserUpdateState) {
        if !handleShowingUpdate { refresh(waiting: .some(update.displayVersionString)) }
    }

    func standardUserDriverDidReceiveUserAttention(forUpdate update: SUAppcastItem) {
        refresh(waiting: .some(nil))
    }

    func standardUserDriverWillFinishUpdateSession() {
        refresh(waiting: .some(nil))
    }
}

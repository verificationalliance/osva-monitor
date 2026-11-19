import Foundation
import Testing
import OSVAKit
@testable import OSVAMonitorUI

/// The first-launch card (Consent), through the app's model: before Start nothing reaches the network or the system;
/// Start applies exactly the switches as set, then scans; someone updating from 0.4.0 sees it once, its switches as
/// they had them; once agreed it never shows again; Quit leaves everything as it was. Sparkle, notifications, the
/// login item and the network are stand-ins that record what they are asked; the defaults and the support folder are
/// a Mac's own, made for each test.
@MainActor @Suite(.serialized) struct ConsentTests {
    /// The site: an empty index, and every request recorded.
    final class Net: HTTPTransport, @unchecked Sendable {
        private let lock = NSLock()
        private var paths: [String] = []
        var requests: [String] { lock.withLock { paths } }

        func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
            lock.withLock { paths.append(request.url?.path ?? "") }
            let body = request.url?.path == "/data/app-index.tsv" ? Data("#osva-app-index\t1\t2026-11-19T03:00:00Z\t0\t0\n".utf8) : Data("{}".utf8)
            return (body, HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: [:])!)
        }
    }

    /// macOS's notification centre: how many times permission was asked for.
    final class Notifications: Notifier, @unchecked Sendable {
        private let lock = NSLock()
        private var count = 0
        var asked: Int { lock.withLock { count } }
        var isAvailable: Bool { true }
        func requestPermission() async { lock.withLock { count += 1 } }
        func post(_ findings: [Finding]) async {}
    }

    /// SMAppService: every register (true) and unregister (false).
    final class Login: LoginItemService {
        var isEnabled: Bool
        var sets: [Bool] = []
        init(enabled: Bool) { isEnabled = enabled }
        var isAvailable: Bool { true }
        func set(_ enabled: Bool) -> Bool { sets.append(enabled); isEnabled = enabled; return enabled }
    }

    /// Sparkle: each start, with its daily check; it keeps the choice, as Sparkle keeps it in the user defaults.
    final class Sparkle: AppUpdating {
        var checksDaily: Bool
        var starts: [Bool] = []
        init(checksDaily: Bool) { self.checksDaily = checksDaily }
        func start(checksDaily: Bool) { starts.append(checksDaily); self.checksDaily = checksDaily }
    }

    /// A Mac: empty defaults and support folder (one that never ran the app), a home with no tools, and the stand-ins.
    @MainActor final class Mac {
        let suite = "osva-consent-tests-\(UUID().uuidString)"
        let defaults: UserDefaults
        let folder: URL
        let storage: Storage
        let tools: ToolEnvironment
        let net = Net(), notifications = Notifications()
        let login: Login, sparkle: Sparkle

        init(openAtLogin: Bool = false, checksDaily: Bool = true) {
            defaults = UserDefaults(suiteName: suite)!
            folder = FileManager.default.temporaryDirectory.appendingPathComponent(suite, isDirectory: true)
            storage = Storage(directory: folder.appendingPathComponent("support", isDirectory: true))
            let home = folder.appendingPathComponent("home", isDirectory: true)
            try? FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
            var tools = ToolEnvironment(home: home, base: ["PATH": "/usr/bin:/bin"], runner: ProcessRunner(), isExecutable: { _ in false })
            tools.systemRoot = folder.path
            self.tools = tools
            login = Login(enabled: openAtLogin)
            sparkle = Sparkle(checksDaily: checksDaily)
        }

        /// A launch of the app: the model, started as the app starts it.
        func launch(_ version: String = "0.5.0") -> AppModel {
            let model = AppModel(storage: storage, notifier: notifications, tools: tools, transport: net, defaults: defaults,
                                 version: version, changelog: Changelog(), loginItem: login, updater: sparkle)
            model.start()
            return model
        }

        /// Everything the app keeps: its user defaults and the files in its support folder.
        var kept: (defaults: NSDictionary, files: [String: Data]) {
            let dir = storage.directory
            let names = (FileManager.default.enumerator(atPath: dir.path)?.allObjects as? [String]) ?? []
            let files = Dictionary(uniqueKeysWithValues: names.compactMap { name in
                (try? Data(contentsOf: dir.appendingPathComponent(name))).map { (name, $0) }
            })
            return (NSDictionary(dictionary: defaults.persistentDomain(forName: suite) ?? [:]), files)
        }

        /// What 0.4.0 leaves: its settings, the version of its last scan, and the scan.
        func ranVersion040(notifications: Bool) {
            storage.save(MonitorSettings(notificationsEnabled: notifications))
            storage.save(PreviewData.report())
            defaults.set("0.4.0", forKey: AppModel.scannedByKey)
        }

        deinit {
            UserDefaults().removePersistentDomain(forName: suite)
            try? FileManager.default.removeItem(at: folder)
        }
    }

    /// Nothing asked of the network, Sparkle, notifications or the login item.
    func nothingRan(_ mac: Mac, _ model: AppModel) -> Bool {
        !model.isScanning && mac.net.requests.isEmpty && mac.sparkle.starts.isEmpty && mac.notifications.asked == 0 && mac.login.sets.isEmpty
    }

    /// The scan Start began, to its end, and anything it left to run (the notification request).
    func settle(_ model: AppModel) async throws {
        for _ in 0..<1200 where model.isScanning { try await Task.sleep(for: .milliseconds(50)) }
        #expect(!model.isScanning, "the scan did not end within a minute")
        try await Task.sleep(for: .milliseconds(200))
    }

    @Test func aFreshInstallDoesNothingBeforeStart() async throws {
        let mac = Mac()
        let model = mac.launch()
        #expect(model.consent == .fresh)
        #expect(model.menuBarState == .waiting && MenuBarLabel(.waiting).symbol == "shield")
        try await Task.sleep(for: .milliseconds(300))                  // anything a task would have started
        #expect(nothingRan(mac, model), "requests \(mac.net.requests), Sparkle \(mac.sparkle.starts), notifications \(mac.notifications.asked), login \(mac.login.sets)")
        #expect(model.report == nil)
        #expect(mac.kept.defaults.count == 0 && mac.kept.files.isEmpty)   // not even a settings file
    }

    @Test(arguments: [ConsentChoices(checkForUpdates: true, notify: true, openAtLogin: true),
                      ConsentChoices(checkForUpdates: false, notify: false, openAtLogin: false),
                      ConsentChoices(checkForUpdates: true, notify: false, openAtLogin: true),
                      ConsentChoices(checkForUpdates: false, notify: true, openAtLogin: false)])
    func startAppliesExactlyTheChosenSwitches(_ choices: ConsentChoices) async throws {
        let mac = Mac()
        let model = mac.launch()
        model.setConsent(choices)
        #expect(nothingRan(mac, model))                                 // a switch alone changes nothing
        model.agree()
        #expect(model.consent == nil && model.menuBarState != .waiting)
        #expect(model.isScanning)                                       // the first scan, at once
        try await settle(model)
        #expect(mac.sparkle.starts == [choices.checkForUpdates])
        #expect(mac.notifications.asked == (choices.notify ? 1 : 0))
        #expect(mac.login.sets == (choices.openAtLogin ? [true] : []))
        #expect(model.launchAtLogin == choices.openAtLogin)
        #expect(model.settings.notificationsEnabled == choices.notify && mac.storage.loadSettings().notificationsEnabled == choices.notify)
        #expect(mac.defaults.integer(forKey: Consent.key) == Consent.version)
        #expect(mac.net.requests.contains("/data/app-index.tsv"))
    }

    @Test func anUpgraderSeesItOncePrefilled() async throws {
        let mac = Mac(openAtLogin: true, checksDaily: false)
        mac.ranVersion040(notifications: false)
        let model = mac.launch()
        #expect(model.consent == ConsentChoices(checkForUpdates: false, notify: false, openAtLogin: true))
        #expect(model.menuBarState == .waiting)                         // not the old report's count
        try await Task.sleep(for: .milliseconds(300))
        #expect(nothingRan(mac, model))                                 // their schedule and update checks wait too
        model.agree()
        try await settle(model)
        #expect(mac.sparkle.starts == [false] && mac.notifications.asked == 0 && mac.login.sets.isEmpty)
        let next = mac.launch()
        #expect(next.consent == nil && next.menuBarState != .waiting)
        try await settle(next)
        #expect(mac.sparkle.starts == [false, false] && mac.notifications.asked == 0 && mac.login.sets.isEmpty)
    }

    /// The other way round: someone who had turned on open at login and kept the defaults otherwise sees that, and
    /// turning it off on the card unregisters it.
    @Test func anUpgraderCanTurnOffWhatTheyHad() async throws {
        let mac = Mac(openAtLogin: true, checksDaily: true)
        mac.ranVersion040(notifications: true)
        let model = mac.launch()
        #expect(model.consent == ConsentChoices(checkForUpdates: true, notify: true, openAtLogin: true))
        model.setConsent(ConsentChoices(checkForUpdates: true, notify: true, openAtLogin: false))
        model.agree()
        try await settle(model)
        #expect(mac.login.sets == [false] && !model.launchAtLogin)
        #expect(mac.sparkle.starts == [true] && mac.notifications.asked == 1)
    }

    @Test func afterConsentItNeverShowsAgain() async throws {
        let mac = Mac()
        let first = mac.launch()
        first.agree()
        try await settle(first)
        for version in ["0.5.0", "0.5.1"] {                             // the next launch, and the next update
            let model = mac.launch(version)
            #expect(model.consent == nil && model.menuBarState != .waiting, "\(version)")
            try await settle(model)
        }
        #expect(mac.sparkle.starts == [true, true, true])
        #expect(mac.defaults.integer(forKey: Consent.key) == Consent.version)
    }

    @Test(arguments: [false, true])
    func quitChangesNothing(upgrading: Bool) async throws {
        let mac = Mac()
        if upgrading { mac.ranVersion040(notifications: true) }
        let before = mac.kept
        let model = mac.launch()
        model.setConsent(ConsentChoices(checkForUpdates: false, notify: false, openAtLogin: true))    // switches moved, then Quit
        try await Task.sleep(for: .milliseconds(300))
        #expect(nothingRan(mac, model))
        let after = mac.kept
        #expect(after.defaults == before.defaults && after.files == before.files)
        #expect(mac.launch().consent == (upgrading ? ConsentChoices(checkForUpdates: true, notify: true, openAtLogin: false) : .fresh))  // asks again
    }
}

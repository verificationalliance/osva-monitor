import Foundation
import Testing
import OSVAKit
@testable import OSVAMonitorUI

/// The app's changelog, Resources/CHANGELOG.md: it reads, it has every version newest first, it has the version
/// build-app.sh builds, and each release's notes in docs/release-notes say what its entry says.
@Suite struct ChangelogTests {
    /// The repository: this file is app/Tests/OSVAMonitorUITests/ChangelogTests.swift.
    static let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent()

    static let released = ["0.1.0", "0.2.0", "0.2.1", "0.3.0"]

    @Test func theBundledFileReadsAndHasEveryVersion() throws {
        let changelog = try Changelog.load()                     // the resource itself, not a fallback
        #expect(changelog == Changelog.bundled)
        let versions = changelog.entries.map(\.version)
        #expect(Set(Self.released).isSubset(of: versions), "\(versions)")
        for entry in changelog.entries {
            #expect((1...6).contains(entry.lines.count), "\(entry.version) has \(entry.lines.count) lines")
            for line in entry.lines {
                #expect(!line.isEmpty && line.count <= 120, "\(entry.version): a long line, \(line.count) characters: \(line)")
            }
        }
    }

    @Test func itHasAnEntryForTheVersionBuildAppBuilds() throws {
        let script = try String(contentsOf: Self.repository.appendingPathComponent("scripts/build-app.sh"), encoding: .utf8)
        let match = try #require(script.firstMatch(of: /version="\$\{VERSION:-([0-9]+\.[0-9]+\.[0-9]+)\}"/))
        let version = String(match.1)
        #expect(Changelog.bundled.entry(for: version) != nil, "CHANGELOG.md has no entry for \(version)")
        #expect(Changelog.bundled.entries.first?.version == version, "the newest entry is the version being built")
    }

    /// The notes Sparkle's update window shows are the version's lines from the changelog, word for word.
    @Test func releaseNotesSayWhatTheChangelogSays() throws {
        let folder = Self.repository.appendingPathComponent("docs/release-notes")
        let files = try FileManager.default.contentsOfDirectory(atPath: folder.path).filter { $0.hasSuffix(".md") }
        #expect(files.contains("0.3.0.md") && files.contains("0.3.1.md"), "\(files)")
        for file in files {
            let version = String(file.dropLast(".md".count))
            let entry = try #require(Changelog.bundled.entry(for: version), "\(file) has no entry in CHANGELOG.md")
            let notes = try Changelog.bullets(String(contentsOf: folder.appendingPathComponent(file), encoding: .utf8))
            #expect(notes == entry.lines, "\(file) and CHANGELOG.md's \(version) differ")
        }
    }

    /// Settings lists every version, newest first, whatever order a changelog was put together in.
    @Test func settingsListsEveryVersionNewestFirst() {
        let rows = WhatsNewSection(changelog: .bundled).rows.map(\.version)
        #expect(rows == Changelog.bundled.entries.map(\.version))
        #expect(Set(rows) == Set(Changelog.bundled.entries.map(\.version)) && Set(Self.released).isSubset(of: rows))
        for (newer, older) in zip(rows, rows.dropFirst()) {
            #expect(Changelog.parts(older)!.lexicographicallyPrecedes(Changelog.parts(newer)!), "\(newer) before \(older)")
        }
        let shuffled = Changelog(entries: ["0.2.0", "0.10.0", "0.9.1", "1.0.0"].map { Changelog.Entry(version: $0, lines: ["x"]) })
        #expect(WhatsNewSection(changelog: shuffled).rows.map(\.version) == ["1.0.0", "0.10.0", "0.9.1", "0.2.0"])
    }

    @Test func readsEntriesAndLinesThatGoOn() throws {
        let changelog = try Changelog.parse("""
        # What’s New

        Anything before the first version is for whoever edits the file.
        - even this

        ## 1.10.0

        - One line that goes on
          over the next.
        - Two.

        ## 1.9.2
        - Three.
        """)
        #expect(changelog.entries == [Changelog.Entry(version: "1.10.0", lines: ["One line that goes on over the next.", "Two."]),
                                      Changelog.Entry(version: "1.9.2", lines: ["Three."])])
    }

    @Test(arguments: [
        "## 0.2.0\n- a\n## 0.3.0\n- b",                           // oldest first
        "## 0.2.0\n- a\n## 0.2.0\n- b",                           // twice
        "## 0.2.0\n",                                             // no lines
        "## 0.2\n- a",                                            // not major.minor.patch
        "## v0.2.0\n- a",
        "## 0.2.0\nA paragraph, not a line.",
        "## 0.2.0\n- a\n### More",                                // a heading that is not a version
        "## 0.2.0\n  goes on from nothing",
        "# Only a title",                                          // no entries
    ])
    func refusesAnythingElse(_ text: String) {
        #expect(throws: Changelog.Problem.self) { try Changelog.parse(text) }
    }
}

/// When What's New shows: once after an update, never on a first install, not again once closed.
@Suite struct WhatsNewTests {
    static let changelog = Changelog(entries: [Changelog.Entry(version: "0.3.1", lines: ["a", "b"]),
                                               Changelog.Entry(version: "0.3.0", lines: ["c"])])
    static var newest: Changelog.Entry { changelog.entries[0] }

    @Test func shownAfterAnUpdate() {
        // from 0.3.0 or older, which kept no last-seen version but left a scan behind
        #expect(WhatsNew.decide(current: "0.3.1", lastSeen: nil, ranBefore: true, changelog: Self.changelog) == .show(Self.newest))
        // from a version that kept one
        #expect(WhatsNew.decide(current: "0.3.1", lastSeen: "0.3.0", ranBefore: true, changelog: Self.changelog) == .show(Self.newest))
        #expect(WhatsNew.decide(current: "0.3.1", lastSeen: "0.2.9", ranBefore: false, changelog: Self.changelog) == .show(Self.newest))
    }

    @Test func notShownOnAFirstInstall() {
        #expect(WhatsNew.decide(current: "0.3.1", lastSeen: nil, ranBefore: false, changelog: Self.changelog) == .remember("0.3.1"))
    }

    @Test func notShownForAVersionAlreadySeenOrAfterGoingBack() {
        #expect(WhatsNew.decide(current: "0.3.1", lastSeen: "0.3.1", ranBefore: true, changelog: Self.changelog) == .nothing)
        #expect(WhatsNew.decide(current: "0.3.0", lastSeen: "0.3.1", ranBefore: true, changelog: Self.changelog) == .nothing)
        #expect(WhatsNew.decide(current: "0.10.0", lastSeen: "0.9.0", ranBefore: true, changelog: Changelog(entries: [
            Changelog.Entry(version: "0.10.0", lines: ["x"])])) == .show(Changelog.Entry(version: "0.10.0", lines: ["x"])))
    }

    @Test func nothingToShowWithoutAnEntryOrAVersion() {
        #expect(WhatsNew.decide(current: "0.3.2", lastSeen: "0.3.1", ranBefore: true, changelog: Self.changelog) == .remember("0.3.2"))
        #expect(WhatsNew.decide(current: "", lastSeen: nil, ranBefore: true, changelog: Self.changelog) == .nothing)   // swift run
    }
}

/// The same, through the app's model and real user defaults: the card is shown once after an update, until Close.
@MainActor @Suite(.serialized) struct WhatsNewModelTests {
    struct Silent: Notifier {
        var isAvailable: Bool { false }
        func requestPermission() async {}
        func post(_ findings: [Finding]) async {}
    }

    /// A launch of `version` with these defaults and this support folder.
    func launch(_ version: String, _ defaults: UserDefaults, _ storage: Storage) -> AppModel {
        let model = AppModel(storage: storage, notifier: Silent(), defaults: defaults, version: version, changelog: WhatsNewTests.changelog)
        model.checkWhatsNew()
        return model
    }

    /// Empty defaults and an empty support folder: a Mac that never ran the app. `done` removes both.
    func fresh() -> (UserDefaults, Storage, done: () -> Void) {
        let suite = "osva-whats-new-tests-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(suite, isDirectory: true)
        return (defaults, Storage(directory: folder), {
            defaults.removePersistentDomain(forName: suite)
            try? FileManager.default.removeItem(at: folder)
        })
    }

    @Test func shownOnceAfterAnUpdateAndNotAgainAfterClose() {
        let (defaults, storage, done) = fresh()
        defer { done() }
        defaults.set("0.3.0", forKey: AppModel.scannedByKey)              // what 0.3.0 leaves: the version of its last scan
        let model = launch("0.3.1", defaults, storage)
        #expect(model.whatsNew == WhatsNewTests.newest)
        model.closeWhatsNew()
        #expect(model.whatsNew == nil)
        #expect(defaults.string(forKey: WhatsNew.lastSeenKey) == "0.3.1")
        #expect(launch("0.3.1", defaults, storage).whatsNew == nil)       // the next launch
    }

    @Test func staysUntilClosed() {
        let (defaults, storage, done) = fresh()
        defer { done() }
        storage.save(MonitorSettings())                                    // what any earlier version leaves
        #expect(launch("0.3.1", defaults, storage).whatsNew == WhatsNewTests.newest)
        #expect(launch("0.3.1", defaults, storage).whatsNew == WhatsNewTests.newest)      // not closed: there again
    }

    @Test func notShownOnAFirstInstallButAfterTheNextUpdate() {
        let (defaults, storage, done) = fresh()
        defer { done() }
        #expect(launch("0.3.0", defaults, storage).whatsNew == nil)
        #expect(defaults.string(forKey: WhatsNew.lastSeenKey) == "0.3.0")
        #expect(launch("0.3.1", defaults, storage).whatsNew == WhatsNewTests.newest)
    }
}

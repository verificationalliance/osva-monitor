import Foundation
import Testing
@testable import OSVAKit

/// Who keeps the apps no check covers up to date, told apart so "not checked" lists only the apps nobody looks after.
@Suite struct AppCoverageTests {
    /// A web app as Chromium writes its shim: Cr keys, and a file named by profile and app ID.
    static func shim(_ root: URL, file: String, plist: [String: Any]) -> URL {
        let bundle = root.appendingPathComponent(file + ".app")
        Make.plist(plist, to: bundle.appendingPathComponent("Contents/Info.plist"))
        return bundle
    }

    @Test func webAppsAreNamedByTheirOwnNameNeverTheirID() {
        let root = temporaryDirectory()
        let id = "beimhnaefocolcplfimocfiaiefpkgbf"
        let music = Self.shim(root, file: "Default \(id)", plist: [
            "CFBundleIdentifier": "com.google.Chrome.app.\(id)", "CrAppModeShortcutID": id, "CrBundleIdentifier": "com.google.Chrome",
            "CrAppModeShortcutName": "Default \(id)", "CFBundleName": "YouTube Music", "CFBundleDisplayName": "Profile 1 \(id)",
        ])
        let a = AppSource.read(music)
        #expect(a.keeper == .browser("Chrome") && a.displayName == "YouTube Music" && a.shownName == "YouTube Music")
        // only an ID anywhere: the site it opens
        let bare = Self.shim(root, file: "Default \(id)x", plist: ["CrAppModeShortcutID": id, "CrBundleIdentifier": "com.microsoft.edgemac",
                                                                  "CFBundleName": id, "CrAppModeShortcutURL": "https://www.outlook.office.com/mail/"])
        #expect(AppSource.read(bare).keeper == .browser("Edge") && AppSource.read(bare).shownName == "outlook.office.com")
        // known by its bundle identifier alone
        let brave = Self.shim(root, file: "Brave", plist: ["CFBundleIdentifier": "com.brave.Browser.app.\(id)", "CFBundleName": "Excalidraw"])
        #expect(AppSource.read(brave).keeper == .browser("Brave") && AppSource.read(brave).shownName == "Excalidraw")
        let nothing = Self.shim(root, file: "NoName", plist: ["CrAppModeShortcutID": id])
        #expect(AppSource.read(nothing).shownName == "Unnamed web app")
        // the browser itself is not one of its web apps
        let chrome = Self.shim(root, file: "Google Chrome", plist: ["CFBundleIdentifier": "com.google.Chrome", "CFBundleName": "Google Chrome"])
        #expect(AppSource.read(chrome).keeper == nil)
    }

    @Test func whatAnAppSaysAboutItselfIsNotTakenOnTrust() {
        let root = temporaryDirectory()
        // a receipt file, but no App Store signature
        let fake = Make.app(root, "Fake Store App", id: "com.example.fake", short: "1.0")
        write("not a receipt", to: fake.appendingPathComponent("Contents/_MASReceipt/receipt"))
        #expect(AppSource.read(fake).keeper == nil)
        // an Apple bundle identifier, but not Apple's signature (an Automator applet has one of these)
        let applet = Make.app(root, "S", id: "com.apple.automator.Screen-translation", short: "1.0")
        #expect(AppSource.read(applet).keeper == nil)
        let impostor = Make.app(root, "Safari Updater", id: "com.apple.Safari", short: "1.0")
        #expect(AppSource.read(impostor).keeper == nil)
    }

    @Test func applesOwnAppsAreConfirmedBySignature() throws {
        let calculator = URL(fileURLWithPath: "/System/Applications/Calculator.app")
        try #require(FileManager.default.fileExists(atPath: calculator.path))
        #expect(AppSource.read(calculator).keeper == .macOS)
        #expect(AppKeepers.satisfies(calculator, AppKeepers.appleRequirement))
        #expect(!AppKeepers.satisfies(calculator, "anchor apple generic and certificate leaf[subject.OU] = \"0000000000\""))
        #expect(!AppKeepers.satisfies(temporaryDirectory(), AppKeepers.appleRequirement))
    }

    @Test func bucketsByWhoKeepsThemUpToDate() {
        func app(_ name: String, _ keeper: AppKeeper?, display: String? = nil) -> InstalledApp {
            InstalledApp(name: name, path: "/Applications/\(name).app", bundleID: nil, shortVersion: nil, bundleVersion: nil, caskToken: nil,
                         keeper: keeper, displayName: display)
        }
        let apps = [app("Keynote", .appStore), app("Safari", .macOS), app("Default abc", .browser("Chrome"), display: "Gmail"),
                    app("Profile 1 def", .browser("Edge"), display: "Outlook"), app("BBEdit", nil), app("alfred 5", nil), app("Default xyz", .browser("Chrome"), display: "Calendar")]
        let split = AppCoverage.buckets(apps.map(\.name) + ["Keynote", "Unknown App"], apps: apps)
        #expect(split.notChecked?.source == "Apps with no security record")
        #expect(split.notChecked?.items == ["alfred 5", "BBEdit", "Unknown App"])                   // sorted as people read, the copy once
        #expect(split.notChecked?.paths == ["/Applications/alfred 5.app", "/Applications/BBEdit.app", ""])
        #expect(split.updatedElsewhere.map(\.source) == ["Kept up to date by the App Store", "Kept up to date by macOS", "Chrome web apps", "Edge web apps"])
        #expect(split.updatedElsewhere[2].items == ["Calendar", "Gmail"])
        #expect(split.updatedElsewhere.allSatisfy { $0.items.allSatisfy { !$0.contains("Default") && !$0.contains("Profile") } })
        #expect(AppCoverage.buckets([], apps: apps).notChecked == nil)
    }

    @Test func reportsSavedBeforeAppsWereToldApartStillRead() throws {
        let old = #"{"notInIndex":[{"source":"pip","items":["six 1.15.0"]}],"notChecked":[{"source":"Apps that do not bundle Electron","items":["Xcode"]}]}"#
        let c = try JSONDecoder().decode(Coverage.self, from: Data(old.utf8))
        #expect(c.updatedElsewhere.isEmpty && c.notChecked[0].paths == nil && c.notCheckedCount == 1)
        let again = try JSONDecoder().decode(Coverage.self, from: JSONEncoder().encode(Coverage(updatedElsewhere: [.init(source: "x", items: ["a"], paths: ["/A.app"])])))
        #expect(again.updatedElsewhere[0].paths == ["/A.app"] && again.updatedElsewhereCount == 1)
        #expect(Coverage.Bucket(source: "x", items: ["a", "b"], paths: ["/A.app"]).paths == nil)    // never misaligned
    }

    /// The real /Applications: how long telling apps apart takes, signatures included. Runs with OSVA_PROBE_APPLICATIONS.
    @Test(.enabled(if: ProcessInfo.processInfo.environment["OSVA_PROBE_APPLICATIONS"] != nil))
    func probeKeepersOnThisMac() {
        let roots = ElectronSource.defaultRoots(home: FileManager.default.homeDirectoryForCurrentUser)
        let clock = ContinuousClock()
        var apps: [InstalledApp] = []
        let took = clock.measure { apps = AppSource(roots: roots).collect().apps }
        let kept = Dictionary(grouping: apps.compactMap(\.keeper), by: { "\($0)" }).mapValues(\.count)
        print("PROBE keepers: \(apps.count) apps read in \(took): \(kept)")
    }
}

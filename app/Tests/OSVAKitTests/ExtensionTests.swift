import Foundation
import Testing
@testable import OSVAKit

@Suite struct ExtensionSourceTests {
    @Test func editorExtensionsAndWhatTheyBundle() throws {
        let home = temporaryDirectory()
        let vscode = home.appendingPathComponent(".vscode/extensions")
        let gitlens = Make.editorExtension(vscode, publisher: "eamodio", name: "gitlens", version: "17.2.1", displayName: "%displayName%",
                                           dependencies: [("lodash", "4.17.20"), ("our-private-thing", "1.0.0")])
        write(#"{"displayName": "GitLens — Git supercharged"}"#, to: gitlens.appendingPathComponent("package.nls.json"))
        // nested, scoped, a duplicate, an invalid version, a link that is not followed, and garbage
        Make.json(["name": "@babel/core", "version": "7.24.0"], to: gitlens.appendingPathComponent("node_modules/@babel/core/package.json"))
        Make.json(["name": "minimist", "version": "0.0.8"], to: gitlens.appendingPathComponent("node_modules/lodash/node_modules/minimist/package.json"))
        Make.json(["name": "lodash", "version": "4.17.20"], to: gitlens.appendingPathComponent("node_modules/@babel/core/node_modules/lodash/package.json"))
        Make.json(["name": "bad", "version": "1.0.0\nX-Evil: 1"], to: gitlens.appendingPathComponent("node_modules/bad/package.json"))
        write("{\"name\": \"trunc", to: gitlens.appendingPathComponent("node_modules/truncated/package.json"))
        let outside = temporaryDirectory()
        Make.json(["name": "outside", "version": "1.0.0"], to: outside.appendingPathComponent("package.json"))
        try FileManager.default.createSymbolicLink(at: gitlens.appendingPathComponent("node_modules/linked"), withDestinationURL: outside)
        // an older copy of the same extension, one being removed, and a broken one
        Make.editorExtension(vscode, publisher: "eamodio", name: "gitlens", version: "16.0.0")
        Make.editorExtension(vscode, publisher: "old", name: "gone", version: "1.0.0")
        write(#"{"old.gone-1.0.0": true}"#, to: vscode.appendingPathComponent(".obsolete"))
        write("{\"publisher\": 7, \"name\": [], \"version\": {}}", to: vscode.appendingPathComponent("broken-1/package.json"))
        write("\u{0}\u{1}garbage", to: vscode.appendingPathComponent("garbage-1/package.json"))
        // Cursor installs from Open VSX
        Make.editorExtension(home.appendingPathComponent(".cursor/extensions"), publisher: "ms-python", name: "python", version: "2026.1.0", displayName: "Python")

        let r = ExtensionSource(home: home).collect()
        #expect(r.extensions.map { "\($0.host.title) \($0.id) \($0.version) \($0.name)" } == [
            "Cursor ms-python.python 2026.1.0 Python",
            "VS Code eamodio.gitlens 17.2.1 GitLens — Git supercharged",
        ])
        #expect(r.report == SourceReport(kind: .extensions, available: true, count: 2, detail: "2 extensions in VS Code, Cursor"))
        let deps = r.packages.filter { if case let .addOn(_, id, _, _, _) = $0.origin { return id == "eamodio.gitlens" }; return false }
        #expect(Set(deps.map { "\($0.name)@\($0.version)" }) == ["lodash@4.17.20", "our-private-thing@1.0.0", "@babel/core@7.24.0", "minimist@0.0.8"])
        #expect(deps.allSatisfy { $0.ecosystem == .npm && $0.origin.kind == .extensions })
    }

    @Test func extensionsJSONSaysWhichFoldersAreInstalled() {
        let home = temporaryDirectory()
        let folder = home.appendingPathComponent(".vscode/extensions")
        Make.editorExtension(folder, publisher: "a", name: "kept", version: "1.0.0")
        Make.editorExtension(folder, publisher: "a", name: "leftover", version: "1.0.0")
        Make.json([["identifier": ["id": "a.kept"], "version": "1.0.0", "relativeLocation": "a.kept-1.0.0"]], to: folder.appendingPathComponent("extensions.json"))
        #expect(ExtensionSource(home: home).collect().extensions.map(\.id) == ["a.kept"])
    }

    @Test func packageLimits() {
        let ext = temporaryDirectory()
        for i in 0..<40 { Make.json(["name": "p\(i)", "version": "1.0.\(i)"], to: ext.appendingPathComponent("node_modules/p\(i)/package.json")) }
        var deep = ext
        for d in 0..<8 {
            deep = deep.appendingPathComponent("node_modules/d\(d)")
            Make.json(["name": "d\(d)", "version": "1.0.0"], to: deep.appendingPathComponent("package.json"))
        }
        var limits = ExtensionSource.Limits()
        limits.packagesPerExtension = 10
        var budget = ExtensionSource.Budget(1000)
        let origin = Origin.addOn(host: .vscode, id: "a.b", name: "B", profile: nil, path: ext.path)
        #expect(ExtensionSource.bundledPackages(in: ext, origin: origin, limits: limits, budget: budget).count == 10)
        #expect(budget.remaining == 990)
        limits = ExtensionSource.Limits()
        budget = ExtensionSource.Budget(3)
        #expect(ExtensionSource.bundledPackages(in: ext, origin: origin, limits: limits, budget: budget).count == 3 && budget.remaining == 0)
        let all = ExtensionSource.bundledPackages(in: ext, origin: origin, limits: limits, budget: ExtensionSource.Budget(1000))
        #expect(all.filter { $0.name.hasPrefix("d") }.map(\.name).sorted() == ["d0", "d1", "d2", "d3"])        // four levels deep
        // many extensions read side by side share one budget
        let many = (0..<8).map { InstalledExtension(host: .vscode, id: "a.b\($0)", name: "B", version: "1", profile: nil, path: ext.path) }
        limits.packagesInAll = 25
        #expect(ExtensionSource.bundledPackages(of: many, limits: limits).count == 25)
    }

    @Test func chromiumProfiles() throws {
        let home = temporaryDirectory()
        let chrome = home.appendingPathComponent(ExtensionHost.chrome.folder)
        Make.json(["profile": ["info_cache": ["Profile 1": ["name": "Work"], "Default": ["name": "Personal\u{202E}"]]]], to: chrome.appendingPathComponent("Local State"))
        let id = "abcdefghijklmnopabcdefghijklmnop"
        Make.chromiumExtension(chrome, profile: "Default", id: id, folder: "1.2.3_0", manifest: ["name": "Old", "version": "1.2.3"])
        let newest = Make.chromiumExtension(chrome, profile: "Default", id: id, folder: "1.10.0_0",
                                            manifest: ["name": "__MSG_appName__", "version": "1.10.0", "default_locale": "en"])
        Make.json(["APPNAME": ["message": "Totally Legit Ad Blocker"]], to: newest.appendingPathComponent("_locales/en/messages.json"))
        Make.chromiumExtension(chrome, profile: "Profile 1", id: id, folder: "1.10.0_0", manifest: ["name": "__MSG_missing__", "version": "1.10.0"])
        Make.chromiumExtension(chrome, profile: "Profile 1", id: "not-an-id", folder: "1_0", manifest: ["name": "x", "version": "1"])
        Make.chromiumExtension(chrome, profile: "Profile 1", id: "ponmlkjihgfedcbaponmlkjihgfedcba", folder: "2.0_0", manifest: ["version": 2])
        write("garbage", to: chrome.appendingPathComponent("Profile 1/Extensions/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/1.0_0/manifest.json"))

        let r = ExtensionSource(home: home, hosts: [.chrome]).collect()
        #expect(r.extensions.map { "\($0.profile ?? "") \($0.name) \($0.version)" } == ["Work \(id) 1.10.0", "Personal Totally Legit Ad Blocker 1.10.0"])
        #expect(r.packages.isEmpty)                                     // browser extensions are not walked for packages
        #expect(ExtensionSource.chromiumFolderVersion("1.10.0_12") == "1.10.0" && ExtensionSource.chromiumFolderVersion("1.0") == "1.0")
    }

    @Test func firefoxProfiles() {
        let home = temporaryDirectory()
        let profiles = home.appendingPathComponent(ExtensionHost.firefox.folder)
        Make.json(["addons": [
            ["id": "{8A3F5B2E-1111-4C7A-9E0D-123456789ABC}", "version": "3.1", "type": "extension", "location": "app-profile", "defaultLocale": ["name": "Video Downloader Pro"]],
            ["id": "uBlock0@raymondhill.net", "version": "1.60.0", "type": "extension", "location": "app-profile", "defaultLocale": ["name": "uBlock Origin"]],
            ["id": "formautofill@mozilla.org", "version": "1.0", "type": "extension", "location": "app-builtin"],
            ["id": "firefox-compact-dark@mozilla.org", "version": "1.2", "type": "theme", "location": "app-profile"],
            ["id": 42, "version": "1", "type": "extension"],
        ]], to: profiles.appendingPathComponent("x1y2z3.default-release/extensions.json"))
        write("{\"addons\": [", to: profiles.appendingPathComponent("broken.other/extensions.json"))
        let r = ExtensionSource(home: home, hosts: [.firefox]).collect()
        #expect(r.extensions.map { "\($0.profile ?? "") \($0.name)" } == ["default-release uBlock Origin", "default-release Video Downloader Pro"])
    }

    @Test func noEditorsOrBrowsers() {
        let r = ExtensionSource(home: temporaryDirectory()).collect()
        #expect(r.report == SourceReport(kind: .extensions, available: false, count: 0, detail: "no editors or browsers with extensions"))
    }

    @Test func maliciousIsDecidedPerStoreOnThisMac() {
        let products = Make.index.products
        func ext(_ host: ExtensionHost, _ id: String, profile: String? = nil) -> InstalledExtension {
            InstalledExtension(host: host, id: id, name: "N", version: "1.0", profile: profile, path: "/x/\(host)/\(id)/\(profile ?? "")")
        }
        let installed = [
            ext(.vscode, "evil-pub.prettier-vscode"),                 // listed for the Marketplace: flagged (ID compared without case)
            ext(.cursor, "evil-pub.prettier-vscode"),                 // the same ID on Open VSX is someone else's: not flagged
            ext(.vscode, "ms-python.python"),                         // flagged on Open VSX only: the Marketplace's is Microsoft's
            ext(.vscodium, "MS-Python.python"),
            ext(.chrome, "abcdefghijklmnopabcdefghijklmnop", profile: "Work"),
            ext(.chrome, "abcdefghijklmnopabcdefghijklmnop", profile: "Personal"),
            ext(.brave, "abcdefghijklmnopabcdefghijklmnop", profile: "Default"),
            ext(.firefox, "{8a3f5b2e-1111-4c7a-9e0d-123456789abc}", profile: "default-release"),
            ext(.firefox, "uBlock0@raymondhill.net"),
        ]
        let m = BundleCheck.malicious(installed, in: products)
        #expect(m.map { "\($0.copies[0].host.title): \($0.copies.count)" } == ["VS Code: 1", "VSCodium: 1", "Chrome: 2", "Brave: 1", "Firefox: 1"])
        #expect(BundleCheck.malicious(installed, in: ProductIndex()).isEmpty)
    }
}

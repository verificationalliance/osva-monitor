import Foundation
import Testing
@testable import OSVAKit

@Suite struct BundleFindingTests {
    /// /Applications with: Zoom (a product record, Sparkle 1.24, a cask), Figma (the same Sparkle, no cask), an app
    /// with OpenSSL 3.0.13 as libssl and libcrypto, one with Python 3.11.15, one with a current Qt, and one whose
    /// Sparkle cannot be read.
    static func applications() -> (root: URL, inventory: Inventory) {
        let root = temporaryDirectory()
        let zoom = Make.app(root, "zoom.us", id: "us.zoom.xos", short: "6.6.10 (69071)")
        Make.framework(zoom, "Sparkle", short: "1.24.0", build: "1.24.0")
        let figma = Make.app(root, "Figma", id: "com.figma.Desktop", short: "126.1.4")
        Make.framework(figma, "Sparkle", short: "1.24.0", build: "1.24.0")
        let sink = Make.app(root, "Sink", id: "com.example.sink", short: "1.0")
        Make.bytes(Make.dylib(current: "3.0.0", compatibility: "3.0.0"), to: sink.appendingPathComponent("Contents/Frameworks/libssl.3.dylib"))
        Make.bytes(Make.dylib(current: "3.0.0", compatibility: "3.0.0", strings: ["OpenSSL 3.0.13 30 Jan 2024"]),
                   to: sink.appendingPathComponent("Contents/Frameworks/libcrypto.3.dylib"))
        let py = Make.app(root, "SpotifyNowPlaying", id: "com.example.nowplaying", short: "2.0")
        Make.framework(py, "Python", short: "3.11.15, (c) 2001-2023 Python Software Foundation.", build: "3.11.15")
        let qt = Make.app(root, "QtPass", id: "com.example.qtpass", short: "1.4")
        Make.framework(qt, "QtCore", short: "6.10", build: "6.10.1")
        let broken = Make.app(root, "Unreadable", id: "com.example.unreadable", short: "1.0")
        Make.framework(broken, "Sparkle", short: nil, build: nil)
        let apps = AppSource(roots: [root], caskForApp: ["zoom.us.app": "zoom"]).collect().apps
        return (root, Inventory(apps: apps))
    }

    static let products = ["zoom": Make.product("zoom"), "sparkle": Make.product("sparkle"), "openssl": Make.product("openssl"), "qt": Make.product("qt")]

    @Test func appsAndTheLibrariesTheyBundle() throws {
        let (_, inventory) = Self.applications()
        let check = BundleCheck.match(inventory, index: Make.index)
        // one question per product, however many apps bundle it; a bundled Python is the cpython project
        #expect(PrivacyFilter(index: Make.index).approve(products: check.productKeys).map(\.key) == ["openssl", "qt", "sparkle", "zoom"])
        #expect(check.projectSlugs == ["cpython"])

        let f = FindingOrder.sorted(check.findings(products: Self.products, projects: ["cpython": Make.cpython]))
        #expect(f.map { "\($0.title) · \($0.versionLabel)" } == [
            "Figma · Sparkle 1.24.0 → 2.7.3", "zoom.us · Sparkle 1.24.0 → 2.7.3", "zoom.us · 6.6.10 → 6.6.12",   // Zoom's two together
            "Sink · OpenSSL 3.0.13 → 3.0.18", "SpotifyNowPlaying · Python 3.11.15 → 3.14.11",
        ])
        #expect(f.allSatisfy { $0.group == .likely })                              // the records publish no ranges

        let zoomOwn = try #require(f.first { $0.title == "zoom.us" && $0.component == nil })
        #expect(zoomOwn.severity == .high && zoomOwn.flawCount == 1 && zoomOwn.advisoryIDs == ["ZSB-26031"])
        #expect(zoomOwn.upgradeCommand == "brew upgrade --cask zoom" && zoomOwn.note == "Likely affected: the site publishes no affected ranges, and the issuer names 6.6.12 as fixed.")
        let folder = (try #require(inventory.apps.first { $0.name == "zoom.us" }).path as NSString).deletingLastPathComponent
        #expect(zoomOwn.originSummary == "App in \(Paths.abbreviatingHome(folder)) · Homebrew cask")
        #expect(zoomOwn.pageURL.host == "www.zoom.com" && zoomOwn.pageLabel == "Open the report on www.zoom.com")
        #expect(zoomOwn.subject == .product(key: "zoom", name: "Zoom Workplace"))

        let zoomSparkle = try #require(f.first { $0.title == "zoom.us" && $0.component == "Sparkle" })
        #expect(zoomSparkle.severity == .critical && zoomSparkle.flawCount == 2)
        #expect(zoomSparkle.note == "Likely affected: the site publishes no affected ranges, and the issuer names 2.7.3 as fixed. zoom.us ships its own Sparkle: upgrading the app updates it.")
        let figma = try #require(f.first { $0.title == "Figma" })
        #expect(figma.upgradeCommand == nil)
        #expect(figma.note == "Likely affected: the site publishes no affected ranges, and the issuer names 2.7.3 as fixed. Update Figma from its own menu or its website: it ships its own Sparkle.")

        let python = try #require(f.first { $0.component == "Python" })
        #expect(python.subject == .project(slug: "cpython", name: "CPython", installedAs: "Python.framework"))
        #expect(python.pageURL == SiteURL.projectPage(slug: "cpython") && python.pageLabel == "Open on verificationalliance.org")
        #expect(python.grade == nil && python.verification == .none)              // CPython's grade is not the app's

        // what could not be checked is said
        let unread = check.notChecked(products: Self.products, projects: ["cpython": Make.cpython])
        #expect(unread.map(\.source) == ["Bundled libraries with no readable version"] && unread[0].items == ["Sparkle in Unreadable"])
        #expect(unread[0].paths?.first?.hasSuffix("/Unreadable.app") == true)                      // the app it is in, for its icon
        #expect(check.accountedApps(products: Self.products) == ["zoom.us"])
        // without the product records (offline, or the server has none), nothing is claimed and all of it is listed
        let none = check.notChecked(products: [:], projects: [:])
        #expect(none.first { $0.source == "Bundled libraries with no product record" }?.items
                == ["OpenSSL 3.0.13 in Sink", "Python 3.11.15 in SpotifyNowPlaying", "Qt 6.10.1 in QtPass", "Sparkle 1.24.0 in Figma", "Sparkle 1.24.0 in zoom.us"])
        #expect(check.findings(products: [:], projects: [:]).isEmpty && check.accountedApps(products: [:]).isEmpty)
    }

    @Test func aLibrarysOwnNumberIsComparedOnlyWithFixesNumberedTheSameWay() throws {
        let root = temporaryDirectory()
        let app = Make.app(root, "Cutter", id: "com.example.cutter", short: "1.0")
        Make.bytes(Make.dylib(current: "60.23.100", compatibility: "60.0.0", strings: ["FFmpeg version N-111721-g132a3b7340"]),
                   to: app.appendingPathComponent("Contents/Frameworks/libavcodec.60.dylib"))
        let check = BundleCheck.match(AppSource(roots: [root]).collect().apps.reduce(into: Inventory()) { $0.apps.append($1) }, index: Make.index)
        let found = try #require(check.components.first)
        #expect(found.found.label == "libavcodec" && found.found.version == "60.23.100" && found.found.isLibraryVersion)
        func record(_ fixed: [String]) -> ProductResponse {
            try! JSONDecoder().decode(ProductResponse.self, from: Data(#"{"key":"ffmpeg","recent":[{"id":"CVE-1","sev":"CRITICAL","fixed_hint":\#(fixed)}]}"#.utf8))
        }
        // FFmpeg's releases: 60.23.100 is not comparable with 7.1.1; said, not counted as fine
        let releases = ["ffmpeg": record(["7.1.1", "6.1.3"])]
        #expect(check.findings(products: releases, projects: [:]).isEmpty)
        #expect(check.notChecked(products: releases, projects: [:]).map { "\($0.source): \($0.items)" }
                == ["Bundled libraries numbered unlike their advisories: [\"libavcodec 60.23.100 in Cutter\"]"])
        // a record numbered by libavcodec's own versions is compared
        let own = ["ffmpeg": record(["60.31.102"])]
        #expect(check.findings(products: own, projects: [:]).map(\.versionLabel) == ["libavcodec 60.23.100 → 60.31.102"])
        #expect(check.notChecked(products: own, projects: [:]).isEmpty)
    }

    @Test func anExploitedFlawWithoutRangesMarksTheApp() throws {
        let app = InstalledApp(name: "zoom.us", path: "/nonexistent/zoom.us.app", bundleID: "us.zoom.xos", shortVersion: "6.5.1", bundleVersion: nil, caskToken: nil)
        let check = BundleCheck.match(Inventory(apps: [app]), index: Make.index)
        let f = try #require(check.findings(products: Self.products, projects: [:]).first)
        // the record publishes no ranges: likely, and never counted; how serious it would be, and its mark, stay
        #expect(f.group == .likely && f.exploited && f.severity == .critical && f.fixedVersion == "6.6.12" && f.flawCount == 2)
        #expect(f.notChecked?.exploited == true && f.deservesNotification)
        #expect(f.note == "Likely affected: the site publishes no affected ranges, and the issuer names 6.6.12 as fixed. Update zoom.us from its own menu or its website.")
        // at the fix, nothing
        var fixed = app; fixed.shortVersion = "6.6.12"
        #expect(BundleCheck.match(Inventory(apps: [fixed]), index: Make.index).findings(products: Self.products, projects: [:]).isEmpty)
    }

    /// A product advisory without published ranges is likely affected: never counted, but its critical flaw is marked.
    @Test func aProductAdvisoryWithoutRangesIsLikely() throws {
        let zoom = try JSONDecoder().decode(ProductResponse.self, from: Data(#"""
            {"key":"zoom","name":"Zoom Workplace","recent":[{"id":"ZSB-1","sev":"CRITICAL","fixed_hint":["6.6.12"],"ranges":null}]}
            """#.utf8))
        let app = InstalledApp(name: "zoom.us", path: "/nonexistent/zoom.us.app", bundleID: "us.zoom.xos", shortVersion: "6.6.10", bundleVersion: nil, caskToken: nil)
        let f = try #require(BundleCheck.match(Inventory(apps: [app]), index: Make.index).findings(products: ["zoom": zoom], projects: [:]).first)
        #expect(f.group == .likely && !f.group.needsAction && f.fixedVersion == "6.6.12" && f.severity == .critical)
        #expect(f.notChecked == Finding.NotChecked(id: "ZSB-1", exploited: false, critical: true))
        #expect(f.note == "Likely affected: the site publishes no affected ranges, and the issuer names 6.6.12 as fixed. "
                + "Update zoom.us from its own menu or its website.")
    }

    @Test func maliciousExtensionsComeFirstWithTheirRemoval() throws {
        let installed = [
            InstalledExtension(host: .vscode, id: "Evil-Pub.Prettier-VSCode", name: "Prettier", version: "11.0.3", profile: nil, path: "/u/.vscode/extensions/p"),
            InstalledExtension(host: .chrome, id: "abcdefghijklmnopabcdefghijklmnop", name: "Ad Blocker", version: "1.10.0", profile: "Work", path: "/u/c/Work/e"),
            InstalledExtension(host: .chrome, id: "abcdefghijklmnopabcdefghijklmnop", name: "Ad Blocker", version: "1.10.0", profile: "Personal", path: "/u/c/Personal/e"),
            InstalledExtension(host: .firefox, id: "{8A3F5B2E-1111-4C7A-9E0D-123456789ABC}", name: "Video Downloader Pro", version: "3.1",
                               profile: "default-release", path: "/u/ff/x.default-release"),
        ]
        let apps = Self.applications().inventory.apps
        let check = BundleCheck.match(Inventory(apps: apps, extensions: installed), index: Make.index)
        let f = FindingOrder.sorted(check.findings(products: Self.products, projects: [:]))
        #expect(f.prefix(3).map(\.title) == ["Ad Blocker", "Prettier", "Video Downloader Pro"])
        #expect(f.prefix(3).allSatisfy { $0.group == .malicious && $0.malicious && $0.isExtension && $0.severity == nil })

        let editor = f[1]
        #expect(editor.upgradeCommand == "code --uninstall-extension Evil-Pub.Prettier-VSCode")
        #expect(editor.note == "Flagged by the Visual Studio Marketplace: malware: sends SSH keys and tokens to a remote host. Remove it, then rotate every secret it could read.")
        #expect(editor.originSummary == "VS Code extension · Evil-Pub.Prettier-VSCode" && editor.versionLabel == "11.0.3")
        #expect(editor.pageLabel == "Open the report on example.org")

        let chrome = f[0]
        #expect(chrome.upgradeCommand == nil && chrome.origins.count == 2)
        #expect(chrome.note == "Flagged by the Chrome Web Store: removed by the store: malware. Remove it in Chrome: open chrome://extensions, "
                + "in each of the profiles “Work”, “Personal”, find Ad Blocker, and click Remove. Its ID is abcdefghijklmnopabcdefghijklmnop. "
                + "Then rotate every secret it could read.")
        #expect(chrome.originSummary == "Chrome extension · Work, Personal")

        let firefox = f[2]
        #expect(firefox.note?.contains("open about:addons, in the profile “default-release”") == true)
        #expect(firefox.pageURL == SiteURL.home)                                  // its report link was not https
    }

    @Test func commandsAndQuoting() {
        func advice(_ o: Origin, component: String? = nil, malicious: Bool = false) -> UpgradeCommand.Advice {
            BundleAdvice.advice(for: o, component: component, malicious: malicious)
        }
        #expect(advice(.application(name: "Zoom", bundlePath: "/Applications/zoom.us.app", caskToken: "zoom")).command == "brew upgrade --cask zoom")
        #expect(advice(.application(name: "X", bundlePath: "/A/X.app", caskToken: "x; rm -rf ~")).command == "brew upgrade --cask 'x; rm -rf ~'")
        #expect(advice(.application(name: "X", bundlePath: "/A/X.app", caskToken: "-x")).command == "brew upgrade --cask '-x'")
        #expect(advice(.application(name: "Figma", bundlePath: "/A/Figma.app", caskToken: nil)).command == nil)
        for host in ExtensionHost.allCases where host.isEditor {
            let a = advice(.addOn(host: host, id: "evil$(curl x).y", name: "Y", profile: nil, path: "/p"), malicious: true)
            #expect(a.command == "\(host.cli!) --uninstall-extension 'evil$(curl x).y'")
        }
        #expect(ExtensionHost.allCases.filter(\.isEditor).map { $0.cli! } == ["code", "code-insiders", "cursor", "codium", "windsurf"])
        for host in ExtensionHost.allCases where !host.isEditor {
            let a = advice(.addOn(host: host, id: "x", name: "X", profile: "Default", path: "/p"), malicious: true)
            #expect(a.command == nil && a.note?.contains(host.extensionsPage!) == true)
        }
        // a package an extension bundles: updating the extension is the fix; malicious: remove the extension
        let ext = Origin.addOn(host: .vscode, id: "eamodio.gitlens", name: "GitLens", profile: nil, path: "/p")
        #expect(UpgradeCommand.advice(for: ext, name: "lodash", ecosystem: .npm, target: Fixture.fix("4.17.21"), malicious: false)
                == .init(command: nil, note: "Update GitLens in VS Code: it ships its own lodash."))
        #expect(UpgradeCommand.command(for: ext, name: "axios", ecosystem: .npm, fixed: nil, malicious: true) == "code --uninstall-extension eamodio.gitlens")
        // nothing here downloads an installer
        for c in [advice(.application(name: "A", bundlePath: "/A.app", caskToken: "a")).command] { #expect(c?.contains("curl") != true && c?.contains("install ") != true) }
    }

    @Test func eachExtensionThatBundlesAPackageIsItsOwnFinding() throws {
        let batch = try JSONDecoder().decode(BatchResponse.self, from: Fixture.data("api/check-batch-plan.json"))
        func ext(_ id: String, _ name: String) -> Origin { .addOn(host: .vscode, id: id, name: name, profile: nil, path: "/u/.vscode/extensions/\(id)") }
        let installed = [
            InstalledPackage(ecosystem: .npm, name: "lodash", version: "4.17.20", origin: ext("eamodio.gitlens", "GitLens")),
            InstalledPackage(ecosystem: .npm, name: "lodash", version: "4.17.20", origin: ext("a.other", "Other")),
            InstalledPackage(ecosystem: .npm, name: "axios", version: "1.14.1", origin: ext("eamodio.gitlens", "GitLens")),
        ]
        let selection = PrivacyFilter(index: Fixture.index).approve(installed)
        #expect(selection.approved.count == 2 && selection.approved.keys.allSatisfy { $0.platform == "macos" })   // one question per version
        let verdicts = Dictionary(uniqueKeysWithValues: selection.approved.keys.compactMap { a in batch.packages.first { $0.name == a.name }.map { (a, $0) } })
        let f = FindingOrder.sorted(FindingBuilder(index: Fixture.index).findings(approved: selection.approved, verdicts: verdicts, brew: [], projects: [:], bigIssues: []))
        #expect(f.map { "\($0.title) · \($0.versionLabel) · \($0.group)" } == ["GitLens · axios 1.14.1 · malicious",
                                                                                "GitLens · lodash 4.17.20 → 4.17.21 · criticalHigh",
                                                                                "Other · lodash 4.17.20 → 4.17.21 · criticalHigh"])
        #expect(f[0].upgradeCommand == "code --uninstall-extension eamodio.gitlens" && f[0].note == "Remove it, then rotate every secret it could read.")
        #expect(f[1].upgradeCommand == nil && f[1].note == "Update GitLens in VS Code: it ships its own lodash.")
        #expect(f[1].originSummary == "VS Code extension · eamodio.gitlens")
    }

    @Test func orderKeepsEachAppTogetherWhereItsWorstFindingIs() {
        func finding(_ id: String, _ title: String, _ s: Severity, app: String?) -> Finding {
            Finding(id: id, group: .criticalHigh, subject: .product(key: id, name: id), title: title, installedVersion: "1", fixedVersion: "2",
                    severity: s, advisoryIDs: [], flawCount: 1, exploited: false, malicious: false, note: nil, bigIssue: nil,
                    origins: app.map { [.application(name: title, bundlePath: $0, caskToken: nil)] } ?? [.homebrewFormula(name: title)],
                    pageURL: SiteURL.home, upgradeCommand: nil, verification: .none, grade: nil)
        }
        let f = FindingOrder.sorted([
            finding("a1", "Zoom", .high, app: "/A/zoom.us.app"), finding("b", "curl", .critical, app: nil),
            finding("a2", "Zoom", .critical, app: "/A/zoom.us.app"), finding("c", "Alpha", .high, app: "/A/Alpha.app"),
        ])
        #expect(f.map(\.id) == ["b", "a2", "a1", "c"])
    }
}

@Suite struct BundleScanTests {
    /// A whole scan of apps and extensions against recorded answers.
    @Test func endToEnd() async throws {
        let home = temporaryDirectory()
        let applications = home.appendingPathComponent("Applications")
        let zoom = Make.app(applications, "zoom.us", id: "us.zoom.xos", short: "6.6.10 (69071)")
        Make.framework(zoom, "Sparkle", short: "1.24.0", build: "1.24.0")
        Make.framework(zoom, "Python", short: "3.11.15", build: "3.11.15")
        Make.app(applications, "Secret Internal Tool", id: "com.secret.internal", short: "0.9")
        let vscode = home.appendingPathComponent(".vscode/extensions")
        Make.editorExtension(vscode, publisher: "Evil-Pub", name: "Prettier-VSCode", version: "11.0.3", displayName: "Prettier",
                             dependencies: [("lodash", "4.17.20"), ("our-internal-ui", "3.0.0")])
        Make.editorExtension(vscode, publisher: "eamodio", name: "gitlens", version: "17.2.1", displayName: "GitLens", dependencies: [("axios", "1.14.1")])
        Make.chromiumExtension(home.appendingPathComponent(ExtensionHost.chrome.folder), profile: "Default", id: "abcdefghijklmnopabcdefghijklmnop",
                               folder: "1.0_0", manifest: ["name": "Ad Blocker", "version": "1.0"])
        let tools = ToolEnvironment.fixture(home: home)
        let transport = RecordedTransport.bundleSite()
        let scanner = Scanner(configuration: ScanConfiguration(storage: Storage(directory: home.appendingPathComponent("support")), tools: tools,
                                                               folders: [], applicationRoots: [applications]),
                              transport: transport, pause: { _ in })
        let report = await scanner.scan()

        #expect(report.problems.isEmpty, "\(report.problems)")
        #expect(report.findings.map { "\($0.group) · \($0.title) · \($0.versionLabel)" } == [
            "malicious · Ad Blocker · 1.0",
            "malicious · GitLens · axios 1.14.1",
            "malicious · Prettier · 11.0.3",
            "likely · zoom.us · Sparkle 1.24.0 → 2.7.3",                          // the records publish no ranges
            "likely · zoom.us · Python 3.11.15 → 3.14.11",
            "likely · zoom.us · 6.6.10 → 6.6.12",
            "reported · Prettier · lodash 4.17.20",                                // 0.5.1's answer lists no flaws: not checked
        ])
        #expect(report.inventory.reports.map(\.detail).contains("2 apps"))
        #expect(report.inventory.reports.map(\.detail).contains("3 extensions in VS Code, Chrome"))

        // What left the Mac: index names only. No bundle ID, path, extension ID, private package or app name.
        #expect(report.sent.distinctItems == ["npm axios 1.14.1 · macOS", "npm lodash 4.17.20 · macOS", "project cpython", "product sparkle", "product zoom"])
        for r in transport.requests {
            let wire = (r.url?.absoluteString ?? "") + String(decoding: r.httpBody ?? Data(), as: UTF8.self)
            for secret in ["us.zoom.xos", "zoom.us", "com.secret", "Secret", "evil", "Evil", "prettier", "Prettier", "gitlens", "abcdefghijklmnop",
                           "our-internal-ui", "Sparkle.framework", home.path] {
                #expect(!wire.contains(secret), "\(secret) left the Mac in \(wire)")
            }
        }
        // and what was not vouched for is said
        #expect(report.coverage.notChecked.first { $0.source == AppCoverage.noRecord }?.items == ["Secret Internal Tool"])
        #expect(report.coverage.notInIndex.contains(Coverage.Bucket(source: "Extensions", items: ["our-internal-ui 3.0.0"])))

        // A second scan right away answers from the cache and sends nothing new.
        let before = transport.requests.count
        let again = await scanner.scan(previous: report)
        #expect(again.findings.map(\.id) == report.findings.map(\.id))
        #expect(again.sent.requests.isEmpty && transport.requests.count == before)
    }

    @Test func aProductTheServerDoesNotKnowIsNotChecked() async throws {
        let home = temporaryDirectory()
        let applications = home.appendingPathComponent("Applications")
        Make.app(applications, "Slack", id: "com.tinyspeck.slackmacgap", short: "4.53.292")       // an A line, but no record (404)
        let tools = ToolEnvironment.fixture(home: home)
        let transport = RecordedTransport.bundleSite()
        let scanner = Scanner(configuration: ScanConfiguration(storage: Storage(directory: home.appendingPathComponent("support")), tools: tools,
                                                               folders: [], applicationRoots: [applications]),
                              transport: transport, pause: { _ in })
        let report = await scanner.scan()
        #expect(report.problems.isEmpty && report.findings.isEmpty)
        #expect(report.coverage.notChecked.first { $0.source == AppCoverage.noRecord }?.items == ["Slack"])
        _ = await scanner.scan(previous: report)
        #expect(transport.requests.filter { $0.url!.path.hasPrefix("/api/v1/product/") }.count == 1)    // the "no record" is remembered
    }

    /// Reads this Mac's real /Applications and extensions with realistic index lines, and prints what it finds and how
    /// long it takes. Runs only when OSVA_PROBE_APPLICATIONS is set (it depends on what is installed).
    @Test(.enabled(if: ProcessInfo.processInfo.environment["OSVA_PROBE_APPLICATIONS"] != nil))
    func probeThisMac() throws {
        let extra = """
        A\tcom.google.Chrome\tgoogle-chrome\tGoogle Chrome
        A\torg.mozilla.firefox\tfirefox\tFirefox
        A\tcom.microsoft.VSCode\tvscode\tVisual Studio Code
        A\tcom.spotify.client\tspotify\tSpotify
        A\tcom.docker.docker\tdocker-desktop\tDocker Desktop
        A\torg.whispersystems.signal-desktop\tsignal\tSignal
        A\tru.keepcoder.Telegram\ttelegram\tTelegram
        A\torg.videolan.vlc\tvlc\tVLC
        C\tdylib\tlibavutil\tffmpeg\tFFmpeg
        C\tdylib\tlibcurl\tcurl\tcurl
        C\tdylib\tlibxml2\tlibxml2\tlibxml2
        C\tdylib\tlibsqlite\tsqlite\tSQLite

        """
        let index = try PublicIndex.decode(Make.indexData + Data(extra.utf8))
        let home = FileManager.default.homeDirectoryForCurrentUser
        let roots = ElectronSource.defaultRoots(home: home)
        let clock = ContinuousClock()
        var apps: (apps: [InstalledApp], report: SourceReport)!
        let tApps = clock.measure { apps = AppSource(roots: roots).collect() }
        let tElectron = clock.measure { _ = ElectronSource(roots: roots).collect() }
        var check: BundleCheck!
        let tMatch = clock.measure { check = BundleCheck.match(Inventory(apps: apps.apps), index: index) }
        // OSVA_PROBE_HOME: another home folder for the extensions; OSVA_PROBE_INDEX: a downloaded app-index.tsv for the
        // privacy filter's cost over the packages extensions bundle (nothing is sent from here).
        let env = ProcessInfo.processInfo.environment
        let extHome = env["OSVA_PROBE_HOME"].map { URL(fileURLWithPath: $0, isDirectory: true) } ?? home
        var ext: (extensions: [InstalledExtension], packages: [InstalledPackage], report: SourceReport)!
        let tExt = clock.measure { ext = ExtensionSource(home: extHome).collect() }
        for a in apps.apps where a.bundleID?.hasPrefix("com.apple.") == true || a.keeper != nil { print("PROBE keeper \(a.name) \(a.bundleID ?? "-") \(String(describing: a.keeper))") }
        let electron = ElectronSource(roots: roots).collect()
        print("PROBE other apps \(electron.otherApps.count), Safari among them: \(electron.otherApps.contains("Safari"))")
        let split = AppCoverage.buckets(electron.otherApps, apps: apps.apps)
        for b in [split.notChecked].compactMap({ $0 }) + split.updatedElsewhere {
            print("PROBE bucket \(b.source): \(b.items.count) · \(b.items.joined(separator: " | "))")
        }
        print("PROBE apps: \(apps.apps.count) in \(tApps); electron pass \(tElectron); match + components: \(tMatch); extensions: \(ext.extensions.count) (\(ext.packages.count) packages) in \(tExt) · \(ext.report.detail)")
        var lines = ""
        for i in 0..<5000 { lines += "M\tchrome\t\(String(repeating: "abcdefghijklmnop", count: 2).shuffled().prefix(32).map(String.init).joined())\tmalware \(i)\t\n" }
        for i in 0..<5000 { lines += "M\tvscode\tpub\(i).ext\(i)x\tmalware\t\n" }
        let big = try PublicIndex.decode(Make.indexData + Data(lines.utf8))
        var hits = 0
        let tMalicious = clock.measure { hits = BundleCheck.malicious(ext.extensions, in: big.products).count }
        print("PROBE malicious check of \(ext.extensions.count) extensions against \(big.products.malicious.count) M lines: \(tMalicious), \(hits) hits")
        if let path = env["OSVA_PROBE_INDEX"] {
            var real: PublicIndex!
            let tDecode = clock.measure { real = try! PublicIndex.decode(Data(contentsOf: URL(fileURLWithPath: path))) }
            var approved = 0
            let tFilter = clock.measure { approved = PrivacyFilter(index: real).approve(ext.packages).approved.count }
            print("PROBE real index: \(real.packageCount) packages, decoded in \(tDecode); privacy filter over \(ext.packages.count) bundled packages: \(tFilter), \(approved) approved")
        }
        for m in check.apps { print("PROBE app  \(m.app.name)  \(m.record.product)  \(m.version ?? "?")") }
        for c in check.components { print("PROBE comp \(c.app.name)  \(c.found.label) \(c.found.version ?? "?")  \(c.found.path)") }
        let f = FindingOrder.sorted(check.findings(products: BundleFindingTests.products, projects: ["cpython": Make.cpython]))
        for x in f { print("PROBE find \(x.group) · \(x.title) · \(x.versionLabel) · \(x.originSummary) · \(x.upgradeCommand ?? "-") · \(x.note ?? "")") }
        for b in check.notChecked(products: BundleFindingTests.products, projects: ["cpython": Make.cpython]) { print("PROBE not checked \(b.source): \(b.items.count) e.g. \(b.items.prefix(6))") }
    }
}

extension Finding {
    /// The version line as the row shows it.
    var versionLabel: String { (component.map { "\($0) " } ?? "") + installedVersion + (malicious ? "" : fixedVersion.map { " → \($0)" } ?? "") }
}

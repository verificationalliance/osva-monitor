import Foundation
import OSVAKit

/// Fixture data for SwiftUI previews and `osva-render`: a Mac like the one the app was tried on, with one finding of
/// every kind the popover distinguishes.
public enum PreviewData {
    public static let now = Date(timeIntervalSince1970: 1_795_575_000)      // 19 Nov 2026, 02:10 UTC

    static func finding(_ id: String, _ group: Finding.Group, _ subject: Finding.Subject, _ title: String, component: String? = nil,
                        _ installed: String, _ fixed: String?, _ severity: Severity?, flaws: Int, exploited: Bool = false,
                        malicious: Bool = false, note: String? = nil, bigIssue: String? = nil, origins: [Origin], page: URL,
                        command: String?, mark: Verification = .none, grade: String? = nil, fixes: Int? = nil,
                        unresolved: [UnresolvedFlaw] = []) -> Finding {
        Finding(id: id, group: group, subject: subject, title: title, component: component, installedVersion: installed, fixedVersion: fixed,
                severity: severity, advisoryIDs: [], flawCount: flaws, exploited: exploited, malicious: malicious, note: note,
                bigIssue: bigIssue, origins: origins, pageURL: page, upgradeCommand: command, verification: mark, grade: grade,
                fixesCount: fixes, unresolved: unresolved)
    }

    public static let applePython = PythonEnvironment(executable: "/usr/bin/python3", version: "3.9.6", kind: .apple, externallyManaged: false,
                                                      userSite: NSHomeDirectory() + "/Library/Python/3.9/lib/python/site-packages", formula: nil)
    public static let homebrewPython = PythonEnvironment(executable: "/opt/homebrew/bin/python3", version: "3.15.2", kind: .homebrew, externallyManaged: true,
                                                         userSite: NSHomeDirectory() + "/Library/Python/3.15/lib/python/site-packages", formula: "python@3.15")
    static let managedNote = "Homebrew Python 3.15.2 is externally managed (PEP 668): pip will not change it. "
        + "Install what you need in a virtual environment (python3 -m venv), or a command-line tool with pipx."

    public static let coverage = Coverage(
        notInIndex: [.init(source: "pip", items: ["annotated-types 0.8.0", "altgraph 0.17.2", "macholib 1.15.2", "mlx 0.32.4"]),
                     .init(source: "RubyGems", items: ["CFPropertyList 2.3.6", "did_you_mean 1.3.0", "minitest 5.11.3"]),
                     .init(source: "Folders", items: ["@next/env 14.0.0", "accepts 1.3.8", "express 4.18.2"])],
        notChecked: [.init(source: "Homebrew packages with no graded project", items: ["abseil 20260817.0", "ack 3.10.0", "aom 3.15.3", "slack 4.51.180"]),
                     .init(source: "Apps that do not bundle Electron", items: ["Firefox", "Google Chrome", "iTerm", "Xcode"])])

    public static let findings: [Finding] = {
        let home = NSHomeDirectory()
        let likely = { (v: String) in "Likely affected: the issuer names \(v) as fixed." }
        return [
            finding("pkg|npm|axios|1.14.1", .malicious, .package(ecosystem: .npm, name: "axios"), "axios", "1.14.1", nil, nil, flaws: 34,
                    malicious: true, note: "Remove it, then rotate every secret it could read.",
                    origins: [.folder(root: home + "/code/storefront", lockfile: home + "/code/storefront/package-lock.json", direct: true)],
                    page: SiteURL.packagePage(.npm, "axios", version: "1.14.1"), command: "cd ~/code/storefront && npm uninstall axios"),
            finding("brew|openssh|10.6p1", .exploited, .project(slug: "openssh", name: "OpenSSH", installedAs: "openssh"), "OpenSSH",
                    "10.6p1", "10.6p2", .high, flaws: 1, exploited: true, note: likely("10.6p2"),
                    bigIssue: "On the site's “patch these first” list", origins: [.homebrewFormula(name: "openssh")],
                    page: SiteURL.projectPage(slug: "openssh"), command: "brew upgrade openssh", mark: .parts, grade: "U"),
            finding("app|/Applications/OpenMTP.app|18.3.15", .exploited, .package(ecosystem: .npm, name: "electron"), "OpenMTP", component: "Electron",
                    "18.3.15", "42.11.16", .high, flaws: 50, exploited: true,
                    origins: [.electronApp(name: "OpenMTP", bundlePath: "/Applications/OpenMTP.app", caskToken: "openmtp")],
                    page: SiteURL.packagePage(.npm, "electron", version: "18.3.15"), command: "brew upgrade --cask openmtp"),
            finding("brew|nginx|1.30.2", .criticalHigh, .project(slug: "nginx", name: "nginx", installedAs: "nginx"), "nginx",
                    "1.30.2", "1.30.7", .critical, flaws: 6, note: likely("1.30.7"), bigIssue: "On the site's “patch these first” list",
                    origins: [.homebrewFormula(name: "nginx")], page: SiteURL.projectPage(slug: "nginx"), command: "brew upgrade nginx", grade: "C"),
            finding("pkg|RubyGems|nokogiri|1.13.8", .criticalHigh, .package(ecosystem: .rubygems, name: "nokogiri"), "nokogiri",
                    "1.13.8", "1.19.5", .critical, flaws: 23, origins: [.gem(gem: "/usr/bin/gem")],
                    page: SiteURL.packagePage(.rubygems, "nokogiri", version: "1.13.8"), command: "gem install --user-install nokogiri -v '>= 1.19.5'", grade: "C"),
            finding("brew|python@3.12|3.12.16", .criticalHigh, .project(slug: "cpython", name: "CPython", installedAs: "python@3.12"), "CPython",
                    "3.12.16", "3.14.11", .high, flaws: 1, note: likely("3.14.11"), origins: [.homebrewFormula(name: "python@3.12")],
                    page: SiteURL.projectPage(slug: "cpython"), command: "brew upgrade python@3.12", mark: .parts, grade: "C"),
            finding("pkg|PyPI|urllib3|1.26.5", .criticalHigh, .package(ecosystem: .pypi, name: "urllib3"), "urllib3", "1.26.5", "2.8.0", .high,
                    flaws: 10, note: managedNote, origins: [.pip(python: homebrewPython, user: false, formula: nil)],
                    page: SiteURL.packagePage(.pypi, "urllib3", version: "1.26.5"), command: nil),
            finding("pkg|PyPI|setuptools|58.0.4|py3.9.6", .criticalHigh, .package(ecosystem: .pypi, name: "setuptools"), "setuptools", "58.0.4", "78.1.1",
                    .high, flaws: 4, note: "Apple's Python keeps its own packages read-only; this installs a newer copy in your user site, which Python loads first. "
                        + "For development, a current Python (python.org or Homebrew) is better than Apple's, which is part of Xcode.",
                    origins: [.pip(python: applePython, user: false, formula: nil)],
                    page: SiteURL.packagePage(.pypi, "setuptools", version: "58.0.4"),
                    command: "/usr/bin/python3 -m pip install --user --upgrade 'setuptools>=78.1.1'", fixes: 3,
                    unresolved: [UnresolvedFlaw(id: "GHSA-h35f-9h28-mq5c", severity: .moderate, fixedIn: "83.0.0", reason: .needsPython,
                                                detail: "Python >=3.10", python: "3.9.6"),
                                 UnresolvedFlaw(id: "PYSEC-2026-3447", severity: .low, fixedIn: "84.1.0", reason: .otherPlatform, detail: "Windows")]),
            finding("app|/Applications/Visual Studio Code.app|42.10.0", .criticalHigh, .package(ecosystem: .npm, name: "electron"),
                    "Visual Studio Code", component: "Electron", "42.10.0", "42.11.16", .high, flaws: 8,
                    origins: [.electronApp(name: "Visual Studio Code", bundlePath: "/Applications/Visual Studio Code.app", caskToken: "visual-studio-code")],
                    page: SiteURL.packagePage(.npm, "electron", version: "42.10.0"), command: "brew upgrade --cask visual-studio-code"),
            finding("pkg|PyPI|pip|21.2.4", .other, .package(ecosystem: .pypi, name: "pip"), "pip", "21.2.4", "26.2", .moderate, flaws: 7,
                    origins: [.pip(python: applePython, user: false, formula: nil)], page: SiteURL.packagePage(.pypi, "pip", version: "21.2.4"),
                    command: "/usr/bin/python3 -m pip install --upgrade --user 'pip>=26.2'"),
            finding("pkg|npm|hacl-wasm|1.4.0", .other, .package(ecosystem: .npm, name: "hacl-wasm"), "hacl-wasm", "1.4.0", "1.4.2", .low, flaws: 1,
                    origins: [.folder(root: home + "/code/storefront", lockfile: home + "/code/storefront/package-lock.json", direct: true)],
                    page: SiteURL.packagePage(.npm, "hacl-wasm", version: "1.4.0"), command: "cd ~/code/storefront && npm install hacl-wasm@1.4.2",
                    mark: .whole, grade: "A"),
            finding("pkg|PyPI|pygments|2.14.0|py3.15.2", .other, .package(ecosystem: .pypi, name: "pygments"), "pygments", "2.14.0", nil, .moderate,
                    flaws: 1, origins: [.pip(python: homebrewPython, user: false, formula: "pygments")],
                    page: SiteURL.packagePage(.pypi, "pygments", version: "2.14.0"), command: nil,
                    unresolved: [UnresolvedFlaw(id: "GHSA-x9mx-xxxx-wq5c", severity: .moderate, fixedIn: "2.15.0", reason: .otherPlatform, detail: "Windows")]),
            finding("pkg|crates.io|time|0.1.43", .other, .package(ecosystem: .crates, name: "time"), "time", "0.1.43", nil, .moderate, flaws: 1,
                    note: "No fixed release yet.",
                    origins: [.folder(root: home + "/code/tools", lockfile: home + "/code/tools/cli/Cargo.lock", direct: false)],
                    page: SiteURL.packagePage(.crates, "time", version: "0.1.43"), command: nil),
        ]
    }()

    public static let inventoryReports: [SourceReport] = [
        SourceReport(kind: .homebrew, available: true, count: 407, detail: "338 formulae, 69 casks"),
        SourceReport(kind: .electron, available: true, count: 15, detail: "15 apps"),
        SourceReport(kind: .npm, available: true, count: 1, detail: "1 global package"),
        SourceReport(kind: .pip, available: true, count: 18, detail: "18 packages"),
        SourceReport(kind: .cargo, available: false, count: 0, detail: "no crates installed with cargo install"),
        SourceReport(kind: .gem, available: true, count: 48, detail: "48 gems"),
        SourceReport(kind: .folders, available: true, count: 212, detail: "2 folders, 5 lockfiles"),
    ]

    public static let sent = SentRecord(requests: [
        SentRequest(endpoint: "POST api/v1/check/batch", items: ["npm axios 1.14.1", "npm electron 18.3.15 · macOS", "npm electron 42.10.0 · macOS",
                                                             "npm electron 45.3.2 · macOS", "PyPI pip 21.2.4 · Python 3.9.6 · macOS",
                                                             "PyPI setuptools 58.0.4 · Python 3.9.6 · macOS", "PyPI urllib3 1.26.5 · Python 3.15.2 · macOS",
                                                             "RubyGems nokogiri 1.13.8 · macOS", "crates.io time 0.1.43"]),
        SentRequest(endpoint: "GET api/v1/project", items: ["project cpython", "project nginx", "project openssh", "project openssl"]),
    ], withheldCount: withheld.reduce(0) { $0 + $1.items.count }, answeredFromCache: cached.count, cached: cached, withheld: withheld)

    /// Answered from the cache in the fixture scan: checked a few hours before, not sent again.
    public static let cached = [
        "npm @babel/traverse 7.22.5", "npm braces 3.0.2", "npm cookie 0.5.0", "npm cross-spawn 7.0.3", "npm express 4.18.2 · macOS",
        "npm micromatch 4.0.5", "npm path-to-regexp 0.1.7", "npm semver 7.5.2", "npm ws 8.13.0",
        "PyPI certifi 2023.7.22 · Python 3.9.6 · macOS", "PyPI idna 3.4 · Python 3.15.2 · macOS", "PyPI requests 2.31.0 · Python 3.15.2 · macOS",
        "RubyGems rexml 3.2.5 · macOS", "crates.io regex 1.9.1",
        "project curl", "project git", "project libxml2", "project sqlite",
    ]

    /// What the fixture scan never sent, by where it was found.
    public static let withheld: [Coverage.Bucket] = [
        .init(source: "Homebrew", items: ["abseil 20260817.0", "ack 3.10.0", "aom 3.15.3", "brotli 1.2.0", "c-ares 1.34.6", "ca-certificates 2026-09-30",
                                          "cairo 1.18.6", "fontconfig 2.17.1", "gettext 0.26", "glib 2.86.2", "harfbuzz 12.3.0", "icu4c@78 78.1",
                                          "jq 1.8.1", "libevent 2.1.12", "libuv 1.52.0", "little-cms2 2.17", "lz4 1.10.0", "mpdecimal 4.0.1",
                                          "oniguruma 6.9.10", "pcre 8.45", "pkgconf 2.5.1", "readline 8.3.3", "ripgrep 15.1.0", "slack 4.51.180",
                                          "tree 2.2.1", "webp 1.6.0", "zstd 1.5.7"]),
        .init(source: "pip", items: ["altgraph 0.17.2", "annotated-types 0.8.0", "beniget 0.4.2.post1", "macholib 1.15.2", "mlx 0.32.4",
                                     "mlx-metal 0.32.4", "packaging 25.0", "pydantic-core 2.41.5", "six 1.15.0", "typing-extensions 4.15.0"]),
        .init(source: "RubyGems", items: ["CFPropertyList 2.3.6", "did_you_mean 1.3.0", "minitest 5.11.3", "net-telnet 0.2.0",
                                          "power_assert 1.1.3", "test-unit 3.2.9", "xmlrpc 0.3.0"]),
        .init(source: "Folders", items: ["@next/env 14.0.0", "@swc/helpers 0.5.2", "accepts 1.3.8", "array-flatten 1.1.1", "busboy 1.6.0",
                                         "caniuse-lite 1.0.30001660", "content-disposition 0.5.4", "depd 2.0.0", "destroy 1.2.0", "ee-first 1.1.1",
                                         "encodeurl 1.0.2", "escape-html 1.0.3", "etag 1.8.1", "finalhandler 1.2.0", "fresh 0.5.2",
                                         "graceful-fs 4.2.11", "merge-descriptors 1.0.1", "methods 1.1.2", "nanoid 3.3.7", "our-design-system 3.0.0",
                                         "picocolors 1.1.0", "range-parser 1.2.1", "source-map-js 1.2.1", "styled-jsx 5.1.1", "vary 1.1.2"]),
    ]

    public static func report(findings: [Finding] = findings, problems: [String] = [], coverage: Coverage = coverage) -> ScanReport {
        ScanReport(startedAt: now.addingTimeInterval(-300), finishedAt: now.addingTimeInterval(-240),
                   inventory: Inventory(reports: inventoryReports), findings: findings, sent: sent,
                   indexGeneratedAt: "2026-11-19T01:32:46Z", problems: problems, coverage: coverage)
    }

    public static func settings(report: ScanReport? = report()) -> SettingsState {
        let home = NSHomeDirectory()
        return SettingsState(folders: [home + "/code/storefront", home + "/code/tools"], intervalHours: 6, notifications: true,
                             notificationsAvailable: true, launchAtLogin: true, launchAtLoginAvailable: true, lastReport: report,
                             updates: updates)
    }

    /// The installed app's updater, checked this morning.
    public static let updates = UpdateState(isAvailable: true, canCheck: true, checksAutomatically: true, version: "0.1.1",
                                            lastChecked: now.addingTimeInterval(-3 * 3600))
}

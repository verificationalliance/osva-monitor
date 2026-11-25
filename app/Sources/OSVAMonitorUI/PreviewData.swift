import CoreGraphics
import Foundation
import OSVAKit

/// Fixture data for SwiftUI previews and `osva-render`: a Mac like the one the app was tried on, with one finding of
/// every kind the popover distinguishes.
public enum PreviewData {
    public static let now = Date(timeIntervalSince1970: 1_795_575_000)      // 19 Nov 2026, 02:10 UTC

    /// `make`'s result, made off the main thread and waited for. Fixtures built as a scan builds its findings ask the core
    /// for upgrades and judgements, which must not run on the main thread (Core.swift), and osva-render and the previews
    /// first read them there. `make` must not need a fixture that is still being built: when the main thread is in a
    /// fixture's first read (a `static let`) and `make` reads that same fixture, the two wait for each other forever.
    static func offMain<T: Sendable>(_ make: @escaping @Sendable () -> T) -> T {
        guard Thread.isMainThread else { return make() }
        let box = MadeOffMain<T>(), done = DispatchSemaphore(value: 0)
        DispatchQueue.global(qos: .userInitiated).async { box.value = make(); done.signal() }
        done.wait()
        return box.value!
    }

    /// A fixture's version to upgrade to, as the core checks one: `version` above `installed`, clear of an advisory
    /// fixed in it. Asked off the main thread (`offMain`).
    static func fix(_ version: String, above installed: String) -> CheckedUpgrade {
        let answer = offMain { Core.shared.upgrade(from: installed, advisories: [CoreAdvisory(ranges: [AffectedRange(fixed: version)], fixed: [])]) }
        guard case let .upgrade(u) = answer, u.version == version else { preconditionFailure("the core does not take \(version) above \(installed)") }
        return u
    }

    static func finding(_ id: String, _ group: Finding.Group, _ subject: Finding.Subject, _ title: String, component: String? = nil,
                        _ installed: String, _ fixed: String?, _ severity: Severity?, flaws: Int, exploited: Bool = false,
                        malicious: Bool = false, note: String? = nil, bigIssue: String? = nil, origins: [Origin], page: URL,
                        name: String? = nil, ecosystem: Ecosystem? = nil, runnable: Bool = true, mark: Verification = .none,
                        grade: String? = nil, fixes: Int? = nil, unresolved: [UnresolvedFlaw] = [], notChecked: Finding.NotChecked? = nil) -> Finding {
        // The command is UpgradeCommand's, from the same inputs a scan would record, and the version one the core checked.
        let upgrade = malicious ? nil : fixed.map { fix($0, above: installed) }
        let inputs = UpgradeCommand.Inputs(origin: origins[0], name: name ?? title, ecosystem: ecosystem, target: upgrade, malicious: malicious)
        let advice = runnable ? UpgradeCommand.advice(inputs) : nil
        return Finding(id: id, group: group, subject: subject, title: title, component: component, installedVersion: installed, upgrade: upgrade,
                       severity: severity, advisoryIDs: [], flawCount: flaws, exploited: exploited, malicious: malicious, note: note,
                       bigIssue: bigIssue, origins: origins, pageURL: page, advice: advice, verification: mark, grade: grade,
                       fixesCount: fixes, unresolved: unresolved, commandInputs: advice?.command == nil ? nil : inputs, notChecked: notChecked)
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
                     .init(source: "Apps with no security record", items: ["Firefox", "Google Chrome", "iTerm", "Xcode"])])

    public static let findings: [Finding] = {
        let home = NSHomeDirectory()
        let affected = { (installed: String, fixed: String) in "The issuer lists \(installed) as affected and \(fixed) as fixed." }
        return [
            finding("pkg|npm|axios|1.14.1", .malicious, .package(ecosystem: .npm, name: "axios"), "axios", "1.14.1", nil, nil, flaws: 34,
                    malicious: true, note: "Remove it, then rotate every secret it could read.",
                    origins: [.folder(root: home + "/code/storefront", lockfile: home + "/code/storefront/package-lock.json", direct: true)],
                    page: SiteURL.packagePage(.npm, "axios", version: "1.14.1"), ecosystem: .npm),
            finding("brew|openssh|10.6p1", .exploited, .project(slug: "openssh", name: "OpenSSH", installedAs: "openssh"), "OpenSSH",
                    "10.6p1", "10.6p2", .high, flaws: 1, exploited: true, note: affected("10.6p1", "10.6p2"),
                    bigIssue: "On the site's “patch these first” list", origins: [.homebrewFormula(name: "openssh")],
                    page: SiteURL.projectPage(slug: "openssh"), name: "openssh", mark: .parts, grade: "U"),
            finding("app|/Applications/OpenMTP.app|18.3.15", .exploited, .package(ecosystem: .npm, name: "electron"), "OpenMTP", component: "Electron",
                    "18.3.15", "42.11.16", .high, flaws: 50, exploited: true,
                    origins: [.electronApp(name: "OpenMTP", bundlePath: "/Applications/OpenMTP.app", caskToken: "openmtp")],
                    page: SiteURL.packagePage(.npm, "electron", version: "18.3.15"), name: "electron", ecosystem: .npm),
            finding("brew|nginx|1.30.2", .criticalHigh, .project(slug: "nginx", name: "nginx", installedAs: "nginx"), "nginx",
                    "1.30.2", "1.30.7", .critical, flaws: 6, note: affected("1.30.2", "1.30.7"), bigIssue: "On the site's “patch these first” list",
                    origins: [.homebrewFormula(name: "nginx")], page: SiteURL.projectPage(slug: "nginx"), grade: "C"),
            finding("pkg|RubyGems|nokogiri|1.13.8", .criticalHigh, .package(ecosystem: .rubygems, name: "nokogiri"), "nokogiri",
                    "1.13.8", "1.19.5", .critical, flaws: 23, origins: [.gem(gem: "/usr/bin/gem")],
                    page: SiteURL.packagePage(.rubygems, "nokogiri", version: "1.13.8"), ecosystem: .rubygems, grade: "C"),
            // checked and affected, with critical advisories beside that state no affected versions: its row carries the mark
            finding("brew|python@3.12|3.12.16", .criticalHigh, .project(slug: "cpython", name: "CPython", installedAs: "python@3.12"), "CPython",
                    "3.12.16", "3.14.11", .high, flaws: 1,
                    note: affected("3.12.16", "3.14.11") + " 4 more advisories state no affected versions; not checked, among them CVE-2026-38812, critical.",
                    origins: [.homebrewFormula(name: "python@3.12")], page: SiteURL.projectPage(slug: "cpython"), name: "python@3.12", mark: .parts,
                    grade: "C", notChecked: Finding.NotChecked(id: "CVE-2026-38812", exploited: false, critical: true)),
            finding("pkg|PyPI|urllib3|1.26.5", .criticalHigh, .package(ecosystem: .pypi, name: "urllib3"), "urllib3", "1.26.5", "2.8.0", .high,
                    flaws: 10, note: managedNote, origins: [.pip(python: homebrewPython, user: false, formula: nil)],
                    page: SiteURL.packagePage(.pypi, "urllib3", version: "1.26.5"), ecosystem: .pypi, runnable: false),
            finding("pkg|PyPI|setuptools|58.0.4|py3.9.6", .criticalHigh, .package(ecosystem: .pypi, name: "setuptools"), "setuptools", "58.0.4", "78.1.1",
                    .high, flaws: 4, note: "Apple's Python keeps its own packages read-only; this installs a newer copy in your user site, which Python loads first. "
                        + "For development, a current Python (python.org or Homebrew) is better than Apple's, which is part of Xcode.",
                    origins: [.pip(python: applePython, user: false, formula: nil)],
                    page: SiteURL.packagePage(.pypi, "setuptools", version: "58.0.4"),
                    ecosystem: .pypi, fixes: 3,
                    unresolved: [UnresolvedFlaw(id: "GHSA-h35f-9h28-mq5c", severity: .moderate, fixedIn: "83.0.0", reason: .needsPython,
                                                detail: "Python >=3.10", python: "3.9.6", summary: "Unsafe archive extraction"),
                                 UnresolvedFlaw(id: "PYSEC-2026-3447", severity: .low, fixedIn: "84.1.0", reason: .otherPlatform, detail: "Windows",
                                                summary: "Command injection on Windows")]),
            finding("app|/Applications/Visual Studio Code.app|42.10.0", .criticalHigh, .package(ecosystem: .npm, name: "electron"),
                    "Visual Studio Code", component: "Electron", "42.10.0", "42.11.16", .high, flaws: 8,
                    origins: [.electronApp(name: "Visual Studio Code", bundlePath: "/Applications/Visual Studio Code.app", caskToken: "visual-studio-code")],
                    page: SiteURL.packagePage(.npm, "electron", version: "42.10.0"), name: "electron", ecosystem: .npm),
            finding("pkg|PyPI|pip|21.2.4", .other, .package(ecosystem: .pypi, name: "pip"), "pip", "21.2.4", "26.2", .moderate, flaws: 7,
                    origins: [.pip(python: applePython, user: false, formula: nil)], page: SiteURL.packagePage(.pypi, "pip", version: "21.2.4"),
                    ecosystem: .pypi),
            finding("pkg|npm|hacl-wasm|1.4.0", .other, .package(ecosystem: .npm, name: "hacl-wasm"), "hacl-wasm", "1.4.0", "1.4.2", .low, flaws: 1,
                    origins: [.folder(root: home + "/code/storefront", lockfile: home + "/code/storefront/package-lock.json", direct: true)],
                    page: SiteURL.packagePage(.npm, "hacl-wasm", version: "1.4.0"), ecosystem: .npm, mark: .whole, grade: "A"),
            // its one flaw is Windows-only, inside its published ranges there: listed, nothing to do on this Mac, never
            // counted among the lower-severity findings
            { () -> Finding in
                var f = finding("pkg|PyPI|pygments|2.14.0|py3.15.2", .other, .package(ecosystem: .pypi, name: "pygments"), "pygments", "2.14.0", nil,
                                .moderate, flaws: 1, origins: [.pip(python: homebrewPython, user: false, formula: "pygments")],
                                page: SiteURL.packagePage(.pypi, "pygments", version: "2.14.0"), runnable: false,
                                unresolved: [UnresolvedFlaw(id: "GHSA-x9mx-xxxx-wq5c", severity: .moderate, fixedIn: "2.15.0", reason: .otherPlatform,
                                                            detail: "Windows", summary: "Code execution via a crafted path on Windows")])
                f.onlyElsewhere = true
                return f
            }(),
            finding("pkg|crates.io|time|0.1.43", .other, .package(ecosystem: .crates, name: "time"), "time", "0.1.43", nil, .moderate, flaws: 1,
                    note: "No fixed release yet.",
                    origins: [.folder(root: home + "/code/tools", lockfile: home + "/code/tools/cli/Cargo.lock", direct: false)],
                    page: SiteURL.packagePage(.crates, "time", version: "0.1.43"), runnable: false),
        ] + notCheckedFindings
    }()

    /// What the core could not check against published ranges: a formula the site reports an exploited, critical flaw
    /// for, with no affected versions published (the amber mark, never counted), and one likely affected by the
    /// issuer's first fixed version, with the version the core checked.
    public static let notCheckedFindings: [Finding] = [
        finding("brew|imagemagick|7.1.2-8", .reported, .project(slug: "imagemagick", name: "ImageMagick", installedAs: "imagemagick"), "ImageMagick",
                "7.1.2-8", nil, .critical, flaws: 1, exploited: true,
                note: "Reported by the site, not checked: it publishes no affected versions for CVE-2026-41730.",
                origins: [.homebrewFormula(name: "imagemagick")], page: SiteURL.projectPage(slug: "imagemagick"), name: "imagemagick",
                runnable: false, grade: "D", notChecked: Finding.NotChecked(id: "CVE-2026-41730", exploited: true, critical: true)),
        finding("brew|redis|8.2.1", .likely, .project(slug: "redis", name: "Redis", installedAs: "redis"), "Redis", "8.2.1", "8.2.3", .high, flaws: 2,
                note: "Likely affected: the site publishes no affected ranges, and the issuer names 8.2.3 as fixed.",
                origins: [.homebrewFormula(name: "redis")], page: SiteURL.projectPage(slug: "redis"), name: "redis", grade: "B"),
    ]

    public enum NotCheckedID {
        public static let imagemagick = "brew|imagemagick|7.1.2-8", redis = "brew|redis|8.2.1"
    }

    /// Only what was not checked: nothing the core checked needs action, and an exploited flaw is reported.
    public static func notCheckedReport() -> ScanReport { report(findings: notCheckedFindings) }

    /// Rows with everything on their status line at once, and long names and versions: the status line wraps a chip
    /// whole to its next line, never inside it; a title too long for the row is cut in the middle.
    public static let crowdedFindings: [Finding] = {
        let openmtp = Origin.electronApp(name: "OpenMTP", bundlePath: "/Applications/OpenMTP.app", caskToken: "openmtp")
        let insiders = Origin.electronApp(name: "Visual Studio Code - Insiders", bundlePath: "/Applications/Visual Studio Code - Insiders.app",
                                          caskToken: "visual-studio-code@insiders")
        let storefront = Origin.folder(root: NSHomeDirectory() + "/code/storefront", lockfile: NSHomeDirectory() + "/code/storefront/package-lock.json",
                                       direct: true)
        return [
            finding("crowded|openmtp|128", .exploited, .package(ecosystem: .npm, name: "electron"), "OpenMTP", component: "Electron", "18.3.15",
                    "42.11.16", .moderate, flaws: 128, exploited: true, origins: [openmtp], page: SiteURL.packagePage(.npm, "electron", version: "18.3.15"),
                    name: "electron", ecosystem: .npm, notChecked: Finding.NotChecked(id: "CVE-2026-50112", exploited: true, critical: false)),
            finding("crowded|openmtp|12", .exploited, .package(ecosystem: .npm, name: "electron"), "OpenMTP", component: "Electron", "24.2.0",
                    "42.11.16", .moderate, flaws: 12, exploited: true, origins: [openmtp], page: SiteURL.packagePage(.npm, "electron", version: "24.2.0"),
                    name: "electron", ecosystem: .npm, notChecked: Finding.NotChecked(id: "CVE-2026-50112", exploited: true, critical: true)),
            finding("crowded|insiders", .likely, .package(ecosystem: .npm, name: "electron"), "Visual Studio Code - Insiders Edition (Universal)",
                    component: "Electron", "38.0.0-beta.17", "38.0.1", .critical, flaws: 128, exploited: true,
                    note: "Likely affected: the site publishes no affected ranges, and the issuer names 38.0.1 as fixed.",
                    origins: [insiders], page: SiteURL.packagePage(.npm, "electron", version: "38.0.0-beta.17"), name: "electron", ecosystem: .npm,
                    mark: .parts, grade: "B", notChecked: Finding.NotChecked(id: "CVE-2026-50113", exploited: true, critical: true)),
            finding("crowded|aws", .criticalHigh, .package(ecosystem: .npm, name: "@aws-sdk/client-secrets-manager"), "@aws-sdk/client-secrets-manager",
                    "3.1022.0-beta.17", "3.1022.1", .high, flaws: 12, origins: [storefront],
                    page: SiteURL.packagePage(.npm, "@aws-sdk/client-secrets-manager", version: "3.1022.0-beta.17"), ecosystem: .npm, mark: .whole,
                    grade: "A", notChecked: Finding.NotChecked(id: "CVE-2026-50114", exploited: false, critical: true)),
            // checked: its only flaw's published ranges leave 2.0.0-1 out. In Other, with no severity and nothing counted
            { () -> Finding in
                var f = finding("crowded|numeric", .other, .package(ecosystem: .npm, name: "numeric"), "numeric", "2.0.0-1", nil, nil, flaws: 1,
                                note: "Reported by the site; its published ranges for CVE-2026-50115 do not include 2.0.0-1.", origins: [storefront],
                                page: SiteURL.packagePage(.npm, "numeric", version: "2.0.0-1"), ecosystem: .npm, runnable: false)
                f.outsideItsRanges = true
                return f
            }(),
            // its one flaw, high, is Windows-only and has no published ranges: in Other, with no severity and nothing to do
            { () -> Finding in
                var f = finding("crowded|win-path", .other, .package(ecosystem: .npm, name: "win-path"), "win-path", "1.4.0", nil, nil, flaws: 1,
                                origins: [.npmGlobal(npm: "/opt/homebrew/bin/npm")], page: SiteURL.packagePage(.npm, "win-path", version: "1.4.0"),
                                ecosystem: .npm, runnable: false,
                                unresolved: [UnresolvedFlaw(id: "CVE-2026-50116", severity: .high, fixedIn: nil, reason: .otherPlatform, detail: "windows",
                                                            summary: "Path traversal through drive-relative paths on Windows")])
                f.onlyElsewhere = true
                return f
            }(),
        ]
    }()

    public static func crowdedReport() -> ScanReport { report(findings: crowdedFindings, coverage: Coverage()) }

    // MARK: Fixes (osva-render)

    /// This Mac as the fixtures describe it: every tool their commands name is there.
    static let fixtureTools = ToolEnvironment(base: [:], isExecutable: { _ in true })

    static func finding(_ id: String) -> Finding { findings.first { $0.id == id }! }

    /// A package some project's framework needs held back: the starlette under fastapi 0.120.0 that 0.2.0 broke.
    public static let python311 = PythonEnvironment(executable: "/opt/homebrew/bin/python3.11", version: "3.11.14", kind: .homebrew,
                                                    externallyManaged: false, userSite: nil, formula: "python@3.11")
    public static let starlette = finding("pkg|PyPI|starlette|0.48.0|py3.11.14", .exploited, .package(ecosystem: .pypi, name: "starlette"),
                                          "starlette", "0.48.0", "1.3.1", .high, flaws: 6, exploited: true,
                                          origins: [.pip(python: python311, user: false, formula: nil)],
                                          page: SiteURL.packagePage(.pypi, "starlette", version: "0.48.0"), ecosystem: .pypi)

    /// torch in python.org's Python, where torchaudio pins it: they move together.
    public static let pythonOrg = PythonEnvironment(executable: "/usr/local/bin/python3.13", version: "3.13.9",
                                                    kind: .pythonOrg, externallyManaged: false, userSite: nil, formula: nil)
    public static let torch = finding("pkg|PyPI|torch|2.7.0|py3.13.9", .criticalHigh, .package(ecosystem: .pypi, name: "torch"), "torch", "2.7.0", "2.8.0",
                                      .high, flaws: 6, origins: [.pip(python: pythonOrg, user: false, formula: nil)],
                                      page: SiteURL.packagePage(.pypi, "torch", version: "2.7.0"), ecosystem: .pypi)

    /// The findings the fix scenes draw from: the fixtures, starlette, torch, and jupyterlab's tornado and jinja2.
    public static var fixFindings: [Finding] { findings + [starlette, torch, tornado, jinja2] }

    static func fixFinding(_ id: String) -> Finding { fixFindings.first { $0.id == id }! }

    /// What each in-app state looks like, on the findings it applies to (osva-render, CaptureMode's --fix-states).
    public struct FixScene: Sendable {
        public var fixes: [String: FixRowState]
        /// Rows kept after their finding left the report (fixed, removed, or fixed but broke something).
        public var resolved: [String]
        public var open: Set<String>
        /// The findings shown; the resolved ones are left out of the report and come back through `resolved`.
        public var shown: [String]

        public func report() -> ScanReport { PreviewData.report(findings: PreviewData.sceneFindings.filter { shown.contains($0.id) && !resolved.contains($0.id) }) }
        public var resolvedFindings: [Finding] { PreviewData.sceneFindings.filter { resolved.contains($0.id) } }
    }

    public static let fixSceneNames = ["offer", "confirm", "running", "done", "problems", "results"]

    public static func fixScene(_ name: String) -> FixScene? {
        typealias F = FixID
        switch name {
        case "offer": return FixScene(fixes: fixOffers, resolved: [], open: Set(fixOffers.keys), shown: Array(fixOffers.keys))
        case "confirm": return FixScene(fixes: fixConfirmations, resolved: [], open: Set(fixConfirmations.keys), shown: Array(fixConfirmations.keys))
        case "running": return FixScene(fixes: fixRunning, resolved: [], open: [F.nginx, F.axios], shown: [F.nginx, F.axios, F.vscode])
        case "done": return FixScene(fixes: fixDone, resolved: [F.nginx, F.axios, F.torch], open: [F.nginx, F.torch], shown: [F.nginx, F.axios, F.torch])
        case "problems": return FixScene(fixes: fixProblems, resolved: [F.starlette], open: Set(fixProblems.keys), shown: Array(fixProblems.keys))
        case "results": return FixScene(fixes: fixResults, resolved: fixResolved, open: [F.openssh, F.torch],
                                        shown: [F.axios, F.openssh, F.openmtp, F.nginx, F.torch])
        default: return nil
        }
    }

    /// The plan a fixture finding gets, made by FixPlan as the app makes it.
    public static func offer(_ id: String, homebrew: String? = nil, companions: [String] = []) -> FixOffer {
        guard case let .success(plan) = FixPlan.make(for: fixFinding(id), tools: fixtureTools) else { preconditionFailure("no fix for \(id)") }
        return FixOffer(plan: plan, homebrew: homebrew, companions: companions)
    }

    /// What FixPlan decides for a fixture finding: its plan, or the refusal the row shows (a pip or lockfile upgrade
    /// is not run for you since 0.2.1).
    static func availability(_ id: String) -> FixRowState.Availability {
        switch FixPlan.make(for: finding(id), tools: fixtureTools) {
        case let .success(plan): return .offered(FixOffer(plan: plan, homebrew: nil))
        case let .failure(refusal): return .withheld(refusal.explanation)
        }
    }

    public enum FixID {
        public static let axios = "pkg|npm|axios|1.14.1", openssh = "brew|openssh|10.6p1", openmtp = "app|/Applications/OpenMTP.app|18.3.15"
        public static let nginx = "brew|nginx|1.30.2", nokogiri = "pkg|RubyGems|nokogiri|1.13.8", cpython = "brew|python@3.12|3.12.16"
        public static let setuptools = "pkg|PyPI|setuptools|58.0.4|py3.9.6", vscode = "app|/Applications/Visual Studio Code.app|42.10.0"
        public static let hacl = "pkg|npm|hacl-wasm|1.4.0", starlette = "pkg|PyPI|starlette|0.48.0|py3.11.14", torch = "pkg|PyPI|torch|2.7.0|py3.13.9"
    }

    /// Rows opened: Remove, Update to a version, Update the app that carries the flaw; none because something depends
    /// on the version there now, and none because Homebrew does not have the fix yet.
    public static var fixOffers: [String: FixRowState] {
        [FixID.axios: FixRowState(availability: .offered(offer(FixID.axios))),
         FixID.nginx: FixRowState(availability: .offered(offer(FixID.nginx, homebrew: "Has 1.30.7."))),
         FixID.openmtp: FixRowState(availability: .offered(offer(FixID.openmtp, homebrew: "Has OpenMTP 3.2.25; 3.2.24 is installed."))),
         FixID.starlette: FixRowState(availability: .withheld("fastapi 0.120.0 needs starlette < 0.49.0 — update fastapi first."), hold: .blocked),
         FixID.cpython: FixRowState(availability: .withheld("Homebrew still ships 3.12.17; the fix is 3.14.11 upstream."))]
    }

    /// The review open: a `brew upgrade` with its dry run, a pip upgrade whose pinning companion moves with it, a removal.
    public static var fixConfirmations: [String: FixRowState] {
        [FixID.nginx: FixRowState(availability: .offered(offer(FixID.nginx, homebrew: "Has 1.30.7.")),
                                  preview: .ready(FixPreview(source: "brew upgrade --dry-run",
                                                             lines: FixPreviewer.parseBrewDryRun("""
                                                                 ==> Would upgrade 2 outdated packages:
                                                                 openssl@3 3.6.1 -> 3.6.2
                                                                 nginx 1.30.2 -> 1.30.7
                                                                 """)))),
         FixID.torch: FixRowState(availability: .offered(offer(FixID.torch, companions: ["torchaudio"])),
                                  preview: .ready(FixPreview(source: "pip install --dry-run (asks PyPI, installs nothing)",
                                                             lines: ["Would install torch 2.8.0, torchaudio 2.8.0"],
                                                             installs: ["torch": "2.8.0", "torchaudio": "2.8.0"], pins: ["torchaudio==2.8.0"],
                                                             usedBy: ["pyannote.audio", "whisperx"]))),
         FixID.axios: FixRowState(availability: .offered(offer(FixID.axios)),
                                  preview: .ready(.none("npm has no dry run the app uses: the log shows what changes.")))]
    }

    static let brewLog = FixLog(["==> Auto-updating Homebrew...", "==> Fetching downloads for: nginx", "==> Upgrading nginx", "  1.30.2 -> 1.30.7"],
                                partial: "==> Pouring nginx--1.30.7.arm64_tahoe.bottle.tar.gz")

    /// nginx updating (a minute in, its log streaming); the next row's button waits for it.
    public static var fixRunning: [String: FixRowState] {
        [FixID.nginx: FixRowState(availability: .offered(offer(FixID.nginx, homebrew: "Has 1.30.7.")), progress: .running,
                                  run: FixRunState(step: .running, doing: "Updating", startedAt: Date().addingTimeInterval(-63), log: brewLog,
                                                   command: "brew upgrade nginx")),
         FixID.axios: FixRowState(availability: .offered(offer(FixID.axios)), waitingFor: "nginx"),
         FixID.vscode: FixRowState(availability: .offered(offer(FixID.vscode)), waitingFor: "nginx")]
    }

    /// The three steps of one run, for the component sheet.
    public static func runSteps() -> [FixRunState] {
        [FixRunState(step: .preparing, doing: "Updating", startedAt: Date().addingTimeInterval(-1), command: "brew upgrade nginx"),
         FixRunState(step: .running, doing: "Updating", startedAt: Date().addingTimeInterval(-63), log: brewLog, command: "brew upgrade nginx"),
         FixRunState(step: .checking, doing: "Updating", startedAt: Date().addingTimeInterval(-81), endedAt: Date().addingTimeInterval(-2),
                     log: FixLog(brewLog.lines + ["==> Pouring nginx--1.30.7.arm64_tahoe.bottle.tar.gz", "🍺  /opt/homebrew/Cellar/nginx/1.30.7: 27 files, 2.6MB"]),
                     command: "brew upgrade nginx")]
    }

    /// Fixed (its version rolled over), removed, and fixed beyond a patch of something others use (who to check, and Undo).
    public static var fixDone: [String: FixRowState] {
        let undo = PipUndo(invocation: FixInvocation(executable: pythonOrg.executable,
                                                     arguments: ["-m", "pip", "install", "--no-deps", "--disable-pip-version-check", "torch==2.7.0", "torchaudio==2.7.0"]),
                           restores: ["torch 2.7.0", "torchaudio 2.7.0"])
        return [FixID.nginx: FixRowState(progress: .finished(.fixed(now: "1.30.7")),
                                         run: FixRunState(step: .checking, doing: "Updating", startedAt: now.addingTimeInterval(-81), endedAt: now.addingTimeInterval(-2),
                                                          log: brewLog, command: "brew upgrade nginx")),
                FixID.axios: FixRowState(progress: .finished(.removed)),
                FixID.torch: FixRowState(progress: .finished(.fixedCheck(now: "2.8.0", users: "whisperx")),
                                         run: FixRunState(step: .checking, doing: "Updating", startedAt: now.addingTimeInterval(-95), endedAt: now.addingTimeInterval(-3),
                                                          log: FixLog(["Successfully installed torch-2.8.0 torchaudio-2.8.0"]),
                                                          command: torch.upgradeCommand! + " torchaudio==2.8.0", undo: undo))]
    }

    /// How a run can end badly: it broke what depends on it (Undo), it needs a password (Terminal), it failed (Retry).
    public static var fixProblems: [String: FixRowState] {
        let undo = PipUndo(invocation: FixInvocation(executable: python311.executable,
                                                     arguments: ["-m", "pip", "install", "--no-deps", "--disable-pip-version-check", "starlette==0.48.0"]),
                           restores: ["starlette 0.48.0"])
        return [
            FixID.starlette: FixRowState(progress: .finished(.broke("fastapi 0.120.0")),
                                         run: FixRunState(step: .checking, doing: "Updating", startedAt: now.addingTimeInterval(-14), endedAt: now.addingTimeInterval(-6),
                                                          log: FixLog(["Collecting starlette==1.3.1", "Installing collected packages: starlette",
                                                                       "Successfully installed starlette-1.3.1",
                                                                       "ERROR: pip's dependency resolver does not currently take into account all the packages that are installed.",
                                                                       "fastapi 0.120.0 requires starlette<0.49.0,>=0.40.0, but you have starlette 1.3.1 which is incompatible."]),
                                                          command: starlette.upgradeCommand!, undo: undo)),
            FixID.openmtp: FixRowState(availability: .offered(offer(FixID.openmtp)), progress: .finished(.needsPassword),
                                       run: FixRunState(step: .checking, doing: "Updating", startedAt: now.addingTimeInterval(-38), endedAt: now.addingTimeInterval(-9),
                                                        log: FixLog(["==> Upgrading openmtp", "==> Running installer for openmtp with sudo; the password may be necessary.",
                                                                     "sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper",
                                                                     "sudo: a password is required"]),
                                                        command: "brew upgrade --cask openmtp")),
            FixID.torch: FixRowState(availability: .offered(offer(FixID.torch, companions: ["torchaudio"])), progress: .finished(.exitedWithError(1)),
                                     run: FixRunState(step: .checking, doing: "Updating", startedAt: now.addingTimeInterval(-21), endedAt: now.addingTimeInterval(-5),
                                                      log: FixLog(["Collecting torch==2.8.0",
                                                                   "WARNING: Retrying (Retry(total=0)) after connection broken by 'NewConnectionError': /simple/torch/",
                                                                   "ERROR: Could not find a version that satisfies the requirement torch==2.8.0 (from versions: none)",
                                                                   "ERROR: No matching distribution found for torch==2.8.0"]),
                                                      command: torch.upgradeCommand! + " torchaudio==2.8.0")),
        ]
    }

    /// After runs, as a panel shows them later: one updating in the app now, one removed, two fixed (kept in place, not
    /// counted; torch beyond a patch, so it says who to check and keeps Undo), one still affected. (The Terminal
    /// outcomes, kept for the password fallback, are not shown here.)
    public static var fixResults: [String: FixRowState] {
        var results = fixDone
        results[FixID.openssh] = FixRowState(availability: .offered(offer(FixID.openssh, homebrew: "Has 10.6p2.")), progress: .running,
                                             run: FixRunState(step: .running, doing: "Updating", startedAt: Date().addingTimeInterval(-41),
                                                              log: FixLog(["==> Auto-updating Homebrew...", "==> Fetching downloads for: openssh",
                                                                           "==> Upgrading openssh", "  10.6p1 -> 10.6p2"],
                                                                          partial: "==> Pouring openssh--10.6p2.arm64_tahoe.bottle.tar.gz"),
                                                              command: "brew upgrade openssh"))
        results[FixID.openmtp] = FixRowState(progress: .finished(.stillAffected("now Electron 41.0.2; the fix is 42.11.16")))
        return results
    }
    public static let fixResolved = [FixID.axios, FixID.nginx, FixID.torch]

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
                             updates: updates, changelog: .bundled)
    }

    /// The installed app's updater, checked this morning.
    public static let updates = UpdateState(isAvailable: true, canCheck: true, checksAutomatically: true, version: "0.1.1",
                                            lastChecked: now.addingTimeInterval(-3 * 3600))
}

extension PreviewData {
    /// How many pixels of a render are SwiftUI's placeholder for a view it cannot draw off-screen (an AppKit control:
    /// a `.borderless` button, a linear progress bar): the yellow (255, 204, 0) square behind its red "no" sign. A render of
    /// the panel has none (osva-render fails on one, and PopoverContentTests/thePanelDrawsNoPlaceholder).
    public static func placeholderPixels(_ image: CGImage) -> Int {
        let width = image.width, height = image.height
        let context = CGContext(data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: 0,
                                space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
        context.draw(image, in: CGRect(x: 0, y: 0, width: width, height: height))
        let bytes = context.makeImage()!.dataProvider!.data! as Data, row = context.bytesPerRow
        var count = 0
        for y in 0..<height {
            for x in 0..<width {
                let i = y * row + x * 4
                if bytes[i] >= 252 && abs(Int(bytes[i + 1]) - 204) <= 3 && bytes[i + 2] <= 3 && bytes[i + 3] == 255 { count += 1 }
            }
        }
        return count
    }
}

/// What `PreviewData.offMain` made: written once by the worker, read only after it signals.
private final class MadeOffMain<T>: @unchecked Sendable { var value: T? }

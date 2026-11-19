import Foundation
import OSVAKit

/// Fix all's fixtures, for `osva-render`: the header's button with its breakdown, the review (a batch per tool and place,
/// proposals unticked), a run at batch 2, a Python batch put back and run one at a time, and the summary with what needs
/// the person; and rows: proposals, casks whose upgrade would change nothing, one that needs a password, a partial fix
/// done. On the fix scenes' findings plus a Python 3.11 with nine packages to update, jupyterlab's two, the owner's
/// torch (held below 2.9 by whisperx), Dropbox and Zoom.
extension PreviewData {
    /// The Python inside Homebrew's jupyterlab formula: its packages are upgraded by upgrading the formula.
    public static let jupyterPython = PythonEnvironment(executable: "/opt/homebrew/Cellar/jupyterlab/4.4.0/libexec/bin/python", version: "3.13.9",
                                                        kind: .homebrew, externallyManaged: true, userSite: nil, formula: "python@3.13")
    public static let tornado = finding("pkg|PyPI|tornado|6.4.1|py3.13.9", .criticalHigh, .package(ecosystem: .pypi, name: "tornado"), "tornado",
                                        "6.4.1", "6.5", .high, flaws: 2, origins: [.pip(python: jupyterPython, user: false, formula: "jupyterlab")],
                                        page: SiteURL.packagePage(.pypi, "tornado", version: "6.4.1"), ecosystem: .pypi)
    public static let jinja2 = finding("pkg|PyPI|jinja2|3.1.4|py3.13.9", .other, .package(ecosystem: .pypi, name: "jinja2"), "jinja2",
                                       "3.1.4", "3.1.6", .moderate, flaws: 2, origins: [.pip(python: jupyterPython, user: false, formula: "jupyterlab")],
                                       page: SiteURL.packagePage(.pypi, "jinja2", version: "3.1.4"), ecosystem: .pypi)

    /// Python 3.11's packages that update cleanly: one pip command for all nine.
    public static let python311Packages: [Finding] = [
        ("requests", "2.31.0", "2.32.4", Severity.high), ("urllib3", "2.2.1", "2.5.0", .high), ("certifi", "2024.2.2", "2024.7.4", .high),
        ("idna", "3.6", "3.7", .high), ("pillow", "10.2.0", "10.3.0", .critical), ("aiohttp", "3.9.3", "3.10.11", .high),
        ("werkzeug", "3.0.1", "3.0.6", .high), ("cryptography", "42.0.4", "44.0.1", .high), ("h11", "0.14.0", "0.16.0", .high),
    ].map { name, installed, fixed, severity in
        finding("pkg|PyPI|\(name)|\(installed)|py3.11.14", .criticalHigh, .package(ecosystem: .pypi, name: name), name, installed, fixed, severity,
                flaws: 1, origins: [.pip(python: python311, user: false, formula: nil)], page: SiteURL.packagePage(.pypi, name, version: installed),
                ecosystem: .pypi)
    }

    /// The owner's torch: every fix is in 2.9 or later, which goes with a torchaudio that removed what whisperx uses.
    public static let torch311 = finding("pkg|PyPI|torch|2.7.0|py3.11.14", .criticalHigh, .package(ecosystem: .pypi, name: "torch"), "torch",
                                         "2.7.0", "2.13.0", .critical, flaws: 14, origins: [.pip(python: python311, user: false, formula: nil)],
                                         page: SiteURL.packagePage(.pypi, "torch", version: "2.7.0"), ecosystem: .pypi)
    /// Dropbox updates itself: the app is at Homebrew's newest, the cask record is far behind, and it still ships an old
    /// Electron. `brew upgrade --cask dropbox` would change nothing.
    public static let dropbox = finding("app|/Applications/Dropbox.app|37.10.3", .exploited, .package(ecosystem: .npm, name: "electron"), "Dropbox",
                                        component: "Electron", "37.10.3", "38.4.0", .high, flaws: 3, exploited: true,
                                        origins: [.electronApp(name: "Dropbox", bundlePath: "/Applications/Dropbox.app", caskToken: "dropbox")],
                                        page: SiteURL.packagePage(.npm, "electron", version: "37.10.3"), name: "electron", ecosystem: .npm)
    /// torch after its partial fix: still found at 2.8.0, with the 8 flaws whisperx's limit leaves.
    public static let torch311After = finding("pkg|PyPI|torch|2.8.0|py3.11.14", .criticalHigh, .package(ecosystem: .pypi, name: "torch"), "torch",
                                              "2.8.0", "2.13.0", .critical, flaws: 8, origins: [.pip(python: python311, user: false, formula: nil)],
                                              page: SiteURL.packagePage(.pypi, "torch", version: "2.8.0"), ecosystem: .pypi)
    /// Zoom's cask installs a pkg: its update needs an administrator's password.
    public static let zoom = finding("brew-cask|zoom|6.2.5", .criticalHigh, .project(slug: "zoom", name: "Zoom", installedAs: "zoom"), "Zoom",
                                     "6.2.5", "6.3.11", .high, flaws: 2, origins: [.homebrewCask(token: "zoom")], page: SiteURL.projectPage(slug: "zoom"),
                                     name: "zoom")

    public enum FixAllID {
        public static let tornado = "pkg|PyPI|tornado|6.4.1|py3.13.9", jinja2 = "pkg|PyPI|jinja2|3.1.4|py3.13.9"
        public static let torch311 = "pkg|PyPI|torch|2.7.0|py3.11.14", dropbox = "app|/Applications/Dropbox.app|37.10.3", zoom = "brew-cask|zoom|6.2.5"
        public static let aiohttp = "pkg|PyPI|aiohttp|3.9.3|py3.11.14"
    }

    /// Every finding Fix all's scenes show.
    static var fixAllFindings: [Finding] { fixFindings + python311Packages + [torch311, dropbox, zoom] }
    /// And what a row scene may show besides: torch after its partial fix.
    static var sceneFindings: [Finding] { fixAllFindings + [torch311After] }

    /// One Fix all state on its findings: the panel's rows, and Fix all's button and card.
    public struct FixAllScene: Sendable {
        public var scene: FixScene
        public var panel: FixAllPanel
    }

    public static let fixAllSceneNames = ["all-button", "all-waiting", "all-review", "all-running", "all-isolated", "all-summary"]

    /// torch to 2.8.0 with torchaudio, within whisperx's limit: 6 of its 14 flaws.
    public static var torchPartial: FixOffer {
        guard case let .success(plan) = FixPlan.make(for: torch311, tools: fixtureTools, target: "2.8.0") else { preconditionFailure("no partial plan") }
        return FixOffer(plan: plan, companions: ["torchaudio"],
                        proposal: .partial(.init(fixes: 6, of: 14, blocker: FixConstraint(specifier: "<2.9", from: "whisperx", boundary: true),
                                                 constraints: ["<2.9"])))
    }

    /// starlette with fastapi and the instrumentator, as pip's resolver works them out.
    public static var starletteTogether: FixOffer {
        FixOffer(plan: offer(FixID.starlette).plan,
                 proposal: .together(.init(package: "starlette", fix: "1.3.1", blockers: ["fastapi", "prometheus-fastapi-instrumentator"],
                                           exploited: true, python: python311)))
    }

    static let starletteWhy = "fastapi 0.120.0 needs starlette < 0.49.0 — update fastapi first."
    static let torchWhy = "torch 2.9 goes with torchaudio 2.9, which removed AudioMetaData — whisperx 3.3.4 may rely on it."

    /// Every row as the app decides it: the plans FixPlan makes, with Homebrew's answers and pip's dependents as the
    /// fixture offers have them, the refusals (Apple's Ruby and Python, Homebrew without the fix, a project's lockfile,
    /// no command at all), the two proposals, the casks with nothing newer, and the one that needs a password.
    public static var fixAllRows: [String: FixRowState] {
        var rows: [String: FixRowState] = [:]
        for f in fixAllFindings {
            switch FixPlan.make(for: f, tools: fixtureTools) {
            case let .success(plan): rows[f.id] = FixRowState(availability: .offered(FixOffer(plan: plan)))
            case let .failure(refusal): rows[f.id] = FixRowState(availability: .withheld(refusal.explanation), hold: .yours)
            }
        }
        rows.merge(fixOffers) { _, fixture in fixture }
        for (id, row) in rows { if case let .withheld(why?)? = row.availability, let f = fixAllFindings.first(where: { $0.id == id }) { rows[id]?.hold = AppModel.hold(f, why) } }
        let jupyterlab = "Has jupyterlab 4.5.1; 4.4.0 is installed. Whether that brings the fix shows when the app checks again."
        rows[FixID.openssh] = FixRowState(availability: .offered(offer(FixID.openssh, homebrew: "Has 10.6p2.")))
        rows[FixID.vscode] = FixRowState(availability: .offered(offer(FixID.vscode, homebrew: "Has Visual Studio Code 1.107.0; 1.106.2 is installed.")))
        rows[FixID.torch] = FixRowState(availability: .offered(offer(FixID.torch, companions: ["torchaudio"])))
        rows[FixAllID.tornado] = FixRowState(availability: .offered(offer(FixAllID.tornado, homebrew: jupyterlab)))
        rows[FixAllID.jinja2] = FixRowState(availability: .offered(offer(FixAllID.jinja2, homebrew: jupyterlab)))
        rows[FixID.starlette] = FixRowState(availability: .withheld(starletteWhy), proposal: starletteTogether, hold: .blocked)
        rows[FixAllID.torch311] = FixRowState(availability: .withheld(torchWhy), proposal: torchPartial, hold: .blocked)
        rows[FixAllID.dropbox] = FixRowState(availability: .withheld(HomebrewAvailability.newestInstalled(electron: "Electron 37.10.3")), hold: .noFix)
        rows[FixAllID.zoom] = FixRowState(availability: .terminal(offerAll(FixAllID.zoom),
                                                                  HomebrewAvailability.passwordLine + ": its update runs an installer package."))
        return rows
    }

    /// The plan a Fix all fixture finding gets, made by FixPlan as the app makes it.
    static func offerAll(_ id: String, homebrew: String? = nil) -> FixOffer {
        guard let f = fixAllFindings.first(where: { $0.id == id }), case let .success(plan) = FixPlan.make(for: f, tools: fixtureTools) else {
            preconditionFailure("no fix for \(id)")
        }
        return FixOffer(plan: plan, homebrew: homebrew)
    }

    static var fixAllShown: [String] { fixAllFindings.map(\.id) }

    static func fixAllReport(resolved: [String] = []) -> [Finding] {
        fixAllFindings.filter { !resolved.contains($0.id) }
    }

    /// The review as the app makes it from these rows.
    public static var fixAllReview: FixAllState { FixAll.review(fixAllReport(), fixes: fixAllRows) }

    static let caskLog = FixLog(["Dry run:", "Would upgrade 2 outdated packages:", "openmtp 3.2.24 → 3.2.25", "visual-studio-code 1.106.2 → 1.107.0",
                                 "==> Upgrading 2 outdated packages:", "==> Upgrading openmtp"],
                                partial: "==> Moving App 'OpenMTP.app' to '/Applications/OpenMTP.app'")

    static let pipOneLog = FixLog(["Collecting aiohttp==3.10.11", "Downloading aiohttp-3.10.11-cp311-cp311-macosx_11_0_arm64.whl (389 kB)"],
                                  partial: "Installing collected packages: aiohttp")

    public static func fixAllScene(_ name: String) -> FixAllScene? {
        var rows = fixAllRows
        let review = fixAllReview
        func panel(_ batch: FixAllState?, resolved: [String] = [], waiting: String? = nil, run: FixRunState? = nil, undo: PipUndo? = nil) -> FixAllPanel {
            let standing = fixAllFindings.filter { !resolved.contains($0.id) }
            return FixAllPanel(count: FixAll.offered(standing, fixes: rows).count, waitingFor: waiting, batch: batch, run: run, undo: undo,
                               breakdown: FixAll.breakdown(standing, fixes: rows)?.line)
        }
        func scene(resolved: [String] = [], open: Set<String> = []) -> FixScene {
            FixScene(fixes: rows, resolved: resolved, open: open, shown: fixAllShown)
        }
        /// These findings done as the outcomes say (fixed and removed rows leave the report).
        func finish(_ batch: inout FixAllState, _ i: Int, _ outcomes: [String: FixOutcome], resolved: inout [String]) {
            for f in batch.batches[i].findings {
                guard let o = outcomes[f.id] else { continue }
                batch.batches[i].outcomes[f.id] = o
                // a row that did not end fixed keeps its offer (Retry after a failed download), as the app keeps it
                let run = FixRunState(step: .checking, doing: "Updating", startedAt: now.addingTimeInterval(-40),
                                      endedAt: now.addingTimeInterval(-30), command: batch.batches[i].command)
                rows[f.id] = FixRowState(availability: o.isResolved ? nil : rows[f.id]?.availability, progress: .finished(o),
                                         run: o == .needsPassword || o.canRetry ? run : nil)
                if o.isResolved { resolved.append(f.id) }
            }
        }
        func all(_ i: Int, in batch: FixAllState, _ o: (Finding) -> FixOutcome) -> [String: FixOutcome] {
            Dictionary(uniqueKeysWithValues: batch.batches[i].findings.map { ($0.id, o($0)) })
        }
        func fixed(_ f: Finding) -> FixOutcome { f.malicious ? .removed : .fixed(now: f.fixedVersion ?? "") }
        func index(_ id: String, in batch: FixAllState) -> Int { batch.batches.firstIndex { $0.findings.contains { $0.id == id } }! }

        switch name {
        case "all-button":
            return FixAllScene(scene: scene(), panel: panel(nil))

        case "all-waiting":
            // one fix running from its own row: Fix all waits, and says why under the button
            rows[FixID.nginx] = fixRunning[FixID.nginx]!
            return FixAllScene(scene: scene(open: [FixID.nginx]), panel: panel(nil, waiting: "nginx"))

        case "all-review":
            // torch's partial fix ticked: it joins Python 3.11's batch; starlette's upgrade together left unticked
            let ticked = FixAll.review(fixAllReport(), fixes: rows, ticked: [FixAllID.torch311])
            return FixAllScene(scene: scene(), panel: panel(ticked))

        case "all-running":
            // the removal done; batch 2, Homebrew's formulae, done; batch 3, the casks, updating with its live log
            var batch = review, resolved: [String] = []
            batch.phase = .running
            for i in 0..<2 { finish(&batch, i, all(i, in: batch, fixed), resolved: &resolved); batch.batches[i].status = .done }
            let i = index(FixID.openmtp, in: batch)
            batch.current = i
            batch.batches[i].status = .running
            batch.changedSomething = true
            let run = FixRunState(step: .running, doing: "Updating", startedAt: Date().addingTimeInterval(-38), log: caskLog,
                                  command: batch.batches[i].command)
            for f in batch.batches[i].findings { rows[f.id] = FixRowState(availability: rows[f.id]?.availability, progress: .running, run: run) }
            return FixAllScene(scene: scene(resolved: resolved), panel: panel(batch, resolved: resolved, waiting: batch.batches[i].label, run: run))

        case "all-isolated":
            // Python 3.11's nine together broke httpx: put back, now one at a time; three done, aiohttp running
            var batch = review, resolved: [String] = []
            batch.phase = .running
            batch.changedSomething = true
            let p = index(python311Packages[0].id, in: batch)
            for i in 0..<p { finish(&batch, i, all(i, in: batch, fixed), resolved: &resolved); batch.batches[i].status = .done }
            batch.current = p
            batch.batches[p].status = .running
            let k = batch.batches[p].items.firstIndex { $0.id == FixAllID.aiohttp }!
            batch.batches[p].stage = .oneByOne(next: k, why: "it broke httpx 0.27.0")
            var done: [String: FixOutcome] = [:]
            for item in batch.batches[p].items[..<k] { for f in item.findings { done[f.id] = fixed(f) } }
            finish(&batch, p, done, resolved: &resolved)
            let run = FixRunState(step: .running, doing: "Updating", startedAt: Date().addingTimeInterval(-12), log: pipOneLog,
                                  command: batch.batches[p].items[k].plan.command)
            rows[FixAllID.aiohttp] = FixRowState(availability: rows[FixAllID.aiohttp]?.availability, progress: .running, run: run)
            return FixAllScene(scene: scene(resolved: resolved), panel: panel(batch, resolved: resolved, waiting: "aiohttp", run: run))

        case "all-summary":
            // every batch had its turn: OpenMTP needs a password, Visual Studio Code had nothing newer when its turn came,
            // Python 3.11 broke httpx together and was put back, then ran one at a time (aiohttp broke it again on its
            // own, and was put back); torch's partial fix landed; the rest are fixed
            var batch = FixAll.review(fixAllReport(), fixes: rows, ticked: [FixAllID.torch311]), resolved: [String] = []
            batch.phase = .done
            batch.ending = .finished
            for i in batch.batches.indices {
                var outcomes = all(i, in: batch, fixed)
                for id in outcomes.keys {
                    switch id {
                    case FixID.openmtp: outcomes[id] = .needsPassword
                    case FixID.vscode: outcomes[id] = .blocked("Homebrew has no newer Visual Studio Code than 1.107.0, the one installed")
                    case FixAllID.aiohttp: outcomes[id] = .putBack("httpx 0.27.0")
                    case FixAllID.torch311: outcomes[id] = .partlyFixed(now: "2.8.0", remain: 8)
                    default: break
                    }
                }
                if batch.batches[i].findings.contains(where: { $0.id == FixAllID.aiohttp }) {
                    batch.batches[i].stage = .oneByOne(next: batch.batches[i].items.count, why: "it broke httpx 0.27.0")
                }
                finish(&batch, i, outcomes, resolved: &resolved)
                batch.batches[i].status = .done
            }
            return FixAllScene(scene: scene(resolved: resolved), panel: panel(batch, resolved: resolved))

        default:
            return nil
        }
    }

    // MARK: Rows

    public static let proposalSceneNames = ["proposals", "partly"]

    /// Rows open: torch's partial fix and starlette's upgrade together, each with its button; Dropbox, whose cask has
    /// nothing newer than the app it would replace; Zoom, whose update needs a password; and the partial fix done, with
    /// starlette's upgrade together under review.
    public static func proposalScene(_ name: String) -> (scene: FixScene, panel: FixAllPanel)? {
        var rows = fixAllRows
        func panel(_ shown: [String]) -> FixAllPanel {
            let findings = sceneFindings.filter { shown.contains($0.id) }
            return FixAllPanel(count: FixAll.offered(findings, fixes: rows).count, breakdown: FixAll.breakdown(findings, fixes: rows)?.line)
        }
        let shown = [FixAllID.torch311, FixID.starlette, FixAllID.dropbox, FixID.openmtp, FixAllID.zoom]
        switch name {
        case "proposals":
            rows[FixID.openmtp] = FixRowState(availability: .withheld(HomebrewAvailability.newestInstalled(electron: "Electron 18.3.15")), hold: .noFix)
            return (FixScene(fixes: rows, resolved: [], open: Set(shown), shown: shown), panel(shown))
        case "partly":
            rows[torch311After.id] = FixRowState(availability: .withheld(torchWhy), progress: .finished(.partlyFixed(now: "2.8.0", remain: 8)),
                                                 hold: .blocked)
            rows[torch311After.id]?.run = FixRunState(step: .checking, doing: "Updating", startedAt: now.addingTimeInterval(-95),
                                                      endedAt: now.addingTimeInterval(-3), log: FixLog(["Successfully installed torch-2.8.0 torchaudio-2.8.0"]),
                                                      command: torchPartial.plan.command + " torchaudio==2.8.0")
            var preview = FixPreview(source: "pip install --dry-run --report (asks PyPI about starlette, fastapi, prometheus-fastapi-instrumentator, installs nothing)",
                                     lines: ["Would install starlette 1.3.1, fastapi 0.135.2, prometheus-fastapi-instrumentator 7.2.0"],
                                     installs: ["starlette": "1.3.1", "fastapi": "0.135.2", "prometheus-fastapi-instrumentator": "7.2.0"],
                                     pins: ["starlette==1.3.1", "fastapi==0.135.2", "prometheus-fastapi-instrumentator==7.2.0"])
            preview.asks = ["starlette", "fastapi", "prometheus-fastapi-instrumentator"]
            rows[FixID.starlette]?.preview = .ready(preview)
            let partly = [torch311After.id, FixID.starlette]
            return (FixScene(fixes: rows, resolved: [], open: Set(partly), shown: partly), panel(partly))
        default:
            return nil
        }
    }
}

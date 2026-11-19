import Foundation
import OSVAKit

/// Fix all's fixtures, for `osva-render`: the header's button, the review, a run at step 3 of 7, a run stopped by a
/// step that broke something, and the summary, on the fix scenes' findings plus two Python packages that one
/// `brew upgrade jupyterlab` fixes together (one step, run once).
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

    public enum FixAllID {
        public static let tornado = "pkg|PyPI|tornado|6.4.1|py3.13.9", jinja2 = "pkg|PyPI|jinja2|3.1.4|py3.13.9"
    }

    /// One Fix all state on its findings: the panel's rows, and Fix all's button and card.
    public struct FixAllScene: Sendable {
        public var scene: FixScene
        public var panel: FixAllPanel
    }

    public static let fixAllSceneNames = ["all-button", "all-waiting", "all-review", "all-running", "all-broke", "all-summary"]

    /// Every row as the app decides it: the plans FixPlan makes, with Homebrew's answers and pip's dependents as the
    /// fixture offers have them, and the refusals (Apple's Ruby and Python, Homebrew without the fix, a dependent that
    /// pins starlette, a project's lockfile, no command at all).
    public static var fixAllRows: [String: FixRowState] {
        var rows: [String: FixRowState] = [:]
        for f in fixFindings {
            switch FixPlan.make(for: f, tools: fixtureTools) {
            case let .success(plan): rows[f.id] = FixRowState(availability: .offered(FixOffer(plan: plan)))
            case let .failure(refusal): rows[f.id] = FixRowState(availability: .withheld(refusal.explanation))
            }
        }
        rows.merge(fixOffers) { _, fixture in fixture }
        let jupyterlab = "Has jupyterlab 4.5.1; 4.4.0 is installed. Whether that brings the fix shows when the app checks again."
        rows[FixID.openssh] = FixRowState(availability: .offered(offer(FixID.openssh, homebrew: "Has 10.6p2.")))
        rows[FixID.vscode] = FixRowState(availability: .offered(offer(FixID.vscode, homebrew: "Has Visual Studio Code 1.107.0; 1.106.2 is installed.")))
        rows[FixID.torch] = FixRowState(availability: .offered(offer(FixID.torch, companions: ["torchaudio"])))
        rows[FixAllID.tornado] = FixRowState(availability: .offered(offer(FixAllID.tornado, homebrew: jupyterlab)))
        rows[FixAllID.jinja2] = FixRowState(availability: .offered(offer(FixAllID.jinja2, homebrew: jupyterlab)))
        return rows
    }

    static var fixAllShown: [String] { fixFindings.map(\.id) }

    static func fixAllReport(resolved: [String] = []) -> [Finding] {
        fixFindings.filter { !resolved.contains($0.id) }
    }

    /// The review as the app makes it from these rows.
    public static var fixAllReview: FixAllState { FixAll.review(fixAllReport(), fixes: fixAllRows) }

    static let caskLog = FixLog(["==> Auto-updating Homebrew...", "==> Fetching downloads for: openmtp", "==> Upgrading 1 outdated package:",
                                 "openmtp 3.2.24 -> 3.2.25"], partial: "==> Moving App 'OpenMTP.app' to '/Applications/OpenMTP.app'")

    public static func fixAllScene(_ name: String) -> FixAllScene? {
        var rows = fixAllRows
        let review = fixAllReview
        func panel(_ batch: FixAllState?, resolved: [String] = [], waiting: String? = nil, run: FixRunState? = nil, undo: PipUndo? = nil) -> FixAllPanel {
            let standing = fixFindings.filter { !resolved.contains($0.id) }
            return FixAllPanel(count: FixAll.offered(standing, fixes: rows).count, waitingFor: waiting, batch: batch, run: run, undo: undo)
        }
        func scene(resolved: [String] = [], open: Set<String> = []) -> FixScene {
            FixScene(fixes: rows, resolved: resolved, open: open, shown: fixAllShown)
        }
        /// The step's findings, done as the outcomes say (fixed and removed rows leave the report).
        func finish(_ batch: inout FixAllState, _ i: Int, _ outcomes: [FixOutcome], resolved: inout [String]) {
            for (f, o) in zip(batch.steps[i].findings, outcomes) {
                batch.steps[i].outcomes[f.id] = o
                // a row that did not end fixed keeps its offer (Retry after a failed download), as the app keeps it
                let run = FixRunState(step: .checking, doing: batch.steps[i].plan.doing, startedAt: now.addingTimeInterval(-40),
                                      endedAt: now.addingTimeInterval(-30), command: batch.steps[i].plan.command)
                rows[f.id] = FixRowState(availability: o.isResolved ? nil : rows[f.id]?.availability, progress: .finished(o),
                                         run: o == .needsPassword || o.canRetry ? run : nil)
                if o.isResolved || { if case .broke = o { true } else { false } }() { resolved.append(f.id) }
            }
            batch.steps[i].status = .done
        }
        func index(_ id: String, in batch: FixAllState) -> Int { batch.steps.firstIndex { $0.findings.contains { $0.id == id } }! }

        switch name {
        case "all-button":
            return FixAllScene(scene: scene(), panel: panel(nil))

        case "all-waiting":
            // one fix running from its own row: Fix all waits, and says why under the button
            rows[FixID.nginx] = fixRunning[FixID.nginx]!
            return FixAllScene(scene: scene(open: [FixID.nginx]), panel: panel(nil, waiting: "nginx"))

        case "all-review":
            return FixAllScene(scene: scene(), panel: panel(review))

        case "all-running":
            // step 3 of 7: axios removed, OpenSSH fixed, OpenMTP updating with its live log
            var batch = review, resolved: [String] = []
            batch.phase = .running
            finish(&batch, index(FixID.axios, in: batch), [.removed], resolved: &resolved)
            finish(&batch, index(FixID.openssh, in: batch), [.fixed(now: "10.6p2")], resolved: &resolved)
            let i = index(FixID.openmtp, in: batch)
            batch.current = i
            batch.steps[i].status = .running
            batch.changedSomething = true
            let run = FixRunState(step: .running, doing: "Updating", startedAt: Date().addingTimeInterval(-38), log: caskLog,
                                  command: "brew upgrade --cask openmtp")
            rows[FixID.openmtp] = FixRowState(availability: rows[FixID.openmtp]?.availability, progress: .running, run: run)
            return FixAllScene(scene: scene(resolved: resolved), panel: panel(batch, resolved: resolved, waiting: "OpenMTP", run: run))

        case "all-broke":
            // starlette's upgrade brought anyio 5, which httpx cannot take: Fix all stops there, with Undo
            rows[FixID.starlette] = FixRowState(availability: .offered(offer(FixID.starlette)))
            var batch = FixAll.review(fixAllReport(), fixes: rows), resolved: [String] = []
            batch.phase = .done
            let s = index(FixID.starlette, in: batch)
            for i in 0..<s {
                finish(&batch, i, batch.steps[i].findings.map { $0.malicious ? .removed : .fixed(now: $0.fixedVersion ?? "") }, resolved: &resolved)
            }
            finish(&batch, s, [.broke("httpx 0.27.0")], resolved: &resolved)
            for i in (s + 1)..<batch.steps.count { batch.steps[i].status = .notRun }
            batch.ending = .broke(step: s, what: "httpx 0.27.0")
            let undo = PipUndo(invocation: FixInvocation(executable: python311.executable,
                                                         arguments: ["-m", "pip", "install", "--no-deps", "--disable-pip-version-check",
                                                                     "anyio==4.0.0", "starlette==0.48.0"]),
                               restores: ["anyio 4.0.0", "starlette 0.48.0"])
            rows[FixID.starlette] = FixRowState(progress: .finished(.broke("httpx 0.27.0")),
                                                run: FixRunState(step: .checking, doing: "Updating", startedAt: now.addingTimeInterval(-14),
                                                                 endedAt: now.addingTimeInterval(-6),
                                                                 log: FixLog(["Successfully installed anyio-5.0.0 starlette-1.3.1"]),
                                                                 command: starlette.upgradeCommand!, undo: undo))
            return FixAllScene(scene: scene(resolved: resolved), panel: panel(batch, resolved: resolved, undo: undo))

        case "all-summary":
            // every step had its turn: OpenMTP needs a password, Visual Studio Code was no longer valid when its turn
            // came, torch's download failed; the rest are fixed
            var batch = review, resolved: [String] = []
            batch.phase = .done
            batch.ending = .finished
            for i in batch.steps.indices {
                let step = batch.steps[i]
                switch step.id {
                case FixID.openmtp: finish(&batch, i, [.needsPassword], resolved: &resolved)
                case FixID.torch: finish(&batch, i, [.exitedWithError(1)], resolved: &resolved)
                case FixID.vscode:
                    let why = "Homebrew has no newer Visual Studio Code than 1.107.0, the one installed"
                    finish(&batch, i, [.blocked(why)], resolved: &resolved)
                    batch.steps[i].status = .skipped(why)
                    rows[FixID.vscode]?.availability = .withheld(why + ".")          // as Preparing decided it
                default:
                    finish(&batch, i, step.findings.map { $0.malicious ? .removed : .fixed(now: $0.fixedVersion ?? "") }, resolved: &resolved)
                }
            }
            return FixAllScene(scene: scene(resolved: resolved), panel: panel(batch, resolved: resolved))

        default:
            return nil
        }
    }
}

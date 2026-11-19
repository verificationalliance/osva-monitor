import Foundation
import Testing
import OSVAKit
@testable import OSVAMonitorUI

/// The whole loop of a fix, as the app runs it, with only Terminal replaced: Fix… opens the confirmation, Run writes
/// the script and hands it to "Terminal" (here: run at once, without a window and without waiting for a key), the
/// script leaves its result file, the app sees it, checks the finding again, and the row says what happened. The
/// tool is a stand-in npm that records what it was asked and changes the version it reports.
@MainActor @Suite struct FixLoopTests {
    /// Runs the script as Terminal would, minus the window and the key.
    struct ScriptRunner: TerminalOpener {
        func open(_ script: URL, completion: @escaping @Sendable (String?) -> Void) {
            DispatchQueue.global().async {
                let p = Process()
                p.executableURL = script
                p.environment = ["PATH": "/usr/bin:/bin", FixScript.noWaitVariable: "1"]
                p.standardInput = FileHandle.nullDevice
                p.standardOutput = FileHandle.nullDevice
                p.standardError = FileHandle.nullDevice
                do { try p.run(); completion(nil) } catch { completion(error.localizedDescription) }
            }
        }
    }

    struct Refused: TerminalOpener {
        func open(_ script: URL, completion: @escaping @Sendable (String?) -> Void) { completion("Terminal is not on this Mac") }
    }

    /// The site: an index that lists lodash, and a batch answer with nothing to report about the version asked.
    final class Site: HTTPTransport, @unchecked Sendable {
        let lock = NSLock()
        var bodies: [String] = []
        func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
            let body: Data
            switch request.url!.path {
            case "/data/app-index.tsv": body = Data("#osva-app-index\t1\t2026-11-19T03:00:00Z\t1\t0\nK\tnpm\tlodash\n".utf8)
            case "/api/v1/check/batch":
                lock.withLock { bodies.append(String(decoding: request.httpBody ?? Data(), as: UTF8.self)) }
                body = Data(#"{"checked":1,"packages":[]}"#.utf8)
            default: body = Data("{}".utf8)
            }
            return (body, HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: [:])!)
        }
    }

    struct Quiet: Notifier {
        var isAvailable: Bool { false }
        func requestPermission() async {}
        func post(_ findings: [Finding]) async {}
    }

    /// A temporary home with a stand-in npm in ~/.volta/bin, and a last scan that found lodash 4.17.20 there.
    func setUp(terminal: any TerminalOpener) throws -> (AppModel, Finding, URL, Site) {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("osva-fixloop-\(UUID().uuidString)", isDirectory: true)
        let bin = home.appendingPathComponent(".volta/bin", isDirectory: true)
        try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: true)
        let npm = bin.appendingPathComponent("npm")
        try Data("""
        #!/bin/sh
        state="$(dirname "$0")/lodash-version"
        case "$1" in
          install) printf '%s\\0' "$@" > "$(dirname "$0")/argv"; echo "${3##*@}" > "$state"; echo "changed 1 package" ;;
          ls) printf '{"dependencies":{"lodash":{"version":"%s"}}}' "$(cat "$state" 2>/dev/null || echo 4.17.20)" ;;
        esac

        """.utf8).write(to: npm)
        chmod(npm.path, 0o755)
        let tools = ToolEnvironment(home: home, base: ["PATH": "/usr/bin:/bin"], runner: ProcessRunner(),
                                    isExecutable: { $0.hasPrefix(home.path) && FileManager.default.isExecutableFile(atPath: $0) })
        let inputs = UpgradeCommand.Inputs(origin: .npmGlobal(npm: npm.path), name: "lodash", ecosystem: .npm, target: "4.17.21", malicious: false)
        let finding = Finding(id: "pkg|npm|lodash|4.17.20", group: .criticalHigh, subject: .package(ecosystem: .npm, name: "lodash"), title: "lodash",
                              installedVersion: "4.17.20", fixedVersion: "4.17.21", severity: .high, advisoryIDs: ["GHSA-35jh-r3h4-6jhm"], flawCount: 1,
                              exploited: false, malicious: false, note: nil, bigIssue: nil, origins: [inputs.origin],
                              pageURL: SiteURL.packagePage(.npm, "lodash", version: "4.17.20"), upgradeCommand: UpgradeCommand.advice(inputs).command,
                              verification: .none, grade: nil, commandInputs: inputs)
        let storage = Storage(directory: home.appendingPathComponent("support", isDirectory: true))
        storage.save(ScanReport(startedAt: Date(), finishedAt: Date(), inventory: Inventory(packages: [
            InstalledPackage(ecosystem: .npm, name: "lodash", version: "4.17.20", origin: inputs.origin)]), findings: [finding], sent: SentRecord(),
                                indexGeneratedAt: nil, problems: []))
        let site = Site()
        let model = AppModel(storage: storage, notifier: Quiet(), tools: tools, transport: site)
        model.terminal = terminal
        return (model, finding, bin, site)
    }

    func waitUntil(_ condition: () -> Bool) async throws {
        for _ in 0..<300 where !condition() { try await Task.sleep(for: .milliseconds(50)) }
    }

    @Test func fixRunsInTerminalAndTheRowSaysFixed() async throws {
        let (model, finding, bin, site) = try setUp(terminal: ScriptRunner())
        model.assessFix(finding)
        guard case let .offered(offer)? = model.fixes[finding.id]?.availability else { Issue.record("no Fix button"); return }
        #expect(offer.plan.command == "\(bin.path)/npm install -g lodash@4.17.21")

        model.beginFix(finding)
        try await waitUntil { model.fixes[finding.id]?.preview != .loading }
        #expect(model.fixes[finding.id]?.preview == .ready(.none("npm has no dry run the app uses: the Terminal window shows what changes.")))

        model.runFix(finding)
        #expect(model.fixes[finding.id]?.progress == .running && model.fixes[finding.id]?.preview == nil)
        try await waitUntil { if case .finished? = model.fixes[finding.id]?.progress { true } else { false } }

        #expect(model.fixes[finding.id]?.progress == .finished(.fixed(now: "4.17.21")))
        let argv = try String(contentsOf: bin.appendingPathComponent("argv"), encoding: .utf8).split(separator: "\0").map(String.init)
        #expect(argv == ["install", "-g", "lodash@4.17.21"])                               // what ran is what was shown
        #expect(site.lock.withLock { site.bodies } == [#"{"packages":[{"ecosystem":"npm","name":"lodash","platform":"macos","version":"4.17.21"}]}"#])
        #expect(model.report?.findings.isEmpty == true && model.resolved.map(\.id) == [finding.id])
        let content = model.popoverContent
        #expect(content.hero == .clean && content.sections.first?.findings.map(\.id) == [finding.id] && content.sections.first?.count == 0)
        // nothing is left behind: the script deleted itself, and the result was taken
        let support = Storage(directory: bin.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("support")).directory
        #expect((try FileManager.default.contentsOfDirectory(atPath: support.appendingPathComponent("fixes").path)).isEmpty)
        #expect((try FileManager.default.contentsOfDirectory(atPath: support.appendingPathComponent("fix-results").path)).isEmpty)
    }

    @Test func nothingRunsWithoutTheConfirmation() throws {
        let (model, finding, bin, _) = try setUp(terminal: ScriptRunner())
        model.assessFix(finding)
        model.runFix(finding)                                                      // Run without Fix… first: ignored
        #expect(model.fixes[finding.id]?.progress == nil)
        #expect(!FileManager.default.fileExists(atPath: bin.appendingPathComponent("argv").path))
    }

    @Test func whenTerminalCannotOpenTheRowSaysSo() async throws {
        let (model, finding, _, _) = try setUp(terminal: Refused())
        model.assessFix(finding)
        model.beginFix(finding)
        model.runFix(finding)
        try await waitUntil { if case .finished? = model.fixes[finding.id]?.progress { true } else { false } }
        #expect(model.fixes[finding.id]?.progress == .finished(.couldNotOpen("Terminal is not on this Mac")))
        #expect(model.report?.findings.map(\.id) == [finding.id])                     // nothing changed
    }
}

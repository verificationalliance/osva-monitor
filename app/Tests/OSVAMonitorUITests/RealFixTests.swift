import Foundation
import Testing
import OSVAKit
@testable import OSVAMonitorUI

/// A real fix, through the app's own loop, on this Mac: Homebrew's Python 3.11 (not externally managed, like the one
/// on the owner's Mac), a real `pip install --user --upgrade six==1.17.0` from PyPI after its real dry run, `pip check`
/// before and after, with the user site moved to a throwaway folder (PYTHONUSERBASE) so nothing of anyone's changes.
/// Off by default (it needs the network and that Python); `OSVA_REAL_FIX=1 swift test --filter RealFixTests` runs it
/// and prints each state the row goes through, with the log as it streams. (Apple's Python is not used: the app
/// leaves it to macOS.)
@MainActor @Suite(.enabled(if: ProcessInfo.processInfo.environment["OSVA_REAL_FIX"] != nil)) struct RealFixTests {
    final class Site: HTTPTransport, @unchecked Sendable {
        func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
            let body: Data
            switch request.url!.path {
            case "/data/app-index.tsv": body = Data("#osva-app-index\t1\t2026-11-19T03:00:00Z\t1\t0\nK\tPyPI\tsix\n".utf8)
            case "/api/v1/check/batch":
                // six 1.16.0 is "vulnerable" for the test, fixed in 1.17.0; anything else has nothing to report
                let asked = String(decoding: request.httpBody ?? Data(), as: UTF8.self)
                let six = #"{"ecosystem":"PyPI","name":"six","version":"1.16.0","malicious":false,"distinct_flaws":1,"worst_severity":"HIGH","advisories":["TEST-1"],"flaws":[{"id":"TEST-1","severity":"HIGH","fixed_in":["1.17.0"],"ranges":[{"fixed":"1.17.0"}]}],"plan":{"target":"1.17.0","fixes":["TEST-1"],"remaining":[]}}"#
                body = Data((#"{"checked":1,"packages":["# + (asked.contains(#""version":"1.16.0""#) ? six : "") + "]}").utf8)
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

    static let python3 = "/opt/homebrew/bin/python3.11"

    func python(_ args: [String], env: [String: String]) throws -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: Self.python3)
        p.arguments = args
        p.environment = env
        let out = Pipe()
        p.standardOutput = out; p.standardError = out
        try p.run()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
    }

    @Test func aRealPipUpgradeRunsInTheAppAndTheRowSaysFixed() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("osva-realfix-\(UUID().uuidString)", isDirectory: true)
        let userBase = root.appendingPathComponent("userbase").path
        var env = ProcessInfo.processInfo.environment
        env["PYTHONUSERBASE"] = userBase
        env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
        // the starting point: six 1.16.0 in the throwaway user site
        print(try python(["-m", "pip", "install", "--user", "--quiet", "six==1.16.0"], env: env))
        let userSite = try python(["-c", "import site; print(site.getusersitepackages())"], env: env).trimmingCharacters(in: .whitespacesAndNewlines)
        print("user site:", userSite)

        let tools = ToolEnvironment(base: env)
        let version = try python(["-c", "import platform; print(platform.python_version())"], env: env).trimmingCharacters(in: .whitespacesAndNewlines)
        let brewPython = PythonEnvironment(executable: Self.python3, version: version, kind: .homebrew, externallyManaged: false, userSite: userSite,
                                           formula: "python@3.11")
        let inputs = UpgradeCommand.Inputs(origin: .pip(python: brewPython, user: true, formula: nil), name: "six", ecosystem: .pypi, target: "1.17.0", malicious: false)
        let finding = Finding(id: "pkg|PyPI|six|1.16.0|py\(version)", group: .criticalHigh, subject: .package(ecosystem: .pypi, name: "six"), title: "six",
                              installedVersion: "1.16.0", fixedVersion: "1.17.0", severity: .high, advisoryIDs: ["TEST-1"], flawCount: 1, exploited: false,
                              malicious: false, note: nil, bigIssue: nil, origins: [inputs.origin], pageURL: SiteURL.packagePage(.pypi, "six", version: "1.16.0"),
                              upgradeCommand: UpgradeCommand.advice(inputs).command, verification: .none, grade: nil, commandInputs: inputs)
        let storage = Storage(directory: root.appendingPathComponent("support", isDirectory: true))
        storage.save(ScanReport(startedAt: Date(), finishedAt: Date(), inventory: Inventory(packages: [
            InstalledPackage(ecosystem: .pypi, name: "six", version: "1.16.0", origin: inputs.origin)]), findings: [finding], sent: SentRecord(),
                                indexGeneratedAt: nil, problems: []))
        let model = AppModel(storage: storage, notifier: Quiet(), tools: tools, transport: Site())
        func state() -> FixRowState? { model.fixes[finding.id] }
        func wait(_ what: String, _ condition: () -> Bool) async throws {
            for _ in 0..<1200 where !condition() { try await Task.sleep(for: .milliseconds(100)) }
            #expect(condition(), "waited for \(what)")
        }

        print("command:", finding.upgradeCommand ?? "-")
        model.assessFix(finding)
        try await wait("the button") { state()?.availability != .checking }
        guard case let .offered(offer)? = state()?.availability else { Issue.record("no button: \(String(describing: state()))"); return }
        print("offer:", offer.plan.actionTitle, "| argv:", offer.plan.invocation.argv)
        model.beginFix(finding)
        try await wait("the review") { state()?.preview != .loading }
        guard case let .ready(p)? = state()?.preview else { Issue.record("no review"); return }
        print("review:", offer.plan.summary, "| dry run:", p.unavailable ?? p.lines.joined(separator: "; "), "| blocked:", p.blocked ?? "no",
              "| pins:", p.pins)
        #expect(p.blocked == nil && p.installs == ["six": "1.17.0"])

        model.runFix(finding)
        let start = Date()
        var seen: [String] = [], snapshots = 0, lastLog: FixLog?
        while true {
            guard let s = state() else { break }
            if let run = s.run {
                if run.log != lastLog, run.step == .running { snapshots += 1; lastLog = run.log }
                let key = "\(run.step) \(run.log.all.last ?? "")"
                if seen.last != key {
                    seen.append(key)
                    print(String(format: "%5.1fs  %-9@ %@", Date().timeIntervalSince(start), "\(run.step)" as NSString, (run.log.all.last ?? "") as NSString))
                }
            }
            if case .finished? = s.progress { break }
            if Date().timeIntervalSince(start) > 300 { Issue.record("no end after 5 minutes"); break }
            try await Task.sleep(for: .milliseconds(100))
        }
        let end = try #require(state())
        print("outcome:", end.outcome?.text ?? "-")
        print("log:\n" + (end.run?.log.text ?? ""))
        // 1.16 to 1.17 is more than a patch: if anything installed uses six, the row also says to check it
        switch end.outcome {
        case .fixed(now: "1.17.0")?, .fixedCheck(now: "1.17.0", _)?: break
        default: Issue.record("outcome: \(String(describing: end.outcome))")
        }
        #expect(end.run?.log.lines.contains { $0.hasPrefix("Successfully installed six-1.17.0") } == true)
        #expect(snapshots >= 1)
        let installed = PythonSite.read(folders: [userSite]).first { $0.key == "six" }?.version
        #expect(installed == "1.17.0")
        try? FileManager.default.removeItem(at: root)
    }
}

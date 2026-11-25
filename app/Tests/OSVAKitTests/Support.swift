import Foundation
@testable import OSVAKit

/// Recorded fixtures (Tests/OSVAKitTests/Fixtures).
enum Fixture {
    static var root: URL { Bundle.module.resourceURL!.appendingPathComponent("Fixtures", isDirectory: true) }
    /// Fixture lockfiles are stored as `<name>.fixture`, so GitHub's dependency graph does not read deliberately old test
    /// data as this repository's dependencies; tests see them under their real names in a copy made once per run.
    static let lockfiles: URL = {
        let copy = FileManager.default.temporaryDirectory.appendingPathComponent("osva-lockfiles-\(UUID().uuidString)", isDirectory: true)
        let source = root.appendingPathComponent("lockfiles", isDirectory: true)
        // Paths relative to `source`, from the enumerator itself: the URLs it gives have symlinks resolved, so under /tmp
        // or /var they start /private/… while `source` does not, and cutting `source.path` off them would be off.
        let files = FileManager.default.enumerator(atPath: source.path)!
        for case let relative as String in files {
            let file = source.appendingPathComponent(relative)
            guard (try? file.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true else { continue }
            let name = relative.hasSuffix(".fixture") ? String(relative.dropLast(".fixture".count)) : relative
            let target = copy.appendingPathComponent(name)
            try! FileManager.default.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
            try! FileManager.default.copyItem(at: file, to: target)
        }
        return copy
    }()
    static func url(_ path: String) -> URL {
        if path == "lockfiles" || path.hasPrefix("lockfiles/") { return lockfiles.appendingPathComponent(String(path.dropFirst("lockfiles".count)).trimmingCharacters(in: CharacterSet(charactersIn: "/"))) }
        return root.appendingPathComponent(path)
    }
    static func data(_ path: String) -> Data { try! Data(contentsOf: url(path)) }
    static func text(_ path: String) -> String { String(decoding: data(path), as: UTF8.self) }
    static let index: PublicIndex = try! PublicIndex.decode(data("api/app-index.tsv"))

    static let applePython = PythonEnvironment(executable: "/usr/bin/python3", version: "3.9.6", kind: .apple, externallyManaged: false,
                                               userSite: "/Users/ana/Library/Python/3.9/lib/python/site-packages", formula: nil)
    static let pythonOrg = PythonEnvironment(executable: "/Library/Frameworks/Python.framework/Versions/3.13/bin/python3", version: "3.13.1",
                                             kind: .pythonOrg, externallyManaged: false, userSite: "/Users/ana/Library/Python/3.13/lib/python/site-packages",
                                             formula: nil)
    static let homebrewPython = PythonEnvironment(executable: "/opt/homebrew/bin/python3", version: "3.15.2", kind: .homebrew, externallyManaged: true,
                                                  userSite: "/Users/ana/Library/Python/3.15/lib/python/site-packages", formula: "python@3.15")
}

/// Answers requests from recorded responses and remembers every request.
final class RecordedTransport: HTTPTransport, @unchecked Sendable {
    struct Reply { var status: Int; var headers: [String: String] = [:]; var body: Data }
    private let lock = NSLock()
    private var _requests: [URLRequest] = []
    private let route: @Sendable (URLRequest, Int) -> Reply

    /// `route` gets the request and how many requests came before it.
    init(route: @escaping @Sendable (URLRequest, Int) -> Reply) { self.route = route }

    var requests: [URLRequest] { lock.withLock { _requests } }

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let n = lock.withLock { () -> Int in _requests.append(request); return _requests.count - 1 }
        let reply = route(request, n)
        let response = HTTPURLResponse(url: request.url!, statusCode: reply.status, httpVersion: "HTTP/1.1", headerFields: reply.headers)!
        return (reply.body, response)
    }

    /// Serves the site from the recorded fixtures; `projects` names another fixture for a project's record.
    static func site(batch: String = "api/check-batch.json", projects: [String: String] = [:]) -> RecordedTransport {
        RecordedTransport { request, _ in
            let path = request.url!.path
            switch path {
            case "/data/app-index.tsv": return Reply(status: 200, headers: ["ETag": "\"v1\""], body: Fixture.data("api/app-index.tsv"))
            case "/api/v1/check/batch": return Reply(status: 200, body: Fixture.data(batch))
            case "/api/v1/state": return Reply(status: 200, body: Fixture.data("api/state.json"))
            default:
                if path.hasPrefix("/api/v1/project/") {
                    let slug = String(path.dropFirst("/api/v1/project/".count))
                    if let data = try? Data(contentsOf: Fixture.url(projects[slug] ?? "api/project-\(slug).json")) { return Reply(status: 200, body: data) }
                    return Reply(status: 404, body: Data(#"{"error":"unknown project"}"#.utf8))
                }
                return Reply(status: 404, body: Data(#"{"error":"not found"}"#.utf8))
            }
        }
    }
}

/// Answers tool invocations from recorded output, keyed by "<tool> <arguments>".
struct RecordedRunner: CommandRunner {
    var outputs: [String: CommandResult]
    func run(_ executable: String, _ arguments: [String], environment: [String: String], timeout: TimeInterval) async throws -> CommandResult {
        result(for: ([executable] + arguments).joined(separator: " "))
    }
    private func result(for key: String) -> CommandResult {
        outputs[key] ?? CommandResult(status: 127, stdout: Data(), stderr: Data("not recorded: \(key)".utf8))
    }
}

extension ToolEnvironment {
    /// A Mac made of the test's own folders: `home` is its home folder and `home`/system-root its "/" (`systemRoot`),
    /// and it has none of this process's environment variables. A scan with it reads nothing machine-wide of the Mac
    /// the tests run on: no JDK in /Library/Java/JavaVirtualMachines or Homebrew's opt (CI's macOS runners have both),
    /// no Nix profile, no Python.
    static func fixture(home: URL, base: [String: String] = [:], runner: any CommandRunner = RecordedRunner(outputs: [:]),
                        isExecutable: @escaping @Sendable (String) -> Bool = { _ in false }) -> ToolEnvironment {
        var tools = ToolEnvironment(home: home, base: base, runner: runner, isExecutable: isExecutable)
        tools.systemRoot = home.appendingPathComponent("system-root", isDirectory: true).path
        return tools
    }
}

/// A fresh temporary directory, removed when the test process ends.
func temporaryDirectory(_ name: String = #function) -> URL {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("osva-tests-\(ProcessInfo.processInfo.processIdentifier)", isDirectory: true)
        .appendingPathComponent(name.filter { $0.isLetter || $0.isNumber } + "-" + UUID().uuidString, isDirectory: true)
    try! FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

func write(_ text: String, to url: URL) {
    try! FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    try! Data(text.utf8).write(to: url)
}

/// Approves packages through the real privacy filter (the only way to get ApprovedPackage values).
func approved(_ packages: [(Ecosystem, String, String)], index: PublicIndex = Fixture.index) -> [ApprovedPackage: [InstalledPackage]] {
    PrivacyFilter(index: index).approve(packages.map { InstalledPackage(ecosystem: $0.0, name: $0.1, version: $0.2, origin: .cargoInstall) }).approved
}

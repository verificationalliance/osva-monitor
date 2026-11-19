import Foundation
@testable import OSVAKit

/// Recorded fixtures (Tests/OSVAKitTests/Fixtures).
enum Fixture {
    static var root: URL { Bundle.module.resourceURL!.appendingPathComponent("Fixtures", isDirectory: true) }
    static func url(_ path: String) -> URL { root.appendingPathComponent(path) }
    static func data(_ path: String) -> Data { try! Data(contentsOf: url(path)) }
    static func text(_ path: String) -> String { String(decoding: data(path), as: UTF8.self) }
    static let index: PublicIndex = try! PublicIndex.decode(data("api/app-index.tsv"))

    static let applePython = PythonEnvironment(executable: "/usr/bin/python3", version: "3.9.6", kind: .apple, externallyManaged: false,
                                               userSite: "/Users/ana/Library/Python/3.9/lib/python/site-packages", formula: nil)
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

    /// Serves the site from the recorded fixtures.
    static func site(batch: String = "api/check-batch.json") -> RecordedTransport {
        RecordedTransport { request, _ in
            let path = request.url!.path
            switch path {
            case "/data/app-index.tsv": return Reply(status: 200, headers: ["ETag": "\"v1\""], body: Fixture.data("api/app-index.tsv"))
            case "/api/v1/check/batch": return Reply(status: 200, body: Fixture.data(batch))
            case "/api/v1/state": return Reply(status: 200, body: Fixture.data("api/state.json"))
            default:
                if path.hasPrefix("/api/v1/project/") {
                    let slug = String(path.dropFirst("/api/v1/project/".count))
                    if let data = try? Data(contentsOf: Fixture.url("api/project-\(slug).json")) { return Reply(status: 200, body: data) }
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

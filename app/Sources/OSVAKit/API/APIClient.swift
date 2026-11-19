import Foundation

/// The three API calls the app makes, each rate-limited, retried politely on 429, and recorded in "What leaves your
/// Mac". Calls that name installed software accept only values approved by the privacy filter.
public actor APIClient {
    public enum APIError: Error, LocalizedError, Equatable {
        case http(status: Int, message: String)
        case keptRateLimiting
        case undecodable(String)

        public var errorDescription: String? {
            switch self {
            case let .http(status, message): return "verificationalliance.org answered \(status)\(message.isEmpty ? "" : ": \(message)")"
            case .keptRateLimiting: return "verificationalliance.org kept asking the app to slow down; the rest waits for the next scan"
            case let .undecodable(what): return "Could not read verificationalliance.org's answer (\(what))"
            }
        }
    }

    /// The server's limit for one batch (`check_many` in server.py).
    public static let batchLimit = 200

    private let transport: any HTTPTransport
    private let limiter: RateLimiter
    private let pause: @Sendable (Duration) async -> Void
    private var sent: [SentRequest] = []

    public init(transport: any HTTPTransport, limiter: RateLimiter = RateLimiter(),
                pause: @escaping @Sendable (Duration) async -> Void = { try? await Task.sleep(for: $0) }) {
        self.transport = transport; self.limiter = limiter; self.pause = pause
    }

    /// POST api/v1/check/batch with up to 200 exact versions (with each PyPI package's Python, and the platform).
    /// Returns only the vulnerable or malicious ones, each with its flaws and upgrade plan.
    public func checkBatch(_ packages: [ApprovedPackage]) async throws -> [BatchResponse.Result] {
        precondition(!packages.isEmpty && packages.count <= Self.batchLimit, "A batch holds 1 to \(Self.batchLimit) packages.")
        var request = URLRequest(url: SiteURL.checkBatch)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try Self.batchBody(packages)
        record("POST api/v1/check/batch", packages.map(\.sentDescription))
        return try decode(BatchResponse.self, await send(request, budgets: [.check])).packages
    }

    /// POST api/v1/check/batch for one PyPI package, with the PEP 440 specifiers its plan's target must satisfy: a
    /// partial fix, when a dependent's specifier or a runtime boundary blocks the full one. The specifiers are versions
    /// and operators only (`PythonConstraints.isSendable`), never a name: the package itself was already approved, and
    /// nothing else about this Mac is named. Recorded in "What leaves your Mac" with what it named.
    public func checkWithin(_ package: ApprovedPackage, constraints: [String]) async throws -> BatchResponse.Result? {
        precondition(package.ecosystem == .pypi && !constraints.isEmpty && constraints.count <= PythonConstraints.maxSent
                     && constraints.allSatisfy(PythonConstraints.isSendable), "Constraints are 1 to 8 PEP 440 specifier sets.")
        var request = URLRequest(url: SiteURL.checkBatch)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try Self.batchBody([package], constraints: constraints)
        record("POST api/v1/check/batch", [package.sentDescription + " · within " + constraints.joined(separator: " and ")])
        return try decode(BatchResponse.self, await send(request, budgets: [.check])).packages.first
    }

    /// GET api/v1/project/<slug>.
    public func project(_ project: ApprovedProject) async throws -> ProjectResponse {
        record("GET api/v1/project", [project.sentDescription])
        return try decode(ProjectResponse.self, await send(URLRequest(url: SiteURL.project(project)), budgets: [.read]))
    }

    /// GET api/v1/product/<key>: an app's or a bundled library's record, with its recent advisories.
    public func product(_ product: ApprovedProduct) async throws -> ProductResponse {
        record("GET api/v1/product", [product.sentDescription])
        return try decode(ProductResponse.self, await send(URLRequest(url: SiteURL.product(product)), budgets: [.read]))
    }

    /// GET api/v1/state. Names nothing about this Mac.
    public func state() async throws -> StateResponse {
        try decode(StateResponse.self, await send(URLRequest(url: SiteURL.state), budgets: [.read]))
    }

    /// The requests that named installed software since the last call, merged per endpoint.
    public func takeSentRequests() -> [SentRequest] {
        defer { sent = [] }
        var merged: [SentRequest] = []
        for r in sent {
            if let i = merged.firstIndex(where: { $0.endpoint == r.endpoint && r.endpoint != "POST api/v1/check/batch" }) {
                merged[i].items += r.items
            } else {
                merged.append(r)
            }
        }
        return merged
    }

    static func batchBody(_ packages: [ApprovedPackage], constraints: [String]? = nil) throws -> Data {
        let body = BatchRequest(packages: packages.map {
            .init(ecosystem: $0.ecosystem.rawValue, name: $0.name, version: $0.version, python: $0.python, platform: $0.platform,
                  constraints: constraints)
        })
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(body)
    }

    private func record(_ endpoint: String, _ items: [String]) {
        sent.append(SentRequest(endpoint: endpoint, items: items))
    }

    private func send(_ request: URLRequest, budgets: [RateLimiter.Budget]) async throws -> Data {
        var request = request
        request.setValue(HTTPHeaders.userAgent, forHTTPHeaderField: "User-Agent")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        for attempt in 0..<5 {
            for b in budgets { await limiter.acquire(b) }
            let (data, response) = try await transport.send(request)
            switch response.statusCode {
            case 200..<300:
                return data
            case 429, 503:
                let asked = response.value(forHTTPHeaderField: "Retry-After").flatMap(Double.init)
                let seconds = min(asked ?? 5 * Double(1 << attempt), 120)
                await pause(.milliseconds(Int(seconds * 1000)))
            default:
                let message = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["error"] as? String
                throw APIError.http(status: response.statusCode, message: message ?? "")
            }
        }
        throw APIError.keptRateLimiting
    }

    private func decode<T: Decodable>(_ type: T.Type, _ data: Data) throws -> T {
        do { return try JSONDecoder().decode(type, from: data) }
        catch { throw APIError.undecodable(String(describing: type)) }
    }
}

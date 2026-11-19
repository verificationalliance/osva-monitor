import Foundation

/// Sends one HTTP request. The app uses `URLSessionTransport`; the tests replay recorded responses.
public protocol HTTPTransport: Sendable {
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

/// URLSession without cookies, credentials or a shared cache, so requests carry nothing beyond what we put in them.
public struct URLSessionTransport: HTTPTransport {
    private let session: URLSession

    public init() {
        let c = URLSessionConfiguration.ephemeral
        c.httpCookieStorage = nil
        c.httpShouldSetCookies = false
        c.urlCredentialStorage = nil
        c.urlCache = nil
        c.requestCachePolicy = .reloadIgnoringLocalCacheData
        c.timeoutIntervalForRequest = 30
        c.timeoutIntervalForResource = 120
        session = URLSession(configuration: c)
    }

    public func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw URLError(.badServerResponse) }
        return (data, http)
    }
}

public enum HTTPHeaders {
    /// Names the app and its version only: no OS, machine or locale.
    public static let userAgent = "OSVA-Monitor/0.1.0 (+https://verificationalliance.org/)"
}

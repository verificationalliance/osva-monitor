import Foundation
import OSVAKit

/// The site, for a fix's own questions (a partial fix's plan, the flaws of what an upgrade together moves): each asked
/// through a scanner of its own, with the scans' rate limiter, and what it named handed to `record` for "What leaves
/// your Mac".
struct AppFixServer: FixServer {
    let storage: Storage
    let tools: ToolEnvironment
    let transport: any HTTPTransport
    let limiter: RateLimiter
    let record: @Sendable ([SentRequest]) -> Void

    private func scanner() -> OSVAKit.Scanner {
        Scanner(configuration: ScanConfiguration(storage: storage, tools: tools, folders: [], applicationRoots: []), transport: transport, limiter: limiter)
    }

    func plan(_ finding: Finding, within constraints: [String]) async -> Result<BatchResponse.Result?, FixServerError> {
        let s = scanner()
        let answer = await s.plan(finding, within: constraints)
        record(await s.takeSentRequests())
        return answer
    }

    func flaws(_ versions: [PackageVersion], python: PythonEnvironment) async -> Result<[PackageVersion: BatchResponse.Result], FixServerError> {
        let s = scanner()
        let answer = await s.flaws(versions, python: python)
        record(await s.takeSentRequests())
        return answer
    }
}

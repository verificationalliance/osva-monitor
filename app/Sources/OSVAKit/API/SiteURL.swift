import Foundation

/// The URLs the app builds for the site, its API requests and its links to the site's pages: the fixed base
/// https://verificationalliance.org/ plus path components (and query values) encoded by the verified core, so that a
/// package name can never change which resource is asked for. Not every URL is one of these: the update feed is
/// Sparkle's (Info.plist), and a product's own page is the link its record gives (`ProductResponse.sourceURL`).
public enum SiteURL {
    public static let base = "https://verificationalliance.org/"

    /// base + "/"-joined encoded components [+ "?" encoded query].
    public static func resource(_ components: [String], query: [(String, String)] = []) -> URL {
        let core = Core.shared
        var s = base + components.map(core.percentEncode).joined(separator: "/")
        if !query.isEmpty {
            s += "?" + query.map { core.percentEncode($0.0) + "=" + core.percentEncode($0.1) }.joined(separator: "&")
        }
        return URL(string: s)!   // only unreserved bytes and %XX after the fixed base: always a valid URL
    }

    public static var index: URL { resource(["data", "app-index.tsv"]) }
    public static var checkBatch: URL { resource(["api", "v1", "check", "batch"]) }
    public static var state: URL { resource(["api", "v1", "state"]) }

    public static func project(_ p: ApprovedProject) -> URL { resource(["api", "v1", "project", p.slug]) }

    // Pages on the site (the part after "#" is read by the page's script, never sent to the server).

    public static var home: URL { URL(string: base)! }

    public static func projectPage(slug: String) -> URL {
        URL(string: base + "#/project/" + Core.shared.percentEncode(slug))!
    }

    /// The site's package page for one exact version (`pkgHash` in site/formalinformer/app.js).
    public static func packagePage(_ ecosystem: Ecosystem, _ name: String, version: String?) -> URL {
        let core = Core.shared
        var s = base + "#/check/pkg/" + core.percentEncode(ecosystem.rawValue) + "/" + core.percentEncode(name)
        if let version, !version.isEmpty { s += "@" + core.percentEncode(version) }
        return URL(string: s)!
    }
}

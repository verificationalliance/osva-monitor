import Foundation

/// GET api/v1/product/<key>: an app's or a bundled library's record. `recent` has the project endpoint's shape, so
/// the same verified decision (`osva_affected` on each advisory's `fixed_hint`) says whether a version is affected.
public struct ProductResponse: Codable, Sendable {
    public var key: String
    public var name: String
    /// "app" or "component".
    public var kind: String
    public var vendor: String?
    public var openSource: Bool
    /// Where the record's advisories come from (the vendor's security bulletins, say).
    public var source: String?
    public var asOf: String?
    public var recent: [ProjectResponse.Advisory]

    enum CodingKeys: String, CodingKey {
        case key, name, kind, vendor, source, recent
        case openSource = "open_source", asOf = "as_of"
    }

    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        key = try c.decode(String.self, forKey: .key)
        name = (try? c.decodeIfPresent(String.self, forKey: .name)) ?? key
        kind = (try? c.decodeIfPresent(String.self, forKey: .kind)) ?? ""
        vendor = try? c.decodeIfPresent(String.self, forKey: .vendor)
        openSource = (try? c.decodeIfPresent(Bool.self, forKey: .openSource)) ?? false
        source = try? c.decodeIfPresent(String.self, forKey: .source)
        asOf = try? c.decodeIfPresent(String.self, forKey: .asOf)
        recent = (try? c.decodeIfPresent([ProjectResponse.Advisory].self, forKey: .recent)) ?? []
    }

    /// The record's source as a page to open, when it is an https URL.
    public var sourceURL: URL? { source.flatMap(ProductIndex.httpsURL) }
}

extension SiteURL {
    public static func product(_ p: ApprovedProduct) -> URL { resource(["api", "v1", "product", p.key]) }
}

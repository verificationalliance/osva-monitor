import Foundation

/// The public index's records for software that is not a registry package:
///
///     M  <store>  <id>  <reason>  <source-url>           an extension known to be malicious or removed by its store
///     A  <bundle-id>  <product>  <display name>  [<version key>]     an app, by its exact CFBundleIdentifier
///     C  <kind>  <match>  <product>  <display name>       a library bundled inside apps
///
/// `store` is vscode, openvsx, chrome or firefox. A `C` line's kind is framework (`match` is the bundle's directory
/// name, "Sparkle.framework"), dylib (a file-name prefix, "libssl"), jre ("java") or python ("Python.framework").
/// The optional fifth column of an `A` line names the Info.plist key whose version the product's advisories use
/// (CFBundleShortVersionString unless it says CFBundleVersion).
///
/// The lines come from the server, and the app reads files by them, so each is checked before it is kept: a store,
/// kind or key the app does not know, a match that could name a path, or a product key that is not a plain slug drops
/// the line (and an unknown line type is ignored altogether), so the server can add to the format.
public struct ProductIndex: Sendable {
    public struct MaliciousExtension: Hashable, Sendable {
        public var store: String
        /// Lowercased.
        public var id: String
        /// Why it is listed, in the store's or the reporter's words; may be empty.
        public var reason: String
        /// The report, when it is an https URL.
        public var source: URL?
    }

    public struct App: Hashable, Sendable {
        public var bundleID: String
        public var product: String
        public var name: String
        /// "CFBundleShortVersionString" or "CFBundleVersion".
        public var versionKey: String
    }

    public struct Component: Hashable, Sendable {
        public enum Kind: String, Sendable, CaseIterable { case framework, dylib, jre, python }
        public var kind: Kind
        public var match: String
        public var product: String
        public var name: String
    }

    /// By `maliciousKey(store:id:)`.
    public private(set) var malicious: [String: MaliciousExtension] = [:]
    /// By exact bundle identifier.
    public private(set) var apps: [String: App] = [:]
    public private(set) var components: [Component] = []
    /// The `M` lines' keys, for the verified core's membership test.
    public private(set) var maliciousKeys = KeyList([])
    /// "product\u{1F}<key>" for every product an `A` or `C` line names: what `PrivacyFilter.approve(products:)` checks.
    public private(set) var productKeys = KeyList([])

    public init() {}

    /// For tests and previews: an index of these records.
    public init(malicious: [MaliciousExtension] = [], apps: [App] = [], components: [Component] = []) {
        for m in malicious where self.malicious[Self.maliciousKey(store: m.store, id: m.id)] == nil {
            self.malicious[Self.maliciousKey(store: m.store, id: m.id)] = m
        }
        for a in apps where self.apps[a.bundleID] == nil { self.apps[a.bundleID] = a }
        self.components = components
        finish()
    }

    public static let stores: Set<String> = ["vscode", "openvsx", "chrome", "firefox"]

    /// "<store>\u{1F}<id lowercased>". Every store compares IDs without regard to case; Chrome's are lowercase anyway.
    public static func maliciousKey(store: String, id: String) -> String { store + "\u{1F}" + id.lowercased() }

    // MARK: Reading

    /// Whether the line is one of these records (by its first field), whatever becomes of it.
    static func isRecord(_ firstByte: UInt8) -> Bool {
        firstByte == UInt8(ascii: "M") || firstByte == UInt8(ascii: "A") || firstByte == UInt8(ascii: "C")
    }

    /// Takes one tab-separated line; malformed ones are dropped.
    mutating func add(_ fields: [String]) {
        switch fields.first {
        case "M":
            guard fields.count >= 3, Self.stores.contains(fields[1]), let id = Self.extensionID(fields[2], store: fields[1]) else { return }
            let key = Self.maliciousKey(store: fields[1], id: id)
            guard malicious[key] == nil else { return }
            malicious[key] = MaliciousExtension(store: fields[1], id: id,
                                                reason: fields.count > 3 ? Self.clean(fields[3], max: 160) ?? "" : "",
                                                source: fields.count > 4 ? Self.httpsURL(fields[4]) : nil)
        case "A":
            guard fields.count >= 3, let bundleID = Self.bundleID(fields[1]), let product = Self.productKey(fields[2]),
                  apps[bundleID] == nil else { return }
            let versionKey = fields.count > 4 && fields[4] == "CFBundleVersion" ? "CFBundleVersion" : "CFBundleShortVersionString"
            apps[bundleID] = App(bundleID: bundleID, product: product,
                                 name: fields.count > 3 ? Self.clean(fields[3], max: 80) ?? product : product, versionKey: versionKey)
        case "C":
            guard fields.count >= 4, let kind = Component.Kind(rawValue: fields[1]), let match = Self.match(fields[2], kind: kind),
                  let product = Self.productKey(fields[3]) else { return }
            let c = Component(kind: kind, match: match, product: product, name: fields.count > 4 ? Self.clean(fields[4], max: 80) ?? product : product)
            if !components.contains(c), components.count < 2000 { components.append(c) }
        default:
            return
        }
    }

    /// Lays out the key lists once every line is read.
    mutating func finish() {
        maliciousKeys = KeyList(malicious.keys.sorted())
        let products = Set(apps.values.map(\.product) + components.map(\.product))
        productKeys = KeyList(products.sorted().map(PackageNames.productKey))
    }

    // MARK: Checks on each field

    private static let slugBytes = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._~+-")

    /// A product key: a plain slug ("zoom", "openssl", "google-chrome"), at most 128 bytes, not "." or "..".
    static func productKey(_ s: String) -> String? {
        guard !s.isEmpty, s.utf8.count <= 128, s != ".", s != "..", s.unicodeScalars.allSatisfy({ slugBytes.contains($0) }) else { return nil }
        return s
    }

    /// A bundle identifier: printable, no spaces, at most 255 bytes ("us.zoom.xos").
    static func bundleID(_ s: String) -> String? {
        guard !s.isEmpty, s.utf8.count <= 255, s.unicodeScalars.allSatisfy({ $0.value > 0x20 && $0.value < 0x7F }) else { return nil }
        return s
    }

    /// An extension ID as its store writes it, lowercased. Chrome's are 32 letters a to p; the others printable,
    /// without spaces, at most 255 bytes, and not starting with "-" (an editor's CLI would read that as an option,
    /// quoted or not).
    static func extensionID(_ s: String, store: String) -> String? {
        let id = s.lowercased()
        guard !id.isEmpty, id.utf8.count <= 255, !id.hasPrefix("-"),
              id.unicodeScalars.allSatisfy({ $0.value > 0x20 && $0.value < 0x7F }) else { return nil }
        if store == "chrome" {
            guard id.utf8.count == 32, id.utf8.allSatisfy({ $0 >= UInt8(ascii: "a") && $0 <= UInt8(ascii: "p") }) else { return nil }
        }
        return id
    }

    /// A `C` line's match. It is compared with names in a bundle's directories, never joined into a path, but a match
    /// that could name one is dropped anyway: no "/", no NUL, not "." or "..".
    static func match(_ s: String, kind: Component.Kind) -> String? {
        guard !s.isEmpty, s.utf8.count <= 255, s != ".", s != "..", !s.contains("/"),
              s.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value != 0x7F }) else { return nil }
        switch kind {
        case .framework, .python: return s.hasSuffix(".framework") && s.count > ".framework".count ? s : nil
        case .dylib: return s
        case .jre: return s
        }
    }

    /// Text to show: control characters removed, at most `max` characters; nil when nothing is left.
    static func clean(_ s: String, max: Int) -> String? {
        let kept = String(String.UnicodeScalarView(s.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) }))
            .trimmingCharacters(in: .whitespaces)
        guard !kept.isEmpty else { return nil }
        return kept.count > max ? String(kept.prefix(max - 1)) + "…" : kept
    }

    static func httpsURL(_ s: String) -> URL? {
        guard s.utf8.count <= 2048, let c = URLComponents(string: s), c.scheme?.lowercased() == "https",
              let host = c.host, !host.isEmpty, c.user == nil, c.password == nil, let url = c.url else { return nil }
        return url
    }
}

extension PackageNames {
    /// The key of a product (an app or a bundled library). "product" is not an OSV ecosystem, so it cannot collide with
    /// a package, nor with a project ("project\u{1F}…").
    public static func productKey(_ key: String) -> String { "product\u{1F}" + key }
}

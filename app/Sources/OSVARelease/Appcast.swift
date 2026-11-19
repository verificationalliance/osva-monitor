import Foundation

/// Sparkle's appcast: the feed OSVA Monitor reads once a day, at https://verificationalliance.org/app/appcast.xml, to
/// learn about a new version. `scripts/release.sh` writes it through `osva-appcast`; this is its one format.
///
/// Each item names a release on GitHub, its size, its EdDSA signature, the macOS it needs and its notes. The notes are
/// inside the feed, in Markdown or plain text, never a link to HTML: the feed is signed as a whole (`sign_update`
/// appends the signature after `</rss>`), so the notes the update window shows are covered by the same signature as
/// the download they describe.
///
/// The file is written whole from these values. Reading an existing feed accepts only what this type writes, and
/// refuses anything else rather than drop it.
public struct Appcast: Equatable, Sendable {
    /// Newest first.
    public var items: [Item]

    public init(items: [Item] = []) { self.items = items }

    public struct Item: Equatable, Sendable {
        /// The app's CFBundleVersion, which Sparkle compares: `sparkle:version`.
        public var version: String
        /// The app's CFBundleShortVersionString, which people see: `sparkle:shortVersionString`.
        public var shortVersion: String
        public var published: Date
        /// The zip on GitHub Releases.
        public var url: String
        /// The zip's size in bytes.
        public var length: Int
        /// The zip's EdDSA (Ed25519) signature, base64, from `sign_update`.
        public var edSignature: String
        /// The oldest macOS the release runs on, three parts ("26.0.0").
        public var minimumSystemVersion: String
        public var notes: Notes?

        public init(version: String, shortVersion: String, published: Date, url: String, length: Int, edSignature: String,
                    minimumSystemVersion: String, notes: Notes? = nil) {
            self.version = version; self.shortVersion = shortVersion; self.published = published; self.url = url
            self.length = length; self.edSignature = edSignature; self.minimumSystemVersion = minimumSystemVersion; self.notes = notes
        }

        /// The release's page on GitHub, for the update window's link.
        public var releasePage: String { "\(Appcast.repository)/releases/tag/v\(shortVersion)" }
    }

    /// Release notes, shown in Sparkle's update window.
    public struct Notes: Equatable, Sendable {
        public enum Format: String, Sendable { case markdown, plainText = "plain-text" }
        public var text: String
        public var format: Format
        public init(_ text: String, format: Format) { self.text = text; self.format = format }
    }

    public static let repository = "https://github.com/verificationalliance/osva-monitor"
    public static let feedURL = "https://verificationalliance.org/app/appcast.xml"
    static let sparkleNamespace = "http://www.andymatuschak.org/xml-namespaces/sparkle"

    /// Where GitHub serves a release's zip: the asset must be uploaded under exactly this name.
    public static func downloadURL(version: String) -> String {
        "\(repository)/releases/download/v\(version)/\(assetName(version: version))"
    }

    public static func assetName(version: String) -> String { "OSVA-Monitor-\(version).zip" }

    /// "26.0" as "26.0.0": Sparkle's documentation asks for three parts in `sparkle:minimumSystemVersion`.
    public static func threePartVersion(_ v: String) -> String {
        var parts = v.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        while parts.count < 3 { parts.append("0") }
        return parts.joined(separator: ".")
    }

    /// Notes for a release made without any: where to read about it.
    public static func defaultNotes(version: String) -> Notes {
        let page = "\(repository)/releases/tag/v\(version)"
        return Notes("What is new in \(version) is on [its GitHub release page](\(page)).", format: .markdown)
    }

    public enum Problem: Error, Equatable, CustomStringConvertible {
        case unreadable(String)
        case unexpected(String)
        case notNewer(version: String, newest: String)

        public var description: String {
            switch self {
            case let .unreadable(why): return "the appcast is not readable XML: \(why)"
            case let .unexpected(what): return "the appcast has \(what), which osva-appcast does not write; edit it by hand or start a new file"
            case let .notNewer(version, newest):
                return "version \(version) is not newer than \(newest), the newest in the appcast (Sparkle would not offer it)"
            }
        }
    }

    // MARK: Adding a release

    /// This feed with `item` added, or put in place of the item with the same version (a release made again).
    /// A version older than the newest one is refused: Sparkle would never offer it.
    public func adding(_ item: Item) throws -> Appcast {
        let others = items.filter { $0.version != item.version && $0.shortVersion != item.shortVersion }
        if let newest = others.max(by: { Self.isOlder($0.version, than: $1.version) }), !Self.isOlder(newest.version, than: item.version) {
            throw Problem.notNewer(version: item.version, newest: newest.version)
        }
        return Appcast(items: ([item] + others).sorted { Self.isOlder($1.version, than: $0.version) })
    }

    /// Dot-separated numbers, compared part by part ("1001" < "1002", "0.9" < "0.10"); a missing part counts as 0.
    public static func isOlder(_ a: String, than b: String) -> Bool {
        let pa = a.split(separator: ".").map { Int($0) ?? 0 }, pb = b.split(separator: ".").map { Int($0) ?? 0 }
        for i in 0..<max(pa.count, pb.count) {
            let x = i < pa.count ? pa[i] : 0, y = i < pb.count ? pb[i] : 0
            if x != y { return x < y }
        }
        return false
    }

    // MARK: Writing

    /// The whole feed, unsigned. `sign_update --disable-signing-warning` then appends the signature block.
    public func xml() -> String {
        var out = """
        <?xml version="1.0" encoding="utf-8"?>
        <!-- sparkle-sign-warning:
        Signed with the OSVA Monitor update key by scripts/release.sh. Any change to this file, even to a space, breaks
        the signature at its end, and the app then ignores the feed. Change it only by running scripts/release.sh again.
        -->
        <rss version="2.0" xmlns:sparkle="\(Self.sparkleNamespace)">
          <channel>
            <title>OSVA Monitor</title>
            <link>https://verificationalliance.org/app/</link>
            <description>New versions of OSVA Monitor, signed with its update key.</description>
            <language>en</language>

        """
        for item in items { out += Self.xml(item) }
        out += """
          </channel>
        </rss>

        """
        return out
    }

    static func xml(_ item: Item) -> String {
        var lines = [
            "<item>",
            "  <title>\(escape("OSVA Monitor \(item.shortVersion)"))</title>",
            "  <pubDate>\(rfc822.string(from: item.published))</pubDate>",
            "  <sparkle:version>\(escape(item.version))</sparkle:version>",
            "  <sparkle:shortVersionString>\(escape(item.shortVersion))</sparkle:shortVersionString>",
            "  <sparkle:minimumSystemVersion>\(escape(item.minimumSystemVersion))</sparkle:minimumSystemVersion>",
            "  <link>\(escape(item.releasePage))</link>",
        ]
        if let notes = item.notes {
            lines.append("  <description sparkle:format=\"\(notes.format.rawValue)\">\(escape(notes.text))</description>")
        }
        lines.append("  <enclosure url=\"\(escape(item.url))\" length=\"\(item.length)\" type=\"application/octet-stream\""
                     + " sparkle:edSignature=\"\(escape(item.edSignature))\"/>")
        lines.append("</item>")
        return lines.map { "    " + $0 + "\n" }.joined()
    }

    /// Text for an XML element or a double-quoted attribute: `& < > " '` as entities, and the characters XML 1.0 cannot
    /// carry at all (controls other than tab, line feed and carriage return) left out. A carriage return becomes an
    /// entity, so a parser does not fold "\r\n" into "\n".
    public static func escape(_ text: String) -> String {
        var out = ""
        out.reserveCapacity(text.utf8.count)
        for scalar in text.unicodeScalars {
            switch scalar {
            case "&": out += "&amp;"
            case "<": out += "&lt;"
            case ">": out += "&gt;"
            case "\"": out += "&quot;"
            case "'": out += "&apos;"
            case "\r": out += "&#13;"
            case "\t", "\n": out.unicodeScalars.append(scalar)
            default:
                let v = scalar.value
                let allowed = (0x20...0xD7FF).contains(v) || (0xE000...0xFFFD).contains(v) || (0x10000...0x10FFFF).contains(v)
                if allowed { out.unicodeScalars.append(scalar) }
            }
        }
        return out
    }

    static var rfc822: DateFormatter {                    // DateFormatter is not Sendable: one per use
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "EEE, dd MMM yyyy HH:mm:ss Z"
        return f
    }

    // MARK: Reading

    /// Reads a feed this type wrote (with or without the signature block after it).
    public static func parse(_ data: Data) throws -> Appcast {
        let content = FeedSignature.content(of: data)
        let document: XMLDocument
        do { document = try XMLDocument(data: content, options: [.nodeLoadExternalEntitiesNever, .nodePreserveCDATA]) }
        catch { throw Problem.unreadable(error.localizedDescription) }
        guard let rss = document.rootElement(), rss.name == "rss",
              let channel = rss.children?.compactMap({ $0 as? XMLElement }).first(where: { $0.name == "channel" }) else {
            throw Problem.unexpected("no <rss><channel>")
        }
        var items: [Item] = []
        for child in channel.children ?? [] {
            guard let element = child as? XMLElement else { continue }        // comments and whitespace
            switch element.name {
            case "title", "link", "description", "language": continue       // written again from the constants above
            case "item": items.append(try item(element))
            default: throw Problem.unexpected("<\(element.name ?? "?")> in its channel")
            }
        }
        return Appcast(items: items)
    }

    private static func item(_ element: XMLElement) throws -> Item {
        var fields: [String: String] = [:]
        var notes: Notes?
        var enclosure: XMLElement?
        for child in element.children ?? [] {
            guard let e = child as? XMLElement, let name = e.name else { continue }
            switch name {
            case "title", "link": continue                                     // derived from the version
            case "pubDate", "sparkle:version", "sparkle:shortVersionString", "sparkle:minimumSystemVersion":
                fields[name] = e.stringValue ?? ""
            case "description":
                let format = e.attribute(forName: "sparkle:format")?.stringValue ?? Notes.Format.plainText.rawValue
                guard let f = Notes.Format(rawValue: format) else { throw Problem.unexpected("release notes in \(format)") }
                notes = Notes(e.stringValue ?? "", format: f)
            case "enclosure": enclosure = e
            default: throw Problem.unexpected("<\(name)> in an item")
            }
        }
        func field(_ name: String) throws -> String {
            guard let v = fields[name], !v.isEmpty else { throw Problem.unexpected("an item without <\(name)>") }
            return v
        }
        func attribute(_ name: String) throws -> String {
            guard let v = enclosure?.attribute(forName: name)?.stringValue, !v.isEmpty else {
                throw Problem.unexpected("an item whose <enclosure> has no \(name)")
            }
            return v
        }
        guard let published = rfc822.date(from: try field("pubDate")) else { throw Problem.unexpected("an item with an unreadable <pubDate>") }
        guard let length = Int(try attribute("length")) else { throw Problem.unexpected("an item with an unreadable length") }
        return Item(version: try field("sparkle:version"), shortVersion: try field("sparkle:shortVersionString"), published: published,
                    url: try attribute("url"), length: length, edSignature: try attribute("sparkle:edSignature"),
                    minimumSystemVersion: try field("sparkle:minimumSystemVersion"), notes: notes)
    }
}

import Foundation
import Testing
@testable import OSVARelease

@Suite struct AppcastTests {
    static let date = Date(timeIntervalSince1970: 1_795_089_600)                    // Thu, 19 Nov 2026 12:00:00 +0000
    static let signature = String(repeating: "A", count: 86) + "=="

    static func item(_ short: String, build: String, notes: Appcast.Notes? = nil) -> Appcast.Item {
        Appcast.Item(version: build, shortVersion: short, published: date, url: Appcast.downloadURL(version: short), length: 4_508_410,
                     edSignature: signature, minimumSystemVersion: "26.0.0", notes: notes)
    }

    @Test func oneItemAsSparkleReadsIt() {
        let xml = Appcast.xml(Self.item("0.1.1", build: "1001", notes: .init("- Faster.", format: .markdown)))
        #expect(xml == """
                <item>
                  <title>OSVA Monitor 0.1.1</title>
                  <pubDate>Thu, 19 Nov 2026 12:00:00 +0000</pubDate>
                  <sparkle:version>1001</sparkle:version>
                  <sparkle:shortVersionString>0.1.1</sparkle:shortVersionString>
                  <sparkle:minimumSystemVersion>26.0.0</sparkle:minimumSystemVersion>
                  <link>https://github.com/verificationalliance/osva-monitor/releases/tag/v0.1.1</link>
                  <description sparkle:format="markdown">- Faster.</description>
                  <enclosure url="https://github.com/verificationalliance/osva-monitor/releases/download/v0.1.1/OSVA-Monitor-0.1.1.zip" length="4508410" type="application/octet-stream" sparkle:edSignature="\(Self.signature)"/>
                </item>

            """)
    }

    @Test func theDownloadIsTheGitHubAsset() {
        #expect(Appcast.downloadURL(version: "0.1.1") == "https://github.com/verificationalliance/osva-monitor/releases/download/v0.1.1/OSVA-Monitor-0.1.1.zip")
        #expect(Appcast.threePartVersion("26.0") == "26.0.0")
        #expect(Appcast.threePartVersion("26") == "26.0.0")
        #expect(Appcast.threePartVersion("26.1.2") == "26.1.2")
    }

    @Test func escaping() {
        #expect(Appcast.escape(#"a & b < c > d "e" 'f'"#) == "a &amp; b &lt; c &gt; d &quot;e&quot; &apos;f&apos;")
        #expect(Appcast.escape("]]></description><evil/>") == "]]&gt;&lt;/description&gt;&lt;evil/&gt;")
        #expect(Appcast.escape("tab\tline\nreturn\r") == "tab\tline\nreturn&#13;")
        #expect(Appcast.escape("bell\u{07} null\u{00} esc\u{1B} fffe\u{FFFE}") == "bell null esc fffe")    // XML 1.0 cannot carry them
        #expect(Appcast.escape("Ünïcödé — ✓ 🔐") == "Ünïcödé — ✓ 🔐")
    }

    /// Whatever the notes say, they come back as written, and never as markup.
    @Test func hostileNotesStayText() throws {
        let text = "1 < 2 && \"quotes\" 'too'\r\n]]><item><title>injected</title></item><!-- -- -->\n- 🔐 ok"
        let feed = Appcast(items: [Self.item("0.1.1", build: "1001", notes: .init(text, format: .plainText))])
        let back = try Appcast.parse(Data(feed.xml().utf8))
        #expect(back.items.count == 1)
        #expect(back.items[0].notes == .init(text, format: .plainText))
        let doc = try XMLDocument(data: Data(feed.xml().utf8))
        #expect(try doc.nodes(forXPath: "//item").count == 1)
    }

    @Test func roundTrip() throws {
        let feed = Appcast(items: [Self.item("0.2.0", build: "2000", notes: .init("**Big** release", format: .markdown)),
                                   Self.item("0.1.1", build: "1001")])
        #expect(try Appcast.parse(Data(feed.xml().utf8)) == feed)
    }

    /// The elements are in Sparkle's namespace, which is how Sparkle finds them whatever the prefix.
    @Test func sparkleNamespace() throws {
        let doc = try XMLDocument(data: Data(Appcast(items: [Self.item("0.1.1", build: "1001")]).xml().utf8))
        let item = try #require(try doc.nodes(forXPath: "//item").first as? XMLElement)
        let ns = "http://www.andymatuschak.org/xml-namespaces/sparkle"
        #expect(item.elements(forLocalName: "version", uri: ns).first?.stringValue == "1001")
        #expect(item.elements(forLocalName: "shortVersionString", uri: ns).first?.stringValue == "0.1.1")
        #expect(item.elements(forLocalName: "minimumSystemVersion", uri: ns).first?.stringValue == "26.0.0")
        let enclosure = try #require(item.elements(forName: "enclosure").first)
        #expect(enclosure.attribute(forLocalName: "edSignature", uri: ns)?.stringValue == Self.signature)
        #expect(enclosure.attribute(forName: "length")?.stringValue == "4508410")
    }

    @Test func aNewReleaseGoesFirst() throws {
        let feed = try Appcast().adding(Self.item("0.1.1", build: "1001")).adding(Self.item("0.2.0", build: "2000"))
        #expect(feed.items.map(\.shortVersion) == ["0.2.0", "0.1.1"])
    }

    @Test func theSameVersionAgainReplacesIt() throws {
        var again = Self.item("0.1.1", build: "1001"); again.length = 99
        let feed = try Appcast(items: [Self.item("0.1.1", build: "1001")]).adding(again)
        #expect(feed.items == [again])
    }

    @Test func anOlderVersionIsRefused() throws {
        let feed = Appcast(items: [Self.item("0.2.0", build: "2000")])
        #expect(throws: Appcast.Problem.notNewer(version: "1001", newest: "2000")) { try feed.adding(Self.item("0.1.1", build: "1001")) }
        #expect(Appcast.isOlder("999", than: "1000") && Appcast.isOlder("0.9", than: "0.10") && !Appcast.isOlder("1.0", than: "1"))
    }

    @Test func readsAFeedSignedBySignUpdate() throws {
        let feed = try Appcast.parse(Fixture.data("signed-by-sign_update.xml"))
        #expect(feed.items.map(\.shortVersion) == ["0.1.1"])
        #expect(feed.items[0].published == Self.date)
        #expect(feed.items[0].notes == Appcast.defaultNotes(version: "0.1.1"))
    }

    @Test func refusesWhatItDidNotWrite() {
        func parse(_ s: String) throws -> Appcast { try Appcast.parse(Data(s.utf8)) }
        let item = Appcast.xml(Self.item("0.1.1", build: "1001"))
        let rss = { (body: String) in "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\"><channel>\(body)</channel></rss>" }
        #expect(throws: Appcast.Problem.unexpected("<sparkle:deltas> in an item")) {
            try parse(rss(item.replacingOccurrences(of: "</item>", with: "<sparkle:deltas/></item>")))
        }
        #expect(throws: Appcast.Problem.unexpected("<sparkle:bundleIdentifier> in its channel")) {
            try parse(rss("<sparkle:bundleIdentifier>x</sparkle:bundleIdentifier>" + item))
        }
        #expect(throws: Appcast.Problem.unexpected("release notes in html")) {
            try parse(rss(item.replacingOccurrences(of: "<link>", with: "<description sparkle:format=\"html\">x</description><link>")))
        }
        #expect(throws: Appcast.Problem.unexpected("an item without <sparkle:version>")) {
            try parse(rss(item.replacingOccurrences(of: "<sparkle:version>1001</sparkle:version>", with: "")))
        }
        #expect(throws: (any Error).self) { try parse("<rss><channel><item>") }
    }
}

enum Fixture {
    static func data(_ name: String) -> Data {
        try! Data(contentsOf: Bundle.module.resourceURL!.appendingPathComponent("Fixtures").appendingPathComponent(name))
    }
}

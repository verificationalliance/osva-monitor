import Foundation
import Testing
@testable import OSVAKit

@Suite struct ProductIndexTests {
    @Test func readsTheBundleRecordsAndDropsWhatItCannotTrust() throws {
        let index = Make.index
        // the recorded index's own records are untouched
        #expect(index.packageCount == 35 && index.projects.count == 314 && index.keys.count == 35 + 314)
        let p = index.products
        // M: IDs lowercased; a Chrome ID that is not 32 letters a-p, and a store the app does not know, are dropped;
        // the report link is kept only when it is https
        #expect(Set(p.malicious.keys) == ["vscode\u{1F}evil-pub.prettier-vscode", "openvsx\u{1F}ms-python.python",
                                          "chrome\u{1F}abcdefghijklmnopabcdefghijklmnop", "firefox\u{1F}{8a3f5b2e-1111-4c7a-9e0d-123456789abc}"])
        #expect(p.malicious["vscode\u{1F}evil-pub.prettier-vscode"]?.source?.absoluteString == "https://example.org/reports/prettier-clone")
        #expect(p.malicious["vscode\u{1F}evil-pub.prettier-vscode"]?.reason == "malware: sends SSH keys and tokens to a remote host")
        #expect(p.malicious["firefox\u{1F}{8a3f5b2e-1111-4c7a-9e0d-123456789abc}"]?.source == nil)
        // A: exact bundle IDs; a product key that is not a slug and a bundle ID with a space are dropped
        #expect(Set(p.apps.keys) == ["us.zoom.xos", "com.tinyspeck.slackmacgap", "com.example.buildnumber"])
        #expect(p.apps["us.zoom.xos"]?.versionKey == "CFBundleShortVersionString" && p.apps["us.zoom.xos"]?.name == "Zoom")
        #expect(p.apps["com.example.buildnumber"]?.versionKey == "CFBundleVersion")
        // C: a path, a framework match that is not a framework, and an unknown kind are dropped
        #expect(p.components.map(\.match) == ["Sparkle.framework", "QtCore.framework", "Chromium Embedded Framework.framework",
                                               "libssl", "libcrypto", "libavcodec", "java", "Python.framework"])
        #expect(p.components.first { $0.match == "libssl" }?.kind == .dylib)
    }

    @Test func linesTheAppDoesNotKnowAreIgnored() throws {
        let tsv = "#osva-app-index\t1\tT\nM\tvscode\nA\tonly.two\nC\tframework\nM\nA\nC\nMystery\tline\nAlpha\tbeta\tgamma\nK\tnpm\tx\n"
        let index = try PublicIndex.decode(Data(tsv.utf8))
        #expect(index.packageCount == 1 && index.products.malicious.isEmpty && index.products.apps.isEmpty && index.products.components.isEmpty)
    }

    @Test func fieldChecks() {
        #expect(ProductIndex.productKey("google-chrome") == "google-chrome")
        for bad in ["", ".", "..", "a/b", "a b", "a%2Fb", "a?x", "\u{202E}x", String(repeating: "a", count: 129)] {
            #expect(ProductIndex.productKey(bad) == nil, "\(bad)")
        }
        #expect(ProductIndex.extensionID("ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP", store: "chrome") == "abcdefghijklmnopabcdefghijklmnop")
        #expect(ProductIndex.extensionID("abcdefghijklmnopabcdefghijklmnoq", store: "chrome") == nil)     // q is not a-p
        #expect(ProductIndex.extensionID("--install-extension=evil.x", store: "vscode") == nil)          // an option, quoted or not
        #expect(ProductIndex.match("Sparkle.framework", kind: .framework) == "Sparkle.framework")
        #expect(ProductIndex.match(".framework", kind: .framework) == nil)
        #expect(ProductIndex.match("..", kind: .dylib) == nil && ProductIndex.match("lib/x", kind: .dylib) == nil)
        #expect(ProductIndex.clean("Evil\u{202E}name\u{0}\n", max: 80) == "Evilname")   // no bidi overrides, no NUL
        #expect(ProductIndex.httpsURL("javascript:alert(1)") == nil && ProductIndex.httpsURL("https://user:pw@example.org/") == nil)
    }

    @Test func onlyIndexedProductKeysAreApproved() {
        let filter = PrivacyFilter(index: Make.index)
        #expect(filter.approve(products: ["zoom", "sparkle", "zoom", "my-internal-app", "cpython"]).map(\.key) == ["cpython", "sparkle", "zoom"])
        // "cpython" is a C line's product here; a key in no line at all is never approved
        #expect(filter.approve(products: ["us.zoom.xos"]).isEmpty)                  // a bundle ID is not a product key
        let empty = PrivacyFilter(index: Fixture.index)
        #expect(empty.approve(products: ["zoom"]).isEmpty)                           // no A lines, nothing to ask
    }

    @Test func productURLsAreEncodedByTheCore() throws {
        var index = ProductIndex()
        index.add(["A", "com.x", "c++~1.0"])
        index.finish()
        let approved = try #require(PrivacyFilter(index: PublicIndex(generatedAt: "", packages: [], projects: [], products: index)).approve(products: ["c++~1.0"]).first)
        #expect(SiteURL.product(approved).absoluteString == "https://verificationalliance.org/api/v1/product/c%2B%2B~1.0")
        #expect(approved.sentDescription == "product c++~1.0")
    }

    @Test func productRecordsReadLeniently() throws {
        let zoom = Make.product("zoom")
        #expect(zoom.kind == "app" && zoom.vendor == "Zoom Communications" && !zoom.openSource && zoom.asOf == "2026-11-18")
        #expect(zoom.recent.count == 3 && zoom.recent[1].kev && zoom.recent[0].fixedHint == ["6.6.12"])
        #expect(zoom.sourceURL?.host == "www.zoom.com")
        let bare = try JSONDecoder().decode(ProductResponse.self, from: Data(#"{"key":"x","recent":"not a list","open_source":"yes"}"#.utf8))
        #expect(bare.name == "x" && bare.recent.isEmpty && !bare.openSource)
        let again = try JSONDecoder().decode(ProductResponse.self, from: JSONEncoder().encode(zoom))       // the cache's copy
        #expect(again.recent == zoom.recent && again.source == zoom.source)
    }
}

@Suite struct BundleReaderTests {
    @Test("versions as apps write them", arguments: [
        ("6.6.10 (69071)", "6.6.10"), ("3.11.15, (c) 2001-2023 Python Software Foundation.", "3.11.15"),
        ("2.10.1-3254-g0858e9bc", "2.10.1"), ("2.5.0-beta.1", "2.5.0-beta.1"), ("3.0b2", "3.0b2"), ("v1.2", "1.2"),
        ("157.0.8103.80", "157.0.8103.80"), (" 4.53.292", "4.53.292"),
    ])
    func leadingVersions(_ raw: String, _ expected: String) {
        #expect(VersionText.leading(raw) == expected)
    }

    @Test func notVersions() {
        for raw in ["", "beta", "(c) 2001", String(repeating: "1.", count: 300)] { #expect(VersionText.leading(raw) == nil, "\(raw)") }
    }

    @Test func printedReleases() {
        func find(_ s: String, _ name: String) -> String? {
            VersionText.embedded(in: Data(s.utf8), needles: [name + " version ", name + " ", name + "/"])
        }
        #expect(find("\0OpenSSL 1.1.1v  1 Aug 2023\0", "OpenSSL") == "1.1.1v")
        #expect(find("x\0OpenSSL 3.0 FIPS provider\0OpenSSL 3.6.2 7 Apr 2026\0", "OpenSSL") == "3.6.2")    // three parts win
        #expect(find("FFmpeg version n7.1\0", "FFmpeg") == "7.1")
        #expect(find("FFmpeg version N-111721-g132a3b7340\0", "FFmpeg") == nil)                          // a git build
        #expect(find("libcurl/8.4.0 SecureTransport\0", "libcurl") == "8.4.0")
        #expect(find(String(repeating: "OpenSSL x ", count: 1000), "OpenSSL") == nil)
        #expect(VersionText.embedded(in: Data(), needles: ["OpenSSL "]) == nil)
    }

    @Test func machOVersionsAndStrings() throws {
        let lib = Make.dylib(current: "61.3.100", compatibility: "61.0.0", strings: ["Lavc61.3.100", "FFmpeg version 7.0.2"])
        let info = try #require(MachO.parse(size: lib.count) { o, n in lib.subdata(in: o..<min(o + n, lib.count)) })
        #expect(info.current.map(VersionText.machO) == "61.3.100" && info.compatibility.map(VersionText.machO) == "61.0.0")
        let strings = lib.subdata(in: try #require(info.cstrings))
        #expect(VersionText.embedded(in: strings, needles: ["FFmpeg version "]) == "7.0.2")

        // a universal binary: the arm64 slice is the one read
        let fat = Make.fat([(0x0100_0007, Make.dylib(current: "1.0.0", compatibility: "0.9.0", cpu: 0x0100_0007)),
                            (0x0100_000C, Make.dylib(current: "2.0.0", compatibility: "1.0.0"))])
        let fatInfo = try #require(MachO.parse(size: fat.count) { o, n in o < fat.count ? fat.subdata(in: o..<min(o + n, fat.count)) : nil })
        #expect(fatInfo.current.map(VersionText.machO) == "2.0.0")
    }

    @Test func garbageAndTruncatedMachOFilesGiveNothingOrLess() {
        let lib = Make.dylib(current: "3.0.0", compatibility: "3.0.0", strings: ["OpenSSL 3.0.13 30 Jan 2024"])
        // every truncation of a real-shaped file: no crash, no read past the end
        for n in 0...lib.count {
            let cut = lib.prefix(n)
            _ = MachO.parse(size: cut.count) { o, len in o <= cut.count ? cut.subdata(in: o..<min(o + len, cut.count)) : nil }
        }
        func parse(_ d: Data) -> MachO.Info? { MachO.parse(size: d.count) { o, len in o <= d.count ? d.subdata(in: o..<min(o + len, d.count)) : nil } }
        var rng = SystemRandomNumberGenerator()
        for _ in 0..<200 { _ = parse(Data((0..<Int.random(in: 0...512, using: &rng)).map { _ in UInt8.random(in: 0...255, using: &rng) })) }
        // a load command of size 0 (would loop forever), sizes past the end, absurd counts
        var zero = lib
        zero.replaceSubrange(36..<40, with: [0, 0, 0, 0])
        #expect(parse(zero)?.current == nil)
        var huge = lib
        huge.replaceSubrange(20..<24, with: [0xFF, 0xFF, 0xFF, 0x7F])            // sizeofcmds
        #expect(parse(huge) == nil)
        var manySections = lib
        let seg = 32 + (24 + 18 + 7) / 8 * 8
        manySections.replaceSubrange((seg + 64)..<(seg + 68), with: [0xFF, 0xFF, 0xFF, 0x0F])
        #expect(parse(manySections)?.cstrings == nil)
        var fat = Data([0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x03, 0xE8])          // 1000 slices
        #expect(parse(fat) == nil)
        fat = Data([0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 1, 1, 0, 0, 12, 0, 0, 0, 0, 0x7F, 0xFF, 0xFF, 0xFF, 0, 0, 0x10, 0, 0, 0, 0, 12])
        #expect(parse(fat) == nil)                                                // its one slice is past the end
        #expect(parse(Data([0xCF, 0xFA, 0xED, 0xFE])) == nil)
    }

    @Test func boundedFilesAreRegularFilesOnly() throws {
        let dir = temporaryDirectory()
        let fifo = dir.appendingPathComponent("Info.plist")
        #expect(mkfifo(fifo.path, 0o644) == 0)
        let started = Date()
        #expect(BoundedFile.read(fifo, limit: 1 << 20) == nil)                 // no writer: must not wait for one
        #expect(Documents.plist(fifo) == nil)
        #expect(Date().timeIntervalSince(started) < 2)
        #expect(BoundedFile.read(dir, limit: 1 << 20) == nil)                  // a directory
        let big = dir.appendingPathComponent("big")
        try Data(count: 2048).write(to: big)
        #expect(BoundedFile.read(big, limit: 1024) == nil && BoundedFile.read(big, limit: 2048)?.count == 2048)
        #expect(BoundedFile.read(big, offset: 2000, length: 100)?.count == 48 && BoundedFile.read(big, offset: 4000, length: 1) == nil)
        for i in 0..<50 { write("", to: dir.appendingPathComponent("many/\(i)")) }
        #expect(Directory.entries(dir.appendingPathComponent("many"), limit: 10).count == 10)
        #expect(Directory.entries(dir.appendingPathComponent("missing"), limit: 10).isEmpty)
    }

    @Test func javaReleaseFiles() {
        #expect(JavaRelease.version("IMPLEMENTOR=\"Eclipse Adoptium\"\nJAVA_VERSION=\"17.0.9\"\n") == "17.0.9")
        #expect(JavaRelease.version("JAVA_VERSION=\"1.8.0_392\"") == "1.8.0_392")
        #expect(JavaRelease.version("JAVA_VERSION=\"$(rm -rf ~)\"") == nil)
        #expect(JavaRelease.version("garbage\u{0}\u{1}") == nil && JavaRelease.version("") == nil)
    }

    @Test("the framework version that is complete", arguments: [
        // short, CFBundleVersion, current_version, compatibility_version -> version
        ("6.10", "6.10.1", "6.10.1", "6.0.0", "6.10.1"),           // Qt 6
        ("5.15.1", "18", "5.15.1", "5.15.0", "5.15.1"),            // Parallels' Qt: CFBundleVersion is a build
        ("5.6", "5.6.0", "5.6.0", "5.6.0", "5.6.0"),               // Qt 5, ABI version equal: the plist's
        ("2.9.2", "2057", "2.9.2", "1.6.0", "2.9.2"),              // Sparkle 2
        ("2.5.0-beta.1", "2029", "2.5.0", "1.6.0", "2.5.0-beta.1"),
        ("1.24.0", "1.24.0", "1.0.0", "1.0.0", "1.24.0"),          // Sparkle 1
    ] as [(String, String, String, String, String)])
    func frameworkVersions(_ short: String, _ build: String, _ current: String, _ compat: String, _ expected: String) {
        func v(_ s: String) -> UInt32 { let p = s.split(separator: ".").map { UInt32($0)! }; return p[0] << 16 | p[1] << 8 | p[2] }
        #expect(ComponentReader.choose(short: VersionText.leading(short), bundle: VersionText.leading(build), current: v(current), compatibility: v(compat)) == expected)
    }
}

@Suite struct AppSourceTests {
    @Test func readsEveryAppAndSurvivesBrokenOnes() throws {
        let root = temporaryDirectory()
        Make.app(root, "zoom.us", id: "us.zoom.xos", short: "6.6.10 (69071)", build: "6.6.10.69071")
        Make.app(root.appendingPathComponent("Utilities"), "Nested", id: "com.example.nested", short: "1.0")
        let garbage = Make.app(root, "Garbage", id: nil, short: nil)
        try Data("<?xml version=\"1.0\"?><plist><dict><key>CFBundle".utf8).write(to: garbage.appendingPathComponent("Contents/Info.plist"))
        let fifo = Make.app(root, "Fifo", id: nil, short: nil)
        try FileManager.default.removeItem(at: fifo.appendingPathComponent("Contents/Info.plist"))
        #expect(mkfifo(fifo.appendingPathComponent("Contents/Info.plist").path, 0o644) == 0)
        let binary = Make.app(root, "BinaryJunk", id: nil, short: nil)
        try Data((0..<4096).map { UInt8(truncatingIfNeeded: $0 &* 31) }).write(to: binary.appendingPathComponent("Contents/Info.plist"))
        let home = temporaryDirectory()
        try FileManager.default.createDirectory(at: home.appendingPathComponent("Applications"), withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: home.appendingPathComponent("Applications/zoom.us.app"), withDestinationURL: root.appendingPathComponent("zoom.us.app"))

        let r = AppSource(roots: [root, home.appendingPathComponent("Applications")], caskForApp: ["zoom.us.app": "zoom"]).collect()
        #expect(r.apps.map(\.name) == ["BinaryJunk", "Fifo", "Garbage", "Nested", "zoom.us"])        // the link to zoom.us is one app
        let zoom = try #require(r.apps.first { $0.name == "zoom.us" })
        #expect(zoom.bundleID == "us.zoom.xos" && zoom.shortVersion == "6.6.10 (69071)" && zoom.caskToken == "zoom")
        #expect(r.apps.filter { $0.bundleID == nil }.count == 3)
        #expect(r.report == SourceReport(kind: .apps, available: true, count: 5, detail: "5 apps"))
    }

    @Test func versionKeyOfTheProduct() {
        let app = InstalledApp(name: "Slack", path: "/Applications/Slack.app", bundleID: "com.tinyspeck.slackmacgap",
                               shortVersion: "4.53.292", bundleVersion: "453000292", caskToken: nil)
        #expect(BundleCheck.version(of: app, key: "CFBundleShortVersionString") == "4.53.292")
        #expect(BundleCheck.version(of: app, key: "CFBundleVersion") == "453000292")
        var noShort = app; noShort.shortVersion = nil
        #expect(BundleCheck.version(of: noShort, key: "CFBundleShortVersionString") == nil)       // never a bare build number
        noShort.bundleVersion = "6.6.10.69071"
        #expect(BundleCheck.version(of: noShort, key: "CFBundleShortVersionString") == "6.6.10.69071")
    }
}

@Suite struct ComponentReaderTests {
    /// One app with one of each kind of bundled library, plus decoys.
    static func kitchenSink() -> URL {
        let root = temporaryDirectory()
        let app = Make.app(root, "Sink", id: "com.example.sink", short: "1.0")
        Make.framework(app, "Sparkle", short: "1.24.0", build: "1.24.0", binary: Make.dylib(current: "1.0.0", compatibility: "1.0.0"))
        Make.framework(app, "QtCore", short: "6.10", build: "6.10.1", binary: Make.dylib(current: "6.10.1", compatibility: "6.0.0"))
        Make.framework(app, "Chromium Embedded Framework", short: "151.3.18.0", build: "18.0")
        Make.framework(app, "Electron Framework", short: "38.1.0", build: "38.1.0")       // checked as npm electron, not here
        let python = Make.framework(app, "Python", short: "3.11.15, (c) 2001-2023 Python Software Foundation.", build: "3.11.15")
        _ = python
        let fw = app.appendingPathComponent("Contents/Frameworks")
        Make.bytes(Make.dylib(current: "3.0.0", compatibility: "3.0.0"), to: fw.appendingPathComponent("libssl.3.dylib"))
        Make.bytes(Make.dylib(current: "3.0.0", compatibility: "3.0.0", strings: ["OpenSSL 3.0.13 30 Jan 2024"]), to: fw.appendingPathComponent("libcrypto.3.dylib"))
        Make.bytes(Make.dylib(current: "60.23.100", compatibility: "60.0.0", strings: ["FFmpeg version N-111721-g132a3b7340"]),
                   to: fw.appendingPathComponent("libavcodec.60.dylib"))
        try! FileManager.default.createSymbolicLink(at: fw.appendingPathComponent("libavcodec.dylib"), withDestinationURL: fw.appendingPathComponent("libavcodec.60.dylib"))
        Make.bytes(Data("not a library".utf8), to: fw.appendingPathComponent("libsslwrapper.dylib"))           // not libssl
        write("JAVA_VERSION=\"17.0.9\"\n", to: app.appendingPathComponent("Contents/runtime/Contents/Home/release"))
        return app
    }

    @Test func findsEachKindWithItsVersion() throws {
        let app = Self.kitchenSink()
        let found = ComponentReader.components(in: app, records: Make.index.products.components)
        let byLabel = Dictionary(found.map { ("\($0.label)|\($0.path)", $0.version ?? "?") }, uniquingKeysWith: { a, _ in a })
        #expect(byLabel == [
            "Sparkle|Contents/Frameworks/Sparkle.framework": "1.24.0",
            "Qt|Contents/Frameworks/QtCore.framework": "6.10.1",
            "CEF|Contents/Frameworks/Chromium Embedded Framework.framework": "151.3.18",
            "Python|Contents/Frameworks/Python.framework": "3.11.15",
            "OpenSSL|Contents/Frameworks/libssl.3.dylib": "3.0.13",             // its release is printed in libcrypto
            "OpenSSL|Contents/Frameworks/libcrypto.3.dylib": "3.0.13",
            "libavcodec|Contents/Frameworks/libavcodec.60.dylib": "60.23.100",  // the file's own version, named as the file
            "Java|Contents/runtime/Contents/Home": "17.0.9",
        ])
        #expect(found.count == 8)                                                // the libavcodec link is the same file
    }

    @Test func brokenLibrariesAreFoundWithoutAVersion() throws {
        let root = temporaryDirectory()
        let app = Make.app(root, "Broken", id: nil, short: nil)
        let fw = app.appendingPathComponent("Contents/Frameworks")
        let sparkle = Make.framework(app, "Sparkle", short: nil, build: nil)
        try Data("garbage".utf8).write(to: sparkle.appendingPathComponent("Versions/A/Resources/Info.plist"))
        Make.bytes(Make.dylib(current: "3.0.0", compatibility: "3.0.0").prefix(40), to: fw.appendingPathComponent("libssl.3.dylib"))   // truncated
        Make.bytes(Data(count: 0), to: fw.appendingPathComponent("libcrypto.3.dylib"))
        #expect(mkfifo(fw.appendingPathComponent("libavcodec.60.dylib").path, 0o644) == 0)
        write("JAVA_VERSION=\n", to: app.appendingPathComponent("Contents/jbr/Contents/Home/release"))
        let started = Date()
        let found = ComponentReader.components(in: app, records: Make.index.products.components)
        #expect(Date().timeIntervalSince(started) < 5)
        #expect(Set(found.map(\.label)) == ["Sparkle", "OpenSSL", "FFmpeg", "Java"])       // unreadable: named as the index names it
        #expect(found.allSatisfy { $0.version == nil })
    }

    @Test func aLibrarysOwnNumberIsUsedOnlyWhenItsFileNameAgrees() throws {
        let dir = temporaryDirectory()
        let libxml2 = ProductIndex.Component(kind: .dylib, match: "libxml2", product: "libxml2", name: "libxml2")
        // libtool's numbering: libxml2.2.dylib says current_version 15.3.0, which is no version of libxml2
        Make.bytes(Make.dylib(current: "15.3.0", compatibility: "13.0.0"), to: dir.appendingPathComponent("libxml2.2.dylib"))
        #expect(ComponentReader.dylibVersion(dir.appendingPathComponent("libxml2.2.dylib"), record: libxml2).0 == nil)
        // a release printed inside wins over any number
        Make.bytes(Make.dylib(current: "15.3.0", compatibility: "13.0.0", strings: ["libxml2 2.13.5"]), to: dir.appendingPathComponent("libxml2.16.dylib"))
        let printed = ComponentReader.dylibVersion(dir.appendingPathComponent("libxml2.16.dylib"), record: libxml2)
        #expect(printed.0 == "2.13.5" && !printed.own)
        #expect(ComponentReader.fileMajor("libavcodec.61.3.100.dylib", prefix: "libavcodec") == "61")
        #expect(ComponentReader.fileMajor("libavcodec.dylib", prefix: "libavcodec") == nil)
        #expect(ComponentReader.fileMajor("libssl-1.1.dylib", prefix: "libssl") == "1")
        #expect(ComponentReader.majorOf("60.23.100") == "60" && ComponentReader.majorOf("v1") == "")
    }

    @Test func prefixesMatchWholeNames() {
        #expect(ComponentReader.hasPrefix("libssl.3.dylib", "libssl") && ComponentReader.hasPrefix("libssl-1.1.dylib", "libssl"))
        #expect(!ComponentReader.hasPrefix("libsslwrapper.dylib", "libssl") && !ComponentReader.hasPrefix("libcryptopp.dylib", "libcrypto"))
        #expect(!ComponentReader.hasPrefix("libssl", "libssl"))
    }

    @Test func cefVersionHeader() {
        #expect(ComponentReader.cefHeaderVersion("#define CEF_VERSION \"151.3.18+g41fa824+chromium-151.0.7922.86\"") == "151.3.18")
        #expect(ComponentReader.cefHeaderVersion("#define CHROME_VERSION_MAJOR 151") == nil)
    }
}

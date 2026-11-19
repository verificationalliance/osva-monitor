import Foundation
import Testing
@testable import OSVAKit

@Suite struct IndexTests {
    @Test func decodesTheRecordedIndex() throws {
        let index = Fixture.index
        #expect(index.generatedAt == "2026-11-19T03:00:00Z")
        #expect(index.projects.count == 314)
        #expect(index.packageCount == 35)
        #expect(index.project(repo: "GitHub.com/OpenSSL/OpenSSL")?.slug == "openssl")
        #expect(index.keys.count == index.packageCount + index.projects.count)
        // all-time: packages whose only advisories are years old are in it
        let old = PrivacyFilter(index: index).approve([InstalledPackage(ecosystem: .npm, name: "minimist", version: "0.0.8", origin: .cargoInstall)])
        #expect(old.approved.count == 1)
    }

    @Test func readsTheFormatAndIgnoresWhatItDoesNotKnow() throws {
        let tsv = "#osva-app-index\t1\tT\t2\t1\nP\tcurl\tcurl\tgithub.com/curl/curl\nK\tnpm\tevil-pkg\nZ\tfuture\trecord\nK\tPyPI\tpyyaml\textra\r\n\n"
        let index = try PublicIndex.decode(Data(tsv.utf8))
        #expect(index.packageCount == 2 && index.projects.map(\.slug) == ["curl"])
        let mask = Core.shared.select(inventory: ["npm\u{1F}evil-pkg", "PyPI\u{1F}pyyaml", "project\u{1F}curl", "npm\u{1F}other"], index: index.keys)
        #expect(mask == [true, true, true, false])
        #expect(throws: PublicIndex.DecodeError.self) { try PublicIndex.decode(Data("<html>maintenance</html>".utf8)) }
        #expect(throws: PublicIndex.DecodeError.self) { try PublicIndex.decode(Data("#osva-app-index\t2\tT\n".utf8)) }
    }

    @Test("PyPI names as the index writes them", arguments: [
        ("Flask_Login", "flask-login"), ("zope.interface", "zope-interface"), ("typing__extensions", "typing-extensions"),
        ("PyYAML", "pyyaml"), ("a-_.b", "a-b"),
    ])
    func pypiNames(_ name: String, _ expected: String) {
        #expect(PackageNames.indexName(name, in: .pypi) == expected)
    }

    @Test func otherRegistriesKeepTheirSpelling() {
        #expect(PackageNames.indexName("JSONStream", in: .npm) == "JSONStream")
        #expect(PackageNames.indexName("WWBN/AVideo", in: .packagist) == "WWBN/AVideo")
        #expect(PackageNames.key(.pypi, "Jinja2") == "PyPI\u{1F}jinja2")
    }
}

@Suite struct PrivacyFilterTests {
    @Test func onlyPackagesInTheIndexAreApproved() {
        let installed = [
            InstalledPackage(ecosystem: .pypi, name: "URLLib3", version: "1.26.5", origin: .cargoInstall),        // in the index (normalised)
            InstalledPackage(ecosystem: .npm, name: "my-private-tool", version: "1.0.0", origin: .cargoInstall),  // not in the index
            InstalledPackage(ecosystem: .npm, name: "Lodash", version: "4.17.20", origin: .cargoInstall),         // npm names are exact
            InstalledPackage(ecosystem: .npm, name: "lodash", version: "4.17.20\nX-Evil: 1", origin: .cargoInstall), // not a version
            InstalledPackage(ecosystem: Ecosystem("Homebrew"), name: "lodash", version: "1", origin: .cargoInstall), // not checkable
            InstalledPackage(ecosystem: .npm, name: "lodash", version: "4.17.20", origin: .npmGlobal(npm: "npm")),
            InstalledPackage(ecosystem: .npm, name: "lodash", version: "4.17.20", origin: .folder(root: "/p", lockfile: "/p/package-lock.json", direct: true)),
            InstalledPackage(ecosystem: .npm, name: "lodash", version: "4.17.20", origin: .folder(root: "/q", lockfile: "/q/package-lock.json", direct: false)),
        ]
        let r = PrivacyFilter(index: Fixture.index).approve(installed)
        // installed on this Mac ("macos") and in project folders (no platform: deployed anywhere) are separate questions
        #expect(Set(r.approved.keys.map(\.sentDescription)) == ["PyPI urllib3 1.26.5 · macOS", "npm lodash 4.17.20 · macOS", "npm lodash 4.17.20"])
        #expect(r.approved.values.map(\.count).sorted() == [1, 1, 2])         // both project copies stand behind one request
        #expect(r.withheld.count == 4)
    }

    @Test func projectsToo() {
        let r = PrivacyFilter(index: Fixture.index).approve(projects: ["openssl", "my-company-internal", "openssl"])
        #expect(r.map(\.slug) == ["openssl"])
    }
}

@Suite struct RequestTests {
    @Test func urls() {
        #expect(SiteURL.index.absoluteString == "https://verificationalliance.org/data/app-index.tsv")
        #expect(SiteURL.checkBatch.absoluteString == "https://verificationalliance.org/api/v1/check/batch")
        #expect(SiteURL.projectPage(slug: "openssl").absoluteString == "https://verificationalliance.org/#/project/openssl")
        #expect(SiteURL.packagePage(.npm, "@babel/core", version: "7.24.0").absoluteString
                == "https://verificationalliance.org/#/check/pkg/npm/%40babel%2Fcore@7.24.0")
        #expect(SiteURL.packagePage(.crates, "time", version: nil).absoluteString == "https://verificationalliance.org/#/check/pkg/crates.io/time")
        // a hostile name stays one path component
        let project = PrivacyFilter(index: PublicIndex(generatedAt: "", packages: [], projects: [.init(slug: "../../admin?x=1#", name: "", repo: "")]))
            .approve(projects: ["../../admin?x=1#"]).first!
        #expect(SiteURL.project(project).absoluteString == "https://verificationalliance.org/api/v1/project/..%2F..%2Fadmin%3Fx%3D1%23")
    }

    @Test func batchBody() throws {
        let installed = [
            InstalledPackage(ecosystem: .pypi, name: "SetupTools", version: "58.0.4", origin: .pip(python: Fixture.applePython, user: false, formula: nil)),
            InstalledPackage(ecosystem: .npm, name: "lodash", version: "4.17.20", origin: .folder(root: "/p", lockfile: "/p/package-lock.json", direct: true)),
            InstalledPackage(ecosystem: .npm, name: "lodash", version: "4.17.20", origin: .npmGlobal(npm: "/opt/homebrew/bin/npm")),
        ]
        let packages = PrivacyFilter(index: Fixture.index).approve(installed).approved.keys.sorted { $0.cacheKey < $1.cacheKey }
        #expect(packages.count == 3)                         // a project's lodash and this Mac's lodash are two questions
        let body = String(decoding: try APIClient.batchBody(packages), as: UTF8.self)
        #expect(body == #"{"packages":[{"ecosystem":"PyPI","name":"setuptools","platform":"macos","python":"3.9.6","version":"58.0.4"},"#
                + #"{"ecosystem":"npm","name":"lodash","platform":null,"version":"4.17.20"},"#
                + #"{"ecosystem":"npm","name":"lodash","platform":"macos","version":"4.17.20"}]}"#)
        #expect(packages.map(\.sentDescription) == ["PyPI setuptools 58.0.4 · Python 3.9.6 · macOS", "npm lodash 4.17.20", "npm lodash 4.17.20 · macOS"])
    }

    @Test func theSameVersionTwiceGoesInDifferentBatches() {
        let installed = (0..<3).map { i in
            InstalledPackage(ecosystem: .pypi, name: "setuptools", version: "58.0.4",
                             origin: .pip(python: PythonEnvironment(executable: "/x\(i)", version: "3.1\(i).0", kind: .other, externallyManaged: false,
                                                                    userSite: nil, formula: nil), user: false, formula: nil))
        } + [InstalledPackage(ecosystem: .npm, name: "lodash", version: "4.17.20", origin: .cargoInstall)]
        let packages = Array(PrivacyFilter(index: Fixture.index).approve(installed).approved.keys)
        let batches = Scanner.batches(packages)
        #expect(batches.count == 3 && batches.flatMap { $0 }.count == 4)
        for b in batches { #expect(Set(b.map(\.versionKey)).count == b.count) }
    }

    @Test func requestsCarryOnlyWhatWasApproved() async throws {
        let transport = RecordedTransport.site()
        let api = APIClient(transport: transport, pause: { _ in })
        let packages = Array(approved([(.pypi, "urllib3", "1.26.5"), (.npm, "lodash", "4.17.20")]).keys)
        _ = try await api.checkBatch(packages)
        let request = try #require(transport.requests.first)
        #expect(request.httpMethod == "POST")
        #expect(request.value(forHTTPHeaderField: "User-Agent") == HTTPHeaders.userAgent)
        #expect(request.value(forHTTPHeaderField: "Cookie") == nil)
        let sent = await api.takeSentRequests()
        #expect(sent == [SentRequest(endpoint: "POST api/v1/check/batch", items: packages.map(\.sentDescription))])
        #expect(await api.takeSentRequests().isEmpty)
    }

    @Test func backsOffWhenRateLimited() async throws {
        let pauses = Locked<[Duration]>([])
        let transport = RecordedTransport { request, n in
            n < 2 ? .init(status: 429, headers: n == 0 ? ["Retry-After": "7"] : [:], body: Data(#"{"error":"Too many checks; slow down."}"#.utf8))
                  : .init(status: 200, body: Fixture.data("api/check-batch.json"))
        }
        let api = APIClient(transport: transport, pause: { d in pauses.mutate { $0.append(d) } })
        let r = try await api.checkBatch(Array(approved([(.npm, "lodash", "4.17.20")]).keys))
        #expect(r.count == 4)
        #expect(pauses.value == [.seconds(7), .seconds(10)])     // the server's Retry-After, then our own backoff
        #expect(transport.requests.count == 3)
    }

    @Test func givesUpPolitely() async {
        let transport = RecordedTransport { _, _ in .init(status: 429, body: Data()) }
        let api = APIClient(transport: transport, pause: { _ in })
        await #expect(throws: APIClient.APIError.keptRateLimiting) { try await api.state() }
        #expect(transport.requests.count == 5)
    }

    @Test func serverErrorsAreReadable() async {
        let api = APIClient(transport: RecordedTransport { _, _ in .init(status: 400, body: Data(#"{"error":"bad request"}"#.utf8)) }, pause: { _ in })
        await #expect(throws: APIClient.APIError.http(status: 400, message: "bad request")) { try await api.state() }
    }
}

@Suite struct ResponseTests {
    @Test func batch() throws {
        let r = try JSONDecoder().decode(BatchResponse.self, from: Fixture.data("api/check-batch.json"))
        #expect(r.checked == 4 && r.packages.count == 4)
        let rack = try #require(r.packages.first { $0.name == "rack" })
        #expect(rack.worstSeverity == "CRITICAL" && rack.distinctFlaws == 35 && !rack.malicious)
        let m = try JSONDecoder().decode(BatchResponse.self, from: Fixture.data("api/check-batch-malicious.json"))
        #expect(m.packages.first { $0.name == "axios" }?.malicious == true)
    }

    @Test func flawsAndPlan() throws {
        let r = try JSONDecoder().decode(BatchResponse.self, from: Fixture.data("api/check-batch-plan.json"))
        let setuptools = try #require(r.packages.first { $0.name == "setuptools" })
        #expect(setuptools.python == "3.9.6" && setuptools.flaws.count == 5)
        #expect(setuptools.flaws.first { $0.id == "PYSEC-2026-3447" }?.platform == "windows")
        #expect(setuptools.flaws.first { $0.id == "PYSEC-2026-3447" }?.affectsThisMac == false)
        let plan = try #require(setuptools.plan)
        #expect(plan.target == "78.1.1" && plan.fixes.count == 3 && plan.newestInstallable == "82.0.1" && plan.requiresPython == ">=3.9")
        #expect(plan.remaining.map(\.reason) == [.needsPython, .otherPlatform])
        #expect(plan.remaining[0].detail == "Python >=3.10" && plan.remaining[0].fixedIn == "83.0.0")
        let axios = try #require(r.packages.first { $0.name == "axios" })
        #expect(axios.malicious && axios.plan?.target == nil && axios.plan?.remaining.first?.reason == .malicious)
        // an answer from before plans existed still reads
        let old = try JSONDecoder().decode(BatchResponse.self, from: Fixture.data("api/check-batch.json"))
        #expect(old.packages.allSatisfy { $0.flaws.isEmpty && $0.plan == nil })
    }

    @Test func projects() throws {
        let nginx = try JSONDecoder().decode(ProjectResponse.self, from: Fixture.data("api/project-nginx.json"))
        #expect(nginx.recent.contains { $0.fixedHint == ["1.31.9", "1.30.7"] && $0.severity == "CRITICAL" })
        #expect(nginx.verificationMark == .none)
        let hacl = try JSONDecoder().decode(ProjectResponse.self, from: Fixture.data("api/project-hacl-star.json"))
        #expect(hacl.verificationTier == "fully_verified_artifact" && hacl.verificationMark == .whole)
        let openssh = try JSONDecoder().decode(ProjectResponse.self, from: Fixture.data("api/project-openssh.json"))
        #expect(openssh.verificationTier == "ships_proved_code" && openssh.verificationMark == .parts)
        let openssl = try JSONDecoder().decode(ProjectResponse.self, from: Fixture.data("api/project-openssl.json"))
        #expect(openssl.grade == "B")
        // a cached copy reads back the same
        let again = try JSONDecoder().decode(ProjectResponse.self, from: JSONEncoder().encode(nginx))
        #expect(again.recent == nginx.recent && again.verified == nginx.verified)
    }

    @Test func state() throws {
        let s = try JSONDecoder().decode(StateResponse.self, from: Fixture.data("api/state.json"))
        let nginx = try #require(s.bigIssues.first { $0.slug == "nginx" })
        #expect(nginx.fixedIn == ["1.30.7", "1.31.9"] && nginx.severity == "CRITICAL")
        #expect(s.bigIssues.first { $0.slug == "openssh" }?.exploited == true)
        let again = try JSONDecoder().decode(StateResponse.self, from: JSONEncoder().encode(s))
        #expect(again.bigIssues == s.bigIssues)
    }
}

@Suite struct IndexStoreTests {
    @Test func downloadsOnceThenAsksConditionally() async throws {
        let dir = temporaryDirectory()
        let transport = RecordedTransport { request, n in
            n == 0 ? .init(status: 200, headers: ["ETag": "\"abc\"", "Last-Modified": "Thu, 19 Nov 2026 01:33:07 GMT"], body: Fixture.data("api/app-index.tsv"))
                   : .init(status: 304, body: Data())
        }
        let store = IndexStore(directory: dir, transport: transport)
        let t0 = Date()
        _ = try await store.load(now: t0)
        _ = try await store.load(now: t0.addingTimeInterval(3600))               // fresh: no request
        #expect(transport.requests.count == 1)
        let loaded = try await store.load(now: t0.addingTimeInterval(2 * 86_400))  // a day old: a conditional request
        #expect(transport.requests.count == 2)
        #expect(transport.requests[1].value(forHTTPHeaderField: "If-None-Match") == "\"abc\"")
        #expect(transport.requests[1].value(forHTTPHeaderField: "If-Modified-Since") == "Thu, 19 Nov 2026 01:33:07 GMT")
        #expect(loaded.index.projects.count == 314 && loaded.problem == nil)
    }

    @Test func keepsTheOldCopyWhenOffline() async throws {
        let dir = temporaryDirectory()
        let online = RecordedTransport { _, _ in .init(status: 200, body: Fixture.data("api/app-index.tsv")) }
        _ = try await IndexStore(directory: dir, transport: online).load()
        let offline = RecordedTransport { _, _ in .init(status: 502, body: Data()) }
        let loaded = try await IndexStore(directory: dir, transport: offline).load(now: Date().addingTimeInterval(3 * 86_400))
        #expect(loaded.index.projects.count == 314)
        #expect(loaded.problem?.hasPrefix("Could not refresh the public index") == true)
    }

    @Test func neverStoresSomethingThatIsNotAnIndex() async {
        let dir = temporaryDirectory()
        let broken = RecordedTransport { _, _ in .init(status: 200, body: Data("<html>maintenance</html>".utf8)) }
        await #expect(throws: (any Error).self) { try await IndexStore(directory: dir, transport: broken).load() }
        #expect(!FileManager.default.fileExists(atPath: dir.appendingPathComponent("app-index.tsv").path))
    }
}

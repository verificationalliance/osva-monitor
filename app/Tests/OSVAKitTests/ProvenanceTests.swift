import Foundation
import Testing
@testable import OSVAKit

/// A site-packages folder made on disk for a test, one `.dist-info` per distribution.
struct FakeSite {
    let url: URL
    var path: String { url.path }

    init(_ name: String = #function, in parent: URL? = nil) {
        url = (parent ?? temporaryDirectory(name)).appendingPathComponent("site-packages")
        try! FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    }

    /// Writes `<name>-<version>.dist-info` (METADATA, INSTALLER, REQUESTED, direct_url.json, top_level.txt) and the
    /// package's folder, then sets the metadata folder's time to `installed`.
    @discardableResult
    func dist(_ name: String, _ version: String, requires: [String] = [], requested: Bool = false, installer: String? = "pip",
              directURL: String? = nil, topLevel: String? = nil, installed: Date? = nil, package: Bool = true) -> URL {
        let dir = url.appendingPathComponent("\(name.replacingOccurrences(of: "-", with: "_"))-\(version).dist-info")
        var metadata = "Metadata-Version: 2.1\nName: \(name)\nVersion: \(version)\n"
        for r in requires { metadata += "Requires-Dist: \(r)\n" }
        metadata += "\nThe long description.\nRequires-Dist: not-a-header-in-the-body\n"
        write(metadata, to: dir.appendingPathComponent("METADATA"))
        if let installer { write(installer + "\n", to: dir.appendingPathComponent("INSTALLER")) }
        if requested { write("", to: dir.appendingPathComponent("REQUESTED")) }
        if let directURL { write(directURL, to: dir.appendingPathComponent("direct_url.json")) }
        if let topLevel { write(topLevel + "\n", to: dir.appendingPathComponent("top_level.txt")) }
        if package { write("", to: url.appendingPathComponent(name.replacingOccurrences(of: "-", with: "_").lowercased() + "/__init__.py")) }
        if let installed { try! FileManager.default.setAttributes([.modificationDate: installed], ofItemAtPath: dir.path) }
        return dir
    }
}

let utc = TimeZone(identifier: "UTC")!
func date(_ s: String) -> Date { ISO8601DateFormatter().date(from: s + "T12:00:00Z")! }

@Suite struct SitePackagesTests {
    @Test func whoAskedForItAndWhichToolInstalledIt() {
        let site = FakeSite()
        site.dist("fastapi", "0.120.0", requested: true)
        site.dist("starlette", "0.48.0")
        site.dist("chromadb", "0.4.24", installer: "Poetry 2.3.2")
        site.dist("odd", "1.0", installer: nil)
        let s = SitePackages(sites: [site.path])
        #expect(s.complete)
        #expect(s.distribution("fastapi")?.requested == true)
        #expect(s.distribution("starlette")?.requested == false)          // pip writes REQUESTED; it did not
        #expect(s.distribution("chromadb")?.requested == nil)             // Poetry never writes it: unknown
        #expect(s.distribution("chromadb")?.installer == "Poetry 2.3.2")
        #expect(s.distribution("odd")?.requested == nil)
    }

    @Test func aSiteWithoutAnyRequestedPredatesIt() {
        let site = FakeSite()
        site.dist("six", "1.15.0")
        site.dist("certifi", "2022.12.7")
        #expect(SitePackages(sites: [site.path]).distribution("six")?.requested == nil)
    }

    /// The fix flow refuses an upgrade a dependent does not accept: what each accepts, from METADATA, by any spelling.
    @Test func reverseDependenciesKeepEachSpecifier() {
        let site = FakeSite()
        site.dist("fastapi", "0.120.0", requires: ["starlette<0.49.0,>=0.40.0", "pydantic>=1.7.4"], requested: true)
        site.dist("prometheus-fastapi-instrumentator", "7.1.0", requires: ["starlette (>=0.30.0,<1.0.0)"])
        site.dist("sentry-sdk", "2.58.0", requires: [#"starlette>=0.19.1; extra == "starlette""#])
        site.dist("transformers", "4.51.3", requires: [#"Starlette; extra == "serving""#])
        site.dist("Starlette", "0.48.0")
        let deps = ReverseDependencies.for(package: "STARLETTE", in: [site.path])
        #expect(deps.map(\.dependent) == ["fastapi", "prometheus-fastapi-instrumentator"])
        #expect(deps.map(\.specifier) == ["<0.49.0,>=0.40.0", ">=0.30.0,<1.0.0"])
        #expect(deps.map(\.version) == ["0.120.0", "7.1.0"])
        #expect(deps.map(\.requestedByUser) == [true, false])
        #expect(deps.allSatisfy { $0.site == site.path && !$0.isProject })
        #expect(SitePackages(sites: [site.path]).isNamedByAnExtra("starlette"))   // sentry-sdk[starlette] would need it
    }

    @Test("markers: only the plainly false are dropped", arguments: [
        (#"pywin32; sys_platform == "win32""#, false),
        (#"appnope; sys_platform == "darwin""#, true),
        (#"colorama; platform_system == "Windows""#, false),
        (#"x; platform_system != 'Darwin'"#, false),
        (#"y; os_name == "nt""#, false),
        (#"uvloop; sys_platform != "win32" and implementation_name == "cpython""#, true),
        (#"z; sys_platform == "win32" or python_version < "3.8""#, true),       // "or": kept, not evaluated
        (#"tomli; python_version < "3.11""#, true),                             // Python versions: kept
        (#"w; sys_platform == "linux" and extra == "gpu""#, false),
    ])
    func markers(_ line: String, _ kept: Bool) {
        #expect((SitePackages.requirement(line) != nil) == kept, "\(line)")
    }

    @Test func requirementForms() throws {
        let a = try #require(SitePackages.requirement("uvicorn[standard, other] >= 0.29 , < 1"))
        #expect(a.key == "uvicorn" && a.extras == ["standard", "other"] && a.specifier == ">=0.29,<1" && a.forExtras.isEmpty)
        let b = try #require(SitePackages.requirement(#"pytest>=8.0.0; extra == "dev""#))
        #expect(b.forExtras == ["dev"] && b.marker == #"extra == "dev""#)
        let c = try #require(SitePackages.requirement("Zope.Interface"))
        #expect(c.key == "zope-interface" && c.specifier == "")
        let d = try #require(SitePackages.requirement("pkg @ https://example.org/pkg-1.0.whl"))
        #expect(d.specifier == "@ https://example.org/pkg-1.0.whl")
        #expect(SitePackages.requirement("") == nil && SitePackages.requirement(";;;") == nil)
    }

    /// blooper-backend asks for uvicorn[standard]: uvicorn's "standard" requirements are in use, its others are not.
    @Test func extrasSomeoneAsksForCount() {
        let site = FakeSite()
        site.dist("blooper-backend", "0.1.0", requires: ["uvicorn[standard]>=0.29.0"], directURL: #"{"url": "file:///Users/ana/code/blooper", "dir_info": {"editable": true}}"#)
        site.dist("uvicorn", "0.30.0", requires: [#"watchfiles>=0.13; extra == "standard""#, #"websockets[speedups]>=10; extra == "standard""#,
                                                   #"rich; extra == "fancy""#])
        site.dist("watchfiles", "1.1.1")
        site.dist("websockets", "15.0", requires: [#"speedlib; extra == "speedups""#])
        site.dist("speedlib", "1.0")
        site.dist("rich", "13.0")
        let s = SitePackages(sites: [site.path])
        #expect(s.dependents(of: "watchfiles").map(\.distribution.name) == ["uvicorn"])
        #expect(s.dependents(of: "speedlib").map(\.distribution.name) == ["websockets"])       // through an extra's extra
        #expect(s.dependents(of: "rich").isEmpty && s.isNamedByAnExtra("rich"))
        #expect(!s.isNamedByAnExtra("watchfiles"))
        let chain = s.chainToTop(of: "speedlib")
        #expect(chain?.chain.map(\.name) == ["websockets", "uvicorn", "blooper-backend"] && chain?.top == .project)
    }

    @Test func theChainGoesUpToYourProjectPastPackagesInstalledByName() {
        let site = FakeSite()
        site.dist("blooper-backend", "0.1.0", requires: ["fastapi>=0.111.0", "prometheus-fastapi-instrumentator>=6.1.0"],
                  directURL: #"{"url": "file:///Users/ana/code/blooper", "dir_info": {"editable": true}}"#)
        site.dist("fastapi", "0.120.0", requires: ["starlette<0.49.0,>=0.40.0"], requested: true)
        site.dist("prometheus-fastapi-instrumentator", "7.1.0", requires: ["starlette>=0.30.0,<1.0.0"])
        site.dist("starlette", "0.48.0")
        let s = SitePackages(sites: [site.path])
        let c = s.chainToTop(of: "starlette")
        #expect(c?.chain.map(\.name) == ["fastapi", "blooper-backend"] && c?.top == .project)
        #expect(s.distribution("blooper-backend")?.projectFolder == "/Users/ana/code/blooper")
        #expect(s.chainToTop(of: "blooper-backend") == nil)
    }

    @Test func cyclesEnd() {
        let site = FakeSite()
        site.dist("a", "1", requires: ["b"])
        site.dist("b", "1", requires: ["a"])
        site.dist("c", "1", requires: ["a"])
        #expect(SitePackages(sites: [site.path]).chainToTop(of: "a")?.chain.map(\.name) == ["c"])
    }

    @Test func garbageIsSkippedAndSaidSo() throws {
        let site = FakeSite()
        site.dist("good", "1.0", requires: ["needed"])
        site.dist("needed", "1.0")
        // a half-removed folder with no METADATA: ignored, as pip ignores it
        try FileManager.default.createDirectory(at: site.url.appendingPathComponent("brotli-1.2.1.dist-info"), withIntermediateDirectories: true)
        #expect(SitePackages(sites: [site.path]).complete)
        // binary junk, a header block without a name, a METADATA that is a folder
        try Data([0, 1, 2, 0xFF, 0xFE, 0]).write(to: site.url.appendingPathComponent("junk-1.0.dist-info/METADATA").creatingParent())
        write("Summary: no name or version\n", to: site.url.appendingPathComponent("-.dist-info/METADATA"))
        try FileManager.default.createDirectory(at: site.url.appendingPathComponent("dir-1.0.dist-info/METADATA"), withIntermediateDirectories: true)
        // a stray file named like metadata
        write("not a folder", to: site.url.appendingPathComponent("stray-1.0.dist-info"))
        let s = SitePackages(sites: [site.path, "/nonexistent/site-packages", ""])
        #expect(!s.complete)
        #expect(s.distributions.map(\.name).sorted() == ["good", "needed"])
        #expect(s.dependents(of: "needed").map(\.distribution.name) == ["good"])
        // the body after the headers is not read as headers
        #expect(s.distribution("good")?.requirements.map(\.name) == ["needed"])
    }

    @Test func aHugeMetadataIsReadOnlyUpToItsCap() {
        let site = FakeSite()
        let dir = site.url.appendingPathComponent("big-1.0.dist-info")
        var text = "Name: big\nVersion: 1.0\n"
        for i in 0..<20_000 { text += "Requires-Dist: dep\(i)\n" }       // ~400 KB of headers
        write(text, to: dir.appendingPathComponent("METADATA"))
        let d = SitePackages(sites: [site.path]).distribution("big")
        #expect(d != nil)
        #expect((d?.requirements.count ?? 0) <= SitePackages.maxRequirements)
    }

    /// A METADATA that is a link out of the site (to a private file) is never read.
    @Test func aLinkOutOfTheSiteIsNotFollowed() throws {
        let root = temporaryDirectory()
        let site = FakeSite(in: root)
        let secret = root.appendingPathComponent("private/id_ed25519")
        write("Name: secret\nVersion: 1.0\nRequires-Dist: victim\n", to: secret)
        let dir = site.url.appendingPathComponent("evil-1.0.dist-info")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: dir.appendingPathComponent("METADATA").path, withDestinationPath: secret.path)
        site.dist("victim", "1.0")
        let s = SitePackages(sites: [site.path])
        #expect(s.distribution("secret") == nil && s.distribution("evil") == nil)
        #expect(s.dependents(of: "victim").isEmpty)
        #expect(!s.complete)
        #expect(LocalFiles.read(dir.appendingPathComponent("METADATA").path, limit: 100, within: LocalFiles.roots([site.path])) == nil)
        #expect(LocalFiles.read(secret.path, limit: 100, within: LocalFiles.roots([root.path])) != nil)   // the reader itself works
    }

    @Test func wherePackagesAre() {
        let site = FakeSite()
        site.dist("starlette", "0.48.0", topLevel: "starlette")
        site.dist("PyYAML", "6.0.1", topLevel: "_yaml\nyaml", package: false)
        write("", to: site.url.appendingPathComponent("yaml/__init__.py"))
        write("", to: site.url.appendingPathComponent("_yaml/__init__.py"))
        site.dist("six", "1.16.0", package: false)
        write("", to: site.url.appendingPathComponent("six.py"))
        // protobuf's files are in google/protobuf, inside the "google" folder other packages share
        let pb = site.dist("protobuf", "5.29.5", topLevel: "google", package: false)
        write("google/protobuf/__init__.py,,\ngoogle/protobuf/message.py,,\ngoogle/protobuf/internal/x.py,,\n../../bin/protoc,,\n", to: pb.appendingPathComponent("RECORD"))
        write("", to: site.url.appendingPathComponent("google/protobuf/__init__.py"))
        // no top_level.txt: from RECORD
        let gp = site.dist("GitPython", "3.1.31", package: false)
        write("git/__init__.py,sha256=x,1\ngit/repo/base.py,,\nGitPython-3.1.31.dist-info/METADATA,,\n", to: gp.appendingPathComponent("RECORD"))
        write("", to: site.url.appendingPathComponent("git/__init__.py"))
        let nothing = site.dist("ghost", "1.0", package: false)
        let s = SitePackages(sites: [site.path])
        func at(_ n: String) -> String? { s.distribution(n).map { s.location(of: $0) } }
        #expect(at("starlette") == site.path + "/starlette")
        #expect(at("pyyaml") == site.path + "/yaml")
        #expect(at("six") == site.path + "/six.py")
        #expect(at("protobuf") == site.path + "/google/protobuf")
        #expect(at("gitpython") == site.path + "/git")
        #expect(at("ghost") == nothing.path)                                    // nothing else: its metadata folder
    }

    @Test func eggInfo() {
        let site = FakeSite()
        let dir = site.url.appendingPathComponent("legacy-2.0-py3.11.egg-info")
        write("Metadata-Version: 1.1\nName: legacy\nVersion: 2.0\n", to: dir.appendingPathComponent("PKG-INFO"))
        write("requests>=2\n\n[socks]\nPySocks\n\n[:sys_platform == \"win32\"]\ncolorama\n\n[:python_version < \"3.8\"]\nimportlib-metadata\n",
              to: dir.appendingPathComponent("requires.txt"))
        let d = SitePackages(sites: [site.path]).distribution("legacy")
        #expect(d?.version == "2.0")
        #expect(d?.requirements.filter { $0.forExtras.isEmpty }.map(\.name) == ["requests", "importlib-metadata"])
        #expect(d?.requirements.first { $0.name == "PySocks" }?.forExtras == ["socks"])
    }

    @Test func namesNormaliseAsTheIndexDoes() {
        for n in ["Starlette", "zope.interface", "Foo__Bar--baz", "a-_.b", "PyYAML", "ruamel.yaml.clib", "_private", "x.", "", "Ünïcode_Name"] {
            #expect(SitePackages.key(n) == PackageNames.indexName(n, in: .pypi), "\(n)")
        }
    }

    @Test func directURL() {
        #expect(SitePackages.directURL(Data(#"{"url":"file:///Users/ana/x","dir_info":{"editable":true}}"#.utf8)) == .editable(folder: "/Users/ana/x"))
        #expect(SitePackages.directURL(Data(#"{"url":"file:///Users/ana/x","dir_info":{}}"#.utf8)) == .folder("/Users/ana/x"))
        #expect(SitePackages.directURL(Data(#"{"url":"https://github.com/a/b","vcs_info":{"vcs":"git"}}"#.utf8)) == .vcs)
        #expect(SitePackages.directURL(Data(#"{"url":"file:///tmp/pip-26.whl","archive_info":{}}"#.utf8)) == .archive)
        #expect(SitePackages.directURL(Data("garbage".utf8)) == nil)
    }
}

@Suite struct ProvenanceTextTests {
    @Test func sentences() {
        #expect(ProvenanceText.neededBy(chain: ["fastapi", "blooper-backend"], top: .project) == "Needed by fastapi → blooper-backend (your project)")
        #expect(ProvenanceText.neededBy(chain: ["whisperx"], top: .requested) == "Needed by whisperx (installed by you)")
        #expect(ProvenanceText.neededBy(chain: ["body-parser", "express"], top: .manifest("package.json"))
            == "Needed by body-parser → express (in package.json)")
        #expect(ProvenanceText.neededBy(chain: ["a", "b", "c", "d"], top: .project) == "Needed by a → … → d (your project)")
        #expect(ProvenanceText.neededBy(names: ["ffmpeg", "yt-dlp"], top: .requested) == "Needed by ffmpeg and yt-dlp (installed by you)")
        #expect(ProvenanceText.neededBy(names: ["a", "b", "c", "d"], top: .unknown) == "Needed by a, b and 2 more")
        // nobody known to have asked: the direct dependents, not one chain among many
        #expect(ProvenanceText.neededBy(chain: ["x", "y"], top: .unknown, direct: ["x", "z"], directLikeTop: []) == "Needed by x and z")
        #expect(ProvenanceText.neededBy(chain: ["ffmpeg"], top: .requested, direct: ["ffmpeg", "lib", "yt-dlp"], directLikeTop: ["ffmpeg", "yt-dlp"])
            == "Needed by ffmpeg and yt-dlp (installed by you)")
        #expect(ProvenanceText.installedByYou(on: date("2026-01-12"), timeZone: utc) == "You installed it on 12 Jan 2026")
        #expect(ProvenanceText.installedByYou(on: date("2026-03-03"), with: "npm -g", timeZone: utc) == "You installed it with npm -g on 3 Mar 2026")
        #expect(ProvenanceText.installed(on: date("2026-02-02"), by: "Poetry", timeZone: utc) == "Installed by Poetry on 2 Feb 2026")
        #expect(ProvenanceText.installed(on: nil) == nil)
        #expect(ProvenanceText.unused == "Nothing here uses it — removing it may be better than upgrading it.")
        #expect(ProvenanceText.plausible(Date(timeIntervalSince1970: 499_162_500)) == nil)        // npm's 1985
        #expect(Provenance.Dependent(name: "fastapi", version: "0.120.0", specifier: "<0.49.0").line == "fastapi 0.120.0 needs <0.49.0")
        #expect(Provenance.Dependent(name: "ffmpeg").line == "ffmpeg needs it")
    }

    @Test func savedProvenanceLoadsWithFieldsMissing() throws {
        let p = try JSONDecoder().decode(Provenance.self, from: Data(#"{"path":"/x"}"#.utf8))
        #expect(p == Provenance(path: "/x"))
        let f = try JSONDecoder().decode(InstalledPackage.self, from: Data(#"{"ecosystem":"npm","name":"a","version":"1","origin":{"cargoInstall":{}}}"#.utf8))
        #expect(f.provenance == nil)
    }
}

/// The explainer on pip copies: the sentences each kind of place gets.
@Suite struct PipProvenanceTests {
    static let python = PythonEnvironment(executable: "/opt/homebrew/bin/python3.11", version: "3.11.18", kind: .homebrew, externallyManaged: true,
                                          userSite: nil, formula: "python@3.11")

    func explain(_ name: String, _ version: String, in site: FakeSite, python: PythonEnvironment = python, user: Bool = false,
                 formula: String? = nil, others: [(String, String)] = []) async -> Provenance? {
        let origin = Origin.pip(python: python, user: user, formula: formula)
        let packages = ([(name, version)] + others).map {
            InstalledPackage(ecosystem: .pypi, name: $0.0, version: $0.1, origin: origin, provenance: Provenance(path: site.path))
        }
        let finding = Finding(id: "f", group: .exploited, subject: .package(ecosystem: .pypi, name: PackageNames.indexName(name, in: .pypi)),
                              title: name, installedVersion: version, upgrade: nil, severity: .high, advisoryIDs: [], flawCount: 1,
                              exploited: true, malicious: false, note: nil, bigIssue: nil, origins: [origin],
                              pageURL: SiteURL.packagePage(.pypi, name, version: version), advice: nil, verification: .none, grade: nil)
        let explainer = ProvenanceExplainer(tools: ToolEnvironment(home: URL(fileURLWithPath: "/Users/ana"), base: [:], runner: RecordedRunner(outputs: [:]),
                                                                   isExecutable: { _ in false }), timeZone: utc, homebrewPrefixes: [])
        return await explainer.explain([finding], inventory: Inventory(packages: packages)).first?.provenance?.first
    }

    /// The owner's starlette: there because fastapi needs it, for their project.
    @Test func theOwnersStarlette() async throws {
        let site = FakeSite()
        site.dist("blooper-backend", "0.1.0", requires: ["fastapi>=0.111.0", "prometheus-fastapi-instrumentator>=6.1.0"],
                  directURL: #"{"url": "file:///Users/ana/code/blooper/backend", "dir_info": {"editable": true}}"#, package: false)
        site.dist("fastapi", "0.120.0", requires: ["starlette<0.49.0,>=0.40.0"], requested: true, installed: date("2025-10-23"))
        site.dist("prometheus-fastapi-instrumentator", "7.1.0", requires: ["starlette (>=0.30.0,<1.0.0)"])
        site.dist("starlette", "0.48.0", installed: date("2026-03-03"))
        let p = try #require(await explain("starlette", "0.48.0", in: site))
        #expect(p.path == site.path + "/starlette")
        #expect(p.why == "Needed by fastapi → blooper-backend (your project)")
        #expect(p.advice == nil)
        #expect(p.dependents.map(\.line) == ["fastapi 0.120.0 needs <0.49.0,>=0.40.0", "prometheus-fastapi-instrumentator 7.1.0 needs >=0.30.0,<1.0.0"])
        #expect(p.details == ["blooper-backend is your project, from ~/code/blooper/backend", "Installed by pip on 3 Mar 2026"])
    }

    @Test func installedByName() async throws {
        let site = FakeSite()
        site.dist("gitpython", "3.1.31", requested: true, installed: date("2023-05-30"))
        #expect(try #require(await explain("GitPython", "3.1.31", in: site)).why == "You installed it on 30 May 2023")
        site.dist("tool", "1.0", requested: true, installer: "uv", installed: date("2026-01-12"))
        #expect(try #require(await explain("tool", "1.0", in: site)).why == "You installed it with uv on 12 Jan 2026")
    }

    @Test func neededByWhatYouInstalled() async throws {
        let site = FakeSite()
        site.dist("whisperx", "3.3.4", requires: ["nltk>=3.9.1"], requested: true, installed: date("2025-06-01"))
        site.dist("sentence-transformers", "5.1.2", requires: ["nltk"], requested: true)
        site.dist("other", "1", requires: ["nltk"])
        site.dist("nltk", "3.9.1")
        let p = try #require(await explain("nltk", "3.9.1", in: site))
        #expect(p.why == "Needed by sentence-transformers and whisperx (installed by you)")
        #expect(p.dependents.map(\.name) == ["other", "sentence-transformers", "whisperx"])
    }

    @Test func nothingUsesIt() async throws {
        let site = FakeSite()
        site.dist("fastapi", "0.120.0", requested: true)                    // the site's pip writes REQUESTED
        site.dist("strawberry-graphql", "0.314.3", installed: date("2026-04-20"))
        let p = try #require(await explain("strawberry-graphql", "0.314.3", in: site))
        #expect(p.why == "Installed on 20 Apr 2026 for another package")
        #expect(p.advice == ProvenanceText.unused)
    }

    @Test func removalIsNotSuggestedWhereItIsNotSafeToSay() async throws {
        // an extra names it: pip does not record whether someone asked for that extra
        let a = FakeSite("extra")
        a.dist("fastapi", "0.120.0", requested: true)
        a.dist("sentry-sdk", "2.58.0", requires: [#"starlette>=0.19.1; extra == "starlette""#], requested: true)
        a.dist("starlette", "0.48.0")
        #expect(try #require(await explain("starlette", "0.48.0", in: a)).advice == nil)
        // some metadata could not be read: who needs it is not fully known
        let b = FakeSite("incomplete")
        b.dist("fastapi", "0.120.0", requested: true)
        b.dist("leftover", "1.0")
        try Data([0, 0, 0]).write(to: b.url.appendingPathComponent("junk-1.dist-info/METADATA").creatingParent())
        #expect(try #require(await explain("leftover", "1.0", in: b)).advice == nil)
        // pip itself
        let c = FakeSite("pip")
        c.dist("fastapi", "0.120.0", requested: true)
        c.dist("pip", "25.0.1")
        #expect(try #require(await explain("pip", "25.0.1", in: c)).advice == nil)
        // Apple's Python: part of Xcode
        let d = FakeSite("apple")
        d.dist("six", "1.15.0")
        let apple = PythonEnvironment(executable: "/usr/bin/python3", version: "3.9.6", kind: .apple, externallyManaged: false, userSite: nil, formula: nil)
        let six = try #require(await explain("six", "1.15.0", in: d, python: apple))
        #expect(six.why == "Comes with Apple's Python, part of Xcode" && six.advice == nil)
        // a Homebrew formula's own package
        let e = FakeSite("formula")
        e.dist("fastapi", "0.120.0", requested: true)
        e.dist("pygments", "2.19.2", installer: "brew")
        let pygments = try #require(await explain("pygments", "2.19.2", in: e, formula: "pygments"))
        #expect(pygments.why == "Comes with Homebrew's pygments" && pygments.advice == nil)
    }

    @Test func yourOwnProject() async throws {
        let site = FakeSite()
        site.dist("blooper-backend", "0.1.0", directURL: #"{"url": "file:///Users/ana/code/blooper", "dir_info": {"editable": true}}"#)
        #expect(try #require(await explain("blooper-backend", "0.1.0", in: site)).why == "Your own project, from ~/code/blooper")
    }

    @Test func installedByPoetry() async throws {
        let site = FakeSite()
        site.dist("chromadb", "0.4.24", installer: "Poetry 2.3.2", installed: date("2026-02-02"))
        let p = try #require(await explain("chromadb", "0.4.24", in: site))
        #expect(p.why == "Installed by Poetry on 2 Feb 2026" && p.advice == nil)
    }
}

/// Homebrew's receipts, as a Cellar on disk.
@Suite struct HomebrewReceiptsTests {
    /// A prefix with a Cellar and opt links: each formula `(name, version, onRequest, declared dependencies)`.
    static func prefix(_ formulae: [(String, String, Bool, [String])], name: String = #function, oldReceipt: Bool = false) -> String {
        let prefix = temporaryDirectory(name).appendingPathComponent("homebrew")
        for (n, v, onRequest, deps) in formulae {
            let keg = prefix.appendingPathComponent("Cellar/\(n)/\(v)")
            let runtime = deps.map { d in oldReceipt ? #"{"full_name":"\#(d)","version":"1"}"# : #"{"full_name":"\#(d)","version":"1","declared_directly":true}"# }
                + (oldReceipt ? [] : [#"{"full_name":"ca-certificates","version":"1","declared_directly":false}"#])
            write(#"{"installed_on_request":\#(onRequest),"time":1772539200,"runtime_dependencies":[\#(runtime.joined(separator: ","))]}"#,
                  to: keg.appendingPathComponent("INSTALL_RECEIPT.json"))
            try! FileManager.default.createDirectory(at: prefix.appendingPathComponent("opt"), withIntermediateDirectories: true)
            try? FileManager.default.createSymbolicLink(atPath: prefix.appendingPathComponent("opt/\(n)").path, withDestinationPath: "../Cellar/\(n)/\(v)")
        }
        return prefix.path
    }

    static let mac = [("ffmpeg", "8.0", true, ["xz", "brotli"]), ("yt-dlp", "2026.1", true, ["python@3.13", "brotli"]),
                      ("python@3.13", "3.13.18", false, ["xz", "openssl@3"]), ("openssl@3", "3.6.1", false, ["ca-certificates"]),
                      ("ca-certificates", "2026-10-20", false, []), ("xz", "5.8.1", false, []), ("brotli", "1.2.1", false, []),
                      ("leftover", "1.0", false, []), ("wget", "1.25", true, ["openssl@3"])]

    @Test func dependentsAndChains() {
        let r = HomebrewReceipts(prefix: Self.prefix(Self.mac))
        #expect(r.complete && r.kegs.count == 9)
        #expect(r.dependents(of: "xz") == ["ffmpeg", "python@3.13"])
        #expect(r.dependents(of: "ca-certificates") == ["openssl@3"])            // not python@3.13: it does not declare it
        #expect(r.kegs["xz"]?.onRequest == false && r.kegs["ffmpeg"]?.onRequest == true)
        #expect(r.kegs["xz"]?.installed == Date(timeIntervalSince1970: 1772539200))
        let c = r.chainToTop(of: "ca-certificates")
        #expect(c?.chain == ["openssl@3", "wget"] && c?.top == .requested)
        #expect(r.chainToTop(of: "leftover") == nil)
    }

    @Test func olderReceiptsListEveryRuntimeDependency() {
        let r = HomebrewReceipts(prefix: Self.prefix([("a", "1", true, ["b", "c"]), ("b", "1", false, []), ("c", "1", false, [])], oldReceipt: true))
        #expect(r.dependents(of: "c") == ["a"])
    }

    @Test func garbageInTheCellar() throws {
        let prefix = Self.prefix([("good", "1", true, ["dep"]), ("dep", "1", false, [])])
        let cellar = URL(fileURLWithPath: prefix).appendingPathComponent("Cellar")
        write("", to: cellar.appendingPathComponent(".keepme"))
        try FileManager.default.createDirectory(at: cellar.appendingPathComponent("llvm@22"), withIntermediateDirectories: true)   // no version
        write(#"{"installed_on_request":"yes","runtime_dependencies":"nope"}"#, to: cellar.appendingPathComponent("odd/1.0/INSTALL_RECEIPT.json"))
        #expect(HomebrewReceipts(prefix: prefix).complete)                    // an emptied formula folder is not installed
        write("{not json", to: cellar.appendingPathComponent("broken/1.0/INSTALL_RECEIPT.json"))
        let r = HomebrewReceipts(prefix: prefix)
        #expect(!r.complete)
        #expect(r.kegs["good"] != nil && r.kegs["broken"] == nil && r.kegs["odd"]?.dependencies == [])
        #expect(r.dependents(of: "dep") == ["good"])
        #expect(HomebrewReceipts(prefix: "/nonexistent").kegs.isEmpty)
    }

    func explain(_ origin: Origin, version: String, prefix: String) async -> Provenance? {
        let finding = Finding(id: "f", group: .criticalHigh, subject: .project(slug: "x", name: "X", installedAs: "x"), title: "X",
                              installedVersion: version, upgrade: nil, severity: .high, advisoryIDs: [], flawCount: 1, exploited: false,
                              malicious: false, note: nil, bigIssue: nil, origins: [origin], pageURL: SiteURL.projectPage(slug: "x"),
                              advice: nil, verification: .none, grade: nil)
        let tools = ToolEnvironment(home: URL(fileURLWithPath: "/Users/ana"), base: [:], runner: RecordedRunner(outputs: [:]), isExecutable: { _ in false })
        return await ProvenanceExplainer(tools: tools, timeZone: utc, homebrewPrefixes: [prefix]).explain([finding], inventory: Inventory())
            .first?.provenance?.first
    }

    @Test func formulaSentences() async throws {
        let prefix = Self.prefix(Self.mac)
        let brotli = try #require(await explain(.homebrewFormula(name: "brotli"), version: "1.2.1", prefix: prefix))
        #expect(brotli.path == Paths.realPath(prefix + "/Cellar/brotli/1.2.1"))
        #expect(brotli.why == "Needed by ffmpeg and yt-dlp (installed by you)")
        #expect(brotli.dependents.map(\.line) == ["ffmpeg needs it", "yt-dlp needs it"])
        let python = try #require(await explain(.homebrewFormula(name: "python@3.13"), version: "3.13.18", prefix: prefix))
        #expect(python.why == "Needed by yt-dlp (installed by you)")
        let wget = try #require(await explain(.homebrewFormula(name: "wget"), version: "1.25", prefix: prefix))
        #expect(wget.why == "You installed it on 3 Mar 2026")
        let leftover = try #require(await explain(.homebrewFormula(name: "leftover"), version: "1.0", prefix: prefix))
        #expect(leftover.why == "Installed on 3 Mar 2026 for another formula")
        #expect(leftover.advice == "Nothing else from Homebrew uses it — if you don't either, removing it may be better than upgrading it.")
        #expect(await explain(.homebrewFormula(name: "absent"), version: "1", prefix: prefix) == nil)
    }

    @Test func casks() async throws {
        let root = temporaryDirectory()
        let prefix = root.appendingPathComponent("homebrew")
        let apps = root.appendingPathComponent("Applications")
        try FileManager.default.createDirectory(at: apps.appendingPathComponent("Alfred 5.app"), withIntermediateDirectories: true)
        let room = prefix.appendingPathComponent("Caskroom/alfred")
        try FileManager.default.createDirectory(at: room.appendingPathComponent("5.7.3,2320"), withIntermediateDirectories: true)
        let stamp = room.appendingPathComponent(".metadata/5.7.3,2320/20260408223910.438")
        write(#"{"artifacts":[{"uninstall":[{"quit":"x"}]},{"app":["Alfred 5.app"]},{"zap":[]}]}"#, to: stamp.appendingPathComponent("Casks/alfred.json"))
        write(#"{"default":{"appdir":"\#(apps.path)"}}"#, to: room.appendingPathComponent(".metadata/config.json"))
        try FileManager.default.setAttributes([.modificationDate: date("2026-04-08")], ofItemAtPath: stamp.path)
        let cask = try #require(HomebrewReceipts.cask("alfred", version: "5.7.3", prefix: prefix.path))
        #expect(cask.app == apps.path + "/Alfred 5.app" && cask.installed == date("2026-04-08"))
        let p = try #require(await explain(.homebrewCask(token: "alfred"), version: "5.7.3", prefix: prefix.path))
        #expect(p.path == apps.path + "/Alfred 5.app" && p.why == "You installed it with Homebrew on 8 Apr 2026")
        // garbage metadata: still the Caskroom folder, no date claimed from it
        write("garbage", to: prefix.appendingPathComponent("Caskroom/odd/1.0/x"))
        #expect(HomebrewReceipts.cask("odd", prefix: prefix.path)?.path == prefix.path + "/Caskroom/odd/1.0")
        #expect(HomebrewReceipts.cask("missing", prefix: prefix.path) == nil)
    }
}

/// npm, gems, cargo, apps and lockfiles through the explainer.
@Suite struct OtherProvenanceTests {
    func explain(_ p: InstalledPackage, tools: ToolEnvironment? = nil) async -> Provenance? {
        let finding = Finding(id: "f", group: .criticalHigh, subject: .package(ecosystem: p.ecosystem, name: PackageNames.indexName(p.name, in: p.ecosystem)),
                              title: p.name, installedVersion: p.version, upgrade: nil, severity: .high, advisoryIDs: [], flawCount: 1,
                              exploited: false, malicious: false, note: nil, bigIssue: nil, origins: [p.origin],
                              pageURL: SiteURL.packagePage(p.ecosystem, p.name, version: p.version), advice: nil, verification: .none, grade: nil)
        let t = tools ?? ToolEnvironment(home: URL(fileURLWithPath: "/Users/ana"), base: [:], runner: RecordedRunner(outputs: [:]), isExecutable: { _ in false })
        return await ProvenanceExplainer(tools: t, timeZone: utc, homebrewPrefixes: []).explain([finding], inventory: Inventory(packages: [p]))
            .first?.provenance?.first
    }

    @Test func electronApps() async throws {
        let p = try #require(await explain(InstalledPackage(ecosystem: .npm, name: "electron", version: "18.3.15",
                                                            origin: .electronApp(name: "OpenMTP", bundlePath: "/Applications/OpenMTP.app", caskToken: nil))))
        #expect(p.path == "/Applications/OpenMTP.app" && p.why == "Inside OpenMTP, which ships its own Electron")
    }

    @Test func npmGlobal() async throws {
        let prefix = temporaryDirectory().appendingPathComponent("node")
        write("", to: prefix.appendingPathComponent("lib/node_modules/npm/bin/npm-cli.js"))
        write(#"{"name":"left-pad","version":"1.3.0"}"#, to: prefix.appendingPathComponent("lib/node_modules/left-pad/package.json"))
        try FileManager.default.setAttributes([.modificationDate: date("2026-03-03")], ofItemAtPath: prefix.appendingPathComponent("lib/node_modules/left-pad").path)
        try FileManager.default.createDirectory(at: prefix.appendingPathComponent("bin"), withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: prefix.appendingPathComponent("bin/npm").path, withDestinationPath: "../lib/node_modules/npm/bin/npm-cli.js")
        let npm = prefix.appendingPathComponent("bin/npm").path
        let pad = try #require(await explain(InstalledPackage(ecosystem: .npm, name: "left-pad", version: "1.3.0", origin: .npmGlobal(npm: npm))))
        #expect(pad.path == Paths.realPath(prefix.path) + "/lib/node_modules/left-pad" && pad.why == "You installed it with npm -g on 3 Mar 2026")
        let itself = try #require(await explain(InstalledPackage(ecosystem: .npm, name: "npm", version: "11.0.0", origin: .npmGlobal(npm: npm))))
        #expect(itself.why == "Comes with Node.js")
        #expect(ProvenanceExplainer.Context.npmParent(of: "/p/lib/node_modules/eslint/node_modules/debug", root: "/p/lib/node_modules") == "eslint")
        #expect(ProvenanceExplainer.Context.npmParent(of: "/p/lib/node_modules/@s/x", root: "/p/lib/node_modules") == nil)
    }

    @Test func gems() async throws {
        let base = temporaryDirectory().appendingPathComponent("gems/3.3.0")
        let gem = "/opt/homebrew/opt/ruby/bin/gem"
        // RubyGems before 3 wrote every dependency again as add_dependency, development ones too
        write("""
        Gem::Specification.new do |s|
          s.name = "rails".freeze
          if s.respond_to? :add_runtime_dependency then
            s.add_runtime_dependency(%q<rack>.freeze, ["~> 2.0"])
            s.add_development_dependency(%q<minitest>.freeze, [">= 0"])
          else
            s.add_dependency(%q<rack>.freeze, ["~> 2.0"])
            s.add_dependency(%q<minitest>.freeze, [">= 0"])
          end
        end
        """, to: base.appendingPathComponent("specifications/rails-7.0.0.gemspec"))
        write("Gem::Specification.new do |s|\n  s.add_dependency(\"rack\")\nend\n", to: base.appendingPathComponent("specifications/sinatra-4.0.0.gemspec"))
        write("Gem::Specification.new do |s|\nend\n", to: base.appendingPathComponent("specifications/rack-2.2.3.gemspec"))
        write("Gem::Specification.new do |s|\nend\n", to: base.appendingPathComponent("specifications/minitest-5.11.3.gemspec"))
        write("Gem::Specification.new do |s|\nend\n", to: base.appendingPathComponent("specifications/default/json-2.1.0.gemspec"))
        write("\0\0garbage", to: base.appendingPathComponent("specifications/broken.gemspec"))
        for g in ["rails-7.0.0", "rack-2.2.3", "minitest-5.11.3", "sinatra-4.0.0"] {
            try FileManager.default.createDirectory(at: base.appendingPathComponent("gems/\(g)"), withIntermediateDirectories: true)
        }
        try FileManager.default.setAttributes([.modificationDate: date("2026-01-05")], ofItemAtPath: base.appendingPathComponent("gems/minitest-5.11.3").path)
        let tools = ToolEnvironment(home: URL(fileURLWithPath: "/Users/ana"), base: [:], runner: RecordedRunner(outputs: [
            "\(gem) env gempath": CommandResult(status: 0, stdout: Data((base.path + ":/nonexistent\n").utf8), stderr: Data()),
        ]), isExecutable: { _ in true })
        func p(_ n: String, _ v: String) async -> Provenance? {
            await explain(InstalledPackage(ecosystem: .rubygems, name: n, version: v, origin: .gem(gem: gem)), tools: tools)
        }
        let rack = try #require(await p("rack", "2.2.3"))
        #expect(rack.why == "Needed by rails and sinatra" && rack.path == base.path + "/gems/rack-2.2.3")
        #expect(rack.dependents.map(\.line) == ["rails 7.0.0 needs ~> 2.0", "sinatra 4.0.0 needs any version"])
        #expect(try #require(await p("minitest", "5.11.3")).why == "Installed on 5 Jan 2026; no other gem needs it")   // development only
        #expect(try #require(await p("json", "2.1.0")).why == "Comes with Ruby itself (a default gem)")
        #expect(GemSpecs.nameAndVersion("nokogiri-1.13.8-arm64-darwin")! == ("nokogiri", "1.13.8"))
        #expect(GemSpecs.nameAndVersion("net-telnet-0.2.0")! == ("net-telnet", "0.2.0"))
    }

    @Test func cargoInstalls() async throws {
        let home = temporaryDirectory().appendingPathComponent("cargo")
        write(#"{"installs":{"ripgrep 14.1.0 (registry+https://github.com/rust-lang/crates.io-index)":{"bins":["rg"]}}}"#,
              to: home.appendingPathComponent(".crates2.json"))
        write("", to: home.appendingPathComponent("bin/rg"))
        try FileManager.default.setAttributes([.modificationDate: date("2026-02-14")], ofItemAtPath: home.appendingPathComponent("bin/rg").path)
        let tools = ToolEnvironment(home: URL(fileURLWithPath: "/Users/ana"), base: ["CARGO_HOME": home.path], runner: RecordedRunner(outputs: [:]),
                                    isExecutable: { _ in false })
        let p = try #require(await explain(InstalledPackage(ecosystem: .crates, name: "ripgrep", version: "14.1.0", origin: .cargoInstall), tools: tools))
        #expect(p.path == home.path + "/bin/rg" && p.why == "You installed it with cargo install on 14 Feb 2026" && p.details == ["It gives you rg"])
    }

    @Test func lockfiles() async throws {
        let project = temporaryDirectory().appendingPathComponent("shop")
        write(#"{"dependencies":{"express":"^4.18.2"}}"#, to: project.appendingPathComponent("package.json"))
        write(LockfileGraphTests.npmLock, to: project.appendingPathComponent("package-lock.json"))
        write(#"{"name":"qs","version":"6.11.0"}"#, to: project.appendingPathComponent("node_modules/body-parser/node_modules/qs/package.json"))
        let lock = project.appendingPathComponent("package-lock.json").path
        func p(_ n: String, _ v: String, direct: Bool?) async -> Provenance? {
            await explain(InstalledPackage(ecosystem: .npm, name: n, version: v, origin: .folder(root: project.path, lockfile: lock, direct: direct)))
        }
        let qs = try #require(await p("qs", "6.11.0", direct: false))
        #expect(qs.why == "Needed by body-parser → express (in package.json)")
        #expect(qs.path == project.path + "/node_modules/body-parser/node_modules/qs")
        #expect(qs.details == ["package.json → express → body-parser → qs"])
        let express = try #require(await p("express", "4.18.2", direct: true))
        #expect(express.why == "Named in your package.json" && express.path == project.path)      // not installed here: the project
        let lone = try #require(await p("not-in-graph", "1.0.0", direct: false))
        #expect(lone.why == "Needed by another of the project's dependencies")
    }
}

/// Provenance is read after the API is asked, and from nothing the API is given: the requests are the same with it
/// and without it, byte for byte, and name nothing it found.
@Suite struct ProvenancePrivacyTests {
    @Test func batchBodiesAreTheSameWithProvenance() throws {
        let plain = [InstalledPackage(ecosystem: .pypi, name: "setuptools", version: "58.0.4", origin: .pip(python: Fixture.applePython, user: false, formula: nil)),
                     InstalledPackage(ecosystem: .npm, name: "lodash", version: "4.17.20", origin: .npmGlobal(npm: "/opt/homebrew/bin/npm"))]
        var explained = plain
        for i in explained.indices {
            explained[i].provenance = Provenance(path: "/Users/ana/secret-project/site-packages", why: "Needed by secret-project (your project)",
                                                 advice: ProvenanceText.unused, dependents: [.init(name: "secret-dependent", specifier: "<1")],
                                                 details: ["secret-project is your project, from ~/secret-project"])
        }
        func body(_ p: [InstalledPackage]) throws -> Data {
            try APIClient.batchBody(PrivacyFilter(index: Fixture.index).approve(p).approved.keys.sorted { $0.cacheKey < $1.cacheKey })
        }
        #expect(try body(plain) == body(explained))
        #expect(!String(decoding: try body(explained), as: UTF8.self).contains("secret"))
    }

    /// Two whole scans of the same Mac, one able to read the site-packages (provenance) and one not: what was sent is
    /// identical, and none of what provenance read is in it.
    @Test func aScanSendsTheSameWithAndWithoutProvenance() async throws {
        func scan(readable: Bool) async throws -> (requests: [URLRequest], report: ScanReport) {
            let home = temporaryDirectory("scan\(readable)")
            let site = FakeSite(in: home.appendingPathComponent("secret-project"))
            if readable {
                site.dist("secret-project", "0.1.0", requires: ["setuptools>=40"], directURL: #"{"url":"file:///Users/ana/secret-project","dir_info":{"editable":true}}"#)
                site.dist("setuptools", "58.0.4")
            }
            let exe = home.appendingPathComponent("system-root/opt/homebrew/bin/python3").path        // Homebrew's, on the fixture Mac
            let describe = #"{"version": "3.9.6", "executable": "\#(exe)", "prefix": "/opt/homebrew/opt/python@3.9/Frameworks/Python.framework/Versions/3.9", "base_prefix": "/opt/homebrew/opt/python@3.9/Frameworks/Python.framework/Versions/3.9", "stdlib": "/nonexistent", "usersite": null}"#
            let list = #"[{"name": "setuptools", "version": "58.0.4", "location": "\#(site.path)", "installer": "pip"}, {"name": "secret-project", "version": "0.1.0", "location": "\#(site.path)", "installer": "pip"}]"#
            let tools = ToolEnvironment.fixture(home: home, runner: RecordedRunner(outputs: [
                "\(exe) -c \(PythonSource.describeScript)": CommandResult(status: 0, stdout: Data(describe.utf8), stderr: Data()),
                "\(exe) -m pip list -v --format=json --disable-pip-version-check": CommandResult(status: 0, stdout: Data(list.utf8), stderr: Data()),
            ]), isExecutable: { $0 == exe })
            let transport = RecordedTransport.site(batch: "api/check-batch-plan.json")
            let scanner = Scanner(configuration: ScanConfiguration(storage: Storage(directory: home.appendingPathComponent("support")), tools: tools,
                                                                   folders: [], applicationRoots: []), transport: transport, pause: { _ in })
            return (transport.requests, await scanner.scan())
        }
        let with = try await scan(readable: true), without = try await scan(readable: false)
        let setuptools = try #require(with.report.findings.first { $0.title == "setuptools" })
        #expect(setuptools.provenance?.first?.why == "Needed by secret-project (your project)")        // it was read...
        #expect(without.report.findings.first { $0.title == "setuptools" }?.provenance?.first?.why == nil)
        func wire(_ rs: [URLRequest]) -> [String] { rs.map { ($0.httpMethod ?? "GET") + " " + ($0.url?.absoluteString ?? "") + " " + String(decoding: $0.httpBody ?? Data(), as: UTF8.self) } }
        #expect(wire(with.requests) == wire(without.requests))                                            // ...and nothing sent changed
        for w in wire(with.requests) {
            for secret in ["secret-project", "site-packages", "/Users/", "Needed by"] { #expect(!w.contains(secret), "\(secret) left the Mac in \(w)") }
        }
        #expect(with.report.sent == without.report.sent)
    }
}

extension URL {
    /// Creates the parent folder and returns the URL (for writing raw bytes).
    func creatingParent() -> URL {
        try! FileManager.default.createDirectory(at: deletingLastPathComponent(), withIntermediateDirectories: true)
        return self
    }
}

import Foundation
import Testing
@testable import OSVAKit

/// The app reads lockfiles the way the site does: every fixture gives exactly what the site's parseDeps gives
/// (lockfiles-expected.json, written by running the site's JavaScript over the same files).
@Suite struct LockfileParserTests {
    struct Expected: Decodable { var dependencies: [[String]]; var skipped: [String] }
    static let expected: [String: Expected] = try! JSONDecoder().decode([String: Expected].self, from: Fixture.data("lockfiles-expected.json"))

    @Test("agrees with the site's parseDeps", arguments: expected.keys.sorted())
    func agreesWithTheSite(_ fixture: String) {
        let file = Fixture.url("lockfiles/" + fixture)
        let parsed = LockfileParser.parse(Fixture.text("lockfiles/" + fixture), filename: file.lastPathComponent)
        let ours = Set(parsed.dependencies.map { [$0.ecosystem.rawValue, $0.name, $0.version] })
        let theirs = Set(Self.expected[fixture]!.dependencies)
        #expect(ours == theirs, "only ours: \(ours.subtracting(theirs)); only the site's: \(theirs.subtracting(ours))")
        #expect(parsed.skipped == Self.expected[fixture]!.skipped)
    }

    @Test func everyLockfileTypeHasAFixture() {
        let names = Set(Self.expected.keys.map { ($0 as NSString).lastPathComponent })
        for name in FolderSource.lockfileNames { #expect(names.contains(name), "no fixture for \(name)") }
        #expect(names.contains { $0.hasPrefix("requirements") && $0.hasSuffix(".txt") })
    }

    @Test func detailsThatMatter() {
        let lock = LockfileParser.parse(Fixture.text("lockfiles/npm-v3/package-lock.json"), filename: "package-lock.json").dependencies
        #expect(lock.contains(Dependency(ecosystem: .npm, name: "string-width", version: "4.2.3")))   // aliased: the real name
        #expect(!lock.contains { $0.name == "local-lib" || $0.name == "vendored" })                     // links and file: deps are not on npm
        let cargo = LockfileParser.parse(Fixture.text("lockfiles/cargo/Cargo.lock"), filename: "Cargo.lock").dependencies
        #expect(!cargo.contains { $0.name == "git-dep" || $0.name == "demo" })                           // only crates.io crates
        let req = LockfileParser.parse(Fixture.text("lockfiles/requirements/requirements-dev.txt"), filename: "requirements-dev.txt").dependencies
        #expect(req.contains(Dependency(ecosystem: .pypi, name: "requests", version: "2.31.0")))          // extras dropped
        #expect(!req.contains { $0.name == "numpy" })                                                    // ranges are not pins
    }

    @Test func notALockfile() {
        #expect(LockfileParser.parse("", filename: "requirements.txt").dependencies.isEmpty)
        #expect(LockfileParser.parse("[1, 2, 3]", filename: "package-lock.json").dependencies.isEmpty)
        #expect(LockfileParser.parse("{}", filename: "package-lock.json").dependencies.isEmpty)
        // A version with characters no registry uses is never taken
        #expect(LockfileParser.parse("evil==1.0;rm", filename: "requirements.txt").dependencies == [Dependency(ecosystem: .pypi, name: "evil", version: "1.0")])
    }
}

@Suite struct FolderSourceTests {
    @Test func findsLockfilesAndSkipsWhatIsNotTheProject() throws {
        let root = temporaryDirectory()
        write(Fixture.text("lockfiles/npm-v3/package-lock.json"), to: root.appendingPathComponent("web/package-lock.json"))
        write(Fixture.text("lockfiles/cargo/Cargo.lock"), to: root.appendingPathComponent("tools/cli/Cargo.lock"))
        write(Fixture.text("lockfiles/requirements/requirements-dev.txt"), to: root.appendingPathComponent("api/requirements-dev.txt"))
        write("lodash==1", to: root.appendingPathComponent("api/notes.txt"))
        write(Fixture.text("lockfiles/npm-v3/package-lock.json"), to: root.appendingPathComponent("web/node_modules/x/package-lock.json"))
        write(Fixture.text("lockfiles/cargo/Cargo.lock"), to: root.appendingPathComponent("tools/cli/target/release/Cargo.lock"))
        write(Fixture.text("lockfiles/go/go.sum"), to: root.appendingPathComponent(".git/go.sum"))
        write(Fixture.text("lockfiles/go/go.sum"), to: root.appendingPathComponent("a/b/c/d/e/f/g/go.sum"))       // too deep
        let found = FolderSource.lockfiles(in: root).map { $0.path.replacingOccurrences(of: root.path + "/", with: "") }
        #expect(found == ["api/requirements-dev.txt", "tools/cli/Cargo.lock", "web/package-lock.json"])

        let result = FolderSource(roots: [root]).collect()
        #expect(result.report.detail == "1 folder, 3 lockfiles")
        let lodash = try #require(result.packages.first { $0.name == "lodash" })
        #expect(lodash.origin == .folder(root: root.path, lockfile: root.appendingPathComponent("web/package-lock.json").path, direct: nil))   // no package.json
    }

    @Test func noFolders() {
        let r = FolderSource(roots: []).collect()
        #expect(r.packages.isEmpty)
        #expect(r.report.available == false)
    }

    @Test func watcherReportsTheFolderWhoseLockfileChanged() async throws {
        let root = temporaryDirectory()
        let lock = root.appendingPathComponent("app/package-lock.json")
        write("{}", to: lock)
        let seen = Locked<Set<String>>([])
        let watcher = FolderWatcher(roots: [root.path], latency: 0.2) { roots in seen.mutate { $0.formUnion(roots) } }
        watcher.start()
        defer { watcher.stop() }
        try await Task.sleep(for: .milliseconds(500))
        write(Fixture.text("lockfiles/npm-v3/package-lock.json"), to: lock)
        for _ in 0..<40 where seen.value.isEmpty { try await Task.sleep(for: .milliseconds(100)) }
        #expect(seen.value == [root.path])                    // the folder as it was given, though FSEvents writes /private/var/…
    }
}

final class Locked<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var _value: T
    init(_ v: T) { _value = v }
    var value: T { lock.lock(); defer { lock.unlock() }; return _value }
    func mutate(_ f: (inout T) -> Void) { lock.lock(); f(&_value); lock.unlock() }
}

@Suite struct ManifestTests {
    func project(_ files: [String: String]) -> URL {
        let dir = temporaryDirectory()
        for (name, text) in files { write(text, to: dir.appendingPathComponent(name)) }
        return dir
    }

    @Test func npmDirectAndIndirect() throws {
        let dir = project(["package.json": #"{"dependencies": {"lodash": "^4.17.0"}, "devDependencies": {"@babel/core": "^7"}}"#,
                           "package-lock.json": Fixture.text("lockfiles/npm-v3/package-lock.json")])
        let packages = FolderSource.packages(in: dir.appendingPathComponent("package-lock.json"), root: dir)
        func direct(_ name: String) -> Bool? {
            guard case let .folder(_, _, d)? = packages.first(where: { $0.name == name })?.origin else { return nil }
            return d
        }
        #expect(direct("lodash") == true && direct("@babel/core") == true && direct("debug") == false)
    }

    @Test func otherManifests() {
        func names(_ lockfile: String, _ files: [String: String]) -> Set<String>? {
            Manifests.directNames(forLockfile: project(files).appendingPathComponent(lockfile))
        }
        #expect(names("poetry.lock", ["pyproject.toml": """
            [project]
            name = "app"
            dependencies = [
              "Requests>=2.31",
              "urllib3 (>=2)",
            ]
            [tool.poetry.dependencies]
            python = "^3.11"
            Jinja2 = "^3.1"
            [tool.poetry.group.dev.dependencies]
            pytest = "*"
            """]) == ["requests", "urllib3", "jinja2", "pytest"])
        #expect(names("Cargo.lock", ["Cargo.toml": """
            [package]
            name = "demo"
            [dependencies]
            openssl = "0.10"
            serde_json = { version = "1" }
            [dependencies.tokio]
            version = "1"
            [target.'cfg(unix)'.dev-dependencies]
            nix = "0.29"
            """]) == ["openssl", "serde-json", "tokio", "nix"])
        #expect(names("go.sum", ["go.mod": Fixture.text("lockfiles/go-mod/go.mod")]) == ["github.com/gin-gonic/gin"])   // x/net is // indirect
        #expect(names("Gemfile.lock", ["Gemfile.lock": Fixture.text("lockfiles/bundler/Gemfile.lock")]) == ["actionpack", "nokogiri"])
        #expect(names("composer.lock", ["composer.json": #"{"require": {"php": ">=8.1", "ext-json": "*", "Guzzlehttp/Guzzle": "^7"}}"#]) == ["guzzlehttp/guzzle"])
        #expect(names("Pipfile.lock", ["Pipfile": "[packages]\nrequests = \"*\"\n[dev-packages]\npytest = \"*\"\n"]) == ["requests", "pytest"])
        #expect(names("yarn.lock", [:]) == nil)                      // no manifest: unknown, not "indirect"
        #expect(Manifests.isDirect("serde_json", .crates, in: ["serde-json"]))
        #expect(Manifests.isDirect("Requests", .pypi, in: ["requests"]))
    }
}

import Foundation
import Testing
@testable import OSVAKit

/// The chains "Needed by body-parser → express" are read from each lockfile's own structure.
@Suite struct LockfileGraphTests {
    static let npmLock = #"""
    {"name": "shop", "lockfileVersion": 3, "packages": {
      "": {"name": "shop", "dependencies": {"express": "^4.18.2"}, "devDependencies": {"jest": "^29"}},
      "node_modules/express": {"version": "4.18.2", "dependencies": {"body-parser": "1.20.1", "qs": "6.13.0"}},
      "node_modules/body-parser": {"version": "1.20.1", "dependencies": {"qs": "6.11.0"}},
      "node_modules/body-parser/node_modules/qs": {"version": "6.11.0"},
      "node_modules/qs": {"version": "6.13.0"},
      "node_modules/jest": {"version": "29.0.0", "dev": true, "dependencies": {"minimist": "^1"}},
      "node_modules/minimist": {"version": "1.2.8", "dev": true},
      "packages/ui": {"name": "ui", "version": "1.0.0", "dependencies": {"left-pad": "^1"}},
      "node_modules/ui": {"resolved": "packages/ui", "link": true},
      "node_modules/left-pad": {"version": "1.3.0"},
      "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "1"}},
      "node_modules/b": {"version": "1.0.0", "dependencies": {"a": "1"}}
    }}
    """#

    func graph(_ text: String, _ file: String, direct: Set<String>? = nil) throws -> LockfileGraph {
        try #require(LockfileGraph.read(text, filename: file, direct: direct))
    }

    @Test func npm() throws {
        let g = try graph(Self.npmLock, "package-lock.json")
        #expect(g.chain(to: "qs", version: "6.11.0") == ["express", "body-parser"])     // the nested copy, by node's own lookup
        #expect(g.chain(to: "qs", version: "6.13.0") == ["express"])
        #expect(g.chain(to: "minimist", version: "1.2.8") == ["jest"])
        #expect(g.chain(to: "express", version: "4.18.2") == [])
        #expect(g.chain(to: "left-pad", version: "1.3.0") == [])                         // a workspace's own
        #expect(g.chain(to: "a", version: "1.0.0") == nil)                               // a cycle nothing reaches
        #expect(g.installPath(of: "qs", version: "6.11.0") == "node_modules/body-parser/node_modules/qs")
    }

    @Test func yarnV1() throws {
        let text = """
        # yarn lockfile v1


        express@^4.18.2:
          version "4.18.2"
          resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"
          dependencies:
            body-parser "1.20.1"
            "@types/node" "^20"

        body-parser@1.20.1:
          version "1.20.1"
          dependencies:
            qs "6.11.0"

        qs@6.11.0, qs@^6.0.0:
          version "6.11.0"

        "@types/node@^20":
          version "20.1.0"
        """
        let g = try graph(text, "yarn.lock", direct: ["express"])
        #expect(g.chain(to: "qs", version: "6.11.0") == ["express", "body-parser"])
        #expect(g.chain(to: "@types/node", version: "20.1.0") == ["express"])
    }

    @Test func yarnBerry() throws {
        let text = """
        __metadata:
          version: 6
          cacheKey: 8

        "body-parser@npm:1.20.1":
          version: 1.20.1
          resolution: "body-parser@npm:1.20.1"
          dependencies:
            qs: 6.11.0
          languageName: node
          linkType: hard

        "express@npm:^4.18.2":
          version: 4.18.2
          resolution: "express@npm:4.18.2"
          dependencies:
            body-parser: 1.20.1
          languageName: node
          linkType: hard

        "qs@npm:6.11.0":
          version: 6.11.0
          resolution: "qs@npm:6.11.0"
          languageName: node
          linkType: hard

        "shop@workspace:.":
          version: 0.0.0-use.local
          resolution: "shop@workspace:."
          dependencies:
            express: ^4.18.2
          languageName: unknown
          linkType: soft
        """
        let g = try graph(text, "yarn.lock")
        #expect(g.chain(to: "qs", version: "6.11.0") == ["express", "body-parser"])
        #expect(g.chain(to: "express", version: "4.18.2") == [])
    }

    @Test func pnpmV9() throws {
        let text = """
        lockfileVersion: '9.0'

        importers:

          .:
            dependencies:
              express:
                specifier: ^4.18.2
                version: 4.18.2
            devDependencies:
              '@babel/core':
                specifier: ^7
                version: 7.24.0(supports-color@5.5.0)

        packages:

          express@4.18.2:
            resolution: {integrity: sha512-x}

        snapshots:

          '@babel/core@7.24.0(supports-color@5.5.0)':
            dependencies:
              debug: 4.3.4(supports-color@5.5.0)

          debug@4.3.4(supports-color@5.5.0):
            dependencies:
              ms: 2.1.2

          express@4.18.2:
            dependencies:
              body-parser: 1.20.1

          body-parser@1.20.1:
            dependencies:
              qs: 6.11.0

          qs@6.11.0: {}

          ms@2.1.2: {}
        """
        let g = try graph(text, "pnpm-lock.yaml")
        #expect(g.chain(to: "qs", version: "6.11.0") == ["express", "body-parser"])
        #expect(g.chain(to: "ms", version: "2.1.2") == ["@babel/core", "debug"])
    }

    @Test func pnpmV6AndV5() throws {
        let v6 = """
        lockfileVersion: '6.0'

        dependencies:
          express:
            specifier: ^4.18.2
            version: 4.18.2

        packages:

          /express@4.18.2:
            resolution: {integrity: sha512-x}
            dependencies:
              body-parser: 1.20.1
            dev: false

          /body-parser@1.20.1:
            dependencies:
              qs: 6.11.0
            dev: false

          /qs@6.11.0:
            dev: false
        """
        #expect(try graph(v6, "pnpm-lock.yaml").chain(to: "qs", version: "6.11.0") == ["express", "body-parser"])
        let v5 = """
        lockfileVersion: 5.4

        specifiers:
          express: ^4.18.2

        dependencies:
          express: 4.18.2

        packages:

          /express/4.18.2:
            dependencies:
              body-parser: 1.20.1_debug@4.0.0
            dev: false

          /body-parser/1.20.1_debug@4.0.0:
            dependencies:
              qs: 6.11.0

          /qs/6.11.0:
            dev: false
        """
        #expect(try graph(v5, "pnpm-lock.yaml").chain(to: "qs", version: "6.11.0") == ["express", "body-parser"])
    }

    @Test("pnpm keys, every format", arguments: [
        ("/lodash/4.17.21", "lodash", "4.17.21"), ("/@babel/core/7.0.0", "@babel/core", "7.0.0"),
        ("/foo/1.0.0_bar@2.0.0", "foo", "1.0.0"), ("/lodash@4.17.21", "lodash", "4.17.21"),
        ("'@babel/core@7.24.0(supports-color@5.5.0)'", "@babel/core", "7.24.0"), ("qs@6.11.0", "qs", "6.11.0"),
    ])
    func pnpmKeys(_ key: String, _ name: String, _ version: String) {
        let k = LockfileGraph.pnpmKey(key)
        #expect(k?.name == name && k?.version == version, "\(key)")
    }

    @Test func pnpmValues() {
        func t(_ name: String, _ value: String) -> String? { LockfileGraph.pnpmTarget(name, value).map { "\($0.name)@\($0.version)" } }
        #expect(t("body-parser", "1.20.1_debug@4.0.0") == "body-parser@1.20.1")
        #expect(t("debug", "4.3.4(supports-color@5.5.0)") == "debug@4.3.4")
        #expect(t("string-width-cjs", "string-width@4.2.3") == "string-width@4.2.3")
        #expect(t("alias", "/real/1.0.0") == "real@1.0.0")
        #expect(t("ui", "link:../ui") == nil && t("x", "file:x.tgz") == nil)
    }

    @Test func poetry() throws {
        let text = #"""
        [[package]]
        name = "fastapi"
        version = "0.109.2"
        description = "x"
        optional = false
        python-versions = ">=3.8"
        files = [
            {file = "fastapi-0.109.2.tar.gz", hash = "sha256:x"},
        ]

        [package.dependencies]
        pydantic = ">=1.7.4"
        starlette = ">=0.36.3,<0.37.0"

        [package.extras]
        all = ["httpx (>=0.23.0)"]

        [[package]]
        name = "starlette"
        version = "0.36.3"

        [package.dependencies]
        anyio = ">=3.4.0,<5"

        [[package]]
        name = "anyio"
        version = "4.2.0"

        [package.dependencies]
        idna = ">=2.8"
        sniffio = {version = ">=1.1", markers = "python_version < \"3.8\""}

        [[package]]
        name = "idna"
        version = "3.6"

        [[package]]
        name = "Pydantic"
        version = "2.5.0"
        """#
        let g = try graph(text, "poetry.lock", direct: ["fastapi"])
        #expect(g.chain(to: "idna", version: "3.6") == ["fastapi", "starlette", "anyio"])
        #expect(g.chain(to: "pydantic", version: "2.5.0") == ["fastapi"])                 // names compared as PyPI does
        #expect(g.chain(to: "httpx", version: "0.23.0") == nil)                          // an extra is not a dependency
    }

    @Test func cargo() throws {
        let text = #"""
        version = 3

        [[package]]
        name = "cli"
        version = "0.1.0"
        dependencies = [
         "notify-rust",
         "serde 1.0.0",
        ]

        [[package]]
        name = "notify-rust"
        version = "4.0.0"
        source = "registry+https://github.com/rust-lang/crates.io-index"
        dependencies = [
         "chrono",
        ]

        [[package]]
        name = "chrono"
        version = "0.4.0"
        source = "registry+https://github.com/rust-lang/crates.io-index"
        dependencies = ["time 0.1.43 (registry+https://github.com/rust-lang/crates.io-index)"]

        [[package]]
        name = "time"
        version = "0.1.43"
        source = "registry+https://github.com/rust-lang/crates.io-index"

        [[package]]
        name = "time"
        version = "0.3.0"
        source = "registry+https://github.com/rust-lang/crates.io-index"

        [[package]]
        name = "serde"
        version = "1.0.0"
        source = "registry+https://github.com/rust-lang/crates.io-index"
        dependencies = [
         "time 0.3.0",
        ]
        """#
        let g = try graph(text, "Cargo.lock")
        #expect(g.chain(to: "time", version: "0.1.43") == ["notify-rust", "chrono"])     // the workspace's crates are the top
        #expect(g.chain(to: "time", version: "0.3.0") == ["serde"])
        #expect(g.chain(to: "notify-rust", version: "4.0.0") == [])
    }

    @Test func gemfileComposerAndPipCompile() throws {
        let gemfile = """
        GEM
          remote: https://rubygems.org/
          specs:
            actionpack (7.0.0)
              rack (~> 2.0, >= 2.2.0)
              rack-test (>= 0.6.3)
            rack (2.2.3)
            rack-test (2.0.0)
              rack (>= 1.3)
            nokogiri (1.13.8-arm64-darwin)
              racc (~> 1.4)
            racc (1.6.0)
            rails (7.0.0)
              actionpack (= 7.0.0)

        PLATFORMS
          arm64-darwin

        DEPENDENCIES
          nokogiri
          rails (~> 7.0)

        BUNDLED WITH
           2.3.0
        """
        let gems = try graph(gemfile, "Gemfile.lock")
        #expect(gems.chain(to: "rack", version: "2.2.3") == ["rails", "actionpack"])
        #expect(gems.chain(to: "racc", version: "1.6.0") == ["nokogiri"])

        let composer = #"{"content-hash":"x","packages":[{"name":"laravel/framework","version":"v10.0.0","require":{"php":"^8.1","symfony/console":"^6.2"}},{"name":"symfony/console","version":"v6.2.0","require":{"symfony/string":"^6"}},{"name":"symfony/string","version":"v6.2.0"}],"packages-dev":[]}"#
        #expect(try graph(composer, "composer.lock", direct: ["laravel/framework"]).chain(to: "symfony/string", version: "6.2.0")
            == ["laravel/framework", "symfony/console"])

        let compiled = """
        #
        # This file is autogenerated by pip-compile
        #
        anyio==4.2.0
            # via starlette
        fastapi==0.109.2
            # via -r requirements.in
        idna==3.6
            # via anyio
        starlette==0.36.3
            # via
            #   fastapi
            #   sse-starlette
        sse-starlette==1.0
            # via -r requirements.in
        """
        #expect(try graph(compiled, "requirements.txt").chain(to: "idna", version: "3.6") == ["fastapi", "starlette", "anyio"])
        #expect(LockfileGraph.read("django==5.0\n", filename: "requirements.txt", direct: nil) == nil)    // no "via": no graph
    }

    @Test func garbageGivesNoGraph() {
        for (text, file) in [("{\"packages\": [1, 2", "package-lock.json"), ("\u{0}\u{1}binary", "yarn.lock"), ("", "pnpm-lock.yaml"),
                             ("[[package]]\nname = \n", "Cargo.lock"), ("not toml at all", "poetry.lock"), ("x", "go.sum"), ("[]", "composer.lock")] {
            let g = LockfileGraph.read(text, filename: file, direct: ["x"])
            #expect(g == nil || g!.chain(to: "x", version: "1") == nil || g!.chain(to: "x", version: "1") == [], "\(file)")
        }
    }

    /// Every lockfile fixture: a graph where the format has one, and every chain made of its own packages.
    @Test func theRecordedLockfiles() throws {
        var withGraph: [String] = []
        for dir in try FileManager.default.contentsOfDirectory(atPath: Fixture.url("lockfiles").path).sorted() {
            for file in try FileManager.default.contentsOfDirectory(atPath: Fixture.url("lockfiles/\(dir)").path) {
                let url = Fixture.url("lockfiles/\(dir)/\(file)")
                let text = String(decoding: try Data(contentsOf: url), as: UTF8.self)
                guard let g = LockfileGraph.read(text, filename: file, direct: Manifests.directNames(forLockfile: url)) else { continue }
                withGraph.append(dir)
                let names = Set(g.nodes.map(\.name))
                for d in LockfileParser.parse(text, filename: file).dependencies {
                    for n in g.chain(to: d.name, version: d.version) ?? [] { #expect(names.contains(n), "\(dir): \(n)") }
                }
            }
        }
        #expect(Set(withGraph).isSuperset(of: ["npm-v3", "yarn-v1", "yarn-berry", "pnpm-v6", "pnpm-v9", "poetry", "cargo", "bundler", "composer"]),
                "\(withGraph)")
    }

    /// Bounded: a 20,000-package chain is read and searched quickly.
    @Test func aLargeLockfile() throws {
        var packages = [#""": {"dependencies": {"p0": "1"}}"#]
        for i in 0..<20_000 { packages.append(#""node_modules/p\#(i)": {"version": "1.0.0", "dependencies": {"p\#(i + 1)": "1"}}"#) }
        let text = #"{"lockfileVersion": 3, "packages": {"# + packages.joined(separator: ",") + "}}"
        let started = Date()
        let g = try graph(text, "package-lock.json")
        #expect(g.chain(to: "p19999", version: "1.0.0")?.count == 19_999)
        #expect(Date().timeIntervalSince(started) < 10)
    }
}

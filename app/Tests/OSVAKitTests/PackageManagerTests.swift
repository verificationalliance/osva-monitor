import Foundation
import SQLite3
import Testing
@testable import OSVAKit

/// Builders for the package managers' files, in a temporary home.
enum ManagerFiles {
    static func metadata(_ name: String, _ version: String) -> String {
        "Metadata-Version: 2.1\nName: \(name)\nVersion: \(version)\nSummary: x\n\nName: not-the-header\nVersion: 0\n"
    }

    /// A pipx or uv tool's environment with these distributions (nil METADATA: only the dist-info folder).
    static func venv(_ dir: URL, cfg: String, python: String, dists: [(String, String, Bool)], extra: [String: String] = [:]) {
        write(cfg, to: dir.appendingPathComponent("pyvenv.cfg"))
        write("", to: dir.appendingPathComponent("bin/python"))
        for (name, version, hasMetadata) in dists {
            let info = dir.appendingPathComponent("lib/python\(python)/site-packages/\(name.replacingOccurrences(of: "-", with: "_"))-\(version).dist-info")
            if hasMetadata { write(metadata(name, version), to: info.appendingPathComponent("METADATA")) }
            else { try! FileManager.default.createDirectory(at: info, withIntermediateDirectories: true) }
        }
        for (file, text) in extra { write(text, to: dir.appendingPathComponent(file)) }
    }

    /// A conda-meta record.
    static func record(_ name: String, _ version: String, noarch: String? = nil, files: [String] = []) -> String {
        var obj: [String: Any] = ["name": name, "version": version, "build": "0", "files": files]
        if let noarch { obj["noarch"] = noarch }
        return String(decoding: try! JSONSerialization.data(withJSONObject: obj), as: UTF8.self)
    }

    static func condaEnv(_ prefix: URL, _ records: [(String, String)]) {
        try! FileManager.default.createDirectory(at: prefix.appendingPathComponent("conda-meta"), withIntermediateDirectories: true)
        write("==> 2026-11-01 <==\n", to: prefix.appendingPathComponent("conda-meta/history"))
        for (file, json) in records { write(json, to: prefix.appendingPathComponent("conda-meta/\(file).json")) }
    }
}

@Suite struct PythonToolTests {
    @Test func pipxAndUvTools() throws {
        let home = temporaryDirectory()
        let black = home.appendingPathComponent(".local/pipx/venvs/black")
        ManagerFiles.venv(black, cfg: "home = /opt/homebrew/opt/python@3.12/bin\ninclude-system-site-packages = false\nversion = 3.12.4\n", python: "3.12",
                          dists: [("black", "24.1.0", true), ("click", "8.1.3", true), ("requests", "2.25.0", false)],
                          extra: ["pipx_metadata.json": #"{"main_package": {"package": "black", "package_version": "24.1.0"}, "python_version": "Python 3.12.4"}"#])
        let ruff = home.appendingPathComponent(".local/share/uv/tools/ruff")
        ManagerFiles.venv(ruff, cfg: "home = /x/bin\nimplementation = CPython\nuv = 0.9.0\nversion_info = 3.13.1\n", python: "3.13",
                          dists: [("ruff", "0.4.0", true)], extra: ["uv-receipt.toml": "[tool]\nrequirements = [{ name = \"ruff\" }]\n"])
        // a folder that is not a tool's environment, and one whose Python is gone
        write("x", to: home.appendingPathComponent(".local/pipx/venvs/notes.txt"))
        ManagerFiles.venv(home.appendingPathComponent(".local/pipx/venvs/broken"), cfg: "version = 3.11.0\n", python: "3.11", dists: [("x", "1", true)])

        let tools = ToolEnvironment(home: home, base: [:], runner: RecordedRunner(outputs: [:]),
                                    isExecutable: { $0.hasSuffix("/bin/python") && !$0.contains("/broken/") })
        let (packages, reports) = PythonToolSource(environment: tools).collect()
        #expect(packages.map { "\($0.name) \($0.version)" } == ["black 24.1.0", "click 8.1.3", "requests 2.25.0", "ruff 0.4.0"])
        guard case let .pythonTool(t) = packages[1].origin else { Issue.record("not a tool"); return }
        #expect(t.manager == .pipx && t.name == "black" && t.mainPackage == "black" && t.version == "24.1.0" && t.python == "3.12.4")
        #expect(packages[3].origin.pythonVersion == "3.13.1" && packages[3].origin.kind == .uv)
        #expect(reports.map(\.detail) == ["1 tool, 3 packages", "1 tool, 1 package"])
        #expect(packages[0].origin.label == "pipx · Python 3.12.4")
    }

    @Test func metadataHeaderOnly() {
        let crlf = PythonToolSource.metadataNameAndVersion(Array("Name: a\r\nVersion: 1.0\r\n\r\nVersion: 9\n".utf8))
        #expect(crlf?.name == "a" && crlf?.version == "1.0")
        #expect(PythonToolSource.metadataNameAndVersion(Array("Summary: x\n\nName: a\nVersion: 1\n".utf8)) == nil)   // the body is not the header
        #expect(PythonToolSource.metadataNameAndVersion(Array([0xFF, 0xFE, 0x00])) == nil)
        #expect(PythonToolSource.pythonVersion(fromPyvenvCfg: "version_info = 3.12.4.final.0") == "3.12.4")
        #expect(PythonToolSource.pythonVersion(fromPyvenvCfg: "home = /x\n") == nil)
    }

    @Test func noToolsIsNotAnError() {
        let tools = ToolEnvironment(home: temporaryDirectory(), base: [:], runner: RecordedRunner(outputs: [:]), isExecutable: { _ in false })
        let (packages, reports) = PythonToolSource(environment: tools).collect()
        #expect(packages.isEmpty && reports.allSatisfy { !$0.available && $0.error == nil })
    }
}

@Suite struct CondaTests {
    @Test func pythonPackagesWithTheSameNameAreCheckedAsPyPI() throws {
        let home = temporaryDirectory()
        let root = home.appendingPathComponent("miniforge3")
        ManagerFiles.condaEnv(root, [
            ("python-3.11.5-h0", ManagerFiles.record("python", "3.11.5", files: ["bin/python3.11", "lib/python3.11/site-packages/README.txt"])),
            ("pyyaml-6.0.1-py311", ManagerFiles.record("pyyaml", "6.0.1", files: ["lib/python3.11/site-packages/PyYAML-6.0.1.dist-info/METADATA",
                                                                               "lib/python3.11/site-packages/yaml/__init__.py"])),
            ("requests-2.31.0-pyhd8ed1ab_0", ManagerFiles.record("requests", "2.31.0", noarch: "python",
                                                                 files: ["site-packages/requests-2.31.0.dist-info/METADATA"])),
            ("pytorch-2.1.0-py311", ManagerFiles.record("pytorch", "2.1.0", files: ["lib/python3.11/site-packages/torch-2.1.0.dist-info/METADATA"])),
            ("tzdata-2024a-pyh", ManagerFiles.record("old-noarch", "1.0", noarch: "python", files: ["site-packages/old/__init__.py"])),
            ("openssl-3.0.12-h0", ManagerFiles.record("openssl", "3.0.12", files: ["lib/libssl.3.dylib"])),
            ("broken", "{not json"),
        ])
        ManagerFiles.condaEnv(root.appendingPathComponent("envs/ml"), [("python-3.12.1-h0", ManagerFiles.record("python", "3.12.1")),
                                                                       ("numpy-1.26.0-py312", ManagerFiles.record("numpy", "1.26.0", files: ["lib/python3.12/site-packages/numpy-1.26.0.dist-info/RECORD"]))])
        let elsewhere = home.appendingPathComponent("projects/x/.env")
        ManagerFiles.condaEnv(elsewhere, [("six-1.16.0-pyh", ManagerFiles.record("six", "1.16.0", noarch: "python", files: ["site-packages/six-1.16.0.dist-info/METADATA"]))])
        write(elsewhere.path + "\n/nonexistent/env\n", to: home.appendingPathComponent(".conda/environments.txt"))

        let tools = ToolEnvironment(home: home, base: [:], runner: RecordedRunner(outputs: [:]), isExecutable: { $0 == root.path + "/bin/conda" })
        let r = CondaSource(environment: tools, roots: [root.path]).collect()
        #expect(r.packages.map { "\($0.name) \($0.version)" } == ["pyyaml 6.0.1", "requests 2.31.0", "numpy 1.26.0", "six 1.16.0"])
        #expect(r.managed.map { "\($0.name) \($0.version)" } == ["openssl 3.0.12", "python 3.11.5", "python 3.12.1"])
        #expect(r.unchecked.map(\.item) == ["pytorch 2.1.0 (PyPI: torch)", "old-noarch 1.0"])
        let envs = r.packages.compactMap { p -> CondaEnvironment? in if case let .conda(e) = p.origin { return e }; return nil }
        #expect(envs.map(\.name) == ["base", "base", "ml", ".env"] && envs.map(\.named) == [true, true, true, false])
        #expect(envs.map(\.python) == ["3.11.5", "3.11.5", "3.12.1", nil])
        #expect(envs.allSatisfy { $0.tool == .conda })
        #expect(r.report.detail == "3 environments, 9 packages (4 on PyPI)")
    }

    @Test func notFound() {
        let tools = ToolEnvironment(home: temporaryDirectory(), base: [:], runner: RecordedRunner(outputs: [:]), isExecutable: { _ in false })
        let r = CondaSource(environment: tools).collect()
        #expect(r.report.available == false && r.report.detail == "conda not found")
    }

    @Test func records() {
        #expect(CondaSource.record(from: Array(#"{"name": "x"}"#.utf8)) == nil)
        #expect(CondaSource.record(from: Array(#"{"name": "attrs", "version": "23.1.0", "noarch": {"type": "python"}, "files": ["site-packages/attrs-23.1.0.dist-info/METADATA"]}"#.utf8))?
            .classification == .pypi(name: "attrs", version: "23.1.0"))
        #expect(CondaSource.record(from: Array(#"{"name": "msgpack-python", "version": "1.0.5", "files": ["lib/python3.11/site-packages/msgpack-1.0.5.dist-info/RECORD"]}"#.utf8))?
            .classification == .differentPyPIName("msgpack"))
        #expect(CondaSource.record(from: Array(#"{"name": "typing_extensions", "version": "4.8.0", "files": ["lib/python3.11/site-packages/typing_extensions-4.8.0.dist-info/RECORD"]}"#.utf8))?
            .classification == .pypi(name: "typing_extensions", version: "4.8.0"))
    }
}

@Suite struct MacPortsTests {
    /// A registry like MacPorts' own: its version column uses MacPorts' collation.
    func registry(at path: String, rows: [(String, String, Int, String)]) {
        var db: OpaquePointer?
        try! FileManager.default.createDirectory(atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        #expect(sqlite3_open(path, &db) == SQLITE_OK)
        sqlite3_create_collation_v2(db, "VERSION", SQLITE_UTF8, nil, { _, n1, p1, n2, p2 in
            let c = memcmp(p1, p2, Int(min(n1, n2))); return c != 0 ? c : n1 - n2
        }, nil)
        let schema = "CREATE TABLE ports (id INTEGER PRIMARY KEY, name TEXT COLLATE NOCASE, portfile TEXT, location TEXT, epoch INTEGER, "
            + "version TEXT COLLATE VERSION, revision INTEGER, variants TEXT, negated_variants TEXT, state TEXT, date DATETIME, "
            + "installtype TEXT, archs TEXT, requested INTEGER, os_platform TEXT, os_major INTEGER, UNIQUE (name, epoch, version, revision, variants))"
        #expect(sqlite3_exec(db, schema, nil, nil, nil) == SQLITE_OK)
        for (name, version, revision, state) in rows {
            #expect(sqlite3_exec(db, "INSERT INTO ports (name, epoch, version, revision, variants, state) VALUES ('\(name)', 0, '\(version)', \(revision), '', '\(state)')", nil, nil, nil) == SQLITE_OK)
        }
        sqlite3_close(db)
    }

    @Test func activePortsFromTheRegistry() async {
        let prefix = temporaryDirectory()
        registry(at: prefix.path + "/var/macports/registry/registry.db",
                 rows: [("curl", "8.11.0", 0, "installed"), ("curl", "8.10.0", 1, "imaged"), ("openssl3", "3.4.0", 2, "installed")])
        let tools = ToolEnvironment(home: prefix, base: [:], runner: RecordedRunner(outputs: [:]), isExecutable: { $0 == prefix.path + "/bin/port" })
        let (managed, report) = await MacPortsSource(environment: tools, prefix: prefix.path).collect()
        #expect(managed.map { "\($0.name) \($0.version)" } == ["curl 8.11.0", "openssl3 3.4.0"])
        #expect(managed.allSatisfy { $0.manager == .macports } && report.detail == "2 ports" && report.error == nil)
    }

    @Test func withoutTheRegistryPortIsAsked() async {
        let prefix = temporaryDirectory()
        let port = prefix.path + "/bin/port"
        let runner = RecordedRunner(outputs: ["\(port) -q installed": CommandResult(status: 0, stdout: Data("""
              curl @8.11.0_0+ssl (active)
              curl @8.10.0_1+ssl
              openssl3 @3.4.0_2 (active)
              py312-requests @2.32.3_0 (active)
            """.utf8), stderr: Data())])
        let tools = ToolEnvironment(home: prefix, base: [:], runner: runner, isExecutable: { $0 == port })
        let (managed, _) = await MacPortsSource(environment: tools, prefix: prefix.path).collect()
        #expect(managed.map { "\($0.name) \($0.version)" } == ["curl 8.11.0", "openssl3 3.4.0", "py312-requests 2.32.3"])
    }

    @Test func notInstalled() async {
        let tools = ToolEnvironment(home: temporaryDirectory(), base: [:], runner: RecordedRunner(outputs: [:]), isExecutable: { _ in false })
        #expect(await MacPortsSource(environment: tools).collect().report.detail == "MacPorts not found")
    }
}

@Suite struct NixTests {
    static let hash = String(repeating: "a", count: 32)

    @Test("store paths", arguments: [
        ("openssl-3.0.12-bin", "openssl", "3.0.12"), ("python3-3.11.6", "python3", "3.11.6"), ("ripgrep-14.1.0", "ripgrep", "14.1.0"),
        ("gnupg-2.4.5", "gnupg", "2.4.5"), ("nss-cacert-3.95", "nss-cacert", "3.95"),
    ])
    func storePaths(_ base: String, _ name: String, _ version: String) {
        let r = NixSource.nameAndVersion(storePath: "/nix/store/\(Self.hash)-\(base)")
        #expect(r?.name == name && r?.version == version)
    }

    @Test func notVersions() throws {
        let foo = try #require(NixSource.nameAndVersion(storePath: "/nix/store/\(Self.hash)-foo-unstable-2024-01-01"))
        let bar = try #require(NixSource.nameAndVersion(storePath: "/nix/store/\(Self.hash)-bar-0-unstable-2024-01-01"))
        #expect(NixSource.isSnapshot(name: foo.name, version: foo.version) && NixSource.isSnapshot(name: bar.name, version: bar.version))
        #expect(!NixSource.isSnapshot(name: "openssl", version: "3.0.12"))
        #expect(NixSource.nameAndVersion(storePath: "/nix/store/\(Self.hash)-user-environment") == nil)
        #expect(NixSource.nameAndVersion(storePath: "/nix/store/short-1.0") == nil)
    }

    @Test func profiles() {
        let home = temporaryDirectory()
        let p = home.appendingPathComponent("profile-new"), old = home.appendingPathComponent("profile-old")
        write(#"{"version": 3, "elements": {"ripgrep": {"active": true, "attrPath": "legacyPackages.aarch64-darwin.ripgrep", "storePaths": ["/nix/store/\#(Self.hash)-ripgrep-14.1.0"]}, "off": {"active": false, "storePaths": ["/nix/store/\#(Self.hash)-curl-8.0.0"]}}}"#,
              to: p.appendingPathComponent("manifest.json"))
        write(#"[ { meta = { maintainers = [ { name = "Jane"; } ]; name = "openssl-3.0.12"; }; name = "openssl-3.0.12"; out = { outPath = "/nix/store/\#(Self.hash)-openssl-3.0.12"; }; outPath = "/nix/store/\#(Self.hash)-openssl-3.0.12"; bin = { outPath = "/nix/store/\#(Self.hash)-openssl-3.0.12-bin"; }; } ]"#,
              to: old.appendingPathComponent("manifest.nix"))
        let tools = ToolEnvironment(home: home, base: [:], runner: RecordedRunner(outputs: [:]), isExecutable: { $0 == p.path + "/bin/nix-env" })
        let (managed, unchecked, report) = NixSource(environment: tools, profiles: [(p.path, false), (old.path, true)]).collect()
        #expect(unchecked.isEmpty)
        #expect(managed.map { "\($0.name) \($0.version)" } == ["ripgrep 14.1.0", "openssl 3.0.12"])
        #expect(report.detail == "2 packages in 2 profiles")
        guard case let .nix(profile, element) = managed[0].origin, case let .nix(shared, oldElement) = managed[1].origin else { Issue.record("not nix"); return }
        #expect(profile.style == .profile && element == "ripgrep" && !profile.shared)
        #expect(shared.style == .env && oldElement == "openssl" && shared.shared)
        #expect(NixSource.parseManifestJSON(Array(#"{"version": 2, "elements": [{"storePaths": ["/nix/store/x-a-1"]}]}"#.utf8)).map(\.element) == ["0"])
        #expect(NixSource.parseManifestJSON(Array("not json".utf8)).isEmpty)
    }
}

@Suite struct ManagedIndexTests {
    @Test func rLinesNameGradedProjects() throws {
        let tsv = "#osva-app-index\t1\tT\t1\t2\nP\topenssl\tOpenSSL\tgithub.com/openssl/openssl\nP\tcpython\tCPython\tgithub.com/python/cpython\n"
            + "K\tPyPI\trequests\nR\tmacports\topenssl3\topenssl\nR\tnix\topenssl\topenssl\nR\tconda\tpython\tcpython\nR\tnix\tghost\tno-such-project\n"
            + "R\tmacports\tshort\nR\t\t\t\nR\tmacports\tcurl\tcurl\textra\tcolumns\n"
        let index = try PublicIndex.decode(Data(tsv.utf8))
        #expect(index.project(manager: "macports", package: "openssl3")?.slug == "openssl")
        #expect(index.project(manager: "nix", package: "openssl")?.name == "OpenSSL")
        #expect(index.project(manager: "conda", package: "python")?.slug == "cpython")
        #expect(index.project(manager: "nix", package: "ghost") == nil)                  // no P line for its slug
        #expect(index.project(manager: "macports", package: "openssl") == nil)            // names are per manager, exact
        #expect(index.project(manager: "macports", package: "curl") == nil)               // curl is not a project here
        #expect(index.packageCount == 1 && index.projects.count == 2 && index.managedCount == 5)
        // R lines add no keys: nothing about them can be sent
        #expect(index.keys.count == index.packageCount + index.projects.count)
    }

    @Test func theRecordedIndexHasNoneYet() {
        #expect(Fixture.index.managedCount == 0)
    }
}

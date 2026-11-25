import Foundation
import Testing
@testable import OSVAKit

/// Java runtimes as Java's installers and version managers lay them out, from the recorded `release` files and
/// Info.plists in Fixtures/java (Temurin's and GraalVM's are the vendors' own, Temurin's at 17.0.20; Corretto 8's
/// Info.plist is Amazon's, beside which it has no release file at all).
enum JDK {
    static func fixture(_ name: String) -> String { Fixture.text("java/\(name)") }

    /// A bundle (Contents/Home/release, Contents/Info.plist, Contents/Home/bin/java) in `folder`.
    @discardableResult
    static func bundle(_ folder: URL, _ name: String, release: String?, plist: String? = nil) -> URL {
        let b = folder.appendingPathComponent(name, isDirectory: true)
        let home = b.appendingPathComponent("Contents/Home")
        try! FileManager.default.createDirectory(at: home.appendingPathComponent("bin"), withIntermediateDirectories: true)
        write("#!/bin/sh\n", to: home.appendingPathComponent("bin/java"))
        if let release { write(release, to: home.appendingPathComponent("release")) }
        if let plist { write(fixture(plist), to: b.appendingPathComponent("Contents/Info.plist")) }
        return b
    }

    /// A plain folder (SDKMAN's, asdf's, mise's): release and bin/java at its top.
    @discardableResult
    static func folder(_ parent: URL, _ name: String, release: String) -> URL {
        let f = parent.appendingPathComponent(name, isDirectory: true)
        write(release, to: f.appendingPathComponent("release"))
        write("#!/bin/sh\n", to: f.appendingPathComponent("bin/java"))
        return f
    }

    static func link(_ at: URL, to destination: URL) {
        try! FileManager.default.createDirectory(at: at.deletingLastPathComponent(), withIntermediateDirectories: true)
        try! FileManager.default.createSymbolicLink(at: at, withDestinationURL: destination)
    }

    static func release(_ version: String, implementor: String? = "Eclipse Adoptium") -> String {
        (implementor.map { "IMPLEMENTOR=\"\($0)\"\n" } ?? "") + "JAVA_VERSION=\"\(version)\"\n"
    }

    /// A Mac in temporary folders: `system` stands for "/", `home` for the home folder.
    static func mac(runner: CommandRunner = RecordedRunner(outputs: [:]), executable: @escaping @Sendable (String) -> Bool = { _ in false })
        -> (system: URL, home: URL, tools: ToolEnvironment) {
        let root = temporaryDirectory()
        let system = root.appendingPathComponent("system", isDirectory: true), home = root.appendingPathComponent("home", isDirectory: true)
        try! FileManager.default.createDirectory(at: system, withIntermediateDirectories: true)
        try! FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        var tools = ToolEnvironment(home: home, base: [:], runner: runner, isExecutable: executable)
        tools.systemRoot = system.path
        return (system, home, tools)
    }

    static func machineFolder(_ system: URL) -> URL { system.appendingPathComponent("Library/Java/JavaVirtualMachines", isDirectory: true) }

    static var postFix: ProjectResponse {
        try! JSONDecoder().decode(ProjectResponse.self, from: Fixture.data("api/project-openjdk-post-fix-2026-11-19.json"))
    }
    static var live: ProjectResponse {
        try! JSONDecoder().decode(ProjectResponse.self, from: Fixture.data("api/project-openjdk-live-2026-11-19.json"))
    }

    static func runtime(_ version: String, _ vendor: JavaVendor = .temurin, place: JavaRuntime.Place = .system, path: String? = nil,
                        cask: String? = nil, formula: String? = nil) -> JavaRuntime {
        let p = path ?? "/Library/Java/JavaVirtualMachines/\(vendor.rawValue)-\(version).jdk"
        return JavaRuntime(path: p, home: p + "/Contents/Home", realPath: p + "/Contents/Home", place: place, vendor: vendor, version: version,
                           canonical: JavaVersion.canonical(version)!, formula: formula, cask: cask)
    }
}

@Suite struct JavaVersionTests {
    /// The server's own table (fi/ranges.java_version): the app writes every version as the ranges do.
    @Test("as the server writes them", arguments: [
        ("1.8.0_511", "8.0.511"), ("1.8.0_511-b33", "8.0.511"), ("1.8.0", "8.0.0"), ("1.8", "8.0.0"), ("1.7.0_80", "7.0.80"),
        ("1.8.0-472", "8.0.472"), ("8u511", "8.0.511"), ("8u511b33-perf", "8.0.511"), ("8u511-b32", "8.0.511"), ("8u503-perf", "8.0.503"),
        ("7u511", "7.0.511"), ("17", "17"), ("17.0.20", "17.0.20"), ("17.0.20+8", "17.0.20"), ("21.0.5+11-LTS", "21.0.5"),
        ("17.0.21.0.3", "17.0.21.0.3"), ("8.0.511", "8.0.511"),
    ])
    func canonical(_ written: String, _ canonical: String) {
        #expect(JavaVersion.canonical(written) == canonical, "\(written)")
        #expect(JavaVersion.canonical(canonical) == canonical, "not idempotent: \(canonical)")
    }

    /// What the server reads as no version, and an early-access build, have no canonical form: never guessed.
    @Test("no version", arguments: ["17-ea", "27-ea", "see notes", "2026.2.0+9.6.1", "", "1.8.0_511-ea", "1", "v17", "17.0.20 ", "1.9.0"])
    func notAVersion(_ written: String) {
        #expect(JavaVersion.canonical(written) == (written == "17.0.20 " ? "17.0.20" : nil), "\(written)")
    }

    @Test func shownAsJavaNamesThem() {
        #expect(JavaVersion.shown("1.8.0_511") == "8u511" && JavaVersion.shown("8.0.511") == "8u511" && JavaVersion.shown("1.8.0-472") == "8u472")
        #expect(JavaVersion.shown("1.8.0") == "8" && JavaVersion.shown("17.0.20+8") == "17.0.20" && JavaVersion.shown("17.0.21.0.3") == "17.0.21.0.3")
        #expect(JavaVersion.shown("27-ea") == "27-ea")                                       // as written when it is none
    }

    /// The order the ranges rely on, in the verified core: unchanged, the data is what is normalised.
    @Test func theOrderTheRangesRelyOn() {
        let core = Core.shared
        #expect(core.sortedVersions(["8.0.511", "8", "8.0.0"]) == ["8", "8.0.0", "8.0.511"])
        #expect(core.sortedVersions(["17.0.22", "17.0.21.0.3", "17.0.21"]) == ["17.0.21", "17.0.21.0.3", "17.0.22"])
        // and why it has to be: Java 8 as written sorts below every bound of its own line
        #expect(core.compareVersions("1.8.0_511", "8") < 0)
    }
}

@Suite struct JavaSourceTests {
    /// /Library/Java/JavaVirtualMachines with Temurin 17.0.20, Oracle's JDK 8u511 (a release file with no IMPLEMENTOR),
    /// Zulu 21, GraalVM 21, Corretto 8 (no release file), and three that are not readable runtimes.
    static func machine() -> (system: URL, home: URL, tools: ToolEnvironment) {
        let mac = JDK.mac()
        let jvms = JDK.machineFolder(mac.system)
        JDK.bundle(jvms, "temurin-17.jdk", release: JDK.fixture("temurin-17.0.20.release"), plist: "temurin-17.Info.plist")
        JDK.bundle(jvms, "jdk1.8.0_511.jdk", release: JDK.fixture("oracle-8u511.release"), plist: "oracle-8u511.Info.plist")
        JDK.bundle(jvms, "zulu-21.jdk", release: JDK.fixture("zulu-21.0.5.release"), plist: "zulu-21.Info.plist")
        JDK.bundle(jvms, "graalvm-21.jdk", release: JDK.fixture("graalvm-21.0.12.release"), plist: "graalvm-21.Info.plist")
        JDK.bundle(jvms, "amazon-corretto-8.jdk", release: nil, plist: "corretto-8.Info.plist")
        JDK.bundle(jvms, "broken.jdk", release: "\u{0}\u{1}garbage\nJAVA_VERSION\n=\"\"\n")
        JDK.bundle(jvms, "early.jdk", release: "JAVA_VERSION=\"27-ea\"\n")
        try! FileManager.default.createDirectory(at: jvms.appendingPathComponent("empty.jdk"), withIntermediateDirectories: true)   // not a runtime
        return mac
    }

    @Test func readsEachVendorsRuntime() async throws {
        let mac = Self.machine()
        let r = await JavaSource(environment: mac.tools, homebrewPrefixes: []).collect()
        let byName = Dictionary(uniqueKeysWithValues: r.runtimes.map { (($0.path as NSString).lastPathComponent, $0) })
        #expect(byName.keys.sorted() == ["amazon-corretto-8.jdk", "graalvm-21.jdk", "jdk1.8.0_511.jdk", "temurin-17.jdk", "zulu-21.jdk"])

        let temurin = try #require(byName["temurin-17.jdk"])
        #expect(temurin.vendor == .temurin && temurin.version == "17.0.20" && temurin.canonical == "17.0.20" && temurin.build == "17.0.20+8")
        #expect(temurin.implementor == "Eclipse Adoptium" && temurin.place == .system && temurin.image == "JDK")
        #expect(temurin.title == "Java (Temurin)" && temurin.listItem == "Temurin 17.0.20 (temurin-17.jdk)")
        #expect(Origin.javaRuntime(temurin).location == "JDK in \(JDK.machineFolder(mac.system).path)")
        // Oracle's JDK 8: no IMPLEMENTOR in its release file; its Info.plist names it
        let oracle = try #require(byName["jdk1.8.0_511.jdk"])
        #expect(oracle.vendor == .oracle && oracle.version == "1.8.0_511" && oracle.canonical == "8.0.511" && oracle.shownVersion == "8u511")
        #expect(oracle.implementor == "Oracle Corporation")
        let zulu = try #require(byName["zulu-21.jdk"])
        #expect(zulu.vendor == .zulu && zulu.canonical == "21.0.5" && zulu.build == "21.0.5+11-LTS" && zulu.implementorVersion == "Zulu21.38+21-CA")
        #expect(zulu.vendorBuild == nil)                                         // only Corretto's builds are its own numbers here
        // GraalVM says IMPLEMENTOR="Oracle Corporation" and carries Oracle's bundle identifier: its own keys tell it apart
        let graal = try #require(byName["graalvm-21.jdk"])
        #expect(graal.vendor == .graalvm && graal.canonical == "21.0.12")
        // Corretto 8 has no release file: its Info.plist's JVMVersion
        let corretto = try #require(byName["amazon-corretto-8.jdk"])
        #expect(corretto.vendor == .corretto && corretto.version == "1.8.0_514" && corretto.shownVersion == "8u514")

        // the runtimes whose version cannot be read are said, the folder that is no runtime is not
        #expect(r.unchecked.map(\.item).sorted() == ["OpenJDK 27-ea (early.jdk)", "broken.jdk"])
        #expect(r.unchecked.allSatisfy { $0.kind == .java && $0.bucket == JavaSource.unreadable })
        #expect(r.report == SourceReport(kind: .java, available: true, count: 5, detail: "5 JDKs, 2 with no readable version"))
    }

    @Test("the vendor from what a runtime says", arguments: [
        (["IMPLEMENTOR": "Eclipse Adoptium"], [:], "x", JavaVendor.temurin),
        (["IMPLEMENTOR": "Amazon.com Inc."], [:], "x", .corretto),
        (["IMPLEMENTOR": "Microsoft"], [:], "x", .microsoft),
        (["IMPLEMENTOR": "Homebrew"], [:], "openjdk.jdk", .homebrew),
        (["IMPLEMENTOR": "Red Hat, Inc."], [:], "x", .redhat),
        (["IMPLEMENTOR": "BellSoft"], [:], "x", .liberica),
        (["IMPLEMENTOR": "SAP SE"], [:], "x", .sapmachine),
        (["IMPLEMENTOR": "JetBrains s.r.o."], [:], "jbr-17.0.9", .jetbrains),
        (["IMPLEMENTOR": "IBM Corporation", "JVM_VARIANT": "Openj9"], [:], "x", .semeru),
        (["IMPLEMENTOR": "Oracle Corporation"], ["CFBundleIdentifier": "com.oracle.java.jdk"], "jdk-21.jdk", .oracle),
        (["IMPLEMENTOR": "Oracle Corporation"], ["CFBundleIdentifier": "net.java.openjdk.jdk"], "jdk-21.0.2.jdk", .openjdk),   // jdk.java.net
        (["IMPLEMENTOR": "Oracle Corporation", "JAVA_RUNTIME_VERSION": "21.0.12+7-LTS-jvmci-23.1-b96"], [:], "x", .graalvm),
        (["IMPLEMENTOR": "Oracle Corporation"], [:], "21.0.2-oracle", .oracle),                                                 // SDKMAN's
        (["IMPLEMENTOR": "Oracle Corporation"], [:], "21.0.2-open", .openjdk),
        ([:], [:], "17.0.9-tem", .temurin), ([:], [:], "21.0.5-amzn", .corretto), ([:], [:], "22.3.r17-grl-graalce", .graalvm),
        ([:], [:], "corretto-21.0.5", .corretto),                                                                               // IntelliJ's
        ([:], [:], "whatever", .openjdk),
    ] as [([String: String], [String: String], String, JavaVendor)])
    func vendor(_ release: [String: String], _ plist: [String: String], _ folder: String, _ vendor: JavaVendor) {
        #expect(JavaVendor.identify(release: release, plist: plist, folder: folder) == vendor, "\(release) \(plist) \(folder)")
    }

    /// A release file that is not one (huge, a FIFO, a folder, binary) is a runtime with no readable version or nothing,
    /// never a hang or a crash.
    @Test func aBrokenReleaseFileIsSaidNeverACrash() async throws {
        let mac = JDK.mac()
        let jvms = JDK.machineFolder(mac.system)
        JDK.bundle(jvms, "huge.jdk", release: "JAVA_VERSION=\"17.0.20\"\n" + String(repeating: "X", count: JavaSource.maxRelease))
        let fifo = JDK.bundle(jvms, "fifo.jdk", release: nil).appendingPathComponent("Contents/Home/release")
        #expect(mkfifo(fifo.path, 0o644) == 0)
        let dir = JDK.bundle(jvms, "dir.jdk", release: nil).appendingPathComponent("Contents/Home/release")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        JDK.bundle(jvms, "binary.jdk", release: String(decoding: (0..<4096).map { UInt8($0 % 256) }, as: UTF8.self))
        let r = await JavaSource(environment: mac.tools, homebrewPrefixes: []).collect()
        #expect(r.runtimes.isEmpty)
        #expect(r.unchecked.map(\.item).sorted() == ["binary.jdk", "dir.jdk", "fifo.jdk", "huge.jdk"])
    }

    /// One JDK is one runtime, however many ways it is reached: Homebrew's keg, the caveat's link to it in
    /// /Library/Java/JavaVirtualMachines, SDKMAN's "current", mise's "17" for "17.0.2".
    @Test func oneJDKIsOneRuntime() async throws {
        let mac = JDK.mac()
        let cellar = mac.system.appendingPathComponent("opt/homebrew/Cellar/openjdk@17/17.0.21.1", isDirectory: true)
        let keg = JDK.bundle(cellar.appendingPathComponent("libexec"), "openjdk.jdk", release: JDK.release("17.0.21.1", implementor: "Homebrew"))
        JDK.link(mac.system.appendingPathComponent("opt/homebrew/opt/openjdk@17"), to: cellar)
        JDK.link(mac.system.appendingPathComponent("opt/homebrew/opt/openssl@3"), to: cellar.deletingLastPathComponent())    // not Java
        JDK.link(JDK.machineFolder(mac.system).appendingPathComponent("openjdk-17.jdk"), to: keg)
        let sdk = mac.home.appendingPathComponent(".sdkman/candidates/java", isDirectory: true)
        let tem = JDK.folder(sdk, "17.0.9-tem", release: JDK.release("17.0.9"))
        JDK.link(sdk.appendingPathComponent("current"), to: tem)
        let mise = mac.home.appendingPathComponent(".local/share/mise/installs/java", isDirectory: true)
        let full = JDK.folder(mise, "17.0.2", release: JDK.release("17.0.2", implementor: "Oracle Corporation"))
        JDK.link(mise.appendingPathComponent("17"), to: full)
        let r = await JavaSource(environment: mac.tools, homebrewPrefixes: ["/opt/homebrew"]).collect()
        #expect(r.runtimes.map { "\($0.place) \($0.version) \($0.formula ?? "-")" } == ["homebrew 17.0.21.1 openjdk@17", "sdkman 17.0.9 -", "mise 17.0.2 -"])
        #expect(Origin.javaRuntime(r.runtimes[0]).location == "Homebrew openjdk@17")
        #expect(Origin.javaRuntime(r.runtimes[1]).location == "JDK in \(Paths.abbreviatingHome(sdk.path)) · SDKMAN")

        // and a formula's JDK that Homebrew checks as OpenJDK is that finding, not a second one
        let index = Make.index
        #expect(JavaCheck.match(r.runtimes, index: index, checkedBrew: ["openjdk@17"]).matches.map(\.runtime.place) == [.sdkman, .mise])
        #expect(JavaCheck.match(r.runtimes, index: index).matches.count == 3)             // when brew could not say, it is checked here
    }

    /// Every folder the source lists is under the environment's home or its system root, so a test's scan reads no JDK of
    /// the Mac it runs on (CI's macOS runners have Temurin in /Library/Java/JavaVirtualMachines and Homebrew's openjdk).
    @Test func readsOnlyTheHomeAndTheSystemRoot() {
        let home = URL(fileURLWithPath: "/Users/ana", isDirectory: true)
        let tools = ToolEnvironment.fixture(home: home)
        let source = JavaSource(environment: tools)                                    // the app's own Homebrew prefixes
        let folders = (source.optFolders() + source.roots().map(\.folder)).map(\.path)
        #expect(folders.count == 8, "\(folders)")
        #expect(folders.allSatisfy { $0.hasPrefix(home.path + "/") }, "\(folders)")
        #expect(folders.contains(tools.systemRoot + "/Library/Java/JavaVirtualMachines"))
        #expect(folders.contains(tools.systemRoot + "/opt/homebrew/opt") && folders.contains(tools.systemRoot + "/usr/local/opt"))
        // and in the app, nothing changes: the root is empty
        let app = JavaSource(environment: ToolEnvironment(home: home, base: [:]))
        #expect(app.optFolders().map(\.path) == ["/opt/homebrew/opt", "/usr/local/opt"])
        #expect(app.roots().first?.folder.path == "/Library/Java/JavaVirtualMachines")
    }
}

@Suite struct JavaCheckTests {
    /// What each vendor is checked against comes from the index: OpenJDK's builds and Oracle's JDK as the openjdk project;
    /// GraalVM and Semeru nothing; and a vendor's own `C jre` line, when the index gains one, wins without a code change.
    @Test func theIndexSaysWhatEachRuntimeIsCheckedAgainst() throws {
        let openjdk = PublicIndex.Project(slug: "openjdk", name: "OpenJDK", repo: "github.com/openjdk/jdk")
        let today = PublicIndex(generatedAt: "", packages: [], projects: [openjdk])
        for v in JavaVendor.allCases {
            let route = JavaCheck.route(for: v, in: today)
            if v == .graalvm || v == .semeru { #expect(route == nil, "\(v)") } else { #expect(route == .project(slug: "openjdk", name: "OpenJDK"), "\(v)") }
        }
        // the recorded index with the bundle lines: "C jre java" is for the runtimes apps bundle, not these
        #expect(JavaCheck.route(for: .temurin, in: Make.index) == .project(slug: "openjdk", name: "OpenJDK"))

        let oracleSE = ProductIndex.Component(kind: .jre, match: "oracle", product: "oracle-java-se", name: "Oracle Java SE")
        let graal = ProductIndex.Component(kind: .jre, match: "graalvm", product: "graalvm", name: "GraalVM")
        let later = PublicIndex(generatedAt: "", packages: [], projects: [openjdk], products: ProductIndex(components: [oracleSE, graal]))
        #expect(JavaCheck.route(for: .oracle, in: later) == .product(oracleSE) && JavaCheck.route(for: .graalvm, in: later) == .product(graal))
        #expect(JavaCheck.route(for: .zulu, in: later) == .project(slug: "openjdk", name: "OpenJDK"))
        let check = JavaCheck.match([JDK.runtime("1.8.0_511", .oracle), JDK.runtime("21.0.12", .graalvm), JDK.runtime("17.0.20")], index: later)
        #expect(check.productKeys == ["oracle-java-se", "graalvm"] && check.projectSlugs == ["openjdk"])
        #expect(PrivacyFilter(index: later).approve(products: check.productKeys).map(\.key) == ["graalvm", "oracle-java-se"])
        // a JRE an app bundles still takes the "java" line, never a vendor's
        let app = Make.app(temporaryDirectory(), "Bundler", id: "com.example.bundler", short: "1.0")
        write("JAVA_VERSION=\"17.0.20\"\n", to: app.appendingPathComponent("Contents/runtime/Contents/Home/release"))
        let java = ProductIndex.Component(kind: .jre, match: "java", product: "openjdk", name: "Java")
        #expect(ComponentReader.components(in: app, records: [oracleSE, java]).map(\.record) == [java])
        #expect(ComponentReader.components(in: app, records: [oracleSE]).isEmpty)
    }

    /// Java4Shell, CVE-2026-114938, against the record the server publishes after its fix: Oracle names the newest
    /// affected update of each line, so every earlier one is affected, through Java's canonical versions.
    @Test func java4ShellAfterTheServersFix() throws {
        let runtimes = [JDK.runtime("17.0.20"), JDK.runtime("17.0.21"), JDK.runtime("17.0.22"), JDK.runtime("11.0.25"),
                        JDK.runtime("1.8.0_511", .oracle), JDK.runtime("1.8.0_512", .oracle), JDK.runtime("21.0.5", .zulu)]
        let check = JavaCheck.match(runtimes, index: Make.index)
        let f = check.findings(products: [:], projects: ["openjdk": JDK.postFix])
        // the record states nothing for 14 of its weighed advisories, two of them critical but none exploited: they make
        // no finding of their own, and are named and marked on the findings Java4Shell makes
        #expect(f.allSatisfy { $0.notChecked == Finding.NotChecked(id: "CVE-2026-114820", exploited: false, critical: true) })
        #expect(f.map { "\($0.title) \($0.installedVersion)" } == ["Java (Temurin) 17.0.20", "Java (Temurin) 17.0.21", "Java (Oracle) 8u511", "Java (Zulu) 21.0.5"])
        for finding in f {
            #expect(finding.advisoryIDs == ["CVE-2026-114938", "CVE-2026-114820", "CVE-2026-91403"] && finding.severity == .high && finding.group == .criticalHigh
                    && !finding.exploited && finding.flawCount == 1)
            #expect(finding.fixedVersion == nil && finding.subject == .project(slug: "openjdk", name: "OpenJDK", installedAs: "java"))
            #expect(finding.pageURL == SiteURL.projectPage(slug: "openjdk"))
            #expect(!(finding.note ?? "").contains("-XX:") && !(finding.note ?? "").lowercased().contains("workaround"))   // nothing invented
        }
        let temurin = f[0]
        #expect(temurin.note == "The issuer lists 17.0.20 as affected, up to 17.0.21.0.3; it names no fixed release. 14 more advisories state no affected versions; not checked, among them CVE-2026-114820, critical. "
                + "Install the newest Java 17 update from adoptium.net.")
        #expect(temurin.upgradeCommand == nil && temurin.commandInputs == nil && temurin.grade == "C")
        #expect(temurin.originSummary == "JDK in /Library/Java/JavaVirtualMachines")
        let oracle = f[2]
        #expect(oracle.note == "The issuer lists 8u511 as the newest affected version; it names no fixed release. 14 more advisories state no affected versions; not checked, among them CVE-2026-114820, critical. "
                + "Install the newest Java 8 update from oracle.com.")
        #expect(oracle.grade == nil && oracle.verification == .none)                    // OpenJDK's grade is not Oracle's
        #expect(check.notChecked(products: [:], projects: ["openjdk": JDK.postFix]).isEmpty)

        // today's record (ranges null: "version '8u511b33-perf' is not a version") flags none of them, and says nothing wrong
        #expect(check.findings(products: [:], projects: ["openjdk": JDK.live]).filter { $0.advisoryIDs.contains("CVE-2026-114938") }.isEmpty)
    }

    /// A distributor that patches without moving JAVA_VERSION: Corretto 27.0.1.1.4 still says 27.0.1, inside Oracle's
    /// "up to 27.0.1.0.3". The advisory's `fixed_builds` (Amazon's changelog at that tag lists the CVE) decides for
    /// Corretto's own build, by the core's order; every other vendor, and an older server, keeps the ranges' answer.
    @Test func correttosOwnBuildListsItsFix() throws {
        var json = try #require(try JSONSerialization.jsonObject(with: Fixture.data("api/project-openjdk-post-fix-2026-11-19.json")) as? [String: Any])
        var recent = try #require(json["recent"] as? [[String: Any]])
        let i = try #require(recent.firstIndex { $0["id"] as? String == "CVE-2026-114938" })
        recent[i]["fixed_builds"] = [["dist": "Amazon Corretto", "build": "27.0.1.1.4", "url": "https://github.com/corretto/corretto-27/blob/27.0.1.1.4/CHANGELOG.md"]]
        json["recent"] = recent
        let record = try JSONDecoder().decode(ProjectResponse.self, from: JSONSerialization.data(withJSONObject: json))
        #expect(record.recent[i].fixedBuilds == [.init(dist: "Amazon Corretto", build: "27.0.1.1.4", url: "https://github.com/corretto/corretto-27/blob/27.0.1.1.4/CHANGELOG.md")])
        func runtime(_ version: String, _ vendor: JavaVendor, _ implementorVersion: String?) -> JavaRuntime {
            var r = JDK.runtime(version, vendor, path: "/Library/Java/JavaVirtualMachines/\(implementorVersion ?? version).jdk")
            r.implementorVersion = implementorVersion
            return r
        }
        let runtimes = [runtime("27.0.1", .corretto, "Corretto-27.0.1.1.4"), runtime("27.0.1", .corretto, "Corretto-27.0.1.1.5"),
                        runtime("27.0.1", .corretto, "Corretto-27.0.1.1.3"), runtime("27.0.1", .corretto, nil),
                        runtime("17.0.20", .corretto, "Corretto-17.0.20.8.1"), runtime("27.0.1", .temurin, "Temurin-27.0.1+9")]
        let f = JavaCheck.match(runtimes, index: Make.index).findings(products: [:], projects: ["openjdk": record])
        // at or above the build Amazon lists: not affected by that advisory; below it, or unknown, or another line, or another vendor: affected
        #expect(f.map { "\($0.title) \($0.origins.first.flatMap { if case let .javaRuntime(r) = $0 { return r.implementorVersion ?? "-" }; return nil } ?? "")" }
                == ["Java (Corretto) Corretto-27.0.1.1.3", "Java (Corretto) -", "Java (Corretto) Corretto-17.0.20.8.1", "Java (Temurin) Temurin-27.0.1+9"])
        let below = f[0]
        #expect(below.fixedVersion == "27.0.1.1.4" && below.note == "The issuer lists 27.0.1 as affected, up to 27.0.1.0.3; it names no fixed release. 14 more advisories state no affected versions; not checked, among them CVE-2026-114820, critical. "
                + "Amazon Corretto's changelog lists the fix in Corretto 27.0.1.1.4. Install the newest Java 27 update from corretto.aws.")
        #expect(f.dropFirst().allSatisfy { $0.fixedVersion == nil && $0.note?.contains("changelog") == false })
        // what the vendor's build already fixes is said beside what still counts
        let cleared = JavaCheck.vendorFixes(runtimes[0], record.recent)
        #expect(cleared.fix == nil && cleared.recent.count == record.recent.count - 1
                && cleared.cleared == "Corretto 27.0.1.1.4 has Amazon Corretto's fix for CVE-2026-114938, so it does not count here.")
        // an older server, or a malformed list, is no list
        let malformed = #"{"id":"X","sev":"HIGH","fixed_builds":"27.0.1.1.4"}"#
        let decoded = try JSONDecoder().decode(ProjectResponse.Advisory.self, from: Data(malformed.utf8))
        let live = JDK.live
        #expect(decoded.fixedBuilds.isEmpty && live.recent.allSatisfy { $0.fixedBuilds.isEmpty })
    }

    /// A vendor's build is named as the fix only when the core finds it outside the published ranges of an advisory the
    /// row is shown for: Amazon's changelog listing the CVE at a build Oracle's range still holds is not enough.
    @Test func aVendorBuildInsideThePublishedRangesIsNotNamed() throws {
        var json = try #require(try JSONSerialization.jsonObject(with: Fixture.data("api/project-openjdk-post-fix-2026-11-19.json")) as? [String: Any])
        var recent = try #require(json["recent"] as? [[String: Any]])
        let i = try #require(recent.firstIndex { $0["id"] as? String == "CVE-2026-114938" })
        recent[i]["fixed_builds"] = [["dist": "Amazon Corretto", "build": "27.0.1.1.4"]]
        var ranges = try #require(recent[i]["ranges"] as? [[String: Any]])
        let line = try #require(ranges.firstIndex { $0["introduced"] as? String == "27" })
        ranges[line]["last_affected"] = "27.0.1.1.9"
        recent[i]["ranges"] = ranges
        json["recent"] = recent
        let record = try JSONDecoder().decode(ProjectResponse.self, from: JSONSerialization.data(withJSONObject: json))
        var r = JDK.runtime("27.0.1", .corretto, path: "/Library/Java/JavaVirtualMachines/Corretto-27.0.1.1.3.jdk")
        r.implementorVersion = "Corretto-27.0.1.1.3"
        #expect(JavaCheck.vendorFixes(r, record.recent).fix == "27.0.1.1.4")      // the vendor's record names it
        let f = try #require(JavaCheck.match([r], index: Make.index).findings(products: [:], projects: ["openjdk": record]).first)
        #expect(f.advisoryIDs.contains("CVE-2026-114938") && f.fixedVersion == nil && f.note?.contains("changelog") == false)
    }

    /// A vendor's build that fixes only some of the advisories the row is shown for is a partial fix: the row says how
    /// many it fixes and lists the ones it leaves, as every partial fix does. One that lands inside the published ranges
    /// of a weighed advisory the runtime is outside of is never named, as the core's own upgrade never is (ruling 8).
    @Test func aVendorBuildThatFixesSomeListsWhatItLeaves() throws {
        func record(_ more: String = "") throws -> ProjectResponse {
            try JSONDecoder().decode(ProjectResponse.self, from: Data(#"""
                {"slug":"openjdk","name":"OpenJDK","recent":[
                 {"id":"CVE-V","sev":"HIGH","title":"Fixed in Corretto's build","ranges":[{"introduced":"27","last_affected":"27.0.1.0.3"}],
                  "fixed_builds":[{"dist":"Amazon Corretto","build":"27.0.1.1.4"}]},
                 {"id":"CVE-O","sev":"CRITICAL","title":"Not fixed yet","ranges":[{"introduced":"27"}]}\#(more)]}
                """#.utf8))
        }
        var r = JDK.runtime("27.0.1", .corretto, path: "/Library/Java/JavaVirtualMachines/Corretto-27.0.1.1.3.jdk")
        r.implementorVersion = "Corretto-27.0.1.1.3"
        let f = try #require(JavaCheck.match([r], index: Make.index).findings(products: [:], projects: ["openjdk": try record()]).first)
        #expect(f.group == .criticalHigh && f.flawCount == 2 && f.fixedVersion == "27.0.1.1.4" && f.fixesCount == 1)
        #expect(f.unresolved.map(\.id) == ["CVE-O"] && f.unresolved.map(\.explanation) == ["Not fixed by this upgrade"])
        #expect(f.unresolved.first?.name == "Not fixed yet" && f.note?.contains("changelog lists the fix in Corretto 27.0.1.1.4") == true)
        // the same build inside a range 27.0.1 is outside of: never named
        let landing = #",{"id":"CVE-I","sev":"HIGH","title":"From 27.0.1.1","ranges":[{"introduced":"27.0.1.1","fixed":"27.0.1.2"}]}"#
        let inside = try #require(JavaCheck.match([r], index: Make.index).findings(products: [:], projects: ["openjdk": try record(landing)]).first)
        #expect(inside.fixedVersion == nil && inside.fixesCount == nil && inside.unresolved.isEmpty && inside.note?.contains("changelog") == false)
    }

    /// The live record (2026-11-19) states nothing for most of Java 8's advisories ("version '8u511-b32' is not a
    /// version"), two of them critical, none exploited: openjdk@8 8u502 has no finding for them alone; where a finding
    /// is made for other reasons, CVE-2026-114820 is named in its note and marked.
    @Test func anOpenJDKAdvisoryThatStatesNothingIsNamedNeverAFindingAlone() throws {
        func brew(_ version: String, _ record: ProjectResponse) throws -> [Finding] {
            let item = HomebrewItem(kind: .formula, name: "openjdk@8", version: version, urls: ["https://openjdk.org/"])
            let project = try #require(ProjectMatcher.project(for: item, in: Make.index))
            return FindingBuilder(index: Make.index).findings(approved: [:], verdicts: [:], brew: [.init(item: item, project: project)],
                                                              projects: ["openjdk": record], bigIssues: [])
        }
        #expect(try brew("1.8.0-502", JDK.live).isEmpty)
        let f = try #require(try brew("1.8.0-511", JDK.postFix).first)
        #expect(f.group == .criticalHigh && f.advisoryIDs.contains("CVE-2026-114820") && f.note?.hasSuffix("among them CVE-2026-114820, critical.") == true)
        #expect(f.notChecked == Finding.NotChecked(id: "CVE-2026-114820", exploited: false, critical: true))
    }

    /// n2: openjdk@8's finding an item made, made again by a later item, still names its version as Java does.
    @Test func aFindingAnItemMadeKeepsJavasVersions() throws {
        let item = HomebrewItem(kind: .formula, name: "openjdk@8", version: "1.8.0-511", urls: ["https://openjdk.org/"])
        let project = try #require(ProjectMatcher.project(for: item, in: Make.index))
        let record = try JSONDecoder().decode(ProjectResponse.self, from: Data(#"""
            {"slug":"openjdk","name":"OpenJDK","recent":[{"id":"CVE-J","sev":"MODERATE","ranges":[{"introduced":"8","fixed":"8.0.512"}]}]}
            """#.utf8))
        func issue(_ ids: [String], _ fixedIn: [String]) throws -> StateResponse.BigIssue {
            try JSONDecoder().decode(StateResponse.BigIssue.self, from: Data(#"{"name":"OpenJDK","slug":"openjdk","severity":"HIGH","exploited":false,"ids":\#(ids),"fixed_in":\#(fixedIn),"title":"T"}"#.utf8))
        }
        let f = try #require(FindingBuilder(index: Make.index).findings(approved: [:], verdicts: [:], brew: [.init(item: item, project: project)],
                                                                        projects: ["openjdk": record],
                                                                        bigIssues: [try issue(["CVE-Q"], ["8.0.512"]), try issue(["CVE-J"], [])]).first)
        #expect(f.group == .criticalHigh && f.installedVersion == "8u511" && f.fixedVersion == "8u512")
        #expect(f.note?.hasPrefix("The issuer lists 8u511 as affected and 8u512 as fixed.") == true)
    }

    /// MC: a vendor's build is never named for a finding that is only reported.
    @Test func aVendorBuildIsNeverNamedForAReportedFinding() throws {
        let record = try JSONDecoder().decode(ProjectResponse.self, from: Data(#"""
            {"slug":"openjdk","name":"OpenJDK","recent":[{"id":"CVE-U","sev":"HIGH","fixed_hint":["27.0.1.1.2"],"ranges":[{"introduced":"27","limit":"x"}],
             "fixed_builds":[{"dist":"Amazon Corretto","build":"27.0.1.1.4"}]}]}
            """#.utf8))
        var r = JDK.runtime("27.0.1", .corretto, path: "/Library/Java/JavaVirtualMachines/Corretto-27.0.1.1.3.jdk")
        r.implementorVersion = "Corretto-27.0.1.1.3"
        #expect(JavaCheck.vendorFixes(r, record.recent).fix == "27.0.1.1.4")
        let f = try #require(JavaCheck.match([r], index: Make.index).findings(products: [:], projects: ["openjdk": record]).first)
        #expect(f.group == .reported && f.fixedVersion == nil && f.note?.contains("changelog") == false)
    }

    /// GraalVM is listed as not checked, with why, never against OpenJDK's advisories; so is a runtime whose record
    /// could not be read.
    @Test func graalVMIsNotCheckedAndSaysWhy() {
        let check = JavaCheck.match([JDK.runtime("21.0.12", .graalvm), JDK.runtime("17.0.20")], index: Make.index)
        #expect(check.matches.map(\.runtime.vendor) == [.temurin] && check.unmatched.map(\.vendor) == [.graalvm])
        #expect(check.findings(products: [:], projects: ["openjdk": JDK.postFix]).map(\.title) == ["Java (Temurin)"])
        #expect(check.notChecked(products: [:], projects: ["openjdk": JDK.postFix])
                == [Coverage.Bucket(source: JavaCheck.noRecord, items: ["GraalVM 21.0.12 (graalvm-21.0.12.jdk)"])])
        #expect(check.notChecked(products: [:], projects: [:])[0].items.count == 2)
        #expect(JavaVendor.graalvm.notOpenJDK?.contains("apart from OpenJDK's") == true)
    }

    /// Homebrew's openjdk@8 writes 1.8.0-511: compared as 8.0.511, shown 8u511, like the JDKs' own rows.
    @Test func homebrewsOpenJDK8IsComparedInJavasForm() throws {
        let index = Make.index
        func brew(_ version: String) -> [Finding] {
            let item = HomebrewItem(kind: .formula, name: "openjdk@8", version: version, urls: ["https://openjdk.org/"])
            let project = ProjectMatcher.project(for: item, in: index)!
            return FindingBuilder(index: index).findings(approved: [:], verdicts: [:], brew: [.init(item: item, project: project)],
                                                         projects: ["openjdk": JDK.postFix], bigIssues: [])
        }
        let affected = try #require(brew("1.8.0-511").first)
        #expect(affected.id == "brew|openjdk@8|1.8.0-511" && affected.installedVersion == "8u511" && affected.originSummary == "Homebrew openjdk@8")
        #expect(affected.note == "The issuer lists 8u511 as the newest affected version; it names no fixed release. 14 more advisories state no affected versions; not checked, among them CVE-2026-114820, critical."
                && affected.upgradeCommand == "brew upgrade openjdk@8")
        #expect(brew("1.8.0-512").isEmpty)
        // Homebrew's own versions are compared in that form too, and said as Java says them
        let plan = FixPlan.Homebrew(brew: "/opt/homebrew/bin/brew", name: "openjdk@8", cask: false, versionIsTheFix: true, label: "openjdk@8")
        #expect(HomebrewAvailability.decide(HomebrewInfo(name: "openjdk@8", stable: "1.8.0-512", installed: "1.8.0-511"), for: plan, fixedVersion: "8u512")
                == .available(line: "Has 8u512."))
        #expect(HomebrewAvailability.decide(HomebrewInfo(name: "openjdk@8", stable: "1.8.0-511", installed: "1.8.0-511"), for: plan, fixedVersion: "8u512")
                == .unavailable("Homebrew still ships 8u511; the fix is 8u512 upstream."))
    }

    /// A last affected version is said as one; an open range still has no fixed release yet.
    @Test func aLastAffectedVersionIsNotANoFix() throws {
        func advisory(_ ranges: String) -> ProjectResponse.Advisory {
            try! JSONDecoder().decode(ProjectResponse.Advisory.self, from: Data(#"{"id":"X","sev":"HIGH","ranges":\#(ranges)}"#.utf8))
        }
        let last = try #require(AdvisoryCheck.decide("17.0.20", [advisory(#"[{"introduced":"17","last_affected":"17.0.21.0.3"}]"#)]))
        #expect(last.lastAffected == "17.0.21.0.3" && last.note == "The issuer lists 17.0.20 as affected, up to 17.0.21.0.3; it names no fixed release.")
        let open = try #require(AdvisoryCheck.decide("17.0.20", [advisory(#"[{"introduced":"17","last_affected":"17.0.21.0.3"},{"introduced":"17.0.1"}]"#)]))
        #expect(open.lastAffected == nil && open.note == "The issuer lists 17.0.20 as affected. No fixed release yet.")
        let fixed = try #require(AdvisoryCheck.decide("17.0.20", [advisory(#"[{"introduced":"17","fixed":"17.0.22"}]"#)]))
        #expect(fixed.lastAffected == nil && fixed.note(showing: { "<\($0)>" }) == "The issuer lists <17.0.20> as affected and <17.0.22> as fixed.")
    }
}

@Suite struct JavaFixTests {
    static let brew = "/opt/homebrew/bin/brew"
    static let pkgutil = "/usr/sbin/pkgutil"

    static func ok(_ s: String) -> CommandResult { CommandResult(status: 0, stdout: Data(s.utf8), stderr: Data()) }

    /// The command where the app can run it: the JDK's own cask, when the cask's record says it put this folder there,
    /// by a folder it moves into place or by its installer package's receipt.
    @Test func aCaskThatInstalledTheJDKIsUpgradedWithBrew() async throws {
        let root = temporaryDirectory()
        let jvms = root.appendingPathComponent("system/Library/Java/JavaVirtualMachines")
        let temurin = jvms.appendingPathComponent("temurin-17.jdk").path, corretto = jvms.appendingPathComponent("amazon-corretto-8.jdk").path
        let runner = RecordedRunner(outputs: [
            // Temurin's package installs at "/": pkgutil names the receipt the folder belongs to
            "\(Self.pkgutil) --file-info \(temurin)": Self.ok("volume: /\npath: \(temurin)\n\npkgid: net.temurin.17.jdk\npkg-version: 17.0.20+8\n"),
            // Corretto's installs into the JDKs' folder itself: its receipt's own list says so
            "\(Self.pkgutil) --file-info \(corretto)": Self.ok("volume: /\npath: \(corretto)\n"),
            "\(Self.pkgutil) --pkg-info-plist com.amazon.corretto.8": Self.ok("""
                <?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>install-location</key><string>Library/Java/JavaVirtualMachines/</string>\
                <key>pkgid</key><string>com.amazon.corretto.8</string><key>volume</key><string>/</string></dict></plist>
                """),
            "\(Self.pkgutil) --only-dirs --files com.amazon.corretto.8": Self.ok("amazon-corretto-8.jdk\namazon-corretto-8.jdk/Contents\n"),
        ])
        var tools = ToolEnvironment(home: root.appendingPathComponent("home"), base: [:], runner: runner, isExecutable: { [Self.brew, Self.pkgutil].contains($0) })
        tools.systemRoot = root.appendingPathComponent("system").path
        JDK.bundle(jvms, "temurin-17.jdk", release: JDK.fixture("temurin-17.0.20.release"), plist: "temurin-17.Info.plist")
        JDK.bundle(jvms, "amazon-corretto-8.jdk", release: nil, plist: "corretto-8.Info.plist")
        JDK.bundle(jvms, "sapmachine-jdk.jdk", release: JDK.release("17.0.20", implementor: "SAP SE"))
        JDK.bundle(jvms, "zulu-21.jdk", release: JDK.fixture("zulu-21.0.5.release"), plist: "zulu-21.Info.plist")
        let casks = [CaskFootprint(token: "temurin@17", packages: ["net.temurin.17.jdk"]),
                     CaskFootprint(token: "corretto@8", packages: ["com.amazon.corretto.8"]),
                     CaskFootprint(token: "sapmachine-jdk", targets: ["/Library/Java/JavaVirtualMachines/sapmachine-jdk.jdk"]),
                     // installed, but its receipt is not the one this Zulu came from: not offered for it
                     CaskFootprint(token: "zulu@21", packages: ["com.azulsystems.zulu.21"])]
        let r = await JavaSource(environment: tools, casks: casks, homebrewPrefixes: []).collect()
        let cask = Dictionary(uniqueKeysWithValues: r.runtimes.map { (($0.path as NSString).lastPathComponent, $0.cask ?? "-") })
        #expect(cask == ["temurin-17.jdk": "temurin@17", "amazon-corretto-8.jdk": "corretto@8", "sapmachine-jdk.jdk": "sapmachine-jdk", "zulu-21.jdk": "-"])

        let findings = JavaCheck.match(r.runtimes, index: Make.index).findings(products: [:], projects: ["openjdk": JDK.postFix])
        let tem = try #require(findings.first { $0.title == "Java (Temurin)" })
        #expect(tem.upgradeCommand == "brew upgrade --cask temurin@17" && tem.originSummary.hasSuffix("JavaVirtualMachines · Homebrew cask"))
        let plan = try FixPlan.make(for: tem, tools: tools).get()
        #expect(plan.command == "brew upgrade --cask temurin@17" && plan.invocation.argv == [Self.brew, "upgrade", "--cask", "temurin@17"])
        #expect(plan.homebrew == FixPlan.Homebrew(brew: Self.brew, name: "temurin@17", cask: true, versionIsTheFix: false, label: "temurin@17"))
        // its installer package asks for a password: Terminal, where the person types it, never run blind in the app
        let artifacts = CaskArtifacts([["uninstall": [["pkgutil": "net.temurin.17.jdk"]]], ["pkg": ["OpenJDK17U-jdk_aarch64_mac_hotspot_17.0.22_7.pkg"]]])
        let info = HomebrewInfo(name: "temurin@17", stable: "17.0.22", installed: "17.0.20", artifacts: artifacts)
        let root2 = HomebrewInfoReader(tools: tools).root(artifacts, bundle: nil)
        #expect(HomebrewAvailability.decide(info, for: plan.homebrew!, fixedVersion: nil, root: root2)
                == .needsPassword("Needs your administrator password: its update runs an installer package."))
        // a cask already at its newest does nothing: no command to run, said as such
        #expect(HomebrewAvailability.decide(HomebrewInfo(name: "temurin@17", stable: "17.0.20", installed: "17.0.20"), for: plan.homebrew!, fixedVersion: nil)
                == .unavailable(HomebrewAvailability.newestInstalled(electron: nil)))
        // SapMachine's cask moves its folder into /Library: a password too
        #expect(CaskArtifacts([["artifact": ["sapmachine-jdk-17.0.20.jdk", ["target": "/Library/Java/JavaVirtualMachines/sapmachine-jdk.jdk"]]]]).privileged
                == ["files outside your home folder"])

        // the Zulu its cask did not install: the vendor's download, as text; nothing to run
        let zulu = try #require(findings.first { $0.title == "Java (Zulu)" })
        #expect(zulu.upgradeCommand == nil && zulu.note?.hasSuffix("Install the newest Java 21 update from azul.com.") == true)
        #expect(FixPlan.make(for: zulu, tools: tools) == .failure(.noCommand))
    }

    /// SDKMAN, asdf, mise and IntelliJ IDEA are named, not run: `sdk` is a shell function, and none says which install
    /// replaces which.
    @Test func versionManagersAreTextNotCommands() {
        for (place, says) in [(JavaRuntime.Place.sdkman, "SDKMAN installed it: install a newer Java 17 with sdk install java."),
                              (.asdf, "asdf installed it: install a newer Java 17 with asdf install java."),
                              (.mise, "mise installed it: install a newer Java 17 with mise install java."),
                              (.intellij, "IntelliJ IDEA downloaded it: download a newer Java 17 there, in Project Structure > SDKs.")] {
            let a = UpgradeCommand.advice(for: .javaRuntime(JDK.runtime("17.0.20", place: place)), name: "temurin", ecosystem: nil, target: nil, malicious: false)
            #expect(a == UpgradeCommand.Advice(command: nil, note: says), "\(place)")
        }
        #expect(UpgradeCommand.java(JDK.runtime("17.0.20", .jetbrains, place: .user)).note == "It comes with a JetBrains IDE: updating the IDE updates it.")
        #expect(UpgradeCommand.java(JDK.runtime("17.0.21.1", .homebrew, formula: "openjdk@17")).command == "brew upgrade openjdk@17")
    }

    /// Where and why: who put the JDK there; for Oracle's, that it is checked against OpenJDK's advisories.
    @Test func provenanceSaysWhoPutItThereAndHowItIsChecked() async throws {
        let mac = JavaSourceTests.machine()
        let r = await JavaSource(environment: mac.tools, homebrewPrefixes: []).collect()
        let findings = JavaCheck.match(r.runtimes, index: Make.index).findings(products: [:], projects: ["openjdk": JDK.postFix])
        let explained = await ProvenanceExplainer(tools: mac.tools, timeZone: TimeZone(identifier: "UTC")!, homebrewPrefixes: []).explain(findings, inventory: Inventory())
        let oracle = try #require(explained.first { $0.title == "Java (Oracle)" }?.provenance?.first)
        #expect(oracle.path == JDK.machineFolder(mac.system).appendingPathComponent("jdk1.8.0_511.jdk").path)
        #expect(oracle.why?.hasPrefix("Installed for everyone on this Mac") == true)
        #expect(oracle.details == [ProvenanceText.oracleAsOpenJDK, "Built by Oracle Corporation", "Its version, 1.8.0_511, is Java 8u511"])
        let temurin = try #require(explained.first { $0.title == "Java (Temurin)" }?.provenance?.first)
        #expect(temurin.details == ["Built by Eclipse Adoptium, 17.0.20+8"])
        let sdk = JavaRuntime(path: mac.home.path + "/.sdkman/candidates/java/17.0.9-tem", home: "", realPath: "", place: .sdkman, vendor: .temurin,
                              version: "17.0.9", canonical: "17.0.9")
        #expect(ProvenanceExplainer.Context(explainer: ProvenanceExplainer(tools: mac.tools, homebrewPrefixes: []), inventory: Inventory())
                    .located(.javaRuntime(sdk))?.why == "You installed it with SDKMAN")
    }
}

@Suite struct JavaScanTests {
    static let brew = "/opt/homebrew/bin/brew"

    /// The site, with the openjdk record as the server publishes it after its fix.
    static func site() -> RecordedTransport { RecordedTransport.site(projects: ["openjdk": "api/project-openjdk-post-fix-2026-11-19.json"]) }

    /// A whole scan of a Mac with JDKs everywhere: they are found, decided, and nothing about them leaves the Mac but the
    /// project they are checked as. No path, folder name, user name, vendor or version is in any request.
    @Test func noPathLeavesTheMac() async throws {
        let mac = JavaSourceTests.machine()
        JDK.bundle(mac.home.appendingPathComponent("Library/Java/JavaVirtualMachines"), "corretto-17.0.20", release: JDK.release("17.0.20", implementor: "Amazon.com Inc."))
        JDK.folder(mac.home.appendingPathComponent(".jdks"), "openjdk-21.0.2", release: JDK.release("21.0.2", implementor: "Oracle Corporation"))
        JDK.folder(mac.home.appendingPathComponent(".sdkman/candidates/java"), "17.0.9-tem", release: JDK.release("17.0.9"))
        let brewJSON = #"{"formulae":[],"casks":[{"token":"temurin@17","installed":"17.0.20,8","homepage":"https://adoptium.net/","url":"https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.20%2B8/OpenJDK17U-jdk_aarch64_mac_hotspot_17.0.20_8.pkg","artifacts":[{"uninstall":[{"pkgutil":"net.temurin.17.jdk"}]},{"pkg":["OpenJDK17U.pkg"]}]}]}"#
        let temurin = JDK.machineFolder(mac.system).appendingPathComponent("temurin-17.jdk").path
        var tools = ToolEnvironment(home: mac.home, base: [:], runner: RecordedRunner(outputs: [
            "\(Self.brew) info --json=v2 --installed": CommandResult(status: 0, stdout: Data(brewJSON.utf8), stderr: Data()),
            "/usr/sbin/pkgutil --file-info \(temurin)": JavaFixTests.ok("pkgid: net.temurin.17.jdk\n"),
        ]), isExecutable: { [Self.brew, "/usr/sbin/pkgutil"].contains($0) })
        tools.systemRoot = mac.system.path
        let transport = Self.site()
        let scanner = Scanner(configuration: ScanConfiguration(storage: Storage(directory: mac.home.appendingPathComponent("support")), tools: tools,
                                                               folders: [], applicationRoots: []), transport: transport, pause: { _ in })
        let report = await scanner.scan()
        #expect(report.problems.isEmpty, "\(report.problems)")
        #expect(report.findings.map { "\($0.title) \($0.installedVersion)" }.sorted()
                == ["Java (Corretto) 17.0.20", "Java (OpenJDK) 21.0.2", "Java (Oracle) 8u511", "Java (Temurin) 17.0.20", "Java (Temurin) 17.0.9",
                    "Java (Zulu) 21.0.5"])
        // Corretto 8 is 8u514, past the last affected 8u511
        #expect(report.findings.first { $0.installedVersion == "17.0.20" && $0.title == "Java (Temurin)" }?.upgradeCommand == "brew upgrade --cask temurin@17")
        #expect(report.findings.allSatisfy { $0.provenance?.first?.path != nil })

        // what left the Mac: the project, and nothing else
        #expect(report.sent.distinctItems == ["project openjdk"])
        var secrets = [mac.home.path, mac.system.path, "JavaVirtualMachines", ".jdk", "sdkman", "jdks", NSUserName(), ProcessInfo.processInfo.userName]
        secrets += ["Temurin", "temurin", "Zulu", "zulu", "Oracle", "GraalVM", "graalvm", "Corretto", "corretto", "17.0.20", "1.8.0_511", "8u511", "8.0.511", "21.0.5"]
        for r in transport.requests {
            let headers = (r.allHTTPHeaderFields ?? [:]).map { "\($0.key): \($0.value)" }.joined(separator: "\n")
            let wire = (r.url?.absoluteString ?? "") + "\n" + headers + "\n" + String(decoding: r.httpBody ?? Data(), as: UTF8.self)
            for secret in secrets where !secret.isEmpty { #expect(!wire.contains(secret), "\(secret) left the Mac in \(wire)") }
        }
        // what was not checked is said, the cask whose JDK is checked here is not "with no graded project"
        let notChecked = Dictionary(uniqueKeysWithValues: report.coverage.notChecked.map { ($0.source, $0.items) })
        #expect(notChecked[JavaCheck.noRecord] == ["GraalVM 21.0.12 (graalvm-21.jdk)"])
        #expect(notChecked[JavaSource.unreadable]?.count == 2)
        #expect(notChecked["Homebrew packages with no graded project"] == nil)
        #expect(report.inventory.reports.first { $0.kind == .java }?.detail == "8 JDKs, 2 with no readable version")
    }

    /// After a fix, the runtime is read again where it was: updated in place, it is fixed; gone, it is removed.
    @Test func aRecheckReadsTheJDKAgain() async throws {
        let mac = JDK.mac()
        let jvms = JDK.machineFolder(mac.system)
        let bundle = JDK.bundle(jvms, "temurin-17.jdk", release: JDK.fixture("temurin-17.0.20.release"), plist: "temurin-17.Info.plist")
        let transport = Self.site()
        let scanner = Scanner(configuration: ScanConfiguration(storage: Storage(directory: mac.home.appendingPathComponent("support")), tools: mac.tools,
                                                               folders: [], applicationRoots: []), transport: transport, pause: { _ in })
        let report = await scanner.scan(refresh: [.java])
        let finding = try #require(report.findings.first)
        #expect(finding.title == "Java (Temurin)" && finding.installedVersion == "17.0.20")

        write(JDK.release("17.0.22"), to: bundle.appendingPathComponent("Contents/Home/release"))
        let (fixedReport, fixed) = await scanner.recheck(finding, in: report)
        #expect(fixed == .fixed(now: "17.0.22") && fixedReport.findings.isEmpty)

        write(JDK.release("17.0.21"), to: bundle.appendingPathComponent("Contents/Home/release"))
        guard case let .stillAffected(still) = await scanner.recheck(finding, in: report).outcome else { Issue.record("not still affected"); return }
        #expect(still.installedVersion == "17.0.21" && still.id != finding.id)

        try FileManager.default.removeItem(at: bundle)
        #expect(await scanner.recheck(finding, in: report).outcome == .removed)
    }
}

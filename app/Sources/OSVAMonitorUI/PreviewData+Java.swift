import Foundation
import OSVAKit

/// Fixture data for the Java runtimes, for `osva-render`: a Mac with Temurin 17 from its cask, Oracle's JDK 8, Zulu 21
/// from SDKMAN, Homebrew's openjdk@8 and GraalVM, checked against the openjdk record as the server publishes it after its
/// fix (Java4Shell, CVE-2026-114938). The rows are made by JavaCheck and FindingBuilder, as a scan makes them.
extension PreviewData {
    public enum JavaID {
        public static let temurin = "java|/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home|17.0.20"
        public static let oracle = "java|/Library/Java/JavaVirtualMachines/jdk1.8.0_511.jdk/Contents/Home|8.0.511"
        public static let zulu = "java|" + NSHomeDirectory() + "/.sdkman/candidates/java/21.0.5-zulu|21.0.5"
        public static let homebrew = "brew|openjdk@8|1.8.0-511"
    }

    /// The openjdk record, its Java4Shell advisory as the server writes it after its fix.
    static let openJDKRecord: ProjectResponse = {
        let json = #"""
        {"slug": "openjdk", "name": "OpenJDK", "grade": "C", "verified": [], "recent": [
          {"id": "CVE-2026-114938", "date": "2026-11-17", "sev": "HIGH", "title": "Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Compile",
           "fixed_hint": [], "kev": false, "cve": "CVE-2026-114938",
           "ranges": [{"introduced": "8", "last_affected": "8.0.511"}, {"introduced": "17", "last_affected": "17.0.21.0.3"},
                      {"introduced": "21", "last_affected": "21.0.13.0.3"}, {"introduced": "25", "last_affected": "25.0.5.0.3"},
                      {"introduced": "27", "last_affected": "27.0.1.0.3"}],
           "ranges_note": "Oracle lists the newest affected version on each line; earlier ones are affected too"}]}
        """#
        return try! JSONDecoder().decode(ProjectResponse.self, from: Data(json.utf8))
    }()

    static let javaIndex = PublicIndex(generatedAt: "2026-11-19T01:32:46Z", packages: [],
                                       projects: [.init(slug: "openjdk", name: "OpenJDK", repo: "github.com/openjdk/jdk")])

    static func jdk(_ path: String, _ vendor: JavaVendor, _ version: String, place: JavaRuntime.Place = .system, build: String? = nil,
                    implementor: String?, cask: String? = nil) -> JavaRuntime {
        let home = path.hasSuffix(".jdk") ? path + "/Contents/Home" : path
        return JavaRuntime(path: path, home: home, realPath: home, place: place, vendor: vendor, version: version,
                           canonical: JavaVersion.canonical(version)!, build: build, implementor: implementor, cask: cask)
    }

    public static let javaRuntimes: [JavaRuntime] = [
        jdk("/Library/Java/JavaVirtualMachines/temurin-17.jdk", .temurin, "17.0.20", build: "17.0.20+8", implementor: "Eclipse Adoptium", cask: "temurin@17"),
        jdk("/Library/Java/JavaVirtualMachines/jdk1.8.0_511.jdk", .oracle, "1.8.0_511", implementor: "Oracle Corporation"),
        jdk(NSHomeDirectory() + "/.sdkman/candidates/java/21.0.5-zulu", .zulu, "21.0.5", place: .sdkman, build: "21.0.5+11-LTS",
            implementor: "Azul Systems, Inc."),
        jdk("/Library/Java/JavaVirtualMachines/graalvm-21.jdk", .graalvm, "21.0.12", build: "21.0.12+7-LTS-jvmci-23.1-b96", implementor: "Oracle Corporation"),
    ]

    /// Where and why, worded as ProvenanceExplainer words it.
    static let javaProvenance: [String: Provenance] = [
        JavaID.temurin: Provenance(path: "/Library/Java/JavaVirtualMachines/temurin-17.jdk", why: "Homebrew installed it on 22 Jul 2026 (cask temurin@17)",
                                   details: ["Built by Eclipse Adoptium, 17.0.20+8"]),
        JavaID.oracle: Provenance(path: "/Library/Java/JavaVirtualMachines/jdk1.8.0_511.jdk", why: "Installed for everyone on this Mac, on 21 Oct 2026",
                                  details: [ProvenanceText.oracleAsOpenJDK, "Built by Oracle Corporation", "Its version, 1.8.0_511, is Java 8u511"]),
        JavaID.zulu: Provenance(path: NSHomeDirectory() + "/.sdkman/candidates/java/21.0.5-zulu", why: "You installed it with SDKMAN on 3 Nov 2025",
                                details: ["Built by Azul Systems, Inc., 21.0.5+11-LTS"]),
        JavaID.homebrew: Provenance(path: "/opt/homebrew/Cellar/openjdk@8/1.8.0-511", why: "You installed it on 14 Aug 2026"),
    ]

    /// Built off the main thread, where osva-render first reads it: JavaCheck asks the core for upgrades (`offMain`).
    public static let javaFindings: [Finding] = offMain {
        let check = JavaCheck.match(javaRuntimes, index: javaIndex)
        let item = HomebrewItem(kind: .formula, name: "openjdk@8", version: "1.8.0-511", urls: ["https://openjdk.org/"])
        let brew = FindingBuilder(index: javaIndex).findings(approved: [:], verdicts: [:], brew: [.init(item: item, project: javaIndex.project(slug: "openjdk")!)],
                                                             projects: ["openjdk": openJDKRecord], bigIssues: [])
        var out = FindingOrder.sorted(check.findings(products: [:], projects: ["openjdk": openJDKRecord]) + brew
                                      + findings.filter { [FixID.nginx, FixID.openssh].contains($0.id) })
        for i in out.indices { if let p = javaProvenance[out[i].id] { out[i].provenance = [p] } }
        return out
    }

    public static let javaCoverage = Coverage(
        notChecked: [.init(source: JavaCheck.noRecord, items: ["GraalVM 21.0.12 (graalvm-21.jdk)"]),
                     .init(source: JavaSource.unreadable, items: ["OpenJDK 27-ea (openjdk-27)"])])

    /// Temurin's cask asks for a password: Terminal only. The others are text: Oracle's and Zulu's have no command.
    public static var javaFixes: [String: FixRowState] {
        var out: [String: FixRowState] = [:]
        if let f = javaFindings.first(where: { $0.id == JavaID.temurin }), case let .success(plan) = FixPlan.make(for: f, tools: fixtureTools) {
            out[f.id] = FixRowState(availability: .terminal(FixOffer(plan: plan), HomebrewAvailability.passwordLine + ": its update runs an installer package."))
        }
        out[FixID.nginx] = FixRowState(availability: .offered(offer(FixID.nginx, homebrew: "Has 1.30.7.")))
        return out
    }

    public static let javaOpen: Set<String> = [JavaID.temurin, JavaID.oracle]

    public static func javaReport() -> ScanReport {
        var reports = inventoryReports
        reports.append(SourceReport(kind: .java, available: true, count: 5, detail: "5 JDKs, 1 with no readable version", seconds: 0.01))
        reports.sort { $0.kind < $1.kind }
        return ScanReport(startedAt: now.addingTimeInterval(-300), finishedAt: now.addingTimeInterval(-240),
                          inventory: Inventory(reports: reports), findings: javaFindings, sent: sent,
                          indexGeneratedAt: "2026-11-19T01:32:46Z", problems: [], coverage: javaCoverage)
    }
}

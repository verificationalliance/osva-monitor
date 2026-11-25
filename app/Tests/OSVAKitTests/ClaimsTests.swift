import Foundation
import Testing
@testable import OSVAKit

/// The claims about the app, checked on its own findings, and the routing that makes them true, checked in its source:
///   - a version is flagged as affected only if it lies inside a range the site publishes for that flaw;
///   - every version the app suggests upgrading to is newer than the installed one, and lies outside the published
///     ranges of every flaw it says that version fixes;
///   - only Core.swift makes a `CheckedUpgrade`, and nothing writes a version to upgrade to, or a command's version,
///     from anything else.
/// scripts/claims-mutants.sh breaks each in turn and expects this suite to fail.
@Suite struct ClaimsTests {
    let core = Core.shared

    static let claims = try! JSONDecoder().decode(BatchResponse.self, from: Fixture.data("api/check-batch-claims.json")).packages

    static func package(_ name: String) -> Finding {
        BatchCheckTests.findings(claims.filter { $0.name == name }).first!
    }

    static func report(_ findings: [Finding]) -> ScanReport {
        ScanReport(startedAt: Date(), finishedAt: Date(), inventory: Inventory(), findings: findings, sent: SentRecord(), indexGeneratedAt: nil, problems: [])
    }

    // MARK: Behaviour (the mutants likely-as-flagged, unchecked-target, lenient-decoding)

    /// A flaw the site publishes no ranges for is likely affected at most, never affected, and never counted.
    @Test func likelyIsNeverAffected() {
        let f = Self.package("likely-pkg")
        #expect(f.group == .likely)
        #expect(Self.report([f]).actionCount == 0)
    }

    /// The server's target 1.5.0 lies inside the flaw's only published range: the core's judgement names no upgrade, at
    /// its door and in the package's check (a finding also takes a target only for a flaw it leaves, a second layer that
    /// would hide a wrong judgement here), and the finding shows no version and no command.
    @Test func aServerTargetTheCoreRejectsIsNeverShown() throws {
        let inside = [CoreAdvisory(ranges: [AffectedRange(fixed: "2.0.0")], fixed: [])]
        let judged = try #require(core.judge("1.5.0", from: "1.0.0", advisories: inside, flagged: [true]))
        #expect(judged.leaves == [false] && judged.upgrade == nil)
        let answer = try #require(Self.claims.first { $0.name == "inside-target" })
        let check = BatchCheck.read(answer, installed: "1.0.0")
        #expect(check.upgrade == nil && check.target == .unconfirmed && check.fixed.isEmpty)
        let f = Self.package("inside-target")
        #expect(f.group == .criticalHigh)
        #expect(f.fixedVersion == nil && f.upgradeCommand == nil && f.commandInputs == nil)
    }

    /// A range with a key nobody publishes ("fixd") does not read: the flaw is reported, never inside a wider range. The
    /// same range in a project's record gives no affected finding at 3.0.
    @Test func anUnknownRangeKeyIsNeverAWiderRange() throws {
        #expect(Self.package("typo-range").group == .reported)
        let record = try JSONDecoder().decode(ProjectResponse.self, from: Data(#"""
            {"slug":"nginx","name":"nginx","recent":[{"id":"CVE-TYPO","sev":"HIGH","ranges":[{"introduced":"1.0","fixd":"2.0"}]}]}
            """#.utf8))
        let brew = FindingBuilder.BrewMatch(item: HomebrewItem(kind: .formula, name: "nginx", version: "3.0", urls: []),
                                            project: Fixture.index.project(slug: "nginx")!)
        let found = FindingBuilder(index: Fixture.index).findings(approved: [:], verdicts: [:], brew: [brew], projects: ["nginx": record], bigIssues: [])
        #expect(!found.contains { $0.group.needsAction || $0.group == .other })
    }

    // MARK: The claims, over the recorded answers

    /// The batch answers with published ranges, the claims fixture, and PostgreSQL's and CPython's records at versions
    /// in and out of their ranges. Each finding comes with the ranges its advisories publish, by id and alias, and each
    /// id's aliases. Java is left out: its shown versions are not the compared ones.
    struct Checked { var finding: Finding; var ranges: [String: [AffectedRange]]; var same: [String: Set<String>] }

    static let checked: [Checked] = {
        var out: [Checked] = []
        for file in ["check-batch-plan.json", "check-batch-live-2026-11-25.json", "check-batch-programs-live-2026-11-25.json", "check-batch-claims.json"] {
            let results = try! JSONDecoder().decode(BatchResponse.self, from: Fixture.data("api/" + file)).packages
            for f in BatchCheckTests.findings(results) {
                guard case let .package(eco, name) = f.subject,
                      let r = results.first(where: { $0.ecosystem == eco.rawValue && $0.name == name && $0.version == f.installedVersion }) else { continue }
                var c = Checked(finding: f, ranges: [:], same: [:])
                for flaw in r.flaws {
                    let ids = [flaw.id] + flaw.aliases
                    for id in ids { c.ranges[id] = flaw.ranges; c.same[id, default: []].formUnion(ids) }
                }
                out.append(c)
            }
        }
        let postgres = try! JSONDecoder().decode(ProjectResponse.self, from: Fixture.data("api/project-postgres.json"))
        let cpython = try! JSONDecoder().decode(ProjectResponse.self, from: Fixture.data("api/project-cpython-ranges.json"))
        let brew: [(String, String, ProjectResponse)] = [
            ("postgresql@14", "14.10", postgres), ("postgresql@15", "15.19", postgres), ("postgresql@16", "16.14", postgres),
            ("postgresql@16", "16.16", postgres), ("postgresql@17", "17.0", postgres), ("postgresql@18", "18.6", postgres),
            ("python@3.11", "3.11.18", cpython), ("python@3.12", "3.12.16", cpython), ("python@3.13", "3.13.18", cpython),
            ("python@3.14", "3.14.10", cpython), ("python@3.14", "3.14.11", cpython),
        ]
        for (formula, version, project) in brew {
            let match = FindingBuilder.BrewMatch(item: HomebrewItem(kind: .formula, name: formula, version: version, urls: []),
                                                 project: Fixture.index.project(slug: project.slug)!)
            var ranges: [String: [AffectedRange]] = [:], same: [String: Set<String>] = [:]
            for a in project.recent {
                let ids = [a.id] + (a.cve.map { [$0] } ?? [])
                for id in ids { ranges[id] = a.rangesUnreadable ? nil : a.ranges; same[id, default: []].formUnion(ids) }
            }
            for f in FindingBuilder(index: Fixture.index).findings(approved: [:], verdicts: [:], brew: [match], projects: [project.slug: project], bigIssues: []) {
                out.append(Checked(finding: f, ranges: ranges, same: same))
            }
        }
        return out
    }()

    /// "A version is flagged as affected only if it lies inside an affected range the site publishes for that flaw":
    /// every finding in today's groups, malicious ones aside, has an advisory whose published ranges hold its version,
    /// by the test's own comparisons (RangesTests.holds).
    @Test func everyAffectedFindingLiesInsideAPublishedRange() {
        let affected = Self.checked.filter { !$0.finding.malicious && [.exploited, .criticalHigh, .other].contains($0.finding.group) }
        #expect(affected.count >= 10, "the sample has affected findings to check")
        for c in affected {
            let f = c.finding
            let holding = f.advisoryIDs.filter { id in (c.ranges[id] ?? []).contains { RangesTests.holds($0, f.installedVersion) } }
            #expect(!holding.isEmpty, "\(f.id) is in \(f.group) with no published range holding \(f.installedVersion)")
        }
    }

    /// "Every version it suggests upgrading to is newer than yours and lies outside the published ranges of every
    /// advisory it says that version fixes": the advisories whose ranges hold the installed version, less those the
    /// finding lists as not fixed.
    @Test func everyNamedVersionLeavesTheAdvisoriesItFixes() {
        let named = Self.checked.filter { $0.finding.fixedVersion != nil && !$0.finding.malicious }
        #expect(named.count >= 10, "the sample names versions to check")
        for c in named {
            let f = c.finding, fixed = f.fixedVersion!, installed = f.installedVersion
            #expect(core.compareVersions(fixed, installed) > 0, "\(f.id): \(fixed) is not above \(installed)")
            let notFixed = Set(f.unresolved.flatMap { c.same[$0.id] ?? [$0.id] })
            for id in f.advisoryIDs where !notFixed.contains(id) {
                let rs = c.ranges[id] ?? []
                guard rs.contains(where: { RangesTests.holds($0, installed) }) else { continue }
                #expect(!rs.contains { RangesTests.holds($0, fixed) }, "\(f.id): \(fixed) lies inside \(id)'s published ranges")
            }
        }
    }

    // MARK: The routing, in the source

    /// app/Sources, each Swift file's path (from app/Sources) and its lines without comments. The patterns below mark a
    /// name's start with `(?:^|[^A-Za-z0-9_])`, not `\b`: Swift's `\b` is Unicode's word boundary, and there is none
    /// inside "self.fixedVersion" or "Core.shared.newestVersion(".
    static let sources: [(path: String, lines: [String])] = {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources")
        let files = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil)!.compactMap { $0 as? URL }
            .filter { $0.pathExtension == "swift" }.sorted { $0.path < $1.path }
        return files.map { url in
            let path = String(url.path.dropFirst(root.path.count + 1))
            let lines = try! String(contentsOf: url, encoding: .utf8).components(separatedBy: "\n").map { line -> String in
                if line.trimmingCharacters(in: .whitespaces).hasPrefix("//") { return "" }
                return line.range(of: " // ").map { String(line[..<$0.lowerBound]) } ?? line
            }
            return (path, lines)
        }
    }()

    /// The files whose code (comments aside) matches `pattern`, each with the first matching line.
    static func files(matching pattern: _StringProcessing.Regex<Substring>, except allowed: (String, String) -> Bool = { _, _ in false }) -> [String] {
        sources.compactMap { file in
            file.lines.first { line in line.contains(pattern) && !allowed(file.path, line) }.map { "\(file.path): \($0.trimmingCharacters(in: .whitespaces))" }
        }
    }

    /// Only Core.swift makes a `CheckedUpgrade` or a `Judgement`, and only it extends them; a version is shown only as a
    /// `CheckedUpgrade.Display` style writes it (`.displayed(.java)`, `.displayed(.program)`); the old doors are gone; the
    /// installed-version readers alone pick a newest version; the server's plan is read only in BatchCheck.swift.
    @Test func onlyCoreSwiftBuildsACheckedUpgrade() throws {
        try #require(Self.sources.contains { $0.path == "OSVAKit/Core.swift" }, "the scan reads app/Sources")
        let core = "OSVAKit/Core.swift"
        #expect(Self.files(matching: /(?:^|[^A-Za-z0-9_])(?:CheckedUpgrade|Judgement)\s*\(/, except: { path, _ in path == core }) == [])
        #expect(Self.files(matching: /(?:^|[^A-Za-z0-9_])extension\s+(?:OSVAKit\s*\.\s*)?(?:CheckedUpgrade|Judgement)(?![A-Za-z0-9_])/, except: { path, _ in path == core }) == [])
        // a version is shown only as CheckedUpgrade.Display writes it: a closed set of styles that carry no text
        let display = try #require(Self.sources.first { $0.path == core }?.lines.joined(separator: "\n"))
        let styles = try #require(display.firstMatch(of: /public enum Display: Sendable, Hashable \{([^}]*)\}/)?.1)
        let cases = styles.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }.filter { $0.hasPrefix("case ") }
        #expect(cases == ["case asChecked", "case java", "case program"], "CheckedUpgrade.Display: \(cases)")
        #expect(display.contains("public func displayed(_ style: Display) -> CheckedUpgrade { CheckedUpgrade(self, style: style) }"))
        #expect(Self.files(matching: /\.displayed\((?!\.java\)|\.asChecked\)|\.program\)|Self\.display\(slug: slug\)\))/) == [])
        // the old doors are gone
        #expect(Self.files(matching: /(?:^|[^A-Za-z0-9_])(?:nearestVersion|affectedness)\(|osva_affected|osva_upgrade_ranges/) == [])
        // a newest version is the installed one's, or goes straight to the core's judge
        let readers: Set = ["OSVAKit/Inventory/HomebrewSource.swift", "OSVAKit/Inventory/ExtensionSource.swift", "OSVAKit/Scan/Scanner.swift",
                            "OSVAKit/Fix/HomebrewAvailability.swift", "OSVAKit/Scan/JavaCheck.swift", "OSVAKit/Scan/ProgramFindings.swift",
                            "OSVAKit/Scan/AdvisoryCheck.swift"]          // AdvisoryCheck: the newest last affected version, never an upgrade
        #expect(Self.files(matching: /(?:^|[^A-Za-z0-9_])newestVersion\(/, except: { path, line in path == core || readers.contains(path) }) == [])
        // the server's plan target is read only where the core judges it
        #expect(Self.files(matching: /plan\?\.target|answer\.target/, except: { path, _ in path == "OSVAKit/Scan/BatchCheck.swift" }) == [])
    }

    /// Nothing writes a finding's version to upgrade to, or a command's version, but from a `CheckedUpgrade`: both are
    /// `private(set)`, and their own types set them only from one.
    @Test func versionsAreWrittenOnlyFromACheckedUpgrade() throws {
        func file(_ path: String) throws -> String { try #require(Self.sources.first { $0.path == path }?.lines.joined(separator: "\n")) }
        let finding = try file("OSVAKit/Model/Finding.swift"), command = try file("OSVAKit/Scan/UpgradeCommand.swift")
        #expect(finding.contains("public private(set) var fixedVersion: String?"))
        #expect(command.contains("public private(set) var target: String?"))
        let fixedWrites = Self.sources.flatMap { f in f.lines.filter { $0.contains(/(?:^|[^A-Za-z0-9_])fixedVersion\s*=[^=]/) }.map { "\(f.path): \($0.trimmingCharacters(in: .whitespaces))" } }
        #expect(fixedWrites.allSatisfy { $0.hasPrefix("OSVAKit/Model/Finding.swift: ") && $0.contains("fixedVersion = upgrade?.display") }, "\(fixedWrites)")
        #expect(fixedWrites.count == 2, "\(fixedWrites)")
        let targetWrites = command.split(separator: "\n").filter { $0.contains(/(?:^|[^A-Za-z0-9_])target\s*=[^=]/) && !$0.contains(/(?:let|var)\s+target(?![A-Za-z0-9_])/) }
        #expect(targetWrites.map { $0.trimmingCharacters(in: .whitespaces) }.allSatisfy { $0.contains("self.target = target?.version") }, "\(targetWrites)")
        #expect(Self.files(matching: /(?:commandInputs\??|[iI]nputs)\.target\s*=[^=]/) == [])
    }

    /// No command builder writes `@latest`, which lets a registry pick the version; and nothing reinterprets memory,
    /// which could forge a `CheckedUpgrade`, but the screen capture's one C function pointer.
    @Test func noLatestAndNoBitCasts() {
        #expect(Self.files(matching: /@latest/) == [])
        #expect(Self.files(matching: /(?:^|[^A-Za-z0-9_])unsafeBitCast(?![A-Za-z0-9_])/, except: { path, line in
            path == "OSVAMonitor/CaptureMode.swift" && line.contains("unsafeBitCast(symbol, to: CreateImage.self)")
        }) == [])
    }
}

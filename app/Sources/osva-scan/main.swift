// osva-scan: one OSVA Monitor scan from the command line, with the code the app runs.
//
//   osva-scan [--folder PATH]... [--data-dir PATH] [--json] [--quiet] [--why]
//
// --folder    a project folder to look for lockfiles in (repeatable; adds to the app's watched folders)
// --data-dir  where the index, caches and the last report are kept (default: the app's, or $OSVA_SUPPORT_DIR)
// --json      print the whole report as JSON
// --why       also time explaining where each finding's copies are and why (a second pass, after the scan)
import Foundation
import OSVAKit

func usage() -> Never {
    FileHandle.standardError.write(Data("usage: osva-scan [--folder PATH]... [--data-dir PATH] [--json] [--quiet] [--why]\n".utf8))
    exit(2)
}

var folders: [String] = [], dataDir: String?, json = false, quiet = false, why = false
var args = CommandLine.arguments.dropFirst()
while let a = args.popFirst() {
    switch a {
    case "--folder": guard let v = args.popFirst() else { usage() }; folders.append(v)
    case "--data-dir": guard let v = args.popFirst() else { usage() }; dataDir = v
    case "--json": json = true
    case "--quiet": quiet = true
    case "--why": why = true
    default: usage()
    }
}

let directory = dataDir.map { URL(fileURLWithPath: ($0 as NSString).expandingTildeInPath, isDirectory: true) } ?? Paths.supportDirectory()
let storage = Storage(directory: directory)
let settings = storage.loadSettings()
let roots = (settings.watchedFolders + folders).map { URL(fileURLWithPath: ($0 as NSString).expandingTildeInPath, isDirectory: true) }
let scanner = Scanner(configuration: ScanConfiguration(storage: storage, folders: roots))

let showProgress = !quiet && !json
let report = await scanner.scan(previous: nil, progress: { message in
    if showProgress && !message.isEmpty { FileHandle.standardError.write(Data("… \(message)\n".utf8)) }
})
storage.save(report)

if json {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
    encoder.dateEncodingStrategy = .iso8601
    FileHandle.standardOutput.write(try encoder.encode(report))
    print()
    exit(0)
}

print("OSVA Monitor scan, \(report.finishedAt.formatted(date: .abbreviated, time: .standard)) (index of \(report.indexGeneratedAt ?? "?"))")
print("")
print("Looked at:   (seconds per source; they run side by side, the scan took \(String(format: "%.2f", report.finishedAt.timeIntervalSince(report.startedAt))) s)")
for r in report.inventory.reports {
    let time = r.seconds.map { String(format: "%6.2f s  ", $0) } ?? String(repeating: " ", count: 10)
    print("  \(r.kind.title.padding(toLength: 14, withPad: " ", startingAt: 0)) \(time)\(r.detail)\(r.error.map { "  [\($0)]" } ?? "")")
}
print("")
if report.findings.isEmpty {
    print("Nothing installed matches a known malicious package or a known vulnerability in the public index.")
} else {
    for group in Finding.Group.allCases {
        let items = report.findings.filter { $0.group == group }
        guard !items.isEmpty else { continue }
        print("\(group.title.uppercased()) (\(items.count))")
        for f in items {
            let version = (f.component.map { "\($0) " } ?? "") + f.installedVersion + (f.fixedVersion.map { " -> \($0)" } ?? "")
            var tags: [String] = []
            if let s = f.severity { tags.append(s.label.lowercased()) }
            if f.exploited { tags.append("exploited") }
            if f.flawCount > 1 { tags.append("\(f.flawCount) flaws") }
            if f.verification != .none { tags.append(f.verification == .whole ? "verified as a whole" : "verified parts") }
            if let g = f.grade { tags.append("grade \(g)") }
            print("  \(f.title)  \(version)  [\(tags.joined(separator: ", "))]")
            print("      from \(f.originSummary)")
            for p in f.provenance ?? [] {
                if let path = p.path { print("      where: \(Paths.abbreviatingHome(path))") }
                if let w = p.why { print("      why: \(w)") }
                if let a = p.advice { print("      \(a)") }
                for d in p.dependents { print("        · \(d.line)") }
                for d in p.details { print("        · \(d)") }
            }
            if let n = f.note { print("      \(n)") }
            for u in f.unresolved { print("      · \(u.severity.map { $0.label + ", " } ?? "")\(u.id): \(u.explanation)") }
            if let b = f.bigIssue { print("      \(b)") }
            if let c = f.upgradeCommand { print("      $ \(c)") }
            print("      \(f.pageURL.absoluteString)")
        }
        print("")
    }
}
let coverage = report.coverage
if coverage.notInIndexCount > 0 {
    print("\(coverage.notInIndexCount) not in the index — no known problems (not proof of safety):")
    for b in coverage.notInIndex { print("  \(b.source): \(b.items.count)") }
    print("")
}
if coverage.notCheckedCount > 0 {
    print("NOT CHECKED (\(coverage.notCheckedCount))")
    for b in coverage.notChecked { print("  \(b.source): \(b.items.count)  e.g. \(b.items.prefix(4).joined(separator: ", "))") }
    print("")
}
print("What left this Mac:")
for r in report.sent.requests {
    print("  \(r.endpoint): \(r.items.count) item\(r.items.count == 1 ? "" : "s")")
    for i in r.items.prefix(quiet ? 0 : 400) { print("      \(i)") }
}
print("  \(report.sent.answeredFromCache) answered from the local cache; \(report.sent.withheldCount) installed items are not in the public index and were not sent.")
if why {
    // Explaining again from scratch, as the scan did: what it adds to a scan's time.
    let stripped = report.findings.map { f -> Finding in var c = f; c.provenance = nil; return c }
    let clock = ContinuousClock(), started = clock.now
    let explained = await ProvenanceExplainer().explain(stripped, inventory: report.inventory)
    let elapsed = clock.now - started
    let copies = explained.reduce(0) { $0 + ($1.provenance?.count ?? 0) }
    print("")
    print("Where and why: \(copies) copies of \(explained.count) findings explained in \(elapsed.formatted(.units(allowed: [.milliseconds])))")
    for kind in SourceKind.allCases {                               // each source alone, from scratch
        let some = stripped.filter { $0.origins.first?.kind == kind }
        guard !some.isEmpty else { continue }
        let t = clock.now
        _ = await ProvenanceExplainer().explain(some, inventory: report.inventory)
        print("  \(kind.title): \(some.count) findings in \((clock.now - t).formatted(.units(allowed: [.milliseconds])))")
    }
}
if !report.problems.isEmpty {
    print("")
    print("Problems:")
    for p in report.problems { print("  \(p)") }
}

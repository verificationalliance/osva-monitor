import Foundation
import OSVAKit

/// What the popover shows, worked out from the last report: kept apart from the views so it can be tested and
/// rendered from fixtures.
public struct PopoverContent: Sendable {
    public struct Section: Identifiable, Sendable {
        public var group: Finding.Group
        /// Its rows: the findings, and those fixed since the last full scan, each where it was.
        public var findings: [Finding]
        /// How many still stand (the heading's number): fixed rows are shown, not counted.
        public var count: Int
        public var id: Int { group.rawValue }
    }

    /// What the hero says, worst first. Its shield and colour follow from it.
    public enum Hero: Equatable, Sendable {
        case notScanned
        case firstScan
        case malicious
        case critical          // exploited, or critical severity
        case high              // only high severity needs action
        case clean

        public var symbol: String {
            switch self {
            case .notScanned, .firstScan: return "shield"
            case .malicious: return "xmark.shield.fill"
            case .critical, .high: return "exclamationmark.shield.fill"
            case .clean: return "checkmark.shield.fill"
            }
        }
    }

    /// What the hero's summary chips count.
    public enum Tally: Hashable, Sendable {
        case malicious, exploited
        case severity(Severity)

        public func word(_ n: Int) -> String {
            switch self {
            case .malicious: return "Malicious"
            case .exploited: return "Exploited"
            case let .severity(s): return s.label
            }
        }
    }

    public var sections: [Section]
    /// Findings that need action now (malicious, exploited, critical or high): the number beside the menu-bar shield.
    public var actionCount: Int
    public var hero: Hero
    /// The large number beside the shield, when something needs action.
    public var heroCount: Int?
    public var sentence: String
    /// What to do first, when one thing comes before the rest ("Remove the malicious package first.").
    public var advice: String?
    /// "Scanned 4 minutes ago · Homebrew, 15 Electron apps, pip, RubyGems, 2 folders".
    public var subline: String
    public struct TallyCount: Identifiable, Hashable, Sendable {
        public var tally: Tally
        public var count: Int
        public var id: Tally { tally }
    }

    public var tallies: [TallyCount]
    public var problem: String?
    /// What the scan could not vouch for: never counted as clean.
    public var coverage: Coverage
    public var isScanning: Bool
    public var progress: String
    public var hasReport: Bool

    /// `resolved` are findings fixed since the last full scan: no longer in the report, still shown in their place
    /// (their rows say "Fixed — now …") until the next full scan.
    public init(report: ScanReport?, isScanning: Bool, progress: String = "", now: Date = Date(), resolved: [Finding] = []) {
        self.isScanning = isScanning
        self.progress = progress
        hasReport = report != nil
        let findings = report?.findings ?? []
        let standing = Set(findings.map(\.id))
        let shown = findings + resolved.filter { !standing.contains($0.id) }
        sections = Finding.Group.allCases.compactMap { g in
            let items = shown.filter { $0.group == g }.sorted(by: FindingBuilder.precedes)
            return items.isEmpty ? nil : Section(group: g, findings: items, count: items.filter { standing.contains($0.id) }.count)
        }
        actionCount = report?.actionCount ?? 0
        problem = report?.problems.first
        coverage = report?.coverage ?? Coverage()

        let urgent = findings.filter(\.group.needsAction)
        let malicious = urgent.filter(\.malicious).count
        let exploited = urgent.filter { $0.exploited && !$0.malicious }.count
        let rest = urgent.filter { !$0.malicious && !$0.exploited }
        let critical = rest.filter { $0.severity == .critical }.count
        let high = rest.count - critical
        tallies = [TallyCount(tally: .malicious, count: malicious), TallyCount(tally: .exploited, count: exploited),
                   TallyCount(tally: .severity(.critical), count: critical), TallyCount(tally: .severity(.high), count: high)].filter { $0.count > 0 }

        let lower = findings.count - urgent.count
        let scanned = report.map { "Scanned \(Self.relative($0.finishedAt, now: now))" }
        let looked = report.map { Self.sourcesSummary($0.inventory.reports) } ?? ""
        let when = [scanned, looked.isEmpty ? nil : looked].compactMap { $0 }.joined(separator: " · ")

        switch (report, actionCount) {
        case (nil, _):
            hero = isScanning ? .firstScan : .notScanned
            heroCount = nil
            sentence = isScanning ? "Taking a first look" : "Not scanned yet"
            subline = isScanning ? (progress.isEmpty ? "Reading Homebrew, apps and global packages…" : progress)
                                 : "Scan to see what the site knows about this Mac."
        case (_, 0):
            hero = .clean
            heroCount = nil
            sentence = "Nothing needs action"
            let others = lower == 0 ? nil : (lower == 1 ? "1 lower-severity finding" : "\(lower) lower-severity findings")
            let unchecked = coverage.notCheckedCount == 0 ? nil : "\(coverage.notCheckedCount.formatted()) not checked"
            subline = [others, unchecked, when].compactMap { $0 }.joined(separator: " · ")
        case let (_, n):
            hero = malicious > 0 ? .malicious : (exploited + critical > 0 ? .critical : .high)
            heroCount = n
            switch hero {
            case .malicious:
                sentence = n == 1 ? "needs action" : "need action"
                advice = "Remove the malicious \(malicious == 1 ? "package" : "packages") first."
            default: sentence = n == 1 ? "needs action" : "need action"
            }
            subline = when
        }
        if isScanning && report != nil, !progress.isEmpty { subline = progress }
    }

    /// The whole headline in words ("8 need action"), for notifications and accessibility.
    public var headline: String { [heroCount.map(String.init), sentence].compactMap { $0 }.joined(separator: " ") }

    /// "Homebrew, 15 Electron apps, pip, RubyGems, 2 folders": the sources that had something.
    public static func sourcesSummary(_ reports: [SourceReport]) -> String {
        reports.filter { $0.available && $0.count > 0 }.map { r in
            switch r.kind {
            case .electron: return r.count == 1 ? "1 Electron app" : "\(r.count) Electron apps"
            case .folders:
                let n = Int(r.detail.split(separator: " ").first ?? "") ?? 0
                return n == 1 ? "1 folder" : "\(n) folders"
            default: return r.kind.title
            }
        }.joined(separator: ", ")
    }

    static func relative(_ date: Date, now: Date) -> String {
        if now.timeIntervalSince(date) < 60 { return "just now" }
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .full
        return f.localizedString(for: date, relativeTo: now)
    }

    /// The menu-bar icon's state.
    public var menuBarState: MenuBarLabel.State {
        switch hero {
        case .notScanned, .firstScan: return .notScanned
        case .clean: return .clean
        case .malicious: return .malicious(actionCount)
        case .critical, .high: return .action(actionCount)
        }
    }
}

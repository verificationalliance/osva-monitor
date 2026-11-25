import Foundation
import OSVAKit

/// What the popover shows, worked out from the last report: kept apart from the views so it can be tested and
/// rendered from fixtures.
public struct PopoverContent: Sendable {
    public struct Section: Identifiable, Sendable {
        /// The section's group: likely and reported findings share one, keyed `.likely` (Finding.Group.section).
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
        /// Nothing the core checked needs action, but an exploited or critical flaw was not checked against published
        /// ranges: never the green "Nothing needs action".
        case notChecked
        case clean

        public var symbol: String {
            switch self {
            case .notScanned, .firstScan: return "shield"
            case .malicious: return "xmark.shield.fill"
            case .critical, .high: return "exclamationmark.shield.fill"
            case .notChecked: return "exclamationmark.shield"
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
        sections = Finding.Group.sections.compactMap { g in
            let items = FindingOrder.sorted(shown.filter { $0.group.section == g })  // each app's findings together
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

        let lower = findings.filter { $0.group == .other }.count
        let notChecked = findings.filter(\.group.isNotChecked).count
        // an exploited or critical flaw the core could not check, on any finding
        let alerting = findings.contains { $0.notCheckedMark != nil }
        let scanned = report.map { Self.unbroken("Scanned \(Self.relative($0.finishedAt, now: now))") }
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
            hero = alerting ? .notChecked : .clean
            heroCount = nil
            sentence = alerting ? "Nothing checked needs action" : "Nothing needs action"
            let notAgainstRanges = notChecked == 0 ? nil : Self.unbroken("\(notChecked) not checked against published ranges")
            let others = lower == 0 ? nil : Self.unbroken(lower == 1 ? "1 lower-severity finding" : "\(lower) lower-severity findings")
            let unchecked = coverage.notCheckedCount == 0 ? nil : Self.unbroken("\(coverage.notCheckedCount.formatted()) not checked")
            subline = [notAgainstRanges, others, unchecked, when].compactMap { $0 }.joined(separator: " · ")
        case let (_, n):
            hero = malicious > 0 ? .malicious : (exploited + critical > 0 ? .critical : .high)
            heroCount = n
            switch hero {
            case .malicious:
                sentence = n == 1 ? "needs action" : "need action"
                advice = Self.removeFirst(urgent.filter(\.malicious))
            default: sentence = n == 1 ? "needs action" : "need action"
            }
            subline = when
        }
        if isScanning && report != nil, !progress.isEmpty { subline = progress }
    }

    /// The whole headline in words ("8 need action"), for notifications and accessibility.
    public var headline: String { [heroCount.map(String.init), sentence].compactMap { $0 }.joined(separator: " ") }

    /// "Remove the malicious package first.", "Remove the malicious extensions first."
    static func removeFirst(_ malicious: [Finding]) -> String {
        let extensions = malicious.filter(\.isExtension).count, packages = malicious.count - extensions
        let what = [packages == 0 ? nil : packages == 1 ? "package" : "packages",
                    extensions == 0 ? nil : extensions == 1 ? "extension" : "extensions"].compactMap { $0 }.joined(separator: " and ")
        return "Remove the malicious \(what) first."
    }

    /// "Homebrew, 138 apps, 23 extensions, Go and Rust programs, pip, pipx, RubyGems, 2 folders": the sources that had
    /// something. The apps count includes those that bundle Electron, so they are not counted twice; Go and Rust
    /// programs, and pipx and uv tools, share one name when both are there. Each name keeps its words together
    /// (no-break spaces), so a wrapped line never splits "138 apps" or "Go and Rust programs".
    public static func sourcesSummary(_ reports: [SourceReport]) -> String {
        let shown = reports.filter { $0.available && $0.count > 0 }
        let kinds = Set(shown.map(\.kind))
        return shown.filter { !(kinds.contains(.apps) && $0.kind == .electron) }.compactMap { r -> String? in
            switch r.kind {
            case .electron: return r.count == 1 ? "1 Electron app" : "\(r.count) Electron apps"
            case .apps: return r.count == 1 ? "1\u{00A0}app" : "\(r.count.formatted())\u{00A0}apps"             // never "140 / apps"
            case .extensions: return r.count == 1 ? "1\u{00A0}extension" : "\(r.count.formatted())\u{00A0}extensions"
            case .java: return r.count == 1 ? "1\u{00A0}JDK" : "\(r.count)\u{00A0}JDKs"
            case .folders:
                let n = Int(r.detail.split(separator: " ").first ?? "") ?? 0
                return n == 1 ? "1 folder" : "\(n) folders"
            case .go where kinds.contains(.rust): return "Go and Rust programs"
            case .rust where kinds.contains(.go): return nil
            case .pipx where kinds.contains(.uv): return "pipx and uv tools"
            case .uv where kinds.contains(.pipx): return nil
            default: return r.kind.title
            }
        }.map(unbroken).joined(separator: ", ")
    }

    /// The phrase with no-break spaces: a wrapped subline breaks between its parts, never inside "4 minutes ago".
    static func unbroken(_ phrase: String) -> String { phrase.replacingOccurrences(of: " ", with: "\u{00A0}") }

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
        case .notChecked: return .notChecked
        case .malicious: return .malicious(actionCount)
        case .critical, .high: return .action(actionCount)
        }
    }
}

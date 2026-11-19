import Foundation
import Testing
import OSVAKit
@testable import OSVAMonitorUI

@Suite struct BundlePopoverTests {
    let now = PreviewData.now

    @Test func scannedSaysAppsAndExtensions() {
        let c = PopoverContent(report: PreviewData.bundlesReport(), isScanning: false, now: now)
        // the apps count includes those that bundle Electron; a count never parts from its noun at a line break
        #expect(c.subline == "Scanned 4 minutes ago · Homebrew, 140\u{00A0}apps, 23\u{00A0}extensions, npm, pip, RubyGems, 2 folders")
        let older = PopoverContent.sourcesSummary(PreviewData.inventoryReports)                   // a report from before apps were read
        #expect(older == "Homebrew, 15 Electron apps, npm, pip, RubyGems, 2 folders")
        #expect(PopoverContent.sourcesSummary([SourceReport(kind: .extensions, available: false, count: 0, detail: "no editors or browsers with extensions")]) == "")
    }

    @Test func maliciousExtensionsLeadTheList() {
        let c = PopoverContent(report: PreviewData.bundlesReport(), isScanning: false, now: now)
        #expect(c.sections.map(\.group) == [.malicious, .exploited, .criticalHigh])
        #expect(c.sections[0].findings.allSatisfy { $0.isExtension })
        #expect(c.hero == .malicious && c.heroCount == 8 && c.advice == "Remove the malicious extensions first.")
        #expect(c.tallies.map { "\($0.count) \($0.tally.word($0.count))" } == ["2 Malicious", "1 Exploited", "1 Critical", "4 High"])
        // an app's findings sit together: VLC's Sparkle, then VLC's own
        #expect(c.sections[2].findings.prefix(2).map(\.title) == ["VLC", "VLC"])
        // a bundled library's project grade is not drawn beside the app's name
        #expect(c.sections[2].findings.allSatisfy { $0.grade == nil && $0.verification == .none })
    }

    @Test func removeFirstNamesWhatIsMalicious() {
        let f = PreviewData.findings.filter(\.malicious) + PreviewData.bundleFindings.filter(\.malicious)
        #expect(PopoverContent.removeFirst(Array(f.prefix(1))) == "Remove the malicious package first.")
        #expect(PopoverContent.removeFirst(Array(f.suffix(1))) == "Remove the malicious extension first.")
        #expect(PopoverContent.removeFirst(f) == "Remove the malicious package and extensions first.")
    }

    @Test func linksSayWhereTheyGo() {
        let byTitle = Dictionary(PreviewData.bundleFindings.map { ($0.title + ($0.component ?? ""), $0) }, uniquingKeysWith: { a, _ in a })
        #expect(byTitle["Prettier – Code formatter"]?.pageLabel == "Open the report on github.com")
        #expect(byTitle["Volume Booster Pro"]?.pageLabel == "Open on verificationalliance.org")
        #expect(byTitle["Volume Booster Pro"]?.originSummary == "Chrome extension · Work, Personal")
        #expect(byTitle["GitLenslodash"]?.originSummary == "VS Code extension · eamodio.gitlens")
    }

    @Test func whatLeavesYourMacCountsProducts() {
        #expect(SentSummary.counts(PreviewData.bundleSent) == .init(batch: 3, projects: 2, products: 4))
        let lists = SentSummary.lists(PreviewData.bundleSent)
        #expect(lists.map(\.kind) == [.checked, .projects, .products, .cached, .withheld])
        #expect(lists[2].title == "Apps and bundled libraries checked" && lists[2].sections.flatMap(\.items) == ["openssl", "sparkle", "vlc", "zoom"])
        #expect(!SentSummary.lists(PreviewData.sent).contains { $0.kind == .products })       // only once a scan asked about any
    }

    @Test func notificationsNameAnExtension() {
        let fresh = PreviewData.bundleFindings.filter(\.deservesNotification)
        #expect(SystemNotifier.text(for: [fresh[0]]).title == "Malicious extension: Prettier – Code formatter")
        #expect(SystemNotifier.text(for: [PreviewData.findings[0]]).title == "Malicious package: axios")
    }
}

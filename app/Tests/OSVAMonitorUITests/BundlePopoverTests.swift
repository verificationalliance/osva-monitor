import Foundation
import Testing
import OSVAKit
@testable import OSVAMonitorUI

@Suite struct BundlePopoverTests {
    let now = PreviewData.now

    @Test func scannedSaysAppsAndExtensions() {
        let c = PopoverContent(report: PreviewData.bundlesReport(), isScanning: false, now: now)
        // the apps count includes those that bundle Electron; no phrase is split at a line break, a count never parts from its noun
        #expect(c.subline == "Scanned\u{00A0}4\u{00A0}minutes\u{00A0}ago ·\u{00A0}Homebrew, 140\u{00A0}apps, 23\u{00A0}extensions, npm, pip, RubyGems, 2\u{00A0}folders")
        let older = PopoverContent.sourcesSummary(PreviewData.inventoryReports)                   // a report from before apps were read
        #expect(older == "Homebrew, 15\u{00A0}Electron\u{00A0}apps, npm, pip, RubyGems, 2\u{00A0}folders")
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

/// What could not be vouched for, as lists of names: readable, one per line, the long ones in a window with search.
@Suite struct CoverageListTests {
    let coverage = PreviewData.appCoverage

    @Test func appListsReadAsNamesWithIconsPackagesAsWritten() {
        let apps = CoverageLists.list(coverage.notChecked[1], in: .notChecked)
        #expect(apps.title == "Apps with no security record" && apps.style == .names && apps.many == "apps" && apps.shown == 104)
        #expect(apps.sections[0].paths?.count == 104 && apps.searchable)
        let brew = CoverageLists.list(coverage.notChecked[0], in: .notChecked)
        #expect(brew.style == .code && brew.many == "names" && !brew.searchable)
        let libraries = CoverageLists.list(coverage.notChecked[2], in: .notChecked)
        #expect(libraries.style == .names && libraries.many == "names")              // what apps bundle, by the app's icon
        let chrome = CoverageLists.list(coverage.updatedElsewhere[1], in: .updatedElsewhere)
        #expect(chrome.title == "Chrome web apps" && chrome.explanation.contains("updated with Chrome") && chrome.style == .names)
        #expect(CoverageLists.list(coverage.updatedElsewhere[0], in: .updatedElsewhere).explanation.contains("not checked here"))
    }

    @Test func aListLongEnoughToSearchOpensInAWindow() {
        func row(_ n: Int) -> ListDisclosureRow {
            ListDisclosureRow(NameList(title: "t", explanation: "", count: n, sections: [.init(title: nil, items: (0..<n).map { "a\($0)" })], style: .names))
        }
        #expect(!row(20).opensWindow && row(21).opensWindow && NameList.searchThreshold == 20)
    }

    @Test func theKeepersInAFewWords() {
        #expect(CoverageLists.keepersCaption(coverage.updatedElsewhere) == "App Store and web apps — not checked here")
        #expect(CoverageLists.keepersCaption([.init(source: AppCoverage.appStore, items: ["a"])]) == "App Store — not checked here")
        #expect(CoverageLists.keepersCaption([.init(source: AppCoverage.appStore, items: ["a"]), .init(source: AppCoverage.macOS, items: ["b"]),
                                              .init(source: "Edge web apps", items: ["c"])]) == "App Store, macOS and web apps — not checked here")
    }

    @Test func onlyWhatNobodyLooksAfterHasNoRecord() {
        let c = PopoverContent(report: PreviewData.coverageReport(), isScanning: false, now: PreviewData.now)
        #expect(c.coverage.notCheckedCount == 109 && c.coverage.updatedElsewhereCount == 37)
        #expect(c.subline.hasPrefix("3\u{00A0}lower-severity\u{00A0}findings ·\u{00A0}109\u{00A0}with\u{00A0}no\u{00A0}record ·\u{00A0}Scanned"))
        #expect(PreviewData.appsWithNoRecord.count + PreviewData.appsFromTheAppStore.count + PreviewData.chromeWebApps.count
                + PreviewData.edgeWebApps.count == 141)
    }

    @Test func searchAndFooterSayApps() {
        let list = CoverageLists.list(coverage.notChecked[1], in: .notChecked)
        let found = NameListView.sections(list, matching: "micro").flatMap(\.rows)
        #expect(found.map(\.text) == ["Microsoft Edge", "Microsoft Excel", "Microsoft Outlook", "Microsoft PowerPoint", "Microsoft Word"])
        #expect(found.allSatisfy { $0.path?.hasPrefix("/Applications/Microsoft") == true })
        #expect(NameListView.footer(list, scanned: PreviewData.now, query: "", matching: 104).hasPrefix("104 apps · last scan "))
        #expect(NameListView.footer(list, scanned: PreviewData.now, query: "micro", matching: 5) == "5 of 104")
    }
}

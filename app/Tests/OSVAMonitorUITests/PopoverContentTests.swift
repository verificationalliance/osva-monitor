import AppKit
import Foundation
import Testing
import OSVAKit
import SwiftUI
@testable import OSVAMonitorUI

@Suite struct PopoverContentTests {
    let now = PreviewData.now

    @Test func groupsInTheirOrder() {
        let c = PopoverContent(report: PreviewData.report(), isScanning: false, now: now)
        #expect(c.sections.map(\.group) == [.malicious, .exploited, .criticalHigh, .likely, .other])
        #expect(c.actionCount == 9)                                   // everything but "Other" and what was not checked
    }

    /// Likely and reported findings share one section, "Not checked against published ranges", between what needs
    /// action and Other, and are never counted.
    @Test func notCheckedFindingsShareASectionAndAreNotCounted() throws {
        let c = PopoverContent(report: PreviewData.notCheckedReport(), isScanning: false, now: now)
        #expect(c.sections.count == 1)
        let section = try #require(c.sections.first)
        #expect(section.group == .likely && section.group.heading == "Not checked against published ranges")
        #expect(Finding.Group.likely.title == Finding.Group.reported.title)
        // worst first, as in every section: ImageMagick (critical, reported) before Redis (high, likely)
        #expect(section.findings.map(\.id) == [PreviewData.NotCheckedID.imagemagick, PreviewData.NotCheckedID.redis] && section.count == 2)
        #expect(c.actionCount == 0 && c.heroCount == nil && c.tallies.isEmpty)
    }

    /// An exploited or critical flaw the core could not check against published ranges never leaves the green
    /// "Nothing needs action": the hero says nothing checked needs action, under a hollow amber shield.
    @Test func anExploitedReportIsNeverClean() {
        func content(_ findings: [Finding]) -> PopoverContent { PopoverContent(report: PreviewData.report(findings: findings), isScanning: false, now: now) }
        let c = PopoverContent(report: PreviewData.notCheckedReport(), isScanning: false, now: now)
        #expect(c.hero == .notChecked && c.hero.symbol == "exclamationmark.shield" && c.heroCount == nil)
        #expect(c.sentence == "Nothing checked needs action" && c.headline == "Nothing checked needs action")
        #expect(c.subline.hasPrefix(PopoverContent.unbroken("2 not checked against published ranges") + " ·\u{00A0}" + PopoverContent.unbroken("8 with no record") + " ·\u{00A0}Scanned"))
        #expect(c.menuBarState == .notChecked && c.caveat == "Not proof of safety: it is what has been reported.")
        // a report saved before `notChecked`: the reported finding's own exploited flaw keeps the hero amber
        let saved = PreviewData.notCheckedFindings.map { f in var x = f; x.notChecked = nil; return x }
        #expect(content(saved).hero == .notChecked)
        // critical only, not exploited: amber too, from the finding's mark (a reported finding) or a flaw beside it (Other)
        var reportedCritical = PreviewData.notCheckedFindings.filter { $0.id == PreviewData.NotCheckedID.imagemagick }
        reportedCritical[0].exploited = false
        reportedCritical[0].notChecked = Finding.NotChecked(id: "CVE-C", exploited: false, critical: true)
        #expect(content(reportedCritical).hero == .notChecked && content(reportedCritical).sentence == "Nothing checked needs action")
        var otherCritical = PreviewData.findings.filter { $0.group == .other }
        otherCritical[0].notChecked = Finding.NotChecked(id: "CVE-C", exploited: false, critical: true)
        #expect(content(otherCritical).hero == .notChecked)
        // a checked low finding in Other, with an exploited flaw beside it that the core could not check
        let other = PreviewData.findings.filter { $0.group == .other }
        var marked = other
        marked[0].notChecked = Finding.NotChecked(id: "CVE-X", exploited: true, critical: false)
        #expect(content(marked).hero == .notChecked && content(marked).subline.hasPrefix(PopoverContent.unbroken("4 lower-severity findings")))
        // only a likely high finding: nothing urgent, so the green hero, which says what it did not check; Other alone
        // counts as lower-severity
        let likely = PreviewData.notCheckedFindings.filter { $0.group == .likely }
        let clean = content(other + likely)
        #expect(clean.hero == .clean && clean.sentence == "Nothing needs action" && clean.menuBarState == .clean)
        #expect(clean.subline.hasPrefix([PopoverContent.unbroken("1 not checked against published ranges"), PopoverContent.unbroken("4 lower-severity findings"),
                                         PopoverContent.unbroken("8 with no record"), "Scanned"].joined(separator: " ·\u{00A0}")))
        // anything the core checked that needs action comes first
        #expect(content(PreviewData.findings).hero == .malicious && content(PreviewData.findings).caveat == nil && clean.caveat != nil)
    }

    /// What nothing here checks is "No record", never a second "Not checked" beside "Not checked against published
    /// ranges"; the hero's subline says it in the same words.
    /// The subline's dots go with the part after them: a wrapped line breaks before a dot, so no line ends with "·".
    @Test func noSublineLineEndsWithADot() {
        func content(_ findings: [Finding]) -> PopoverContent { PopoverContent(report: PreviewData.report(findings: findings), isScanning: false, now: now) }
        for c in [content(PreviewData.findings), content(PreviewData.notCheckedFindings), content(PreviewData.crowdedFindings),
                  content(PreviewData.findings.filter { $0.group == .other }), content([])] {
            #expect(c.subline.contains("·") && !c.subline.contains("· ") && !c.subline.contains("·\n"), "\(c.subline)")
            #expect(c.subline.components(separatedBy: "·").dropFirst().allSatisfy { $0.hasPrefix("\u{00A0}") })
        }
        #expect(String.whole("Fixed 6 · 2 need you") == "Fixed\u{00A0}6 ·\u{00A0}2\u{00A0}need\u{00A0}you")
    }

    /// Only the glyphs drawn in one colour lie on a plate: the flame and the hollow shield in the headings, and the
    /// hollow shield in the hero, on its own filled shape. Filled glyphs with a white mark, and quiet ones, have none.
    @MainActor @Test func onlyOneColourGlyphsLieOnPlates() {
        typealias H = GroupContainer<EmptyView>.Heading
        #expect([H.findings(.exploited), .findings(.likely), .findings(.reported)].allSatisfy { $0.plate == .disc })
        #expect([H.findings(.malicious), .findings(.criticalHigh), .findings(.other), .noRecord].allSatisfy { $0.plate == PlateShape.none })
        #expect(PopoverContent.Hero.notChecked.plate == .symbol("shield.fill"))
        #expect([PopoverContent.Hero.notScanned, .firstScan, .malicious, .critical, .high, .clean].allSatisfy { $0.plate == PlateShape.none })
    }

    /// A finding whose only flaw lies outside its published ranges is checked: in Other, not among what was not checked.
    @Test func aFindingCheckedOutsideItsRangesIsOther() {
        let c = PopoverContent(report: PreviewData.crowdedReport(), isScanning: false, now: now)
        let numeric = PreviewData.crowdedFindings.first { $0.title == "numeric" }!
        #expect(numeric.group == .other && numeric.severity == nil && numeric.statusChips.isEmpty)
        #expect(numeric.withoutVersion == "outside its published ranges")
        let windows = PreviewData.crowdedFindings.first { $0.title == "win-path" }!
        #expect(c.sections.first { $0.group == .other }?.findings.map(\.id) == [numeric.id, windows.id])
        #expect(c.subline.hasPrefix(PopoverContent.unbroken("1 not checked against published ranges") + PopoverContent.dot))
    }

    /// A finding whose every flaw is of another platform, not affected there by published ranges: in Other, with no
    /// severity, and a version line that says it does not affect this Mac, never "no fixed release known".
    @Test func anotherPlatformsFindingSaysItDoesNotAffectThisMac() {
        let windows = PreviewData.crowdedFindings.first { $0.title == "win-path" }!
        #expect(windows.group == .other && windows.severity == nil && windows.statusChips.isEmpty && windows.fixedVersion == nil)
        #expect(windows.withoutVersion == "does not affect this Mac")
        // whatever its flaws' lines say: a finding with no unresolved flaws to tell it by
        let bare = Finding(id: "x", group: .other, subject: .package(ecosystem: .npm, name: "x"), title: "x", installedVersion: "1.0", upgrade: nil,
                           severity: nil, advisoryIDs: [], flawCount: 1, exploited: false, malicious: false, note: nil, bigIssue: nil,
                           origins: [.npmGlobal(npm: "npm")], pageURL: SiteURL.home, advice: nil, verification: .none, grade: nil)
        var elsewhere = bare
        elsewhere.onlyElsewhere = true
        #expect(bare.withoutVersion == "no fixed release known" && elsewhere.withoutVersion == "does not affect this Mac")
    }

    /// The hero counts as lower-severity only what is in Other for something to do here: never a finding outside its
    /// published ranges, nor one whose flaws are all of another platform.
    @Test func whatAffectsNothingHereIsNoLowerSeverityFinding() {
        func content(_ findings: [Finding]) -> PopoverContent { PopoverContent(report: PreviewData.report(findings: findings), isScanning: false, now: now) }
        let other = PreviewData.findings.filter { $0.group == .other }
        let listed = PreviewData.crowdedFindings.filter { $0.title == "numeric" || $0.title == "win-path" }
        #expect(listed.count == 2 && listed.allSatisfy { $0.group == .other })
        let c = content(other + listed)
        #expect(c.hero == .clean && c.subline.hasPrefix(PopoverContent.unbroken("4 lower-severity findings") + PopoverContent.dot), "\(c.subline)")
        #expect(!content(listed).subline.contains("lower-severity"))
    }

    @MainActor @Test func whatNothingChecksIsNoRecord() {
        #expect(GroupContainer<EmptyView>.Heading.noRecord.title == "No record")
        #expect(GroupContainer<EmptyView>.Heading.findings(.likely).title == "Not checked against published ranges")
        let clean = PopoverContent(report: PreviewData.report(findings: []), isScanning: false, now: now)
        #expect(clean.subline.hasPrefix(PopoverContent.unbroken("8 with no record") + " ·\u{00A0}Scanned") && !clean.subline.contains("not\u{00A0}checked"))
    }

    /// The panel is drawn by SwiftUI alone, as osva-render draws it: nothing in it is an AppKit control, which an
    /// off-screen render leaves as SwiftUI's placeholder (a yellow square with a red "no" sign). The footer's gear and
    /// power were `.borderless` buttons, which are; the scan's progress bar is drawn as a stand-in off-screen.
    @MainActor @Test func thePanelDrawsNoPlaceholder() throws {
        _ = NSApplication.shared
        func panel(_ report: ScanReport?, scanning: Bool = false, expanded: Set<String> = [], fixes: [String: FixRowState] = [:],
                   resolved: [Finding] = [], fixAll: FixAllPanel = .none) -> AnyView {
            AnyView(PopoverView(content: PopoverContent(report: report, isScanning: scanning, progress: scanning ? "Checking…" : "", now: now, resolved: resolved),
                                actions: .none, fixes: fixes, fixAll: fixAll, expanded: expanded, scrolls: false)
                .environment(\.drawsOffScreen, true))
        }
        let offer = try #require(PreviewData.fixScene("offer")), review = try #require(PreviewData.fixAllScene("all-review"))
        let views: [(String, AnyView)] = [
            ("popover", panel(PreviewData.report(), expanded: [PreviewData.FixID.axios, PreviewData.FixID.nginx])),
            ("not checked", panel(PreviewData.notCheckedReport(), expanded: [PreviewData.NotCheckedID.imagemagick, PreviewData.NotCheckedID.redis])),
            ("scanning", panel(PreviewData.report(), scanning: true)),
            ("first scan", panel(nil, scanning: true)),
            ("fix offer", panel(offer.report(), expanded: offer.open, fixes: offer.fixes)),
            ("fix all review", panel(review.scene.report(), expanded: review.scene.open, fixes: review.scene.fixes, fixAll: review.panel)),
            ("crowded", panel(PreviewData.crowdedReport())),
        ]
        for (name, view) in views {
            let renderer = ImageRenderer(content: view.frame(width: PopoverView.width))
            renderer.scale = 1
            let image = try #require(renderer.cgImage, "\(name) did not render")
            #expect(PreviewData.placeholderPixels(image) == 0, "\(name) draws a placeholder")
        }
    }

    /// The red "Exploited" chip and "Exploited flaw" are for a flaw the core checked. The amber chip marks an exploited
    /// or critical flaw it did not: on a likely or reported row, in the red chip's place, naming critical only when the
    /// row's severity beside it does not; on a checked row, the flaw beside it.
    @Test func theAmberMarkSaysWhatTheCoreDidNotCheck() {
        func words(_ f: Finding) -> String? {
            guard case let .notChecked(alert, namesCritical)? = f.notCheckedChip else { return nil }
            return alert.chipWords(namesCritical: namesCritical)
        }
        let imagemagick = PreviewData.notCheckedFindings.first { $0.id == PreviewData.NotCheckedID.imagemagick }!
        let alert = Finding.NotChecked(id: "CVE-2026-41730", exploited: true, critical: true)
        #expect(imagemagick.exploited && !imagemagick.checkedExploited)
        #expect(imagemagick.notCheckedChip == .notChecked(alert, namesCritical: false) && words(imagemagick) == "Exploited, not checked")
        #expect(alert.chipHelp == "CVE-2026-41730: critical, exploited in the wild; reported by the site, not checked against published ranges")
        // reported, critical, not exploited: its severity says critical beside the chip
        var critical = imagemagick
        critical.exploited = false
        critical.notChecked = Finding.NotChecked(id: "CVE-C", exploited: false, critical: true)
        #expect(words(critical) == "Not checked")
        // likely, high, with a critical reported flaw: the chip names what the row does not
        var likely = PreviewData.notCheckedFindings.first { $0.id == PreviewData.NotCheckedID.redis }!
        #expect(likely.notCheckedChip == nil)
        likely.notChecked = Finding.NotChecked(id: "CVE-R", exploited: false, critical: true)
        #expect(words(likely) == "Critical, not checked")
        // checked and affected, with a critical flaw beside it that states no affected versions
        let cpython = PreviewData.findings.first { $0.id == PreviewData.FixID.cpython }!
        #expect(cpython.group == .criticalHigh && words(cpython) == "Critical, not checked")
        var cpythonExploited = cpython
        cpythonExploited.notChecked = Finding.NotChecked(id: "CVE-E", exploited: true, critical: false)
        #expect(words(cpythonExploited) == "Exploited, not checked")
        let openssh = PreviewData.findings.first { $0.id == PreviewData.FixID.openssh }!
        #expect(openssh.checkedExploited && openssh.notCheckedChip == nil)
        // a report saved before `notChecked`: the finding's own exploited flag; never its severity alone, which may come
        // from a flaw whose published ranges the core checked
        var saved = imagemagick
        saved.notChecked = nil
        #expect(saved.notCheckedMark == Finding.NotChecked(id: nil, exploited: true, critical: false))
        #expect(saved.notCheckedMark!.chipHelp.hasPrefix("Exploited in the wild; reported by the site"))
        saved.exploited = false
        #expect(saved.severity == .critical && saved.notCheckedMark == nil)
        let axios = PreviewData.findings[0]
        #expect(axios.malicious && axios.notCheckedMark == nil && !axios.checkedExploited)
        // without a version, a row the core could not check names no fix
        let time = PreviewData.findings.first { $0.title == "time" }!
        #expect(imagemagick.withoutVersion == "no checked fixed version" && time.withoutVersion == "no fixed release known")
    }

    /// The row's status line is this list, which FindingRow only draws: the red chip only for a flaw the core checked;
    /// the amber chip leads a likely or reported row (in the red chip's place) and trails a checked row (after what was
    /// checked); malicious alone.
    @Test func theStatusLineIsAListInItsOrder() {
        func line(_ id: String) -> [StatusLineItem] { PreviewData.findings.first { $0.id == id }!.statusChips }
        let im = Finding.NotChecked(id: "CVE-2026-41730", exploited: true, critical: true)
        let py = Finding.NotChecked(id: "CVE-2026-38812", exploited: false, critical: true)
        #expect(line(PreviewData.NotCheckedID.imagemagick) == [.chip(.notChecked(im, namesCritical: false)), .severity(.critical)])
        #expect(line(PreviewData.NotCheckedID.redis) == [.severity(.high), .flaws(2)])
        #expect(line(PreviewData.FixID.cpython) == [.severity(.high), .chip(.notChecked(py, namesCritical: true))])
        #expect(line(PreviewData.FixID.openssh) == [.chip(.exploited), .severity(.high)])
        #expect(line(PreviewData.FixID.nginx) == [.severity(.critical), .flaws(6)])
        #expect(line(PreviewData.FixID.axios) == [.chip(.malicious)])
        // the crowded rows: everything at once, the amber chip last on a checked row
        let crowded = PreviewData.crowdedFindings[0]
        #expect(crowded.statusChips == [.chip(.exploited), .severity(.moderate), .flaws(128), .chip(.notChecked(crowded.notChecked!, namesCritical: true))])
    }

    /// A finding the core did not check never says "Exploited flaw": its exploited flaw is "not checked", whether the
    /// report carries the mark or was saved before it.
    @Test func aNotCheckedNotificationSaysSo() {
        let imagemagick = PreviewData.notCheckedFindings.first { $0.id == PreviewData.NotCheckedID.imagemagick }!
        #expect(imagemagick.deservesNotification && SystemNotifier.text(for: [imagemagick]).title == "Exploited flaw, not checked: ImageMagick")
        var saved = imagemagick
        saved.notChecked = nil
        #expect(saved.deservesNotification && SystemNotifier.text(for: [saved]).title == "Exploited flaw, not checked: ImageMagick")
        let redis = PreviewData.notCheckedFindings.first { $0.id == PreviewData.NotCheckedID.redis }!
        #expect(!redis.deservesNotification)
    }

    @Test func theHeroSaysTheWorstThing() {
        let c = PopoverContent(report: PreviewData.report(), isScanning: false, now: now)
        #expect(c.hero == .malicious && c.hero.symbol == "xmark.shield.fill")
        #expect(c.heroCount == 9)
        #expect(c.sentence == "need action" && c.advice == "Remove the malicious package first.")
        #expect(c.headline == "9 need action")
        #expect(c.subline == PopoverContent.unbroken("2 not checked against published ranges")
                + " ·\u{00A0}Scanned\u{00A0}4\u{00A0}minutes\u{00A0}ago ·\u{00A0}Homebrew, 15\u{00A0}Electron\u{00A0}apps, npm, pip, RubyGems, 2\u{00A0}folders")
        #expect(c.tallies.map { "\($0.count) \($0.tally.word($0.count))" } == ["1 Malicious", "2 Exploited", "2 Critical", "4 High"])
        #expect(c.menuBarState == .malicious(9))
    }

    @Test func heroStates() {
        func content(_ findings: [Finding]) -> PopoverContent { PopoverContent(report: PreviewData.report(findings: findings), isScanning: false, now: now) }
        let all = PreviewData.findings
        let critical = content(all.filter { !$0.malicious })
        #expect(critical.hero == .critical && critical.sentence == "need action" && critical.menuBarState == .action(8))
        let high = content(all.filter { $0.severity == .high && !$0.exploited && $0.group.needsAction })
        #expect(high.hero == .high && high.heroCount == 4 && high.sentence == "need action")
        #expect(high.hero.symbol == "exclamationmark.shield.fill")
        let clean = content(all.filter { $0.group == .other })
        #expect(clean.hero == .clean && clean.heroCount == nil && clean.sentence == "Nothing needs action")
        #expect(clean.subline.hasPrefix("4\u{00A0}lower-severity\u{00A0}findings ·\u{00A0}8\u{00A0}with\u{00A0}no\u{00A0}record ·\u{00A0}Scanned"))   // never "clean" without saying so
        #expect(clean.menuBarState == .clean && clean.hero.symbol == "checkmark.shield.fill")
        let none = PopoverContent(report: nil, isScanning: false, now: now)
        #expect(none.hero == .notScanned && none.sentence == "Not scanned yet" && none.menuBarState == .notScanned)
        #expect(none.hero.symbol == "shield")                         // hollow: never mistaken for the clean shield
        let first = PopoverContent(report: nil, isScanning: true, progress: "Looking at what is installed…", now: now)
        #expect(first.hero == .firstScan && first.subline == "Looking at what is installed…")
    }

    @Test func everySourceIsNamedOnceAndKeepsItsWordsTogether() {
        let summary = PopoverContent.sourcesSummary(PreviewData.programReports)
        #expect(summary == ["Homebrew", "MacPorts", "Nix", "15 Electron apps", "Go and Rust programs", "npm", "pip", "pipx and uv tools", "conda",
                            "RubyGems", "2 folders"].map { $0.replacingOccurrences(of: " ", with: "\u{00A0}") }.joined(separator: ", "))
        let goOnly = PreviewData.programReports.filter { $0.kind != .rust && $0.kind != .uv }
        #expect(PopoverContent.sourcesSummary(goOnly).contains("Go\u{00A0}programs, npm, pip, pipx, conda"))
        // with apps and extensions read, the apps count stands for the Electron apps too
        let withApps = PreviewData.programReports + [SourceReport(kind: .apps, available: true, count: 140, detail: "140 apps"),
                                                     SourceReport(kind: .extensions, available: true, count: 23, detail: "23 extensions")]
        #expect(PopoverContent.sourcesSummary(withApps.sorted { $0.kind < $1.kind }) == ["Homebrew", "MacPorts", "Nix", "140 apps", "23 extensions",
                "Go and Rust programs", "npm", "pip", "pipx and uv tools", "conda", "RubyGems", "2 folders"]
                .map { $0.replacingOccurrences(of: " ", with: "\u{00A0}") }.joined(separator: ", "))
        // a source that found nothing, or is not installed, is not named
        let none = [SourceReport(kind: .nix, available: true, count: 0, detail: "0 packages in 1 profile"),
                    SourceReport(kind: .macports, available: false, count: 0, detail: "MacPorts not found")]
        #expect(PopoverContent.sourcesSummary(none) == "")
    }

    @Test func whileScanningTheLastFindingsStay() {
        let c = PopoverContent(report: PreviewData.report(), isScanning: true, progress: "Checking 27 package versions…", now: now)
        #expect(c.subline == "Checking 27 package versions…")
        #expect(c.sections.count == 5 && c.hero == .malicious)
    }

    @Test func versionLines() {
        let f = PreviewData.findings
        #expect(f.first { $0.title == "OpenMTP" }?.versionLine == "Electron 18.3.15 → 42.11.16")
        #expect(f.first { $0.title == "axios" }?.versionLine == "1.14.1")
        #expect(f.first { $0.title == "time" }?.versionLine == "0.1.43")
    }

    @MainActor @Test func menuBarSymbolsAreTemplateShields() {
        #expect(MenuBarLabel(.notScanned).symbol == "shield")
        #expect(MenuBarLabel(.clean).symbol == "checkmark.shield")
        #expect(MenuBarLabel(.notChecked).symbol == "exclamationmark.shield")            // hollow: nothing checked needs action
        #expect(MenuBarLabel(.action(3)).symbol == "exclamationmark.shield.fill")
        #expect(MenuBarLabel(.malicious(1)).symbol == "xmark.shield.fill")
    }

    @Test func whatLeavesYourMacInNumbers() {
        #expect(SentSummary.counts(PreviewData.sent) == .init(batch: 9, projects: 4))
        #expect(SentSummary.counts(SentRecord()) == .init(batch: 0, projects: 0))
    }

    @Test func notCheckedIsShownNotCountedAsClean() {
        let c = PopoverContent(report: PreviewData.report(), isScanning: false, now: now)
        #expect(c.coverage.notCheckedCount == 8 && c.coverage.notInIndexCount == 10)
        #expect(c.coverage.notChecked.map(\.source) == ["Homebrew packages with no graded project", "Apps with no security record"])
    }

    @Test func oneNotificationForManyFindings() {
        let fresh = PreviewData.findings.filter(\.deservesNotification)
        #expect(fresh.map(\.title) == ["axios", "OpenSSH", "OpenMTP", "nginx", "ImageMagick"])
        let (title, body) = SystemNotifier.text(for: fresh)
        #expect(title == "5 new findings, starting with axios")
        #expect(body == "1.14.1 · ~/code/storefront/package-lock.json\nAlso: OpenSSH, OpenMTP, nginx …")
        #expect(SystemNotifier.text(for: [fresh[1]]).title == "Exploited flaw: OpenSSH")
    }

    /// A finding that notifies only because a flaw the app did not check is exploited says that, not "patch these first".
    @Test func anUncheckedExploitedFlawNamesItsNotification() {
        let lodash = Finding(id: "x", group: .other, subject: .package(ecosystem: .npm, name: "lodash"), title: "lodash", installedVersion: "4.17.20",
                             upgrade: nil, severity: .low, advisoryIDs: [], flawCount: 1, exploited: false, malicious: false, note: nil, bigIssue: nil,
                             origins: [.npmGlobal(npm: "npm")], pageURL: PreviewData.findings[0].pageURL, advice: nil, verification: .none,
                             grade: nil, notChecked: Finding.NotChecked(id: "CVE-1", exploited: true, critical: false))
        #expect(lodash.deservesNotification && SystemNotifier.text(for: [lodash]).title == "Exploited flaw, not checked: lodash")
        var listed = lodash
        listed.notChecked = nil; listed.bigIssue = "On the site's list"
        #expect(SystemNotifier.text(for: [listed]).title == "On the “patch these first” list: lodash")
    }

    /// osva-render first reads the Java fixture on the main thread, and JavaCheck asks the core for upgrades, which must
    /// not run there: the fixture is built off it.
    @MainActor @Test func theJavaFixtureIsBuiltOffTheMainThread() {
        // made again here, from the main thread, whichever test read the fixture first
        #expect(Thread.isMainThread)
        #expect(PreviewData.makeJavaFindings().map(\.id) == PreviewData.javaFindings.map(\.id))
        #expect(PreviewData.javaFindings.contains { $0.id == PreviewData.JavaID.temurin })
    }

    @Test func aFixedFindingKeepsItsRowButIsNotCounted() {
        let nginx = PreviewData.findings.first { $0.id == PreviewData.FixID.nginx }!
        let rest = PreviewData.findings.filter { $0.id != nginx.id }
        let c = PopoverContent(report: PreviewData.report(findings: rest), isScanning: false, now: now, resolved: [nginx])
        let section = c.sections.first { $0.group == .criticalHigh }!
        #expect(section.findings.map(\.id).contains(nginx.id))
        #expect(section.count == section.findings.count - 1)
        #expect(section.findings.map(\.id) == section.findings.sorted(by: FindingBuilder.precedes).map(\.id))   // in its place
        #expect(c.heroCount == 8 && c.actionCount == 8)
        // once a scan finds it again, it is listed once
        let again = PopoverContent(report: PreviewData.report(), isScanning: false, now: now, resolved: [nginx])
        #expect(again.sections.flatMap(\.findings).filter { $0.id == nginx.id }.count == 1 && again.heroCount == 9)
    }

    /// A section whose rows were all fixed or removed keeps them until the next scan, with no "0" beside its heading.
    @Test func aSectionWithOnlyFixedRowsShowsNoZero() {
        let axios = PreviewData.findings.first { $0.id == PreviewData.FixID.axios }!
        let rest = PreviewData.findings.filter { $0.id != axios.id }
        let c = PopoverContent(report: PreviewData.report(findings: rest), isScanning: false, now: now, resolved: [axios])
        let malicious = c.sections.first { $0.group == .malicious }!
        #expect(malicious.findings.map(\.id) == [axios.id] && malicious.count == 0)
        #expect(GroupContainer<EmptyView>.countText(malicious.count) == nil && GroupContainer<EmptyView>.countText(3) == "3")
    }

    /// The results scene (it can end up on the website) shows only what the app does now: no Terminal outcomes, no run
    /// on a system component, one fix at a time.
    @Test func theResultsSceneFollowsTheRules() {
        let scene = PreviewData.fixScene("results")!
        let outcomes = scene.fixes.values.compactMap(\.outcome)
        #expect(!outcomes.contains { if case .failed = $0 { true } else { false } })
        #expect(!scene.fixes.values.contains { $0.progress == .running && $0.run == nil })            // "Running in Terminal…"
        #expect(scene.fixes.values.filter(\.isBusy).count == 1)
        #expect(!scene.shown.contains(PreviewData.FixID.nokogiri))                                     // Apple's Ruby: accept-system
        #expect(scene.fixes[PreviewData.FixID.openssh]?.run?.step == .running)
        #expect(outcomes.contains { if case .fixedCheck = $0 { true } else { false } })
    }

    @Test func everyFixtureCommandIsOneTheAppWouldRun() {
        // the render fixtures' commands are UpgradeCommand's own, and FixPlan offers them on a Mac with the tools
        for f in PreviewData.findings where f.upgradeCommand != nil {
            #expect(f.commandInputs.map { UpgradeCommand.advice($0).command } == f.upgradeCommand, "\(f.id)")
        }
        #expect(PreviewData.offer(PreviewData.FixID.nginx).plan.command == "brew upgrade nginx")
        #expect(PreviewData.offer(PreviewData.FixID.axios).plan.action == .removal)
    }

    @Test func notAnInstalledApp() {
        // `swift test` runs outside an app bundle: notifications and the login item must stay off, not crash.
        #expect(AppBundle.isInstalledApp == false)
        #expect(SystemNotifier().isAvailable == false)
        #expect(LoginItem.isEnabled == false)
    }
}

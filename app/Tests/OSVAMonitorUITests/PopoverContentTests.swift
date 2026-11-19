import Foundation
import Testing
import OSVAKit
import SwiftUI
@testable import OSVAMonitorUI

@Suite struct PopoverContentTests {
    let now = PreviewData.now

    @Test func groupsInTheirOrder() {
        let c = PopoverContent(report: PreviewData.report(), isScanning: false, now: now)
        #expect(c.sections.map(\.group) == [.malicious, .exploited, .criticalHigh, .other])
        #expect(c.actionCount == 9)                                   // everything but "Other"
    }

    @Test func theHeroSaysTheWorstThing() {
        let c = PopoverContent(report: PreviewData.report(), isScanning: false, now: now)
        #expect(c.hero == .malicious && c.hero.symbol == "xmark.shield.fill")
        #expect(c.heroCount == 9)
        #expect(c.sentence == "need action" && c.advice == "Remove the malicious package first.")
        #expect(c.headline == "9 need action")
        #expect(c.subline == "Scanned\u{00A0}4\u{00A0}minutes\u{00A0}ago · Homebrew, 15\u{00A0}Electron\u{00A0}apps, npm, pip, RubyGems, 2\u{00A0}folders")
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
        #expect(clean.subline.hasPrefix("4\u{00A0}lower-severity\u{00A0}findings · 8\u{00A0}not\u{00A0}checked · Scanned"))   // never "clean" without saying so
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
        #expect(c.sections.count == 4 && c.hero == .malicious)
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
        #expect(fresh.map(\.title) == ["axios", "OpenSSH", "OpenMTP", "nginx"])
        let (title, body) = SystemNotifier.text(for: fresh)
        #expect(title == "4 new findings, starting with axios")
        #expect(body == "1.14.1 · ~/code/storefront/package-lock.json\nAlso: OpenSSH, OpenMTP, nginx")
        #expect(SystemNotifier.text(for: [fresh[1]]).title == "Exploited flaw: OpenSSH")
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

import AppKit
import Foundation
import Testing
import OSVAKit
@testable import OSVAMonitorUI

/// Every status token clears its role's contrast in every appearance, against the modelled worst glass: #e9e9ee (and
/// white) under light tokens, #3a3a3c (and black) under dark ones. Glyphs and marks need 3:1, text 4.5:1 (WCAG 1.4.11,
/// 1.4.3), with no rounding. These are models: the real panel still has to be sampled (reports/, "What to measure").
@Suite struct ToneTests {
    static let lightGlass: [UInt32] = [0xFFFFFF, 0xE9E9EE]
    static let darkGlass: [UInt32] = [0x000000, 0x3A3A3C]

    static func luminance(_ hex: UInt32) -> Double {
        func channel(_ c: Double) -> Double { c <= 0.04045 ? c / 12.92 : pow((c + 0.055) / 1.055, 2.4) }
        let r = channel(Double((hex >> 16) & 0xFF) / 255), g = channel(Double((hex >> 8) & 0xFF) / 255), b = channel(Double(hex & 0xFF) / 255)
        return 0.2126 * r + 0.7152 * g + 0.0722 * b
    }

    static func contrast(_ a: UInt32, _ b: UInt32) -> Double {
        let (x, y) = (luminance(a), luminance(b))
        return (max(x, y) + 0.05) / (min(x, y) + 0.05)
    }

    /// The worst contrast of a tone's variant against the glass its appearance can put behind it.
    static func worst(_ tone: Tone, _ v: Tone.Variant) -> Double {
        let backgrounds = (v == .light || v == .lightIC) ? lightGlass : darkGlass
        return backgrounds.map { contrast(tone.hex(v), $0) }.min()!
    }

    static let glyphs: [(String, Tone)] = [
        ("critical glyph", Tokens.critical.glyph), ("high glyph", Tokens.high.glyph), ("moderate glyph", Tokens.moderate.glyph),
        ("low glyph", Tokens.low.glyph), ("malicious glyph", Tokens.Malicious.glyph), ("exploited glyph", Tokens.Exploited.glyph),
        ("clean", Tokens.clean), ("verified disc", Tokens.Verification.wholeDisc), ("verified parts", Tokens.Verification.partsStroke),
        ("not checked glyph", Tokens.NotChecked.glyph),
    ]
    static let texts: [(String, Tone)] = [
        ("critical text", Tokens.critical.text), ("high text", Tokens.high.text), ("moderate text", Tokens.moderate.text),
        ("low text", Tokens.low.text), ("malicious text", Tokens.Malicious.text), ("verified text", Tokens.Verification.text),
    ]

    @Test("glyphs and marks clear 3:1", arguments: glyphs.map(\.0))
    func glyph(_ name: String) {
        let tone = Self.glyphs.first { $0.0 == name }!.1
        for v in Tone.Variant.allCases { #expect(Self.worst(tone, v) >= 3, "\(name) \(v): \(Self.worst(tone, v))") }
    }

    @Test("text clears 4.5:1", arguments: texts.map(\.0))
    func text(_ name: String) {
        let tone = Self.texts.first { $0.0 == name }!.1
        for v in Tone.Variant.allCases { #expect(Self.worst(tone, v) >= 4.5, "\(name) \(v): \(Self.worst(tone, v))") }
    }

    @Test func lightRingsUseTheTextShade() {
        // The pale fills keep the site's hex; the ring is what clears contrast on light glass.
        for s in Severity.allCases {
            let ring = Tokens.severity(s).ring
            for v in [Tone.Variant.light, .lightIC] { #expect(Self.worst(ring, v) >= 4.5, "\(s) ring \(v)") }
            #expect(ring.alpha[.dark] == 0 && ring.alpha[.darkIC] == 0)          // no ring on the dark panel
        }
    }

    @Test func gradeTilesKeepTheirFillsAndGainARingOnDark() {
        for (grade, t) in Tokens.grades {
            #expect(Self.contrast(0xFFFFFF, t.fill) >= 4.5, "white on \(grade)")
            let ring = Tone.darkOnly(t.darkRing, darkIC: t.darkICRing)
            for v in [Tone.Variant.dark, .darkIC] { #expect(Self.worst(ring, v) >= 3, "\(grade) ring \(v)") }
        }
    }

    /// One sRGB colour after laying `tone` (at its alpha in `v`) over `under`.
    static func over(_ under: UInt32, _ tone: Tone, _ v: Tone.Variant) -> UInt32 {
        let a = tone.alpha[v] ?? 1, top = tone.hex(v)
        func channel(_ shift: UInt32) -> UInt32 {
            let u = Double((under >> shift) & 0xFF), t = Double((top >> shift) & 0xFF)
            return UInt32(max(0, min(255, (u * (1 - a) + t * a).rounded()))) << shift
        }
        return channel(16) | channel(8) | channel(0)
    }

    /// The amber chip of a flaw not checked against published ranges has the summary chips' form, on the site link's
    /// surface: on a row's container over any glass the panel models, from white (black) to the owner's mid-grey (138),
    /// its shield clears 3:1 and its label, the system's primary text (black or white at 85%), 4.5:1. Its amber is the
    /// moderate severity's, with no hex of its own.
    @Test func theNotCheckedChipReadsOnAnyGlass() {
        for v in Tone.Variant.allCases {
            let dark = v == .dark || v == .darkIC
            for level in dark ? SurfaceTests.darkGlass : SurfaceTests.lightGlass {
                let g = UInt32(level), glass = g << 16 | g << 8 | g
                let chip = Self.over(Self.over(Self.over(glass, Surface.card, v), Surface.control, v), Tokens.NotChecked.tint, v)
                let shield = Self.contrast(Tokens.NotChecked.mark.hex(v), chip)
                #expect(shield >= 3, "not checked shield \(v) on \(level): \(shield)")
                let label = Self.contrast(Self.over(chip, Tone(0x000000, dark: 0xFFFFFF, alpha: 0.85), v), chip)
                #expect(label >= 4.5, "not checked label \(v) on \(level): \(label)")
            }
        }
        #expect(Tokens.NotChecked.glyph == Tokens.moderate.glyph && Tokens.NotChecked.mark == Tokens.moderate.text)
        #expect(Tokens.NotChecked.tint.hex(.light) == Tokens.moderate.fill.hex(.light) && Tokens.NotChecked.tint.alpha[.light] == 0.15)
    }

    @Test func theExploitedChipIsTheOnlySolidRedAndItsLabelReads() {
        for v in Tone.Variant.allCases { #expect(Self.contrast(0xFFFFFF, Tokens.Exploited.chip.hex(v)) >= 4.5) }
    }

    @Test func darkModeSwapsTheVerifiedDiscSoTheFilledMarkStaysLoudest() {
        #expect(Tokens.Verification.wholeDisc.hex(.dark) == 0x86B6EF && Tokens.Verification.wholeCheck.hex(.dark) == 0x0D366B)
        #expect(Self.contrast(Tokens.Verification.wholeCheck.hex(.dark), Tokens.Verification.wholeDisc.hex(.dark)) >= 4.5)
        #expect(Tokens.Verification.partsInterior.alpha[.dark] == 0)                 // the dashed mark is hollow on dark
    }

    @Test func appearancesResolveToTheirVariant() {
        let light = NSAppearance(named: .aqua)!, dark = NSAppearance(named: .darkAqua)!
        #expect(Tone.variant(for: light, increaseContrast: false) == .light)
        #expect(Tone.variant(for: dark, increaseContrast: false) == .dark)
        #expect(Tone.variant(for: light, increaseContrast: true) == .lightIC)       // Increase Contrast on
        #expect(Tone.variant(for: dark, increaseContrast: true) == .darkIC)
    }
}

/// The source guard: colour lives in Theme.swift and in the shared components only, the panel has no glass of its
/// own, and no control carries a tint (so every control follows the person's accent colour).
@Suite struct StyleGuardTests {
    static let app = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()

    static func sources(_ target: String) -> [(String, String)] {
        let dir = app.appendingPathComponent("Sources/\(target)")
        let files = (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []
        return files.filter { $0.hasSuffix(".swift") }.sorted().map { ($0, try! String(contentsOf: dir.appendingPathComponent($0), encoding: .utf8)) }
    }

    @Test func noGlassAndNoTintInTheApp() {
        let banned = [".glassEffect", "glassSurface", "GlassEffectContainer", "glassEffectID", ".tint(", "buttonStyle(.glass",
                      "Material", "Palette"]
        let files = Self.sources("OSVAMonitorUI") + Self.sources("OSVAMonitor")
        #expect(files.count >= 10)
        for (file, text) in files {
            for b in banned { #expect(!text.contains(b), "\(file) uses \(b)") }
        }
    }

    @Test func hexColoursLiveOnlyInTheme() throws {
        let hex = try Regex(#"0x[0-9A-Fa-f]{6}\b|Color\(hex:|#[0-9A-Fa-f]{6}\b"#)
        for (file, text) in Self.sources("OSVAMonitorUI") + Self.sources("OSVAMonitor") where file != "Theme.swift" {
            #expect(text.firstMatch(of: hex) == nil, "\(file) has a colour of its own")
        }
    }

    /// Lists of names are NameRows, one name per line, never one paragraph of names joined by commas.
    @Test func namesAreListedOnePerLine() throws {
        let joined = try Regex(#"items[^\n]*\.joined\(separator: ", "\)"#)
        for (file, text) in Self.sources("OSVAMonitorUI") {
            #expect(text.firstMatch(of: joined) == nil, "\(file) joins a list of names into one line")
        }
        let lists = Self.sources("OSVAMonitorUI").filter { $0.1.contains("ForEach(") && $0.1.contains("items") && $0.1.contains("NameRow(") }.map(\.0)
        #expect(Set(lists).isSuperset(of: ["Components.swift", "NameListView.swift"]))
    }

    @Test func eachSharedThingIsDefinedOnce() {
        let all = (Self.sources("OSVAMonitorUI") + Self.sources("OSVAMonitor")).map(\.1).joined(separator: "\n")
        for component in ["SeverityMark", "StatusChip", "GradeTile", "VerificationMark", "GroupContainer", "FindingRow", "CommandBlock",
                          "FixButton", "FixConfirmation", "FixStatusLine", "FixRunCard", "FixProblemCard", "FixLogView", "FixStepLine",
                          "FixElapsed", "SiteLink", "RowHover", "ProvenanceView", "FactRow", "NameListView", "NameRow",
                          "ListDisclosureRow", "QuietCoverageSection", "AppIcon", "PanelCard", "WhatsNewCard", "ChangelogLines",
                          "WhatsNewSection", "FixAllCard", "FixAllReview", "FixAllBatchLine", "FixAllSkipLine", "FixAllProgress",
                          "FixAllSummary", "FixNotice", "FixDisclosure", "ConsentView", "FixAllProposalLine", "FixAllNeedLine",
                          "TerminalButton", "NeedActionBreakdown"] {
            let definitions = all.components(separatedBy: "struct \(component)").count - 1
            #expect(definitions == 1, "\(component) is defined \(definitions) times")
        }
    }

    /// The amber mark of a flaw not checked against published ranges is one component, StatusChip's `.notChecked`, which
    /// only rows show, from Finding.notCheckedChip. Its amber is reached only through Tokens.NotChecked, by that chip,
    /// its section's heading and the hero; no view takes the moderate amber for itself, writes the chip's words, or
    /// decides the red chip from `exploited` alone.
    @Test func theNotCheckedMarkIsOneComponent() {
        let allowed = ["Components.swift": 3, "PopoverView.swift": 1]
        for (file, text) in Self.sources("OSVAMonitorUI") + Self.sources("OSVAMonitor") where file != "Theme.swift" {
            let code = text.split(separator: "\n").filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("//") }.joined(separator: "\n")
            let amber = code.components(separatedBy: "Tokens.NotChecked").count - 1
            #expect(amber == allowed[file, default: 0], "\(file) uses the not-checked amber \(amber) times")
            #expect(!code.contains("Tokens.moderate"), "\(file) takes the moderate amber for itself")
            #expect(!code.contains("StatusChip(.notChecked"), "\(file) builds its own not-checked chip")
            let words = code.components(separatedBy: "\"Exploited, not checked\"").count - 1
            #expect(words == (file == "Components.swift" ? 1 : 0), "\(file) writes the chip's words")
            let red = code.components(separatedBy: "StatusChip(.exploited)").count - 1
            #expect(red == (file == "FindingRow.swift" ? 1 : 0), "\(file) draws the exploited chip")
        }
        let row = Self.sources("OSVAMonitorUI").first { $0.0 == "FindingRow.swift" }!.1
        #expect(row.contains("if finding.checkedExploited { StatusChip(.exploited) }") && !row.contains("finding.exploited"))
        #expect(row.contains("finding.notCheckedChip.map(StatusChip.init)"))
        // the chip lies on the site link's surface, which theNotCheckedChipReadsOnAnyGlass models under its tint
        let components = Self.sources("OSVAMonitorUI").first { $0.0 == "Components.swift" }!.1
        #expect(components.contains("Capsule().fill(Surface.control.color)\n                Capsule().fill(Tokens.NotChecked.tint.color)"))
    }

    /// Run in Terminal is one button (TerminalButton) wherever it appears: a row whose cask needs a password, a run that
    /// asked for one, Fix all's summary. The header's breakdown is one view (NeedActionBreakdown), and a proposal's
    /// tick is drawn only by FixAllProposalLine, with the review's own symbols.
    @Test func sharedControlsAreDrawnByTheirComponents() {
        for (file, text) in Self.sources("OSVAMonitorUI") + Self.sources("OSVAMonitor") {
            let code = text.split(separator: "\n").filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("//") }.joined(separator: "\n")
            let terminal = code.components(separatedBy: "Text(\"Run in Terminal\")").count - 1
            #expect(terminal == (file == "FixViews.swift" ? 1 : 0), "\(file) draws its own Run in Terminal")
            let breakdown = code.components(separatedBy: "fixAll.breakdown").count - 1
            #expect(breakdown == (file == "PopoverView.swift" ? 1 : 0), "\(file) draws the breakdown itself")
            #expect(!code.contains("toggleStyle(") && !code.contains(" Toggle(") || file == "SettingsView.swift" || file == "ConsentView.swift",
                    "\(file) has a toggle of its own")
        }
        let views = Self.sources("OSVAMonitorUI").first { $0.0 == "FixAllViews.swift" }!.1
        #expect(views.contains("struct FixAllProposalLine") && views.components(separatedBy: "checkmark.circle.fill\" : \"circle\"").count - 1 == 1)
    }

    /// A container on the panel is a PanelCard: the groups, the quiet lists, a waiting update, What's New, Fix all, the
    /// first-launch card. Nothing else draws `Surface.card` or the panel's concentric corners, so no container can be
    /// restyled on its own.
    @Test func containersArePanelCards() {
        for (file, text) in Self.sources("OSVAMonitorUI") + Self.sources("OSVAMonitor") where file != "Theme.swift" {
            let code = text.split(separator: "\n").filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("///") }.joined(separator: "\n")
            let cards = code.components(separatedBy: "Surface.card").count - 1
            let corners = code.components(separatedBy: "ConcentricRectangle(").count - 1
            let allowed = file == "Components.swift" ? 1 : 0                     // PanelCard's own
            #expect(cards == allowed && corners == allowed, "\(file) draws a container of its own (\(cards) Surface.card, \(corners) ConcentricRectangle)")
        }
        let users = Self.sources("OSVAMonitorUI").filter { $0.1.contains(".panelCard(") }.map(\.0)
        #expect(Set(users).isSuperset(of: ["Components.swift", "PopoverView.swift", "Updates.swift", "WhatsNewViews.swift", "FixAllViews.swift",
                                           "ConsentView.swift"]),
                "\(users)")
    }

    /// Hover and links have one implementation each: a row's hover is RowHover (Surface.hover, never a lightening
    /// `.quaternary`), a link is SiteLink (never system-blue text on the glass), and no surface is a system fill that
    /// lightens under dark mode's light text.
    @Test func hoverAndLinksGoThroughTheirComponents() {
        for (file, text) in Self.sources("OSVAMonitorUI") + Self.sources("OSVAMonitor") {
            #expect(!text.contains(".buttonStyle(.link)") && text.firstMatch(of: /Text\([^\n]*\)[^\n]*\.foregroundStyle\(\.tint\)/) == nil
                    && text.firstMatch(of: /Text\([^\n]*\)[^\n]*\.foregroundStyle\(Color\.accentColor\)/) == nil,
                    "\(file) draws link-coloured text on the glass")
            #expect(!text.contains(".fill(.quaternary)") && !text.contains(".fill(.quinary)") && !text.contains("(.quaternary, in:")
                    && !text.contains("(.quinary, in:"), "\(file) uses a system fill that lightens in dark mode")
            let hovers = text.components(separatedBy: ".onHover").count - 1
            let allowed = file == "Components.swift" ? 2 : 0                     // RowHover and SiteLink
            #expect(hovers == allowed, "\(file) has \(hovers) hover handlers of its own")
        }
    }
}

/// The surfaces go the way that raises text contrast, so a hover never lowers it, and the site link clears 4.5:1 on
/// any glass, modelled: light glass from white down to mid-grey under light-mode text, dark glass from black up to the
/// mid-grey measured behind the owner's panel (138) under dark-mode text. Text is the system label colours: black at
/// 85% (secondary 50%) on light, white at 85% (secondary 55%) on dark.
@Suite struct SurfaceTests {
    static let lightGlass: [Double] = [255, 236, 200, 160, 138]
    static let darkGlass: [Double] = [0, 30, 58, 100, 138]

    /// One sRGB grey level, after laying `tone` (at its alpha) over `under`.
    static func over(_ under: Double, _ tone: Tone, _ v: Tone.Variant) -> Double {
        let a = tone.alpha[v] ?? 1, c = Double(tone.hex(v) & 0xFF)
        return under * (1 - a) + c * a
    }

    static func text(on bg: Double, dark: Bool, secondary: Bool = false) -> Double {
        let a = dark ? (secondary ? 0.55 : 0.85) : (secondary ? 0.50 : 0.85)
        return bg * (1 - a) + (dark ? 255 : 0) * a
    }

    static func contrast(_ a: Double, _ b: Double) -> Double {
        let hex = { (g: Double) -> UInt32 in let v = UInt32(max(0, min(255, g.rounded()))); return v << 16 | v << 8 | v }
        return ToneTests.contrast(hex(a), hex(b))
    }

    @Test func hoverNeverLowersContrast() {
        for v in Tone.Variant.allCases {
            let dark = v == .dark || v == .darkIC
            for glass in dark ? Self.darkGlass : Self.lightGlass {
                let card = Self.over(glass, Surface.card, v), hovered = Self.over(card, Surface.hover, v)
                for secondary in [false, true] {
                    let before = Self.contrast(Self.text(on: card, dark: dark, secondary: secondary), card)
                    let after = Self.contrast(Self.text(on: hovered, dark: dark, secondary: secondary), hovered)
                    #expect(after >= before, "\(v) glass \(glass): \(before) → \(after)")
                }
                // and the card itself never lowers it against the bare glass
                #expect(Self.contrast(Self.text(on: card, dark: dark), card) >= Self.contrast(Self.text(on: glass, dark: dark), glass))
            }
        }
    }

    @Test func theSiteLinkReadsOnAnyGlass() {
        for v in Tone.Variant.allCases {
            let dark = v == .dark || v == .darkIC
            for glass in dark ? Self.darkGlass : Self.lightGlass {
                for under in [glass, Self.over(glass, Surface.card, v)] {               // on the panel, or on a container
                    let bg = Self.over(under, Surface.control, v)
                    #expect(Self.contrast(Self.text(on: bg, dark: dark), bg) >= 4.5, "\(v) glass \(glass)")
                }
            }
        }
    }

    @Test func primaryTextOnACardClearsMidGrey() {
        // the owner's case: dark text colours on mid-grey glass; the card alone brings primary text to 4.5:1
        let card = Self.over(138, Surface.card, .dark)
        #expect(Self.contrast(Self.text(on: card, dark: true), card) >= 4.5)
        #expect(Self.contrast(Self.text(on: 138, dark: true), 138) < 4.5)          // which the bare glass did not
    }
}

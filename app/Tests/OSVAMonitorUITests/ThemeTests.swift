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

    @Test func eachSharedThingIsDefinedOnce() {
        let all = (Self.sources("OSVAMonitorUI") + Self.sources("OSVAMonitor")).map(\.1).joined(separator: "\n")
        for component in ["SeverityMark", "StatusChip", "GradeTile", "VerificationMark", "GroupContainer", "FindingRow", "CommandBlock"] {
            let definitions = all.components(separatedBy: "struct \(component)").count - 1
            #expect(definitions == 1, "\(component) is defined \(definitions) times")
        }
    }
}

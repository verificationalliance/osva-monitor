import AppKit
import OSVAKit
import SwiftUI

// Every colour the app draws itself is here, and only here (a test fails if a hex appears in any other UI file).
//
// The panel is one sheet of system Liquid Glass (the MenuBarExtra window); everything inside it is content. Surfaces,
// text and controls are the system's: `.primary`/`.secondary`/`.tertiary` text, `.quinary`/`.quaternary` fills, and
// untinted controls that follow the person's accent colour. The site's colours (site/formalinformer/app.css) appear
// only on status elements: severity marks, the exploited chip, the not-checked chip, the malicious section, grade
// tiles, verification marks, the hero shield and a fixed row's check. Blue is for proof only, clay red for danger only.
//
// Each status colour has a value per role (fill, ring, glyph, text) and per appearance (light, dark, and their
// Increase Contrast variants), from "OSVA Monitor colour palette" (reports/). Glyph values clear 3:1 and text values
// 4.5:1 against the modelled worst glass (#e9e9ee light, #3a3a3c dark); ToneTests checks every one.

/// One colour in the four appearances the system resolves: light, dark, and each with Increase Contrast.
public struct Tone: Sendable, Equatable {
    public enum Variant: CaseIterable, Sendable { case light, dark, lightIC, darkIC }

    public var light: UInt32, dark: UInt32, lightIC: UInt32, darkIC: UInt32
    public var alpha: [Variant: Double]

    /// `nil` Increase Contrast values repeat the plain ones.
    init(_ light: UInt32, dark: UInt32, lightIC: UInt32? = nil, darkIC: UInt32? = nil,
         alpha: Double = 1, darkAlpha: Double? = nil, icAlpha: Double? = nil, darkICAlpha: Double? = nil) {
        self.light = light; self.dark = dark; self.lightIC = lightIC ?? light; self.darkIC = darkIC ?? dark
        self.alpha = [.light: alpha, .dark: darkAlpha ?? alpha, .lightIC: icAlpha ?? alpha, .darkIC: darkICAlpha ?? icAlpha ?? darkAlpha ?? alpha]
    }

    /// Present in light mode only (a ring the dark panel does not need).
    static func lightOnly(_ light: UInt32, lightIC: UInt32? = nil) -> Tone {
        Tone(light, dark: 0, lightIC: lightIC, darkIC: 0, darkAlpha: 0, icAlpha: 1, darkICAlpha: 0)
    }

    /// Present in dark mode only.
    static func darkOnly(_ dark: UInt32, darkIC: UInt32? = nil) -> Tone {
        Tone(0, dark: dark, lightIC: 0, darkIC: darkIC, alpha: 0, darkAlpha: 1, icAlpha: 0, darkICAlpha: 1)
    }

    public func hex(_ v: Variant) -> UInt32 {
        switch v { case .light: return light; case .dark: return dark; case .lightIC: return lightIC; case .darkIC: return darkIC }
    }

    /// The same tone at other opacities (the summary chips' 15% light, 25% dark).
    func opacity(light: Double, dark: Double) -> Tone {
        Tone(self.light, dark: self.dark, lightIC: lightIC, darkIC: darkIC, alpha: light, darkAlpha: dark, icAlpha: light, darkICAlpha: dark)
    }

    /// Which variant an appearance asks for. Increase Contrast shows in the appearance's name when AppKit draws with
    /// it; the system setting is read too, for appearances that do not carry it.
    public static func variant(for appearance: NSAppearance,
                               increaseContrast: Bool = NSWorkspace.shared.accessibilityDisplayShouldIncreaseContrast) -> Variant {
        switch appearance.bestMatch(from: [.aqua, .darkAqua, .accessibilityHighContrastAqua, .accessibilityHighContrastDarkAqua]) {
        case NSAppearance.Name.accessibilityHighContrastAqua?: return .lightIC
        case NSAppearance.Name.accessibilityHighContrastDarkAqua?: return .darkIC
        case NSAppearance.Name.darkAqua?: return increaseContrast ? .darkIC : .dark
        default: return increaseContrast ? .lightIC : .light
        }
    }

    public func nsColor(_ v: Variant) -> NSColor { srgb(hex(v), alpha: alpha[v] ?? 1) }

    /// Resolves per view, as the system resolves its own colours: light/dark and Increase Contrast, in the panel, in
    /// Settings, and in anything the system flips.
    public var color: Color {
        let tone = self
        return Color(nsColor: NSColor(name: nil) { appearance in tone.nsColor(Tone.variant(for: appearance)) })
    }
}

private func srgb(_ hex: UInt32, alpha: Double = 1) -> NSColor {
    NSColor(srgbRed: CGFloat((hex >> 16) & 0xFF) / 255, green: CGFloat((hex >> 8) & 0xFF) / 255, blue: CGFloat(hex & 0xFF) / 255, alpha: alpha)
}

/// A colour that is a site hex in light mode and a system label colour in dark mode (the hollow U tile).
private func lightHexElse(_ hex: UInt32, dark: NSColor) -> Color {
    Color(nsColor: NSColor(name: nil) { appearance in
        switch Tone.variant(for: appearance) { case .light, .lightIC: return srgb(hex); case .dark, .darkIC: return dark }
    })
}

/// The status tokens.
public enum Tokens {
    /// A severity's four roles: the 8 pt mark's fill and its light-mode ring, the glyph shade, the text shade.
    public struct SeverityTones: Sendable {
        public var fill: Tone, ring: Tone, glyph: Tone, text: Tone
    }

    public static let critical = SeverityTones(
        fill: Tone(0xD03B3B, dark: 0xE7524E, lightIC: 0x990015, darkIC: 0xFFA8A0),
        ring: .lightOnly(0xC53032, lightIC: 0x990015),
        glyph: Tone(0xD03B3B, dark: 0xE7524E, lightIC: 0x990015, darkIC: 0xFFA8A0),
        text: Tone(0xC53032, dark: 0xFFA8A0, lightIC: 0x990015, darkIC: 0xFFCDC7))
    public static let high = SeverityTones(
        fill: Tone(0xEC835A, dark: 0xEC835A, lightIC: 0xEC835A, darkIC: 0xFFAA89),
        ring: .lightOnly(0xAE4B21, lightIC: 0x8B3000),
        glyph: Tone(0xD06941, dark: 0xEC835A, lightIC: 0x8B3000, darkIC: 0xFFAA89),
        text: Tone(0xAE4B21, dark: 0xFFAA89, lightIC: 0x8B3000, darkIC: 0xFFCEBB))
    public static let moderate = SeverityTones(
        fill: Tone(0xFAB219, dark: 0xFAB219, lightIC: 0xFAB219, darkIC: 0xFFD187),
        ring: .lightOnly(0x8C6100, lightIC: 0x6B4900),
        glyph: Tone(0xB27C00, dark: 0xFAB219, lightIC: 0x6B4900, darkIC: 0xFFD187),
        text: Tone(0x8C6100, dark: 0xFAB219, lightIC: 0x6B4900, darkIC: 0xFFD187))
    public static let low = SeverityTones(
        fill: Tone(0xB9B7AE, dark: 0xB9B7AE, lightIC: 0xB9B7AE, darkIC: 0xDBD9CF),
        ring: .lightOnly(0x6B6961, lightIC: 0x525049),
        glyph: Tone(0x88867E, dark: 0xB9B7AE, lightIC: 0x525049, darkIC: 0xDBD9CF),
        text: Tone(0x6B6961, dark: 0xC2C0B6, lightIC: 0x525049, darkIC: 0xDBD9CF))

    public static func severity(_ s: Severity) -> SeverityTones {
        switch s { case .critical: return critical; case .high: return high; case .moderate: return moderate; case .low: return low }
    }

    /// Malicious: the site's clay (--clay, `.pkg.mal`). The section wash is the panel's only tinted container.
    public enum Malicious {
        public static let wash = Tone(0xA94524, dark: 0xA94524, alpha: 0.10, darkAlpha: 0.18)
        public static let hairline = Tone(0xA94524, dark: 0xCE6541, lightIC: 0x8D2C00, darkIC: 0xFFCEBD, alpha: 0.35, icAlpha: 1)
        public static let glyph = Tone(0xA94524, dark: 0xCE6541, lightIC: 0x8D2C00, darkIC: 0xFFCEBD)
        public static let text = Tone(0xA94524, dark: 0xFFAA8E, lightIC: 0x8D2C00, darkIC: 0xFFCEBD)
    }

    /// Exploited in the wild: the site's `.chip-kev`, the panel's only solid red.
    public enum Exploited {
        public static let chip = Tone(0xA12828, dark: 0xA12828, lightIC: 0x990015, darkIC: 0xA12828)
        public static let chipRing = Tone.darkOnly(0xE7524E, darkIC: 0xFFA8A0)
        public static let glyph = Tone(0xA12828, dark: 0xE7524E, lightIC: 0x990015, darkIC: 0xFFA8A0)
        /// The section heading's flame, on its plate (GlyphPlate): the glyph in light, critical's text shades in dark,
        /// which keep 3:1 on the plate over grey glass where the glyph's red does not.
        public static let mark = Tone(0xA12828, dark: 0xFFA8A0, lightIC: 0x990015, darkIC: 0xFFCDC7)
    }

    /// Not checked against published ranges: the moderate amber, with no hex of its own. It marks an exploited or
    /// critical flaw the core could not check (the chip, StatusChip's `.notChecked`), the section those findings are
    /// listed in, and the hero when they are all that is urgent. Never the exploited chip's solid red, which says the
    /// core checked the flaw.
    public enum NotChecked {
        /// Every not-checked mark: the chip's shield, the section heading's and the hero's (on their plates). The
        /// darker shade in light, which clears 3:1 on the tint and on the plates over grey glass: one amber, one mark.
        public static let mark = Tokens.moderate.text
        /// The chip's capsule: the summary chips' faint tint of the status colour (15% light, 25% dark).
        public static let tint = Tokens.moderate.fill.opacity(light: 0.15, dark: 0.25)
    }

    /// Nothing needs action: the site's grade-A green, on the hero shield and on the check of a row its fix resolved.
    public static let clean = Tone(0x1D5E3C, dark: 0x8CCDA5, lightIC: 0x195A39, darkIC: 0xA6E7BE)

    /// Verification blue (--v4, --v1). Dark mode swaps disc and check so the filled mark stays the loudest.
    public enum Verification {
        public static let wholeDisc = Tone(0x0D366B, dark: 0x86B6EF, lightIC: 0x0D366B, darkIC: 0xC1DBFF)
        public static let wholeRing = Tone.lightOnly(0xFFFFFF)
        public static let wholeCheck = Tone(0xFFFFFF, dark: 0x0D366B, lightIC: 0xFFFFFF, darkIC: 0x0D366B)
        public static let partsStroke = Tone(0x0D366B, dark: 0x86B6EF, lightIC: 0x0D366B, darkIC: 0xC1DBFF)
        public static let partsInterior = Tone.lightOnly(0xFFFFFF)
        public static let text = Tone(0x0D366B, dark: 0x96C2FF, lightIC: 0x0D366B, darkIC: 0xC1DBFF)
    }

    /// Trust grades (.g-a … .g-f): the site's fills in both modes, white letters, and a hue-matched ring on dark.
    public struct GradeTones: Sendable { public var fill: UInt32; public var darkRing: UInt32; public var darkICRing: UInt32 }

    public static let grades: [String: GradeTones] = [
        "A": GradeTones(fill: 0x1D5E3C, darkRing: 0x51906B, darkICRing: 0x8CCDA5),
        "B": GradeTones(fill: 0x2F7A50, darkRing: 0x489266, darkICRing: 0x84CFA0),
        "C": GradeTones(fill: 0x6B6A65, darkRing: 0x85847E, darkICRing: 0xC0BFBA),
        "D": GradeTones(fill: 0xB04A26, darkRing: 0xCE6541, darkICRing: 0xFFAA8E),
        "F": GradeTones(fill: 0x7E2A19, darkRing: 0xC56A56, darkICRing: 0xFFA995),
    ]

    static func gradeFill(_ g: GradeTones) -> Color { Tone(g.fill, dark: g.fill).color }
    static func gradeRing(_ g: GradeTones) -> Color { Tone.darkOnly(g.darkRing, darkIC: g.darkICRing).color }

    /// U, not enough evidence: hollow and light, so the grey C is never read as missing data.
    enum UngradedTile {
        static let fill = Tone.lightOnly(0xE3E1D9).color
        static let ring = lightHexElse(0xC9C6BB, dark: .tertiaryLabelColor)
        static let letter = lightHexElse(0x141413, dark: .secondaryLabelColor)
    }
}

/// The panel's own surfaces. Each is a wash that goes the way that raises text contrast in its appearance: white under
/// light mode's dark text, black under dark mode's light text. So a container, a hovered row or a well can only make
/// its text easier to read, on any glass: the system's `.quinary`/`.quaternary` fills lighten in dark mode, which on
/// grey glass over a bright wallpaper (white text at 3:1 on the owner's Mac) made a hovered row nearly unreadable.
/// SurfaceTests model each against light, dark and mid-grey glass.
public enum Surface {
    /// A group's container.
    public static let card = Tone(0xFFFFFF, dark: 0x000000, alpha: 0.32, darkAlpha: 0.28, icAlpha: 0.55, darkICAlpha: 0.40)
    /// A row under the pointer, over its container: a little more of the same.
    public static let hover = Tone(0xFFFFFF, dark: 0x000000, alpha: 0.45, darkAlpha: 0.16, icAlpha: 0.55, darkICAlpha: 0.22)
    /// A command or a log, and the fix's review: set into the row.
    public static let well = Tone(0xFFFFFF, dark: 0x000000, alpha: 0.62, darkAlpha: 0.24, icAlpha: 0.80, darkICAlpha: 0.36)
    /// A small control drawn on whatever glass is there (the site link), and the not-checked chip under its tint: its
    /// label clears 4.5:1 even on mid-grey glass.
    public static let control = Tone(0xFFFFFF, dark: 0x000000, alpha: 0.62, darkAlpha: 0.40, icAlpha: 0.80, darkICAlpha: 0.52)
    /// The hairline round a container, well or control.
    public static let edge = Tone(0x000000, dark: 0xFFFFFF, alpha: 0.09, darkAlpha: 0.11, icAlpha: 0.30, darkICAlpha: 0.32)
}

/// The quiet lines that lie on the panel's bare glass, the hero's and the coverage lines under the groups: the system's
/// `.secondary` and `.tertiary` measured 2.31-2.63:1 and 1.49-2.27:1 there over a mid-grey desktop. Black in light mode and white in dark, at the opacity
/// that clears the contrast each needs from white (black) glass to mid-grey (128) in both appearances; ToneTests
/// checks every one.
public enum Ink {
    /// The subline ("2 lower-severity findings · Scanned 4 minutes ago · …"), the breakdown under the count, a scan's
    /// problem, and the quiet coverage lines ("10 not in the index"): 3:1 or more on the bare glass.
    public static let subline = Tone(0x000000, dark: 0xFFFFFF, alpha: 0.66, darkAlpha: 0.80, icAlpha: 0.80, darkICAlpha: 0.90)
    /// The caveat ("Not proof of safety: it is what has been reported."), on its `Surface.control` plate (HeroCaveat):
    /// 4.5:1 or more there. No text colour reaches 4.5:1 on mid-grey dark glass alone (white on rgb 128 is 3.95:1).
    public static let caveat = Tone(0x000000, dark: 0xFFFFFF, alpha: 0.72, darkAlpha: 0.78, icAlpha: 0.85, darkICAlpha: 0.90)
}

/// Type, one place. Counts use SF Pro Rounded with tabular digits.
public enum Typeface {
    public static let heroCount = Font.system(size: 26, weight: .bold, design: .rounded).monospacedDigit()
    public static let heroSentence = Font.system(size: 13, weight: .semibold)
    public static let heroSubline = Font.system(size: 11)
    public static let groupTitle = Font.system(size: 12, weight: .semibold)
    public static let title = Font.system(size: 13, weight: .semibold)
    public static let body = Font.system(size: 12.5)
    public static let small = Font.system(size: 11.5)
    public static let caption = Font.system(size: 11)
    public static let chip = Font.system(size: 11, weight: .medium)
    /// A row's status chip, exploited or not checked: the two are one size, so either sits in the other's place.
    public static let statusChip = Font.system(size: 10, weight: .bold)
    public static let version = Font.system(size: 12, weight: .medium, design: .monospaced)
    public static let code = Font.system(size: 11, design: .monospaced)
    /// A fix's live log: small enough for a useful line, monospaced like the command.
    public static let log = Font.system(size: 10.5, design: .monospaced)
    /// A name as sent, one per line in a list window ("PyPI setuptools 58.0.4 · Python 3.9.6").
    public static let listCode = Font.system(size: 12, design: .monospaced)
    public static func count(_ size: CGFloat, weight: Font.Weight = .semibold) -> Font { .system(size: size, weight: weight, design: .rounded).monospacedDigit() }
}

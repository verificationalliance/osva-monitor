import OSVAKit
import SwiftUI

/// What the popover can ask the app to do.
public struct PopoverActions {
    public var scanNow: () -> Void
    public var openSettings: () -> Void
    public var quit: () -> Void
    public var open: (URL) -> Void
    public var copy: (String) -> Void
    public var fix: FixActions
    /// A check for a new version of the app, the person's own (Sparkle's window shows what it finds).
    public var checkForUpdates: () -> Void
    /// Opens a long list of names (the apps nothing checks) in its own window.
    public var openList: (NameList) -> Void
    /// What's New's Close: the card is not shown again for this version.
    public var closeWhatsNew: () -> Void

    public init(scanNow: @escaping () -> Void, openSettings: @escaping () -> Void, quit: @escaping () -> Void,
                open: @escaping (URL) -> Void, copy: @escaping (String) -> Void, fix: FixActions = .none,
                checkForUpdates: @escaping () -> Void = {}, openList: @escaping (NameList) -> Void = { _ in },
                closeWhatsNew: @escaping () -> Void = {}) {
        self.scanNow = scanNow; self.openSettings = openSettings; self.quit = quit; self.open = open; self.copy = copy; self.fix = fix
        self.checkForUpdates = checkForUpdates; self.openList = openList; self.closeWhatsNew = closeWhatsNew
    }

    public static var none: PopoverActions { PopoverActions(scanNow: {}, openSettings: {}, quit: {}, open: { _ in }, copy: { _ in }) }
}

/// The menu-bar panel. The panel's own window is the one sheet of Liquid Glass; everything here is content on it:
/// after an update, what is new in it (until closed); the hero (one shield, one number, one sentence); the findings in
/// one container per group; and the controls, which are left untinted so they follow the person's accent colour.
public struct PopoverView: View {
    public static let width: CGFloat = 400
    public static let maxListHeight: CGFloat = 480

    public var content: PopoverContent
    public var actions: PopoverActions
    /// Each finding's fix: its button, its confirmation, how its last run went.
    public var fixes: [String: FixRowState]
    public var updates: UpdateState
    /// This version's changelog entry, shown once after an update until it is closed.
    public var whatsNew: Changelog.Entry?
    public var maxListHeight: CGFloat
    /// False draws the list without a scroll view (for ImageRenderer, which does not draw scroll views' content).
    public var scrolls: Bool
    @State private var expanded: Set<String>
    @State private var listHeight: CGFloat = 0
    @State private var gearFrame: CGRect = .zero

    /// Lists opened from the start (`coverageOpen`: bucket titles, and "notInIndex" or "updatedElsewhere" for the quiet
    /// sections), for renders.
    let coverageOpen: Set<String>

    public init(content: PopoverContent, actions: PopoverActions, fixes: [String: FixRowState] = [:], updates: UpdateState = .none,
                whatsNew: Changelog.Entry? = nil, expanded: Set<String> = [], maxListHeight: CGFloat = PopoverView.maxListHeight,
                scrolls: Bool = true, coverageOpen: Set<String> = []) {
        self.content = content; self.actions = actions; self.fixes = fixes; self.updates = updates; self.whatsNew = whatsNew
        self.maxListHeight = maxListHeight
        self.scrolls = scrolls; self.coverageOpen = coverageOpen
        _expanded = State(initialValue: expanded)
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let whatsNew {
                WhatsNewCard(entry: whatsNew, close: actions.closeWhatsNew)
            }
            HeroView(content: content).padding(.leading, 4)
            if content.isScanning {
                ProgressView().progressViewStyle(.linear).padding(.horizontal, 4)
            }
            if !content.sections.isEmpty || content.coverage.notCheckedCount + content.coverage.notInIndexCount + content.coverage.updatedElsewhereCount > 0 {
                if scrolls {
                    ScrollView(.vertical) {
                        groups.background(GeometryReader { g in Color.clear.preference(key: HeightKey.self, value: g.size.height) })
                    }
                    .scrollIndicators(.automatic)
                    .frame(height: min(max(listHeight, 1), maxListHeight))
                    .onPreferenceChange(HeightKey.self) { listHeight = $0 }
                } else {
                    groups
                }
            }
            if let version = updates.waitingVersion {
                UpdateWaitingRow(version: version, install: actions.checkForUpdates)
            }
            footer
        }
        .padding(14)
        .frame(width: Self.width)
        .animation(.smooth(duration: 0.3), value: expanded)
        .animation(.smooth(duration: 0.3), value: content.isScanning)
        .animation(.smooth(duration: 0.25), value: fixes)
        .animation(.smooth(duration: 0.25), value: whatsNew)
    }

    private var groups: some View {
        VStack(alignment: .leading, spacing: 14) {
            ForEach(content.sections) { section in
                GroupContainer(section.group, count: section.count) {
                    ForEach(Array(section.findings.enumerated()), id: \.element.id) { i, f in
                        if i > 0 { Divider().padding(.leading, 12) }
                        FindingRow(finding: f, expanded: expanded.contains(f.id), actions: actions, fix: fixes[f.id] ?? FixRowState()) {
                            if expanded.contains(f.id) { expanded.remove(f.id) } else { expanded.insert(f.id) }
                        }
                    }
                }
            }
            coverage
        }
    }

    /// What could not be vouched for: what nothing classifies, what something else keeps up to date, then what was
    /// never reported. None of it is "clean".
    @ViewBuilder private var coverage: some View {
        let c = content.coverage
        if c.notCheckedCount > 0 {
            GroupContainer(.notChecked, count: c.notCheckedCount) {
                ForEach(Array(c.notChecked.enumerated()), id: \.element.id) { i, bucket in
                    if i > 0 { Divider().padding(.leading, 12) }
                    ListDisclosureRow(CoverageLists.list(bucket, in: .notChecked), open: coverageOpen.contains(bucket.id), openList: actions.openList)
                }
            }
        }
        if c.updatedElsewhereCount > 0 {
            QuietCoverageSection(symbol: "arrow.triangle.2.circlepath", title: "\(c.updatedElsewhereCount.formatted()) kept up to date elsewhere",
                                 caption: CoverageLists.keepersCaption(c.updatedElsewhere),
                                 lists: c.updatedElsewhere.map { CoverageLists.list($0, in: .updatedElsewhere) },
                                 open: coverageOpen.contains("updatedElsewhere"), rowsOpen: coverageOpen, openList: actions.openList)
        }
        if c.notInIndexCount > 0 {
            QuietCoverageSection(symbol: "checkmark.circle", title: "\(c.notInIndexCount.formatted()) not in the index",
                                 caption: "No known problems — not proof of safety",
                                 lists: c.notInIndex.map { CoverageLists.list($0, in: .notInIndex) },
                                 open: coverageOpen.contains("notInIndex"), rowsOpen: coverageOpen, openList: actions.openList)
        }
    }

    /// Scan Now is the one prominent control and takes the accent colour; Settings and Quit are quiet symbols. In the
    /// installed app the gear opens a short menu: Settings, and Check for Updates.
    private var footer: some View {
        HStack(spacing: 4) {
            Button(action: actions.scanNow) {
                Label(content.isScanning ? "Scanning…" : "Scan Now", systemImage: "arrow.clockwise")
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(content.isScanning)
            Spacer()
            quiet("gearshape", updates.isAvailable ? "Settings and updates" : "Settings…") {
                if updates.isAvailable {
                    AppMenu.show(below: gearFrame, updates: updates, openSettings: actions.openSettings, checkForUpdates: actions.checkForUpdates)
                } else {
                    actions.openSettings()
                }
            }
            .background(GeometryReader { g in Color.clear.onAppear { gearFrame = g.frame(in: .global) }
                .onChange(of: g.frame(in: .global)) { _, f in gearFrame = f } })
            quiet("power", "Quit OSVA Monitor", action: actions.quit)
        }
    }

    private func quiet(_ symbol: String, _ help: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: symbol).font(.system(size: 15)).frame(width: 30, height: 28).contentShape(Rectangle())
        }
        .buttonStyle(.borderless)
        .symbolRenderingMode(.hierarchical)
        .foregroundStyle(.secondary)
        .help(help)
        .accessibilityLabel(help)
    }
}

/// A quiet line under the groups, with lists behind it: "1,186 not in the index — No known problems, not proof of
/// safety", "37 kept up to date elsewhere — By the App Store, macOS or their browser; not checked here". It opens to
/// its lists, one row each.
struct QuietCoverageSection: View {
    let symbol: String
    let title: String
    let caption: String
    let lists: [NameList]
    let openList: (NameList) -> Void
    /// Lists opened from the start, by title (for renders).
    let rowsOpen: Set<String>
    @State private var open: Bool

    init(symbol: String, title: String, caption: String, lists: [NameList], open: Bool = false, rowsOpen: Set<String> = [],
         openList: @escaping (NameList) -> Void) {
        self.symbol = symbol; self.title = title; self.caption = caption; self.lists = lists; self.openList = openList
        self.rowsOpen = rowsOpen
        _open = State(initialValue: open)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Image(systemName: symbol).foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 1) {
                    Text(title).foregroundStyle(.secondary)
                    Text(caption).font(Typeface.caption).foregroundStyle(.secondary)
                }
                .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 4)
                Image(systemName: "chevron.down").font(.system(size: 10, weight: .semibold)).foregroundStyle(.secondary)
                    .rotationEffect(.degrees(open ? 180 : 0))
            }
            .font(Typeface.small)
            .padding(.horizontal, 4).padding(.vertical, 3)
            .rowHover()
            .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
            .contentShape(Rectangle())
            .onTapGesture { withAnimation(.smooth(duration: 0.25)) { open.toggle() } }
            .accessibilityElement(children: .combine)
            .accessibilityAddTraits(.isButton)
            if open {
                VStack(spacing: 0) {
                    ForEach(Array(lists.enumerated()), id: \.element.id) { i, list in
                        if i > 0 { Divider().padding(.leading, 12) }
                        ListDisclosureRow(list, open: rowsOpen.contains(list.id), openList: openList)
                    }
                }
                .panelCard()
            }
        }
    }
}

struct HeroView: View {
    let content: PopoverContent

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            shield
                .contentTransition(.symbolEffect(.replace))
                .symbolEffect(.breathe, isActive: content.isScanning)
                .symbolEffect(.bounce, value: content.heroCount ?? 0)
                .frame(width: 36, height: 38)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    if let n = content.heroCount {
                        Text("\(n)").font(Typeface.heroCount).foregroundStyle(.primary)
                            .contentTransition(.numericText(value: Double(n)))
                    }
                    Text(content.sentence).font(Typeface.heroSentence).foregroundStyle(.primary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .frame(minHeight: 32, alignment: .bottomLeading)              // the sentence alone sits level with the shield
                if let advice = content.advice {
                    Text(advice).font(Typeface.body).foregroundStyle(.primary).fixedSize(horizontal: false, vertical: true)
                }
                if !content.tallies.isEmpty {
                    WrapAtSpaces(spacing: 4, lineSpacing: 4) {
                        ForEach(content.tallies) { t in StatusChip(.count(t.tally, t.count)) }
                    }
                    .padding(.vertical, 2)
                }
                if !content.subline.isEmpty {
                    Text(content.subline).font(Typeface.heroSubline).foregroundStyle(.secondary)
                        .contentTransition(.numericText())
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let p = content.problem {
                    Label(p, systemImage: "exclamationmark.triangle")
                        .font(Typeface.heroSubline).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if content.hero == .clean {
                    Text("Not proof of safety: it is what has been reported.").font(Typeface.heroSubline).foregroundStyle(.tertiary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .accessibilityElement(children: .combine)
    }

    /// A status shield is two solid colours: a white mark on the status colour, with the system gradient, so it reads
    /// crisply on any glass. Neutral states (not scanned, first scan, scanning) stay a quiet hierarchical outline.
    @ViewBuilder private var shield: some View {
        let image = Image(systemName: content.hero.symbol).font(.system(size: 32))
        if let fill = statusFill, !content.isScanning {
            image.symbolRenderingMode(.palette).symbolColorRenderingMode(.gradient).foregroundStyle(.white, fill)
        } else {
            image.symbolRenderingMode(.hierarchical).foregroundStyle(glyphStyle)
        }
    }

    private var statusFill: Color? {
        switch content.hero {
        case .malicious: return Tokens.Malicious.glyph.color
        case .critical: return Tokens.critical.glyph.color
        case .high: return Tokens.high.glyph.color
        case .clean: return Tokens.clean.color
        case .notScanned, .firstScan: return nil
        }
    }

    private var glyphStyle: AnyShapeStyle {
        if content.isScanning { return AnyShapeStyle(.secondary) }
        switch content.hero {
        case .notScanned: return AnyShapeStyle(.tertiary)
        case .firstScan: return AnyShapeStyle(.secondary)
        case .malicious: return AnyShapeStyle(Tokens.Malicious.glyph.color)
        case .critical: return AnyShapeStyle(Tokens.critical.glyph.color)
        case .high: return AnyShapeStyle(Tokens.high.glyph.color)
        case .clean: return AnyShapeStyle(Tokens.clean.color)
        }
    }
}

private struct HeightKey: PreferenceKey {
    static let defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = max(value, nextValue()) }
}

import SwiftUI

/// The panel before the person agreed (Consent): one PanelCard, at the panel's width, instead of the findings. What
/// the app reads, what leaves the Mac, the three switches, what a fix does, and Start or Quit. Settings shows the same
/// card until then.
public struct ConsentView: View {
    @Binding public var choices: ConsentChoices
    public var start: () -> Void
    public var quit: () -> Void

    public init(choices: Binding<ConsentChoices>, start: @escaping () -> Void, quit: @escaping () -> Void) {
        _choices = choices; self.start = start; self.quit = quit
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Before OSVA Monitor starts").font(Typeface.title).foregroundStyle(.primary).accessibilityAddTraits(.isHeader)
            VStack(alignment: .leading, spacing: 6) {
                FixNotice(symbol: "magnifyingglass", text: "Reads what is installed: Homebrew, apps, every Python and the packages in them, on this Mac.")
                FixNotice(symbol: "paperplane", text: "Sends only names and versions that match the public index, to verificationalliance.org. Nothing else.")
            }
            VStack(alignment: .leading, spacing: 8) {
                choice("Check for updates daily", $choices.checkForUpdates)
                choice("Notify me about malware and exploited flaws", $choices.notify)
                choice("Open at login", $choices.openAtLogin)
            }
            FixNotice(symbol: "hand.raised", text: "Fixes always show what they change and wait for your OK.")
            HStack(spacing: 8) {
                Spacer(minLength: 0)
                Button("Quit", action: quit)
                    .buttonStyle(.bordered)
                    .buttonBorderShape(.capsule)
                    .help("Quits without changing anything. The next launch asks again.")
                Button(action: start) { Text("Start").fontWeight(.semibold) }
                    .buttonStyle(.borderedProminent)
                    .buttonBorderShape(.capsule)
                    .keyboardShortcut(.defaultAction)
            }
            .controlSize(.regular)
        }
        .padding(.horizontal, 12).padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .panelCard()
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Before OSVA Monitor starts")
        .padding(14)
        .frame(width: PopoverView.width)
    }

    /// One switch: its line at the left, the switch at the right edge, in line with the buttons.
    private func choice(_ title: String, _ isOn: Binding<Bool>) -> some View {
        Toggle(isOn: isOn) {
            Text(title).foregroundStyle(.primary).frame(maxWidth: .infinity, alignment: .leading)
        }
        .toggleStyle(.switch)
        .controlSize(.mini)
        .font(Typeface.small)
    }
}

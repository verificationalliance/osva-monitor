import Foundation

/// What to do about an app, a library an app bundles, or an extension (UpgradeCommand's answer for those origins).
/// No command here downloads an installer: an app updates itself, or Homebrew updates the cask that installed it.
enum BundleAdvice {
    /// `component` names the bundled thing the finding is about ("Sparkle", "lodash"); nil for the app's own version.
    static func advice(for origin: Origin, component: String?, malicious: Bool) -> UpgradeCommand.Advice {
        switch origin {
        case let .application(name, _, cask):
            if let cask {
                return .init(command: "brew upgrade --cask \(UpgradeCommand.quote(cask))",
                             note: component.map { "\(name) ships its own \($0): upgrading the app updates it." })
            }
            return .init(command: nil, note: "Update \(name) from its own menu or its website" + (component.map { ": it ships its own \($0)." } ?? "."))
        case let .addOn(host, id, name, profile, _):
            if malicious {
                if let cli = host.cli { return .init(command: "\(cli) --uninstall-extension \(UpgradeCommand.quote(id))") }
                let page = host.extensionsPage ?? "the browser's extensions page"
                let inProfile = profile.map { ", in the profile “\($0)”" } ?? ""
                return .init(command: nil, note: "Remove it in \(host.title): open \(page)\(inProfile), find \(name), and click Remove.")
            }
            return .init(command: nil, note: "Update \(name) in \(host.title)" + (component.map { ": it ships its own \($0)." } ?? "."))
        default:
            return .init(command: nil)
        }
    }
}

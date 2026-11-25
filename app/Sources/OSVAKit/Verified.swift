// The door to the verified core is its own module, OSVAVerified (Sources/OSVAVerified/Core.swift alone). OSVAKit uses
// it, and passes it on to everything that uses OSVAKit, so the app sees `Core`, `CheckedUpgrade` and the rest as before.
@_exported import OSVAVerified

/// How the app shows a checked version: the version itself, rewritten only as its style (`CheckedUpgrade.Display`)
/// says. The styles are the core module's, and carry no text; the rewriting is the app's.
extension CheckedUpgrade {
    public var display: String {
        switch style {
        case .asChecked: return version
        case .java: return JavaVersion.shown(version)
        case .program: return FindingBuilder.Component.shown(version)
        }
    }
}

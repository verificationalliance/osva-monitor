// swift-tools-version: 6.2
//
// OSVA Monitor: a macOS menu-bar app that watches the software on this Mac and shows what the Open Source
// Verification Alliance (https://verificationalliance.org/) knows about it: malicious packages, exploited and
// critical vulnerabilities, fixed versions, trust grades and formal verification.
//
// Targets
//   OSVACore       C. The verified core: version order, affectedness, the privacy filter, URL encoding.
//   OSVAKit        What the app knows how to do: take inventory (Homebrew, Electron apps, global packages, project
//                  folders), download the public index, ask the API, and turn answers into findings. It calls the
//                  core only through Sources/OSVAKit/Core.swift, but not every decision of the four kinds above is
//                  the core's: packages checked by exact version are flagged, and their upgrades chosen, by the
//                  server. Core.swift says which decisions are which.
//   OSVAMonitorUI  SwiftUI views and the app model, and the app's changelog (Resources/CHANGELOG.md, What's New).
//   OSVAMonitor    The menu-bar app (assembled into "OSVA Monitor.app" by ../scripts/build-app.sh).
//   osva-scan      One scan from the command line, with the same code the app runs.
//   osva-render    Renders the popover and the settings window off-screen to PNG, from fixture data.
//   OSVARelease    The update feed (appcast) and its signatures, for ../scripts/release.sh; osva-appcast runs it.
import Foundation
import PackageDescription

// ── The verified core ──────────────────────────────────────────────────────────────────────────────────────────
//
// OSVACore is the C interface to the Lean core in ../core: its header, Sources/OSVACore/include/osva_core.h, is a copy
// of ../core/include/osva_core.h (a test fails if the two differ), and its one source, Sources/OSVACore/osva_shim.c,
// is a link to ../core/ffi/osva_shim.c, the only unproved code between the app and the theorems. It links:
//   - the core itself, ../core/.lake/build/lib/libosvaCore_OSVACore.a, made by `lake build OSVACore:static` in ../core
//     (../scripts/build-app.sh does this first);
//   - the Lean runtime and libraries of the toolchain ../core/lean-toolchain names, found in elan's toolchains
//     directory ($ELAN_HOME, else ~/.elan), or in $OSVA_LEAN_TOOLCHAIN when that is set.
// The link line is the one ../scripts/check-core.sh uses on macOS.

let coreDirectory = Context.packageDirectory + "/../core"

/// The Lean toolchain's directory: "leanprover/lean4:v4.36.0" is ~/.elan/toolchains/leanprover--lean4---v4.36.0.
let leanToolchain: String = {
    if let explicit = Context.environment["OSVA_LEAN_TOOLCHAIN"], !explicit.isEmpty { return explicit }
    let name = ((try? String(contentsOfFile: coreDirectory + "/lean-toolchain", encoding: .utf8)) ?? "")
        .trimmingCharacters(in: .whitespacesAndNewlines)
        .replacingOccurrences(of: ":", with: "---").replacingOccurrences(of: "/", with: "--")
    let elan = Context.environment["ELAN_HOME"] ?? ((Context.environment["HOME"] ?? "~") + "/.elan")
    return elan + "/toolchains/" + name
}()

let verifiedCore: Target = .target(
    name: "OSVACore",
    path: "Sources/OSVACore",
    sources: ["osva_shim.c"],
    publicHeadersPath: "include",
    cSettings: [.unsafeFlags(["-isystem", leanToolchain + "/include"])],     // Lean's header is not ours to warn about
    linkerSettings: [.unsafeFlags([
        "-L", coreDirectory + "/.lake/build/lib", "-losvaCore_OSVACore",
        "-L", leanToolchain + "/lib/lean", "-lStd", "-lInit", "-lleanrt", "-lcadical",
        "-L", leanToolchain + "/lib", "-lc++", "-lgmp", "-luv",
    ])]
)

// ── Updates ────────────────────────────────────────────────────────────────────────────────────────────────────
//
// Sparkle 2 updates the app (Sources/OSVAMonitor/Updater.swift). It is pinned to one exact release, not a range: it
// installs code on people's Macs, so a new version is taken on purpose, after reading its changes, never by a resolve.
// 2.10.1 (25 October 2026) is the latest stable release; 2.11 is still a beta. The app relies on two older features,
// signed feeds (2.9) and checking the zip before unpacking it (2.7.3); see Resources/Info.plist. SwiftPM checks the
// binary against the checksum in Sparkle's own manifest at that tag, and Package.resolved pins the tag's commit. Only
// the app links Sparkle; OSVAKit, the views and their tests do not. ../scripts/build-app.sh embeds and signs it.

let package = Package(
    name: "OSVAMonitor",
    platforms: [.macOS(.v26)],          // Liquid Glass (SwiftUI glassEffect, GlassEffectContainer, glass button styles)
    products: [
        .executable(name: "OSVAMonitor", targets: ["OSVAMonitor"]),
        .executable(name: "osva-scan", targets: ["osva-scan"]),
        .executable(name: "osva-render", targets: ["osva-render"]),
        .executable(name: "osva-appcast", targets: ["osva-appcast"]),
        .library(name: "OSVAKit", targets: ["OSVAKit"]),
    ],
    dependencies: [
        .package(url: "https://github.com/sparkle-project/Sparkle", exact: "2.10.1"),
    ],
    targets: [
        verifiedCore,
        .target(name: "OSVAKit", dependencies: ["OSVACore"]),
        .target(name: "OSVAMonitorUI", dependencies: ["OSVAKit"], resources: [.copy("Resources/CHANGELOG.md")]),
        .executableTarget(name: "OSVAMonitor", dependencies: ["OSVAKit", "OSVAMonitorUI", .product(name: "Sparkle", package: "Sparkle")]),
        .executableTarget(name: "osva-scan", dependencies: ["OSVAKit"]),
        .executableTarget(name: "osva-render", dependencies: ["OSVAKit", "OSVAMonitorUI"]),
        .target(name: "OSVARelease"),
        .executableTarget(name: "osva-appcast", dependencies: ["OSVARelease"]),
        .testTarget(name: "OSVAKitTests", dependencies: ["OSVAKit", "OSVACore"], resources: [.copy("Fixtures")]),
        .testTarget(name: "OSVAMonitorUITests", dependencies: ["OSVAKit", "OSVAMonitorUI"]),
        .testTarget(name: "OSVAReleaseTests", dependencies: ["OSVARelease"], resources: [.copy("Fixtures")]),
    ]
)

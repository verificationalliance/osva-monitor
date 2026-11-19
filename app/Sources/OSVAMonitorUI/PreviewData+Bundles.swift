import Foundation
import OSVAKit

/// Fixture data for apps, the libraries they bundle, and extensions: a Mac with a malicious editor extension, a
/// malicious browser extension, an app with its own flaw and an old Sparkle, apps with old OpenSSL and Python inside,
/// and an extension that bundles a vulnerable package. Versions and fixes are as the scanner reads them on a real Mac.
extension PreviewData {
    public static let bundleFindings: [Finding] = {
        let home = NSHomeDirectory()
        let likely = { (v: String) in "Likely affected: the issuer names \(v) as fixed." }
        let prettier = Origin.addOn(host: .vscode, id: "esbenp-dev.prettier-vscode", name: "Prettier – Code formatter", profile: nil,
                                    path: home + "/.vscode/extensions/esbenp-dev.prettier-vscode-11.0.3")
        let booster = { (profile: String) in
            Origin.addOn(host: .chrome, id: "kdnfmlogbcgjhdmbpniklnbgopmcfecg", name: "Volume Booster Pro", profile: profile,
                         path: home + "/Library/Application Support/Google/Chrome/\(profile)/Extensions/kdnfmlogbcgjhdmbpniklnbgopmcfecg/2.4.1_0")
        }
        let gitlens = Origin.addOn(host: .vscode, id: "eamodio.gitlens", name: "GitLens", profile: nil, path: home + "/.vscode/extensions/eamodio.gitlens-17.2.1")
        let zoom = Origin.application(name: "zoom.us", bundlePath: "/Applications/zoom.us.app", caskToken: "zoom")
        let vlc = Origin.application(name: "VLC", bundlePath: "/Applications/VLC.app", caskToken: nil)
        let gopro = Origin.application(name: "GoPro Quik", bundlePath: "/Applications/GoPro Quik.app", caskToken: nil)
        let nowPlaying = Origin.application(name: "SpotifyNowPlaying", bundlePath: "/Applications/SpotifyNowPlaying.app", caskToken: nil)
        return [
            finding("ext|vscode|esbenp-dev.prettier-vscode|vscode", .malicious, .addOn(store: "vscode", id: "esbenp-dev.prettier-vscode"),
                    "Prettier – Code formatter", "11.0.3", nil, nil, flaws: 0, malicious: true,
                    note: "Flagged by the Visual Studio Marketplace: malware, sends SSH keys and tokens to a remote host. Remove it, then rotate every secret it could read.",
                    origins: [prettier], page: URL(string: "https://github.com/microsoft/vsmarketplace/blob/main/RemovedPackages.md")!),
            finding("ext|chrome|kdnfmlogbcgjhdmbpniklnbgopmcfecg|chrome", .malicious, .addOn(store: "chrome", id: "kdnfmlogbcgjhdmbpniklnbgopmcfecg"),
                    "Volume Booster Pro", "2.4.1", nil, nil, flaws: 0, malicious: true,
                    note: "Flagged by the Chrome Web Store: removed for malware. Remove it in Chrome: open chrome://extensions, in each of the profiles "
                        + "“Work”, “Personal”, find Volume Booster Pro, and click Remove. Its ID is kdnfmlogbcgjhdmbpniklnbgopmcfecg. "
                        + "Then rotate every secret it could read.",
                    origins: [booster("Work"), booster("Personal")], page: SiteURL.home),
            finding("prod|/Applications/zoom.us.app|zoom|6.5.1", .exploited, .product(key: "zoom", name: "Zoom Workplace"), "zoom.us",
                    "6.5.1", "6.6.12", .critical, flaws: 2, exploited: true, note: likely("6.6.12"), origins: [zoom],
                    page: URL(string: "https://www.zoom.com/en/trust/security-bulletin/")!),
            finding("comp|/Applications/VLC.app|sparkle|1.16.0", .criticalHigh, .product(key: "sparkle", name: "Sparkle"), "VLC", component: "Sparkle",
                    "1.16.0", "2.7.3", .critical, flaws: 2,
                    note: likely("2.7.3") + " Update VLC from its own menu or its website: it ships its own Sparkle.", origins: [vlc],
                    page: URL(string: "https://github.com/sparkle-project/Sparkle/security/advisories")!),
            finding("prod|/Applications/VLC.app|vlc|3.0.20", .criticalHigh, .product(key: "vlc", name: "VLC media player"), "VLC",
                    "3.0.20", "3.0.21", .high, flaws: 1, note: likely("3.0.21") + " Update VLC from its own menu or its website.", origins: [vlc],
                    page: URL(string: "https://www.videolan.org/security/")!),
            finding("comp|/Applications/GoPro Quik.app|openssl|1.0.1q", .criticalHigh, .product(key: "openssl", name: "OpenSSL"), "GoPro Quik",
                    component: "OpenSSL", "1.0.1q", "3.0.18", .high, flaws: 3,
                    note: likely("3.0.18") + " Update GoPro Quik from its own menu or its website: it ships its own OpenSSL.", origins: [gopro],
                    page: URL(string: "https://openssl-library.org/news/vulnerabilities/")!),
            finding("comp|/Applications/SpotifyNowPlaying.app|cpython|3.11.15", .criticalHigh,
                    .project(slug: "cpython", name: "CPython", installedAs: "Python.framework"), "SpotifyNowPlaying", component: "Python",
                    "3.11.15", "3.14.11", .high, flaws: 1,
                    note: likely("3.14.11") + " Update SpotifyNowPlaying from its own menu or its website: it ships its own Python.",
                    origins: [nowPlaying], page: SiteURL.projectPage(slug: "cpython")),
            finding("ext|\(home)/.vscode/extensions/eamodio.gitlens-17.2.1|lodash|4.17.20", .criticalHigh, .package(ecosystem: .npm, name: "lodash"),
                    "GitLens", component: "lodash", "4.17.20", "4.17.21", .high, flaws: 4, note: "Update GitLens in VS Code: it ships its own lodash.",
                    origins: [gitlens], page: SiteURL.packagePage(.npm, "lodash", version: "4.17.20")),
        ]
    }()

    /// The findings opened in the render: the editor extension (its command), the browser one (where to remove it),
    /// and a bundled library (why updating the app is the fix).
    public static let bundlesOpen: Set<String> = ["ext|vscode|esbenp-dev.prettier-vscode|vscode", "ext|chrome|kdnfmlogbcgjhdmbpniklnbgopmcfecg|chrome",
                                                  "comp|/Applications/VLC.app|sparkle|1.16.0"]

    public static let bundleReports: [SourceReport] = [
        SourceReport(kind: .homebrew, available: true, count: 408, detail: "338 formulae, 70 casks"),
        SourceReport(kind: .electron, available: true, count: 15, detail: "15 apps"),
        SourceReport(kind: .apps, available: true, count: 140, detail: "140 apps"),
        SourceReport(kind: .extensions, available: true, count: 23, detail: "23 extensions in VS Code, Cursor, Chrome"),
        SourceReport(kind: .npm, available: true, count: 1, detail: "1 global package"),
        SourceReport(kind: .pip, available: true, count: 495, detail: "495 packages in 8 Pythons"),
        SourceReport(kind: .gem, available: true, count: 48, detail: "48 gems"),
        SourceReport(kind: .folders, available: true, count: 212, detail: "2 folders, 5 lockfiles"),
    ]

    public static let bundleCoverage = Coverage(
        notInIndex: [.init(source: "pip", items: ["annotated-types 0.8.0", "altgraph 0.17.2", "macholib 1.15.2"]),
                     .init(source: "Extensions", items: ["@gitkraken/provider-apis 0.29.7", "md5.js 1.3.5", "sortablejs 1.15.6"])],
        notChecked: [.init(source: "Homebrew packages with no graded project", items: ["abseil 20260817.0", "ack 3.10.0", "aom 3.15.3"]),
                     .init(source: "Apps with no product record", items: ["Ableton Live 12 Standard", "Alfred 5", "Amphetamine", "BusyCal", "Keka"]),
                     .init(source: "Bundled libraries with no readable version", items: ["libxml2 in Airflow", "SQLite in Airflow"])])

    public static let bundleSent = SentRecord(requests: [
        SentRequest(endpoint: "POST api/v1/check/batch", items: ["npm electron 37.10.3 · macOS", "npm lodash 4.17.20 · macOS", "PyPI pip 21.2.4 · Python 3.9.6 · macOS"]),
        SentRequest(endpoint: "GET api/v1/project", items: ["project cpython", "project openssh"]),
        SentRequest(endpoint: "GET api/v1/product", items: ["product openssl", "product sparkle", "product vlc", "product zoom"]),
    ], withheldCount: 732, answeredFromCache: 0)

    public static func bundlesReport(findings: [Finding] = bundleFindings) -> ScanReport {
        ScanReport(startedAt: now.addingTimeInterval(-300), finishedAt: now.addingTimeInterval(-240),
                   inventory: Inventory(reports: bundleReports), findings: findings, sent: bundleSent,
                   indexGeneratedAt: "2026-11-19T07:03:57Z", problems: [], coverage: bundleCoverage)
    }
}

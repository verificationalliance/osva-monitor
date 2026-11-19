import Foundation
import OSVAKit

/// Fixture data for what a scan could not vouch for, as on a Mac with 141 apps that no check covers: the apps nobody
/// is known to look after, those the App Store keeps up to date, and the web apps Chrome and Edge installed. Well-known
/// public apps, so the render shows real icons where the rendering Mac has them.
extension PreviewData {
    public static let appsWithNoRecord = [
        "Ableton Live 12 Standard", "Adobe Acrobat Reader", "Adobe Illustrator 2026", "Adobe Lightroom", "Adobe Photoshop 2026",
        "Affinity Designer 2", "Affinity Photo 2", "Alfred 5", "AltTab", "Arc", "Audacity", "Audio Hijack", "Backblaze", "Bartender 5",
        "BBEdit", "Blender", "Brave Browser", "BusyCal", "Caffeine", "Calibre", "Carbon Copy Cloner", "ChatGPT", "CleanShot X", "CotEditor",
        "Cyberduck", "DaVinci Resolve", "DBeaver", "Default Folder X", "DeepL", "Docker", "Elgato Stream Deck", "Firefox", "Fission",
        "Fork", "ForkLift", "Garmin Express", "GIMP", "Google Chrome", "Google Drive", "GoPro Quik", "GPG Keychain", "HandBrake", "Hazel",
        "Ice", "IINA", "Inkscape", "Insta360 Studio", "iStat Menus", "iTerm", "JetBrains Toolbox", "Jump Desktop", "Kaleidoscope",
        "Karabiner-Elements", "Keka", "KeePassXC", "Keyboard Maestro", "KnockKnock", "LibreOffice", "Little Snitch", "Logi Options+",
        "Loopback", "LuLu", "Maccy", "Malwarebytes", "MarsEdit", "Microsoft Edge", "Microsoft Excel", "Microsoft Outlook",
        "Microsoft PowerPoint", "Microsoft Word", "Mimestream", "Minecraft", "Moom", "MuseScore 4", "NetNewsWire", "Nova", "OBS",
        "OmniFocus 4", "OnyX", "Parallels Desktop", "PDF Expert", "Postico 2", "Proxyman", "qBittorrent", "Raspberry Pi Imager", "Raycast",
        "RealVNC Viewer", "Rectangle", "Sketch", "Soulver 3", "Spotify", "Steam", "SteerMouse", "Sublime Text", "SuperDuper!", "Tailscale",
        "TeamViewer", "Telegram", "Thunderbird", "Tor Browser", "Transmit 5", "UTM", "VLC", "zoom.us",
    ]

    public static let appsFromTheAppStore = [
        "Amphetamine", "Bear", "Darkroom", "Day One", "Final Cut Pro", "GarageBand", "Hand Mirror", "iMovie", "Infuse 7", "Keynote", "Kindle",
        "Logic Pro", "Magnet", "Numbers", "Pages", "Paprika Recipe Manager 3", "Pixelmator Pro", "Things 3", "Tot", "Windows App", "WhatsApp",
        "WireGuard", "Xcode",
    ]

    public static let chromeWebApps = ["Excalidraw", "Gmail", "Google Calendar", "Google Keep", "Google Meet", "Photopea", "Squoosh", "Twitch",
                                       "YouTube", "YouTube Music", "Linear"].sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }
    public static let edgeWebApps = ["Microsoft Teams", "Microsoft To Do", "Outlook"]

    static func bucket(_ title: String, _ names: [String], folder: String) -> Coverage.Bucket {
        let sorted = names.sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }
        return Coverage.Bucket(source: title, items: sorted, paths: sorted.map { "\(folder)/\($0).app" })
    }

    public static let appCoverage: Coverage = {
        let home = NSHomeDirectory()
        return Coverage(
            notInIndex: [.init(source: "pip", items: ["annotated-types 0.8.0", "altgraph 0.17.2", "macholib 1.15.2", "mlx 0.32.4"]),
                         .init(source: "RubyGems", items: ["CFPropertyList 2.3.6", "did_you_mean 1.3.0", "minitest 5.11.3"])],
            notChecked: [.init(source: "Homebrew packages with no graded project", items: ["abseil 20260817.0", "ack 3.10.0", "aom 3.15.3"]),
                         bucket(AppCoverage.noRecord, appsWithNoRecord, folder: "/Applications"),
                         Coverage.Bucket(source: "Bundled libraries with no readable version", items: ["libxml2 in GIMP", "SQLite in Calibre"],
                                         paths: ["/Applications/GIMP.app", "/Applications/Calibre.app"])],
            updatedElsewhere: [bucket(AppCoverage.appStore, appsFromTheAppStore, folder: "/Applications"),
                               bucket(AppCoverage.webApps("Chrome"), chromeWebApps, folder: home + "/Applications/Chrome Apps.localized"),
                               bucket(AppCoverage.webApps("Edge"), edgeWebApps, folder: home + "/Applications/Edge Apps.localized")])
    }()

    /// Nothing that needs action, and everything a scan could not vouch for.
    public static func coverageReport() -> ScanReport {
        report(findings: findings.filter { $0.group == .other }, coverage: appCoverage)
    }
}

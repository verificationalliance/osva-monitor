import Foundation

/// The person's choices, kept in Application Support/OSVA Monitor/settings.json (shared with `osva-scan`).
public struct MonitorSettings: Codable, Sendable, Hashable {
    public var watchedFolders: [String] = []
    public var scanIntervalHours: Int = 6
    public var notificationsEnabled: Bool = true

    public static let intervalChoices = [1, 3, 6, 12, 24]

    public init(watchedFolders: [String] = [], scanIntervalHours: Int = 6, notificationsEnabled: Bool = true) {
        self.watchedFolders = watchedFolders; self.scanIntervalHours = scanIntervalHours; self.notificationsEnabled = notificationsEnabled
    }

    public init(from decoder: Decoder) throws {                  // tolerate files written by older versions
        let c = try decoder.container(keyedBy: CodingKeys.self)
        watchedFolders = try c.decodeIfPresent([String].self, forKey: .watchedFolders) ?? []
        scanIntervalHours = try c.decodeIfPresent(Int.self, forKey: .scanIntervalHours) ?? 6
        notificationsEnabled = try c.decodeIfPresent(Bool.self, forKey: .notificationsEnabled) ?? true
    }
}

/// Reads and writes the files in the support directory.
public struct Storage: Sendable {
    public let directory: URL
    public init(directory: URL) { self.directory = directory }

    public var cache: DiskCache { DiskCache(directory: directory.appendingPathComponent("cache", isDirectory: true)) }

    public func loadSettings() -> MonitorSettings { load(MonitorSettings.self, "settings.json") ?? MonitorSettings() }
    public func save(_ settings: MonitorSettings) { save(settings, "settings.json") }

    public func loadLastReport() -> ScanReport? { load(ScanReport.self, "last-scan.json") }
    public func save(_ report: ScanReport) { save(report, "last-scan.json") }

    /// Whether an earlier run left anything here, a scan or settings: what a first launch has not got, whichever
    /// version of the app wrote it and whether or not it still reads.
    public var hasSavedState: Bool {
        ["last-scan.json", "settings.json"].contains { FileManager.default.fileExists(atPath: directory.appendingPathComponent($0).path) }
    }

    private func load<T: Decodable>(_ type: T.Type, _ file: String) -> T? {
        guard let data = try? Data(contentsOf: directory.appendingPathComponent(file)) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(type, from: data)
    }

    private func save<T: Encodable>(_ value: T, _ file: String) {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        guard let data = try? encoder.encode(value) else { return }
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try? data.write(to: directory.appendingPathComponent(file), options: .atomic)
    }
}

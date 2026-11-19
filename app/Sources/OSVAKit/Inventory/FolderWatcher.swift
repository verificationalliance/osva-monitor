import CoreServices
import Foundation

/// Watches the chosen folders with FSEvents and reports which of them hold a lockfile that changed, so only those
/// are read again. Events are coalesced by FSEvents over `latency` seconds.
public final class FolderWatcher: @unchecked Sendable {   // all mutable state is touched only on `queue`
    public typealias Handler = @Sendable (_ changedRoots: Set<String>) -> Void

    /// The folders as given, and as FSEvents reports them (symbolic links resolved: /var is /private/var).
    private let roots: [(given: String, real: String)]
    private let handler: Handler
    private let latency: CFTimeInterval
    private let queue = DispatchQueue(label: "org.verificationalliance.osva-monitor.folder-watcher")
    private var stream: FSEventStreamRef?

    public init(roots: [String], latency: CFTimeInterval = 3, handler: @escaping Handler) {
        self.roots = roots.map { ($0, Paths.realPath(($0 as NSString).standardizingPath)) }
        self.latency = latency
        self.handler = handler
    }

    deinit { stop() }

    public func start() {
        queue.sync {
            guard stream == nil, !roots.isEmpty else { return }
            var context = FSEventStreamContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(), retain: nil, release: nil, copyDescription: nil)
            let paths = roots.map(\.real)
            let flags = UInt32(kFSEventStreamCreateFlagUseCFTypes | kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagNoDefer)
            guard let s = FSEventStreamCreate(nil, Self.callback, &context, paths as CFArray,
                                              FSEventStreamEventId(kFSEventStreamEventIdSinceNow), latency, flags) else { return }
            FSEventStreamSetDispatchQueue(s, queue)
            FSEventStreamStart(s)
            stream = s
        }
    }

    public func stop() {
        queue.sync {
            guard let s = stream else { return }
            FSEventStreamStop(s)
            FSEventStreamInvalidate(s)
            FSEventStreamRelease(s)
            stream = nil
        }
    }

    private static let callback: FSEventStreamCallback = { _, info, count, paths, flags, _ in
        guard let info else { return }
        let watcher = Unmanaged<FolderWatcher>.fromOpaque(info).takeUnretainedValue()
        let list = Unmanaged<CFArray>.fromOpaque(paths).takeUnretainedValue() as? [String] ?? []
        var changed = Set<String>()
        for i in 0..<min(count, list.count) {
            let path = list[i], flag = Int(flags[i])
            let mustRescan = flag & (kFSEventStreamEventFlagMustScanSubDirs | kFSEventStreamEventFlagRootChanged) != 0
            let newFolder = flag & kFSEventStreamEventFlagItemIsDir != 0 && flag & (kFSEventStreamEventFlagItemCreated | kFSEventStreamEventFlagItemRenamed) != 0
            guard mustRescan || newFolder || FolderSource.isLockfile((path as NSString).lastPathComponent),
                  let root = watcher.roots.first(where: { path == $0.real || path.hasPrefix($0.real + "/") }) else { continue }
            // `npm install` creates thousands of folders under node_modules: changes inside skipped folders never count.
            let inside = path.dropFirst(root.real.count).split(separator: "/").dropLast()
            if !mustRescan, inside.contains(where: { $0.hasPrefix(".") || FolderSource.skippedFolders.contains(String($0)) }) { continue }
            changed.insert(root.given)
        }
        if !changed.isEmpty { watcher.handler(changed) }
    }
}

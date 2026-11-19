import Foundation

/// What a fix's tool printed, as the row shows it: plain lines, safe to display, and bounded.
///
/// `TerminalText` makes it from the raw bytes, so nothing a tool prints can restyle the panel, move or hide text, or
/// grow without end. Only the last `limit` bytes of lines are kept; the lines dropped before them are counted.
public struct FixLog: Equatable, Sendable {
    /// Finished lines, oldest first.
    public private(set) var lines: [String] = []
    /// The line being written (no newline yet), or "".
    public internal(set) var partial = ""
    /// Lines dropped from the start to stay within `limit`.
    public private(set) var droppedLines = 0
    public let limit: Int
    private var keptBytes = 0

    public init(limit: Int = 64 * 1024) { self.limit = max(limit, 1024) }

    /// A log of these lines (fixtures and tests).
    public init(_ lines: [String], partial: String = "", limit: Int = 64 * 1024) {
        self.init(limit: limit)
        lines.forEach { append($0) }
        self.partial = partial
    }

    mutating func append(_ line: String) {
        lines.append(line)
        keptBytes += line.utf8.count + 1
        if keptBytes > limit {
            // drop from the start in one go (one copy, not one per line)
            var drop = 0, freed = 0
            while keptBytes - freed > limit && drop < lines.count - 1 {
                freed += lines[drop].utf8.count + 1
                drop += 1
            }
            lines.removeFirst(drop)
            keptBytes -= freed
            droppedLines += drop
        }
    }

    /// Every line, the one being written last.
    public var all: [String] { partial.isEmpty ? lines : lines + [partial] }

    /// The last `n` lines, blank ones left out.
    public func last(_ n: Int) -> [String] {
        Array(all.filter { !$0.allSatisfy(\.isWhitespace) }.suffix(n))
    }

    public var isEmpty: Bool { lines.isEmpty && partial.isEmpty }

    /// All of it as one text, with a first line saying how much was dropped.
    public var text: String {
        (droppedLines > 0 ? "(\(droppedLines) earlier lines not kept)\n" : "") + all.joined(separator: "\n")
    }
}

/// Turns a tool's raw output into `FixLog` lines, the way a terminal would show it, minus everything a terminal does
/// besides showing text:
///   - bytes are decoded as UTF-8, lossily (anything invalid becomes U+FFFD), a character split across two reads intact;
///   - escape sequences (colours, cursor moves, window titles, OSC 8 links, DCS strings) are removed whole, even when
///     split across reads; an unterminated string ends after 1 KB rather than swallowing the rest;
///   - control characters are removed; a tab becomes spaces; a carriage return starts the line again, so a progress
///     bar shows its last state; a backspace removes the character before it;
///   - C1 controls, line and paragraph separators and bidirectional overrides are removed after decoding, so a line
///     cannot reorder itself or pretend to be two;
///   - a line longer than 4 KB is cut into lines of 4 KB.
public struct TerminalText: Sendable {
    public static let maxLine = 4096
    static let maxString = 1024

    private enum State: Sendable { case text, escape, intermediate, csi, string, stringEscape }
    private var state = State.text
    private var stringLength = 0
    private var line: [UInt8] = []
    private var pendingCR = false
    public private(set) var log: FixLog

    public init(limit: Int = 64 * 1024) { log = FixLog(limit: limit) }

    /// Takes more output. Returns the lines it finished (for the password check).
    @discardableResult
    public mutating func feed<S: Sequence>(_ bytes: S) -> [String] where S.Element == UInt8 {
        var finished: [String] = []
        for b in bytes { step(b, &finished) }
        log.partial = Self.clean(Self.completePrefix(line))
        return finished
    }

    /// The output ended: the line being written becomes a line.
    public mutating func finish() {
        var finished: [String] = []
        if !line.isEmpty { endLine(&finished) }
        log.partial = ""
        state = .text
    }

    private mutating func step(_ b: UInt8, _ finished: inout [String]) {
        switch state {
        case .text:
            break
        case .escape:
            switch b {
            case 0x5B: state = .csi                                            // ESC [
            case 0x5D, 0x50, 0x58, 0x5E, 0x5F: state = .string; stringLength = 0  // ESC ] OSC, P DCS, X SOS, ^ PM, _ APC
            case 0x20...0x2F: state = .intermediate                            // ESC ( B and the like
            case 0x30...0x7E: state = .text                                    // a two-byte sequence, done
            case 0x1B: state = .escape
            default: state = .text; text(b, &finished)                         // not a sequence after all
            }
            return
        case .intermediate:
            switch b {
            case 0x20...0x2F: break
            case 0x30...0x7E: state = .text
            default: state = .text; text(b, &finished)
            }
            return
        case .csi:
            switch b {
            case 0x20...0x3F: break                                            // parameters, intermediates
            case 0x40...0x7E: state = .text                                    // the final byte
            default: state = .text; text(b, &finished)                         // broken off: show what follows
            }
            return
        case .string:
            stringLength += 1
            if b == 0x07 { state = .text }                                     // BEL ends an OSC
            else if b == 0x1B { state = .stringEscape }
            else if stringLength > Self.maxString { state = .text }
            return
        case .stringEscape:
            state = b == 0x5C ? .text : .string                                // ESC \ is the string terminator
            return
        }
        text(b, &finished)
    }

    private mutating func text(_ b: UInt8, _ finished: inout [String]) {
        if pendingCR {
            pendingCR = false
            if b == 0x0A { endLine(&finished); return }
            line.removeAll(keepingCapacity: true)                             // CR alone: the line starts again
        }
        switch b {
        case 0x0A: endLine(&finished)
        case 0x0D: pendingCR = true
        case 0x1B: state = .escape
        case 0x09: line.append(contentsOf: repeatElement(0x20, count: 8 - line.count % 8))
        case 0x08:                                                             // backspace: one character back
            while let last = line.last, last & 0xC0 == 0x80 { line.removeLast() }
            if !line.isEmpty { line.removeLast() }
        case 0x00..<0x20, 0x7F: break
        default:
            line.append(b)
            if line.count >= Self.maxLine { endLine(&finished) }
        }
    }

    private mutating func endLine(_ finished: inout [String]) {
        let s = Self.clean(line)
        line.removeAll(keepingCapacity: true)
        log.append(s)
        finished.append(s)
    }

    /// The bytes without a trailing, incomplete UTF-8 character (it may be completed by the next read).
    static func completePrefix(_ bytes: [UInt8]) -> ArraySlice<UInt8> {
        var i = bytes.count - 1, back = 0
        while i >= 0 && back < 4 && bytes[i] & 0xC0 == 0x80 { i -= 1; back += 1 }
        guard i >= 0 else { return bytes[...] }
        let lead = bytes[i]
        let needed = lead >= 0xF0 ? 4 : lead >= 0xE0 ? 3 : lead >= 0xC0 ? 2 : 1
        return needed > back + 1 ? bytes[..<i] : bytes[...]
    }

    /// Decoded lossily, with what can still reorder or split a line removed, and trailing spaces trimmed.
    static func clean<C: Collection>(_ bytes: C) -> String where C.Element == UInt8 {
        var scalars = String.UnicodeScalarView()
        for s in String(decoding: bytes, as: UTF8.self).unicodeScalars where !hidden(s) { scalars.append(s) }
        var s = String(scalars)
        while s.last == " " { s.removeLast() }
        return s
    }

    /// C0 and C1 controls, DEL, line and paragraph separators, and bidirectional marks, embeddings, overrides and isolates.
    static func hidden(_ s: Unicode.Scalar) -> Bool {
        switch s.value {
        case 0x00..<0x20, 0x7F...0x9F, 0x2028, 0x2029, 0x200E, 0x200F, 0x061C, 0x202A...0x202E, 0x2066...0x2069, 0xFEFF: return true
        default: return false
        }
    }
}

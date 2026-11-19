import Foundation

// Fix all runs one command per tool and place, not one per finding: one `brew upgrade` for every formula, one
// `brew upgrade --cask` for every cask, one exact-pinned `pip install` per Python, one `npm install -g`. A removal, and
// any command of another shape, stays a command of its own. The commands are made here from the plans the rows offer,
// and only from plans whose own command has exactly the shape a batch merges, so a batch runs nothing a row would not.

/// The command a plan joins in Fix all.
public enum FixBatchKind: Hashable, Sendable {
    /// `brew upgrade f1 f2 …` with this brew.
    case formulae(brew: String)
    /// `brew upgrade --cask c1 c2 …` with this brew.
    case casks(brew: String)
    /// One `pip install` of exact pins in this Python (its user site, or not).
    case pip(python: String, user: Bool)
    /// `npm install -g a@x b@y` with this npm.
    case npm(npm: String)
    /// A command of its own: a removal, cargo, a project's tool, anything not of a batch's shape.
    case single(FixInvocation)

    /// The batch a plan joins.
    public static func of(_ plan: FixPlan) -> FixBatchKind {
        let args = plan.invocation.arguments
        guard plan.action == .upgrade, !plan.inProjectFolder, plan.invocation.directory == nil else { return .single(plan.invocation) }
        if let h = plan.homebrew, plan.toolName == "brew" {
            if h.cask, args == ["upgrade", "--cask", h.name] { return .casks(brew: plan.invocation.executable) }
            if !h.cask, args == ["upgrade", h.name] { return .formulae(brew: plan.invocation.executable) }
        }
        if let p = plan.pip, plan.toolName == "pip", args == ["-m", "pip", "install"] + (p.user ? ["--user"] : []) + ["--upgrade", p.requirement] {
            return .pip(python: p.python, user: p.user)
        }
        if plan.toolName == "npm", args.count == 3, args[0] == "install", args[1] == "-g" { return .npm(npm: plan.invocation.executable) }
        return .single(plan.invocation)
    }

    /// Batches run in this order: removals first (malicious code goes before anything else runs), then Homebrew's
    /// formulae (they can replace Homebrew's own Pythons), casks, each Python, npm, and the rest.
    public func order(removal: Bool) -> Int {
        if removal { return 0 }
        switch self {
        case .formulae: return 1
        case .casks: return 2
        case .pip: return 3
        case .npm: return 4
        case .single: return 5
        }
    }

    /// What one item adds to the batch's command: the formula, the cask token, the npm package@version. Nil for pip,
    /// whose pins come from its dry run, and for a command of its own.
    public static func argument(_ plan: FixPlan) -> String? {
        switch of(plan) {
        case .formulae, .casks: return plan.homebrew?.name
        case .npm: return plan.invocation.arguments.last
        case .pip, .single: return nil
        }
    }

    /// The batch's one command, for items in this order (the most urgent first). For pip, `pins` are every version the
    /// dry run named; for a command of its own, its own invocation.
    public func invocation(_ arguments: [String], pins: [String] = []) -> FixInvocation {
        switch self {
        case let .formulae(brew): return FixInvocation(executable: brew, arguments: ["upgrade"] + Self.unique(arguments))
        case let .casks(brew): return FixInvocation(executable: brew, arguments: ["upgrade", "--cask"] + Self.unique(arguments))
        case let .npm(npm): return FixInvocation(executable: npm, arguments: ["install", "-g"] + Self.unique(arguments))
        case let .pip(python, user): return PipSetPreviewer.invocation(python: python, user: user, pins: pins)
        case let .single(invocation): return invocation
        }
    }

    /// brew's own dry run for the batch, where it has one.
    public func dryRun(_ arguments: [String]) -> FixInvocation? {
        switch self {
        case let .formulae(brew): return FixInvocation(executable: brew, arguments: ["upgrade", "--dry-run"] + Self.unique(arguments))
        case let .casks(brew): return FixInvocation(executable: brew, arguments: ["upgrade", "--cask", "--dry-run"] + Self.unique(arguments))
        default: return nil
        }
    }

    static func unique(_ a: [String]) -> [String] {
        var seen = Set<String>()
        return a.filter { seen.insert($0).inserted }
    }

    /// The tool, for the environment it runs in.
    public var toolName: String {
        switch self {
        case .formulae, .casks: return "brew"
        case .pip: return "pip"
        case .npm: return "npm"
        case let .single(i): return (i.executable as NSString).lastPathComponent
        }
    }
}

/// What a batch's log says about each item.
public enum FixBatchLog {
    /// The items whose step asked for a password, from brew's own headings: a prompt belongs to the last item a "==>"
    /// line named before it ("==> Running installer for zoom with sudo"). Nil when a prompt came before any item was
    /// named: then it cannot be told whose it was.
    public static func askedForPassword(_ log: FixLog, items: [String]) -> Set<String>? {
        var current: String?, asked = Set<String>()
        for line in log.all {
            if line.hasPrefix("==> ") {
                let words = Set(line.dropFirst(4).split(whereSeparator: { $0 == " " || $0 == ":" || $0 == "'" }).map(String.init))
                if let named = items.last(where: { words.contains($0) }) { current = named }
            } else if FixPasswordPrompt.asks(line) {
                guard let current else { return nil }
                asked.insert(current)
            }
        }
        return asked
    }
}

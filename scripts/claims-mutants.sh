#!/usr/bin/env bash
# The mutants of the claims guard, app/Tests/OSVAKitTests/ClaimsTests.swift: each breaks one rule the app's claims rest on,
# in the app's sources, and ClaimsTests must fail on it. Run it on a Mac from the root of a scratch clone (it edits the
# sources and puts them back with git checkout):
#   ./scripts/claims-mutants.sh
# For each mutant it checks that every marker it needs is on exactly one line, swaps that line for the mutant's, builds,
# and runs ClaimsTests, which must fail. It ends "claims mutants: N of N caught", and exits 1 if a mutant survives, does
# not build, or a marker is missing; and before any mutant, if ClaimsTests fails on the sources as they are.
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.elan/bin:$PATH"
if [ -n "$(git status --porcelain -- app/Sources)" ]; then echo "app/Sources has changes: run this in a clean scratch clone"; exit 1; fi
trap 'git checkout -q -- app/Sources' EXIT

(cd core && lake build OSVACore:static >/dev/null) || { echo "the core did not build"; exit 1; }
claims() { (cd app && swift build --build-tests >/tmp/claims-build.log 2>&1) || return 2; (cd app && swift test --skip-build --filter ClaimsTests >/tmp/claims-test.log 2>&1); }
claims; base=$?
if [ "$base" != 0 ]; then echo "ClaimsTests does not pass on the sources as they are (status $base): no mutant can be told apart"; exit 1; fi

K=app/Sources/OSVAKit
V=app/Sources/OSVAVerified
total=0; caught=0; bad=0
# mutant NAME FILE MARKER LINE [FILE MARKER LINE ...]: each MARKER (a fixed string) must be on exactly one line of its
# FILE; that line becomes LINE.
mutant() {
  local name=$1; shift
  total=$((total + 1))
  while [ $# -gt 0 ]; do
    local file=$1 marker=$2 line=$3; shift 3
    local n; n=$(grep -cF -- "$marker" "$file")
    if [ "$n" != 1 ]; then echo "MARKER $name: found $n times in $file"; bad=$((bad + 1)); git checkout -q -- app/Sources; return; fi
    M="$marker" L="$line" awk 'index($0, ENVIRON["M"]) { print ENVIRON["L"]; next } { print }' "$file" >"$file.mutant" && mv "$file.mutant" "$file"
  done
  claims; local status=$?
  git checkout -q -- app/Sources
  case $status in
    0) echo "SURVIVED $name"; bad=$((bad + 1)) ;;
    2) echo "DID NOT BUILD $name"; grep -m 3 "error:" /tmp/claims-build.log; bad=$((bad + 1)) ;;
    *) echo "caught   $name"; caught=$((caught + 1)) ;;
  esac
}

# The behaviour the claims are about
mutant likely-as-flagged \
  $K/Scan/BatchCheck.swift "// claims-mutant: likely-as-flagged" "            case .inRange, .likely: decisions[i] = .affected"
mutant unchecked-target \
  $V/Core.swift "// claims-mutant: unchecked-target" "        return Judgement(leaves: leaves, upgrade: CheckedUpgrade(candidate, fixes: fixes))"
mutant lenient-decoding \
  $V/Core.swift "// claims-mutant: lenient-decoding" "        if false, let other = any.allKeys.first(where: { CodingKeys(stringValue: \$0.stringValue) == nil }) {"

# What affects nothing here, what a suggested version may land in, and what a note or a flaw's line may name (the
# final review of core-decisions)
mutant elsewhere-severity \
  $K/Scan/FindingBuilder.swift "// claims-mutant: elsewhere-severity" "        return PackageState(check: check.check, group: .other, severity: worst(shown),"
mutant elsewhere-unmarked \
  $K/Scan/FindingBuilder.swift "// claims-mutant: elsewhere-unmarked" "        if false { finding.onlyElsewhere = true }"
mutant outside-severity \
  $K/Scan/FindingBuilder.swift "// claims-mutant: outside-severity" \
  "            let severity = [worst(reported), check.unlistedWorst].compactMap { \$0 }.max() ?? (flaws.isEmpty ? Severity(api: verdict.worstSeverity) : nil)"
mutant flagged-only-judge \
  $K/Scan/BatchCheck.swift "// claims-mutant: flagged-only-judge" "        _ = reported"
mutant fixed-in-for-another-flaw \
  $K/Scan/BatchCheck.swift "// claims-mutant: fixed-in-for-another-flaw" \
  "            let fixedIn = r?.fixedIn.flatMap { Self.judge(\$0, from: installed, advisories, [])?.upgrade }"
mutant malicious-fixed-in \
  $K/Scan/FindingBuilder.swift "// claims-mutant: malicious-fixed-in" \
  "            return UnresolvedFlaw(id: r.id, severity: Severity(api: flaw?.severity), fixedIn: r.fixedIn, reason: Self.reason(r.reason),"
mutant elsewhere-range-blocks \
  $K/Scan/BatchCheck.swift "// claims-mutant: elsewhere-range-blocks" "        let applies = { (f: BatchResponse.Flaw) in true }"
mutant raw-fixed-in \
  $K/Scan/FindingBuilder.swift "// claims-mutant: raw-fixed-in" \
  "            return UnresolvedFlaw(id: n.flaw.id, severity: Severity(api: n.flaw.severity), fixedIn: n.flaw.fixedIn.first,"
mutant likely-names-unchecked \
  $K/Scan/FindingBuilder.swift "// claims-mutant: likely-names-unchecked" \
  "            note = Self.sentences(check.likelySentence(upgrade: upgrade?.display ?? check.likely.first?.fixedIn.last), how, more)"

# The routing that makes it true
mutant extension-elsewhere \
  $K/Scan/BatchCheck.swift "import Foundation" "import Foundation; extension CheckedUpgrade { var forged: Bool { true } }"
mutant bit-cast \
  $K/Scan/BatchCheck.swift "import Foundation" "import Foundation; func forged(_ s: String) -> CheckedUpgrade { unsafeBitCast(s, to: CheckedUpgrade.self) }"
mutant display-with-text \
  $V/Core.swift "        case program" "        case program, shown(String)" \
  $K/Verified.swift "        case .program: return FindingBuilder.Component.shown(version)" \
                "        case .program: return FindingBuilder.Component.shown(version); case let .shown(text): return text"
mutant display-rewritten \
  $K/Verified.swift "        case .asChecked: return version" "        case .asChecked: return version + \".0\""
# A core function's name declared outside OSVAVerified. (With the C signature itself the tests do not build: CoreTests
# sees both and finds the call ambiguous.)
mutant core-name-declared \
  $K/Scan/BatchCheck.swift "import Foundation" "import Foundation; func osva_pct_encode(_ name: String) -> String { name }"
mutant core-imported-elsewhere \
  $K/Scan/BatchCheck.swift "import Foundation" "import Foundation; import OSVACore"
mutant fixed-version-from-text \
  $K/Model/Finding.swift "public mutating func setUpgrade(_ upgrade: CheckedUpgrade?) { fixedVersion = upgrade?.display }" \
  "    public mutating func setUpgrade(_ upgrade: CheckedUpgrade?) { fixedVersion = upgrade?.display }
    public mutating func setFixedVersion(_ text: String?) { fixedVersion = text }"
mutant settable-command-version \
  $K/Scan/UpgradeCommand.swift "        public private(set) var target: String?" "        public var target: String?"
mutant latest-command \
  $K/Scan/UpgradeCommand.swift "// never npm's @latest" "            guard let target else { return Advice(command: \"\\(tool) install -g \\(quote(name + \"@latest\"))\") }"
mutant newest-version-elsewhere \
  $K/Fix/FixAdvisor.swift "import Foundation" "import Foundation; func newestFix(_ versions: [String]) -> String? { Core.shared.newestVersion(versions) }"
mutant server-target-elsewhere \
  $K/Fix/FixAdvisor.swift "import Foundation" "import Foundation; func planned(_ plan: BatchResponse.Plan?) -> String? { plan?.unjudgedTarget }"
mutant server-target-by-flatmap \
  $K/Fix/FixAdvisor.swift "import Foundation" "import Foundation; func planned(_ plan: BatchResponse.Plan?) -> String? { plan.flatMap { \$0.unjudgedTarget } }"
mutant newest-version-as-a-value \
  $K/Fix/FixAdvisor.swift "import Foundation" "import Foundation; let pickNewest = Core.shared.newestVersion"
mutant newest-version-elsewhere-in-advisorycheck \
  $K/Scan/AdvisoryCheck.swift "import Foundation" "import Foundation; func newestFix(_ versions: [String]) -> String? { Core.shared.newestVersion(versions) }"
mutant raw-pointer-load \
  $K/Fix/FixAdvisor.swift "import Foundation" "import Foundation; func reread(_ data: Data) -> UInt8 { data.withUnsafeBytes { \$0.load(as: UInt8.self) } }"
mutant finding-decoded-again \
  $K/Fix/FixAdvisor.swift "import Foundation" \
  "import Foundation; func reforged(_ f: Finding) -> Finding? { guard var json = (try? JSONSerialization.jsonObject(with: JSONEncoder().encode(f))) as? [String: Any] else { return nil }; json[\"fixedVersion\"] = \"9.9\"; return try? JSONDecoder().decode(Finding.self, from: JSONSerialization.data(withJSONObject: json)) }"
mutant inputs-decoded-again \
  $K/Fix/FixAdvisor.swift "import Foundation" \
  "import Foundation; func reforged(_ i: UpgradeCommand.Inputs) -> UpgradeCommand.Inputs? { guard var json = (try? JSONSerialization.jsonObject(with: JSONEncoder().encode(i))) as? [String: Any] else { return nil }; json[\"target\"] = \"9.9\"; return try? JSONDecoder().decode(UpgradeCommand.Inputs.self, from: JSONSerialization.data(withJSONObject: json)) }"
mutant fixed-version-split-over-lines \
  $K/Model/Finding.swift "public mutating func setUpgrade(_ upgrade: CheckedUpgrade?) { fixedVersion = upgrade?.display }" \
  "    public mutating func setUpgrade(_ upgrade: CheckedUpgrade?) { fixedVersion = upgrade?.display }
    public mutating func forge(_ text: String?) { fixedVersion =
        text }"
mutant target-split-over-lines \
  $K/Scan/UpgradeCommand.swift "self.origin = origin; self.name = name; self.ecosystem = ecosystem; self.target = target?.version; self.malicious = malicious" \
  "            self.origin = origin; self.name = name; self.ecosystem = ecosystem; self.target = target?.version; self.malicious = malicious
        }
        public mutating func forge(_ text: String?) { target =
            text"
mutant command-outside-the-builders \
  $K/Fix/FixAdvisor.swift "import Foundation" "import Foundation; let handWritten = UpgradeCommand.Advice(command: \"npm install -g x@9.9\")"
mutant command-written \
  $K/Model/Finding.swift "public mutating func setAdvice(_ advice: UpgradeCommand.Advice?) { upgradeCommand = advice?.command }" \
  "    public mutating func setAdvice(_ advice: UpgradeCommand.Advice?) { upgradeCommand = advice?.command }
    public mutating func setCommand(_ text: String?) { upgradeCommand = text }"
mutant settable-advice \
  $K/Scan/UpgradeCommand.swift "        public fileprivate(set) var command: String?" "        public var command: String?"
mutant settable-note \
  $K/Model/Finding.swift "    public private(set) var note: String?" "    public var note: String?"
mutant generic-redecode \
  $K/Fix/FixAdvisor.swift "import Foundation" \
  "import Foundation; func redecode<T: Codable>(_ value: T, _ edit: (inout [String: Any]) -> Void) -> T { var j = try! JSONSerialization.jsonObject(with: JSONEncoder().encode(value)) as! [String: Any]; edit(&j); return try! JSONDecoder().decode(T.self, from: JSONSerialization.data(withJSONObject: j)) }; func forged(_ f: Finding) -> Finding { redecode(f) { \$0[\"fixedVersion\"] = \"9.9\" } }"
mutant generic-redecode-plist \
  $K/Fix/FixAdvisor.swift "import Foundation" \
  "import Foundation; func redecode<T: Codable>(_ value: T, _ edit: (inout [String: Any]) -> Void) -> T { var p = try! PropertyListSerialization.propertyList(from: PropertyListEncoder().encode(value), format: nil) as! [String: Any]; edit(&p); return try! PropertyListDecoder().decode(T.self, from: PropertyListSerialization.data(fromPropertyList: p, format: .binary, options: 0)) }; func forged(_ f: Finding) -> Finding { redecode(f) { \$0[\"fixedVersion\"] = \"9.9\" } }"
mutant decode-on-an-unknown-line \
  $K/Fix/FixAdvisor.swift "import Foundation" "import Foundation; func reread<T: Decodable>(_ type: T.Type, _ data: Data) -> T? { try? JSONDecoder().decode(type, from: data) }"
mutant dictionary-made-json \
  $K/Fix/FixAdvisor.swift "import Foundation" "import Foundation; func json(_ fields: [String: Any]) -> Data? { try? JSONSerialization.data(withJSONObject: fields) }"
mutant a-decoder-of-its-own \
  $K/Fix/FixAdvisor.swift "import Foundation" "import Foundation; protocol LooseDecoder: Decoder {}"
mutant value-from-a-decoder \
  $K/Fix/FixAdvisor.swift "import Foundation" "import Foundation; func make<T: Decodable>(_ type: T.Type, _ decoder: Decoder) throws -> T { try T(from: decoder) }"
mutant version-key-elsewhere \
  $K/Fix/FixAdvisor.swift "import Foundation" "import Foundation; let commandKey = \"upgradeCommand\""
mutant target-key-written \
  $K/Fix/FixAdvisor.swift "import Foundation" "import Foundation; func retarget(_ inputs: inout [String: Any]) { inputs[\"target\"] = \"9.9\" }"
mutant version-property-elsewhere \
  $K/Fix/FixAdvisor.swift "import Foundation" "import Foundation; struct Shown { var fixedVersion: String? }"
mutant finding-kept-elsewhere \
  $K/Fix/FixAdvisor.swift "import Foundation" "import Foundation; struct Kept: Codable { var finding: Finding }"
mutant inputs-kept-by-an-extension \
  $K/Fix/FixAdvisor.swift "import Foundation" "import Foundation; struct Kept { var inputs: UpgradeCommand.Inputs }; extension Kept: Codable {}"
mutant advisory-made-elsewhere \
  $K/Fix/FixAdvisor.swift "import Foundation" "import Foundation; let wide = CoreAdvisory(ranges: nil, fixed: [])"
mutant range-made-elsewhere \
  $K/Fix/FixAdvisor.swift "import Foundation" "import Foundation; let everything = AffectedRange()"
mutant report-kept-elsewhere \
  $K/Fix/FixAdvisor.swift "import Foundation" "import Foundation; struct KeptReport: Codable { var report: ScanReport }"
mutant range-bound-rewritten \
  $V/Core.swift "    public let fixed: String?" "    public var fixed: String?" \
  $K/Fix/FixAdvisor.swift "import Foundation" "import Foundation; func widened(_ r: AffectedRange) -> AffectedRange { var w = r; w.fixed = \"999\"; return w }"
mutant advisory-ranges-rewritten \
  $V/Core.swift "    public let ranges: [AffectedRange]?" "    public var ranges: [AffectedRange]?" \
  $K/Fix/FixAdvisor.swift "import Foundation" "import Foundation; func cleared(_ a: CoreAdvisory) -> CoreAdvisory { var c = a; c.ranges = []; return c }"
mutant range-rewritten-by-extension \
  $K/Fix/FixAdvisor.swift "import Foundation" \
  "import Foundation; extension AffectedRange { func refixed(_ v: String) -> AffectedRange { AffectedRange(introduced: introduced, fixed: v, lastAffected: lastAffected) } }"
mutant nearest-version-back \
  $V/Core.swift "    /// The versions, oldest first." \
  "    public func nearestVersion(in versions: [String], above version: String) -> String? { sortedVersions(versions.filter { compareVersions(\$0, version) > 0 }).first }"

echo "claims mutants: $caught of $total caught"
[ "$bad" = 0 ] && [ "$caught" = "$total" ]

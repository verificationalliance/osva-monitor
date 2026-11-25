#!/usr/bin/env bash
# Builds "OSVA Monitor.app": the verified core (Lean), a release build of the app, the bundle, and its signature.
#
#   scripts/build-app.sh                 ad-hoc signed app in app/.build/OSVA Monitor.app (runs on this Mac)
#   DEVELOPER_ID="Developer ID Application: Name (TEAMID)" NOTARY_PROFILE=<notarytool keychain profile> \
#   scripts/build-app.sh                 Developer ID signed, hardened runtime, notarized and stapled
#
# VERSION sets the version (default below), as major.minor.patch. The bundle version Sparkle compares, CFBundleVersion,
# follows from it (1.2.3 is 1002003), so a higher version is always a newer build; BUILD_NUMBER overrides it. A
# Developer ID build needs the version's entry in app/Sources/OSVAMonitorUI/Resources/CHANGELOG.md, which the app shows
# as What's New.
# OUT_DIR changes where the app goes.
# DEV_BUILD=1 makes a build for this Mac only, the one kind of build that takes SWIFTPM_FLAGS: extra arguments for
# `swift build`, split at spaces, tabs and newlines (no quoting, no globbing). Its Info.plist has OSVADevBuild, and it
# is never signed with the Developer ID: DEVELOPER_ID refuses DEV_BUILD, and SIGN_APP refuses an app with OSVADevBuild.
# Any other build may become a release (SIGN_APP signs the Mac server's builds), so it refuses SWIFTPM_FLAGS: a flag
# could add inputs to the link.
# The core is built with the Lean toolchain core/lean-toolchain names, run through elan (not whatever `lake` comes first
# on PATH), and app/Package.swift links the Lean runtime from that toolchain; the build stops if they are not the same.
# SIGNING_KEYCHAIN (and SIGNING_KEYCHAIN_PASSWORD_FILE) name a dedicated keychain holding the identity and the notary
# profile: it is unlocked and appended to the search list only while signing (codesign needs that to build the
# certificate chain), then the search list is restored exactly and the keychain locked again.
#
# Where the code in the executable comes from (check_core_origin). Step 2 links the executable with a link map
# (ld -map), OSVAMonitor.link-map beside the app. The Lean archives are the core's,
# core/.lake/build/lib/libosvaCore_OSVACore.a, and the ones app/Package.swift links from the toolchain
# core/lean-toolchain names: lib/lean/libStd.a, libInit.a, libleanrt.a and libcadical.a, and lib/libgmp.a and libuv.a.
# The build stops unless, in the map:
#   - every "# Object files:" entry that starts with a Lean archive's real path (realpath; ld writes an archive's path
#     so) and "(" is exactly that path, "(", a member name with no "/" or parentheses that `ar t` lists for that
#     archive, and ")"; and no file exists at the entry's literal path, since a file named "libInit.a(x.o)" beside the
#     archive, given to the link, would read the same;
#   - no other entry is a file in the toolchain's folder (a dylib, or an archive the list above lacks);
#   - every symbol in "# Symbols:" (what the executable holds; dead-stripped ones are not checked) whose name a Lean
#     archive defines as a global (nm -g: "address type name") comes from an entry above whose member defines that
#     name, and every symbol whose name starts with _lp_osvaCore_, _initialize_osvaCore_ or _osva_lean_ from a member
#     of the core's archive. A thread-local's descriptor is the linker's own; its initial value, <name>$tlv$init, must
#     then be from the member that defines the name. This holds for a local symbol of such a name too;
#   - no symbol in "# Symbols:" has a name that a Lean archive's member imports (nm -g: "U name") and no Lean archive
#     defines (getenv, memcpy, malloc, ...), but one the linker makes itself (___dso_handle), and that not as a
#     thread-local: the Lean code's calls to such a name go to the system, not to the app's code (a Swift
#     @_cdecl("getenv") would take them);
#   - every global the core's archive defines has one of those three prefixes, and every name it imports is one a
#     toolchain archive imports or defines (SIGN_APP relies on both);
#   - of what the executable takes from a library at run time (nm -m: "(undefined) external name (from library)"),
#     nothing is a name a Lean archive defines or with the core's prefixes, and every name a Lean archive imports is
#     from a system library: one whose install name (otool -L) starts with /usr/lib/ or /System/Library/, matched to
#     nm's short name for it (a framework's name, or a dylib's file name up to its first dot);
#   - these are present: _lp_osvaCore_OSVA_verdict, _lp_osvaCore_OSVA_upgradeFor, _lp_osvaCore_OSVA_judge and
#     _lp_osvaCore_OSVA_pctEncode (the compiled OSVA.verdict, upgradeFor, judge and pctEncode, which the claims in
#     .verificationalliance.json are about), _osva_lean_<name> for every @[export osva_lean_<name>] in
#     core/OSVACore/FFI.lean (what the C shim calls), and _initialize_osvaCore_OSVACore (the core's initializer); the
#     map is this executable's: its "# Path:" names an OSVAMonitor, and nm finds each of these in the executable,
#     external and in __TEXT (T), at the address the map gives.
# So no app object (a Swift @_cdecl, say), other object, archive or dylib given to the link supplies a symbol the
# executable keeps under a name a Lean archive defines, or under the core's prefixes, or under a name the Lean code
# imports from the system. Not checked: that the archives hold what they should (step 1 builds the core's from the
# .lean files in the same run; the toolchain's are whatever elan installed under that toolchain's name); which of two
# members with the same name gave a symbol (libInit.a has several called Basic.c.o.export: "its member defines that
# name" means one of that name does); which system library an import comes from, beyond its being one; the system's
# libraries themselves (libc++, libSystem, the Swift runtime); the shim's own functions; and Swift's own names: a
# function of the app's named like a core function would be called instead of the core's by Swift code in the same
# module, which no link map shows. app/Package.swift keeps the one caller, Core.swift, alone in its module
# (OSVAVerified), and ClaimsTests holds it there.
#
# SIGN_APP=<path to OSVA Monitor.app>, with DEVELOPER_ID: skip steps 1-3 and sign and notarize an app another Mac
# built with this script (the Mac server builds and tests; the signing keys stay on the signing Mac). It is signed only
# if: its CFBundleShortVersionString and CFBundleVersion are this run's version and bundle version; its
# CFBundleIdentifier, SUFeedURL, SUPublicEDKey, SUVerifyUpdateBeforeExtraction and SURequireSignedFeed equal
# app/Resources/Info.plist's; it has no NSAppTransportSecurity (UPDATE_TESTING) or OSVADevBuild (DEV_BUILD) key; its
# executable does not contain the string OSVA_UPDATE_FEED (UPDATE_TESTING) and loads no library named like the core
# (otool -L); and the link map its build wrote passes the origin check above. That map must be copied along with the
# app, to SIGN_APP's folder as OSVAMonitor.link-map, and the toolchain core/lean-toolchain names must be installed
# here (elan toolchain install <it>): without it the Lean archives' members and globals are unknown, so SIGN_APP
# refuses rather than check less than the build did. What differs, since the build Mac's files are not here: each
# archive's path is the build Mac's, read from the map (one folder for the toolchain, one for the core, each the only
# one); the toolchain archives' members, globals and imports are this Mac's copy of the same toolchain; the core's
# members must be named after its modules (core/OSVACore/<Name>.lean is <Name>.c.o.export), its globals and imports
# are unknown, so its prefixed symbols are checked by prefix only, a name the toolchain archives define may not come
# from it, and its imports are covered by the toolchain archives' (which the build checked); and no file can be looked
# for at an entry's literal path. The map is required, rather than trusting that the build checked
# it, so that this Mac refuses an app whose build did not check its code (an older script, or no map), and nm ties the
# map to this executable. The map is the build Mac's word, not signed: it guards against a mistake on the build Mac,
# not against a build Mac that lies.
#
# For testing updates only, and refused together with DEVELOPER_ID:
#   SPARKLE_PUBLIC_KEY=<base64>  trust this update key instead of the real one (a throwaway key's public half)
#   UPDATE_TESTING=1             compile in OSVA_UPDATE_FEED, an environment variable that points the updater at
#                                another feed (http://127.0.0.1:… for a local one); a normal build has no such code
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
app_src="$here/app"
out_dir="${OUT_DIR:-$app_src/.build}"
app="$out_dir/OSVA Monitor.app"
version="${VERSION:-0.6.0}"
min_macos="26.0"
die() { echo "build-app.sh: $*" >&2; exit 1; }

[[ "$version" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || die "VERSION must be major.minor.patch, each 0 to 999 (not $version)"
build_number="${BUILD_NUMBER:-$(( 10#${BASH_REMATCH[1]} * 1000000 + 10#${BASH_REMATCH[2]} * 1000 + 10#${BASH_REMATCH[3]} ))}"
[[ "$build_number" =~ ^[0-9]+$ ]] || die "BUILD_NUMBER must be a whole number (not $build_number)"
[ -z "${DEV_BUILD:-}" ] || [ "$DEV_BUILD" = 1 ] || die "DEV_BUILD is 1 or unset (not $DEV_BUILD)"
swift_flags=()
if [ "${DEV_BUILD:-}" = 1 ]; then
  # Split at whitespace by read, never by an unquoted expansion, which would also expand * and ? against files here.
  # read exits 1 at the end of its input even when it read everything (-d ''), hence the || true.
  [ -z "${SWIFTPM_FLAGS:-}" ] || read -r -d '' -a swift_flags <<<"$SWIFTPM_FLAGS" || true
else
  [ -z "${SWIFTPM_FLAGS:-}" ] || die "SWIFTPM_FLAGS is only for a dev build (DEV_BUILD=1): any other build may become a release, and a flag could add inputs to the link"
fi
if [ -n "${DEVELOPER_ID:-}" ]; then
  [ -z "${SPARKLE_PUBLIC_KEY:-}" ] || die "SPARKLE_PUBLIC_KEY is for test builds; a Developer ID build trusts only the real update key"
  [ -z "${UPDATE_TESTING:-}" ] || die "UPDATE_TESTING is for test builds, never signed with the Developer ID"
  [ -z "${DEV_BUILD:-}" ] || die "DEV_BUILD is for this Mac only, never signed with the Developer ID"
  changelog="$app_src/Sources/OSVAMonitorUI/Resources/CHANGELOG.md"
  [ "$(grep -c -x "## $version" "$changelog" || true)" = 1 ] || die "CHANGELOG.md has no entry for $version, so What's New would show nothing"
fi
[ "${UPDATE_TESTING:-}" != 1 ] || swift_flags+=(-Xswiftc -DOSVA_UPDATE_TESTING)

# otool -L lists no library whose path contains "osvacore" (any case), so the executable does not load the core from a
# dylib, which would be whatever file is at that path when the app runs. This says nothing about where the code inside
# the executable came from; check_core_origin does.
check_core_inside() {
  local loads
  loads="$(otool -L "$1")" || die "otool cannot read $1"
  if grep -i -E '^[[:space:]].*osvacore' <<<"$loads" >&2; then
    die "$1 loads the verified core from a dylib (above) instead of having it inside, from libosvaCore_OSVACore.a"
  fi
}

# The origin check the header describes ("Where the code in the executable comes from").
link_map_name="OSVAMonitor.link-map"
core_prefixes='^_(lp_osvaCore_|initialize_osvaCore_|osva_lean_)'
core_archive_path="/core/.lake/build/lib/libosvaCore_OSVACore.a"
# The toolchain's archives app/Package.swift links (-lStd -lInit -lleanrt -lcadical -lgmp -luv), relative to the
# toolchain's folder. Its -lc++ is the SDK's libc++, a dylib: the toolchain has none.
lean_archives="lib/lean/libStd.a lib/lean/libInit.a lib/lean/libleanrt.a lib/lean/libcadical.a lib/libgmp.a lib/libuv.a"
# The Lean toolchain core/lean-toolchain names, and its folder, worked out as app/Package.swift does.
toolchain="$(tr -d '[:space:]' < "$here/core/lean-toolchain")"
runtime_dir="${ELAN_HOME:-$HOME/.elan}/toolchains/$(sed -e 's|/|--|g' -e 's|:|---|g' <<<"$toolchain")"
# The names that must be in the executable: the four the claims are about, the initializer, and FFI.lean's exports.
core_required() {
  local exports
  exports="$(grep -o '@\[export osva_lean_[A-Za-z0-9_]*\]' "$here/core/OSVACore/FFI.lean" \
    | sed -e 's/^@\[export /_/' -e 's/\]$//')"
  [ -n "$exports" ] || die "core/OSVACore/FFI.lean exports no osva_lean_* function"
  printf '%s\n' _lp_osvaCore_OSVA_verdict _lp_osvaCore_OSVA_upgradeFor _lp_osvaCore_OSVA_judge \
    _lp_osvaCore_OSVA_pctEncode _initialize_osvaCore_OSVACore "$exports"
}
# origin_tables <label> <archive>: "M label member" for each member ar t lists, "D label member name" for each global a
# member defines, and "U label member name" for each name a member imports (nm -g: "address type name" for a definition,
# "U name" for an import, under a "member:" line), tab-separated.
origin_tables() {
  local out
  out="$(ar t "$2")" || die "ar cannot read $2"
  awk -v l="$1" 'NF { print "M\t" l "\t" $0 }' <<<"$out"
  out="$(nm -g "$2")" || die "nm cannot read $2"
  awk -v l="$1" '/:$/ { m = substr($0, 1, length($0) - 1); next }
    NF == 2 && $1 == "U" { print "U\t" l "\t" m "\t" $2 } NF >= 3 { print "D\t" l "\t" m "\t" $3 }' <<<"$out"
}
# The build Mac's folder for a path ending, read from the map's "# Object files:" (SIGN_APP); there must be exactly one.
map_prefix() {
  local found
  found="$(awk -v t="$2" 'sub(/^\[ *[0-9]+\] /, "") && (i = index($0, t)) { print substr($0, 1, i - 1) }' "$1" | sort -u)"
  [ -n "$found" ] && [ "$(wc -l <<<"$found" | tr -d ' ')" = 1 ] \
    || die "$1 names no single folder for ...$t (found: ${found:-none})"
  echo "$found"
}
# check_core_origin <link map> <executable> build|sign
check_core_origin() {
  local map="$1" exe="$2" mode="$3" path arch tables tdir core_dir result rel f required name addr member n line
  local problems="" listing="" core_imports imports
  [ -s "$map" ] || die "no link map at $map (build-app.sh writes it beside the app it builds)"
  path="$(sed -n 's/^# Path: //p' "$map" | head -1)"
  arch="$(sed -n 's/^# Arch: //p' "$map" | head -1)"
  [ "${path##*/}" = OSVAMonitor ] && [ -n "$arch" ] || die "$map is not the link map of an OSVAMonitor executable (# Path: $path)"
  [ -d "$runtime_dir/lib/lean" ] || die "the Lean libraries are checked against $toolchain, which is not installed here ($runtime_dir); install it with: elan toolchain install $toolchain"
  tables="$(mktemp)"
  trap 'rm -f "$tables" "$tables.imports"' EXIT
  # A: each Lean archive's path as the map must write it. In a build: its real path, which is how ld writes an archive.
  # With SIGN_APP: the build Mac's, read from the map; the core's members are then its modules' names, as lake names
  # them (core/OSVACore/<Name>.lean is <Name>.c.o.export), and its globals are not known here.
  if [ "$mode" = build ]; then
    tdir="$(realpath "$runtime_dir")/"
    f="$(realpath "$here$core_archive_path")"
    { printf 'A\tcore\t%s\n' "$f"; origin_tables core "$f"; } >> "$tables"
    line="$(awk -F '\t' -v re="$core_prefixes" '$1 == "D" && $4 !~ re { print $4 }' "$tables" | head -3 | tr '\n' ' ' || true)"
    [ -z "$line" ] || die "the core's archive defines globals without the prefixes SIGN_APP relies on ($core_prefixes): $line"
    core_imports="$(awk -F '\t' '$1 == "U" { print $4 }' "$tables" | sort -u)"
  else
    tdir="$(map_prefix "$map" "/${runtime_dir##*/}/lib/")/${runtime_dir##*/}/"
    core_dir="$(map_prefix "$map" "$core_archive_path(")"
    printf 'A\tcore\t%s\n' "$core_dir$core_archive_path" >> "$tables"
    for f in "$here"/core/OSVACore/*.lean "$here/core/OSVACore.lean"; do
      f="${f##*/}"; printf 'M\tcore\t%s.c.o.export\n' "${f%.lean}"
    done >> "$tables"
  fi
  for rel in $lean_archives; do
    [ -f "$runtime_dir/$rel" ] || die "$toolchain has no $rel, which app/Package.swift links"
    if [ "$mode" = build ]; then f="$(realpath "$runtime_dir/$rel")"; else f="$tdir$rel"; fi
    { printf 'A\t%s\t%s\n' "$rel" "$f"; origin_tables "$rel" "$runtime_dir/$rel"; } >> "$tables"
  done
  if [ "$mode" = build ]; then
    # Every name the core's archive imports is one the toolchain archives import or define (SIGN_APP relies on it).
    line="$(awk -F '\t' 'FNR == NR { if ($2 != "core" || $1 == "D") known[$4] = 1; next } !($1 in known)' "$tables" - <<<"$core_imports" \
      | head -3 | tr '\n' ' ' || true)"
    [ -z "$line" ] || die "the core's archive imports names no toolchain archive imports or defines, which SIGN_APP relies on: $line"
  fi
  # P: a problem; F: an entry taken as an archive member (in a build, no file may have its literal path); S: a symbol
  # with the core's prefixes (name, address, member); C: how many checked symbols each archive gave.
  result="$(awk -F '\t' -v re="$core_prefixes" -v tdir="$tdir" '
    FNR == NR {
      if ($1 == "A") { path[$2] = $3; lab[++nl] = $2 }
      else if ($1 == "M") member[$2 SUBSEP $3] = 1
      else if ($1 == "D") { def[$2 SUBSEP $3 SUBSEP $4] = 1; lean[$4] = 1; hasdef[$2] = 1 }
      else if ($1 == "U") imp[$4] = 1
      next
    }
    /^# Object files:$/ { s = "o"; next }
    /^# Symbols:$/ { s = "s"; next }
    /^# [A-Z][A-Za-z ]*:$/ { s = ""; next }
    /^#/ { next }
    s == "o" && match($0, /^\[ *[0-9]+\] /) {
      i = substr($0, 2, RLENGTH - 3) + 0; p = substr($0, RLENGTH + 1); file[i] = p
      for (k = 1; k <= nl; k++) {
        l = lab[k]; a = path[l] "("
        if (substr(p, 1, length(a)) != a) continue
        m = substr(p, length(a) + 1)
        if (m ~ /\)$/) m = substr(m, 1, length(m) - 1); else m = "/"
        if (m == "" || m ~ /[\/()]/ || !((l SUBSEP m) in member)) print "P\t" p " is not " path[l] "(member) for one of its members"
        else { from[i] = l; mem[i] = m; if (!(p in taken)) print "F\t" p; taken[p] = 1 }
        break
      }
      if (!(i in from) && k > nl && substr(p, 1, length(tdir)) == tdir) print "P\tthe link takes " p " from the toolchain, and this check does not cover it"
      next
    }
    s == "s" && NF >= 3 && match($3, /^\[ *[0-9]+\] /) {
      i = substr($3, 2, RLENGTH - 3) + 0; n = substr($3, RLENGTH + 1); c = (n ~ re); g = (n in lean)
      u = !c && !g && (n in imp)
      if (n ~ /\$tlv\$init$/) {
        tlvany[substr(n, 1, length(n) - 9)] = file[i]
        if (i in from) tlvinit[substr(n, 1, length(n) - 9)] = from[i] SUBSEP mem[i]
      }
      if (!c && !g && !u) next
      if (file[i] == "linker synthesized") { if (u) made[n] = 1; else tlv[n] = 1; next }
      if (u) { print "P\t" n ", which the Lean archives import, is defined by " file[i] ", not left to the system"; next }
      l = from[i]
      if (l == "") print "P\t" n " is defined by " file[i] ", not by a member of a Lean archive"
      else if (c && l != "core") print "P\t" n " is defined by " file[i] ", not by a member of the core'"'"'s archive"
      else if (g && !(hasdef[l] && ((l SUBSEP mem[i] SUBSEP n) in def))) print "P\t" n " is defined by " file[i] ", whose member does not define it"
      else { count[l]++; if (c) print "S\t" n "\t" $1 "\t" mem[i] }
    }
    END {
      # A thread-local: the linker makes its descriptor, and its initial value (name$tlv$init) must be from the member
      # that defines the name.
      for (n in tlv) {
        if ((n in tlvinit) && ((tlvinit[n] SUBSEP n) in def)) { split(tlvinit[n], q, SUBSEP); count[q[1]]++ }
        else print "P\t" n " is a thread-local whose initial value is not from a member of a Lean archive that defines it"
      }
      # A name the Lean archives import may be the linker'"'"'s own (___dso_handle), but not a thread-local of other code.
      for (n in made) if (n in tlvany) print "P\t" n ", which the Lean archives import, is a thread-local of " tlvany[n]
      for (k = 1; k <= nl; k++) print "C\t" lab[k] "\t" count[lab[k]] + 0
    }' "$tables" "$map")"
  problems="$(awk -F '\t' '$1 == "P" { print "   " $2 }' <<<"$result")"
  if [ "$mode" = build ]; then
    while IFS=$'\t' read -r line f; do
      [ "$line" = F ] && [ -e "$f" ] && problems+=$'\n'"   a file named $f exists: the link may have read it, not the archive's member"
    done <<<"$result"
  fi
  # What the executable takes from a library at run time (nm -m: "(undefined) [weak] external name (from library)"), and
  # its libraries (otool -L), each known to nm by its short name: a framework's name, or a dylib's file name up to its
  # first dot. A system library is one under /usr/lib/ or /System/Library/.
  line="$(otool -L -arch "$arch" "$exe")" || die "otool cannot read $exe"
  awk 'NR > 1 { sub(/^[ \t]+/, ""); sub(/ \(compatibility version .*$/, ""); print "L\t" $0 }' <<<"$line" > "$tables.imports"
  line="$(nm -m -arch "$arch" "$exe")" || die "nm cannot read $exe"
  awk '/\(undefined\)/ { for (k = 1; k < NF; k++) if ($k == "external") break
    f = ""; if (match($0, /\(from [^()]*\)$/)) f = substr($0, RSTART + 6, RLENGTH - 7); print "I\t" $(k + 1) "\t" f }' <<<"$line" \
    >> "$tables.imports"
  imports="$(awk -F '\t' -v re="$core_prefixes" '
    FNR == NR { if ($1 == "D") g[$4] = 1; else if ($1 == "U") u[$4] = 1; next }
    $1 == "L" {
      p = $2; sn = p
      if (match(p, /[^\/]+\.framework\//)) sn = substr(p, RSTART, RLENGTH - 11); else { sub(/^.*\//, "", sn); sub(/\..*$/, "", sn) }
      sys = (p ~ /^\/usr\/lib\// || p ~ /^\/System\/Library\//); onsys[sn] = (sn in onsys) ? onsys[sn] && sys : sys
      next
    }
    $1 == "I" { from = ($3 == "" ? "a library looked up at run time" : $3) }
    $1 == "I" && (($2 in g) || $2 ~ re) { print "P\tthe executable takes " $2 " from " from ", not from the Lean archive that defines it"; next }
    $1 == "I" && ($2 in u) {
      if (onsys[$3]) { kept++; by[$3]++ } else print "P\tthe executable takes " $2 ", which the Lean archives import, from " from ", not a system library"
    }
    END { for (l in by) list = list (list == "" ? "" : ", ") l " " by[l]; print "K\t" kept + 0 "\t" list }' "$tables" "$tables.imports")"
  problems+=$'\n'"$(awk -F '\t' '$1 == "P" { print "   " $2 }' <<<"$imports")"
  line="$(nm -g -U -arch "$arch" "$exe")" || die "nm cannot read $exe"
  required="$(core_required)"
  for name in $required; do
    n="$(awk -F '\t' -v n="$name" '$1 == "S" && $2 == n' <<<"$result" | wc -l | tr -d ' ')"
    if [ "$n" != 1 ]; then problems+=$'\n'"   $name is in the link map's # Symbols from the core's archive $n times, not once"; continue; fi
    addr="$(awk -F '\t' -v n="$name" '$1 == "S" && $2 == n { print $3 }' <<<"$result")"
    member="$(awk -F '\t' -v n="$name" '$1 == "S" && $2 == n { print $4 }' <<<"$result")"
    f="$(awk -v n="$name" '$3 == n' <<<"$line")"
    if [ "$(awk '{ print $2 }' <<<"$f")" != T ] || [ $((16#${addr#0x})) != $((16#$(awk '{ print $1 }' <<<"$f"))) ]; then
      problems+=$'\n'"   $name: the map has it at $addr, nm finds in the executable: ${f:-nothing}"
    else
      listing+="   $name $addr libosvaCore_OSVACore.a($member)"$'\n'
    fi
  done
  rm -f "$tables" "$tables.imports"; trap - EXIT
  problems="$(grep . <<<"$problems" || true)"
  [ -z "$problems" ] || { echo "$problems" >&2; die "the executable has code in place of the Lean archives' (above; map: $map)"; }
  printf '%s' "$listing"
  echo "   symbols in the executable that a Lean archive defines, or with the core's prefixes, all from its members:"
  awk -F '\t' '$1 == "C" { printf "%s%s %s", (n++ ? ", " : "   "), ($2 == "core" ? "the core" : $2), $3 } END { print "" }' <<<"$result"
  awk -F '\t' '$1 == "K" { print "   names the Lean archives import: none defined by other code; " $2 " taken from system libraries (" $3 ")" }' \
    <<<"$imports"
}

if [ -z "${SIGN_APP:-}" ]; then
echo "1. verified core (lake build OSVACore:static, with $toolchain)"
[[ "$toolchain" == leanprover/lean4:v* ]] || die "core/lean-toolchain does not name a Lean release: $toolchain"
elan="$(command -v elan || echo "${ELAN_HOME:-$HOME/.elan}/bin/elan")"
[ -x "$elan" ] || die "no elan, which runs the toolchain core/lean-toolchain names (https://github.com/leanprover/elan)"
lake_version="$("$elan" run --install "$toolchain" lake --version)" || die "elan cannot run $toolchain"
[[ "$lake_version" == *"(Lean version ${toolchain#*:v})" ]] || die "$toolchain runs a lake of another Lean: $lake_version"
# The directory app/Package.swift links the Lean runtime from (runtime_dir, above): it must be this toolchain's.
lean_prefix="$("$elan" run "$toolchain" lean --print-prefix)" || die "elan cannot run $toolchain"
[ -d "$runtime_dir" ] && [ "$(cd "$runtime_dir" && pwd -P)" = "$(cd "$lean_prefix" && pwd -P)" ] \
  || die "app/Package.swift would link the Lean runtime from $runtime_dir, but $toolchain is $lean_prefix"
# Built for the app's deployment target, so the linker does not see objects newer than the app.
(cd "$here/core" && MACOSX_DEPLOYMENT_TARGET="$min_macos" "$elan" run "$toolchain" lake build OSVACore:static)

echo "2. release build, linked with a link map"
bin_dir="$(cd "$app_src" && swift build -c release --show-bin-path ${swift_flags[@]+"${swift_flags[@]}"})"
mkdir -p "$out_dir"
link_map="$(cd "$out_dir" && pwd)/$link_map_name"
# Without the executable, swift build links it again, so the map is written, and is this link's.
rm -f "$link_map" "$bin_dir/OSVAMonitor"
(cd "$app_src" && swift build -c release --product OSVAMonitor ${swift_flags[@]+"${swift_flags[@]}"} \
  -Xlinker -map -Xlinker "$link_map")
# Only UPDATE_TESTING code has the string OSVA_UPDATE_FEED (the environment variable's name); no other build may.
if [ "${UPDATE_TESTING:-}" != 1 ] && grep -q -a OSVA_UPDATE_FEED "$bin_dir/OSVAMonitor"; then
  die "this build has the test-only feed override compiled in; remove .build and build again"
fi
check_core_inside "$bin_dir/OSVAMonitor"
check_core_origin "$link_map" "$bin_dir/OSVAMonitor" build

echo "3. bundle"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources" "$app/Contents/Frameworks"
cp "$bin_dir/OSVAMonitor" "$app/Contents/MacOS/OSVAMonitor"
# Sparkle, as SwiftPM fetched and checked it (Package.resolved), with its symlinks kept (ditto), found through
# Contents/Frameworks only: SwiftPM's own @loader_path, which would look beside the executable, is taken out.
sparkle="$bin_dir/Sparkle.framework"
[ -d "$sparkle" ] || sparkle="$app_src/.build/artifacts/sparkle/Sparkle/Sparkle.xcframework/macos-arm64_x86_64/Sparkle.framework"
[ -L "$sparkle/Versions/Current" ] || die "no Sparkle.framework with its symlinks at $sparkle"
ditto "$sparkle" "$app/Contents/Frameworks/Sparkle.framework"
exe="$app/Contents/MacOS/OSVAMonitor"
rpaths="$(otool -l "$exe" | awk '/cmd LC_RPATH/ { getline; getline; print $2 }')"
if grep -qx '@loader_path' <<<"$rpaths"; then install_name_tool -delete_rpath @loader_path "$exe"; fi
if ! grep -qx '@executable_path/../Frameworks' <<<"$rpaths"; then install_name_tool -add_rpath @executable_path/../Frameworks "$exe"; fi
for bundle in "$bin_dir"/*.bundle; do                 # SwiftPM resource bundles: OSVAMonitorUI's has CHANGELOG.md
  [ -e "$bundle" ] && cp -R "$bundle" "$app/Contents/Resources/"
done
# The app finds it there (Changelog.resourceURL); without it there is no What's New.
[ -n "$(find "$app/Contents/Resources/OSVAMonitor_OSVAMonitorUI.bundle" -name CHANGELOG.md 2>/dev/null)" ] \
  || die "no CHANGELOG.md in the app's resources (OSVAMonitor_OSVAMonitorUI.bundle)"
# The app icon, a Liquid Glass icon made in Icon Composer (app/Resources/AppIcon.icon): actool compiles it into
# Assets.car (CFBundleIconName) and AppIcon.icns (CFBundleIconFile, for whatever still reads only that). actool exits 0
# even when it compiled nothing, so the two files are checked for.
icon_tmp="$(mktemp -d)"                               # actool insists on writing the keys it would add; they are below
actool_status=0
actool_log="$(xcrun actool "$app_src/Resources/AppIcon.icon" --compile "$app/Contents/Resources" --app-icon AppIcon \
  --platform macosx --target-device mac --minimum-deployment-target "$min_macos" \
  --output-partial-info-plist "$icon_tmp/AppIcon.plist" --output-format human-readable-text --errors --warnings)" \
  || actool_status=$?
rm -rf "$icon_tmp"
grep -E "(error|warning):" <<<"$actool_log" >&2 || true
for f in Assets.car AppIcon.icns; do
  [ "$actool_status" = 0 ] && [ -s "$app/Contents/Resources/$f" ] || { echo "actool did not make $f" >&2; exit 1; }
done
plist="$app/Contents/Info.plist"
cp "$app_src/Resources/Info.plist" "$plist"
plutil -replace CFBundleShortVersionString -string "$version" "$plist"
plutil -replace CFBundleVersion -string "$build_number" "$plist"
plutil -replace LSMinimumSystemVersion -string "$min_macos" "$plist"
if [ -n "${SPARKLE_PUBLIC_KEY:-}" ]; then
  plutil -replace SUPublicEDKey -string "$SPARKLE_PUBLIC_KEY" "$plist"
  echo "   test build: trusts the update key $SPARKLE_PUBLIC_KEY"
fi
if [ "${UPDATE_TESTING:-}" = 1 ]; then
  # A local test feed is http://127.0.0.1:<port>/; App Transport Security lets the app load it only with this key.
  plutil -insert NSAppTransportSecurity -json '{"NSAllowsLocalNetworking":true}' "$plist"
fi
if [ "${DEV_BUILD:-}" = 1 ]; then
  plutil -insert OSVADevBuild -bool YES "$plist"
  echo "   dev build: for this Mac only (OSVADevBuild), never signed with the Developer ID"
fi
plutil -lint "$app/Contents/Info.plist" >/dev/null
else
  # SIGN_APP: an app built on another Mac. The Mac server builds and tests; the keys stay on the signing Mac. What is
  # checked before it is signed is listed in the header (SIGN_APP=).
  [ -n "${DEVELOPER_ID:-}" ] || die "SIGN_APP signs a build made elsewhere with the Developer ID; set DEVELOPER_ID"
  [ -f "$SIGN_APP/Contents/Info.plist" ] && [ -x "$SIGN_APP/Contents/MacOS/OSVAMonitor" ] || die "SIGN_APP is not an OSVA Monitor app: $SIGN_APP"
  echo "1-3. the app built elsewhere: $SIGN_APP"
  got() { /usr/libexec/PlistBuddy -c "Print :$1" "$SIGN_APP/Contents/Info.plist" 2>/dev/null || true; }
  want() { /usr/libexec/PlistBuddy -c "Print :$1" "$app_src/Resources/Info.plist" 2>/dev/null || true; }
  [ "$(got CFBundleShortVersionString)" = "$version" ] || die "SIGN_APP is version $(got CFBundleShortVersionString), not $version"
  [ "$(got CFBundleVersion)" = "$build_number" ] || die "SIGN_APP has bundle version $(got CFBundleVersion), not $build_number"
  for k in CFBundleIdentifier SUFeedURL SUPublicEDKey SUVerifyUpdateBeforeExtraction SURequireSignedFeed; do
    [ -n "$(want "$k")" ] && [ "$(got "$k")" = "$(want "$k")" ] || die "SIGN_APP's $k is not this repository's"
  done
  [ -z "$(got NSAppTransportSecurity)" ] || die "SIGN_APP is a test build (it allows local networking)"
  [ -z "$(got OSVADevBuild)" ] || die "SIGN_APP is a dev build (DEV_BUILD=1), never signed with the Developer ID"
  ! grep -q -a OSVA_UPDATE_FEED "$SIGN_APP/Contents/MacOS/OSVAMonitor" || die "SIGN_APP is a test build (it has the feed override)"
  check_core_inside "$SIGN_APP/Contents/MacOS/OSVAMonitor"
  # The build Mac's files are not here: the header says what this check does differently then.
  check_core_origin "$(dirname "$SIGN_APP")/$link_map_name" "$SIGN_APP/Contents/MacOS/OSVAMonitor" sign
  rm -rf "$app"; mkdir -p "$out_dir"; ditto "$SIGN_APP" "$app"
fi

echo "4. signature"
# Inside out, each piece once, never --deep (Sparkle's documentation, "Code Signing", for an app that is not sandboxed):
# Sparkle's XPC services, its installer (Autoupdate), its progress app (Updater.app), the framework, then the app.
# The Downloader service keeps its own entitlements; Autoupdate's, made for Sparkle's ad-hoc build, are not kept.
sign_inside_out() {
  local fw="$app/Contents/Frameworks/Sparkle.framework"
  codesign --force "$@" "$fw/Versions/B/XPCServices/Installer.xpc"
  codesign --force "$@" --preserve-metadata=entitlements "$fw/Versions/B/XPCServices/Downloader.xpc"
  codesign --force "$@" "$fw/Versions/B/Autoupdate"
  codesign --force "$@" "$fw/Versions/B/Updater.app"
  codesign --force "$@" "$fw"
  codesign --force "$@" "$app"
  codesign --verify --strict --deep --verbose=2 "$app"
}
zip="$out_dir/OSVA-Monitor-$version.zip"             # the GitHub release asset's name, which the appcast links to
if [ -n "${DEVELOPER_ID:-}" ] && [ -n "${NOTARY_PROFILE:-}" ]; then
  kc_args=()
  if [ -n "${SIGNING_KEYCHAIN:-}" ]; then
    saved_list=$(security list-keychains -d user | tr -d '" ')
    # An account whose search list was empty (the Mac server's build account) gets it back empty: list-keychains -s with
    # no names would leave the signing keychain in it.
    restore_keychains() {
      if [ -n "$saved_list" ]; then security list-keychains -d user -s $saved_list
      else defaults delete com.apple.security DLDBSearchList 2>/dev/null || true; fi
      security lock-keychain "$SIGNING_KEYCHAIN" || true
    }
    trap restore_keychains EXIT
    security unlock-keychain -p "$(cat "${SIGNING_KEYCHAIN_PASSWORD_FILE:?set SIGNING_KEYCHAIN_PASSWORD_FILE}")" "$SIGNING_KEYCHAIN"
    security list-keychains -d user -s $saved_list "$SIGNING_KEYCHAIN"
    kc_args=(--keychain "$SIGNING_KEYCHAIN")
  fi
  # Developer ID with the hardened runtime and a secure timestamp on every piece, then Apple's notary service, then
  # the ticket stapled to the app.
  sign_inside_out --options runtime --timestamp ${kc_args[@]+"${kc_args[@]}"} --sign "$DEVELOPER_ID"
  rm -f "$zip"
  ditto -c -k --keepParent "$app" "$zip"
  xcrun notarytool submit "$zip" --keychain-profile "$NOTARY_PROFILE" ${kc_args[@]+"${kc_args[@]}"} --wait
  xcrun stapler staple "$app"
  xcrun stapler validate "$app"
  spctl --assess --type execute --verbose=2 "$app"
  rm -f "$zip"
  ditto -c -k --keepParent "$app" "$zip"            # the zip to publish, with the ticket inside
  echo "notarized: $zip"
else
  # Ad-hoc: runs on the Mac that built it (and others after "Open Anyway"); touches no keychain. No hardened runtime:
  # its library validation would refuse an ad-hoc Sparkle.framework, which has no Team ID to match.
  sign_inside_out --sign - --timestamp=none
  rm -f "$zip"
  ditto -c -k --keepParent "$app" "$zip"
  echo "zipped: $zip (ad-hoc signed, not notarized)"
fi

echo "built: $app"

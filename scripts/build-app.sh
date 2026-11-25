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
# Where the core in the executable comes from (check_core_origin). Step 2 links the executable with a link map
# (ld -map), OSVAMonitor.link-map beside the app, and stops unless, in that map:
#   - every symbol in "# Symbols:" (what the executable holds, not what was dead-stripped) whose name starts with
#     _lp_osvaCore_, _initialize_osvaCore_ or _osva_lean_ is defined by a member of the archive lake built,
#     core/.lake/build/lib/libosvaCore_OSVACore.a: its "# Object files:" entry is that file (the same file, compared by
#     device and inode) followed by "(member)". Every global symbol the archive defines has one of these prefixes; the
#     build stops if one does not, since it would not be checked;
#   - the executable takes no symbol with these prefixes from a library at run time (nm -u lists none);
#   - these are among them: _lp_osvaCore_OSVA_verdict, _lp_osvaCore_OSVA_upgradeFor, _lp_osvaCore_OSVA_judge and
#     _lp_osvaCore_OSVA_pctEncode (the compiled OSVA.verdict, upgradeFor, judge and pctEncode, which the claims in
#     .verificationalliance.json are about), _osva_lean_<name> for every @[export osva_lean_<name>] in
#     core/OSVACore/FFI.lean (what the C shim calls), and _initialize_osvaCore_OSVACore (the core's initializer);
#   - the map is this executable's: its "# Path:" names an OSVAMonitor, and nm finds each name above in the executable,
#     external and in __TEXT (T), at the address the map gives.
# So no other object, archive or dylib given to the link, and no Swift @_cdecl, defines one of those names in its
# place. Not checked here: that the archive is what lake built from the .lean files (step 1 builds it in the same run),
# the Lean runtime and libraries the core calls (from the toolchain directory step 1 checks), and the shim's own
# functions.
#
# SIGN_APP=<path to OSVA Monitor.app>, with DEVELOPER_ID: skip steps 1-3 and sign and notarize an app another Mac
# built with this script (the Mac server builds and tests; the signing keys stay on the signing Mac). It is signed only
# if: its CFBundleShortVersionString and CFBundleVersion are this run's version and bundle version; its
# CFBundleIdentifier, SUFeedURL, SUPublicEDKey, SUVerifyUpdateBeforeExtraction and SURequireSignedFeed equal
# app/Resources/Info.plist's; it has no NSAppTransportSecurity (UPDATE_TESTING) or OSVADevBuild (DEV_BUILD) key; its
# executable does not contain the string OSVA_UPDATE_FEED (UPDATE_TESTING) and loads no library named like the core
# (otool -L); and the link map its build wrote passes the origin check above. That map must be copied along with the
# app, to SIGN_APP's folder as OSVAMonitor.link-map. Two things differ from the check in a build, since the build Mac's
# files are not here: the archive is recognised only by its path ending in /core/.lake/build/lib/libosvaCore_OSVACore.a
# (and all such paths must be the same one), and the prefixes are not compared with the archive's own symbols. The map
# is required, rather than trusting that the build checked it, so that this Mac refuses an app whose build did not
# check its core (an older script, or no map), and nm ties the map to this executable. The map is the build Mac's
# word, not signed: it guards against a mistake on the build Mac, not against a build Mac that lies.
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

# The origin check the header describes ("Where the core in the executable comes from").
link_map_name="OSVAMonitor.link-map"
core_prefixes='^_(lp_osvaCore_|initialize_osvaCore_|osva_lean_)'
core_archive_path="/core/.lake/build/lib/libosvaCore_OSVACore.a"
# The names that must be in the executable: the four the claims are about, the initializer, and FFI.lean's exports.
core_required() {
  local exports
  exports="$(grep -o '@\[export osva_lean_[A-Za-z0-9_]*\]' "$here/core/OSVACore/FFI.lean" \
    | sed -e 's/^@\[export /_/' -e 's/\]$//')"
  [ -n "$exports" ] || die "core/OSVACore/FFI.lean exports no osva_lean_* function"
  printf '%s\n' _lp_osvaCore_OSVA_verdict _lp_osvaCore_OSVA_upgradeFor _lp_osvaCore_OSVA_judge \
    _lp_osvaCore_OSVA_pctEncode _initialize_osvaCore_OSVACore "$exports"
}
# check_core_origin <link map> <executable> [<archive>]: with the archive (a build), its member's file must be that
# file; without it (SIGN_APP), only its path's ending is known.
check_core_origin() {
  local map="$1" exe="$2" archive="${3:-}" path arch rows nm_out required name addr obj lib n line
  local problems="" listing="" archives=""
  [ -s "$map" ] || die "no link map at $map (build-app.sh writes it beside the app it builds)"
  path="$(sed -n 's/^# Path: //p' "$map" | head -1)"
  arch="$(sed -n 's/^# Arch: //p' "$map" | head -1)"
  [ "${path##*/}" = OSVAMonitor ] && [ -n "$arch" ] || die "$map is not the link map of an OSVAMonitor executable (# Path: $path)"
  if [ -n "$archive" ]; then
    # Every global the archive defines must have one of the prefixes, or the check below would pass it by.
    line="$(nm -g -U -j "$archive")" || die "nm cannot read $archive"
    line="$(grep -v -e '^$' -e ':$' <<<"$line" | grep -v -E "$core_prefixes" | head -3 | tr '\n' ' ' || true)"
    [ -z "$line" ] || die "$archive defines symbols outside the prefixes this check covers ($core_prefixes): $line"
  fi
  # name<TAB>address<TAB>object file, for each symbol in "# Symbols:" whose name has one of the prefixes
  rows="$(awk -F '\t' -v re="$core_prefixes" '
    /^# Object files:$/ { s = "o"; next }
    /^# Symbols:$/ { s = "s"; next }
    /^# [A-Z][A-Za-z ]*:$/ { s = ""; next }
    /^#/ { next }
    s == "o" && match($0, /^\[ *[0-9]+\] /) { obj[substr($0, 2, RLENGTH - 3) + 0] = substr($0, RLENGTH + 1) }
    s == "s" && NF >= 3 && match($3, /^\[ *[0-9]+\] /) {
      name = substr($3, RLENGTH + 1)
      if (name ~ re) print name "\t" $1 "\t" obj[substr($3, 2, RLENGTH - 3) + 0]
    }' "$map")"
  while IFS=$'\t' read -r name addr obj; do
    [ -n "$name" ] || continue
    case "$obj" in *"$core_archive_path("*")") lib="${obj%%"$core_archive_path("*}$core_archive_path" ;; *) lib="" ;; esac
    if [ -z "$lib" ] || { [ -n "$archive" ] && ! [ "$lib" -ef "$archive" ]; }; then
      problems+="   $name is defined by $obj, not by a member of ${archive:-...$core_archive_path}"$'\n'
    else
      case "$archives" in *"<$lib>"*) ;; *) archives+="<$lib>" ;; esac
    fi
  done <<<"$rows"
  [ "$(grep -o '<' <<<"$archives" | wc -l | tr -d ' ')" -le 1 ] || problems+="   the core comes from more than one archive: $archives"$'\n'
  line="$(nm -u -arch "$arch" "$exe")" || die "nm cannot read $exe"
  line="$(grep -E "$core_prefixes" <<<"$line" | head -3 | tr '\n' ' ' || true)"
  [ -z "$line" ] || problems+="   the executable takes these from a library at run time: $line"$'\n'
  nm_out="$(nm -g -U -arch "$arch" "$exe")" || die "nm cannot read $exe"
  required="$(core_required)"
  for name in $required; do
    n="$(awk -F '\t' -v n="$name" '$1 == n' <<<"$rows" | wc -l | tr -d ' ')"
    if [ "$n" != 1 ]; then problems+="   $name is in the link map's # Symbols $n times, not once"$'\n'; continue; fi
    addr="$(awk -F '\t' -v n="$name" '$1 == n { print $2 }' <<<"$rows")"
    line="$(awk -v n="$name" '$3 == n' <<<"$nm_out")"
    if [ "$(awk '{ print $2 }' <<<"$line")" != T ] || [ $((16#${addr#0x})) != $((16#$(awk '{ print $1 }' <<<"$line"))) ]; then
      problems+="   $name: the map has it at $addr, nm finds in the executable: ${line:-nothing}"$'\n'
    else
      obj="$(awk -F '\t' -v n="$name" '$1 == n { print $3 }' <<<"$rows")"
      listing+="   $name $addr ${obj##*/}"$'\n'
    fi
  done
  [ -z "$problems" ] || { printf '%s' "$problems" >&2; die "the core in $exe is not all from libosvaCore_OSVACore.a (above; map: $map)"; }
  printf '%s' "$listing"
  echo "   all $(grep -c . <<<"$rows") of the core's symbols in the executable are from ${archives//[<>]/}"
}

if [ -z "${SIGN_APP:-}" ]; then
toolchain="$(tr -d '[:space:]' < "$here/core/lean-toolchain")"
echo "1. verified core (lake build OSVACore:static, with $toolchain)"
[[ "$toolchain" == leanprover/lean4:v* ]] || die "core/lean-toolchain does not name a Lean release: $toolchain"
elan="$(command -v elan || echo "${ELAN_HOME:-$HOME/.elan}/bin/elan")"
[ -x "$elan" ] || die "no elan, which runs the toolchain core/lean-toolchain names (https://github.com/leanprover/elan)"
lake_version="$("$elan" run --install "$toolchain" lake --version)" || die "elan cannot run $toolchain"
[[ "$lake_version" == *"(Lean version ${toolchain#*:v})" ]] || die "$toolchain runs a lake of another Lean: $lake_version"
# The directory app/Package.swift links the Lean runtime from, worked out as it does: it must be this toolchain's.
runtime_dir="${ELAN_HOME:-$HOME/.elan}/toolchains/$(sed -e 's|/|--|g' -e 's|:|---|g' <<<"$toolchain")"
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
check_core_origin "$link_map" "$bin_dir/OSVAMonitor" "$here$core_archive_path"

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
  # The build Mac's archive is not here: matched by its path's ending only (the header says what else differs).
  check_core_origin "$(dirname "$SIGN_APP")/$link_map_name" "$SIGN_APP/Contents/MacOS/OSVAMonitor"
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

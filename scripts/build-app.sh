#!/usr/bin/env bash
# Builds "OSVA Monitor.app": the verified core (Lean), a release build of the app, the bundle, and its signature.
#
#   scripts/build-app.sh                 ad-hoc signed app in app/.build/OSVA Monitor.app (runs on this Mac)
#   DEVELOPER_ID="Developer ID Application: Name (TEAMID)" NOTARY_PROFILE=<notarytool keychain profile> \
#   scripts/build-app.sh                 Developer ID signed, hardened runtime, notarized and stapled
#
# VERSION sets the version (default below), as major.minor.patch. The bundle version Sparkle compares, CFBundleVersion,
# follows from it (1.2.3 is 1002003), so a higher version is always a newer build; BUILD_NUMBER overrides it.
# OUT_DIR changes where the app goes; SWIFTPM_FLAGS passes extra flags to `swift build`.
# SIGNING_KEYCHAIN (and SIGNING_KEYCHAIN_PASSWORD_FILE) name a dedicated keychain holding the identity and the notary
# profile: it is unlocked and appended to the search list only while signing (codesign needs that to build the
# certificate chain), then the search list is restored exactly and the keychain locked again.
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
version="${VERSION:-0.2.1}"
min_macos="26.0"
die() { echo "build-app.sh: $*" >&2; exit 1; }

[[ "$version" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || die "VERSION must be major.minor.patch, each 0 to 999 (not $version)"
build_number="${BUILD_NUMBER:-$(( 10#${BASH_REMATCH[1]} * 1000000 + 10#${BASH_REMATCH[2]} * 1000 + 10#${BASH_REMATCH[3]} ))}"
[[ "$build_number" =~ ^[0-9]+$ ]] || die "BUILD_NUMBER must be a whole number (not $build_number)"
swift_flags=(${SWIFTPM_FLAGS:-})
if [ -n "${DEVELOPER_ID:-}" ]; then
  [ -z "${SPARKLE_PUBLIC_KEY:-}" ] || die "SPARKLE_PUBLIC_KEY is for test builds; a Developer ID build trusts only the real update key"
  [ -z "${UPDATE_TESTING:-}" ] || die "UPDATE_TESTING is for test builds, never signed with the Developer ID"
  [[ " ${swift_flags[*]-} " != *OSVA_UPDATE_TESTING* ]] || die "OSVA_UPDATE_TESTING in SWIFTPM_FLAGS: not with DEVELOPER_ID"
fi
[ "${UPDATE_TESTING:-}" != 1 ] || swift_flags+=(-Xswiftc -DOSVA_UPDATE_TESTING)

echo "1. verified core (lake build OSVACore:static)"
lake="$(command -v lake || echo "$HOME/.elan/bin/lake")"
# Built for the app's deployment target, so the linker does not see objects newer than the app.
(cd "$here/core" && MACOSX_DEPLOYMENT_TARGET="$min_macos" "$lake" build OSVACore:static)

echo "2. release build"
(cd "$app_src" && swift build -c release --product OSVAMonitor ${swift_flags[@]+"${swift_flags[@]}"})
bin_dir="$(cd "$app_src" && swift build -c release --show-bin-path ${swift_flags[@]+"${swift_flags[@]}"})"
# The feed override exists only in UPDATE_TESTING builds; make sure a normal build has none of it.
if [ "${UPDATE_TESTING:-}" != 1 ] && grep -q -a OSVA_UPDATE_FEED "$bin_dir/OSVAMonitor"; then
  die "this build has the test-only feed override compiled in; remove .build and build again"
fi

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
for bundle in "$bin_dir"/*.bundle; do                 # SwiftPM resource bundles, if any target gains resources
  [ -e "$bundle" ] && cp -R "$bundle" "$app/Contents/Resources/"
done
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
plutil -lint "$app/Contents/Info.plist" >/dev/null

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
    restore_keychains() { security list-keychains -d user -s $saved_list; security lock-keychain "$SIGNING_KEYCHAIN" || true; }
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

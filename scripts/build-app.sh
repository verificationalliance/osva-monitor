#!/usr/bin/env bash
# Builds "OSVA Monitor.app": the verified core (Lean), a release build of the app, the bundle, and its signature.
#
#   scripts/build-app.sh                 ad-hoc signed app in app/.build/OSVA Monitor.app (runs on this Mac)
#   DEVELOPER_ID="Developer ID Application: Name (TEAMID)" NOTARY_PROFILE=<notarytool keychain profile> \
#   scripts/build-app.sh                 Developer ID signed, hardened runtime, notarized and stapled
#
# OUT_DIR changes where the app goes; SWIFTPM_FLAGS passes extra flags to `swift build`.
# SIGNING_KEYCHAIN (and SIGNING_KEYCHAIN_PASSWORD_FILE) name a dedicated keychain holding the identity and the notary
# profile: it is unlocked and appended to the search list only while signing (codesign needs that to build the
# certificate chain), then the search list is restored exactly and the keychain locked again.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
app_src="$here/app"
out_dir="${OUT_DIR:-$app_src/.build}"
app="$out_dir/OSVA Monitor.app"
version="0.1.0"
build_number="1"
min_macos="26.0"

echo "1. verified core (lake build OSVACore:static)"
lake="$(command -v lake || echo "$HOME/.elan/bin/lake")"
# Built for the app's deployment target, so the linker does not see objects newer than the app.
(cd "$here/core" && MACOSX_DEPLOYMENT_TARGET="$min_macos" "$lake" build OSVACore:static)

echo "2. release build"
# shellcheck disable=SC2086
(cd "$app_src" && swift build -c release --product OSVAMonitor ${SWIFTPM_FLAGS:-})
bin_dir="$(cd "$app_src" && swift build -c release --show-bin-path ${SWIFTPM_FLAGS:-})"

echo "3. bundle"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$bin_dir/OSVAMonitor" "$app/Contents/MacOS/OSVAMonitor"
for bundle in "$bin_dir"/*.bundle; do                 # SwiftPM resource bundles, if any target gains resources
  [ -e "$bundle" ] && cp -R "$bundle" "$app/Contents/Resources/"
done
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>            <string>org.verificationalliance.osva-monitor</string>
  <key>CFBundleName</key>                  <string>OSVA Monitor</string>
  <key>CFBundleDisplayName</key>           <string>OSVA Monitor</string>
  <key>CFBundleExecutable</key>            <string>OSVAMonitor</string>
  <key>CFBundlePackageType</key>           <string>APPL</string>
  <key>CFBundleShortVersionString</key>    <string>$version</string>
  <key>CFBundleVersion</key>               <string>$build_number</string>
  <key>CFBundleInfoDictionaryVersion</key> <string>6.0</string>
  <key>CFBundleDevelopmentRegion</key>     <string>en</string>
  <key>LSMinimumSystemVersion</key>        <string>$min_macos</string>
  <key>LSUIElement</key>                   <true/>
  <key>LSApplicationCategoryType</key>     <string>public.app-category.developer-tools</string>
  <key>NSHumanReadableCopyright</key>      <string>Open Source Verification Alliance, https://verificationalliance.org/</string>
</dict>
</plist>
PLIST
plutil -lint "$app/Contents/Info.plist" >/dev/null

echo "4. signature"
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
  # Developer ID with the hardened runtime, then Apple's notary service, then the ticket stapled to the app.
  codesign --force --options runtime --timestamp ${kc_args[@]+"${kc_args[@]}"} --sign "$DEVELOPER_ID" "$app"
  codesign --verify --strict --verbose=2 "$app"
  zip="$out_dir/OSVA Monitor-$version.zip"
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
  # Ad-hoc: runs on the Mac that built it (and others after "Open Anyway"); touches no keychain.
  codesign --force --sign - --timestamp=none "$app"
  codesign --verify --strict --verbose=2 "$app"
fi

echo "built: $app"

#!/usr/bin/env bash
# Publishes a notarized build to the app's update feed: signs the zip with the update key, adds it to the appcast,
# signs the appcast, checks both signatures against the key inside the app, and prints the SHA-256 for the cask.
#
#   SPARKLE_ED_KEY_FILE=<private key file> scripts/release.sh <OSVA-Monitor-X.Y.Z.zip> <X.Y.Z> <appcast.xml> [notes.md]
#
# The zip is the one scripts/build-app.sh made with DEVELOPER_ID and NOTARY_PROFILE. appcast.xml is made if it does not
# exist; otherwise the release is added to it (or put in place of the same version, to make a release again). The notes,
# Markdown or plain text, go inside the feed and so are covered by its signature; without them the item points to the
# GitHub release page. They are docs/release-notes/<X.Y.Z>.md, the version's lines from the app's CHANGELOG.md
# (ChangelogTests checks that the two agree).
#
# SPARKLE_ED_KEY_FILE holds the update key's private half: the base64 of a 32-byte Ed25519 seed (CryptoKit's
# Curve25519.Signing.PrivateKey().rawRepresentation), which is the form Sparkle's `sign_update --ed-key-file` reads.
# It must be readable by its owner only. The key is passed to sign_update and osva-appcast by path and read only into
# their memory; nothing here prints it, copies it or echoes their output when they fail.
#
# Before signing, the zip's app must be: Developer ID signed and notarized, version <X.Y.Z>, with the real feed URL,
# the signed-feed and verify-before-extraction settings, no test-only setting, and an update key that is this key's
# public half (so that the people who install it can take the next update).
#
# For scripts/test-update.sh only: RELEASE_TESTING=1 accepts an ad-hoc signed test build, and RELEASE_DOWNLOAD_URL
# then replaces the GitHub download URL (for a local feed).
set -euo pipefail
set +x                                                # whatever the caller set: no command tracing near the key

here="$(cd "$(dirname "$0")/.." && pwd)"
app_src="$here/app"
die() { echo "release.sh: $*" >&2; exit 1; }

[ $# -ge 3 ] && [ $# -le 4 ] || die "usage: SPARKLE_ED_KEY_FILE=<key> scripts/release.sh <zip> <version> <appcast.xml> [notes.md]"
zip="$1" version="$2" appcast="$3" notes="${4:-}"
testing="${RELEASE_TESTING:-}"
key="${SPARKLE_ED_KEY_FILE:-}"

[ -f "$zip" ] || die "no zip at $zip"
[[ "$version" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || die "the version must be major.minor.patch (not $version)"
[ -d "$(dirname "$appcast")" ] || die "no folder for $appcast"
[ -z "$notes" ] || [ -f "$notes" ] || die "no notes at $notes"
[ -n "$key" ] || die "set SPARKLE_ED_KEY_FILE to the update key's private key file"
[ -f "$key" ] && [ ! -L "$key" ] || die "SPARKLE_ED_KEY_FILE is not a regular file"
[ "$(stat -f %u "$key")" = "$(id -u)" ] || die "the key file belongs to someone else"
[ $(( 0$(stat -f %Lp "$key") & 077 )) = 0 ] || die "the key file can be read by others; chmod 600 it first"

echo "1. tools"
(cd "$app_src" && swift package resolve >/dev/null && swift build -c release --product osva-appcast >/dev/null)
appcast_tool="$(cd "$app_src" && swift build -c release --show-bin-path)/osva-appcast"
sign_update="$app_src/.build/artifacts/sparkle/Sparkle/bin/sign_update"   # Sparkle 2.10.1's own, as SwiftPM checked it
[ -x "$sign_update" ] || die "no sign_update at $sign_update"

echo "2. the app in the zip"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
ditto -x -k "$zip" "$tmp"
[ "$(ls -A "$tmp")" = "OSVA Monitor.app" ] || die "the zip must hold OSVA Monitor.app and nothing else"
app="$tmp/OSVA Monitor.app"
info() { /usr/libexec/PlistBuddy -c "Print :$1" "$app/Contents/Info.plist" 2>/dev/null || true; }
[ "$(info CFBundleIdentifier)" = "org.verificationalliance.osva-monitor" ] || die "not OSVA Monitor (bundle identifier $(info CFBundleIdentifier))"
[ "$(info CFBundleShortVersionString)" = "$version" ] || die "the app is version $(info CFBundleShortVersionString), not $version"
build="$(info CFBundleVersion)"
[[ "$build" =~ ^[0-9]+$ ]] || die "CFBundleVersion is not a whole number ($build)"
[ "$(info SUFeedURL)" = "https://verificationalliance.org/app/appcast.xml" ] || die "the app reads another feed: $(info SUFeedURL)"
[ "$(info SURequireSignedFeed)" = "true" ] && [ "$(info SUVerifyUpdateBeforeExtraction)" = "true" ] \
  || die "the app must require a signed feed and verify updates before unpacking them"
minimum="$(info LSMinimumSystemVersion)"
[ -n "$minimum" ] || die "the app has no LSMinimumSystemVersion"
app_key="$(info SUPublicEDKey)"
codesign --verify --strict --deep "$app" || die "the app's code signature does not verify"
if [ "$testing" = 1 ]; then
  echo "   RELEASE_TESTING: a test build is accepted; this feed is not for publishing"
else
  [ -z "$(info NSAppTransportSecurity)" ] || die "this is a test build (it allows local networking)"
  ! grep -q -a OSVA_UPDATE_FEED "$app/Contents/MacOS/OSVAMonitor" || die "this is a test build (it has the feed override)"
  # grep reads all of codesign's output (no -q): with pipefail, -q stops at the first match and codesign's SIGPIPE
  # (exit 141) would fail a correctly signed app
  codesign -dvv "$app" 2>&1 | grep "^Authority=Developer ID Application:" >/dev/null || die "the app is not signed with a Developer ID"
  xcrun stapler validate "$app" >/dev/null || die "the app has no notarization ticket stapled"
fi
echo "   OSVA Monitor $version (bundle version $build), macOS $minimum or later, trusts update key $app_key"

echo "3. the key"
key_public="$("$appcast_tool" public-key --key-file "$key" 2>/dev/null)" || die "SPARKLE_ED_KEY_FILE does not hold the base64 of a 32-byte Ed25519 seed"
[ "$key_public" = "$app_key" ] || die "the app trusts update key $app_key, but SPARKLE_ED_KEY_FILE is the key $key_public; refusing to sign"
echo "   SPARKLE_ED_KEY_FILE is the private half of $key_public"

echo "4. the zip's signature"
signature="$("$sign_update" -p --ed-key-file "$key" "$zip" 2>/dev/null)" || die "sign_update could not sign the zip"
[[ "$signature" =~ ^[A-Za-z0-9+/]{86}==$ ]] || die "sign_update did not print a signature"
"$appcast_tool" verify-archive --public-key "$app_key" --signature "$signature" "$zip" || die "the zip's signature does not verify"
"$sign_update" --verify --ed-key-file "$key" "$zip" "$signature" >/dev/null 2>&1 || die "sign_update does not verify its own signature"
length="$(stat -f %z "$zip")"
url="https://github.com/verificationalliance/osva-monitor/releases/download/v$version/OSVA-Monitor-$version.zip"
if [ "$testing" = 1 ] && [ -n "${RELEASE_DOWNLOAD_URL:-}" ]; then url="$RELEASE_DOWNLOAD_URL"; fi
echo "   $signature, $length bytes"

echo "5. the appcast"
"$appcast_tool" add --appcast "$appcast" --version "$version" --build "$build" --url "$url" --length "$length" \
  --signature "$signature" --minimum-system "$minimum" ${notes:+--notes "$notes"}
"$sign_update" --disable-signing-warning --ed-key-file "$key" "$appcast" >/dev/null 2>&1 || die "sign_update could not sign the appcast"
"$appcast_tool" verify-feed --public-key "$app_key" "$appcast" || die "the appcast's signature does not verify"
"$sign_update" --verify --ed-key-file "$key" "$appcast" >/dev/null 2>&1 || die "sign_update does not verify the appcast's signature"
echo "   signed: $appcast"

sha="$(shasum -a 256 "$zip" | cut -d' ' -f1)"
cat <<DONE

Released $version (bundle version $build). Next:
  1. Upload $zip to the GitHub release v$version as OSVA-Monitor-$version.zip
     ($url).
  2. Publish $appcast at https://verificationalliance.org/app/appcast.xml exactly as it is: its last lines are its
     signature, and a changed byte makes the app ignore it.
  3. In verificationalliance/homebrew-tap, Casks/osva-monitor.rb:
       version "$version"
       sha256 "$sha"
DONE

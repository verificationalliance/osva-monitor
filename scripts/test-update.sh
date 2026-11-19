#!/usr/bin/env bash
# Tests self-update end to end on this Mac, with a throwaway update key and a feed served from 127.0.0.1. Touches no
# keychain, no signing identity and no real key, and leaves the installed app and its settings alone.
#
#   scripts/test-update.sh            the checks below, without any window
#   scripts/test-update.sh --gui      then also opens the 0.1.0 test app on the good feed, for a look at Sparkle's own
#                                     windows (quit any installed OSVA Monitor first: they share settings)
#
# 1. Makes a throwaway key, and builds OSVA Monitor 0.1.0 and 0.1.1 ad-hoc, trusting it (build-app.sh with
#    SPARKLE_PUBLIC_KEY and UPDATE_TESTING=1).
# 2. Releases 0.1.1 with scripts/release.sh (RELEASE_TESTING=1) into local feeds, and serves them over http.
# 3. Points Sparkle, with a copy of 0.1.0 as the app being updated, at each feed (scripts/update-test/probe.swift:
#    Sparkle's real update cycle, answering "Install" where a person would click it) and expects:
#      good            0.1.0 finds 0.1.1 in the signed feed, downloads it, and the installer verifies and installs it
#      tampered zip    the zip has one byte changed: the installer refuses it, the app stays 0.1.0
#      tampered feed   the feed has one byte changed after signing: Sparkle refuses the feed
#      other key       the feed is signed with another key: Sparkle refuses the feed
#      unsigned feed   the feed's signature is removed: Sparkle refuses the feed
#
# Sparkle's installer runs as a launchd job in the user's login session. Without one (over ssh, on a build account),
# it cannot start, so the steps after the download, which include checking the zip's signature, are reported as not
# verified here; the zip's signature is then checked with Sparkle's sign_update and with CryptoKit instead. Run the
# script in Terminal on a logged-in Mac to see the installer's part too.
#
# WORK sets the folder (default app/.build/update-test); PORT the port (default: a free one).
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
app_src="$here/app"
work="${WORK:-$app_src/.build/update-test}"
port="${PORT:-$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')}"
fw="$app_src/.build/artifacts/sparkle/Sparkle/Sparkle.xcframework/macos-arm64_x86_64"
sign_update="$app_src/.build/artifacts/sparkle/Sparkle/bin/sign_update"
mkdir -p "$work/bin" "$work/keys"
chmod 700 "$work/keys"

echo "== tools"
(cd "$app_src" && swift package resolve >/dev/null && swift build -c release --product osva-appcast >/dev/null)
appcast_tool="$(cd "$app_src" && swift build -c release --show-bin-path)/osva-appcast"
xcrun swiftc -swift-version 6 -O -F "$fw" -framework Sparkle -Xlinker -rpath -Xlinker "$fw" \
  "$here/scripts/update-test/probe.swift" -o "$work/bin/probe"
probe="$work/bin/probe"

echo "== a throwaway key, and 0.1.0 and 0.1.1 built to trust it"
rm -f "$work/keys/"*
public="$("$probe" new-key "$work/keys/throwaway.key")"
other="$("$probe" new-key "$work/keys/other.key")"
echo "   throwaway key $public"
for v in 0.1.0 0.1.1; do
  VERSION=$v SPARKLE_PUBLIC_KEY="$public" UPDATE_TESTING=1 OUT_DIR="$work/build-$v" "$here/scripts/build-app.sh" > "$work/build-$v.log" 2>&1 \
    || { tail -20 "$work/build-$v.log"; exit 1; }
  echo "   built $v ($work/build-$v.log)"
done

echo "== feeds"
feeds="$work/feeds"
rm -rf "$feeds"
mkdir -p "$feeds/good" "$feeds/tampered-zip"
zip="$work/build-0.1.1/OSVA-Monitor-0.1.1.zip"
notes="$work/notes.md"
printf '%s\n' "- The Settings numbers under What Leaves Your Mac open their lists." "- Updates itself, signed & checked." > "$notes"
for feed in good tampered-zip; do
  cp "$zip" "$feeds/$feed/OSVA-Monitor-0.1.1.zip"
  RELEASE_TESTING=1 RELEASE_DOWNLOAD_URL="http://127.0.0.1:$port/$feed/OSVA-Monitor-0.1.1.zip" SPARKLE_ED_KEY_FILE="$work/keys/throwaway.key" \
    "$here/scripts/release.sh" "$feeds/$feed/OSVA-Monitor-0.1.1.zip" 0.1.1 "$feeds/$feed/appcast.xml" "$notes" > "$work/release-$feed.log" \
    || { cat "$work/release-$feed.log"; exit 1; }
done
if grep -q -F -f "$work/keys/throwaway.key" "$work/release-good.log" "$work/release-tampered-zip.log"; then
  echo "release.sh printed the private key"; exit 1
fi
echo "   released 0.1.1 into two feeds; release.sh printed no key material"
# One byte of the zip changed, same length: its signature in the feed no longer matches.
python3 -I - "$feeds/tampered-zip/OSVA-Monitor-0.1.1.zip" <<'PY'
import sys
p = sys.argv[1]
b = bytearray(open(p, "rb").read()); b[len(b) // 2] ^= 0x01; open(p, "wb").write(b)
PY
# The good feed with one character of its notes changed after signing.
mkdir -p "$feeds/tampered-feed" "$feeds/other-key" "$feeds/unsigned-feed"
sed 's/Updates itself/Updates itselF/' "$feeds/good/appcast.xml" > "$feeds/tampered-feed/appcast.xml"
cmp -s "$feeds/good/appcast.xml" "$feeds/tampered-feed/appcast.xml" && { echo "the feed was not changed"; exit 1; }
# The good feed signed again with another key; and with no signature at all.
python3 -I - "$feeds/good/appcast.xml" "$feeds/unsigned-feed/appcast.xml" <<'PY'
import sys
d = open(sys.argv[1], "rb").read(); open(sys.argv[2], "wb").write(d[:d.rindex(b"<!-- sparkle-signatures:\n")])
PY
cp "$feeds/unsigned-feed/appcast.xml" "$feeds/other-key/appcast.xml"
"$sign_update" --disable-signing-warning --ed-key-file "$work/keys/other.key" "$feeds/other-key/appcast.xml" >/dev/null

server_log="$work/http.log"
python3 -I -m http.server "$port" --bind 127.0.0.1 --directory "$feeds" > "$server_log" 2>&1 &
server=$!
trap 'kill $server 2>/dev/null || true' EXIT
sleep 1

results=()
run() {   # run <name> <feed>: a fresh copy of 0.1.0, then Sparkle against the feed
  local name="$1" feed="$2" host="$work/host-$1"
  rm -rf "$host"; mkdir -p "$host"
  ditto "$work/build-0.1.0/OSVA Monitor.app" "$host/OSVA Monitor.app"
  echo "== $name"
  set +e
  "$probe" "$host/OSVA Monitor.app" "http://127.0.0.1:$port/$feed/appcast.xml" | tee "$work/probe-$name.log" | sed 's/^/   /'
  status=${PIPESTATUS[0]}
  set -e
  after="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$host/OSVA Monitor.app/Contents/Info.plist")"
  echo "   exit $status; the app is now $after"
}
found() { grep -q "found 0.1.1 (bundle version 1001), feed signature valid" "$work/probe-$1.log"; }
no_installer() { grep -q "launching the installer" "$work/probe-$1.log"; }

run good good
if [ "$status" = 0 ] && [ "$after" = 0.1.1 ]; then results+=("PASS good: found, feed verified, downloaded, zip verified, installed: 0.1.0 became 0.1.1")
elif found good && no_installer good; then results+=("PART good: found 0.1.1, feed signature verified, downloaded; the installer needs a login session (not verified here)")
else results+=("FAIL good"); fi

run tampered-zip tampered-zip
if [ "$status" = 1 ] && [ "$after" = 0.1.0 ] && ! no_installer tampered-zip; then
  results+=("PASS tampered zip: $(grep 'refused:' "$work/probe-tampered-zip.log" | head -1 | sed 's/^probe: //'); the app stays 0.1.0")
elif found tampered-zip && no_installer tampered-zip; then results+=("PART tampered zip: found and downloaded; the installer, which checks the zip, needs a login session")
else results+=("FAIL tampered zip"); fi
signature="$(grep -o 'sparkle:edSignature="[^"]*"' "$feeds/tampered-zip/appcast.xml" | cut -d'"' -f2)"
if ! "$sign_update" --verify --ed-key-file "$work/keys/throwaway.key" "$feeds/tampered-zip/OSVA-Monitor-0.1.1.zip" "$signature" >/dev/null 2>&1 \
   && ! "$appcast_tool" verify-archive --public-key "$public" --signature "$signature" "$feeds/tampered-zip/OSVA-Monitor-0.1.1.zip" 2>/dev/null \
   && "$appcast_tool" verify-archive --public-key "$public" --signature "$signature" "$feeds/good/OSVA-Monitor-0.1.1.zip"; then
  results+=("PASS tampered zip, offline: Sparkle's sign_update and CryptoKit both reject its signature (and accept the genuine zip's)")
else results+=("FAIL tampered zip, offline"); fi

for case in tampered-feed other-key unsigned-feed; do
  run "$case" "$case"
  if [ "$status" = 1 ] && ! found "$case" && [ "$after" = 0.1.0 ]; then
    results+=("PASS $case: $(grep -e 'refused:' -e 'no update:' "$work/probe-$case.log" | head -1 | sed 's/^probe: //')")
  else results+=("FAIL $case"); fi
done

echo
echo "== results"
printf '   %s\n' "${results[@]}"
echo "   requests served: $(grep -c '" 200 ' "$server_log") (log: $server_log)"

if [ "${1:-}" = --gui ]; then
  gui="$work/host-gui"
  rm -rf "$gui"; mkdir -p "$gui"
  ditto "$work/build-0.1.0/OSVA Monitor.app" "$gui/OSVA Monitor.app"
  open -n --env "OSVA_UPDATE_FEED=http://127.0.0.1:$port/good/appcast.xml" "$gui/OSVA Monitor.app"
  cat <<GUI

== by hand: $gui/OSVA Monitor.app (0.1.0) is open, reading the good feed
   Right after launch Sparkle checks and shows "OSVA Monitor 0.1.1 is available" in front, with the notes.
   Otherwise: click the shield, then the gear, then Check for Updates…
   Install Update: the app quits, is replaced and opens again; Settings › Updates then says 0.1.1.
   Press Return here to stop serving the feed.
GUI
  read -r _
fi
! printf '%s\n' "${results[@]}" | grep -q '^FAIL'

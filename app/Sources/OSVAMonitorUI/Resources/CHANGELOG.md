# What’s New

OSVA Monitor’s changelog, and the only one: the website has none. The app shows the newest entry once, at the top of
its panel after an update, and every entry in Settings > What’s New.

One entry per version, newest first, each a `## major.minor.patch` heading and its lines as `- ` bullets (a bullet may
go on over indented lines). At most six lines, each short and plain: what changed for the person using the app, in
their words, not ours. docs/release-notes/<version>.md, the notes in Sparkle's update window, has the same lines;
ChangelogTests checks both, and that scripts/build-app.sh's version has an entry.

## 0.4.0

- Fix all: one review, then every fix the app can make, one at a time.
- If a fix breaks something, Fix all stops there and offers Undo.

## 0.3.1

- What’s new now shows in the app, once after each update.
- Settings lists every version and what it brought.

## 0.3.0

- Fixes run in the app: review first, watch the log, Stop or Undo.
- Checks what else uses a package before and after a fix, and refuses upgrades known to break them.
- Shows where each package is and why it is there.
- Now checks apps and the libraries inside them, extensions, Go and Rust programs, pipx, uv, conda, MacPorts and
  Nix.
- Fewer false alarms: when the issuer lists the affected versions, only those are flagged. Proved in Lean.
- Updates itself. Each update is signed and checked before it installs.

## 0.2.1

- Fix no longer upgrades Python, Ruby or project packages, which others may depend on. It says so instead.
- Removing a malicious package still works.
- Scans right away after an update, so the findings show what the new version adds.

## 0.2.0

- Fix… on a finding: see the exact command and what else it changes, then run it in Terminal.
- Afterwards the finding is checked again, and its row says how it went.
- Malicious packages get Remove….
- Says when Homebrew does not have the fix yet.
- Flaws an upgrade cannot fix here are named by their summary.

## 0.1.0

- Lives in the menu bar and checks this Mac for known flaws and malware.
- Looks at Homebrew, Electron apps, every Python, global npm, cargo and RubyGems packages, and project folders you
  add.
- Each finding comes with the smallest upgrade that fixes it here, and the command for it.
- Only matches with the public index are sent. Settings shows exactly what.
- Proved in Lean: how versions compare, which are flagged, and which names may be sent.

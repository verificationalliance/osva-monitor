<p align="center">
  <a href="https://verificationalliance.org/">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/logo-dark.png">
      <img alt="Open Source Verification Alliance" src="docs/logo-light.png" width="440">
    </picture>
  </a>
</p>

# OSVA Monitor

[![ci](https://github.com/verificationalliance/osva-monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/verificationalliance/osva-monitor/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Your Mac runs a lot of open-source code you never chose by hand. The Electron inside Slack and VS Code. The Python
that came with Xcode. Whatever Homebrew pulled in. The hundreds of packages in each project's lockfile. Some of it
has known holes. Now and then some of it is malware.

OSVA Monitor lives in the menu bar, checks all of that against public vulnerability and malware data, and shows you
the few things that need you, each with the command that fixes it on this Mac.

<p align="center">
  <img src="docs/screenshots/popover-dark.png" width="400" alt="Findings: a malicious package, flaws exploited in the wild, each with its fix">
</p>

## One example

<img src="docs/screenshots/fix-plan-dark.png" width="330" align="right" alt="setuptools on Apple's Python: upgrade to 78.1.1; one flaw needs Python 3.10; one is Windows only">

Apple's Python, the one that ships with Xcode, has setuptools 58.0.4. It has five known flaws. The usual advice is
"upgrade to 84.1.0", and on this Mac that command fails: 84.1.0 needs Python 3.10, and Apple's Python is 3.9.6.

OSVA Monitor works out what can actually be done here:

- **78.1.1** installs on Python 3.9 and fixes the three high-severity flaws, so that is the target.
- The flaw fixed only in 83.0.0 needs a newer Python. The app says so, instead of suggesting an upgrade that would
  fail.
- One flaw affects Windows only. It is listed, but it does not push you to upgrade.
- Apple's Python is read-only, so the command installs the fixed copy into your user site, which Python loads
  first.

<br clear="right">

```sh
/usr/bin/python3 -m pip install --user --upgrade setuptools==78.1.1
```

Every finding works like this: the smallest upgrade that fixes what can be fixed where the package lives, and a
command for that place, whether it is Homebrew, a project folder, a global npm install or one of your Pythons.
Where it can, the app runs that command itself: you review what will change, watch the log, and can stop it, and the
finding is checked again after. A pip upgrade is checked against what depends on the package, before and after, and
one that breaks something can be undone. Apple's Python changes only with Xcode or macOS, so for this one the app
shows the command and runs nothing.

## What it looks at

- **Homebrew** formulae and casks.
- **Apps that bundle Electron**, checked by the Electron version inside them.
- **Apps** in /Applications: their own version, for the apps the site has a record of, and the libraries they bundle
  (Sparkle, Qt, OpenSSL, FFmpeg, CEF, a Java runtime, Python), read from each framework's Info.plist or the library
  itself.
- **Editor and browser extensions**: VS Code, Cursor, VSCodium and Windsurf; Chrome, Brave, Edge, Arc and Vivaldi;
  Firefox. Each is checked on the Mac against the list of extensions known to be malicious, and the npm packages an
  editor extension bundles are checked like any other.
- **Global packages** from npm, cargo and RubyGems, and **every Python** on the Mac (Apple's, Homebrew's,
  python.org's) with what is installed into it.
- **Go programs** and **Rust programs** on the PATH and in Homebrew's Cellar, by what they were built with: the
  modules and Go version in a Go binary's build info, the crates cargo-auditable records. The binaries are only read,
  never run.
- **pipx and uv tools**, each tool's own environment, and **conda** environments (their PyPI packages).
- **MacPorts** and **Nix**, and conda's other packages, matched to the projects the site grades.
- **Project folders you add**: package-lock.json, yarn.lock, pnpm-lock.yaml, requirements.txt, poetry.lock,
  Pipfile.lock, Cargo.lock, go.sum, Gemfile.lock and composer.lock. A changed lockfile is checked again within
  seconds.

## What leaves your Mac

<img src="docs/screenshots/popover-clean-dark.png" width="340" align="right" alt="Nothing needs action, with what could not be checked and what is not in the index">

Very little. The app downloads the site's public index, every package that has ever had an advisory or a malware
report (about 256,000 names), and matches your packages against it on the Mac. Only the matches are sent: packages as
ecosystem, name and version, and apps and bundled libraries by the index's own name for them. Extensions are checked on
the Mac only. No file paths, no bundle identifiers, no extension IDs, no list of what else you have. Settings shows
exactly what the last scan sent.

Packages that are not in the index are listed as *not in the index: no known problems, not proof of safety*. Things
the app cannot check at all are listed as *not checked*. It never calls something safe because it did not recognise
it.

<br clear="right">

## Updates

The app updates itself with [Sparkle](https://sparkle-project.org/). Once a day it downloads a short feed,
`verificationalliance.org/app/appcast.xml`, that names the latest version. The request tells the site nothing about
your Mac but the app's version. Settings has the switch for the daily check and a button to check now.

Each release is signed with the project's update key, whose public half is built into the app: the zip on GitHub, and
the feed itself. The app takes a new version only if both signatures check. It checks the zip before unpacking any of
it, and it accepts only a zipped app, never an installer package. Someone who could change the web site still could not
make the app install anything else, or put other words in its update window. The zip is also signed with the Developer
ID and notarized by Apple, as before.

`scripts/release.sh` signs a notarized zip and writes the feed. `scripts/test-update.sh` runs a whole update on a Mac,
with a throwaway key and a feed served from the Mac itself, and checks that a changed zip or feed is refused.

## Proved, not only tested

The decisions where a bug would mislead you are written in [Lean 4](https://lean-lang.org/), a programming language
that is also a proof assistant. Next to the code are theorems about it. Lean checks each proof for every possible
input, not for a sample of them, and refuses to build if one is missing or wrong.

<p align="center">
  <img src="docs/how-it-is-proved.svg" width="860" alt="Lean source with 31 theorems is compiled to C and linked into the app through a small C bridge; Lean checks every proof">
</p>

These decisions are proved:

| What the app decides | What is guaranteed, for every input |
|---|---|
| Which of two versions is newer (`1.0rc1 < 1.0 < 1.0.post1 < 1.0.1`, `10.6p1 < 10.6p2`) | The order never contradicts itself: reflexive, antisymmetric, transitive |
| Whether your version is affected, given the versions the issuer lists as affected (PostgreSQL: 16 up to 16.15, 17 up to 17.11) | Your version is flagged if and only if it is in one of those ranges. The upgrade it suggests is newer than yours and in none of them |
| The same, for an advisory that names only the fixed version on each release branch | A warning always comes with a newer version to upgrade to. A version at or past its own branch's fix is never flagged. A version newer than every fix is never flagged |
| Which package names may be sent | A name is sent only if it is byte for byte in the public index |
| How a name is put into a URL | The result never contains `/ ? # @ :`, and decoding it gives the name back, so two names never collide |

This is the guarantee about affected ranges, as Lean states it
([`core/OSVACore/Ranges.lean`](core/OSVACore/Ranges.lean)):

```lean
/-- Every warning means the version lies in one of the issuer's ranges. -/
theorem affectedIn_sound {v : Bytes} {rs : List Range}
    (h : affectedIn v rs = some true) :
    ∃ r ∈ rs, InRange v r
```

In words: if the app says your version `v` is affected, then `v` is in one of the ranges the issuer published. A
companion theorem says the converse, so a version outside every range is never flagged. Both hold for every version
string, including the strange ones nobody thought to test.

When an issuer's record cannot be read as ranges exactly (a range given as commits, or one that contradicts its own
fixes), the site says so, and the app falls back to the fixed version on each release branch.

**The proved code is the code that runs.** Lean compiles the same definitions to C, and that C is linked into the
app. There is no hand-written Swift copy that could drift away from what was proved. About 130 lines of C pass
bytes between Swift and Lean. That bridge is the only unproved code on the path, and it has its own tests.

**Anyone can re-check it.** `scripts/check-core.sh` rebuilds the core, which makes Lean check all 31 proofs again. It
then confirms that they rest only on Lean's three standard axioms (no `sorry`, nothing assumed without proof) and runs
the bridge's tests. CI does the same on every push.

**What is not proved.** The Lean compiler and runtime, the C bridge, and the rest of the app: reading Homebrew,
lockfiles and Pythons, the network, the interface. Those are covered by tests. The data comes from OSV,
the GitHub Advisory Database and NVD. The proofs say the app reasons correctly about that data, not that the data is
right.

The server the app talks to uses the same version order, and its implementation is tested against this Lean core on
30,000 version pairs.

## Build

You need macOS 26, Xcode 26 or later, and [elan](https://github.com/leanprover/elan). The Lean version is pinned in
`core/lean-toolchain`.

```sh
./scripts/check-core.sh   # re-check every proof, audit the axioms, test the bridge
cd app && swift test      # the app's tests
./scripts/build-app.sh    # app/.build/OSVA Monitor.app, ad-hoc signed
```

Set `DEVELOPER_ID` and `NOTARY_PROFILE` for a Developer ID signature and notarization; the script's header has the
details. The app icon is `app/Resources/AppIcon.icon`, a Liquid Glass icon you edit in Icon Composer; `build-app.sh`
compiles it with `actool`. `OSVAMonitor --capture <dir> --fixtures` writes screenshots of the app's own windows. It
waits for you to click the menu-bar shield, because macOS does not let an app open its own menu-bar panel.

| Folder | What is in it |
|---|---|
| `core/` | The Lean core (`OSVACore/*.lean`), its C header and the C bridge |
| `app/` | The Swift package: `OSVAKit` (scanning, the API), `OSVAMonitorUI`, the app, tests |
| `scripts/` | `check-core.sh`, `build-app.sh`, `release.sh` (the update feed), `test-update.sh` |

## Where the data comes from

Findings come from [verificationalliance.org](https://verificationalliance.org/): its public index
([`data/app-index.tsv`](https://verificationalliance.org/data/app-index.tsv)) and its REST API
([`/api/v1`](https://verificationalliance.org/api/v1/), OpenAPI at `/api/v1/openapi.json`). Those are built from OSV,
the GitHub Advisory Database, CVE records, CISA KEV and FIRST EPSS. Comments in the code that name
`site/formalinformer/…` or `formalinformer/api/…` refer to the site's own repository, which is not public yet.

## Security

Please report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE).

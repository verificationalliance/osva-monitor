#!/bin/sh
# Builds the program fixtures on a Mac (arm64), from the sources below:
#   go-inline       Go 1.18+ build info (inline strings); deps: golang.org/x/net v0.23.0, golang.org/x/text replaced by
#                   v0.3.7, a module replaced by a local directory
#   go-pointers     Go 1.17 build info (pointers to string headers); dep: golang.org/x/net at a 2021 pseudo-version
#   rust-auditable  cargo-auditable's .dep-v0 section; crates: time 0.1.43 and libc
# Machine code and Go's pc-line table are zeroed afterwards (the readers never look at them), so the files compress
# to a tenth. Needs: Homebrew's go and rust, network for the modules and crates.
#
#   WORK=/tmp/osva-fixtures ./make-binaries.sh <go1.17 GOROOT>
set -eu
OUT=$(cd "$(dirname "$0")" && pwd)
WORK=${WORK:-$(mktemp -d)}
GO117=${1:?usage: make-binaries.sh <GOROOT of go1.17.x for darwin/arm64>}
export GOPATH="$WORK/gopath" GOMODCACHE="$WORK/gopath/pkg/mod" GOCACHE="$WORK/gocache" GOTELEMETRY=off GOTOOLCHAIN=local GOFLAGS=-mod=mod
export CARGO_HOME="$WORK/cargo-home" CARGO_TARGET_DIR="$WORK/rust-target" PATH="$WORK/cargo-home/bin:/opt/homebrew/bin:$PATH"

mkdir -p "$WORK/gofixture/local" "$WORK/gofixture117" "$WORK/rustfixture/src"
cat > "$WORK/gofixture/go.mod" <<EOF
module example.com/osva/gofixture

go 1.22

require (
	example.com/osva/local v0.0.0
	golang.org/x/net v0.23.0
	golang.org/x/text v0.14.0
)

replace golang.org/x/text => golang.org/x/text v0.3.7

replace example.com/osva/local => ./local
EOF
cat > "$WORK/gofixture/main.go" <<EOF
package main

import (
	"os"

	"example.com/osva/local"
	"golang.org/x/net/html/atom"
	"golang.org/x/text/transform"
)

func main() {
	var t transform.Transformer = transform.Nop
	_ = t
	os.Stdout.WriteString(atom.Lookup([]byte("div")).String() + local.Name + "\n")
}
EOF
printf 'module example.com/osva/local\n\ngo 1.22\n' > "$WORK/gofixture/local/go.mod"
printf 'package local\n\nconst Name = "local"\n' > "$WORK/gofixture/local/local.go"
cat > "$WORK/gofixture117/go.mod" <<EOF
module example.com/osva/gofixture117

go 1.17

require golang.org/x/net v0.0.0-20210226172049-e18ecbb05110
EOF
cat > "$WORK/gofixture117/main.go" <<EOF
package main

import (
	"os"

	"golang.org/x/net/html/atom"
)

func main() { os.Stdout.WriteString(atom.Lookup([]byte("div")).String() + "\n") }
EOF
cat > "$WORK/rustfixture/Cargo.toml" <<EOF
[package]
name = "rustfixture"
version = "0.1.0"
edition = "2021"
publish = false

[dependencies]
time = "=0.1.43"

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
panic = "abort"
strip = true
EOF
printf 'fn main() {\n    let t = time::Duration::seconds(1);\n    println!("{}", t.num_seconds());\n}\n' > "$WORK/rustfixture/src/main.rs"

(cd "$WORK/gofixture" && go mod tidy && go build -trimpath -ldflags="-s -w" -o "$OUT/go-inline" .)
(cd "$WORK/gofixture117" && GOROOT="$GO117" "$GO117/bin/go" mod tidy && GOROOT="$GO117" "$GO117/bin/go" build -trimpath -ldflags="-s -w" -o "$OUT/go-pointers" .)
command -v cargo-auditable >/dev/null || cargo install cargo-auditable --locked
(cd "$WORK/rustfixture" && cargo auditable build --release && cp "$CARGO_TARGET_DIR/release/rustfixture" "$OUT/rust-auditable")

for f in go-inline go-pointers rust-auditable; do
python3 - "$OUT/$f" <<'EOF'
import struct, sys
path = sys.argv[1]
d = bytearray(open(path, "rb").read())
assert d[:4] == b"\xcf\xfa\xed\xfe"
ncmds = struct.unpack_from("<I", d, 16)[0]
at = 32
for _ in range(ncmds):
    cmd, size = struct.unpack_from("<II", d, at)
    if cmd == 0x19:                                  # LC_SEGMENT_64
        for i in range(struct.unpack_from("<I", d, at + 64)[0]):
            s = at + 72 + i * 80
            name, seg = d[s:s + 16].rstrip(b"\0").decode(), d[s + 16:s + 32].rstrip(b"\0").decode()
            addr, sz, off = struct.unpack_from("<QQI", d, s + 32)
            if name in ("__text", "__gopclntab") and off:
                d[off:off + sz] = bytes(sz)
    at += size
open(path, "wb").write(d)
EOF
done
go version -m "$OUT/go-inline" "$OUT/go-pointers"
